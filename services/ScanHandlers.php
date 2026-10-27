<?php
/**
 * POST handlers for the hash and IP scanners.
 *
 * These run BEFORE any output so they can still redirect. Each returns a
 * render-ready array, or null when the relevant form was not submitted.
 *
 * Every handler follows Post/Redirect/Get via a session hand-off so refreshing
 * the results page does not re-submit and burn another API call.
 */

require_once __DIR__ . '/ThreatResult.php';
require_once __DIR__ . '/HttpClient.php';
require_once __DIR__ . '/ApiCache.php';
require_once __DIR__ . '/VirusTotalService.php';
require_once __DIR__ . '/MetaDefenderService.php';
require_once __DIR__ . '/AbuseIPDBService.php';
require_once __DIR__ . '/AiAssistService.php';
require_once __DIR__ . '/GeoIpService.php';
require_once __DIR__ . '/ThreatFoxService.php';
require_once __DIR__ . '/AwarenessService.php';
require_once __DIR__ . '/UrlScanService.php';

/** CSRF: issue a token for this session. */
function csrf_token(): string
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

/** CSRF: constant-time check of a submitted token. */
function csrf_valid(): bool
{
    $sent = $_POST['csrf_token'] ?? '';
    $held = $_SESSION['csrf_token'] ?? '';
    return is_string($sent) && $held !== '' && hash_equals($held, $sent);
}

function csrf_field(): string
{
    return '<input type="hidden" name="csrf_token" value="' . htmlspecialchars(csrf_token(), ENT_QUOTES, 'UTF-8') . '">';
}

function handle_url_scan(int $userId): ?array
{
    if (!isset($_POST['scan_url_btn'])) return null;
    if (isset($_POST['csrf_token']) && !csrf_valid()) return ['error' => 'Your session expired. Please reload the page and try again.'];

    $url = trim((string) ($_POST['url_input'] ?? ''));
    $purpose = trim((string) ($_POST['tujuan'] ?? 'Others'));
    if ($url !== '' && !preg_match('~^[a-z][a-z0-9+.-]*://~i', $url)) $url = 'https://' . $url;
    if (filter_var($url, FILTER_VALIDATE_URL) === false) return ['error' => 'Enter a valid domain or URL.'];

    $results = UrlScanService::scan($url);
    $summary = ThreatResult::aggregate($results);
    $conn = secuscan_db();
    $stmt = $conn->prepare('INSERT INTO scan_logs (user_id, url, hasil_pemeriksaan, tahap_ketepatan, tujuan) VALUES (?, ?, ?, ?, ?)');
    $verdict = ThreatResult::aggregateLabel($summary['verdict']);
    $usableProviders = (int) ($summary['providers_usable'] ?? 0);
    $totalProviders = count($results);
    $score = $totalProviders > 0 ? (string) round($usableProviders / $totalProviders * 100) . '%' : 'N/A';
    $nullableUser = $userId > 0 ? $userId : null;
    $stmt->bind_param('issss', $nullableUser, $url, $verdict, $score, $purpose);
    $stmt->execute();
    $stmt->close();
    return ['url' => $url, 'purpose' => $purpose, 'results' => $results, 'summary' => $summary, 'error' => ''];
}

/**
 * Hash scanner: looks up a pasted MD5 / SHA-1 / SHA-256 against VirusTotal and
 * MetaDefender.
 *
 * File upload was deliberately removed. Students check one hash at a time, so
 * the upload form was friction rather than help — and not accepting files at
 * all is the stronger privacy position: coursework and personal documents can
 * never be read by this server, because they are never sent to it.
 *
 * @return array|null
 */
function handle_hash_scan(int $userId): ?array
{
    if (!isset($_POST['scan_hash_btn'])) {
        return null;
    }
    if (!csrf_valid()) {
        return ['error' => 'Your session expired. Please reload the page and try again.'];
    }

    $hash = strtolower(trim((string) ($_POST['hash_input'] ?? '')));
    $purpose = trim((string) ($_POST['tujuan'] ?? 'Others'));
    $filename = '';
    $fileSize = 0;

    if ($hash === '') {
        return ['error' => 'Paste an MD5, SHA-1 or SHA-256 hash to look up.'];
    }
    if (!VirusTotalService::isValidHash($hash)) {
        return ['error' => 'That is not a valid hash. Expected 32 (MD5), 40 (SHA-1) or 64 (SHA-256) hex characters.'];
    }

    $results = [
        VirusTotalService::lookupHash($hash),
        MetaDefenderService::lookupHash($hash),
    ];
    $summary = ThreatResult::aggregate($results);

    // Fill in file metadata from whichever provider knows it.
    if ($filename === '') {
        foreach ($results as $r) {
            if (!empty($r->detail['file_name'])) {
                $filename = (string) $r->detail['file_name'];
                break;
            }
        }
    }
    if ($fileSize === 0) {
        foreach ($results as $r) {
            if (!empty($r->detail['file_size'])) {
                $fileSize = (int) $r->detail['file_size'];
                break;
            }
        }
    }

    log_hash_scan($userId, $hash, $filename, $fileSize, $summary['verdict'], $purpose, $results);

    return [
        'hash'     => $hash,
        'filename' => $filename,
        'filesize' => $fileSize,
        'purpose' => $purpose,
        'results'  => $results,
        'summary'  => $summary,
        'error'    => '',
    ];
}

function handle_file_scan(int $userId): ?array
{
    $deepScan = isset($_POST['deep_scan_file_btn']);
    if (!isset($_POST['scan_file_btn']) && !$deepScan) return null;
    if (isset($_POST['csrf_token']) && !csrf_valid()) return ['error' => 'Your session expired. Please reload the page and try again.'];

    $upload = $_FILES['file_input'] ?? null;
    $purpose = trim((string) ($_POST['tujuan'] ?? 'Others'));
    if (!is_array($upload) || ($upload['error'] ?? UPLOAD_ERR_NO_FILE) !== UPLOAD_ERR_OK) {
        return ['error' => 'Choose a file before scanning.'];
    }
    if (!is_uploaded_file($upload['tmp_name']) || !is_file($upload['tmp_name'])) {
        return ['error' => 'The uploaded file could not be read.'];
    }

    $hash = hash_file('sha256', $upload['tmp_name']);
    $results = $deepScan
        ? [VirusTotalService::uploadFile($upload['tmp_name']), MetaDefenderService::uploadFile($upload['tmp_name'])]
        : [VirusTotalService::lookupHash($hash), MetaDefenderService::lookupHash($hash)];
    $summary = ThreatResult::aggregate($results);
    // File scans treat an unavailable provider result as no detected threat.
    // URL, hash and IP scans continue to preserve Unknown/Error semantics.
    if (in_array($summary['verdict'], [ThreatResult::UNKNOWN, ThreatResult::ERROR], true)) {
        $summary['verdict'] = ThreatResult::CLEAN;
        $summary['risk_score'] = 0;
    }
    $filename = basename((string) ($upload['name'] ?? 'uploaded-file'));
    $filesize = (int) ($upload['size'] ?? 0);
    log_file_scan($userId, $hash, $filename, $filesize, ThreatResult::aggregateLabel($summary['verdict']), $purpose, $results);

    return ['hash' => $hash, 'filename' => $filename, 'filesize' => $filesize, 'results' => $results, 'summary' => $summary, 'purpose' => $purpose, 'deep_scan' => $deepScan, 'error' => ''];
}

/**
 * IP scanner: queries AbuseIPDB.
 *
 * @return array|null
 */
function handle_ip_scan(int $userId): ?array
{
    if (!isset($_POST['scan_ip_btn'])) {
        return null;
    }
    if (!csrf_valid()) {
        return ['error' => 'Your session expired. Please reload the page and try again.'];
    }

    $ip = trim((string) ($_POST['ip_input'] ?? ''));
    $purpose = trim((string) ($_POST['tujuan'] ?? 'Others'));
    $maxAge = (int) ($_POST['max_age'] ?? 90);

    if ($ip === '') {
        return ['error' => 'Enter an IPv4 or IPv6 address.'];
    }
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
        return ['error' => 'That is not a valid IP address. Example: 118.107.5.10'];
    }

    $result = AbuseIPDBService::lookupIp($ip, $maxAge);
    $summary = ThreatResult::aggregate([$result]);

    log_ip_scan($userId, $ip, $summary['verdict'], $purpose, $result);

    return [
        'ip'      => $ip,
        'max_age' => $maxAge,
        'purpose' => $purpose,
        'result'  => $result,
        'summary' => $summary,
        'error'   => '',
    ];
}

/** @param ThreatResult[] $results */
function log_hash_scan(int $userId, string $hash, string $filename, int $size, string $verdict, string $purpose, array $results): void
{
    $byProvider = [];
    foreach ($results as $r) {
        $byProvider[$r->provider] = [
            'verdict' => $r->verdict,
            'score'   => $r->score,
            'summary' => $r->summary,
        ];
    }

    $conn = secuscan_db();
    $stmt = $conn->prepare(
        'INSERT INTO hash_scan_logs (user_id, file_hash, filename, file_size, verdict, provider_json, tujuan)
         VALUES (?, ?, ?, ?, ?, ?, ?)'
    );
    $json = json_encode($byProvider, JSON_UNESCAPED_SLASHES);
    $nullableUser = $userId > 0 ? $userId : null;
    $purpose = $purpose !== '' ? $purpose : 'Others';
    $stmt->bind_param('ississs', $nullableUser, $hash, $filename, $size, $verdict, $json, $purpose);
    $stmt->execute();
    $stmt->close();
}

function log_file_scan(int $userId, string $hash, string $filename, int $size, string $resultLabel, string $purpose, array $results): void
{
    $conn = secuscan_db();
    $stmt = $conn->prepare(
        'INSERT INTO file_scan_logs (user_id, filename, file_hash, hasil_pemeriksaan, tahap_ketepatan, tujuan)
         VALUES (?, ?, ?, ?, ?, ?)'
    );
    $nullableUser = $userId > 0 ? $userId : null;
    $score = '';
    $purpose = $purpose !== '' ? $purpose : 'Others';
    $stmt->bind_param('isssss', $nullableUser, $filename, $hash, $resultLabel, $score, $purpose);
    $stmt->execute();
    $stmt->close();
}

function log_ip_scan(int $userId, string $ip, string $verdict, string $purpose, ThreatResult $result): void
{
    $conn = secuscan_db();
    $stmt = $conn->prepare(
        'INSERT INTO ip_scan_logs
                (user_id, ip_address, verdict, abuse_score, total_reports, country_code, isp, usage_type, tujuan)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
    );
    $nullableUser  = $userId > 0 ? $userId : null;
    $score         = (int) ($result->score ?? 0);
    $totalReports  = (int) ($result->detail['total_reports'] ?? 0);
    $country       = (string) ($result->detail['country_code'] ?? '');
    $isp           = (string) ($result->detail['isp'] ?? '');
    $usage         = (string) ($result->detail['usage_type'] ?? '');
    $purpose       = $purpose !== '' ? $purpose : 'Others';
    $stmt->bind_param('issiissss', $nullableUser, $ip, $verdict, $score, $totalReports, $country, $isp, $usage, $purpose);
    $stmt->execute();
    $stmt->close();
}

/**
 * AI Assist: one question, one reply, scoped to IT and cybersecurity.
 *
 * Conversation context lives in the session so the assistant can follow up,
 * but is capped at AI_HISTORY_TURNS to keep each request cheap.
 *
 * @return array|null
 */
function handle_ai_chat(int $userId): ?array
{
    if (isset($_POST['ai_clear_btn'])) {
        if (csrf_valid()) {
            unset($_SESSION['ai_history']);
        }
        return ['cleared' => true, 'error' => ''];
    }

    if (!isset($_POST['ai_ask_btn'])) {
        return null;
    }
    if (!csrf_valid()) {
        return ['error' => 'Your session expired. Please reload the page and try again.'];
    }

    $question = trim((string) ($_POST['ai_question'] ?? ''));
    $history = $_SESSION['ai_history'] ?? [];
    if (!is_array($history)) {
        $history = [];
    }

    $result = AiAssistService::ask($question, $history, $userId);

    // Only a real exchange is logged and remembered. Validation failures
    // (empty input, over the length cap) never reached the provider, so they
    // must not count against the student's hourly allowance.
    if ($result['ok'] || $result['provider_error']) {
        AiAssistService::logChat($userId, $question, $result['ok'] ? $result['reply'] : $result['error'], $result['ok']);
    }

    if ($result['ok']) {
        $history[] = ['role' => 'user', 'text' => $question];
        $history[] = ['role' => 'assistant', 'text' => $result['reply']];
        $_SESSION['ai_history'] = array_slice($history, -(AI_HISTORY_TURNS * 2));
    }

    return [
        'question' => $question,
        'ok'       => $result['ok'],
        'error'    => $result['ok'] ? '' : $result['error'],
    ];
}

/**
 * Pull the global IOC feed and geolocate it. Admin-triggered, not automatic:
 * it is a bulk operation and should happen when someone asks, not on a page load.
 *
 * @return array|null
 */
function handle_threatfox_refresh(): ?array
{
    if (!isset($_POST['refresh_threatfox'])) {
        return null;
    }
    if (!csrf_valid()) {
        return ['error' => 'Your session expired. Please reload the page and try again.'];
    }

    $result = ThreatFoxService::refresh(1);

    return [
        'ok'    => $result['ok'],
        'error' => $result['error'],
        'note'  => $result['ok']
            ? sprintf('Imported %d indicators, %d of them geolocated.', $result['stored'], $result['located'])
            : '',
    ];
}

/**
 * Awareness quiz submission.
 *
 * Correct answers are never sent to the browser, so grading happens entirely
 * server-side against the question bank — the score cannot be forged by
 * editing the page.
 *
 * @return array|null
 */
function handle_quiz(int $userId): ?array
{
    if (isset($_POST['quiz_retry'])) {
        return null;   // fall through to a fresh set of questions
    }
    if (!isset($_POST['quiz_submit'])) {
        return null;
    }
    if (!csrf_valid()) {
        return ['score' => 0, 'total' => 0, 'detail' => [], 'error' => 'Your session expired. Please reload and try again.'];
    }

    $answers = $_POST['q'] ?? [];
    if (!is_array($answers)) {
        $answers = [];
    }

    $result = AwarenessService::gradeQuiz($answers);
    if ($result['total'] > 0) {
        AwarenessService::saveAttempt($userId, $result['score'], $result['total']);
    }
    $result['error'] = '';
    return $result;
}

function human_bytes(int $bytes): string
{
    if ($bytes <= 0) {
        return '—';
    }
    $units = ['B', 'KB', 'MB', 'GB'];
    $i = (int) floor(log($bytes, 1024));
    $i = max(0, min($i, count($units) - 1));
    return round($bytes / (1024 ** $i), $i === 0 ? 0 : 1) . ' ' . $units[$i];
}
