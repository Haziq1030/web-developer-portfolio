<?php
/**
 * VirusTotal API v3 — file hash lookup.
 *
 * Endpoint : GET https://www.virustotal.com/api/v3/files/{hash}
 * Auth     : x-apikey header
 * Accepts  : MD5, SHA-1 or SHA-256
 *
 * Important semantics:
 *   HTTP 404 means "this hash has never been submitted to VirusTotal".
 *   That is UNKNOWN, not clean. A brand-new piece of malware returns 404.
 *   Treating 404 as safe is exactly the fail-open bug we are removing.
 */
class VirusTotalService
{
    private const PROVIDER = 'virustotal';
    private const BASE = 'https://www.virustotal.com/api/v3';

    public static function lookupHash(string $hash): ThreatResult
    {
        $hash = strtolower(trim($hash));
        if (!self::isValidHash($hash)) {
            return ThreatResult::error('VirusTotal', 'Not a valid MD5, SHA-1 or SHA-256 hash.');
        }

        $key = secuscan_key('VIRUSTOTAL_API_KEY');
        if ($key === '') {
            return ThreatResult::error('VirusTotal', 'No VirusTotal API key is configured.');
        }

        $cached = ApiCache::get(self::PROVIDER, $hash);
        if ($cached !== null) {
            $result = self::parse($cached['json'], $cached['code']);
            $result->cached = true;
            $result->fetchedAt = $cached['fetched_at'];
            return $result;
        }

        $blocked = ApiCache::rateLimitBlock(self::PROVIDER);
        if ($blocked !== null) {
            return ThreatResult::error('VirusTotal', $blocked);
        }

        $response = HttpClient::get(self::BASE . '/files/' . rawurlencode($hash), [
            'x-apikey' => $key,
            'Accept'   => 'application/json',
        ]);
        ApiCache::recordCall(self::PROVIDER);

        if ($response['error'] !== '') {
            return ThreatResult::error('VirusTotal', 'Connection failed: ' . $response['error']);
        }
        if ($response['json'] === null) {
            return ThreatResult::error('VirusTotal', 'Unreadable response (HTTP ' . $response['code'] . ').');
        }

        // 404 is a legitimate, cacheable answer: VT has never seen this file.
        if ($response['ok'] || $response['code'] === 404) {
            ApiCache::put(self::PROVIDER, $hash, $response['json'], $response['code']);
        }

        return self::parse($response['json'], $response['code']);
    }

    private static function parse(array $json, int $code): ThreatResult
    {
        $r = new ThreatResult('VirusTotal');

        if ($code === 404) {
            $r->verdict = ThreatResult::UNKNOWN;
            $r->summary = 'This file has never been submitted to VirusTotal. Unknown is not the same as safe — a new sample looks exactly like this.';
            return $r;
        }
        if ($code === 401) {
            $r->verdict = ThreatResult::ERROR;
            $r->error = $r->summary = 'API key rejected (HTTP 401). Check the key in config.php.';
            return $r;
        }
        if ($code === 429) {
            $r->verdict = ThreatResult::ERROR;
            $r->error = $r->summary = 'VirusTotal rate limit hit (HTTP 429). The public tier allows 4 requests per minute.';
            return $r;
        }
        if ($code < 200 || $code >= 300) {
            $msg = $json['error']['message'] ?? ('HTTP ' . $code);
            $r->verdict = ThreatResult::ERROR;
            $r->error = $r->summary = 'VirusTotal error: ' . $msg;
            return $r;
        }

        $attr  = $json['data']['attributes'] ?? [];
        $stats = $attr['last_analysis_stats'] ?? [];

        $malicious  = (int) ($stats['malicious'] ?? 0);
        $suspicious = (int) ($stats['suspicious'] ?? 0);
        $harmless   = (int) ($stats['harmless'] ?? 0);
        $undetected = (int) ($stats['undetected'] ?? 0);
        $totalEngines = $malicious + $suspicious + $harmless + $undetected;

        if ($malicious > 0) {
            $r->verdict = ThreatResult::MALICIOUS;
        } elseif ($suspicious > 0) {
            $r->verdict = ThreatResult::SUSPICIOUS;
        } elseif ($totalEngines > 0) {
            $r->verdict = ThreatResult::CLEAN;
        } else {
            $r->verdict = ThreatResult::UNKNOWN;
        }

        // The score is a real, explainable ratio: how many engines flagged it.
        $r->score = $totalEngines > 0
            ? round((($malicious + $suspicious) / $totalEngines) * 100, 2)
            : null;

        $r->summary = $totalEngines > 0
            ? sprintf('%d of %d antivirus engines flagged this file.', $malicious + $suspicious, $totalEngines)
            : 'No engine results are available for this file.';

        // Engine-level detail, malicious first — this is what makes the result
        // defensible instead of a single opaque number.
        $engines = [];
        foreach (($attr['last_analysis_results'] ?? []) as $engineName => $row) {
            $category = $row['category'] ?? 'undetected';
            if ($category !== 'malicious' && $category !== 'suspicious') {
                continue;
            }
            $engines[] = [
                'engine'   => (string) $engineName,
                'category' => $category,
                'result'   => (string) ($row['result'] ?? 'flagged'),
                'version'  => (string) ($row['engine_version'] ?? ''),
            ];
        }
        usort($engines, static fn($a, $b) => strcasecmp($a['engine'], $b['engine']));

        $r->detail = [
            'stats'          => [
                'malicious'  => $malicious,
                'suspicious' => $suspicious,
                'harmless'   => $harmless,
                'undetected' => $undetected,
                'total'      => $totalEngines,
            ],
            'engines'        => $engines,
            'file_name'      => (string) ($attr['meaningful_name'] ?? ''),
            'file_type'      => (string) ($attr['type_description'] ?? ''),
            'file_size'      => (int) ($attr['size'] ?? 0),
            'md5'            => (string) ($attr['md5'] ?? ''),
            'sha1'           => (string) ($attr['sha1'] ?? ''),
            'sha256'         => (string) ($attr['sha256'] ?? ''),
            'reputation'     => (int) ($attr['reputation'] ?? 0),
            'times_submitted' => (int) ($attr['times_submitted'] ?? 0),
            'threat_label'   => (string) ($attr['popular_threat_classification']['suggested_threat_label'] ?? ''),
            'first_seen'     => isset($attr['first_submission_date'])
                ? date('Y-m-d H:i', (int) $attr['first_submission_date']) : '',
            'last_analysis'  => isset($attr['last_analysis_date'])
                ? date('Y-m-d H:i', (int) $attr['last_analysis_date']) : '',
        ];

        return $r;
    }

    public static function isValidHash(string $hash): bool
    {
        return (bool) preg_match('/^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$/i', $hash);
    }

    public static function uploadFile(string $filePath): ThreatResult
    {
        $key = secuscan_key('VIRUSTOTAL_API_KEY');
        if ($key === '') return ThreatResult::error('VirusTotal', 'No VirusTotal API key is configured.');
        $response = HttpClient::uploadFile(self::BASE . '/files', 'file', $filePath, ['x-apikey' => $key]);
        if (!$response['ok'] || empty($response['json']['data']['id'])) {
            return ThreatResult::error('VirusTotal', 'VirusTotal file upload failed (HTTP ' . $response['code'] . ').');
        }
        $analysis = HttpClient::get(self::BASE . '/analyses/' . rawurlencode((string) $response['json']['data']['id']), ['x-apikey' => $key]);
        $status = (string) ($analysis['json']['data']['attributes']['status'] ?? '');
        if ($status !== 'completed') return ThreatResult::error('VirusTotal', 'VirusTotal is still analysing this file. Try again later.');
        $hash = hash_file('sha256', $filePath);
        return self::lookupHash($hash);
    }
}
