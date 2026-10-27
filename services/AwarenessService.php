<?php
/**
 * Awareness page data: campus reality, quiz, and blog items.
 *
 * The campus section is the point of this page. Generic advice — "check the
 * domain", "use 2FA" — is true and almost entirely ignored, because it is
 * abstract. "Seven phishing URLs were caught here this month, and here is what
 * two of them looked like" is the same lesson with evidence attached.
 *
 * PRIVACY: nothing here identifies a student. Only indicators that were
 * FLAGGED are shown — a flagged URL is attacker infrastructure, not a record
 * of someone's browsing — and they are never tied to a username. Clean and
 * unknown lookups are counted but never displayed, because those are the ones
 * that would reveal what an individual was reading.
 */
class AwarenessService
{
    /**
     * Headline counts plus a few real, de-identified examples.
     *
     * @return array{scanned:int, flagged:int, window_days:int, examples:array, top_category:string}
     */
    public static function campusReality(int $windowDays = 30): array
    {
        $conn = secuscan_db();
        $days = max(1, min(365, $windowDays));

        $scanned = 0;
        $flagged = 0;
        $examples = [];

        // --- URL scans (the legacy Python engine's table) ---------------
        $sql = "SELECT COUNT(*) AS total,
                       SUM(hasil_pemeriksaan LIKE '%Phishing%') AS bad
                FROM scan_logs
                WHERE tarikh_semak >= DATE_SUB(NOW(), INTERVAL ? DAY)";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param('i', $days);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        $scanned += (int) ($row['total'] ?? 0);
        $flagged += (int) ($row['bad'] ?? 0);

        $stmt = $conn->prepare(
            "SELECT url, tarikh_semak FROM scan_logs
             WHERE hasil_pemeriksaan LIKE '%Phishing%'
               AND tarikh_semak >= DATE_SUB(NOW(), INTERVAL ? DAY)
             ORDER BY id DESC LIMIT 4"
        );
        $stmt->bind_param('i', $days);
        $stmt->execute();
        $res = $stmt->get_result();
        while ($r = $res->fetch_assoc()) {
            $examples[] = [
                'kind'   => 'URL',
                'icon'   => 'fa-link',
                'value'  => self::defang((string) $r['url']),
                'lesson' => self::urlLesson((string) $r['url']),
                'when'   => (string) $r['tarikh_semak'],
            ];
        }
        $stmt->close();

        // --- Hash scans --------------------------------------------------
        $stmt = $conn->prepare(
            "SELECT COUNT(*) AS total,
                    SUM(verdict IN ('malicious','suspicious')) AS bad
             FROM hash_scan_logs WHERE scanned_at >= DATE_SUB(NOW(), INTERVAL ? DAY)"
        );
        $stmt->bind_param('i', $days);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        $scanned += (int) ($row['total'] ?? 0);
        $flagged += (int) ($row['bad'] ?? 0);

        $stmt = $conn->prepare(
            "SELECT filename, file_hash, scanned_at FROM hash_scan_logs
             WHERE verdict IN ('malicious','suspicious')
               AND scanned_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
             ORDER BY id DESC LIMIT 3"
        );
        $stmt->bind_param('i', $days);
        $stmt->execute();
        $res = $stmt->get_result();
        while ($r = $res->fetch_assoc()) {
            $name = trim((string) $r['filename']);
            $examples[] = [
                'kind'   => 'File',
                'icon'   => 'fa-file-shield',
                'value'  => $name !== '' ? $name : substr((string) $r['file_hash'], 0, 24) . '…',
                'lesson' => 'Flagged by multiple antivirus engines.',
                'when'   => (string) $r['scanned_at'],
            ];
        }
        $stmt->close();

        // --- IP scans ----------------------------------------------------
        $stmt = $conn->prepare(
            "SELECT COUNT(*) AS total,
                    SUM(verdict IN ('malicious','suspicious')) AS bad
             FROM ip_scan_logs WHERE scanned_at >= DATE_SUB(NOW(), INTERVAL ? DAY)"
        );
        $stmt->bind_param('i', $days);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        $stmt->close();
        $scanned += (int) ($row['total'] ?? 0);
        $flagged += (int) ($row['bad'] ?? 0);

        $stmt = $conn->prepare(
            "SELECT ip_address, abuse_score, country_code, scanned_at FROM ip_scan_logs
             WHERE verdict IN ('malicious','suspicious')
               AND scanned_at >= DATE_SUB(NOW(), INTERVAL ? DAY)
             ORDER BY id DESC LIMIT 3"
        );
        $stmt->bind_param('i', $days);
        $stmt->execute();
        $res = $stmt->get_result();
        while ($r = $res->fetch_assoc()) {
            $examples[] = [
                'kind'   => 'IP',
                'icon'   => 'fa-globe',
                'value'  => self::defang((string) $r['ip_address']),
                'lesson' => 'Abuse confidence ' . (int) $r['abuse_score'] . '%'
                          . ((string) $r['country_code'] !== '' ? ', hosted in ' . $r['country_code'] : '') . '.',
                'when'   => (string) $r['scanned_at'],
            ];
        }
        $stmt->close();

        usort($examples, static fn($a, $b) => strcmp($b['when'], $a['when']));

        return [
            'scanned'     => $scanned,
            'flagged'     => $flagged,
            'window_days' => $days,
            'examples'    => array_slice($examples, 0, 6),
        ];
    }

    /**
     * Defang an indicator so it cannot be clicked or auto-linked.
     *
     * Standard SOC practice: a live malicious URL in a report is a hazard, and
     * mail clients and chat apps will helpfully turn it into a link. Breaking
     * the scheme and the dots removes that risk while keeping it readable.
     */
    public static function defang(string $indicator): string
    {
        // Break the scheme first, then every dot. Order matters: doing the dots
        // first would leave "http" intact and the string still auto-linkable.
        $out = preg_replace_callback(
            '#^https?://#i',
            static fn(array $m): string => str_ireplace('http', 'hxxp', $m[0]),
            $indicator
        ) ?? $indicator;

        $out = str_replace('.', '[.]', $out);

        return mb_strlen($out) > 90 ? mb_substr($out, 0, 90) . '…' : $out;
    }

    /** A one-line reason this URL looks wrong, drawn from the URL itself. */
    private static function urlLesson(string $url): string
    {
        $lower = strtolower($url);
        $host = strtolower((string) parse_url($url, PHP_URL_HOST));

        if (str_contains($url, '@')) {
            return 'Contains @ — everything before it is ignored by the browser, so the real host is hidden.';
        }
        foreach (['maybank', 'cimb', 'bank', 'paypal', 'lhdn', 'pos '] as $brand) {
            if (str_contains($host, $brand)) {
                return 'A brand name inside the domain, not the real domain — anyone can register that.';
            }
        }
        if (substr_count($host, '-') >= 2) {
            return 'Several hyphens in the hostname — a common pattern for look-alike domains.';
        }
        foreach (['login', 'verify', 'update', 'secure', 'account'] as $word) {
            if (str_contains($lower, $word)) {
                return 'Urgent action words in the address: "' . $word . '".';
            }
        }
        return 'Flagged by the scanning engine.';
    }

    // -----------------------------------------------------------------------
    // Quiz
    // -----------------------------------------------------------------------

    /** @return array<int,array> a random selection of active questions */
    public static function quizQuestions(int $count = 6): array
    {
        $conn = secuscan_db();
        $count = max(1, min(15, $count));
        $res = $conn->query(
            'SELECT id, qkey, category, question, option_a, option_b, option_c, option_d
             FROM awareness_questions WHERE active = 1 ORDER BY RAND() LIMIT ' . $count
        );
        $out = [];
        while ($res && $r = $res->fetch_assoc()) { $out[] = $r; }
        return $out;
    }

    /**
     * Mark a submission.
     *
     * Correct answers are re-read from the database rather than trusted from
     * the form — the browser never sees which option is right, so the score
     * cannot be forged by editing the page.
     *
     * @param array<int,string> $answers question id => chosen letter
     * @return array{score:int, total:int, detail:array}
     */
    public static function gradeQuiz(array $answers): array
    {
        if (empty($answers)) {
            return ['score' => 0, 'total' => 0, 'detail' => []];
        }

        $ids = array_values(array_filter(array_map('intval', array_keys($answers)), static fn($i) => $i > 0));
        if (empty($ids)) {
            return ['score' => 0, 'total' => 0, 'detail' => []];
        }

        $conn = secuscan_db();
        $placeholders = implode(',', array_fill(0, count($ids), '?'));
        $stmt = $conn->prepare(
            "SELECT id, category, question, option_a, option_b, option_c, option_d, correct, explanation
             FROM awareness_questions WHERE id IN ($placeholders)"
        );
        $stmt->bind_param(str_repeat('i', count($ids)), ...$ids);
        $stmt->execute();
        $res = $stmt->get_result();

        $detail = [];
        $score = 0;
        while ($q = $res->fetch_assoc()) {
            $qid = (int) $q['id'];
            $given = strtoupper(substr((string) ($answers[$qid] ?? ''), 0, 1));
            $correct = strtoupper((string) $q['correct']);
            $isRight = $given === $correct;
            if ($isRight) { $score++; }

            $detail[] = [
                'question'    => (string) $q['question'],
                'category'    => (string) $q['category'],
                'given'       => $given,
                'correct'     => $correct,
                'is_right'    => $isRight,
                'given_text'  => (string) ($q['option_' . strtolower($given)] ?? '(no answer)'),
                'correct_text' => (string) ($q['option_' . strtolower($correct)] ?? ''),
                'explanation' => (string) $q['explanation'],
            ];
        }
        $stmt->close();

        return ['score' => $score, 'total' => count($detail), 'detail' => $detail];
    }

    public static function saveAttempt(int $userId, int $score, int $total): void
    {
        if ($total <= 0) { return; }
        $conn = secuscan_db();
        $stmt = $conn->prepare('INSERT INTO awareness_attempts (user_id, score, total) VALUES (?, ?, ?)');
        $nullableUser = $userId > 0 ? $userId : null;
        $stmt->bind_param('iii', $nullableUser, $score, $total);
        $stmt->execute();
        $stmt->close();
    }

    /** @return array{attempts:int, best:int, best_total:int, last:?string} */
    public static function userProgress(int $userId): array
    {
        if ($userId <= 0) {
            return ['attempts' => 0, 'best' => 0, 'best_total' => 0, 'last' => null];
        }
        $conn = secuscan_db();
        $stmt = $conn->prepare(
            'SELECT COUNT(*) AS attempts,
                    MAX(ROUND(score / NULLIF(total,0) * 100)) AS best_pct,
                    MAX(total) AS best_total,
                    MAX(taken_at) AS last
             FROM awareness_attempts WHERE user_id = ?'
        );
        $stmt->bind_param('i', $userId);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        return [
            'attempts'   => (int) ($row['attempts'] ?? 0),
            'best'       => (int) ($row['best_pct'] ?? 0),
            'best_total' => (int) ($row['best_total'] ?? 0),
            'last'       => $row['last'] ?? null,
        ];
    }

    /** Is the quiz installed? */
    public static function isReady(): bool
    {
        try {
            $conn = secuscan_db();
            $res = $conn->query("SHOW TABLES LIKE 'awareness_questions'");
            if (!$res || $res->num_rows === 0) { return false; }
            $c = $conn->query('SELECT COUNT(*) AS t FROM awareness_questions WHERE active = 1');
            return $c && (int) ($c->fetch_assoc()['t'] ?? 0) > 0;
        } catch (Throwable $ex) {
            return false;
        }
    }

    /**
     * Awareness-relevant headlines from the news cache.
     *
     * Reuses the feed already being fetched for the News page rather than
     * pulling anything extra — same data, filtered to the topics that teach
     * something rather than the ones that only report an incident.
     *
     * @return array<int,array>
     */
    public static function relevantHeadlines(int $limit = 4): array
    {
        require_once __DIR__ . '/NewsService.php';

        $feed = NewsService::latest(false);
        $wanted = ['Phishing', 'Ransomware', 'Data breach', 'Patch'];

        $picked = [];
        foreach ($feed['items'] as $item) {
            $tags = NewsService::tagsFor($item);
            if (array_intersect($tags, $wanted)) {
                $item['tags'] = $tags;
                $picked[] = $item;
            }
            if (count($picked) >= $limit) { break; }
        }
        return $picked;
    }
}
