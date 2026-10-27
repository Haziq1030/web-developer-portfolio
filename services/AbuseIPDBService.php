<?php
/**
 * AbuseIPDB API v2 — IP reputation lookup.
 *
 * Endpoint : GET https://api.abuseipdb.com/api/v2/check
 * Params   : ipAddress, maxAgeInDays (1-365), verbose
 * Auth     : Key header
 *
 * abuseConfidenceScore is 0-100 and is AbuseIPDB's own confidence that the
 * address is engaged in abusive activity. It is a community report score, not
 * a verdict: a score of 0 on an IP with zero reports means "nobody has
 * complained", which is weaker evidence than it looks.
 */
class AbuseIPDBService
{
    private const PROVIDER = 'abuseipdb';
    private const BASE = 'https://api.abuseipdb.com/api/v2';

    /** AbuseIPDB report category IDs. */
    public const CATEGORIES = [
        1  => 'DNS Compromise',
        2  => 'DNS Poisoning',
        3  => 'Fraud Orders',
        4  => 'DDoS Attack',
        5  => 'FTP Brute-Force',
        6  => 'Ping of Death',
        7  => 'Phishing',
        8  => 'Fraud VoIP',
        9  => 'Open Proxy',
        10 => 'Web Spam',
        11 => 'Email Spam',
        12 => 'Blog Spam',
        13 => 'VPN IP',
        14 => 'Port Scan',
        15 => 'Hacking',
        16 => 'SQL Injection',
        17 => 'Spoofing',
        18 => 'Brute-Force',
        19 => 'Bad Web Bot',
        20 => 'Exploited Host',
        21 => 'Web App Attack',
        22 => 'SSH Abuse',
        23 => 'IoT Targeted',
    ];

    public static function lookupIp(string $ip, int $maxAgeInDays = 90): ThreatResult
    {
        $ip = trim($ip);

        if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
            return ThreatResult::error('AbuseIPDB', 'Not a valid IPv4 or IPv6 address.');
        }
        // Private and reserved ranges are never in AbuseIPDB and asking wastes quota.
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            $r = new ThreatResult('AbuseIPDB');
            $r->verdict = ThreatResult::UNKNOWN;
            $r->summary = 'This is a private or reserved address (RFC1918 / loopback / link-local). It has no public reputation to look up.';
            return $r;
        }

        $key = secuscan_key('ABUSEIPDB_API_KEY');
        if ($key === '') {
            return ThreatResult::error('AbuseIPDB', 'No AbuseIPDB API key is configured.');
        }

        $maxAgeInDays = max(1, min(365, $maxAgeInDays));
        $cacheKey = $ip . '|' . $maxAgeInDays;

        $cached = ApiCache::get(self::PROVIDER, $cacheKey);
        if ($cached !== null) {
            $result = self::parse($cached['json'], $cached['code']);
            $result->cached = true;
            $result->fetchedAt = $cached['fetched_at'];
            return $result;
        }

        $blocked = ApiCache::rateLimitBlock(self::PROVIDER);
        if ($blocked !== null) {
            return ThreatResult::error('AbuseIPDB', $blocked);
        }

        $url = self::BASE . '/check?' . http_build_query([
            'ipAddress'    => $ip,
            'maxAgeInDays' => $maxAgeInDays,
            'verbose'      => '',
        ]);

        $response = HttpClient::get($url, [
            'Key'    => $key,
            'Accept' => 'application/json',
        ]);
        ApiCache::recordCall(self::PROVIDER);

        if ($response['error'] !== '') {
            return ThreatResult::error('AbuseIPDB', 'Connection failed: ' . $response['error']);
        }
        if ($response['json'] === null) {
            return ThreatResult::error('AbuseIPDB', 'Unreadable response (HTTP ' . $response['code'] . ').');
        }
        if ($response['ok']) {
            ApiCache::put(self::PROVIDER, $cacheKey, $response['json'], $response['code']);
        }

        return self::parse($response['json'], $response['code']);
    }

    private static function parse(array $json, int $code): ThreatResult
    {
        $r = new ThreatResult('AbuseIPDB');

        if (isset($json['errors'])) {
            $first = $json['errors'][0]['detail'] ?? ('HTTP ' . $code);
            $r->verdict = ThreatResult::ERROR;
            $r->error = $r->summary = 'AbuseIPDB error: ' . $first;
            return $r;
        }
        if ($code === 401) {
            $r->verdict = ThreatResult::ERROR;
            $r->error = $r->summary = 'API key rejected (HTTP 401). Check the key in config.php.';
            return $r;
        }
        if ($code === 429) {
            $r->verdict = ThreatResult::ERROR;
            $r->error = $r->summary = 'AbuseIPDB daily quota exhausted (HTTP 429).';
            return $r;
        }
        if ($code < 200 || $code >= 300) {
            $r->verdict = ThreatResult::ERROR;
            $r->error = $r->summary = 'AbuseIPDB error: HTTP ' . $code;
            return $r;
        }

        $d = $json['data'] ?? [];
        $score = (int) ($d['abuseConfidenceScore'] ?? 0);
        $totalReports = (int) ($d['totalReports'] ?? 0);
        $distinctUsers = (int) ($d['numDistinctUsers'] ?? 0);
        $isWhitelisted = (bool) ($d['isWhitelisted'] ?? false);

        // Thresholds are stated explicitly so they can be defended and tuned,
        // rather than hidden inside a magic constant.
        if ($score >= 50) {
            $r->verdict = ThreatResult::MALICIOUS;
        } elseif ($score >= 15 || ($totalReports > 0 && $distinctUsers > 1)) {
            $r->verdict = ThreatResult::SUSPICIOUS;
        } elseif ($totalReports === 0) {
            // No reports is weak evidence, so say so rather than claiming clean.
            $r->verdict = $isWhitelisted ? ThreatResult::CLEAN : ThreatResult::UNKNOWN;
        } else {
            $r->verdict = ThreatResult::CLEAN;
        }

        $r->score = (float) $score;
        $r->summary = $totalReports > 0
            ? sprintf(
                'Abuse confidence %d%%, from %d report%s by %d distinct reporter%s.',
                $score,
                $totalReports,
                $totalReports === 1 ? '' : 's',
                $distinctUsers,
                $distinctUsers === 1 ? '' : 's'
            )
            : 'No abuse reports on record for this address in the selected window.';

        // Count which attack categories this IP has been reported for.
        $categoryCounts = [];
        $recentReports = [];
        foreach (($d['reports'] ?? []) as $report) {
            foreach (($report['categories'] ?? []) as $catId) {
                $name = self::CATEGORIES[(int) $catId] ?? ('Category ' . (int) $catId);
                $categoryCounts[$name] = ($categoryCounts[$name] ?? 0) + 1;
            }
            if (count($recentReports) < 10) {
                $recentReports[] = [
                    'reported_at' => (string) ($report['reportedAt'] ?? ''),
                    'comment'     => mb_substr(trim((string) ($report['comment'] ?? '')), 0, 220),
                    'country'     => (string) ($report['reporterCountryCode'] ?? ''),
                    'categories'  => array_map(
                        static fn($c) => self::CATEGORIES[(int) $c] ?? ('Cat ' . (int) $c),
                        $report['categories'] ?? []
                    ),
                ];
            }
        }
        arsort($categoryCounts);

        $r->detail = [
            'ip'              => (string) ($d['ipAddress'] ?? ''),
            'ip_version'      => (int) ($d['ipVersion'] ?? 4),
            'is_public'       => (bool) ($d['isPublic'] ?? true),
            'is_whitelisted'  => $isWhitelisted,
            'is_tor'          => (bool) ($d['isTor'] ?? false),
            'country_code'    => (string) ($d['countryCode'] ?? ''),
            'country_name'    => (string) ($d['countryName'] ?? ''),
            'isp'             => (string) ($d['isp'] ?? ''),
            'domain'          => (string) ($d['domain'] ?? ''),
            'usage_type'      => (string) ($d['usageType'] ?? ''),
            'hostnames'       => array_values(array_filter((array) ($d['hostnames'] ?? []))),
            'total_reports'   => $totalReports,
            'distinct_users'  => $distinctUsers,
            'last_reported'   => (string) ($d['lastReportedAt'] ?? ''),
            'category_counts' => $categoryCounts,
            'recent_reports'  => $recentReports,
        ];

        return $r;
    }
}
