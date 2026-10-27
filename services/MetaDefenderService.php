<?php
/**
 * MetaDefender Cloud API v4 — file hash lookup.
 *
 * Endpoint : GET https://api.metadefender.com/v4/hash/{hash}
 * Auth     : apikey header
 *
 * MetaDefender runs a different engine set from VirusTotal, so it is a genuine
 * second opinion rather than a duplicate. Disagreement between the two is
 * itself a useful signal and worth showing the user.
 *
 * scan_all_result_i values used here:
 *   0  No threat detected
 *   1  Infected / known
 *   2  Suspicious
 *   3  Failed to scan
 *   10 Potentially vulnerable file
 *   Anything else is treated as inconclusive rather than clean.
 */
class MetaDefenderService
{
    private const PROVIDER = 'metadefender';
    private const BASE = 'https://api.metadefender.com/v4';

    public static function lookupHash(string $hash): ThreatResult
    {
        $hash = strtolower(trim($hash));
        if (!VirusTotalService::isValidHash($hash)) {
            return ThreatResult::error('MetaDefender', 'Not a valid MD5, SHA-1 or SHA-256 hash.');
        }

        $key = secuscan_key('METADEFENDER_API_KEY');
        if ($key === '') {
            return ThreatResult::error('MetaDefender', 'No MetaDefender API key is configured.');
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
            return ThreatResult::error('MetaDefender', $blocked);
        }

        $response = HttpClient::get(self::BASE . '/hash/' . rawurlencode($hash), [
            'apikey' => $key,
            'Accept' => 'application/json',
        ]);
        ApiCache::recordCall(self::PROVIDER);

        if ($response['error'] !== '') {
            return ThreatResult::error('MetaDefender', 'Connection failed: ' . $response['error']);
        }
        if ($response['json'] === null) {
            return ThreatResult::error('MetaDefender', 'Unreadable response (HTTP ' . $response['code'] . ').');
        }

        if ($response['ok'] || $response['code'] === 404) {
            ApiCache::put(self::PROVIDER, $hash, $response['json'], $response['code']);
        }

        return self::parse($response['json'], $response['code']);
    }

    public static function uploadFile(string $filePath): ThreatResult
    {
        $key = secuscan_key('METADEFENDER_API_KEY');
        if ($key === '') return ThreatResult::error('MetaDefender', 'No MetaDefender API key is configured.');
        $response = HttpClient::uploadFile(self::BASE . '/file', 'file', $filePath, ['apikey' => $key]);
        $dataId = (string) ($response['json']['data_id'] ?? $response['json']['data']['data_id'] ?? '');
        if (!$response['ok'] || $dataId === '') return ThreatResult::error('MetaDefender', 'MetaDefender file upload failed (HTTP ' . $response['code'] . ').');
        $scan = HttpClient::get(self::BASE . '/file/' . rawurlencode($dataId), ['apikey' => $key]);
        if (!$scan['ok'] || !is_array($scan['json'])) return ThreatResult::error('MetaDefender', 'MetaDefender analysis is not available yet.');
        return self::parse($scan['json'], $scan['code']);
    }

    private static function parse(array $json, int $code): ThreatResult
    {
        $r = new ThreatResult('MetaDefender');

        // MetaDefender signals "hash not in database" with an error object
        // (code 404003) as well as with HTTP 404, depending on the route.
        $errorCode = (int) ($json['error']['code'] ?? 0);
        if ($code === 404 || $errorCode === 404003) {
            $r->verdict = ThreatResult::UNKNOWN;
            $r->summary = 'MetaDefender has no record of this hash. Unknown, not clean.';
            return $r;
        }
        if ($code === 401 || $errorCode === 401000) {
            $r->verdict = ThreatResult::ERROR;
            $r->error = $r->summary = 'API key rejected (HTTP 401). Check the key in config.php.';
            return $r;
        }
        if ($code === 429) {
            $r->verdict = ThreatResult::ERROR;
            $r->error = $r->summary = 'MetaDefender rate limit hit (HTTP 429).';
            return $r;
        }
        if (isset($json['error'])) {
            $messages = $json['error']['messages'] ?? [];
            $r->verdict = ThreatResult::ERROR;
            $r->error = $r->summary = 'MetaDefender error: '
                . (is_array($messages) ? implode('; ', $messages) : 'HTTP ' . $code);
            return $r;
        }
        if ($code < 200 || $code >= 300) {
            $r->verdict = ThreatResult::ERROR;
            $r->error = $r->summary = 'MetaDefender error: HTTP ' . $code;
            return $r;
        }

        $scan     = $json['scan_results'] ?? [];
        $fileInfo = $json['file_info'] ?? [];

        $detected = (int) ($scan['total_detected_avs'] ?? 0);
        $totalAvs = (int) ($scan['total_avs'] ?? 0);
        $verdictCode = isset($scan['scan_all_result_i']) ? (int) $scan['scan_all_result_i'] : -1;

        switch ($verdictCode) {
            case 0:
                $r->verdict = $detected > 0 ? ThreatResult::SUSPICIOUS : ThreatResult::CLEAN;
                break;
            case 1:
                $r->verdict = ThreatResult::MALICIOUS;
                break;
            case 2:
            case 10:
                $r->verdict = ThreatResult::SUSPICIOUS;
                break;
            default:
                $r->verdict = $detected > 0 ? ThreatResult::MALICIOUS : ThreatResult::UNKNOWN;
        }

        $r->score = $totalAvs > 0 ? round(($detected / $totalAvs) * 100, 2) : null;

        $r->summary = $totalAvs > 0
            ? sprintf('%d of %d MetaDefender engines flagged this file.', $detected, $totalAvs)
            : (string) ($scan['scan_all_result_a'] ?? 'No engine results available.');

        $engines = [];
        foreach (($scan['scan_details'] ?? []) as $engineName => $row) {
            $threat = trim((string) ($row['threat_found'] ?? ''));
            if ($threat === '') {
                continue;
            }
            $engines[] = [
                'engine'   => (string) $engineName,
                'category' => 'malicious',
                'result'   => $threat,
                'version'  => (string) ($row['def_time'] ?? ''),
            ];
        }
        usort($engines, static fn($a, $b) => strcasecmp($a['engine'], $b['engine']));

        $r->detail = [
            'stats' => [
                'malicious' => $detected,
                'total'     => $totalAvs,
            ],
            'engines'       => $engines,
            'verdict_text'  => (string) ($scan['scan_all_result_a'] ?? ''),
            'file_name'     => (string) ($fileInfo['display_name'] ?? ''),
            'file_type'     => (string) ($fileInfo['file_type_description'] ?? ''),
            'file_size'     => (int) ($fileInfo['file_size'] ?? 0),
            'md5'           => (string) ($fileInfo['md5'] ?? ''),
            'sha1'          => (string) ($fileInfo['sha1'] ?? ''),
            'sha256'        => (string) ($fileInfo['sha256'] ?? ''),
            'scan_time_ms'  => (int) ($scan['total_time'] ?? 0),
        ];

        return $r;
    }
}
