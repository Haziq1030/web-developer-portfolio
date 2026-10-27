<?php
/**
 * ThreatFox (abuse.ch) — community IOC feed.
 *
 * Endpoint : POST https://threatfox-api.abuse.ch/api/v1/
 * Auth     : Auth-Key header (free, from auth.abuse.ch)
 * Query    : {"query":"get_iocs","days":1..7}
 *
 * ThreatFox returns no geolocation, so every IP-shaped indicator is resolved
 * locally through GeoIpService. That is the whole reason the GeoLite2 import
 * exists: without it this feed can populate a list but not a map.
 */
class ThreatFoxService
{
    private const PROVIDER = 'threatfox';
    private const ENDPOINT = 'https://threatfox-api.abuse.ch/api/v1/';

    /**
     * Pull recent IOCs, geolocate the IP ones, and store them.
     *
     * @return array{ok:bool, fetched:int, stored:int, located:int, error:string}
     */
    public static function refresh(int $days = 1): array
    {
        $key = secuscan_key('THREATFOX_API_KEY');
        if ($key === '') {
            return self::fail('No ThreatFox Auth-Key is configured. Add one in config.php.');
        }
        if (!GeoIpService::isReady()) {
            return self::fail('The GeoLite2 database has not been imported yet — run import_geolite.php first.');
        }

        $days = max(1, min(7, $days));
        @set_time_limit(180);

        $response = HttpClient::request(
            'POST',
            self::ENDPOINT,
            ['Content-Type' => 'application/json', 'Auth-Key' => $key],
            json_encode(['query' => 'get_iocs', 'days' => $days]),
            45
        );

        if ($response['error'] !== '') {
            return self::fail('Could not reach the feed: ' . $response['error']);
        }
        if ($response['code'] === 401 || $response['code'] === 403) {
            return self::fail('The feed rejected the Auth-Key (HTTP ' . $response['code'] . '). Check it at auth.abuse.ch.');
        }
        if ($response['json'] === null) {
            return self::fail('The feed returned an unreadable response (HTTP ' . $response['code'] . ').');
        }

        $status = (string) ($response['json']['query_status'] ?? '');
        if ($status !== 'ok') {
            // "no_result" is a normal quiet period, not a failure.
            if ($status === 'no_result') {
                return ['ok' => true, 'fetched' => 0, 'stored' => 0, 'located' => 0, 'error' => ''];
            }
            return self::fail('The feed reported: ' . ($status !== '' ? $status : 'unknown status'));
        }

        $rows = $response['json']['data'] ?? [];
        if (!is_array($rows)) {
            return self::fail('The feed returned no usable data array.');
        }

        $conn = secuscan_db();
        $stmt = $conn->prepare(
            'INSERT INTO threat_observations
                (ioc, ioc_type, ip_address, iso_code, malware, threat_type, confidence, first_seen)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE
                iso_code = VALUES(iso_code), malware = VALUES(malware),
                confidence = VALUES(confidence), imported_at = NOW()'
        );

        $stored = 0;
        $located = 0;

        foreach ($rows as $row) {
            $iocType = (string) ($row['ioc_type'] ?? '');
            $ioc     = (string) ($row['ioc'] ?? '');
            if ($ioc === '') { continue; }

            // Only IP-shaped indicators can be placed on a map. Domains and
            // hashes are skipped rather than resolved — a DNS lookup per
            // indicator would be slow and would tell us where a CDN sits, not
            // where the threat is.
            $ip = self::extractIp($iocType, $ioc);
            if ($ip === null) { continue; }

            $geo = GeoIpService::lookup($ip);
            $iso = $geo['iso'] ?? '';
            if ($iso !== '') { $located++; }

            $malware    = mb_substr((string) ($row['malware_printable'] ?? $row['malware'] ?? ''), 0, 120);
            $threatType = mb_substr((string) ($row['threat_type'] ?? ''), 0, 80);
            $confidence = (int) ($row['confidence_level'] ?? 0);
            $firstSeen  = self::parseDate((string) ($row['first_seen'] ?? ''));

            $stmt->bind_param('ssssssis', $ioc, $iocType, $ip, $iso, $malware, $threatType, $confidence, $firstSeen);
            $stmt->execute();
            $stored++;
        }
        $stmt->close();

        // Keep the table to a working window. This is a live picture, not an
        // archive, and an unbounded table would slow the map for no benefit.
        $conn->query('DELETE FROM threat_observations WHERE imported_at < DATE_SUB(NOW(), INTERVAL 14 DAY)');

        ApiCache::recordCall(self::PROVIDER);

        return ['ok' => true, 'fetched' => count($rows), 'stored' => $stored, 'located' => $located, 'error' => ''];
    }

    /** ThreatFox writes IP indicators as "1.2.3.4:443"; domains and hashes are not mappable. */
    private static function extractIp(string $iocType, string $ioc): ?string
    {
        if (!str_starts_with($iocType, 'ip:')) {
            return null;
        }
        $candidate = strpos($ioc, ':') !== false ? substr($ioc, 0, strrpos($ioc, ':')) : $ioc;
        $candidate = trim($candidate, '[]');
        return filter_var($candidate, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false ? $candidate : null;
    }

    private static function parseDate(string $raw): ?string
    {
        if ($raw === '') { return null; }
        $ts = strtotime($raw);
        return $ts === false ? null : date('Y-m-d H:i:s', $ts);
    }

    private static function fail(string $message): array
    {
        return ['ok' => false, 'fetched' => 0, 'stored' => 0, 'located' => 0, 'error' => $message];
    }

    /** @return array{total:int, located:int, newest:?string} */
    public static function stats(): array
    {
        $conn = secuscan_db();
        $row = $conn->query(
            "SELECT COUNT(*) AS total,
                    SUM(iso_code <> '') AS located,
                    MAX(imported_at) AS newest
             FROM threat_observations"
        )->fetch_assoc();

        return [
            'total'   => (int) ($row['total'] ?? 0),
            'located' => (int) ($row['located'] ?? 0),
            'newest'  => $row['newest'] ?? null,
        ];
    }
}
