<?php
/**
 * Response cache + client-side rate limiter.
 *
 * Why this exists: the VirusTotal public API allows 4 requests per MINUTE.
 * Without a cache, five users clicking "scan" at once, or one user refreshing
 * a results page, exhausts the quota and every later scan returns an error.
 * A live demo would fall over within seconds.
 *
 * The cache is keyed on (provider, key) where key is the hash / IP / feed URL,
 * so repeat lookups of the same indicator are free.
 */
class ApiCache
{
    public static function get(string $provider, string $key): ?array
    {
        $ttl = CACHE_TTL[$provider] ?? 3600;
        $conn = secuscan_db();

        $stmt = $conn->prepare(
            'SELECT response_json, http_code, fetched_at,
                    TIMESTAMPDIFF(SECOND, fetched_at, NOW()) AS age_seconds
             FROM api_cache
             WHERE provider = ? AND cache_key = ?
             LIMIT 1'
        );
        $stmt->bind_param('ss', $provider, $key);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$row || (int) $row['age_seconds'] > $ttl) {
            return null;
        }

        $decoded = json_decode((string) $row['response_json'], true);
        if (!is_array($decoded)) {
            return null;
        }

        return [
            'json'       => $decoded,
            'code'       => (int) $row['http_code'],
            'fetched_at' => $row['fetched_at'],
            'age'        => (int) $row['age_seconds'],
        ];
    }

    public static function put(string $provider, string $key, array $json, int $httpCode): void
    {
        $conn = secuscan_db();
        $payload = json_encode($json, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($payload === false) {
            return;
        }

        $stmt = $conn->prepare(
            'INSERT INTO api_cache (provider, cache_key, response_json, http_code, fetched_at)
             VALUES (?, ?, ?, ?, NOW())
             ON DUPLICATE KEY UPDATE
                response_json = VALUES(response_json),
                http_code     = VALUES(http_code),
                fetched_at    = NOW()'
        );
        $stmt->bind_param('sssi', $provider, $key, $payload, $httpCode);
        $stmt->execute();
        $stmt->close();
    }

    /**
     * Returns null when the call is allowed, or a human-readable reason when
     * the local quota is already spent. Checking locally means we refuse
     * politely instead of burning a request to be told 429 by the provider.
     */
    public static function rateLimitBlock(string $provider): ?string
    {
        $limits = RATE_LIMITS[$provider] ?? null;
        if ($limits === null) {
            return null;
        }

        $conn = secuscan_db();

        $stmt = $conn->prepare(
            'SELECT
                SUM(called_at >= DATE_SUB(NOW(), INTERVAL 1 MINUTE)) AS last_minute,
                SUM(called_at >= DATE_SUB(NOW(), INTERVAL 1 DAY))    AS last_day
             FROM api_rate_log
             WHERE provider = ?'
        );
        $stmt->bind_param('s', $provider);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        $lastMinute = (int) ($row['last_minute'] ?? 0);
        $lastDay    = (int) ($row['last_day'] ?? 0);

        if ($lastMinute >= $limits['per_minute']) {
            return sprintf(
                '%s per-minute quota reached (%d/min). Wait about a minute and try again.',
                ucfirst($provider),
                $limits['per_minute']
            );
        }
        if ($lastDay >= $limits['per_day']) {
            return sprintf(
                '%s daily quota reached (%d/day). It resets 24 hours after the first call.',
                ucfirst($provider),
                $limits['per_day']
            );
        }

        return null;
    }

    public static function recordCall(string $provider): void
    {
        $conn = secuscan_db();
        $stmt = $conn->prepare('INSERT INTO api_rate_log (provider, called_at) VALUES (?, NOW())');
        $stmt->bind_param('s', $provider);
        $stmt->execute();
        $stmt->close();

        // Keep the table small; anything older than a day is irrelevant.
        $conn->query('DELETE FROM api_rate_log WHERE called_at < DATE_SUB(NOW(), INTERVAL 2 DAY)');
    }

    /** @return array{last_minute:int,last_day:int} */
    public static function usage(string $provider): array
    {
        $conn = secuscan_db();
        $stmt = $conn->prepare(
            'SELECT
                SUM(called_at >= DATE_SUB(NOW(), INTERVAL 1 MINUTE)) AS last_minute,
                SUM(called_at >= DATE_SUB(NOW(), INTERVAL 1 DAY))    AS last_day
             FROM api_rate_log WHERE provider = ?'
        );
        $stmt->bind_param('s', $provider);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        return [
            'last_minute' => (int) ($row['last_minute'] ?? 0),
            'last_day'    => (int) ($row['last_day'] ?? 0),
        ];
    }
}
