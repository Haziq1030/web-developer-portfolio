<?php
/**
 * GeoIP lookup backed by the MaxMind GeoLite2 Country CSV, imported into MySQL.
 *
 * Why CSV-into-MySQL rather than the .mmdb binary: reading .mmdb needs either a
 * PHP extension or a Composer package, and this project's Composer setup has
 * already caused one outage. A range query on an indexed integer column needs
 * neither, is fast enough at this scale, and the data can be inspected in
 * phpMyAdmin when a result looks wrong.
 *
 * IPv6 is deliberately out of scope. The GeoLite2 IPv6 block file is much larger
 * and this tool's traffic is overwhelmingly v4; an IPv6 address simply returns no
 * country rather than a guess.
 */
class GeoIpService
{
    /** In-request memo — a feed import looks up the same networks repeatedly. */
    private static array $memo = [];

    /**
     * @return array{iso:string, name:string, continent:string}|null
     */
    public static function lookup(string $ip): ?array
    {
        $ip = trim($ip);

        if (isset(self::$memo[$ip])) {
            return self::$memo[$ip];
        }

        $long = self::ipToLong($ip);
        if ($long === null) {
            return self::$memo[$ip] = null;
        }

        $conn = secuscan_db();

        // The row we want is the last block that starts at or before this
        // address; end_ip is then checked to confirm the address really falls
        // inside it rather than in an unallocated gap.
        $stmt = $conn->prepare(
            'SELECT b.end_ip, c.iso_code, c.country_name, c.continent
             FROM geoip_block b
             LEFT JOIN geoip_country c ON c.geoname_id = b.geoname_id
             WHERE b.start_ip <= ?
             ORDER BY b.start_ip DESC
             LIMIT 1'
        );
        $stmt->bind_param('i', $long);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        if (!$row || (int) $row['end_ip'] < $long || ($row['iso_code'] ?? '') === '') {
            return self::$memo[$ip] = null;
        }

        return self::$memo[$ip] = [
            'iso'       => (string) $row['iso_code'],
            'name'      => (string) $row['country_name'],
            'continent' => (string) $row['continent'],
        ];
    }

    /**
     * IPv4 dotted-quad to unsigned 32-bit, as a signed int for bind_param('i').
     *
     * Addresses above 127.255.255.255 exceed PHP's signed 32-bit range on some
     * builds, so the value is wrapped the same way MySQL's INT UNSIGNED column
     * stores it — the comparison stays correct because both sides wrap alike.
     */
    public static function ipToLong(string $ip): ?int
    {
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return null;
        }
        $long = ip2long($ip);
        return $long === false ? null : $long;
    }

    /** Is the imported database usable? */
    public static function isReady(): bool
    {
        try {
            $conn = secuscan_db();
            $res = $conn->query('SELECT COUNT(*) AS total FROM geoip_block');
            return $res && (int) ($res->fetch_assoc()['total'] ?? 0) > 0;
        } catch (Throwable $ex) {
            return false;
        }
    }

    /** @return array{blocks:int, countries:int} */
    public static function stats(): array
    {
        $conn = secuscan_db();
        $blocks = (int) ($conn->query('SELECT COUNT(*) AS t FROM geoip_block')->fetch_assoc()['t'] ?? 0);
        $countries = (int) ($conn->query('SELECT COUNT(*) AS t FROM geoip_country')->fetch_assoc()['t'] ?? 0);
        return ['blocks' => $blocks, 'countries' => $countries];
    }

    /**
     * Expand a CIDR block into its first and last address.
     *
     * @return array{0:int,1:int}|null
     */
    public static function cidrRange(string $cidr): ?array
    {
        $parts = explode('/', trim($cidr));
        if (count($parts) !== 2) {
            return null;
        }
        $base = self::ipToLong($parts[0]);
        $bits = (int) $parts[1];
        if ($base === null || $bits < 0 || $bits > 32) {
            return null;
        }
        // Mask everything back to 32 bits. On 64-bit PHP the bitwise operators
        // work on 64-bit integers, so a plain ~$mask sets the high 32 bits too
        // and a /0 block ends up with end_ip = -1 — a range that matches
        // nothing. 0xFFFFFFFF keeps the arithmetic in IPv4 space.
        $mask  = $bits === 0 ? 0 : ((-1 << (32 - $bits)) & 0xFFFFFFFF);
        $start = $base & $mask & 0xFFFFFFFF;
        $end   = ($start | (~$mask & 0xFFFFFFFF)) & 0xFFFFFFFF;
        return [$start, $end];
    }
}
