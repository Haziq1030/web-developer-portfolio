<?php
/**
 * Minimal cURL wrapper with strict TLS, timeouts and structured errors.
 *
 * Every method returns:
 *   ['ok' => bool, 'code' => int, 'body' => string, 'json' => array|null, 'error' => string]
 *
 * It never throws and never returns a bare false — callers must be able to tell
 * "clean" apart from "the request failed", which is the single most important
 * property of a security scanner.
 */
class HttpClient
{
    /**
     * @param array<string,string> $headers
     */
    public static function get(string $url, array $headers = [], int $timeout = HTTP_TIMEOUT): array
    {
        return self::request('GET', $url, $headers, null, $timeout);
    }

    /** Upload one local file as multipart/form-data to a provider endpoint. */
    public static function uploadFile(string $url, string $field, string $filePath, array $headers = [], int $timeout = HTTP_TIMEOUT): array
    {
        if (!function_exists('curl_init')) {
            return self::fail('The PHP cURL extension is not enabled.');
        }
        if (!is_file($filePath) || !is_readable($filePath)) {
            return self::fail('The file could not be read for upload.');
        }
        $ch = curl_init();
        $headers['Accept'] = $headers['Accept'] ?? 'application/json';
        $headerLines = [];
        foreach ($headers as $name => $value) $headerLines[] = $name . ': ' . $value;
        curl_setopt_array($ch, [
            CURLOPT_URL => $url, CURLOPT_POST => true, CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER => $headerLines, CURLOPT_POSTFIELDS => [$field => curl_file_create($filePath)],
            CURLOPT_TIMEOUT => $timeout, CURLOPT_CONNECTTIMEOUT => HTTP_CONNECT_TIMEOUT,
            CURLOPT_FOLLOWLOCATION => true, CURLOPT_MAXREDIRS => 3, CURLOPT_USERAGENT => HTTP_USER_AGENT,
            CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2,
        ]);
        if (CA_BUNDLE_PATH !== '' && is_file(CA_BUNDLE_PATH)) curl_setopt($ch, CURLOPT_CAINFO, CA_BUNDLE_PATH);
        $raw = curl_exec($ch); $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE); $err = curl_error($ch); curl_close($ch);
        if ($raw === false) return self::fail($err !== '' ? $err : 'The upload request failed.', $code);
        $decoded = json_decode((string) $raw, true);
        return ['ok' => $code >= 200 && $code < 300, 'code' => $code, 'body' => (string) $raw, 'json' => is_array($decoded) ? $decoded : null, 'error' => ''];
    }

    /**
     * @param array<string,string> $headers
     */
    public static function request(
        string $method,
        string $url,
        array $headers = [],
        ?string $body = null,
        int $timeout = HTTP_TIMEOUT
    ): array {
        if (!function_exists('curl_init')) {
            return self::fail('The PHP cURL extension is not enabled. Uncomment extension=curl in php.ini and restart Apache.');
        }

        $ch = curl_init();

        $headerLines = [];
        foreach ($headers as $name => $value) {
            $headerLines[] = $name . ': ' . $value;
        }

        curl_setopt_array($ch, [
            CURLOPT_URL            => $url,
            CURLOPT_CUSTOMREQUEST  => $method,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HTTPHEADER     => $headerLines,
            CURLOPT_TIMEOUT        => $timeout,
            CURLOPT_CONNECTTIMEOUT => HTTP_CONNECT_TIMEOUT,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 3,
            CURLOPT_USERAGENT      => HTTP_USER_AGENT,
            CURLOPT_ENCODING       => '',      // accept gzip
            // TLS verification stays ON. See config.php CA_BUNDLE_PATH if this
            // fails on XAMPP for Windows.
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);

        if (CA_BUNDLE_PATH !== '' && is_file(CA_BUNDLE_PATH)) {
            curl_setopt($ch, CURLOPT_CAINFO, CA_BUNDLE_PATH);
        }

        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }

        $raw  = curl_exec($ch);
        $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $err  = curl_error($ch);
        curl_close($ch);

        if ($raw === false) {
            return self::fail($err !== '' ? $err : 'The request failed for an unknown reason.', $code);
        }

        $json = null;
        $decoded = json_decode((string) $raw, true);
        if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
            $json = $decoded;
        }

        return [
            'ok'    => $code >= 200 && $code < 300,
            'code'  => $code,
            'body'  => (string) $raw,
            'json'  => $json,
            'error' => '',
        ];
    }

    private static function fail(string $message, int $code = 0): array
    {
        return ['ok' => false, 'code' => $code, 'body' => '', 'json' => null, 'error' => $message];
    }
}
