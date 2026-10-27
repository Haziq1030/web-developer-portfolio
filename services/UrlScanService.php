<?php

class UrlScanService
{
    public static function scan(string $url): array
    {
        $results = [
            self::virusTotal($url),
            self::metaDefender($url),
        ];

        $host = parse_url($url, PHP_URL_HOST);
        $ip = $host ? gethostbyname($host) : '';
        $results[] = $ip !== '' && $ip !== $host
            ? AbuseIPDBService::lookupIp($ip)
            : ThreatResult::error('AbuseIPDB', 'Domain could not be resolved to a public IP address.');

        return $results;
    }

    private static function virusTotal(string $url): ThreatResult
    {
        $key = secuscan_key('VIRUSTOTAL_API_KEY');
        if ($key === '') return ThreatResult::error('VirusTotal', 'No VirusTotal API key is configured.');

        $response = HttpClient::request('POST', 'https://www.virustotal.com/api/v3/urls', [
            'x-apikey' => $key,
            'Accept' => 'application/json',
            'Content-Type' => 'application/x-www-form-urlencoded',
        ], http_build_query(['url' => $url]));

        if ($response['error'] !== '' || $response['json'] === null) {
            return ThreatResult::error('VirusTotal', 'Primary URL threat analysis is currently unavailable.');
        }
        $id = (string) ($response['json']['data']['id'] ?? '');
        if ($id === '') return ThreatResult::error('VirusTotal', 'Primary URL threat analysis returned no usable result.');

        $lookup = null;
        for ($attempt = 0; $attempt < 6; $attempt++) {
            $lookup = HttpClient::get('https://www.virustotal.com/api/v3/analyses/' . rawurlencode($id), [
                'x-apikey' => $key,
                'Accept' => 'application/json',
            ]);
            $status = (string) ($lookup['json']['data']['attributes']['status'] ?? '');
            if ($lookup['error'] === '' && $lookup['json'] !== null && $status !== 'queued' && $status !== 'in-progress') break;
            usleep(500000);
        }
        if (!$lookup || $lookup['error'] !== '' || $lookup['json'] === null) {
            return ThreatResult::error('VirusTotal', 'Primary URL threat analysis could not be completed yet.');
        }

        $stats = $lookup['json']['data']['attributes']['stats'] ?? [];
        $malicious = (int) ($stats['malicious'] ?? 0);
        $suspicious = (int) ($stats['suspicious'] ?? 0);
        $total = array_sum(array_map('intval', $stats));
        $result = new ThreatResult('VirusTotal');
        $result->verdict = $malicious > 0 ? ThreatResult::MALICIOUS : ($suspicious > 0 ? ThreatResult::SUSPICIOUS : ($total > 0 ? ThreatResult::CLEAN : ThreatResult::UNKNOWN));
        $result->score = $total > 0 ? round(($malicious + $suspicious) / $total * 100, 2) : null;
        $result->summary = "$malicious malicious and $suspicious suspicious detections out of $total engines.";
        return $result;
    }

    private static function metaDefender(string $url): ThreatResult
    {
        $key = secuscan_key('METADEFENDER_API_KEY');
        if ($key === '') return ThreatResult::error('MetaDefender', 'No MetaDefender API key is configured.');

        $response = HttpClient::request('POST', 'https://api.metadefender.com/v4/url', [
            'apikey' => $key,
            'Accept' => 'application/json',
            'Content-Type' => 'application/x-www-form-urlencoded',
        ], http_build_query(['url' => $url]));
        if ($response['error'] !== '' || $response['json'] === null) {
            return ThreatResult::error('MetaDefender', 'Secondary URL threat analysis is currently unavailable.');
        }

        $dataId = (string) ($response['json']['data_id'] ?? $response['json']['data']['data_id'] ?? '');
        if ($dataId === '') return ThreatResult::error('MetaDefender', 'Secondary URL threat analysis returned no usable result.');
        $lookup = null;
        for ($attempt = 0; $attempt < 6; $attempt++) {
            $lookup = HttpClient::get('https://api.metadefender.com/v4/url/' . rawurlencode($dataId), [
                'apikey' => $key,
                'Accept' => 'application/json',
            ]);
            $scanStatus = (string) ($lookup['json']['scan_results']['scan_all_result_a'] ?? '');
            if ($lookup['error'] === '' && $lookup['json'] !== null && stripos($scanStatus, 'progress') === false && stripos($scanStatus, 'queue') === false) break;
            usleep(500000);
        }
        if (!$lookup || $lookup['error'] !== '' || $lookup['json'] === null) {
            return ThreatResult::error('MetaDefender', 'Secondary URL threat analysis could not be completed yet.');
        }

        $scan = $lookup['json']['scan_results'] ?? [];
        $detected = (int) ($scan['total_detected_avs'] ?? 0);
        $total = (int) ($scan['total_avs'] ?? 0);
        $code = (int) ($scan['scan_all_result_i'] ?? -1);
        $result = new ThreatResult('MetaDefender');
        $result->verdict = $code === 1 ? ThreatResult::MALICIOUS : (($code === 2 || $code === 10 || $detected > 0) ? ThreatResult::SUSPICIOUS : ($total > 0 ? ThreatResult::CLEAN : ThreatResult::UNKNOWN));
        $result->score = $total > 0 ? round($detected / $total * 100, 2) : null;
        $result->summary = "$detected detections out of $total MetaDefender engines.";
        return $result;
    }
}
