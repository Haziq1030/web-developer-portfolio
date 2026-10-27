<?php
/**
 * Cybersecurity news aggregator.
 *
 * Pulls RSS/Atom from the feeds listed in config.php, normalizes them into one
 * list, sorts newest first and caches the merged result. A dead or slow feed is
 * skipped rather than taking the page down with it.
 *
 * Feed content is third-party HTML, so every field is escaped at render time
 * and links are rendered with rel="noopener noreferrer".
 */
class NewsService
{
    private const PROVIDER = 'news';
    private const CACHE_KEY = 'merged_feed';

    /**
     * @return array{items: array<int,array>, sources: array<int,array>, cached: bool, fetched_at: ?string}
     */
    public static function latest(bool $forceRefresh = false): array
    {
        if (!$forceRefresh) {
            $cached = ApiCache::get(self::PROVIDER, self::CACHE_KEY);
            if ($cached !== null) {
                return [
                    'items'      => $cached['json']['items'] ?? [],
                    'sources'    => $cached['json']['sources'] ?? [],
                    'cached'     => true,
                    'fetched_at' => $cached['fetched_at'],
                ];
            }
        }

        $items = [];
        $sources = [];

        foreach (NEWS_FEEDS as [$label, $url, $region]) {
            $outcome = self::fetchFeed($label, $url, $region);
            $sources[] = [
                'label'  => $label,
                'url'    => $url,
                'region' => $region,
                'status' => $outcome['status'],
                'count'  => count($outcome['items']),
                'error'  => $outcome['error'],
            ];
            foreach ($outcome['items'] as $item) {
                $items[] = $item;
            }
        }

        // Newest first, then trim.
        usort($items, static fn($a, $b) => ($b['timestamp'] ?? 0) <=> ($a['timestamp'] ?? 0));
        $items = array_slice($items, 0, NEWS_MAX_ITEMS);

        $payload = ['items' => $items, 'sources' => $sources];
        // Only cache a run that actually produced something, so one bad network
        // moment does not pin an empty page for the whole TTL.
        if (count($items) > 0) {
            ApiCache::put(self::PROVIDER, self::CACHE_KEY, $payload, 200);
        }

        return ['items' => $items, 'sources' => $sources, 'cached' => false, 'fetched_at' => null];
    }

    /**
     * @return array{items: array<int,array>, status: string, error: string}
     */
    private static function fetchFeed(string $label, string $url, string $region): array
    {
        $response = HttpClient::get($url, ['Accept' => 'application/rss+xml, application/xml, text/xml, */*'], 12);

        if ($response['error'] !== '') {
            return ['items' => [], 'status' => 'error', 'error' => $response['error']];
        }
        if (!$response['ok']) {
            return ['items' => [], 'status' => 'error', 'error' => 'HTTP ' . $response['code']];
        }

        $previous = libxml_use_internal_errors(true);
        // LIBXML_NOCDATA folds CDATA into plain text; LIBXML_NONET blocks any
        // external entity fetch, which is the XXE defence for untrusted XML.
        $xml = simplexml_load_string($response['body'], 'SimpleXMLElement', LIBXML_NOCDATA | LIBXML_NONET);
        libxml_clear_errors();
        libxml_use_internal_errors($previous);

        if ($xml === false) {
            return ['items' => [], 'status' => 'error', 'error' => 'Response was not valid XML.'];
        }

        $items = [];

        // RSS 2.0
        if (isset($xml->channel->item)) {
            foreach ($xml->channel->item as $node) {
                $items[] = self::normalize(
                    (string) $node->title,
                    (string) $node->link,
                    (string) ($node->description ?? ''),
                    (string) ($node->pubDate ?? ''),
                    $label,
                    $region
                );
            }
        // Atom
        } elseif (isset($xml->entry)) {
            foreach ($xml->entry as $node) {
                $link = '';
                foreach ($node->link as $linkNode) {
                    $rel = (string) ($linkNode['rel'] ?? 'alternate');
                    if ($rel === 'alternate' || $rel === '') {
                        $link = (string) $linkNode['href'];
                        break;
                    }
                }
                if ($link === '' && isset($node->link[0]['href'])) {
                    $link = (string) $node->link[0]['href'];
                }
                $items[] = self::normalize(
                    (string) $node->title,
                    $link,
                    (string) ($node->summary ?? $node->content ?? ''),
                    (string) ($node->updated ?? $node->published ?? ''),
                    $label,
                    $region
                );
            }
        } else {
            return ['items' => [], 'status' => 'empty', 'error' => 'No <item> or <entry> elements found.'];
        }

        $items = array_values(array_filter($items, static fn($i) => $i['title'] !== '' && $i['link'] !== ''));

        return ['items' => $items, 'status' => 'ok', 'error' => ''];
    }

    private static function normalize(
        string $title,
        string $link,
        string $description,
        string $date,
        string $source,
        string $region
    ): array {
        $timestamp = $date !== '' ? strtotime($date) : false;

        // Strip the publisher's markup; we re-escape on output anyway, but this
        // keeps the summary readable rather than a wall of tags.
        $clean = trim(html_entity_decode(strip_tags($description), ENT_QUOTES | ENT_HTML5, 'UTF-8'));
        $clean = preg_replace('/\s+/u', ' ', $clean) ?? '';

        // Only allow http(s) links through — a feed is untrusted input and
        // javascript: in an href is a stored XSS waiting to happen.
        $scheme = strtolower((string) parse_url($link, PHP_URL_SCHEME));
        if ($scheme !== 'http' && $scheme !== 'https') {
            $link = '';
        }

        return [
            'title'     => trim($title),
            'link'      => $link,
            'summary'   => mb_substr($clean, 0, 260),
            'source'    => $source,
            'region'    => $region,
            'published' => $timestamp !== false ? date('Y-m-d H:i', $timestamp) : '',
            'timestamp' => $timestamp !== false ? $timestamp : 0,
        ];
    }

    /**
     * Countries an article appears to concern.
     *
     * Keyword matching, so treat it as a hint. An article that mentions a
     * country once gets tagged with it, and one that names none stays
     * untagged — which is why the page offers "All" rather than forcing every
     * article into a bucket.
     *
     * @return array<int,string>
     */
    public static function countriesFor(array $item): array
    {
        // Pad with spaces so keywords ending in a space ("fbi ") can match at
        // the very start or end of the text too.
        $haystack = ' ' . strtolower(($item['title'] ?? '') . ' ' . ($item['summary'] ?? '')) . ' ';

        $found = [];
        foreach (NEWS_COUNTRIES as $country => $needles) {
            foreach ($needles as $needle) {
                if (str_contains($haystack, $needle)) {
                    $found[] = $country;
                    break;
                }
            }
        }
        // A single article rarely concerns five countries; keep the card readable.
        return array_slice($found, 0, 3);
    }

    /** Rough keyword tagging so the dashboard can highlight what matters. */
    public static function tagsFor(array $item): array
    {
        $haystack = strtolower($item['title'] . ' ' . $item['summary']);
        $map = [
            'Ransomware'    => ['ransomware', 'lockbit', 'ransom'],
            'Phishing'      => ['phishing', 'smishing', 'credential harvest'],
            'Zero-day'      => ['zero-day', 'zero day', '0-day'],
            'CVE'           => ['cve-'],
            'Data breach'   => ['breach', 'data leak', 'leaked'],
            'Malware'       => ['malware', 'trojan', 'infostealer', 'botnet'],
            'Patch'         => ['patch', 'update available', 'security update'],
            'APT'           => ['apt', 'state-sponsored', 'nation-state'],
        ];
        $tags = [];
        foreach ($map as $tag => $needles) {
            foreach ($needles as $needle) {
                if (str_contains($haystack, $needle)) {
                    $tags[] = $tag;
                    break;
                }
            }
        }
        return array_slice($tags, 0, 3);
    }
}
