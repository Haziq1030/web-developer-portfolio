<?php
/**
 * Cybersecurity News page.
 * Expects: e() helper. Reads ?refresh=1 to bypass the cache.
 */
require_once __DIR__ . '/../services/NewsService.php';

$forceRefresh = isset($_GET['refresh']);
$feed = NewsService::latest($forceRefresh);
$items = $feed['items'];
$sources = $feed['sources'];

$activeSource  = trim((string) ($_GET['source'] ?? ''));
$activeTag     = trim((string) ($_GET['tag'] ?? ''));
$activeCountry = trim((string) ($_GET['country'] ?? ''));

// Counts are taken from the articles actually on this page. Using the raw
// per-feed totals was misleading: a feed could report 50 while only a handful
// survived the trim to NEWS_MAX_ITEMS, so the number never matched what a
// student could click through to.
$allTags = [];
$allCountries = [];
$sourceCounts = [];
foreach ($items as $item) {
    $sourceCounts[$item['source']] = ($sourceCounts[$item['source']] ?? 0) + 1;
    foreach (NewsService::tagsFor($item) as $tag) {
        $allTags[$tag] = ($allTags[$tag] ?? 0) + 1;
    }
    foreach (NewsService::countriesFor($item) as $country) {
        $allCountries[$country] = ($allCountries[$country] ?? 0) + 1;
    }
}
arsort($allTags);
arsort($allCountries);

// Pinned countries stay visible even at zero, so the local view is always there.
foreach (NEWS_PINNED_COUNTRIES as $pinned) {
    if (!isset($allCountries[$pinned])) {
        $allCountries[$pinned] = 0;
    }
}

/** Rebuild the query string, changing one filter and keeping the rest. */
function news_link(array $current, string $key, string $value): string
{
    $params = array_filter([
        'page'    => 'news',
        'source'  => $current['source'],
        'tag'     => $current['tag'],
        'country' => $current['country'],
    ], static fn($v) => $v !== '');
    if ($value === '') { unset($params[$key]); } else { $params[$key] = $value; }
    return 'index.php?' . http_build_query($params);
}

/** Refresh keeps whatever filters are active. */
function news_refresh_link(array $current): string
{
    $params = array_filter([
        'page'    => 'news',
        'source'  => $current['source'],
        'tag'     => $current['tag'],
        'country' => $current['country'],
        'refresh' => '1',
    ], static fn($v) => $v !== '');
    return 'index.php?' . http_build_query($params);
}
$filters = ['source' => $activeSource, 'tag' => $activeTag, 'country' => $activeCountry];

$visible = array_values(array_filter($items, static function (array $item) use ($activeSource, $activeTag, $activeCountry) {
    if ($activeSource !== '' && $item['source'] !== $activeSource) {
        return false;
    }
    if ($activeTag !== '' && !in_array($activeTag, NewsService::tagsFor($item), true)) {
        return false;
    }
    if ($activeCountry !== '' && !in_array($activeCountry, NewsService::countriesFor($item), true)) {
        return false;
    }
    return true;
}));

$liveSources = array_values(array_filter($sources, static fn($s) => $s['status'] === 'ok'));
$deadSources = array_values(array_filter($sources, static fn($s) => $s['status'] !== 'ok'));
?>
<div class="info-banner mb-4">
  <div class="row align-items-center">
    <div class="col-lg-8">
      <div class="eyebrow text-white opacity-75">Threat intelligence feed</div>
      <h2 class="h3 fw-bold mt-2">Cybersecurity News</h2>
      <p class="mb-0 opacity-75">
        Aggregated from <?php echo count($liveSources); ?> security publication<?php echo count($liveSources) === 1 ? '' : 's'; ?>.
        <?php if ($feed['cached']): ?>
          Cached copy from <?php echo e((string) $feed['fetched_at']); ?>.
        <?php else: ?>
          Fetched just now.
        <?php endif; ?>
      </p>
    </div>
    <div class="col-lg-4 text-lg-end mt-3 mt-lg-0">
      <a href="<?php echo e(news_refresh_link($filters)); ?>" class="btn btn-light btn-sm fw-bold">
        <i class="fa-solid fa-rotate me-1"></i>Refresh now
      </a>
    </div>
  </div>
</div>

<?php if (!empty($deadSources)): ?>
  <?php
    // A skipped feed is an operations problem, not the student's. It gets a
    // quiet line at the bottom of the page rather than a warning banner at the
    // top — the articles that did load are what they came for. Administrators
    // see the full per-feed detail in api_test.php.
    $deadNames = implode(', ', array_map(static fn($s) => $s['label'], $deadSources));
  ?>
<?php endif; ?>

<div class="clean-card p-3 mb-4">
  <div class="d-flex flex-wrap gap-2 align-items-center">
    <small class="text-muted fw-bold me-2" style="min-width:62px">SOURCE</small>
    <a href="<?php echo e(news_link($filters, 'source', '')); ?>"
       class="btn btn-sm <?php echo $activeSource === '' ? 'btn-primary' : 'btn-outline-primary'; ?> rounded-pill">All</a>
    <?php foreach ($sourceCounts as $label => $count): ?>
      <a href="<?php echo e(news_link($filters, 'source', (string) $label)); ?>"
         class="btn btn-sm <?php echo $activeSource === $label ? 'btn-primary' : 'btn-outline-primary'; ?> rounded-pill">
        <?php echo e($label); ?> <span class="opacity-75">(<?php echo (int) $count; ?>)</span>
      </a>
    <?php endforeach; ?>
  </div>

  <hr class="opacity-25 my-3">
  <div class="d-flex flex-wrap gap-2 align-items-center">
    <small class="text-muted fw-bold me-2" style="min-width:62px">COUNTRY</small>
    <a href="<?php echo e(news_link($filters, 'country', '')); ?>"
       class="btn btn-sm <?php echo $activeCountry === '' ? 'btn-primary' : 'btn-outline-primary'; ?> rounded-pill">All</a>
    <?php foreach (array_slice($allCountries, 0, 12, true) as $country => $count): ?>
      <a href="<?php echo e(news_link($filters, 'country', (string) $country)); ?>"
         class="btn btn-sm <?php echo $activeCountry === $country ? 'btn-primary' : 'btn-outline-primary'; ?> rounded-pill
                <?php echo $count === 0 ? 'opacity-50' : ''; ?>">
        <?php echo e($country); ?> <span class="opacity-75">(<?php echo (int) $count; ?>)</span>
      </a>
    <?php endforeach; ?>
  </div>
  <small class="text-muted d-block mt-2" style="font-size:.75rem">
    Country is detected from the words in each headline and summary, so treat it as a hint.
    An article that names no country will not appear under any of them.
  </small>

  <?php if (!empty($allTags)): ?>
    <hr class="opacity-25 my-3">
    <div class="d-flex flex-wrap gap-2 align-items-center">
      <small class="text-muted fw-bold me-2" style="min-width:62px">TOPIC</small>
      <a href="<?php echo e(news_link($filters, 'tag', '')); ?>"
         class="btn btn-sm <?php echo $activeTag === '' ? 'btn-primary' : 'btn-outline-primary'; ?> rounded-pill">All</a>
      <?php foreach (array_slice($allTags, 0, 8, true) as $tag => $count): ?>
        <a href="<?php echo e(news_link($filters, 'tag', (string) $tag)); ?>"
           class="btn btn-sm <?php echo $activeTag === $tag ? 'btn-primary' : 'btn-outline-primary'; ?> rounded-pill">
          <?php echo e($tag); ?> <span class="opacity-75">(<?php echo (int) $count; ?>)</span>
        </a>
      <?php endforeach; ?>
    </div>
  <?php endif; ?>
</div>

<?php if (empty($visible)): ?>
  <div class="clean-card p-5 text-center">
    <i class="fa-solid fa-newspaper fs-1 text-primary opacity-50 mb-3"></i>
    <h3 class="h5 fw-bold">No articles to show</h3>
    <p class="text-muted mb-0">
      <?php if (empty($items)): ?>
        No feed could be reached. Check your internet connection, and confirm cURL can make HTTPS requests
        by opening <code>api_test.php</code>.
      <?php else: ?>
        No article matches that combination of filters.
        <a href="index.php?page=news" class="ms-1">Clear all filters</a>
      <?php endif; ?>
    </p>
  </div>
<?php else: ?>
  <div class="row g-3">
    <?php foreach ($visible as $item): $tags = NewsService::tagsFor($item); ?>
      <div class="col-md-6">
        <div class="clean-card p-4 h-100 d-flex flex-column">
          <div class="d-flex justify-content-between align-items-start gap-2 mb-2">
            <span class="badge text-bg-primary rounded-pill"><?php echo e($item['source']); ?></span>
            <small class="text-muted text-nowrap"><?php echo e($item['published']); ?></small>
          </div>

          <h3 class="h6 fw-bold mb-2">
            <?php if ($item['link'] !== ''): ?>
              <a href="<?php echo e($item['link']); ?>" target="_blank" rel="noopener noreferrer nofollow"
                 class="text-decoration-none stretched-link">
                <?php echo e($item['title']); ?>
              </a>
            <?php else: ?>
              <?php echo e($item['title']); ?>
            <?php endif; ?>
          </h3>

          <p class="small text-muted flex-grow-1 mb-3"><?php echo e($item['summary']); ?><?php echo mb_strlen($item['summary']) >= 260 ? '…' : ''; ?></p>

          <?php $countries = NewsService::countriesFor($item); ?>
          <?php if (!empty($tags) || !empty($countries)): ?>
            <div class="d-flex flex-wrap gap-1">
              <?php foreach ($countries as $country): ?>
                <span class="badge text-bg-info rounded-pill"><i class="fa-solid fa-location-dot me-1"></i><?php echo e($country); ?></span>
              <?php endforeach; ?>
              <?php foreach ($tags as $tag): ?>
                <span class="badge text-bg-secondary rounded-pill"><?php echo e($tag); ?></span>
              <?php endforeach; ?>
            </div>
          <?php endif; ?>
        </div>
      </div>
    <?php endforeach; ?>
  </div>

  <p class="text-muted small text-center mt-4 mb-0">
    Headlines and summaries belong to their publishers and link back to the original article.
    SecuScan stores no article content beyond a <?php echo (int) round(CACHE_TTL['news'] / 60); ?>-minute cache.
    <?php if (!empty($deadSources)): ?>
      <span class="d-block mt-2 opacity-75">
        <?php echo count($deadSources); ?> source<?php echo count($deadSources) === 1 ? '' : 's'; ?>
        unavailable right now (<?php echo e($deadNames); ?>).
      </span>
    <?php endif; ?>
  </p>
<?php endif; ?>
