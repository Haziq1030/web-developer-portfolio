<?php
/**
 * SecuScan — API diagnostics.
 *
 * Verifies, in order: PHP extensions, TLS, database tables, all three API
 * keys against a known-good indicator, and every configured news feed.
 *
 * Open this FIRST after installing. It tells you exactly which piece is
 * broken instead of leaving you guessing from a blank scan result.
 *
 * DELETE THIS FILE before any public deployment — it reveals configuration
 * state, and the checks consume real API quota.
 */

declare(strict_types=1);
session_start();

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/services/ThreatResult.php';
require_once __DIR__ . '/services/HttpClient.php';
require_once __DIR__ . '/services/ApiCache.php';
require_once __DIR__ . '/services/VirusTotalService.php';
require_once __DIR__ . '/services/MetaDefenderService.php';
require_once __DIR__ . '/services/AbuseIPDBService.php';
require_once __DIR__ . '/services/NewsService.php';
require_once __DIR__ . '/services/AiAssistService.php';

// Only a logged-in admin should see this. If you have not logged in yet,
// comment the next three lines out, run the test, then put them back.
if (empty($_SESSION['user_id']) || empty($_SESSION['is_admin'])) {
    http_response_code(403);
    exit('Administrator login required. See the comment in api_test.php if you are still setting up.');
}

function e(string $v): string { return htmlspecialchars($v, ENT_QUOTES, 'UTF-8'); }
function mask(string $key): string {
    $len = strlen($key);
    if ($len === 0) { return '(not set)'; }
    if ($len <= 10) { return str_repeat('*', $len); }
    return substr($key, 0, 6) . str_repeat('*', 8) . substr($key, -4) . '  [' . $len . ' chars]';
}

$checks = [];

// ---- 1. PHP environment -----------------------------------------------
$checks[] = [
    'group' => 'Environment',
    'name'  => 'PHP version',
    'pass'  => version_compare(PHP_VERSION, '8.0.0', '>='),
    'detail' => PHP_VERSION . (version_compare(PHP_VERSION, '8.0.0', '>=') ? '' : ' — 8.0 or newer is required'),
];
foreach (['curl' => 'HTTPS requests', 'openssl' => 'TLS', 'simplexml' => 'RSS parsing', 'mysqli' => 'database', 'mbstring' => 'text handling'] as $ext => $why) {
    $checks[] = [
        'group' => 'Environment',
        'name'  => 'Extension: ' . $ext,
        'pass'  => extension_loaded($ext),
        'detail' => extension_loaded($ext)
            ? 'loaded (' . $why . ')'
            : 'MISSING — uncomment extension=' . $ext . ' in php.ini and restart Apache',
    ];
}

// ---- 2. TLS trust store ------------------------------------------------
$tls = HttpClient::get('https://www.google.com/generate_204', [], 10);
$checks[] = [
    'group' => 'Environment',
    'name'  => 'Outbound HTTPS + certificate trust',
    'pass'  => $tls['error'] === '',
    'detail' => $tls['error'] === ''
        ? 'OK (HTTP ' . $tls['code'] . ')'
        : $tls['error'] . ' — if this mentions certificates, download https://curl.se/ca/cacert.pem and set CA_BUNDLE_PATH in config.php. Never disable CURLOPT_SSL_VERIFYPEER.',
];

// ---- 3. Database -------------------------------------------------------
$dbOk = true; $dbDetail = '';
try {
    $conn = secuscan_db();
    $needed = ['api_cache', 'api_rate_log', 'hash_scan_logs', 'ip_scan_logs'];
    $missing = [];
    foreach ($needed as $table) {
        $res = $conn->query("SHOW TABLES LIKE '" . $conn->real_escape_string($table) . "'");
        if (!$res || $res->num_rows === 0) { $missing[] = $table; }
    }
    $dbOk = count($missing) === 0;
    $dbDetail = $dbOk ? 'All 5 tables present.' : 'Missing: ' . implode(', ', $missing) . ' — run api_setup.sql and ai_setup.sql';
} catch (Throwable $ex) {
    $dbOk = false;
    $dbDetail = 'Connection failed: ' . $ex->getMessage();
}
$checks[] = ['group' => 'Database', 'name' => 'Required tables', 'pass' => $dbOk, 'detail' => $dbDetail];

// ---- 4. API keys -------------------------------------------------------
// EICAR test file — the industry-standard harmless string every AV detects.
// Perfect for proving the pipeline works without touching real malware.
const EICAR_SHA256 = '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f';
// Cloudflare's public resolver: always present, always clean.
const CLEAN_TEST_IP = '1.1.1.1';

$apiResults = [];
if ($dbOk) {
    $vt = VirusTotalService::lookupHash(EICAR_SHA256);
    $apiResults[] = ['VirusTotal', secuscan_key('VIRUSTOTAL_API_KEY'), $vt,
        'EICAR test file — expect Malicious with a high engine count'];

    $md = MetaDefenderService::lookupHash(EICAR_SHA256);
    $apiResults[] = ['MetaDefender', secuscan_key('METADEFENDER_API_KEY'), $md,
        'EICAR test file — expect Malicious'];

    $ab = AbuseIPDBService::lookupIp(CLEAN_TEST_IP);
    $apiResults[] = ['AbuseIPDB', secuscan_key('ABUSEIPDB_API_KEY'), $ab,
        '1.1.1.1 (Cloudflare DNS) — expect a low abuse score'];
}

// AI Assist is checked separately: it returns text, not a ThreatResult.
$aiOn  = null;
$aiOff = null;
$aiModels = null;
if ($dbOk) {
    // Discovery first: if the key cannot list models, nothing else will work,
    // and the list itself is the answer to a 404.
    if (AI_PROVIDER === 'gemini') {
        $aiModels = AiAssistService::resolveGeminiModel(secuscan_key('AI_ASSIST_API_KEY'), isset($_GET['refresh_models']));
    }
    $aiOn  = AiAssistService::ask('In one sentence, what is phishing?', [], 0);
    $aiOff = AiAssistService::ask('Give me a recipe for nasi lemak.', [], 0);
}

// ---- 5. News feeds -----------------------------------------------------
$feedResults = [];
foreach (NEWS_FEEDS as [$label, $url, $region]) {
    $resp = HttpClient::get($url, ['Accept' => 'application/rss+xml, application/xml, text/xml, */*'], 12);
    $ok = $resp['error'] === '' && $resp['ok'];
    $itemCount = 0;
    if ($ok) {
        $prev = libxml_use_internal_errors(true);
        $xml = simplexml_load_string($resp['body'], 'SimpleXMLElement', LIBXML_NOCDATA | LIBXML_NONET);
        libxml_clear_errors();
        libxml_use_internal_errors($prev);
        if ($xml !== false) {
            $itemCount = isset($xml->channel->item) ? count($xml->channel->item) : (isset($xml->entry) ? count($xml->entry) : 0);
        }
        $ok = $itemCount > 0;
    }
    $feedResults[] = [
        'label' => $label, 'url' => $url, 'ok' => $ok, 'count' => $itemCount,
        'detail' => $resp['error'] !== '' ? $resp['error'] : ($ok ? $itemCount . ' articles' : 'HTTP ' . $resp['code'] . ' or no parseable items'),
    ];
}

$totalPass = count(array_filter($checks, static fn($c) => $c['pass']));
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SecuScan API Diagnostics</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" rel="stylesheet">
  <style>
    body{background:linear-gradient(135deg,#f8fbff 0%,#eef4ff 45%,#f1f5f9 100%);color:#0f172a;padding:32px 16px}
    .card{background:rgba(255,255,255,.96);border:1px solid #e2e8f0;border-radius:16px;box-shadow:0 18px 42px rgba(15,23,42,.05)}
    .table{--bs-table-color:#334155;--bs-table-bg:transparent}
    .table th{color:#64748b;font-size:.72rem;text-transform:uppercase;letter-spacing:.06em;border-bottom-color:rgba(148,163,184,.2)}
    .table td{border-bottom-color:rgba(148,163,184,.16);font-size:.86rem;vertical-align:middle}
    code{color:#2563eb}
    .mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.8rem}
  </style>
</head>
<body>
<div class="container" style="max-width:1000px">

  <h1 class="fw-bold mb-1"><i class="fa-solid fa-stethoscope text-info me-2"></i>SecuScan Diagnostics</h1>
  <p class="text-secondary mb-4">
    <?php echo $totalPass; ?> of <?php echo count($checks); ?> environment checks passed.
    Delete this file before deploying anywhere public.
  </p>

  <div class="card p-4 mb-4">
    <h2 class="h5 fw-bold mb-3">Environment &amp; database</h2>
    <table class="table table-sm mb-0">
      <thead><tr><th>Check</th><th>Status</th><th>Detail</th></tr></thead>
      <tbody>
      <?php foreach ($checks as $c): ?>
        <tr>
          <td class="fw-semibold"><?php echo e($c['name']); ?></td>
          <td><span class="badge <?php echo $c['pass'] ? 'text-bg-success' : 'text-bg-danger'; ?> rounded-pill">
            <?php echo $c['pass'] ? 'PASS' : 'FAIL'; ?></span></td>
          <td class="text-secondary"><?php echo e($c['detail']); ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>

  <div class="card p-4 mb-4">
    <h2 class="h5 fw-bold mb-1">API keys</h2>
    <p class="text-secondary small mb-3">Each key is tested against a known indicator. Keys are masked below.</p>

    <?php if (!$dbOk): ?>
      <div class="alert alert-warning">Run <code>api_setup.sql</code> first — the API tests need the cache tables.</div>
    <?php else: ?>
      <?php foreach ($apiResults as [$name, $key, $result, $expectation]): ?>
        <div class="border-top pt-3 mt-3">
          <div class="d-flex justify-content-between align-items-center flex-wrap gap-2 mb-2">
            <strong><?php echo e($name); ?></strong>
            <span class="badge <?php echo $result->badgeClass(); ?> rounded-pill"><?php echo e($result->label()); ?></span>
          </div>
          <div class="mono text-secondary mb-2">key: <?php echo e(mask($key)); ?></div>
          <div class="small mb-1"><span class="text-secondary">Test:</span> <?php echo e($expectation); ?></div>
          <div class="small"><span class="text-secondary">Result:</span> <?php echo e($result->summary); ?></div>
          <?php if ($result->verdict === ThreatResult::ERROR): ?>
            <div class="alert alert-danger small mt-2 mb-0"><?php echo e($result->error); ?></div>
          <?php elseif ($result->cached): ?>
            <div class="small text-info mt-1"><i class="fa-solid fa-database me-1"></i>served from cache — no quota used</div>
          <?php endif; ?>
        </div>
      <?php endforeach; ?>
    <?php endif; ?>
  </div>

  <div class="card p-4 mb-4">
    <h2 class="h5 fw-bold mb-1">AI Assist</h2>
    <p class="text-secondary small mb-3">
      Build: <code><?php echo e(defined('AiAssistService::BUILD') ? AiAssistService::BUILD : 'STALE FILE - AiAssistService.php was not replaced'); ?></code> &middot;
      Provider: <code><?php echo e(AI_PROVIDER); ?></code> &middot;
      key: <span class="mono"><?php echo e(mask(secuscan_key('AI_ASSIST_API_KEY'))); ?></span>
    </p>

    <?php if ($aiModels !== null): ?>
      <div class="border-top pt-3 mb-3">
        <div class="d-flex justify-content-between align-items-center mb-2 flex-wrap gap-2">
          <strong>Models this key can reach</strong>
          <a href="api_test.php?refresh_models=1" class="btn btn-sm btn-outline-info rounded-pill">
            Re-check
          </a>
        </div>
        <?php if ($aiModels['model'] !== ''): ?>
          <p class="small mb-2">
            Selected: <code><?php echo e($aiModels['model']); ?></code>
            <span class="text-secondary">(chosen automatically, cached for 7 days)</span>
          </p>
          <details>
            <summary class="small text-info" style="cursor:pointer">
              <?php echo count($aiModels['available']); ?> models support generateContent
            </summary>
            <div class="mono small text-secondary mt-2" style="max-height:220px;overflow:auto">
              <?php foreach ($aiModels['available'] as $m): ?>
                <div><?php echo e($m); ?><?php echo $m === $aiModels['model'] ? '  &larr; in use' : ''; ?></div>
              <?php endforeach; ?>
            </div>
          </details>
        <?php else: ?>
          <div class="alert alert-danger small mb-0">
            <?php echo e($aiModels['error']); ?>
            <div class="mt-2">
              If this mentions authentication, the key is not a Google AI Studio key. Set
              <code>AI_PROVIDER</code> in config.php to <code>openai</code> or <code>groq</code> and reload.
            </div>
          </div>
        <?php endif; ?>
      </div>
    <?php endif; ?>
    <?php if (!$dbOk): ?>
      <div class="alert alert-warning">Run <code>api_setup.sql</code> and <code>ai_setup.sql</code> first.</div>
    <?php else: ?>
      <div class="border-top pt-3">
        <div class="d-flex justify-content-between mb-2">
          <strong>In-scope question</strong>
          <span class="badge <?php echo $aiOn['ok'] ? 'text-bg-success' : 'text-bg-danger'; ?> rounded-pill">
            <?php echo $aiOn['ok'] ? 'ANSWERED' : 'FAILED'; ?></span>
        </div>
        <div class="small text-secondary mb-1">Asked: "In one sentence, what is phishing?"</div>
        <div class="small"><?php echo e($aiOn['ok'] ? $aiOn['reply'] : $aiOn['error']); ?></div>
        <?php if (!$aiOn['ok']): ?>
          <div class="alert alert-danger small mt-2 mb-0">
            If this says authentication failed, the key is probably not a
            <code><?php echo e(AI_PROVIDER); ?></code> key. Change <code>AI_PROVIDER</code> in config.php
            to <code>openai</code> or <code>groq</code> and reload this page.
          </div>
        <?php endif; ?>
      </div>
      <div class="border-top pt-3 mt-3">
        <div class="d-flex justify-content-between mb-2">
          <strong>Out-of-scope question</strong>
          <span class="badge text-bg-secondary rounded-pill">check the wording</span>
        </div>
        <div class="small text-secondary mb-1">Asked: "Give me a recipe for nasi lemak."</div>
        <div class="small"><?php echo e($aiOff['ok'] ? $aiOff['reply'] : $aiOff['error']); ?></div>
        <div class="small text-info mt-2">
          Expected: a one-line refusal offering to help with IT or security instead — NOT a recipe.
        </div>
      </div>
    <?php endif; ?>
  </div>

  <div class="card p-4">
    <h2 class="h5 fw-bold mb-1">News feeds</h2>
    <p class="text-secondary small mb-3">A failing feed is skipped at runtime, not fatal. Remove dead URLs from <code>NEWS_FEEDS</code> in config.php.</p>
    <table class="table table-sm mb-0">
      <thead><tr><th>Source</th><th>Status</th><th>Detail</th></tr></thead>
      <tbody>
      <?php foreach ($feedResults as $f): ?>
        <tr>
          <td>
            <strong><?php echo e($f['label']); ?></strong>
            <small class="d-block text-secondary mono text-break"><?php echo e($f['url']); ?></small>
          </td>
          <td><span class="badge <?php echo $f['ok'] ? 'text-bg-success' : 'text-bg-warning'; ?> rounded-pill">
            <?php echo $f['ok'] ? 'OK' : 'DEAD'; ?></span></td>
          <td class="text-secondary"><?php echo e($f['detail']); ?></td>
        </tr>
      <?php endforeach; ?>
      </tbody>
    </table>
  </div>

  <p class="text-center mt-4"><a href="index.php" class="btn btn-outline-info btn-sm">Back to SecuScan</a></p>
</div>
</body>
</html>
