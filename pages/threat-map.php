<?php
/**
 * Threat Map — two layers over one world map.
 *
 *   Campus  : countries the IPs your students looked up are hosted in
 *             (ip_scan_logs.country_code, already collected)
 *   Global  : countries hosting recent ThreatFox indicators, geolocated locally
 *
 * The map library is loaded from a CDN. If that fails — offline lab, blocked
 * CDN — the ranked table below still renders from the same data, so the page
 * never becomes useless. That table is also the accessible view: colour is
 * never the only way to read this page.
 */
require_once __DIR__ . '/../services/GeoIpService.php';
require_once __DIR__ . '/../services/ThreatFoxService.php';

$layer = ($_GET['layer'] ?? 'campus') === 'global' ? 'global' : 'campus';
$conn = secuscan_db();
$geoReady = GeoIpService::isReady();

// ---------------------------------------------------------------------------
// Pull the counts for the selected layer
// ---------------------------------------------------------------------------
$rows = [];
$layerNote = '';

if ($layer === 'campus') {
    $sql = "SELECT i.country_code AS iso,
                   COALESCE(NULLIF(c.country_name,''), i.country_code) AS name,
                   COUNT(*) AS total,
                   SUM(i.verdict IN ('malicious','suspicious')) AS flagged,
                   MAX(i.abuse_score) AS worst_score
            FROM ip_scan_logs i
            LEFT JOIN geoip_country c ON c.iso_code = i.country_code
            WHERE i.country_code <> ''
            GROUP BY i.country_code, name
            ORDER BY total DESC";
    $layerNote = 'Every IP a student has looked up, grouped by where it is hosted. '
               . 'Hosting country is not the attacker\'s location — rented infrastructure is the norm.';
} else {
    $sql = "SELECT o.iso_code AS iso,
                   COALESCE(NULLIF(c.country_name,''), o.iso_code) AS name,
                   COUNT(*) AS total,
                   COUNT(*) AS flagged,
                   MAX(o.confidence) AS worst_score
            FROM threat_observations o
            LEFT JOIN geoip_country c ON c.iso_code = o.iso_code
            WHERE o.iso_code <> ''
            GROUP BY o.iso_code, name
            ORDER BY total DESC";
    $layerNote = 'Command-and-control and malware-distribution hosts reported to the community feed '
               . 'in the last few days, geolocated to the network that hosts them.';
}

try {
    $res = $conn->query($sql);
    while ($res && $row = $res->fetch_assoc()) {
        $rows[] = [
            'iso'     => (string) $row['iso'],
            'name'    => (string) $row['name'],
            'total'   => (int) $row['total'],
            'flagged' => (int) $row['flagged'],
            'worst'   => (int) $row['worst_score'],
        ];
    }
} catch (Throwable $ex) {
    $rows = [];
}

$grandTotal = array_sum(array_column($rows, 'total'));
$maxTotal   = $rows ? max(array_column($rows, 'total')) : 0;

// ---------------------------------------------------------------------------
// Bin each country onto the validated 5-step ramp.
//
// Bins are on a log scale: observation counts are heavily skewed — one country
// routinely holds ten times the next — and a linear split would leave every
// country but the top one in the palest band, which is a map that says nothing.
// ---------------------------------------------------------------------------
$ramp = MAP_RAMP;
$steps = count($ramp);
$fills = [];
$binOf = [];

foreach ($rows as $row) {
    if ($maxTotal <= 0) { continue; }
    $ratio = log(1 + $row['total']) / log(1 + $maxTotal);
    $bin = (int) floor($ratio * $steps);
    $bin = max(0, min($steps - 1, $bin));
    $fills[$row['iso']] = $ramp[$bin];
    $binOf[$row['iso']] = $bin;
}

// Legend thresholds, derived from the same log split so the labels are true.
$legend = [];
for ($i = 0; $i < $steps; $i++) {
    $lo = (int) ceil(exp(($i / $steps) * log(1 + $maxTotal)) - 1);
    $hi = (int) floor(exp((($i + 1) / $steps) * log(1 + $maxTotal)) - 1);
    $legend[] = ['color' => $ramp[$i], 'lo' => max($lo, $i === 0 ? 1 : $lo), 'hi' => $hi];
}

$tfStats = ['total' => 0, 'located' => 0, 'newest' => null];
try { $tfStats = ThreatFoxService::stats(); } catch (Throwable $ex) {}
?>
<div class="row g-4 mb-4">
  <div class="col-lg-8">
    <div class="clean-card p-4 h-100">
      <div class="d-flex justify-content-between align-items-start flex-wrap gap-3 mb-3">
        <div>
          <div class="eyebrow">Threat map</div>
          <h2 class="h4 fw-bold mb-1"><?php echo $layer === 'campus' ? 'Campus lookups by country' : 'Global indicators by country'; ?></h2>
          <small class="text-muted"><?php echo e($layerNote); ?></small>
        </div>
        <div class="btn-group btn-group-sm" role="group">
          <a href="index.php?page=threat-map&amp;layer=campus"
             class="btn <?php echo $layer === 'campus' ? 'btn-primary' : 'btn-outline-primary'; ?>">Campus</a>
          <a href="index.php?page=threat-map&amp;layer=global"
             class="btn <?php echo $layer === 'global' ? 'btn-primary' : 'btn-outline-primary'; ?>">Global</a>
        </div>
      </div>

      <?php if (empty($rows)): ?>
        <div class="text-center py-5">
          <i class="fa-solid fa-earth-asia fs-1 text-primary opacity-50 mb-3 d-block"></i>
          <h3 class="h6 fw-bold">Nothing to plot yet</h3>
          <p class="text-muted small mb-0">
            <?php if ($layer === 'campus'): ?>
              Run a few lookups on the IP Scanner page and they will appear here.
            <?php elseif (!$geoReady): ?>
              The GeoLite2 database has not been imported. Run <code>import_geolite.php</code> first.
            <?php else: ?>
              No global indicators stored yet. Use the refresh button in the panel on the right.
            <?php endif; ?>
          </p>
        </div>
      <?php else: ?>
        <div id="threat-map" style="height:420px"></div>
        <div id="map-unavailable" class="text-center py-4" hidden>
          <i class="fa-solid fa-map fs-3 text-muted opacity-50 mb-2 d-block"></i>
          <small class="text-muted">
            The map graphic could not load. The full ranking is in the table below — no data is missing.
          </small>
        </div>

        <div class="d-flex flex-wrap align-items-center gap-3 mt-3 pt-3 border-top">
          <small class="text-muted fw-bold">OBSERVATIONS</small>
          <div class="d-flex align-items-center gap-1">
            <?php foreach ($legend as $i => $bin): ?>
              <span class="d-inline-block" style="width:34px;height:12px;border-radius:2px;background:<?php echo e($bin['color']); ?>"
                    title="<?php echo (int) $bin['lo']; ?><?php echo $bin['hi'] > $bin['lo'] ? '–' . (int) $bin['hi'] : ''; ?>"></span>
            <?php endforeach; ?>
          </div>
          <small class="text-muted">low <i class="fa-solid fa-arrow-right mx-1"></i> high</small>
          <small class="text-muted ms-auto">
            <?php echo number_format($grandTotal); ?> observation<?php echo $grandTotal === 1 ? '' : 's'; ?>
            across <?php echo count($rows); ?> countries
          </small>
        </div>
      <?php endif; ?>
    </div>
  </div>

  <div class="col-lg-4">
    <div class="clean-card p-4 mb-4">
      <div class="section-title mb-3">What this map is not</div>
      <p class="small text-muted mb-2">
        These are not attacks in flight. Nothing here is live, and no laser flies between
        countries — the public maps that show that are largely animation.
      </p>
      <p class="small text-muted mb-0">
        A colour here means <strong>how many indicators are hosted in that country</strong>.
        Attackers rent servers wherever it is cheap, so a bright country often means a large
        hosting industry rather than a hostile one.
      </p>
    </div>

    <div class="clean-card p-4 mb-4">
      <div class="section-title mb-3">Global feed</div>
      <div class="d-flex justify-content-between small mb-2">
        <span>Indicators stored</span><strong><?php echo number_format($tfStats['total']); ?></strong>
      </div>
      <div class="d-flex justify-content-between small mb-2">
        <span>Geolocated</span><strong><?php echo number_format($tfStats['located']); ?></strong>
      </div>
      <div class="d-flex justify-content-between small mb-3">
        <span>Last import</span>
        <strong><?php echo $tfStats['newest'] ? e(date('Y-m-d H:i', strtotime($tfStats['newest']))) : '—'; ?></strong>
      </div>

      <?php if (!$geoReady): ?>
        <div class="alert alert-warning small rounded-3 mb-0">
          GeoLite2 not imported — run <code>import_geolite.php</code>.
        </div>
      <?php elseif (secuscan_key('THREATFOX_API_KEY') === ''): ?>
        <div class="alert alert-secondary small rounded-3 mb-0">
          No feed key set. Add a free Auth-Key from
          <a href="https://auth.abuse.ch/" target="_blank" rel="noopener noreferrer">auth.abuse.ch</a>
          to <code>config.php</code>.
        </div>
      <?php else: ?>
        <form method="post">
          <?php echo csrf_field(); ?>
          <button name="refresh_threatfox" class="btn btn-outline-primary btn-sm w-100">
            <i class="fa-solid fa-rotate me-1"></i>Refresh global feed
          </button>
        </form>
        <small class="text-muted d-block mt-2" style="font-size:.75rem">
          Pulls the last 24 hours of community indicators and geolocates them locally.
        </small>
      <?php endif; ?>
    </div>

    <div class="clean-card p-4">
      <div class="section-title mb-3">Location Lookup Table</div>
      <?php $gs = $geoReady ? GeoIpService::stats() : ['blocks' => 0, 'countries' => 0]; ?>
      <div class="d-flex justify-content-between small mb-2">
        <span>IP blocks</span><strong><?php echo number_format($gs['blocks']); ?></strong>
      </div>
      <div class="d-flex justify-content-between small">
        <span>Countries</span><strong><?php echo number_format($gs['countries']); ?></strong>
      </div>
    </div>
  </div>
</div>

<?php if (!empty($rows)): ?>
<div class="clean-card p-4">
  <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
    <div>
      <div class="section-title">Ranked by country</div>
      <small class="text-muted">The same data as the map, readable without colour.</small>
    </div>
    <span class="badge text-bg-primary rounded-pill"><?php echo count($rows); ?> countries</span>
  </div>
  <div class="table-responsive">
    <table class="table table-hover align-middle mb-0">
      <thead>
        <tr>
          <th style="width:44px">#</th>
          <th>Country</th>
          <th style="width:34%">Observations</th>
          <th class="text-end">Count</th>
          <th class="text-end"><?php echo $layer === 'campus' ? 'Flagged' : 'Top confidence'; ?></th>
        </tr>
      </thead>
      <tbody>
        <?php foreach (array_slice($rows, 0, 25) as $i => $row): ?>
          <tr>
            <td class="text-muted"><?php echo $i + 1; ?></td>
            <td>
              <span class="d-inline-block me-2 align-middle"
                    style="width:10px;height:10px;border-radius:2px;background:<?php echo e($fills[$row['iso']] ?? MAP_EMPTY_FILL); ?>"></span>
              <strong><?php echo e($row['name']); ?></strong>
              <small class="text-muted ms-1"><?php echo e($row['iso']); ?></small>
            </td>
            <td>
              <div class="mini-bar">
                <span style="width:<?php echo $maxTotal > 0 ? max(3, round($row['total'] / $maxTotal * 100)) : 0; ?>%;
                             background:<?php echo e($fills[$row['iso']] ?? MAP_EMPTY_FILL); ?>"></span>
              </div>
            </td>
            <td class="text-end fw-bold" style="font-variant-numeric:tabular-nums"><?php echo number_format($row['total']); ?></td>
            <td class="text-end" style="font-variant-numeric:tabular-nums">
              <?php if ($layer === 'campus'): ?>
                <?php echo $row['flagged'] > 0
                    ? '<span class="badge text-bg-danger rounded-pill">' . (int) $row['flagged'] . '</span>'
                    : '<span class="text-muted">0</span>'; ?>
              <?php else: ?>
                <span class="text-muted"><?php echo (int) $row['worst']; ?>%</span>
              <?php endif; ?>
            </td>
          </tr>
        <?php endforeach; ?>
      </tbody>
    </table>
  </div>
  <?php if (count($rows) > 25): ?>
    <small class="text-muted d-block mt-3">Showing the top 25 of <?php echo count($rows); ?> countries.</small>
  <?php endif; ?>
</div>

<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/jsvectormap@1.7.0/dist/jsvectormap.min.css">
<script src="https://cdn.jsdelivr.net/npm/jsvectormap@1.7.0/dist/jsvectormap.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/jsvectormap@1.7.0/dist/maps/world.js"></script>
<script>
document.addEventListener('DOMContentLoaded', function () {
    var host = document.getElementById('threat-map');
    var fallback = document.getElementById('map-unavailable');
    if (!host) { return; }

    // The CDN may be unreachable. Say so and lean on the table rather than
    // leaving an empty box that looks like a bug.
    if (typeof jsVectorMap === 'undefined') {
        host.hidden = true;
        if (fallback) { fallback.hidden = false; }
        return;
    }

    var fills  = <?php echo json_encode($fills, JSON_UNESCAPED_SLASHES); ?>;
    var counts = <?php echo json_encode(array_column($rows, 'total', 'iso'), JSON_UNESCAPED_SLASHES); ?>;
    var names  = <?php echo json_encode(array_column($rows, 'name', 'iso'), JSON_UNESCAPED_SLASHES); ?>;

    try {
        new jsVectorMap({
            selector: '#threat-map',
            map: 'world',
            zoomButtons: true,
            backgroundColor: 'transparent',
            regionStyle: {
                initial: {
                    fill: <?php echo json_encode(MAP_EMPTY_FILL); ?>,
                    stroke: '#0b1526',
                    strokeWidth: 0.5
                },
                hover: { fillOpacity: 1, stroke: '#7dd3fc', strokeWidth: 1 }
            },
            // Colours are computed in PHP from the validated ramp and passed in
            // per country, so what renders is exactly the binning the legend
            // describes — no client-side interpolation to drift out of step.
            onLoaded: function (map) {
                try { map.regions && Object.keys(fills).forEach(function (iso) {
                    if (map.regions[iso]) {
                        map.regions[iso].element.setStyle('fill', fills[iso]);
                    }
                }); } catch (e) { /* styling is cosmetic; the table carries the data */ }
            },
            onRegionTooltipShow: function (event, tooltip, code) {
                if (counts[code] === undefined) {
                    tooltip.text((names[code] || code) + ' — no observations');
                    return;
                }
                tooltip.text((names[code] || code) + ' — ' + counts[code].toLocaleString() + ' observation(s)');
            }
        });
    } catch (err) {
        host.hidden = true;
        if (fallback) { fallback.hidden = false; }
    }
});
</script>
<?php endif; ?>
