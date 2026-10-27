<?php
/**
 * IP Scanner page. Provider is labelled via ThreatResult::displayName().
 * Expects: $ip_scan (array|null from handle_ip_scan), e() helper, csrf_field().
 */
$abuseUsage = ApiCache::usage('abuseipdb');
$currentIp = $ip_scan['ip'] ?? '';
$currentAge = (int) ($ip_scan['max_age'] ?? 90);
?>
<div class="row g-4">
  <div class="col-lg-5">
    <div class="clean-card p-4 p-lg-5 h-100">
      <span class="stat-icon mb-3"><i class="fa-solid fa-globe"></i></span>
      <h2 class="h4 fw-bold">IP Reputation Scanner</h2>
      <p class="text-muted">
        Checks an address against a community reputation database built from abuse reports
        submitted by network operators, honeypots and security teams worldwide.
      </p>

      <form method="post" class="mt-4">
        <?php echo csrf_field(); ?>

        <label class="form-label fw-semibold" for="ip_purpose">Scan Purpose</label>
        <select id="ip_purpose" name="tujuan" class="form-select mb-4" required>
          <option value="">-- Select a purpose --</option>
          <option value="Education">Education</option>
          <option value="Work">Work</option>
          <option value="Others">Others</option>
          <option value="Shopping">Shopping</option>
        </select>

        <label class="form-label fw-semibold" for="ip_input">IP address</label>
        <input type="text" id="ip_input" name="ip_input" class="form-control code-font mb-2"
               placeholder="8.8.8.8 or 2001:4860:4860::8888"
               value="<?php echo e($currentIp); ?>" required>
        <small class="text-muted d-block mb-4">IPv4 or IPv6. Private ranges have no public reputation.</small>

        <label class="form-label fw-semibold" for="max_age">Report window</label>
        <select id="max_age" name="max_age" class="form-select mb-4">
          <?php foreach ([30 => 'Last 30 days', 90 => 'Last 90 days', 180 => 'Last 180 days', 365 => 'Last 365 days'] as $days => $label): ?>
            <option value="<?php echo $days; ?>" <?php echo $currentAge === $days ? 'selected' : ''; ?>><?php echo e($label); ?></option>
          <?php endforeach; ?>
        </select>

        <button class="btn btn-primary w-100" name="scan_ip_btn">
          <i class="fa-solid fa-radar me-2"></i>Check Reputation
        </button>
      </form>

      <div class="d-flex justify-content-between small text-muted mt-4 pt-3 border-top">
        <span>Lookups used today</span>
        <strong><?php echo (int) $abuseUsage['last_day']; ?> / <?php echo RATE_LIMITS['abuseipdb']['per_day']; ?></strong>
      </div>
    </div>
  </div>

  <div class="col-lg-7">
    <?php if ($ip_scan === null): ?>
      <div class="clean-card p-5 h-100 d-flex flex-column justify-content-center text-center">
        <i class="fa-solid fa-globe fs-1 text-primary opacity-50 mb-3"></i>
        <h3 class="h5 fw-bold">No lookup yet</h3>
        <p class="text-muted mb-0">Enter an IP address to see its abuse history, hosting details and report categories.</p>
      </div>

    <?php elseif (!empty($ip_scan['error'])): ?>
      <div class="alert alert-warning rounded-4">
        <i class="fa-solid fa-triangle-exclamation me-2"></i><?php echo e($ip_scan['error']); ?>
      </div>

    <?php else: ?>
      <?php
        $r = $ip_scan['result'];
        $d = $r->detail;
        $verdictClass = [
            ThreatResult::MALICIOUS  => 'danger',
            ThreatResult::SUSPICIOUS => 'warning',
            ThreatResult::CLEAN      => 'success',
            ThreatResult::UNKNOWN    => 'secondary',
            ThreatResult::ERROR      => 'dark',
        ][$r->verdict] ?? 'secondary';
        $score = (int) ($r->score ?? 0);
      ?>

      <div class="clean-card p-4 mb-4">
        <div class="d-flex justify-content-between align-items-start flex-wrap gap-3 mb-3">
          <div>
            <div class="eyebrow"><?php echo e($r->displayName()); ?></div>
            <h2 class="h3 fw-bold text-<?php echo $verdictClass; ?> mb-1"><?php echo e($r->label()); ?></h2>
            <span class="code-font text-muted"><?php echo e($ip_scan['ip']); ?></span>
          </div>
          <div class="text-end">
            <?php if ($r->cached): ?>
              <span class="badge text-bg-secondary rounded-pill mb-2">
                <i class="fa-solid fa-database me-1"></i>cached
              </span><br>
            <?php endif; ?>
            <div class="display-5 fw-bold text-<?php echo $verdictClass; ?>"><?php echo $score; ?>%</div>
            <small class="text-muted">abuse confidence</small>
          </div>
        </div>

        <div class="mini-bar mb-2">
          <span style="width:<?php echo max(2, min(100, $score)); ?>%;background:<?php
            echo $score >= 50 ? '#ef4444' : ($score >= 15 ? '#f59e0b' : '#22c55e'); ?>"></span>
        </div>
        <p class="text-muted small mb-0"><?php echo e($r->summary); ?></p>

        <?php if ($r->verdict === ThreatResult::UNKNOWN && (int) ($d['total_reports'] ?? 0) === 0): ?>
          <div class="alert alert-secondary small mt-3 mb-0 rounded-3">
            <strong>No reports is weak evidence.</strong> It means nobody has complained about this address,
            not that it is trustworthy. Freshly rented attacker infrastructure also has zero reports.
          </div>
        <?php endif; ?>
      </div>

      <?php if ($r->verdict !== ThreatResult::ERROR): ?>
        <div class="row g-3 mb-4">
          <?php
            $facts = [
              ['Country',     trim(($d['country_name'] ?? '') . ' ' . (!empty($d['country_code']) ? '(' . $d['country_code'] . ')' : '')), 'fa-flag'],
              ['ISP',         $d['isp'] ?? '',          'fa-network-wired'],
              ['Usage type',  $d['usage_type'] ?? '',   'fa-server'],
              ['Domain',      $d['domain'] ?? '',       'fa-at'],
              ['Total reports', (string) ($d['total_reports'] ?? 0), 'fa-flag-checkered'],
              ['Last reported', $d['last_reported'] !== '' ? date('Y-m-d H:i', strtotime((string) $d['last_reported'])) : '—', 'fa-clock'],
            ];
            foreach ($facts as [$label, $value, $icon]):
              if (trim((string) $value) === '') { $value = '—'; }
          ?>
            <div class="col-sm-6 col-lg-4">
              <div class="clean-card p-3 h-100">
                <small class="text-muted d-block mb-1"><i class="fa-solid <?php echo e($icon); ?> me-1"></i><?php echo e($label); ?></small>
                <strong class="small"><?php echo e($value); ?></strong>
              </div>
            </div>
          <?php endforeach; ?>
        </div>

        <?php if (!empty($d['is_tor']) || !empty($d['is_whitelisted']) || !empty($d['hostnames'])): ?>
          <div class="clean-card p-4 mb-4">
            <div class="section-title mb-3">Address attributes</div>
            <?php if (!empty($d['is_tor'])): ?>
              <span class="badge text-bg-warning rounded-pill me-1 mb-1"><i class="fa-solid fa-user-secret me-1"></i>Tor exit node</span>
            <?php endif; ?>
            <?php if (!empty($d['is_whitelisted'])): ?>
              <span class="badge text-bg-success rounded-pill me-1 mb-1"><i class="fa-solid fa-check me-1"></i>Known-good listing</span>
            <?php endif; ?>
            <span class="badge text-bg-secondary rounded-pill me-1 mb-1">IPv<?php echo (int) ($d['ip_version'] ?? 4); ?></span>
            <?php if (!empty($d['hostnames'])): ?>
              <div class="mt-3">
                <small class="text-muted d-block mb-1">Hostnames</small>
                <?php foreach ($d['hostnames'] as $host): ?>
                  <span class="code-font small d-block text-break"><?php echo e($host); ?></span>
                <?php endforeach; ?>
              </div>
            <?php endif; ?>
          </div>
        <?php endif; ?>

        <?php if (!empty($d['category_counts'])): ?>
          <div class="clean-card p-4 mb-4">
            <div class="section-title mb-3">What it was reported for</div>
            <?php
              $maxCount = max($d['category_counts']);
              foreach ($d['category_counts'] as $catName => $count):
            ?>
              <div class="d-flex justify-content-between small mb-1">
                <span><?php echo e($catName); ?></span><strong><?php echo (int) $count; ?></strong>
              </div>
              <div class="mini-bar mb-3">
                <span style="width:<?php echo $maxCount > 0 ? round($count / $maxCount * 100) : 0; ?>%;background:#ef4444"></span>
              </div>
            <?php endforeach; ?>
          </div>
        <?php endif; ?>

        <?php if (!empty($d['recent_reports'])): ?>
          <div class="clean-card p-4">
            <div class="section-title mb-3">Recent reports</div>
            <div class="table-responsive">
              <table class="table table-hover table-sm align-middle mb-0">
                <thead><tr><th>When</th><th>Categories</th><th>Reporter comment</th></tr></thead>
                <tbody>
                  <?php foreach ($d['recent_reports'] as $report): ?>
                    <tr>
                      <td class="text-muted text-nowrap">
                        <small><?php echo e($report['reported_at'] !== '' ? date('Y-m-d', strtotime($report['reported_at'])) : '—'); ?></small>
                      </td>
                      <td>
                        <?php foreach ($report['categories'] as $cat): ?>
                          <span class="badge text-bg-danger rounded-pill mb-1"><?php echo e($cat); ?></span>
                        <?php endforeach; ?>
                      </td>
                      <td class="text-muted small" style="max-width:320px"><?php echo e($report['comment']); ?></td>
                    </tr>
                  <?php endforeach; ?>
                </tbody>
              </table>
            </div>
            <small class="text-muted d-block mt-3">
              Report comments are written by third parties and are shown as submitted.
            </small>
          </div>
        <?php endif; ?>
      <?php endif; ?>
    <?php endif; ?>
  </div>
</div>
