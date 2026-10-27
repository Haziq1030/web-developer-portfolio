<?php
/**
 * Hash Scanner page.
 * Expects: $hash_scan (array|null from handle_hash_scan), e() helper, csrf_field().
 */
$vtUsage = ApiCache::usage('virustotal');
?>
<div class="row g-4">
  <div class="col-lg-5">
    <div class="clean-card p-4 p-lg-5 h-100">
      <span class="stat-icon mb-3"><i class="fa-solid fa-fingerprint"></i></span>
      <h2 class="h4 fw-bold">Hash Scanner</h2>
      <p class="text-muted">
        Checked against two independent multi-engine services covering roughly 100 antivirus engines
        between them. Two separate engine sets means a miss by one is often caught by the other.
      </p>

      <div class="alert alert-info small rounded-4 d-flex gap-2">
        <i class="fa-solid fa-lock mt-1"></i>
        <div>
          SecuScan never accepts your file — only its hash. Your documents stay on your own
          computer, because they are never sent here in the first place.
        </div>
      </div>

      <form method="post" class="mt-4">
        <?php echo csrf_field(); ?>

        <label class="form-label fw-semibold" for="hash_purpose">Scan Purpose</label>
        <select id="hash_purpose" name="tujuan" class="form-select mb-4" required>
          <option value="">-- Select a purpose --</option>
          <option value="Education">Education</option>
          <option value="Work">Work</option>
          <option value="Others">Others</option>
          <option value="Shopping">Shopping</option>
        </select>

        <label class="form-label fw-semibold" for="hash_input">File hash</label>
        <input type="text" id="hash_input" name="hash_input" class="form-control code-font mb-2"
               placeholder="e.g. 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
               pattern="[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64}"
               value="<?php echo e($hash_scan['hash'] ?? ''); ?>" required autofocus>
        <small class="text-muted d-block mb-4">
          MD5 (32), SHA-1 (40) or SHA-256 (64) hex characters.
        </small>

        <button class="btn btn-primary w-100" name="scan_hash_btn">
          <i class="fa-solid fa-magnifying-glass-chart me-2"></i>Scan Hash
        </button>
      </form>

      <details class="mt-4">
        <summary class="small fw-bold text-primary" style="cursor:pointer">
          How do I get a file's hash?
        </summary>
        <div class="small text-muted mt-3">
          <p class="mb-2"><strong>Windows</strong> — open PowerShell and run:</p>
          <pre class="code-font p-2 rounded mb-3" style="background:rgba(0,0,0,.25);white-space:pre-wrap"><code>Get-FileHash "C:\path\to\file.exe"</code></pre>
          <p class="mb-2"><strong>macOS or Linux</strong> — in a terminal:</p>
          <pre class="code-font p-2 rounded mb-0" style="background:rgba(0,0,0,.25);white-space:pre-wrap"><code>shasum -a 256 /path/to/file</code></pre>
        </div>
      </details>

      <div class="d-flex justify-content-between small text-muted mt-4 pt-3 border-top">
        <span>Lookups used today</span>
        <strong><?php echo (int) $vtUsage['last_day']; ?> / <?php echo RATE_LIMITS['virustotal']['per_day']; ?></strong>
      </div>
      <div class="d-flex justify-content-between small text-muted">
        <span>This minute</span>
        <strong><?php echo (int) $vtUsage['last_minute']; ?> / <?php echo RATE_LIMITS['virustotal']['per_minute']; ?></strong>
      </div>
    </div>
  </div>

  <div class="col-lg-7">
    <?php if ($hash_scan === null): ?>
      <div class="clean-card p-5 h-100 d-flex flex-column justify-content-center text-center">
        <i class="fa-solid fa-file-shield fs-1 text-primary opacity-50 mb-3"></i>
        <h3 class="h5 fw-bold">No scan yet</h3>
        <p class="text-muted mb-0">Paste a file hash to see engine-by-engine results.</p>
      </div>

    <?php elseif (!empty($hash_scan['error'])): ?>
      <div class="alert alert-warning rounded-4">
        <i class="fa-solid fa-triangle-exclamation me-2"></i><?php echo e($hash_scan['error']); ?>
      </div>

    <?php else: ?>
      <?php
        $verdict = $hash_scan['summary']['verdict'];
        $verdictClass = [
            ThreatResult::MALICIOUS  => 'danger',
            ThreatResult::SUSPICIOUS => 'warning',
            ThreatResult::CLEAN      => 'success',
            ThreatResult::UNKNOWN    => 'secondary',
            ThreatResult::ERROR      => 'dark',
        ][$verdict] ?? 'secondary';
      ?>

      <div class="clean-card p-4 mb-4 border-<?php echo $verdictClass; ?>">
        <div class="d-flex justify-content-between align-items-start flex-wrap gap-3">
          <div>
            <div class="eyebrow">Combined verdict</div>
            <h2 class="h3 fw-bold text-<?php echo $verdictClass; ?> mb-1">
              <?php echo e(ThreatResult::aggregateLabel($verdict)); ?>
            </h2>
            <small class="text-muted">
              <?php echo (int) $hash_scan['summary']['providers_usable']; ?> of
              <?php echo (int) $hash_scan['summary']['providers_queried']; ?> providers returned a usable answer
            </small>
          </div>
          <i class="fa-solid <?php
            echo $verdict === ThreatResult::CLEAN ? 'fa-circle-check'
               : ($verdict === ThreatResult::MALICIOUS ? 'fa-skull-crossbones'
               : ($verdict === ThreatResult::ERROR ? 'fa-plug-circle-xmark' : 'fa-circle-question'));
          ?> fs-1 text-<?php echo $verdictClass; ?> opacity-75"></i>
        </div>

        <?php if ($verdict === ThreatResult::UNKNOWN): ?>
          <div class="alert alert-secondary small mt-3 mb-0 rounded-3">
            <strong>Unknown is not clean.</strong> Neither provider has a record of this file. Freshly built
            malware looks exactly like this, so treat an unknown file as untrusted until something else clears it.
          </div>
        <?php elseif ($verdict === ThreatResult::ERROR): ?>
          <div class="alert alert-dark small mt-3 mb-0 rounded-3">
            <strong>The scan did not complete.</strong> No verdict was produced — this is not a clean result.
            Check the per-provider messages below.
          </div>
        <?php endif; ?>

        <div class="row g-3 mt-2 pt-3 border-top">
          <div class="col-sm-8">
            <small class="text-muted d-block">SHA-256</small>
            <span class="code-font text-break"><?php echo e($hash_scan['hash']); ?></span>
          </div>
          <div class="col-sm-4">
            <small class="text-muted d-block">File</small>
            <strong class="hash-file-name"><?php echo e($hash_scan['filename'] !== '' ? $hash_scan['filename'] : '—'); ?></strong>
            <small class="d-block text-muted"><?php echo e(human_bytes((int) $hash_scan['filesize'])); ?></small>
          </div>
        </div>
      </div>

      <?php foreach ($hash_scan['results'] as $r): ?>
        <div class="clean-card p-4 mb-3">
          <div class="d-flex justify-content-between align-items-center mb-2 flex-wrap gap-2">
            <div class="section-title"><?php echo e($r->displayName()); ?></div>
            <div class="d-flex align-items-center gap-2">
              <?php if ($r->cached): ?>
                <span class="badge text-bg-secondary rounded-pill" title="Served from local cache — no API quota used">
                  <i class="fa-solid fa-database me-1"></i>cached
                </span>
              <?php endif; ?>
              <span class="badge <?php echo $r->badgeClass(); ?> rounded-pill"><?php echo e($r->label()); ?></span>
            </div>
          </div>

          <p class="text-muted small mb-3"><?php echo e($r->summary); ?></p>

          <?php if ($r->score !== null): ?>
            <div class="d-flex justify-content-between small mb-1">
              <span>Detection ratio</span><strong><?php echo e(number_format((float) $r->score, 2)); ?>%</strong>
            </div>
            <div class="mini-bar mb-3">
              <span style="width:<?php echo min(100, (float) $r->score); ?>%;background:<?php
                echo $r->verdict === ThreatResult::MALICIOUS ? '#ef4444'
                   : ($r->verdict === ThreatResult::SUSPICIOUS ? '#f59e0b' : '#22c55e'); ?>"></span>
            </div>
          <?php endif; ?>

          <?php if (!empty($r->detail['threat_label'])): ?>
            <div class="mb-3">
              <small class="text-muted d-block">Threat classification</small>
              <strong class="text-danger"><?php echo e($r->detail['threat_label']); ?></strong>
            </div>
          <?php endif; ?>

          <?php if (!empty($r->detail['engines'])): ?>
            <details>
              <summary class="small fw-bold text-primary" style="cursor:pointer">
                Show the <?php echo count($r->detail['engines']); ?> engines that flagged this file
              </summary>
              <div class="table-responsive mt-3">
                <table class="table table-sm table-hover mb-0">
                  <thead><tr><th>Engine</th><th>Detection name</th></tr></thead>
                  <tbody>
                    <?php foreach ($r->detail['engines'] as $engine): ?>
                      <tr>
                        <td class="fw-semibold"><?php echo e($engine['engine']); ?></td>
                        <td class="code-font text-danger"><?php echo e($engine['result']); ?></td>
                      </tr>
                    <?php endforeach; ?>
                  </tbody>
                </table>
              </div>
            </details>
          <?php endif; ?>

          <?php if (!empty($r->detail['first_seen']) || !empty($r->detail['times_submitted'])): ?>
            <div class="row g-3 mt-2 pt-3 border-top small">
              <?php if (!empty($r->detail['first_seen'])): ?>
                <div class="col-6"><small class="text-muted d-block">First seen</small><?php echo e($r->detail['first_seen']); ?></div>
              <?php endif; ?>
              <?php if (!empty($r->detail['times_submitted'])): ?>
                <div class="col-6"><small class="text-muted d-block">Times submitted</small><?php echo (int) $r->detail['times_submitted']; ?></div>
              <?php endif; ?>
            </div>
          <?php endif; ?>
        </div>
      <?php endforeach; ?>
    <?php endif; ?>
  </div>
</div>
