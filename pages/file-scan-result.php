<?php if (!empty($file_scan) && empty($file_scan['error'])): ?>
<?php
$verdict = $file_scan['summary']['verdict'];
$tone = $verdict === ThreatResult::MALICIOUS ? 'danger' : ($verdict === ThreatResult::SUSPICIOUS ? 'warning' : ($verdict === ThreatResult::CLEAN ? 'success' : 'secondary'));
$riskScore = $file_scan['summary']['risk_score'];
$title = $verdict === ThreatResult::MALICIOUS ? 'Critical' : ($verdict === ThreatResult::SUSPICIOUS ? 'Suspicious' : ($verdict === ThreatResult::CLEAN ? 'Safe' : 'Not Available'));
?>
<section class="security-report security-report-<?php echo $tone; ?>">
  <div class="security-report-head"><div><div class="security-report-kicker">Passive security analysis</div><h2>Complete File Security Report</h2><p>SecuScan analysed the file hash using available multi-engine security signals.</p></div><div class="risk-score"><strong><?php echo $riskScore === null ? 'N/A' : (int) $riskScore . '/100'; ?></strong><small><?php echo e($title); ?></small></div></div>
  <div class="report-meter"><span style="width:<?php echo $riskScore === null ? 0 : (int) $riskScore; ?>%"></span></div>
  <div class="report-grid">
    <article class="report-panel"><h3><i class="fa-solid fa-file-shield"></i> File Overview</h3><dl><div><dt>Filename</dt><dd class="hash-file-name"><?php echo e($file_scan['filename']); ?></dd></div><div><dt>File size</dt><dd><?php echo e(human_bytes((int) $file_scan['filesize'])); ?></dd></div><div><dt>Scan type</dt><dd><?php echo !empty($file_scan['deep_scan']) ? 'Content upload analysis' : 'Hash-based analysis'; ?></dd></div><div><dt>Privacy</dt><dd><?php echo !empty($file_scan['deep_scan']) ? 'File uploaded with your consent' : 'File content not uploaded'; ?></dd></div></dl></article>
    <article class="report-panel"><h3><i class="fa-solid fa-fingerprint"></i> Hash Analysis</h3><dl><div><dt>SHA-256</dt><dd class="code-font"><?php echo e($file_scan['hash']); ?></dd></div><div><dt>Overall result</dt><dd><?php echo e(ThreatResult::aggregateLabel($verdict)); ?></dd></div><div><dt>Risk score</dt><dd><?php echo $riskScore === null ? 'N/A' : (int) $riskScore . '/100'; ?></dd></div><div><dt>Usable sources</dt><dd><?php echo (int) $file_scan['summary']['providers_usable']; ?> / <?php echo (int) $file_scan['summary']['providers_queried']; ?></dd></div></dl></article>
    <article class="report-panel"><h3><i class="fa-solid fa-shield-halved"></i> Security Assessment</h3><dl><div><dt>Malicious</dt><dd><?php echo $verdict === ThreatResult::MALICIOUS ? 'Detected' : 'Not detected'; ?></dd></div><div><dt>Suspicious</dt><dd><?php echo $verdict === ThreatResult::SUSPICIOUS ? 'Detected' : 'Not detected'; ?></dd></div><div><dt>Reputation</dt><dd>Checked against available engines</dd></div></dl></article>
    <article class="report-panel"><h3><i class="fa-solid fa-clock"></i> Scan Status</h3><dl><div><dt>Analysis</dt><dd>Completed</dd></div><div><dt>Purpose</dt><dd><?php echo e($file_scan['purpose'] ?? 'Personal'); ?></dd></div><div><dt>Decision</dt><dd><?php echo e($title); ?></dd></div></dl></article>
  </div>
  <div class="report-engines"><div class="security-report-kicker">Analysis signals</div><div class="provider-result-grid"><?php foreach ($file_scan['results'] as $provider_result): ?><div class="provider-result"><div class="d-flex justify-content-between align-items-center gap-2"><strong><?php echo e($provider_result->displayName()); ?></strong><span class="badge <?php echo e($provider_result->badgeClass()); ?> rounded-pill"><?php echo e($provider_result->label()); ?></span></div><small class="text-muted d-block mt-2"><?php echo e($provider_result->summary); ?></small></div><?php endforeach; ?></div></div>
</section>
<?php endif; ?>
