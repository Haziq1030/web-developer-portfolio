<?php if (!empty($url_scan) && empty($url_scan['error']) && !empty($url_report)): ?>
<?php
$reportVerdict = $url_scan['summary']['verdict'];
$reportTone = $reportVerdict === ThreatResult::MALICIOUS ? 'danger' : ($reportVerdict === ThreatResult::SUSPICIOUS ? 'warning' : ($reportVerdict === ThreatResult::CLEAN ? 'success' : 'secondary'));
$reportRisk = $url_report['risk_score'];
$reportTitle = $reportVerdict === ThreatResult::MALICIOUS ? 'Critical' : ($reportVerdict === ThreatResult::SUSPICIOUS ? 'Suspicious' : ($reportVerdict === ThreatResult::CLEAN ? 'Safe' : 'Not Available'));
?>
<section class="security-report security-report-<?php echo $reportTone; ?>">
  <div class="security-report-head">
    <div><div class="security-report-kicker">Passive security analysis</div><h2>Complete URL Security Report</h2><p>SecuScan combined the available threat intelligence signals for this URL.</p></div>
    <div class="risk-score"><strong><?php echo $reportRisk === null ? 'N/A' : (int) $reportRisk . '/100'; ?></strong><small><?php echo e($reportTitle); ?></small></div>
  </div>
  <div class="report-meter"><span style="width:<?php echo $reportRisk === null ? 0 : (int) $reportRisk; ?>%"></span></div>
  <div class="report-grid">
    <article class="report-panel"><h3><i class="fa-solid fa-link"></i> URL Overview</h3><dl><div><dt>Full URL</dt><dd><?php echo e($url_scan['url']); ?></dd></div><div><dt>URL validity</dt><dd>Valid</dd></div><div><dt>Protocol</dt><dd><?php echo e($url_report['protocol']); ?></dd></div><div><dt>Hostname</dt><dd><?php echo e($url_report['hostname']); ?></dd></div><div><dt>Port</dt><dd><?php echo (int) $url_report['port']; ?> (default)</dd></div><div><dt>Path</dt><dd><?php echo e($url_report['path']); ?></dd></div></dl></article>
    <article class="report-panel"><h3><i class="fa-solid fa-network-wired"></i> Network &amp; DNS</h3><dl><div><dt>IPv4</dt><dd><?php echo e($url_report['ip']); ?></dd></div><div><dt>IPv6</dt><dd>Not Available</dd></div><div><dt>DNS status</dt><dd><?php echo $url_report['ip'] === 'Not Available' ? 'Not Available' : 'Resolved'; ?></dd></div><div><dt>Hostname</dt><dd><?php echo e($url_report['hostname']); ?></dd></div><div><dt>Reputation</dt><dd>Included in analysis</dd></div></dl></article>
    <article class="report-panel"><h3><i class="fa-solid fa-globe"></i> HTTP Analysis</h3><dl><div><dt>Request type</dt><dd>Passive URL lookup</dd></div><div><dt>Redirects</dt><dd>Not Available</dd></div><div><dt>Content fetch</dt><dd>Not performed</dd></div><div><dt>Threat signals</dt><dd><?php echo (int) $url_scan['summary']['providers_usable']; ?> usable sources</dd></div></dl></article>
    <article class="report-panel"><h3><i class="fa-solid fa-lock"></i> SSL / TLS</h3><dl><div><dt>Protocol</dt><dd><?php echo e($url_report['protocol']); ?></dd></div><div><dt>Certificate</dt><dd>Not inspected</dd></div><div><dt>Transport</dt><dd><?php echo $url_report['protocol'] === 'HTTPS' ? 'Encrypted' : 'Unencrypted'; ?></dd></div></dl></article>
  </div>
  <div class="report-engines"><div class="security-report-kicker">Analysis signals</div><div class="provider-result-grid"><?php foreach ($url_scan['results'] as $provider_result): ?><div class="provider-result"><div class="d-flex justify-content-between align-items-center gap-2"><strong><?php echo e($provider_result->displayName()); ?></strong><span class="badge <?php echo e($provider_result->badgeClass()); ?> rounded-pill"><?php echo e($provider_result->label()); ?></span></div><small class="text-muted d-block mt-2"><?php echo e($provider_result->summary); ?></small></div><?php endforeach; ?></div></div>
</section>
<?php endif; ?>
