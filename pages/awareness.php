<?php
/**
 * Cybersecurity Info & Awareness.
 *
 * Three layers, most concrete first:
 *   1. What has actually been caught on this campus
 *   2. A quiz that makes the reader decide something
 *   3. The standing advice, and current headlines that illustrate it
 *
 * Expects: $quiz_result (array|null), e(), csrf_field().
 */
require_once __DIR__ . '/../services/AwarenessService.php';

$quizReady = AwarenessService::isReady();
$reality   = ['scanned' => 0, 'flagged' => 0, 'window_days' => 30, 'examples' => []];
try { $reality = AwarenessService::campusReality(30); } catch (Throwable $ex) {}

$progress  = $quizReady ? AwarenessService::userProgress($user_id) : ['attempts' => 0, 'best' => 0, 'last' => null];
$questions = ($quizReady && $quiz_result === null) ? AwarenessService::quizQuestions(6) : [];

$headlines = [];
try { $headlines = AwarenessService::relevantHeadlines(4); } catch (Throwable $ex) {}
?>
<div class="info-banner mb-4">
  <div class="row align-items-center">
    <div class="col-lg-8">
      <div class="eyebrow text-white opacity-75">SecuScan awareness</div>
      <h2 class="display-6 fw-bold mt-2">Stop. Check. Protect.</h2>
      <p class="mb-0 opacity-75">
        Small habits — checking a domain, never reading an OTP aloud — remove most of the risk.
      </p>
    </div>
    <div class="col-lg-4 text-center d-none d-lg-block">
      <i class="fa-solid fa-user-shield fa-5x opacity-50"></i>
    </div>
  </div>
</div>

<!-- ===================== 1. Campus reality ===================== -->
<div class="clean-card p-4 mb-4">
  <div class="d-flex justify-content-between align-items-start flex-wrap gap-3 mb-3">
    <div>
      <div class="section-title"><i class="fa-solid fa-chart-simple text-primary me-2"></i>Caught on this campus</div>
      <small class="text-muted">Last <?php echo (int) $reality['window_days']; ?> days. No student is identified.</small>
    </div>
    <div class="text-end">
      <div class="h3 fw-bold mb-0 <?php echo $reality['flagged'] > 0 ? 'text-danger' : 'text-muted'; ?>">
        <?php echo number_format($reality['flagged']); ?>
      </div>
      <small class="text-muted">flagged of <?php echo number_format($reality['scanned']); ?> checks</small>
    </div>
  </div>

  <?php if (empty($reality['examples'])): ?>
    <p class="text-muted small mb-0">
      Nothing has been flagged here yet. Once students start scanning links, hashes and addresses,
      the real examples appear in this space — they teach far better than generic advice.
    </p>
  <?php else: ?>
    <p class="text-muted small">
      These were submitted by students here and came back flagged. Addresses are
      <strong>defanged</strong> — the dots and scheme are broken on purpose so nothing is clickable.
      That is standard practice when a live malicious indicator has to appear in a report.
    </p>
    <div class="row g-3">
      <?php foreach ($reality['examples'] as $ex): ?>
        <div class="col-md-6">
          <div class="clean-card p-3 h-100">
            <div class="d-flex justify-content-between align-items-center mb-2">
              <span class="badge text-bg-danger rounded-pill">
                <i class="fa-solid <?php echo e($ex['icon']); ?> me-1"></i><?php echo e($ex['kind']); ?>
              </span>
              <small class="text-muted"><?php echo e(date('d M', strtotime($ex['when']))); ?></small>
            </div>
            <div class="code-font small text-break mb-2"><?php echo e($ex['value']); ?></div>
            <small class="text-muted"><?php echo e($ex['lesson']); ?></small>
          </div>
        </div>
      <?php endforeach; ?>
    </div>
  <?php endif; ?>
</div>

<!-- ===================== 2. Quiz ===================== -->
<?php if (!$quizReady): ?>
  <div class="clean-card p-4 mb-4">
    <div class="section-title mb-2"><i class="fa-solid fa-circle-question text-primary me-2"></i>Quick check</div>
    <p class="text-muted small mb-0">
      The question bank has not been installed. Run <code>awareness_setup.sql</code> in phpMyAdmin.
    </p>
  </div>

<?php elseif ($quiz_result !== null && !empty($quiz_result['detail'])): ?>
  <?php
    $pct = $quiz_result['total'] > 0 ? round($quiz_result['score'] / $quiz_result['total'] * 100) : 0;
    $tone = $pct >= 80 ? 'success' : ($pct >= 50 ? 'warning' : 'danger');
  ?>
  <div class="clean-card p-4 mb-4">
    <div class="d-flex justify-content-between align-items-center flex-wrap gap-3 mb-4">
      <div>
        <div class="section-title">Your result</div>
        <small class="text-muted">Read the explanations — that is where the learning is.</small>
      </div>
      <div class="text-end">
        <div class="display-5 fw-bold text-<?php echo $tone; ?>">
          <?php echo (int) $quiz_result['score']; ?>/<?php echo (int) $quiz_result['total']; ?>
        </div>
        <small class="text-muted"><?php echo $pct; ?>%</small>
      </div>
    </div>

    <?php foreach ($quiz_result['detail'] as $i => $d): ?>
      <div class="border-top pt-3 mt-3">
        <div class="d-flex gap-2 mb-2">
          <span class="badge <?php echo $d['is_right'] ? 'text-bg-success' : 'text-bg-danger'; ?> rounded-pill flex-shrink-0">
            <i class="fa-solid <?php echo $d['is_right'] ? 'fa-check' : 'fa-xmark'; ?>"></i>
          </span>
          <div>
            <div class="fw-semibold small mb-1"><?php echo e($d['question']); ?></div>
            <?php if (!$d['is_right']): ?>
              <div class="small text-danger mb-1">
                You chose: <?php echo e($d['given_text']); ?>
              </div>
              <div class="small text-success mb-1">
                Correct: <?php echo e($d['correct_text']); ?>
              </div>
            <?php endif; ?>
            <div class="small text-muted"><?php echo e($d['explanation']); ?></div>
          </div>
        </div>
      </div>
    <?php endforeach; ?>

    <form method="post" class="mt-4">
      <?php echo csrf_field(); ?>
      <button name="quiz_retry" class="btn btn-outline-primary btn-sm">
        <i class="fa-solid fa-rotate me-1"></i>Try another set
      </button>
    </form>
  </div>

<?php elseif (!empty($questions)): ?>
  <div class="clean-card p-4 mb-4">
    <div class="d-flex justify-content-between align-items-start flex-wrap gap-3 mb-3">
      <div>
        <div class="section-title"><i class="fa-solid fa-circle-question text-primary me-2"></i>Quick check</div>
        <small class="text-muted"><?php echo count($questions); ?> questions, drawn at random. No time limit, no record kept beyond your score.</small>
      </div>
      <?php if ($progress['attempts'] > 0): ?>
        <div class="text-end">
          <small class="text-muted d-block">Your best</small>
          <strong class="text-primary"><?php echo (int) $progress['best']; ?>%</strong>
          <small class="text-muted">· <?php echo (int) $progress['attempts']; ?> attempt<?php echo $progress['attempts'] === 1 ? '' : 's'; ?></small>
        </div>
      <?php endif; ?>
    </div>

    <form method="post">
      <?php echo csrf_field(); ?>
      <?php foreach ($questions as $i => $q): ?>
        <div class="border-top pt-3 mt-3">
          <div class="d-flex justify-content-between align-items-start gap-2 mb-2">
            <div class="fw-semibold small"><?php echo ($i + 1); ?>. <?php echo e($q['question']); ?></div>
            <span class="badge text-bg-secondary rounded-pill flex-shrink-0"><?php echo e($q['category']); ?></span>
          </div>
          <?php foreach (['a', 'b', 'c', 'd'] as $opt): ?>
            <div class="form-check small mb-1">
              <input class="form-check-input" type="radio" required
                     name="q[<?php echo (int) $q['id']; ?>]"
                     id="q<?php echo (int) $q['id'] . $opt; ?>"
                     value="<?php echo strtoupper($opt); ?>">
              <label class="form-check-label" for="q<?php echo (int) $q['id'] . $opt; ?>">
                <?php echo e($q['option_' . $opt]); ?>
              </label>
            </div>
          <?php endforeach; ?>
        </div>
      <?php endforeach; ?>

      <button name="quiz_submit" class="btn btn-primary mt-4">
        <i class="fa-solid fa-paper-plane me-2"></i>Check my answers
      </button>
    </form>
  </div>
<?php endif; ?>

<!-- ===================== 3. Standing advice ===================== -->
<div class="row g-4 mb-4">
  <div class="col-md-4">
    <div class="clean-card p-4 h-100">
      <i class="fa-solid fa-link text-primary fs-3 mb-3"></i>
      <h3 class="h6 fw-bold">Read the domain, not the message</h3>
      <p class="small text-muted mb-0">
        Read the address from the right: the registrable domain is the last two parts before the first
        slash. <span class="code-font">maybank2u-secure[.]com</span> is not
        <span class="code-font">maybank2u[.]com[.]my</span>. Urgency and typos are hints; the domain is proof.
      </p>
    </div>
  </div>
  <div class="col-md-4">
    <div class="clean-card p-4 h-100">
      <i class="fa-solid fa-key text-warning fs-3 mb-3"></i>
      <h3 class="h6 fw-bold">An OTP only ever authorises what you started</h3>
      <p class="small text-muted mb-0">
        If a code arrives and you did not ask for one, somebody else is trying to get in right now.
        Nobody legitimate will ever ask you to read it aloud — knowing your name or IC proves nothing.
      </p>
    </div>
  </div>
  <div class="col-md-4">
    <div class="clean-card p-4 h-100">
      <i class="fa-solid fa-clock-rotate-left text-success fs-3 mb-3"></i>
      <h3 class="h6 fw-bold">Report fast, not perfectly</h3>
      <p class="small text-muted mb-0">
        If you have already clicked or typed a password somewhere you should not have, change it now and
        tell campus IT. Every minute matters, and you will not be the first person to do it.
      </p>
    </div>
  </div>
</div>

<?php if (!empty($headlines)): ?>
<div class="clean-card p-4">
  <div class="d-flex justify-content-between align-items-center mb-3 flex-wrap gap-2">
    <div>
      <div class="section-title"><i class="fa-solid fa-bullhorn text-danger me-2"></i>This week, in the wild</div>
      <small class="text-muted">The same lessons, happening to someone else right now.</small>
    </div>
    <a href="index.php?page=news" class="btn btn-sm btn-outline-primary rounded-pill">All news</a>
  </div>
  <div class="row g-3">
    <?php foreach ($headlines as $item): ?>
      <div class="col-md-6">
        <div class="clean-card p-3 h-100">
          <div class="d-flex justify-content-between align-items-start gap-2 mb-2">
            <span class="badge text-bg-primary rounded-pill"><?php echo e($item['source']); ?></span>
            <small class="text-muted text-nowrap"><?php echo e($item['published']); ?></small>
          </div>
          <h4 class="h6 fw-bold mb-2">
            <?php if ($item['link'] !== ''): ?>
              <a href="<?php echo e($item['link']); ?>" target="_blank" rel="noopener noreferrer nofollow"
                 class="text-decoration-none stretched-link"><?php echo e($item['title']); ?></a>
            <?php else: ?>
              <?php echo e($item['title']); ?>
            <?php endif; ?>
          </h4>
          <div class="d-flex flex-wrap gap-1">
            <?php foreach (($item['tags'] ?? []) as $tag): ?>
              <span class="badge text-bg-secondary rounded-pill"><?php echo e($tag); ?></span>
            <?php endforeach; ?>
          </div>
        </div>
      </div>
    <?php endforeach; ?>
  </div>
</div>
<?php endif; ?>
