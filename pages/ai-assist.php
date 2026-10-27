<?php
/**
 * AI Assist page — scoped IT / cybersecurity Q&A for students.
 * Expects: $ai_chat (array|null from handle_ai_chat), e(), csrf_field().
 */
$history = $_SESSION['ai_history'] ?? [];
if (!is_array($history)) { $history = []; }
$usage = AiAssistService::userUsage($user_id);
$remaining = max(0, $usage['limit'] - $usage['used']);

$starters = [
    'How do I spot a phishing email?',
    'What makes a password strong?',
    'Why does SecuScan only accept a hash, not my file?',
    'What is two-factor authentication and should I turn it on?',
];
?>
<div class="row g-4">
  <div class="col-lg-8">
    <div class="clean-card p-4 p-lg-5 d-flex flex-column" style="min-height:560px">

      <div class="d-flex justify-content-between align-items-start flex-wrap gap-2 mb-4">
        <div>
          <span class="stat-icon mb-3"><i class="fa-solid fa-robot"></i></span>
          <h2 class="h4 fw-bold mb-1">SecuScan Assist</h2>
          <p class="text-muted mb-0">Ask anything about IT or cybersecurity.</p>
        </div>
        <?php if (!empty($history)): ?>
          <form method="post" class="m-0">
            <?php echo csrf_field(); ?>
            <button name="ai_clear_btn" class="btn btn-sm btn-outline-primary rounded-pill">
              <i class="fa-solid fa-eraser me-1"></i>Clear chat
            </button>
          </form>
        <?php endif; ?>
      </div>

      <div class="flex-grow-1 mb-4" id="chat-log">
        <?php if (empty($history)): ?>
          <div class="text-center py-5">
            <i class="fa-solid fa-comments fs-1 text-primary opacity-50 mb-3 d-block"></i>
            <h3 class="h6 fw-bold">No questions yet</h3>
            <p class="text-muted small mb-4">Try one of these to start:</p>
            <div class="d-flex flex-column align-items-center gap-2">
              <?php foreach ($starters as $starter): ?>
                <button type="button" class="btn btn-sm btn-outline-primary rounded-pill starter-btn"
                        data-question="<?php echo e($starter); ?>">
                  <?php echo e($starter); ?>
                </button>
              <?php endforeach; ?>
            </div>
          </div>
        <?php else: ?>
          <?php foreach ($history as $turn): ?>
            <?php if ($turn['role'] === 'user'): ?>
              <div class="d-flex justify-content-end mb-3">
                <div class="px-3 py-2 rounded-4"
                     style="max-width:82%;background:rgba(37,99,235,.22);border:1px solid rgba(96,165,250,.3)">
                  <?php echo e($turn['text']); ?>
                </div>
              </div>
            <?php else: ?>
              <div class="d-flex gap-3 mb-4">
                <div class="stat-icon flex-shrink-0" style="width:34px;height:34px">
                  <i class="fa-solid fa-shield-halved" style="font-size:.8rem"></i>
                </div>
                <div class="small" style="max-width:82%">
                  <?php echo AiAssistService::renderReply($turn['text']); ?>
                </div>
              </div>
            <?php endif; ?>
          <?php endforeach; ?>
        <?php endif; ?>

        <?php if ($ai_chat !== null && !empty($ai_chat['error'])): ?>
          <div class="alert alert-warning rounded-4 small mb-0">
            <i class="fa-solid fa-triangle-exclamation me-2"></i><?php echo e($ai_chat['error']); ?>
          </div>
        <?php endif; ?>
      </div>

      <form method="post" class="mt-auto" id="ai-form">
        <?php echo csrf_field(); ?>
        <!--
          The submit flag lives in a hidden field, NOT only on the button.
          A button's name is only submitted when it is the active submitter,
          and two things here break that: requestSubmit() with no argument
          sends no submitter at all, and disabling the button in the submit
          handler removes it from the form data (the data set is built after
          the event fires). Either way the handler saw no flag and silently
          did nothing. A hidden field is always sent.
        -->
        <input type="hidden" name="ai_ask_btn" value="1">
        <div class="input-group">
          <textarea name="ai_question" id="ai_question" class="form-control" rows="2"
                    maxlength="<?php echo (int) AI_MAX_QUESTION_CHARS; ?>"
                    placeholder="Ask about phishing, passwords, networks, malware…"
                    <?php echo $remaining === 0 ? 'disabled' : ''; ?>
                    required></textarea>
          <button type="submit" class="btn btn-primary px-4" id="ai-send"
                  <?php echo $remaining === 0 ? 'disabled' : ''; ?>>
            <i class="fa-solid fa-paper-plane"></i>
          </button>
        </div>
        <div class="d-flex justify-content-between mt-2">
          <small class="text-muted">Enter to send, Shift+Enter for a new line.</small>
          <small class="text-muted"><span id="char-count">0</span>/<?php echo (int) AI_MAX_QUESTION_CHARS; ?></small>
        </div>
      </form>
    </div>
  </div>

  <div class="col-lg-4">
    <div class="clean-card p-4 mb-4">
      <div class="section-title mb-3">What it covers</div>
      <ul class="small text-muted ps-3 mb-0">
        <li class="mb-2">Cybersecurity — phishing, malware, passwords, 2FA, privacy, social engineering</li>
        <li class="mb-2">IT — networks, operating systems, software, programming, databases, hardware</li>
        <li class="mb-0">Using SecuScan — scanning links, hashes and IPs, and reading the results</li>
      </ul>
      <hr class="opacity-25 my-3">
      <p class="small text-muted mb-0">
        Questions outside those subjects will be turned down politely. This keeps the shared
        campus quota for the students who need it.
      </p>
    </div>

    <div class="clean-card p-4 mb-4">
      <div class="section-title mb-3">Your usage</div>
      <div class="d-flex justify-content-between small mb-2">
        <span>Questions this hour</span>
        <strong><?php echo (int) $usage['used']; ?> / <?php echo (int) $usage['limit']; ?></strong>
      </div>
      <div class="mini-bar">
        <span style="width:<?php echo $usage['limit'] > 0 ? min(100, round($usage['used'] / $usage['limit'] * 100)) : 0; ?>%;
                     background:<?php echo $remaining === 0 ? '#ef4444' : ($remaining <= 5 ? '#f59e0b' : '#22c55e'); ?>"></span>
      </div>
      <?php if ($remaining === 0): ?>
        <p class="small text-danger mt-3 mb-0">
          You have used your questions for this hour. The allowance refills gradually — check back shortly.
        </p>
      <?php endif; ?>
    </div>

    <div class="clean-card p-4">
      <div class="section-title mb-3"><i class="fa-solid fa-circle-info text-primary me-2"></i>Before you rely on it</div>
      <p class="small text-muted mb-2">
        This is an AI assistant. It is useful for learning and for quick explanations, but it can be
        wrong — check anything that matters against official documentation.
      </p>
      <p class="small text-muted mb-0">
        Never paste passwords, tokens, student ID numbers or other personal data into the box.
        If you are dealing with a live security incident on campus, contact the IT team directly
        rather than asking here.
      </p>
    </div>
  </div>
</div>

<script>
document.addEventListener('DOMContentLoaded', function () {
    var box = document.getElementById('ai_question');
    var form = document.getElementById('ai-form');
    var count = document.getElementById('char-count');
    var log = document.getElementById('chat-log');

    if (log) { log.scrollTop = log.scrollHeight; }

    if (box && count) {
        box.addEventListener('input', function () { count.textContent = box.value.length; });
    }

    // Enter sends, Shift+Enter makes a new line.
    if (box && form) {
        box.addEventListener('keydown', function (ev) {
            if (ev.key === 'Enter' && !ev.shiftKey) {
                ev.preventDefault();
                if (box.value.trim() !== '') {
                    // Pass the button explicitly as the submitter.
                    var send = document.getElementById('ai-send');
                    if (form.requestSubmit) { form.requestSubmit(send || undefined); }
                    else { form.submit(); }
                }
            }
        });
    }

    document.querySelectorAll('.starter-btn').forEach(function (btn) {
        btn.addEventListener('click', function () {
            if (!box) { return; }
            box.value = btn.dataset.question || '';
            if (count) { count.textContent = box.value.length; }
            box.focus();
        });
    });

    // Show progress and block a double-click, WITHOUT disabling the button
    // during the submit event — that would drop it from the form data.
    // Deferring to a timeout lets the browser finish building the request
    // first; the submit flag is a hidden field either way, so this is now
    // only about the spinner and the double-submit guard.
    if (form) {
        var submitted = false;
        form.addEventListener('submit', function (ev) {
            if (submitted) { ev.preventDefault(); return; }
            submitted = true;
            window.setTimeout(function () {
                var send = document.getElementById('ai-send');
                if (send) {
                    send.disabled = true;
                    send.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
                }
            }, 0);
        });
    }
});
</script>
