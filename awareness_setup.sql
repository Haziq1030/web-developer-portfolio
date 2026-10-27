-- =====================================================================
-- SecuScan — Awareness quiz schema and question bank
--
-- Run AFTER api_setup.sql. Creates two tables and seeds 15 questions.
-- Safe to re-run: questions are keyed so they update rather than duplicate.
-- =====================================================================

USE secuscan_db;

-- ---------------------------------------------------------------------
-- Question bank. Editable in phpMyAdmin — the whole point of putting it
-- in the database rather than in code is that a lecturer can add or fix
-- a question without touching PHP.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS awareness_questions (
    id          INT NOT NULL AUTO_INCREMENT,
    qkey        VARCHAR(40)  NOT NULL,          -- stable key, lets re-seeding update in place
    category    VARCHAR(40)  NOT NULL DEFAULT 'General',
    question    TEXT         NOT NULL,
    option_a    VARCHAR(255) NOT NULL,
    option_b    VARCHAR(255) NOT NULL,
    option_c    VARCHAR(255) NOT NULL,
    option_d    VARCHAR(255) NOT NULL,
    correct     CHAR(1)      NOT NULL,
    explanation TEXT         NOT NULL,
    active      TINYINT(1)   NOT NULL DEFAULT 1,
    PRIMARY KEY (id),
    UNIQUE KEY uniq_qkey (qkey),
    KEY idx_active (active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ---------------------------------------------------------------------
-- Attempt history. Stores the score, not the identity of wrong answers
-- beyond what the student needs to review — this is a learning tool, not
-- an assessment record, and treating it as one changes how students use it.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS awareness_attempts (
    id         INT NOT NULL AUTO_INCREMENT,
    user_id    INT          DEFAULT NULL,
    score      TINYINT UNSIGNED NOT NULL DEFAULT 0,
    total      TINYINT UNSIGNED NOT NULL DEFAULT 0,
    taken_at   TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (id),
    KEY idx_attempt_user (user_id, taken_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ---------------------------------------------------------------------
-- Question bank
-- ---------------------------------------------------------------------
INSERT INTO awareness_questions (qkey, category, question, option_a, option_b, option_c, option_d, correct, explanation) VALUES

('phish-domain', 'Phishing',
 'An email says your student account will be closed today. The link points to maybank2u-secure.com. What is the strongest reason to distrust it?',
 'The email arrived outside office hours',
 'The real domain is maybank2u.com.my — this is a different domain that merely contains the brand name',
 'It uses HTTPS instead of HTTP',
 'The message has a spelling mistake',
 'B',
 'Anyone can register a domain with a brand name inside it. What matters is the registrable domain itself, read from the right: in maybank2u-secure.com the domain is maybank2u-secure.com, which has nothing to do with the bank. Urgency and typos are hints; the domain is proof.'),

('phish-https', 'Phishing',
 'A login page has a padlock icon and a valid HTTPS certificate. What does that prove?',
 'Traffic to the site is encrypted — nothing about who runs it',
 'The site is operated by the company it claims to be',
 'The site has been checked for malware',
 'The site is safe to enter your password into',
 'A',
 'HTTPS certificates are free and automated. A padlock means the connection is encrypted, so nobody in between can read it. It says nothing about who is at the other end. Most phishing sites today use HTTPS.'),

('otp-share', 'Account security',
 'Someone calls claiming to be from your bank fraud team and asks you to read out the OTP they just sent, to "cancel a fraudulent transaction". What is happening?',
 'Standard verification — read it out',
 'They are logging into your account right now and need that code to finish',
 'The bank is testing your account security',
 'It is safe if the caller knows your full name and IC number',
 'B',
 'An OTP only ever authorises an action YOU started. If you did not start one, someone else did. Knowing your name or IC proves nothing — that data leaks constantly. No legitimate bank will ever ask you to read an OTP aloud.'),

('password-reuse', 'Account security',
 'Why is reusing one strong password across several sites risky, even if the password is long?',
 'Long passwords expire faster',
 'Websites can read each other''s passwords',
 'It is not risky if the password is long enough',
 'When any one of those sites is breached, that password opens all the others',
 'D',
 'This is credential stuffing, and it is one of the most common ways accounts fall. Attackers take username/password pairs from one breach and try them everywhere else. Password strength does not help once the password itself is known.'),

('2fa-type', 'Account security',
 'Which second factor is hardest for an attacker to defeat remotely?',
 'A hardware security key or passkey',
 'SMS code sent to your phone',
 'Email code sent to your inbox',
 'A security question about your first school',
 'A',
 'SMS can be intercepted through SIM swap. Email is only as strong as the email account. Security questions are often answerable from social media. A hardware key or passkey is bound to the real site, so it will not authenticate to a phishing page even if you are fooled.'),

('hash-unknown', 'Using SecuScan',
 'You scan a file hash and SecuScan reports "Unknown — no provider has a record of this file". What should you conclude?',
 'The file is clean',
 'The file is malicious',
 'Nothing yet — it has simply never been submitted anywhere, which is also true of brand-new malware',
 'The scan failed and should be repeated',
 'C',
 'Unknown is not a verdict. Antivirus databases only know files someone has already submitted. A freshly built piece of malware looks exactly like a harmless file nobody has ever uploaded. Treat unknown as untrusted until something else clears it.'),

('hash-privacy', 'Using SecuScan',
 'Why does SecuScan ask for a file hash instead of the file itself?',
 'Hashes are faster to upload',
 'Files are too large for the server',
 'The file never leaves your computer, so your documents cannot be read or published by anyone',
 'Hashes are more accurate than files',
 'C',
 'Uploading a document to a public scanning service can make it retrievable by that service''s subscribers. A hash is a one-way fingerprint: it identifies a file that is already known, and reveals nothing about a file that is not.'),

('ip-zero-reports', 'Using SecuScan',
 'An IP address comes back with an abuse confidence score of 0 and no reports. How much does that tell you?',
 'It is a trusted address',
 'Very little — nobody has complained about it, which is also true of infrastructure rented yesterday',
 'It is definitely safe to connect to',
 'The lookup failed',
 'B',
 'Reputation databases are built from complaints. Absence of complaints is weak evidence: attackers rotate infrastructure constantly, and a server rented this morning has a clean record by definition.'),

('macro-doc', 'Malware',
 'A document from an unknown sender asks you to "Enable Editing" and then "Enable Content" to see it properly. What is that?',
 'A normal compatibility prompt',
 'A Microsoft account verification step',
 'A way to improve document formatting',
 'A request to run the macros embedded in the document — a common malware delivery route',
 'D',
 'Protected View exists precisely to stop documents running code automatically. Those two clicks are how a user is talked into disabling that protection. Legitimate documents almost never need macros to be readable.'),

('usb-found', 'Malware',
 'You find an unlabelled USB drive in a campus lab. What is the safe action?',
 'Hand it to IT or campus security without plugging it in anywhere',
 'Plug it into a lab computer to find the owner',
 'Plug it into your own laptop, which has antivirus',
 'Format it and use it',
 'A',
 'A USB device can present itself as a keyboard and type commands the moment it is connected — antivirus does not stop that. "Finding the owner" is the exact pretext this attack relies on.'),

('ransomware-backup', 'Ransomware',
 'Which backup arrangement actually survives a ransomware infection?',
 'A second folder on the same computer',
 'An external drive left permanently connected',
 'A copy kept offline or in versioned cloud storage the malware cannot overwrite',
 'A synced cloud folder that mirrors changes instantly',
 'C',
 'Ransomware encrypts everything it can reach, including mapped drives and synced folders — a sync mirrors the encrypted files straight over your good ones. Only a copy it cannot write to survives.'),

('public-wifi', 'Privacy',
 'You need to check your bank balance on café Wi-Fi. What is the real risk today?',
 'Anyone on the network can read your HTTPS traffic',
 'Your password will be visible in plaintext',
 'There is no risk at all',
 'Being redirected to a fake login page or a hostile portal — the traffic itself is encrypted',
 'D',
 'HTTPS protects the contents of the connection even on a hostile network. The practical risks are a fake access point pushing you to a look-alike page, or a captive portal asking for credentials it has no business collecting.'),

('report-incident', 'Incident response',
 'You realise you entered your campus password into a phishing page ten minutes ago. What comes first?',
 'Wait and watch whether anything happens',
 'Change that password now and tell campus IT immediately',
 'Run an antivirus scan',
 'Delete the email so nobody else clicks it',
 'B',
 'Speed decides the outcome. Every minute the old password works is a minute the attacker can use it. Reporting matters too: if your account is one of many, IT can act on all of them — and you will not be the first person to do this.'),

('shortened-url', 'Phishing',
 'A message contains a shortened link (bit.ly, tinyurl). Why is that worth extra care?',
 'The real destination is hidden until you click, so the usual domain check is impossible',
 'Shortened links are always malicious',
 'They are slower to load',
 'They do not work on mobile',
 'A',
 'Shorteners are a normal tool, not an attack in themselves — but they remove the one signal you would otherwise rely on. Expand the link first, or paste it into SecuScan, before deciding.'),

('oversharing', 'Privacy',
 'Why does posting your first pet''s name, first school, or mother''s maiden name in a social media quiz matter?',
 'It does not matter, they are only games',
 'It uses mobile data',
 'They are the standard set of account-recovery security questions',
 'It breaks platform rules',
 'C',
 'Those "fun" quizzes collect exactly the fields used to reset passwords. Recovery questions are effectively a second password, one you may have answered publicly without realising it.')

ON DUPLICATE KEY UPDATE
    question = VALUES(question), option_a = VALUES(option_a), option_b = VALUES(option_b),
    option_c = VALUES(option_c), option_d = VALUES(option_d), correct = VALUES(correct),
    explanation = VALUES(explanation), category = VALUES(category);

-- ---------------------------------------------------------------------
-- Verify
-- ---------------------------------------------------------------------
SELECT category, COUNT(*) AS questions FROM awareness_questions WHERE active = 1 GROUP BY category;
SELECT COUNT(*) AS total_questions FROM awareness_questions WHERE active = 1;
