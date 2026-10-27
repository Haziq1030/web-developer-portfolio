<?php
session_start();
$conn = new mysqli("localhost", "root", "", "secuscan_db");

if (!$conn) {
    die("Database connection failed.");
}

$statusTitle = "Verification failed";
$statusText = "This link is invalid or has already been used.";
$statusLink = "<a href='login.php' class='verify-action-btn'><i class='fa-solid fa-arrow-right-to-bracket me-2'></i>Back to login</a>";

if (!isset($_GET['token']) || empty($_GET['token'])) {
    $statusTitle = "Invalid verification link";
    $statusText = "Please use the link from your email.";
    $statusLink = "<a href='login.php' class='verify-action-btn'><i class='fa-solid fa-arrow-right-to-bracket me-2'></i>Back to login</a>";
} else {
    $token = trim($_GET['token']);
    $stmt = $conn->prepare("SELECT id, username, email FROM users WHERE verification_token = ? LIMIT 1");
    $stmt->bind_param("s", $token);
    $stmt->execute();
    $result = $stmt->get_result();

    if ($user = $result->fetch_assoc()) {
        $update = $conn->prepare("UPDATE users SET email_verified = 1, verification_token = NULL WHERE id = ?");
        $update->bind_param("i", $user['id']);
        $update->execute();

        $statusTitle = "Email verified successfully!";
        $statusText = "Welcome, " . htmlspecialchars($user['username']) . ". Your account is now active.";
        $statusLink = "<a href='login.php' class='verify-action-btn'><i class='fa-solid fa-arrow-right-to-bracket me-2'></i>Click here to login</a>";
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Email Verification - SecuScan</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="style.css">
    <style>
        * { box-sizing: border-box; }
        body {
            margin: 0;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 24px;
            background: linear-gradient(135deg, #f8fbff 0%, #eef4ff 52%, #f1f5f9 100%);
            color: #0f172a;
            font-family: 'Plus Jakarta Sans', sans-serif;
            overflow: hidden;
        }
        body:before, body:after {
            content: '';
            position: fixed;
            width: 300px;
            height: 300px;
            border-radius: 50%;
            filter: blur(75px);
            pointer-events: none;
            opacity: .35;
        }
        body:before { top: -140px; left: -100px; background: rgba(96, 165, 250, .3); }
        body:after { right: -100px; bottom: -160px; background: rgba(147, 197, 253, .45); }
        .verify-card {
            position: relative;
            z-index: 1;
            width: 100%;
            max-width: 540px;
            background: rgba(255,255,255,.94);
            border: 1px solid rgba(148,163,184,.25);
            border-radius: 18px;
            box-shadow: 0 20px 50px rgba(15,23,42,.08);
            padding: 2.5rem 2rem;
            text-align: center;
        }
        .brand-icon {
            width: 64px;
            height: 64px;
            display: grid;
            place-items: center;
            margin: 0 auto 1.25rem;
            color: #2563eb;
            border: 1px solid rgba(37,99,235,.18);
            border-radius: 18px;
            background: rgba(37,99,235,.05);
            box-shadow: inset 0 0 18px rgba(37,99,235,.04);
        }
        .brand-title {
            color: #0f172a;
            font-family: 'Orbitron', sans-serif;
            font-size: clamp(1.5rem, 2vw, 2rem);
            letter-spacing: .04em;
            margin-bottom: .5rem;
        }
        .verify-card h3 {
            margin: 0 0 1rem;
            font-size: clamp(1.4rem, 2vw, 2rem);
            color: #111827;
            font-weight: 800;
        }
        .verify-card p {
            margin: 0 0 1rem;
            color: #334155;
            font-size: 1rem;
        }
        .verify-action-btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 220px;
            padding: 12px 20px;
            border-radius: 10px;
            background: linear-gradient(135deg, #ff5f6d, #ffc371, #4facfe, #00c6ff);
            background-size: 220% 220%;
            color: #ffffff !important;
            font-weight: 800;
            text-decoration: none !important;
            box-shadow: 0 10px 22px rgba(79, 172, 254, .25);
            animation: verifyBlink 0.6s ease-in-out infinite alternate;
        }
        .verify-action-btn:hover {
            color: #ffffff !important;
            text-decoration: none !important;
            transform: translateY(-1px);
        }
        @keyframes verifyBlink {
            0% { opacity: 1; transform: scale(1); background-position: 0% 50%; }
            100% { opacity: .82; transform: scale(1.02); background-position: 100% 50%; }
        }
        @media (max-width: 480px) {
            .verify-card { padding: 2rem 1.35rem; }
            .verify-action-btn { min-width: 100%; }
        }
    </style>
</head>
<body>
    <div class="verify-card">
        <div class="brand-icon"><i class="fa-solid fa-shield-halved fa-2x"></i></div>
        <h1 class="brand-title">SecuScan</h1>
        <h3><?php echo htmlspecialchars($statusTitle); ?></h3>
        <p><?php echo htmlspecialchars($statusText); ?></p>
        <p><?php echo $statusLink; ?></p>
    </div>
</body>
</html>
