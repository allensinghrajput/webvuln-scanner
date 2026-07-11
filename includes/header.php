<?php $current = basename($_SERVER['SCRIPT_NAME']); ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title><?= isset($pageTitle) ? htmlspecialchars($pageTitle) . ' · ' : '' ?>WebVuln Scanner</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;600;700&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="assets/css/style.css">
</head>
<body>
<div class="grid-overlay" aria-hidden="true"></div>
<header class="topbar">
    <a href="index.php" class="brand">
        <span class="brand-mark" aria-hidden="true">
            <svg viewBox="0 0 32 32" width="26" height="26">
                <circle cx="16" cy="16" r="14" fill="none" stroke="var(--accent-cyan)" stroke-width="1.5"/>
                <circle cx="16" cy="16" r="8" fill="none" stroke="var(--accent-cyan)" stroke-width="1" opacity="0.6"/>
                <circle cx="16" cy="16" r="2.5" fill="var(--accent-cyan)"/>
                <line x1="16" y1="2" x2="16" y2="8" stroke="var(--accent-cyan)" stroke-width="1.5"/>
            </svg>
        </span>
        <span class="brand-text">WebVuln<span class="brand-accent">Scanner</span></span>
    </a>
    <nav class="topnav">
        <a href="index.php" class="<?= $current === 'index.php' ? 'active' : '' ?>">New scan</a>
        <a href="history.php" class="<?= $current === 'history.php' ? 'active' : '' ?>">Scan history</a>
    </nav>
</header>
<main class="page">
