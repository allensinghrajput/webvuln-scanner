<?php $pageTitle = 'New scan'; include __DIR__ . '/includes/header.php'; ?>

<section class="hero">
    <div class="hero-copy">
        <p class="eyebrow">Passive · non-destructive scanning</p>
        <h1>Map a site's attack surface before someone else does.</h1>
        <p class="hero-sub">
            Checks security headers, TLS, cookies, exposed files, CMS/server fingerprints,
            and probes for reflected XSS and error-based SQL injection — all read-only.
        </p>
    </div>
    <div class="hero-radar" aria-hidden="true">
        <svg viewBox="0 0 240 240" id="radar-svg">
            <circle cx="120" cy="120" r="110" class="radar-ring"/>
            <circle cx="120" cy="120" r="78" class="radar-ring"/>
            <circle cx="120" cy="120" r="46" class="radar-ring"/>
            <line x1="120" y1="10" x2="120" y2="230" class="radar-cross"/>
            <line x1="10" y1="120" x2="230" y2="120" class="radar-cross"/>
            <g id="radar-sweep" class="radar-sweep-group">
                <path d="M120,120 L120,10 A110,110 0 0,1 197,197 Z" fill="url(#sweepGrad)"/>
            </g>
            <defs>
                <linearGradient id="sweepGrad" x1="0" y1="0" x2="1" y2="1">
                    <stop offset="0%" stop-color="var(--accent-cyan)" stop-opacity="0.35"/>
                    <stop offset="100%" stop-color="var(--accent-cyan)" stop-opacity="0"/>
                </linearGradient>
            </defs>
            <circle cx="120" cy="120" r="3" fill="var(--accent-cyan)"/>
        </svg>
    </div>
</section>

<section class="panel scan-form-panel">
    <form id="scan-form">
        <label for="target_url">Target URL</label>
        <div class="input-row">
            <input type="text" id="target_url" name="target_url" placeholder="https://example.com" autocomplete="off" required>
            <button type="submit" id="scan-btn">Run scan</button>
        </div>

        <label class="consent-row">
            <input type="checkbox" id="consent" name="consent" required>
            <span>I own this target, or I have explicit written authorization to test it.</span>
        </label>
        <p class="form-note">Scans of private/internal IP ranges are blocked by default (see <code>config.php</code>).</p>
    </form>
</section>

<section class="panel" id="modules-panel">
    <h2 class="panel-title">Check modules</h2>
    <div class="module-grid" id="module-grid">
        <div class="module-node" data-module="headers"><span class="node-dot"></span>Security headers</div>
        <div class="module-node" data-module="cookies"><span class="node-dot"></span>Cookie flags</div>
        <div class="module-node" data-module="tls"><span class="node-dot"></span>TLS / certificate</div>
        <div class="module-node" data-module="fingerprint"><span class="node-dot"></span>Tech fingerprint</div>
        <div class="module-node" data-module="exposure"><span class="node-dot"></span>Exposed files</div>
        <div class="module-node" data-module="xss"><span class="node-dot"></span>Reflected XSS</div>
        <div class="module-node" data-module="sqli"><span class="node-dot"></span>SQLi (error-based)</div>
    </div>
</section>

<section class="panel" id="results-panel" hidden>
    <div class="results-header">
        <div>
            <h2 class="panel-title" id="results-target">Results</h2>
            <p class="results-sub" id="results-sub"></p>
        </div>
        <div class="risk-badge" id="risk-badge">
            <span class="risk-score" id="risk-score">--</span>
            <span class="risk-label" id="risk-label">—</span>
        </div>
    </div>
    <div class="findings-filter" id="findings-filter">
        <button type="button" class="filter-chip active" data-filter="all">All</button>
        <button type="button" class="filter-chip" data-filter="critical">Critical</button>
        <button type="button" class="filter-chip" data-filter="high">High</button>
        <button type="button" class="filter-chip" data-filter="medium">Medium</button>
        <button type="button" class="filter-chip" data-filter="low">Low</button>
        <button type="button" class="filter-chip" data-filter="info">Info</button>
    </div>
    <div class="findings-list" id="findings-list"></div>
</section>

<section class="panel" id="error-panel" hidden>
    <p id="error-text"></p>
</section>

<script src="assets/js/app.js"></script>

<?php include __DIR__ . '/includes/footer.php'; ?>
