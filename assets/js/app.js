(function () {
    const form = document.getElementById('scan-form');
    const scanBtn = document.getElementById('scan-btn');
    const urlInput = document.getElementById('target_url');
    const consentInput = document.getElementById('consent');

    const resultsPanel = document.getElementById('results-panel');
    const errorPanel = document.getElementById('error-panel');
    const errorText = document.getElementById('error-text');
    const resultsTarget = document.getElementById('results-target');
    const resultsSub = document.getElementById('results-sub');
    const riskScoreEl = document.getElementById('risk-score');
    const riskLabelEl = document.getElementById('risk-label');
    const findingsList = document.getElementById('findings-list');
    const filterBar = document.getElementById('findings-filter');
    const moduleNodes = Array.from(document.querySelectorAll('.module-node'));
    const sweep = document.getElementById('radar-sweep');

    const MODULE_ORDER = ['headers', 'cookies', 'tls', 'fingerprint', 'exposure', 'xss', 'sqli'];
    let currentFindings = [];
    let moduleTimer = null;

    function resetModules() {
        moduleNodes.forEach(n => n.classList.remove('active', 'done'));
    }

    function animateModules() {
        resetModules();
        let i = 0;
        sweep && sweep.classList.remove('idle');
        moduleTimer = setInterval(() => {
            if (i > 0) {
                const prev = moduleNodes.find(n => n.dataset.module === MODULE_ORDER[i - 1]);
                if (prev) { prev.classList.remove('active'); prev.classList.add('done'); }
            }
            if (i < MODULE_ORDER.length) {
                const node = moduleNodes.find(n => n.dataset.module === MODULE_ORDER[i]);
                if (node) node.classList.add('active');
                i++;
            } else {
                clearInterval(moduleTimer);
            }
        }, 450);
    }

    function finishModules() {
        if (moduleTimer) clearInterval(moduleTimer);
        moduleNodes.forEach(n => n.classList.remove('active'));
        moduleNodes.forEach(n => n.classList.add('done'));
        sweep && sweep.classList.add('idle');
    }

    function severityRank(sev) {
        return { critical: 0, high: 1, medium: 2, low: 3, info: 4 }[sev] ?? 5;
    }

    function renderFindings(filter) {
        findingsList.innerHTML = '';
        const filtered = filter === 'all'
            ? currentFindings
            : currentFindings.filter(f => f.severity === filter);

        if (filtered.length === 0) {
            findingsList.innerHTML = '<p class="empty-state">No findings in this category. Nice.</p>';
            return;
        }

        filtered
            .slice()
            .sort((a, b) => severityRank(a.severity) - severityRank(b.severity))
            .forEach((f, idx) => {
                const card = document.createElement('article');
                card.className = `finding-card severity-${f.severity}`;
                card.innerHTML = `
                    <div class="finding-head">
                        <span class="finding-id">F-${String(idx + 1).padStart(2, '0')}</span>
                        <span class="severity-tag severity-tag-${f.severity}">${f.severity}</span>
                        <span class="module-tag">${f.module}</span>
                    </div>
                    <h3>${escapeHtml(f.title)}</h3>
                    <p>${escapeHtml(f.description)}</p>
                    ${f.evidence ? `<p class="evidence mono">${escapeHtml(f.evidence)}</p>` : ''}
                    ${f.recommendation ? `<p class="recommendation"><strong>Fix:</strong> ${escapeHtml(f.recommendation)}</p>` : ''}
                `;
                findingsList.appendChild(card);
            });
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str ?? '';
        return div.innerHTML;
    }

    filterBar.addEventListener('click', (e) => {
        const btn = e.target.closest('.filter-chip');
        if (!btn) return;
        filterBar.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
        btn.classList.add('active');
        renderFindings(btn.dataset.filter);
    });

    form.addEventListener('submit', async (e) => {
        e.preventDefault();

        errorPanel.hidden = true;
        resultsPanel.hidden = true;
        scanBtn.disabled = true;
        scanBtn.textContent = 'Scanning…';
        animateModules();

        try {
            const res = await fetch('api/scan.php', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    target_url: urlInput.value.trim(),
                    consent: consentInput.checked,
                }),
            });
            const data = await res.json();
            finishModules();

            if (!data.ok) {
                errorText.textContent = data.error || 'Scan failed for an unknown reason.';
                errorPanel.hidden = false;
                return;
            }

            currentFindings = data.findings || [];
            resultsTarget.textContent = 'Results';
            resultsSub.textContent = data.target_url;
            riskScoreEl.textContent = data.risk_score;
            riskLabelEl.textContent = data.risk_level;
            riskScoreEl.parentElement.className = `risk-badge risk-${data.risk_level}`;

            filterBar.querySelectorAll('.filter-chip').forEach(c => c.classList.remove('active'));
            filterBar.querySelector('[data-filter="all"]').classList.add('active');
            renderFindings('all');

            resultsPanel.hidden = false;
            resultsPanel.scrollIntoView({ behavior: 'smooth', block: 'start' });
        } catch (err) {
            finishModules();
            errorText.textContent = 'Network error contacting the scan API: ' + err.message;
            errorPanel.hidden = false;
        } finally {
            scanBtn.disabled = false;
            scanBtn.textContent = 'Run scan';
        }
    });
})();
