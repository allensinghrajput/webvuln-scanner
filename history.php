<?php
$pageTitle = 'Scan history';
require_once __DIR__ . '/includes/db.php';
include __DIR__ . '/includes/header.php';

$pdo = get_db();
$scans = $pdo->query(
    'SELECT id, target_url, status, risk_score, risk_level, started_at, finished_at
     FROM scans ORDER BY started_at DESC LIMIT 100'
)->fetchAll();
?>

<section class="panel">
    <h2 class="panel-title">Scan history</h2>

    <?php if (empty($scans)): ?>
        <p class="empty-state">No scans yet. <a href="index.php">Run your first scan</a>.</p>
    <?php else: ?>
    <table class="history-table">
        <thead>
        <tr>
            <th>Target</th>
            <th>Status</th>
            <th>Risk</th>
            <th>Started</th>
            <th></th>
        </tr>
        </thead>
        <tbody>
        <?php foreach ($scans as $s): ?>
            <tr>
                <td class="mono"><?= htmlspecialchars($s['target_url']) ?></td>
                <td><span class="status-pill status-<?= htmlspecialchars($s['status']) ?>"><?= htmlspecialchars($s['status']) ?></span></td>
                <td><span class="risk-pill risk-<?= htmlspecialchars($s['risk_level']) ?>"><?= htmlspecialchars($s['risk_level']) ?> (<?= (int)$s['risk_score'] ?>)</span></td>
                <td class="mono"><?= htmlspecialchars($s['started_at']) ?></td>
                <td><a href="scan_detail.php?id=<?= (int)$s['id'] ?>" class="link-btn">View →</a></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
    <?php endif; ?>
</section>

<?php include __DIR__ . '/includes/footer.php'; ?>
