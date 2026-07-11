<?php
$pageTitle = 'Scan detail';
require_once __DIR__ . '/includes/db.php';

$id = (int) ($_GET['id'] ?? 0);
$pdo = get_db();

$stmt = $pdo->prepare('SELECT * FROM scans WHERE id = :id');
$stmt->execute([':id' => $id]);
$scan = $stmt->fetch();

include __DIR__ . '/includes/header.php';

if (!$scan) {
    echo '<section class="panel"><p class="empty-state">Scan not found. <a href="history.php">Back to history</a>.</p></section>';
    include __DIR__ . '/includes/footer.php';
    exit;
}

$stmt = $pdo->prepare('SELECT * FROM findings WHERE scan_id = :id ORDER BY FIELD(severity,"critical","high","medium","low","info")');
$stmt->execute([':id' => $id]);
$findings = $stmt->fetchAll();
?>

<section class="panel">
    <div class="results-header">
        <div>
            <h2 class="panel-title mono"><?= htmlspecialchars($scan['target_url']) ?></h2>
            <p class="results-sub">
                Started <?= htmlspecialchars($scan['started_at']) ?>
                <?php if ($scan['finished_at']): ?> · finished <?= htmlspecialchars($scan['finished_at']) ?><?php endif; ?>
                · status: <?= htmlspecialchars($scan['status']) ?>
            </p>
        </div>
        <div class="risk-badge">
            <span class="risk-score"><?= (int) $scan['risk_score'] ?></span>
            <span class="risk-label"><?= htmlspecialchars($scan['risk_level']) ?></span>
        </div>
    </div>

    <?php if ($scan['status'] === 'failed'): ?>
        <p class="error-text"><?= htmlspecialchars($scan['error_message']) ?></p>
    <?php elseif (empty($findings)): ?>
        <p class="empty-state">No findings recorded for this scan.</p>
    <?php else: ?>
        <div class="findings-list">
            <?php foreach ($findings as $i => $f): ?>
                <article class="finding-card severity-<?= htmlspecialchars($f['severity']) ?>">
                    <div class="finding-head">
                        <span class="finding-id">F-<?= str_pad($i + 1, 2, '0', STR_PAD_LEFT) ?></span>
                        <span class="severity-tag severity-tag-<?= htmlspecialchars($f['severity']) ?>"><?= htmlspecialchars($f['severity']) ?></span>
                        <span class="module-tag"><?= htmlspecialchars($f['module']) ?></span>
                    </div>
                    <h3><?= htmlspecialchars($f['title']) ?></h3>
                    <p><?= htmlspecialchars($f['description']) ?></p>
                    <?php if ($f['evidence']): ?><p class="evidence mono"><?= htmlspecialchars($f['evidence']) ?></p><?php endif; ?>
                    <?php if ($f['recommendation']): ?><p class="recommendation"><strong>Fix:</strong> <?= htmlspecialchars($f['recommendation']) ?></p><?php endif; ?>
                </article>
            <?php endforeach; ?>
        </div>
    <?php endif; ?>
</section>

<?php include __DIR__ . '/includes/footer.php'; ?>
