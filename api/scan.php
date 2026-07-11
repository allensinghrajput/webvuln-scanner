<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);

require_once __DIR__ . '/../includes/helpers.php';
require_once __DIR__ . '/../includes/db.php';
require_once __DIR__ . '/../includes/Scanner.php';

header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_out(['ok' => false, 'error' => 'Method not allowed'], 405);
}

$input = json_decode(file_get_contents('php://input'), true) ?? $_POST;

$targetUrl = trim($input['target_url'] ?? '');
$consent = (bool) ($input['consent'] ?? false);

if (!$consent) {
    json_out(['ok' => false, 'error' => 'You must confirm you are authorized to scan this target before scanning.'], 400);
}

$validation = validate_target_url($targetUrl);
if (!$validation['ok']) {
    json_out(['ok' => false, 'error' => $validation['error']], 400);
}

$pdo = get_db();

$stmt = $pdo->prepare(
    'INSERT INTO scans (target_url, target_host, status, started_at) VALUES (:url, :host, "running", NOW())'
);
$stmt->execute([':url' => $validation['url'], ':host' => $validation['host']]);
$scanId = (int) $pdo->lastInsertId();

try {
    $scanner = new Scanner($validation['url'], $validation['host'], $validation['scheme']);
    $result = $scanner->run();

    if (!$result['ok']) {
        $stmt = $pdo->prepare('UPDATE scans SET status = "failed", error_message = :err, finished_at = NOW() WHERE id = :id');
        $stmt->execute([':err' => $result['error'], ':id' => $scanId]);
        json_out(['ok' => false, 'error' => $result['error'], 'scan_id' => $scanId], 502);
    }

    $insertFinding = $pdo->prepare(
        'INSERT INTO findings (scan_id, module, severity, title, description, evidence, recommendation)
         VALUES (:scan_id, :module, :severity, :title, :description, :evidence, :recommendation)'
    );

    foreach ($result['findings'] as $f) {
        $insertFinding->execute([
            ':scan_id' => $scanId,
            ':module' => $f['module'],
            ':severity' => $f['severity'],
            ':title' => $f['title'],
            ':description' => $f['description'],
            ':evidence' => $f['evidence'],
            ':recommendation' => $f['recommendation'],
        ]);
    }

    $stmt = $pdo->prepare(
        'UPDATE scans SET status = "completed", risk_score = :score, risk_level = :level, finished_at = NOW() WHERE id = :id'
    );
    $stmt->execute([':score' => $result['risk_score'], ':level' => $result['risk_level'], ':id' => $scanId]);

    json_out([
        'ok' => true,
        'scan_id' => $scanId,
        'target_url' => $validation['url'],
        'risk_score' => $result['risk_score'],
        'risk_level' => $result['risk_level'],
        'findings' => $result['findings'],
    ]);
} catch (Throwable $e) {
    $stmt = $pdo->prepare('UPDATE scans SET status = "failed", error_message = :err, finished_at = NOW() WHERE id = :id');
    $stmt->execute([':err' => $e->getMessage(), ':id' => $scanId]);
    json_out(['ok' => false, 'error' => 'Scan failed: ' . $e->getMessage(), 'scan_id' => $scanId], 500);
}
