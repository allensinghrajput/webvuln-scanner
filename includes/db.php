<?php
require_once __DIR__ . '/../config.php';

/**
 * Returns a shared PDO connection. Dies with a JSON error if the DB
 * is unreachable so the frontend can show something useful instead of
 * a raw PHP warning.
 */
function get_db(): PDO
{
    static $pdo = null;

    if ($pdo !== null) {
        return $pdo;
    }

    $dsn = 'mysql:host=' . DB_HOST . ';dbname=' . DB_NAME . ';charset=' . DB_CHARSET;

    try {
        $pdo = new PDO($dsn, DB_USER, DB_PASS, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]);
        return $pdo;
    } catch (PDOException $e) {
        http_response_code(500);
        header('Content-Type: application/json');
        echo json_encode([
            'ok' => false,
            'error' => 'Database connection failed. Have you imported sql/schema.sql and set the credentials in config.php? (' . $e->getMessage() . ')',
        ]);
        exit;
    }
}
