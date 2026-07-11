-- WebVuln Scanner database schema
-- Import with: mysql -u root -p < schema.sql

CREATE DATABASE IF NOT EXISTS webvuln_scanner CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE webvuln_scanner;

CREATE TABLE IF NOT EXISTS scans (
    id INT AUTO_INCREMENT PRIMARY KEY,
    target_url VARCHAR(512) NOT NULL,
    target_host VARCHAR(255) NOT NULL,
    status ENUM('running','completed','failed') NOT NULL DEFAULT 'running',
    risk_score INT DEFAULT 0,
    risk_level VARCHAR(20) DEFAULT 'unknown',
    started_at DATETIME NOT NULL,
    finished_at DATETIME NULL,
    error_message TEXT NULL,
    INDEX idx_target_host (target_host),
    INDEX idx_started_at (started_at)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS findings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    scan_id INT NOT NULL,
    module VARCHAR(64) NOT NULL,
    severity ENUM('info','low','medium','high','critical') NOT NULL DEFAULT 'info',
    title VARCHAR(255) NOT NULL,
    description TEXT,
    evidence TEXT,
    recommendation TEXT,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    INDEX idx_scan_id (scan_id),
    INDEX idx_severity (severity)
) ENGINE=InnoDB;
