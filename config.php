<?php
/**
 * WebVuln Scanner - Configuration
 * Copy this file and edit the values for your environment.
 */

// ---- Database ----
define('DB_HOST', '127.0.0.1');
define('DB_NAME', 'webvuln_scanner');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_CHARSET', 'utf8mb4');

// ---- Scanner behaviour ----

// Max seconds to wait for each HTTP request the scanner makes to a target.
define('SCAN_TIMEOUT', 10);

// User-Agent string sent by the scanner. Identifying yourself is good practice.
define('SCAN_USER_AGENT', 'WebVulnScanner/1.0 (+authorized-security-testing)');

// If true, blocks scanning of private/loopback/link-local IP ranges (RFC1918,
// 127.0.0.0/8, 169.254.0.0/16, etc.) to prevent this tool being used as an
// SSRF pivot into your internal network. Turn off ONLY if you specifically
// intend to scan internal infrastructure you control, on a trusted network.
define('BLOCK_PRIVATE_TARGETS', true);

// Maximum number of links/forms the XSS/SQLi param modules will probe per scan.
define('MAX_PROBE_TARGETS', 15);

date_default_timezone_set('UTC');
