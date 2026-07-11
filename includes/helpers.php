<?php
require_once __DIR__ . '/../config.php';

/**
 * Validate that a user-supplied URL is well formed and (optionally) that
 * its host does not resolve to a private/loopback/link-local address.
 * This stops the scanner being abused as an SSRF pivot against internal
 * infrastructure when it is exposed to multiple users.
 *
 * @return array{ok:bool, error?:string, host?:string, scheme?:string}
 */
function validate_target_url(string $url): array
{
    $url = trim($url);

    if ($url === '') {
        return ['ok' => false, 'error' => 'Please enter a target URL.'];
    }

    // Require an explicit scheme so parse_url behaves predictably.
    if (!preg_match('#^https?://#i', $url)) {
        $url = 'http://' . $url;
    }

    $parts = parse_url($url);
    if ($parts === false || empty($parts['host'])) {
        return ['ok' => false, 'error' => 'That does not look like a valid URL.'];
    }

    $scheme = strtolower($parts['scheme'] ?? 'http');
    if (!in_array($scheme, ['http', 'https'], true)) {
        return ['ok' => false, 'error' => 'Only http:// and https:// targets are supported.'];
    }

    $host = $parts['host'];

    if (BLOCK_PRIVATE_TARGETS) {
        $ips = [];
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $ips[] = $host;
        } else {
            $records = @dns_get_record($host, DNS_A | DNS_AAAA);
            if ($records) {
                foreach ($records as $r) {
                    if (!empty($r['ip'])) $ips[] = $r['ip'];
                    if (!empty($r['ipv6'])) $ips[] = $r['ipv6'];
                }
            }
        }

        foreach ($ips as $ip) {
            if (is_private_or_reserved_ip($ip)) {
                return [
                    'ok' => false,
                    'error' => "Refusing to scan $host — it resolves to a private/internal address ($ip). " .
                               "Set BLOCK_PRIVATE_TARGETS to false in config.php if you specifically intend to scan internal infrastructure you control.",
                ];
            }
        }

        if (in_array(strtolower($host), ['localhost'], true)) {
            return ['ok' => false, 'error' => 'Refusing to scan localhost. Adjust config.php if this is intentional.'];
        }
    }

    return ['ok' => true, 'host' => $host, 'scheme' => $scheme, 'url' => $url];
}

function is_private_or_reserved_ip(string $ip): bool
{
    // filter_var with these flags returns false for private/reserved ranges,
    // which is exactly what we want to catch.
    return filter_var(
        $ip,
        FILTER_VALIDATE_IP,
        FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
    ) === false;
}

/**
 * Perform an HTTP GET with curl, returning headers, body, status and timing.
 * Never throws — errors are returned in the array so scan modules can
 * degrade gracefully instead of fataling the whole scan.
 */
function http_get(string $url, int $timeout = SCAN_TIMEOUT): array
{
    $ch = curl_init();
    curl_setopt_array($ch, [
        CURLOPT_URL => $url,
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HEADER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_MAXREDIRS => 5,
        CURLOPT_TIMEOUT => $timeout,
        CURLOPT_CONNECTTIMEOUT => $timeout,
        CURLOPT_SSL_VERIFYPEER => false, // we report TLS problems ourselves, don't want curl to hard-fail
        CURLOPT_SSL_VERIFYHOST => 0,
        CURLOPT_USERAGENT => SCAN_USER_AGENT,
        CURLOPT_ENCODING => '',
    ]);

    $raw = curl_exec($ch);
    $err = curl_error($ch);
    $info = curl_getinfo($ch);
    curl_close($ch);

    if ($raw === false) {
        return ['ok' => false, 'error' => $err ?: 'Request failed', 'info' => $info];
    }

    $headerSize = $info['header_size'] ?? 0;
    $rawHeaders = substr($raw, 0, $headerSize);
    $body = substr($raw, $headerSize);

    return [
        'ok' => true,
        'status' => $info['http_code'] ?? 0,
        'headers' => parse_raw_headers($rawHeaders),
        'raw_headers' => $rawHeaders,
        'body' => $body,
        'info' => $info,
    ];
}

/**
 * Parses raw HTTP header text (possibly across several responses if
 * redirects happened) into a flat, lower-cased-key associative array
 * of the FINAL response's headers, plus all Set-Cookie values.
 */
function parse_raw_headers(string $rawHeaders): array
{
    $blocks = preg_split('/\r?\n\r?\n/', trim($rawHeaders));
    $lastBlock = end($blocks);
    $lines = preg_split('/\r?\n/', trim($lastBlock));

    $headers = [];
    $cookies = [];

    foreach ($lines as $line) {
        if (stripos($line, 'HTTP/') === 0) {
            continue;
        }
        if (strpos($line, ':') === false) {
            continue;
        }
        [$k, $v] = explode(':', $line, 2);
        $k = strtolower(trim($k));
        $v = trim($v);

        if ($k === 'set-cookie') {
            $cookies[] = $v;
        }

        if (isset($headers[$k])) {
            $headers[$k] .= ', ' . $v;
        } else {
            $headers[$k] = $v;
        }
    }

    $headers['_set_cookie_all'] = $cookies;
    return $headers;
}

function severity_weight(string $severity): int
{
    return match ($severity) {
        'critical' => 40,
        'high' => 20,
        'medium' => 10,
        'low' => 4,
        default => 0,
    };
}

function risk_level_from_score(int $score): string
{
    if ($score >= 80) return 'critical';
    if ($score >= 50) return 'high';
    if ($score >= 20) return 'medium';
    if ($score > 0) return 'low';
    return 'info';
}

function json_out(array $data, int $code = 200): void
{
    http_response_code($code);
    header('Content-Type: application/json');
    echo json_encode($data, JSON_UNESCAPED_SLASHES);
    exit;
}
