<?php
require_once __DIR__ . '/helpers.php';

/**
 * WebVuln Scanner core.
 *
 * IMPORTANT: every check here is passive / non-destructive detection.
 * Nothing in this class writes, deletes, or exfiltrates data from the
 * target — it only inspects responses the target already sends back
 * for a normal request, or sends a single benign marker/character to
 * see how it's handled. This tool is for testing sites you own or are
 * explicitly authorized to test.
 */
class Scanner
{
    private string $baseUrl;
    private string $host;
    private string $scheme;
    /** @var array<int, array{module:string,severity:string,title:string,description:string,evidence:string,recommendation:string}> */
    private array $findings = [];

    public function __construct(string $baseUrl, string $host, string $scheme)
    {
        $this->baseUrl = rtrim($baseUrl, '/');
        $this->host = $host;
        $this->scheme = $scheme;
    }

    public function run(): array
    {
        $main = http_get($this->baseUrl);

        if (!$main['ok']) {
            return [
                'ok' => false,
                'error' => 'Could not connect to target: ' . $main['error'],
                'findings' => [],
            ];
        }

        $headers = $main['headers'];
        $body = $main['body'];

        $this->checkSecurityHeaders($headers, $this->scheme);
        $this->checkCookies($headers);
        $this->checkServerFingerprint($headers, $body);
        if ($this->scheme === 'https') {
            $this->checkTls();
        } else {
            $this->addFinding('tls', 'medium', 'Site served over plain HTTP',
                'The target does not use HTTPS by default, so traffic (including any login data) can be read or altered in transit.',
                'Scanned URL used http://',
                'Serve the site over HTTPS and redirect all HTTP traffic to HTTPS.');
        }
        $this->checkExposedFiles();
        $this->checkDirectoryListing();
        $this->checkRobotsAndSitemap();

        $probeTargets = $this->extractProbeTargets($body);
        if (!empty($probeTargets)) {
            $this->checkReflectedXSS($probeTargets);
            $this->checkSQLiErrors($probeTargets);
        }

        $score = 0;
        foreach ($this->findings as $f) {
            $score += severity_weight($f['severity']);
        }
        $score = min(100, $score);

        return [
            'ok' => true,
            'findings' => $this->findings,
            'risk_score' => $score,
            'risk_level' => risk_level_from_score($score),
            'http_status' => $main['status'],
        ];
    }

    private function addFinding(string $module, string $severity, string $title, string $description, string $evidence, string $recommendation): void
    {
        $this->findings[] = compact('module', 'severity', 'title', 'description', 'evidence', 'recommendation');
    }

    // ---------------------------------------------------------------
    // Security headers
    // ---------------------------------------------------------------
    private function checkSecurityHeaders(array $headers, string $scheme): void
    {
        $checks = [
            'strict-transport-security' => [
                'title' => 'Missing Strict-Transport-Security header',
                'desc' => 'HSTS tells browsers to only ever talk to this site over HTTPS. Without it, users can be downgraded to HTTP by an attacker on the network.',
                'sev' => $scheme === 'https' ? 'medium' : 'low',
                'rec' => "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                'onlyHttps' => true,
            ],
            'content-security-policy' => [
                'title' => 'Missing Content-Security-Policy header',
                'desc' => 'CSP restricts which scripts/styles/resources a page may load, and is one of the strongest defenses against XSS.',
                'sev' => 'medium',
                'rec' => "Define a CSP, e.g.: Content-Security-Policy: default-src 'self'",
                'onlyHttps' => false,
            ],
            'x-content-type-options' => [
                'title' => 'Missing X-Content-Type-Options header',
                'desc' => 'Without this header, older browsers may "sniff" content types, which can turn an upload endpoint into a script-execution vector.',
                'sev' => 'low',
                'rec' => 'Add: X-Content-Type-Options: nosniff',
                'onlyHttps' => false,
            ],
            'x-frame-options' => [
                'title' => 'Missing X-Frame-Options header',
                'desc' => 'Without this (or a frame-ancestors CSP directive), the site can be embedded in an iframe on another site, enabling clickjacking.',
                'sev' => 'medium',
                'rec' => 'Add: X-Frame-Options: DENY (or SAMEORIGIN), or a CSP frame-ancestors directive.',
                'onlyHttps' => false,
            ],
            'referrer-policy' => [
                'title' => 'Missing Referrer-Policy header',
                'desc' => 'Without a Referrer-Policy, full URLs (sometimes containing tokens or IDs) may leak to third-party sites via the Referer header.',
                'sev' => 'low',
                'rec' => 'Add: Referrer-Policy: strict-origin-when-cross-origin',
                'onlyHttps' => false,
            ],
            'permissions-policy' => [
                'title' => 'Missing Permissions-Policy header',
                'desc' => 'Permissions-Policy restricts access to browser features (camera, mic, geolocation) for embedded/third-party content.',
                'sev' => 'info',
                'rec' => "Add a Permissions-Policy header limiting features you don't use, e.g.: Permissions-Policy: geolocation=(), camera=()",
                'onlyHttps' => false,
            ],
        ];

        foreach ($checks as $headerName => $c) {
            if ($c['onlyHttps'] && $scheme !== 'https') {
                continue;
            }
            if (!isset($headers[$headerName])) {
                $this->addFinding('headers', $c['sev'], $c['title'], $c['desc'], 'Header absent from response', $c['rec']);
            }
        }

        // Server / X-Powered-By verbosity is handled in fingerprinting.
    }

    // ---------------------------------------------------------------
    // Cookies
    // ---------------------------------------------------------------
    private function checkCookies(array $headers): void
    {
        $cookies = $headers['_set_cookie_all'] ?? [];
        foreach ($cookies as $cookie) {
            $name = explode('=', $cookie, 2)[0];
            $lower = strtolower($cookie);
            $issues = [];

            if (strpos($lower, 'secure') === false && $this->scheme === 'https') {
                $issues[] = 'missing Secure flag';
            }
            if (strpos($lower, 'httponly') === false) {
                $issues[] = 'missing HttpOnly flag';
            }
            if (strpos($lower, 'samesite') === false) {
                $issues[] = 'missing SameSite attribute';
            }

            if (!empty($issues)) {
                $looksSensitive = preg_match('/sess|token|auth|login|id\b/i', $name);
                $this->addFinding(
                    'cookies',
                    $looksSensitive ? 'medium' : 'low',
                    "Cookie '$name' has weak flags",
                    'Cookies missing Secure/HttpOnly/SameSite are more exposed to theft via XSS or network interception, and to CSRF.',
                    implode(', ', $issues) . " on: $cookie",
                    'Set Secure, HttpOnly and SameSite=Lax (or Strict) on all session/auth cookies.'
                );
            }
        }
    }

    // ---------------------------------------------------------------
    // TLS / SSL
    // ---------------------------------------------------------------
    private function checkTls(): void
    {
        $context = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => false,
                'verify_peer_name' => false,
            ],
        ]);

        $client = @stream_socket_client(
            "ssl://{$this->host}:443",
            $errno,
            $errstr,
            SCAN_TIMEOUT,
            STREAM_CLIENT_CONNECT,
            $context
        );

        if (!$client) {
            $this->addFinding('tls', 'medium', 'Could not establish a TLS connection to verify certificate',
                "Connection error: $errstr",
                "errno=$errno",
                'Ensure port 443 is reachable and serving a valid TLS certificate.');
            return;
        }

        $params = stream_context_get_params($client);
        $cert = $params['options']['ssl']['peer_certificate'] ?? null;
        fclose($client);

        if (!$cert) {
            return;
        }

        $certInfo = openssl_x509_parse($cert);
        if (!$certInfo) {
            return;
        }

        $validTo = $certInfo['validTo_time_t'] ?? null;
        if ($validTo !== null) {
            $daysLeft = (int) floor(($validTo - time()) / 86400);
            if ($daysLeft < 0) {
                $this->addFinding('tls', 'critical', 'TLS certificate has expired',
                    'An expired certificate breaks trust indicators and browsers will show warnings to every visitor.',
                    'Certificate expired ' . date('Y-m-d', $validTo),
                    'Renew the TLS certificate immediately.');
            } elseif ($daysLeft < 14) {
                $this->addFinding('tls', 'high', 'TLS certificate expires very soon',
                    "The certificate expires in $daysLeft day(s).",
                    'Valid to: ' . date('Y-m-d', $validTo),
                    'Renew the certificate now to avoid an outage/browser warning.');
            } elseif ($daysLeft < 30) {
                $this->addFinding('tls', 'low', 'TLS certificate expiring soon',
                    "The certificate expires in $daysLeft day(s).",
                    'Valid to: ' . date('Y-m-d', $validTo),
                    'Plan a renewal within the next couple of weeks.');
            }
        }

        $commonName = $certInfo['subject']['CN'] ?? '';
        $altNames = $certInfo['extensions']['subjectAltName'] ?? '';
        if ($commonName && stripos($altNames, $this->host) === false && strcasecmp($commonName, $this->host) !== 0) {
            $this->addFinding('tls', 'high', 'TLS certificate does not match hostname',
                "Certificate CN/SAN does not appear to cover {$this->host}.",
                "CN=$commonName; SAN=$altNames",
                'Issue a certificate that covers the hostname being served (or all relevant SANs).');
        }

        $issuer = $certInfo['issuer']['CN'] ?? '';
        if (stripos($issuer, 'self') !== false || $issuer === $commonName) {
            $this->addFinding('tls', 'medium', 'Possible self-signed certificate',
                'Self-signed certificates are not trusted by browsers by default and will trigger warnings.',
                "Issuer CN=$issuer",
                'Use a certificate from a trusted CA (e.g. via Let\'s Encrypt).');
        }
    }

    // ---------------------------------------------------------------
    // Server / framework / CMS fingerprinting
    // ---------------------------------------------------------------
    private function checkServerFingerprint(array $headers, string $body): void
    {
        if (!empty($headers['server'])) {
            $server = $headers['server'];
            if (preg_match('/[0-9]+\.[0-9]+/', $server)) {
                $this->addFinding('fingerprint', 'low', 'Server header discloses version number',
                    'Revealing exact software versions makes it easier for an attacker to look up known vulnerabilities for that version.',
                    "Server: $server",
                    'Configure the web server (e.g. ServerTokens Prod / ServerSignature Off in Apache) to hide version details.');
            } else {
                $this->addFinding('fingerprint', 'info', 'Web server identified', "Server header present.", "Server: $server", 'No action required unless you want to hide this too.');
            }
        }

        if (!empty($headers['x-powered-by'])) {
            $this->addFinding('fingerprint', 'low', 'X-Powered-By header discloses backend technology',
                'This reveals the language/framework (and often version) powering the site.',
                'X-Powered-By: ' . $headers['x-powered-by'],
                'Disable this header (e.g. expose_php = Off in php.ini, or strip it at the proxy/server level).');
        }

        // CMS / framework signatures - body based
        $signatures = [
            'WordPress' => ['/wp-content/', '/wp-includes/', 'wp-json'],
            'Drupal' => ['Drupal.settings', '/sites/default/files', 'drupal.js'],
            'Joomla' => ['/media/system/js/', 'Joomla!'],
            'Magento' => ['/skin/frontend/', 'Mage.Cookies'],
            'Shopify' => ['cdn.shopify.com'],
            'Laravel' => ['laravel_session'],
            'Express/Node.js' => ['X-Powered-By: Express'],
        ];

        $bodyLower = strtolower($body);
        foreach ($signatures as $name => $needles) {
            foreach ($needles as $needle) {
                if (stripos($bodyLower, strtolower($needle)) !== false || stripos($headers['x-powered-by'] ?? '', $needle) !== false) {
                    $this->addFinding('fingerprint', 'info', "Detected technology: $name",
                        "Signature '$needle' was found, suggesting the site runs $name.",
                        $needle,
                        'Keep this platform patched and updated to the latest stable version.');
                    break;
                }
            }
        }

        if (preg_match('/<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']/i', $body, $m)) {
            $this->addFinding('fingerprint', 'low', 'Generator meta tag discloses CMS/version',
                'A meta generator tag makes fingerprinting trivial for automated attack tools.',
                'meta generator: ' . $m[1],
                'Remove or blank out the generator meta tag in your CMS theme/template.');
        }
    }

    // ---------------------------------------------------------------
    // Exposed sensitive files
    // ---------------------------------------------------------------
    private function checkExposedFiles(): void
    {
        $paths = [
            '.env' => 'critical',
            '.git/config' => 'high',
            '.git/HEAD' => 'high',
            'wp-config.php.bak' => 'critical',
            'config.php.bak' => 'critical',
            'backup.zip' => 'high',
            'backup.sql' => 'critical',
            'database.sql' => 'critical',
            '.DS_Store' => 'low',
            'phpinfo.php' => 'high',
            'info.php' => 'medium',
            '.htpasswd' => 'high',
            'server-status' => 'medium',
            'composer.json' => 'low',
            '.well-known/security.txt' => 'info',
        ];

        foreach ($paths as $path => $sev) {
            $res = http_get($this->baseUrl . '/' . $path, 8);
            if (!$res['ok']) continue;

            $status = $res['status'];
            $bodyLen = strlen($res['body']);

            if ($status === 200 && $bodyLen > 0) {
                if ($path === '.well-known/security.txt') {
                    $this->addFinding('exposure', 'info', 'security.txt found',
                        'Good practice: a security.txt file tells researchers how to report vulnerabilities responsibly.',
                        "$path -> HTTP $status", 'No action needed.');
                    continue;
                }
                $this->addFinding('exposure', $sev, "Potentially sensitive file accessible: /$path",
                    'This path returned HTTP 200 with content, which may expose credentials, source code, or backups to anyone.',
                    "$path -> HTTP $status, " . $bodyLen . ' bytes',
                    'Remove this file from the public web root, or block access to it at the web server level.');
            }
        }
    }

    // ---------------------------------------------------------------
    // Directory listing
    // ---------------------------------------------------------------
    private function checkDirectoryListing(): void
    {
        $dirs = ['images', 'uploads', 'backup', 'backups', 'assets', 'includes', 'files', 'tmp'];
        foreach ($dirs as $dir) {
            $res = http_get($this->baseUrl . '/' . $dir . '/', 8);
            if (!$res['ok']) continue;

            if ($res['status'] === 200 && preg_match('/Index of \/|Directory Listing For/i', $res['body'])) {
                $this->addFinding('exposure', 'medium', "Directory listing enabled on /$dir/",
                    'Directory listing exposes the full file structure of a folder, which can reveal files never meant to be public.',
                    "/$dir/ -> HTTP 200, directory index page",
                    "Disable directory listing (Apache: 'Options -Indexes' in .htaccess or the vhost config).");
            }
        }
    }

    // ---------------------------------------------------------------
    // robots.txt / sitemap.xml
    // ---------------------------------------------------------------
    private function checkRobotsAndSitemap(): void
    {
        $res = http_get($this->baseUrl . '/robots.txt', 8);
        if ($res['ok'] && $res['status'] === 200) {
            if (preg_match_all('/Disallow:\s*(\S+)/i', $res['body'], $m)) {
                $interesting = array_filter($m[1], fn($p) => preg_match('/admin|backup|config|private|secret/i', $p));
                if (!empty($interesting)) {
                    $this->addFinding('exposure', 'low', 'robots.txt hints at sensitive paths',
                        'robots.txt is meant to guide search engines, but it also tells attackers exactly which paths might be interesting, since disallowed paths are still reachable directly.',
                        'Disallowed paths of interest: ' . implode(', ', array_slice($interesting, 0, 10)),
                        'Do not rely on robots.txt to hide sensitive paths — protect them with authentication instead.');
                }
            }
        }
    }

    // ---------------------------------------------------------------
    // Extract candidate URLs (with query params) to probe for XSS/SQLi
    // ---------------------------------------------------------------
    private function extractProbeTargets(string $body): array
    {
        $targets = [];

        // Links with query strings
        if (preg_match_all('/href=["\']([^"\']+\?[^"\']+)["\']/i', $body, $m)) {
            foreach ($m[1] as $link) {
                $absolute = $this->toAbsoluteUrl($link);
                if ($absolute) $targets[] = $absolute;
            }
        }

        // GET forms
        if (preg_match_all('/<form[^>]*>(.*?)<\/form>/is', $body, $formMatches)) {
            foreach ($formMatches[0] as $form) {
                if (preg_match('/method=["\']post["\']/i', $form)) {
                    continue; // keep this tool to safe, read-only probing
                }
                preg_match('/action=["\']([^"\']*)["\']/i', $form, $actionMatch);
                $action = $actionMatch[1] ?? '';
                $absoluteAction = $this->toAbsoluteUrl($action ?: $this->baseUrl);
                if (!$absoluteAction) continue;

                preg_match_all('/<input[^>]+name=["\']([^"\']+)["\'][^>]*>/i', $form, $inputMatches);
                if (!empty($inputMatches[1])) {
                    $params = [];
                    foreach ($inputMatches[1] as $name) {
                        $params[$name] = 'test';
                    }
                    $sep = strpos($absoluteAction, '?') === false ? '?' : '&';
                    $targets[] = $absoluteAction . $sep . http_build_query($params);
                }
            }
        }

        $targets = array_unique($targets);
        return array_slice($targets, 0, MAX_PROBE_TARGETS);
    }

    private function toAbsoluteUrl(string $link): ?string
    {
        if ($link === '' || str_starts_with($link, '#') || str_starts_with($link, 'mailto:') || str_starts_with($link, 'javascript:')) {
            return null;
        }
        if (preg_match('#^https?://#i', $link)) {
            $parts = parse_url($link);
            if (($parts['host'] ?? '') !== $this->host) {
                return null; // stay on-target, don't wander off to third-party hosts
            }
            return $link;
        }
        if (str_starts_with($link, '//')) {
            return $this->scheme . ':' . $link;
        }
        if (str_starts_with($link, '/')) {
            return $this->scheme . '://' . $this->host . $link;
        }
        return $this->baseUrl . '/' . ltrim($link, '/');
    }

    // ---------------------------------------------------------------
    // Reflected XSS - passive detection only.
    // Sends a unique, harmless marker string and checks whether it comes
    // back un-escaped in the HTML response. Does not attempt to steal
    // data, chain payloads, or interact with any real user session.
    // ---------------------------------------------------------------
    private function checkReflectedXSS(array $targets): void
    {
        foreach ($targets as $target) {
            $marker = 'xsschk' . substr(md5(uniqid((string) mt_rand(), true)), 0, 8);
            $probe = $this->injectMarkerIntoQuery($target, $marker, '<' . $marker . '>');
            if (!$probe) continue;

            $res = http_get($probe, 8);
            if (!$res['ok']) continue;

            if (strpos($res['body'], '<' . $marker . '>') !== false) {
                $this->addFinding('xss', 'high', 'Possible reflected XSS',
                    'A marker value sent in a URL parameter was reflected back in the page without HTML-encoding, which is the classic signature of a reflected cross-site scripting vulnerability.',
                    'Tested URL: ' . $this->truncate($probe),
                    'HTML-encode all user-supplied output, and add a Content-Security-Policy as defense in depth.');
            }
        }
    }

    // ---------------------------------------------------------------
    // SQL injection - error-based passive detection only.
    // Appends a single quote to each parameter and looks for database
    // error signatures that appear ONLY in the modified request and
    // not in the unmodified baseline response. Never attempts to
    // extract, modify, or dump any data.
    // ---------------------------------------------------------------
    private function checkSQLiErrors(array $targets): void
    {
        $errorSignatures = [
            '/you have an error in your sql syntax/i',
            '/warning: mysqli?_/i',
            '/unclosed quotation mark/i',
            '/quoted string not properly terminated/i',
            '/pg_query\(\)/i',
            '/postgresql.*error/i',
            '/ORA-[0-9]{4,5}/i',
            '/microsoft odbc/i',
            '/sqlite3?::/i',
            '/syntax error at or near/i',
        ];

        foreach ($targets as $target) {
            $baseline = http_get($target, 8);
            $probeUrl = $this->injectMarkerIntoQuery($target, null, "'");
            if (!$probeUrl) continue;
            $probe = http_get($probeUrl, 8);

            if (!$baseline['ok'] || !$probe['ok']) continue;

            foreach ($errorSignatures as $pattern) {
                $inProbe = preg_match($pattern, $probe['body']);
                $inBaseline = preg_match($pattern, $baseline['body']);
                if ($inProbe && !$inBaseline) {
                    $this->addFinding('sqli', 'critical', 'Possible SQL injection (error-based)',
                        "Adding a single quote (') to a parameter triggered a database error message that was not present in the normal response — a strong indicator of unsanitized SQL input.",
                        'Tested URL: ' . $this->truncate($probeUrl),
                        'Use parameterized queries / prepared statements everywhere; never concatenate user input into SQL. Also disable detailed DB error output in production.');
                    break;
                }
            }
        }
    }

    /**
     * Given a URL with query params, either appends $suffix to every
     * param value (if $markerLabel is null) or sets every param value
     * to $suffix (used for the XSS marker).
     */
    private function injectMarkerIntoQuery(string $url, ?string $markerLabel, string $suffix): ?string
    {
        $parts = parse_url($url);
        if (!isset($parts['query'])) return null;

        parse_str($parts['query'], $params);
        if (empty($params)) return null;

        foreach ($params as $k => $v) {
            $params[$k] = $markerLabel === null ? $v . $suffix : $suffix;
        }

        $newQuery = http_build_query($params);
        $scheme = $parts['scheme'] ?? $this->scheme;
        $host = $parts['host'] ?? $this->host;
        $path = $parts['path'] ?? '/';

        return "$scheme://$host$path?$newQuery";
    }

    private function truncate(string $s, int $len = 160): string
    {
        return strlen($s) > $len ? substr($s, 0, $len) . '…' : $s;
    }
}
