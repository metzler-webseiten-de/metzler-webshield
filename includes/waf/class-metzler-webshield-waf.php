<?php

use JetBrains\PhpStorm\NoReturn;

if ( ! defined( 'ABSPATH' ) ) {
    die;
}

class Metzler_Webshield_WAF {
    
    private array $rules = array();
    
    public function __construct() {
        $this->load_rules();
    }
    
    public function run(): void {
        // Skip WAF for CLI and Cron
        if ( defined('WP_CLI') && WP_CLI ) return;
        if ( defined('DOING_CRON') && DOING_CRON ) return;
        
        $client_ip = $_SERVER['REMOTE_ADDR'] ?? ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
        $server_ip = $_SERVER['SERVER_ADDR'] ?? ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
        $host_ip = isset($_SERVER['HTTP_HOST']) ? gethostbyname($_SERVER['HTTP_HOST']) : '';
        $is_loopback = !empty($client_ip) && ($client_ip === $server_ip || $client_ip === $host_ip || $client_ip === '127.0.0.1' || $client_ip === '::1');
        
        $script_name = $_SERVER['SCRIPT_NAME'] ?? ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
        $is_cron = (basename($script_name) === 'wp-cron.php');
        
        // Only skip browser integrity checks for automated background tasks, 
        // but KEEP the actual malware payload inspection active for them!
        if ( ! $is_cron && ! $is_loopback ) {
            $this->browser_integrity_check();
        }
        
        $this->inspect_payload($_GET, 'GET'); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification
        $this->inspect_payload($_POST, 'POST'); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification
        $this->inspect_payload($_COOKIE, 'COOKIE');
        
        // Inspect Raw URIs (Crucial for pretty permalinks where $_GET is empty during MU phase) // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification
        if ( isset($_SERVER['REQUEST_URI']) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
            $this->inspect_string( $_SERVER['REQUEST_URI'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
        }
        if ( isset($_SERVER['QUERY_STRING']) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
            $this->inspect_string( $_SERVER['QUERY_STRING'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
        }
        
        // Inspect User-Agent (Skip for loopback so internal curl requests like WP Amelia don't trigger Bad_Bots)
        if ( ! $is_loopback && isset($_SERVER['HTTP_USER_AGENT']) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
            $this->inspect_string( $_SERVER['HTTP_USER_AGENT'] ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
        }
    }
    
    private function browser_integrity_check(): void {
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
        
        // 1. Missing User-Agent
        if ( empty(trim($user_agent)) ) {
            $this->block_request( 'Browser_Integrity', 'Empty User-Agent string' );
        }
        
        // 2. Missing Accept Header on GET requests
        if ( !isset($_SERVER['HTTP_ACCEPT']) && isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'GET' ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
            $uri = $_SERVER['REQUEST_URI'] ?? ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
            if ( ! str_contains( $uri, 'xmlrpc.php' ) && ! str_contains( $uri, 'wp-json' ) ) {
                $this->block_request( 'Browser_Integrity', 'Empty Accept Header' );
            }
        }
        
        // 3. Headless Browsers & Frameworks
        $headless_patterns = '/HeadlessChrome|PhantomJS|Puppeteer|Selenium|slimerjs/i';
        if ( preg_match($headless_patterns, $user_agent) ) {
            $this->block_request( 'Browser_Integrity', $user_agent );
        }
    }
    
    private function load_rules(): void {
        $enc_file = WP_CONTENT_DIR . '/uploads/metzler-webshield/waf-rules.enc';
        $key_file = WP_CONTENT_DIR . '/uploads/metzler-webshield/waf.key';
        
        if ( file_exists($enc_file) && file_exists($key_file) ) {
            $token = file_get_contents($key_file);
            $json = file_get_contents($enc_file);
            if ( $token && $json ) {
                $data = json_decode($json, true);
                if ( isset($data['payload']) && isset($data['iv']) ) {
                    $encrypted = base64_decode($data['payload']);
                    $iv = base64_decode($data['iv']);
                    $key = substr(hash('sha256', $token, true), 0, 32);
                    $decrypted_json = openssl_decrypt($encrypted, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
                    if ( $decrypted_json ) {
                        $this->rules = json_decode($decrypted_json, true);
                    }
                }
            }
        } 
        
        // Fallback to hardcoded minimal rules if sync hasn't run yet or decryption failed
        if ( empty($this->rules) ) {
            $this->rules = array(
                'SQLi' => array(
                    '/(?:\b(?:union|select|insert|update|delete|drop|truncate|alter|create|rename|desc|replace)\b.*(?:from|into|table|database))/i',
                    '/(?:\b(?:information_schema|mysql_.*\b|pg_.*\b|sysobjects|syscolumns|xp_cmdshell)\b)/i',
                    '/(?:waitfor\s+delay\s+\'|\bbenchmark\s*\()/i',
                    '/(?:--\s*$|\/\*.*?\*\/|;\s*(?:declare|set|exec|execute)\b)/i',
                    '/(?:\b(?:concat|group_concat|load_file|outfile|dumpfile)\b\s*\()/i'
                ),
                'XSS' => array(
                    '/(?:[<‹⟨]script.*?[>›⟩]?)/is',
                    '/(?:[<‹⟨].*?\bon(?:load|error|click|mouseover|keydown|keyup)\s*=)/is',
                    '/(?:javascript:|vbscript:|data:text\/html)/i',
                    '/(?:eval\s*\(|setTimeout\s*\(|setInterval\s*\()/i',
                    '/(?:document\.(?:cookie|location|write|body)|window\.(?:location|name))/i'
                ),
                'LFI' => array(
                    '/(?:\.\.\/|\.\.\\\\|\.\.\/|%2e%2e%2f)/i',
                    '/(?:etc\/passwd|etc\/shadow|etc\/hosts|boot\.ini|win\.ini|windows\\\\system32)/i',
                    '/(?:%00|\\0)/'
                ),
                'Bad_Bots' => array(
                    '/(?:nikto|sqlmap|nmap|zmeu|dirbuster|havij|curl|wget|python-requests|libwww-perl)/i'
                )
            );
        }
    }
    
    private function inspect_payload( $payload, $source ): void {
        if ( ! is_array($payload) ) return;
        
        foreach ( $payload as $key => $value ) {
            // Ignore some false-positive-heavy WordPress core fields
            if ( in_array(strtolower($key), array('content', 'post_content', 'excerpt', 'html', 'description')) ) {
                continue;
            }
            
            if ( is_array($value) ) {
                $this->inspect_payload($value, $source);
            } else {
                $this->inspect_string( $value );
            }
        }
    }
    
    private function inspect_string( $string ): void {
        if ( empty($string) || ! is_string($string) ) return;
        
        // Decode for inspection
        $string = urldecode($string);
        
        foreach ( $this->rules as $category => $patterns ) {
            foreach ( $patterns as $pattern ) {
                if ( preg_match($pattern, $string) ) {
                    $this->block_request( $category, $string );
                }
            }
        }
    }
    
    #[NoReturn]
    private function block_request( $category, $payload = '' ): void {
        $ip = sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? '')) ?? '127.0.0.1'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
        
        // WAF blocks are logged asynchronously via telemetry.jsonl to prevent MySQL crashing during DDoS.
        
        // Push 100% of Telemetry to local Batch File (Extremely Fast, NO API/DB overhead)
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
        $request_uri = $_SERVER['REQUEST_URI'] ?? ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
        $request_method = $_SERVER['REQUEST_METHOD'] ?? ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
        $domain = $_SERVER['HTTP_HOST'] ?? ( $_SERVER['SERVER_NAME'] ?? 'unknown' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput

        $headers = array();
        if ( function_exists('getallheaders') ) {
            $headers = getallheaders();
        } else {
            foreach ($_SERVER as $name => $value) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
                if ( str_starts_with( $name, 'HTTP_' ) ) {
                    $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
                }
            }
        }

        $telemetry_data = array(
            'domain'         => $domain,
            'ip_address'     => $ip,
            'user_agent'     => $user_agent,
            'request_uri'    => $request_uri,
            'request_method' => $request_method,
            'attack_type'    => $category,
            'payload'        => substr(urldecode($payload), 0, 1000), // Trim to max 1000 chars
            'headers'        => $headers
        );

        $upload_dir = WP_CONTENT_DIR . '/uploads/metzler-webshield';
        if ( ! is_dir($upload_dir) ) {
            @mkdir($upload_dir, 0755, true); // phpcs:ignore
        }
        $telemetry_file = $upload_dir . '/telemetry.jsonl';
        @file_put_contents($telemetry_file, json_encode($telemetry_data) . "\n", FILE_APPEND | LOCK_EX); // phpcs:ignore
        
        // Output Block Screen
        header('HTTP/1.1 403 Forbidden');
        header('Status: 403 Forbidden');
        ?>
        <!DOCTYPE html>
        <html lang="<?php echo esc_attr( str_replace('_', '-', get_locale()) ); ?>">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title><?php echo esc_html__('Access Blocked', 'metzler-webshield'); ?> | Metzler_Webshield</title>
            <style>
                :root { --primary-color: #0d1b2a; --error-color: #e63946; --text-color: #333; --bg-color: #f8f9fa; }
                body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: var(--bg-color); color: var(--text-color); margin: 0; padding: 0; display: flex; justify-content: center; align-items: center; min-height: 100vh; }
                .container { background: #fff; max-width: 650px; width: 90%; padding: 50px; border-radius: 12px; box-shadow: 0 10px 30px rgba(0,0,0,0.05); text-align: center; border-top: 5px solid var(--error-color); }
                .icon { background: #fee2e2; color: var(--error-color); width: 80px; height: 80px; border-radius: 50%; display: flex; justify-content: center; align-items: center; margin: 0 auto 25px; }
                .icon svg { width: 40px; height: 40px; }
                h1 { color: var(--primary-color); font-size: 28px; margin: 0 0 15px; font-weight: 700; }
                p.lead { font-size: 18px; line-height: 1.6; color: #555; margin-bottom: 30px; }
                .details-box { background: #f8f9fa; border: 1px solid #e9ecef; border-radius: 8px; padding: 20px; text-align: left; margin-bottom: 30px; }
                .details-box p { margin: 8px 0; font-size: 14px; color: #666; font-family: monospace; }
                .details-box strong { color: var(--primary-color); display: inline-block; width: 120px; }
                .footer { font-size: 13px; color: #999; margin-top: 20px; border-top: 1px solid #eee; padding-top: 20px; display: flex; justify-content: space-between; align-items: center; }
                .footer a { color: #666; text-decoration: none; }
                .footer a:hover { text-decoration: underline; }
                .badge { background: #e63946; color: white; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="icon">
                    <svg fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
                </div>
                <h1><?php echo esc_html__('Access Blocked', 'metzler-webshield'); ?></h1>
                <p class="lead"><?php echo esc_html__('Your request was classified as potentially dangerous by our Web Application Firewall and blocked for security reasons.', 'metzler-webshield'); ?></p>
                
                <div class="details-box">
                    <p><strong><?php echo esc_html__('IP:', 'metzler-webshield'); ?></strong> <?php // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
 echo esc_html( sanitize_text_field(wp_unslash($_SERVER['REMOTE_ADDR'] ?? '')) ?: __('Unknown', 'metzler-webshield') ); ?></p>
                    <p><strong><?php echo esc_html__('Event ID:', 'metzler-webshield'); ?></strong> <?php echo esc_html(md5($ip . time())); ?></p>
                </div>
                
                <div class="footer">
                    <span><?php echo wp_kses_post(__('Protected by <strong>Metzler_Webshield</strong>', 'metzler-webshield')); ?></span>
                    <a href="mailto:<?php echo esc_attr(get_option('admin_email')); ?>"><?php echo esc_html__('Contact Admin', 'metzler-webshield'); ?></a>
                </div>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
}
