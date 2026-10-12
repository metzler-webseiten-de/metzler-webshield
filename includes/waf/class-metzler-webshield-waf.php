<?php

if ( ! defined( 'ABSPATH' ) && ! defined( 'METZLER_WEBSHIELD_WAF_PREPENDED' ) ) {
    die;
}

// Loaded standalone by the legacy mu-plugin bootstrapper (beta versions), so pull in storage ourselves.
require_once dirname( __DIR__ ) . '/class-metzler-webshield-storage.php';
require_once dirname( __DIR__ ) . '/class-metzler-webshield-request.php';
require_once __DIR__ . '/class-metzler-webshield-cloud-rules.php';

class Metzler_Webshield_WAF {

    /**
     * Categories that only make sense for one part of the request. Bot signatures describe the client,
     * so a blog search for "curl" is no attack; reconnaissance rules describe probed file paths.
     */
    const SCOPED_CATEGORIES = array(
        'Bad_Bots'       => 'user_agent',
        'Reconnaissance' => 'path',
    );

    /** Larger JSON bodies are not inspected (uploads, imports) */
    const MAX_JSON_BODY = 1048576;

    /** Attackers stack URL encodings (%252e -> %2e -> .) to slip past a single decode */
    const MAX_DECODE_PASSES = 3;

    private array $rules = array();
    private bool $xmlrpc_disabled = false;

    /**
     * @param array|null $config Firewall snapshot when running before WordPress (auto_prepend_file):
     *                           there are no options or filters yet, so rules and settings come from it.
     */
    public function __construct( ?array $config = null ) {
        if ( null === $config ) {
            $this->rules           = self::build_rules();
            $this->xmlrpc_disabled = get_option( 'metzler_webshield_disable_xmlrpc', '0' ) === '1';
            return;
        }

        $this->rules           = ! empty( $config['rules'] ) && is_array( $config['rules'] ) ? $config['rules'] : self::local_rules();
        $this->xmlrpc_disabled = ! empty( $config['xmlrpc_disabled'] );
    }
    
    public function run(): void {
        // Skip WAF for CLI and Cron
        if ( defined('WP_CLI') && WP_CLI ) return;
        if ( defined('DOING_CRON') && DOING_CRON ) return;
        
        $is_loopback = Metzler_Webshield_Request::is_own_server_request();
        
        $script_name = $_SERVER['SCRIPT_NAME'] ?? ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
        $uri = $_SERVER['REQUEST_URI'] ?? ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
        $is_cron = (basename($script_name) === 'wp-cron.php');
        
        // XML-RPC Inspection & Abuse Protection
        $is_xmlrpc = (basename($script_name) === 'xmlrpc.php' || stripos($script_name, 'xmlrpc.php') !== false || stripos($uri, 'xmlrpc.php') !== false);
        if ( $is_xmlrpc ) {
            if ( $this->xmlrpc_disabled ) {
                $this->block_request( 'XML_RPC_Abuse', 'Blocked XML-RPC request (disabled by administrator)' );
            }
            
            // Detect malicious multicall brute-force or pingback DDoS even if XML-RPC is enabled
            $raw_input = file_get_contents('php://input');
            if ( ! empty($raw_input) && (stripos($raw_input, 'system.multicall') !== false || stripos($raw_input, 'pingback.ping') !== false) ) {
                $this->block_request( 'XML_RPC_Abuse', 'Blocked malicious XML-RPC payload: ' . substr($raw_input, 0, 200) );
            }
        }
        
        // Only skip browser integrity checks for automated background tasks, 
        // but KEEP the actual malware payload inspection active for them!
        if ( ! $is_cron && ! $is_loopback ) {
            $this->browser_integrity_check();
        }
        
        $this->inspect_payload(self::unslash($_GET), 'GET'); // phpcs:ignore WordPress.Security.NonceVerification
        $this->inspect_payload(self::unslash($_POST), 'POST'); // phpcs:ignore WordPress.Security.NonceVerification
        $this->inspect_payload(self::unslash($_COOKIE), 'COOKIE');
        $this->inspect_json_body();
        
        // Inspect Raw URIs (Crucial for pretty permalinks where $_GET is empty during MU phase)
        if ( isset($_SERVER['REQUEST_URI']) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
            $request_uri = self::unslash($_SERVER['REQUEST_URI']); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
            $this->inspect_string( $request_uri, 'uri' );
            $this->inspect_string( (string) parse_url( $request_uri, PHP_URL_PATH ), 'path' ); // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- also runs before WordPress
        }
        if ( isset($_SERVER['QUERY_STRING']) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
            $this->inspect_string( self::unslash($_SERVER['QUERY_STRING']), 'uri' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
        }
        
        // Inspect User-Agent (Skip for loopback so internal curl requests like WP Amelia don't trigger Bad_Bots)
        if ( ! $is_loopback && isset($_SERVER['HTTP_USER_AGENT']) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
            $this->inspect_string( self::unslash($_SERVER['HTTP_USER_AGENT']), 'user_agent' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
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
            
            // Allow crawlers that sometimes drop Accept headers (e.g., Google-Read-Aloud). The User-Agent is
            // enough here: anyone can send an Accept header, so this check never stopped a determined client.
            $is_known_bot = preg_match( '/google|bingbot|bingpreview|yandex|baiduspider|Applebot|DuckDuckBot|Slurp/i', $user_agent );
            
            if ( ! $is_known_bot && strpos( $uri, 'xmlrpc.php' ) === false && strpos( $uri, 'wp-json' ) === false ) {
                $this->block_request( 'Browser_Integrity', 'Empty Accept Header' );
            }
        }
        
        // 3. Headless Browsers & Frameworks
        $headless_patterns = '/HeadlessChrome|PhantomJS|Puppeteer|Selenium|slimerjs/i';
        if ( preg_match($headless_patterns, $user_agent) ) {
            $this->block_request( 'Browser_Integrity', $user_agent );
        }
    }
    
    /**
     * Rule set of a WordPress request: synchronized cloud rules (connected sites) or the built-in rules,
     * extended by add-ons. Also written into the firewall snapshot for the auto_prepend_file mode.
     */
    public static function build_rules(): array {
        $cloud_rules = Metzler_Webshield_Cloud_Rules::load();
        $base_rules  = ! empty( $cloud_rules ) ? $cloud_rules : self::local_rules();

        $rules = apply_filters( 'metzler_webshield_waf_rules', $base_rules );
        return ( is_array( $rules ) && ! empty( $rules ) ) ? $rules : $base_rules;
    }

    /**
     * Built-in rule set, used until a connected site has synchronized cloud rules.
     * Rules look for query structure (quotes, operators, SQL/JS syntax) rather than single words, so
     * ordinary text like "select a size from the list" or "please delete my data" passes.
     */
    public static function local_rules(): array {
        return array(
            'SQLi' => array(
                '/\bunion(?:\s|\/\*.*?\*\/|\()+(?:all\b|distinct\b)?(?:\s|\/\*.*?\*\/|\()*select\b/is',
                '/[\'"`)]\s*(?:\b(?:or|and|xor)\b|\|\||&&)\s*[\'"`(]{0,2}\s*[\w.-]+\s*[\'"`)]{0,2}\s*(?:=|<|>|\blike\b|\brlike\b|\bregexp\b|\bis\s+not\b)/i',
                '/\b(?:waitfor\s+delay\s+\'|benchmark\s*\(\s*\d|sleep\s*\(\s*\d+(?:\.\d+)?\s*\)|pg_sleep\s*\()|\b(?:information_schema|sysobjects|syscolumns|xp_cmdshell|pg_catalog|mysql\.user)\b/i',
                '/;\s*(?:(?:drop|truncate|alter|create)\s+(?:table|database|schema|user)\b|delete\s+from\b|insert\s+into\b|exec(?:ute)?\s|declare\s+@|shutdown\b)|[\'"`)]\s*(?:--|#)\s*$/i',
                '/\b(?:group_concat|load_file|extractvalue|updatexml)\s*\(|\binto\s+(?:out|dump)file\b|\bconcat(?:_ws)?\s*\(\s*0x|\/\*!\d*|\b(?:union|select|from|where|and|or)\/\*|\*\/(?:union|select|from|where|and|or)\b/i',
            ),
            'XSS' => array(
                '/(?:[<‹⟨]script.*?[>›⟩]?)/is',
                '/[<‹⟨][^>]*?\bon[a-z]{3,20}\s*=/is',
                '/(?:javascript:|vbscript:|data:text\/html)/i',
                '/\b(?:eval|setTimeout|setInterval|Function)\s*\(\s*(?:atob|unescape|decodeURI(?:Component)?|String\.fromCharCode)\b/i',
                '/(?:document\.(?:cookie|location|write|body)|window\.(?:location|name))/i'
            ),
            'LFI' => array(
                '/(?:\.\.\/|\.\.\\\\|%2e%2e%2f)/i',
                '/(?:etc\/passwd|etc\/shadow|etc\/hosts|boot\.ini|win\.ini|windows\\\\system32)/i',
                '/(?:%00|\\0)/',
                '/\b(?:php|phar|expect|zip|glob):\/\//i'
            ),
            'Bad_Bots' => array(
                '/(?:nikto|sqlmap|nmap|zmeu|dirbuster|havij|curl|wget|python-requests|libwww-perl)/i'
            )
        );
    }

    private function inspect_payload( $payload, $source ): void {
        if ( ! is_array($payload) ) return;
        
        foreach ( $payload as $key => $value ) {
            // Ignore some false-positive-heavy WordPress core fields
            if ( in_array(strtolower((string) $key), array('content', 'post_content', 'excerpt', 'html', 'description')) ) {
                continue;
            }
            
            if ( is_array($value) ) {
                $this->inspect_payload($value, $source);
            } elseif ( is_scalar($value) ) {
                $this->inspect_string( (string) $value );
            }
        }
    }

    /**
     * REST API requests with a JSON body never reach $_POST, so they are decoded and inspected here.
     */
    private function inspect_json_body(): void {
        $content_type = $_SERVER['CONTENT_TYPE'] ?? ( $_SERVER['HTTP_CONTENT_TYPE'] ?? '' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
        if ( stripos( (string) $content_type, 'json' ) === false ) {
            return;
        }
        $length = (int) ( $_SERVER['CONTENT_LENGTH'] ?? 0 ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
        if ( $length > self::MAX_JSON_BODY ) {
            return;
        }

        $raw = file_get_contents( 'php://input', false, null, 0, self::MAX_JSON_BODY );
        if ( false === $raw || '' === trim( $raw ) ) {
            return;
        }

        $data = json_decode( $raw, true );
        if ( is_array( $data ) ) {
            $this->inspect_payload( $data, 'JSON' );
        } elseif ( is_scalar( $data ) ) {
            $this->inspect_string( (string) $data );
        } else {
            // Not valid JSON despite the header: inspect it as it is
            $this->inspect_string( $raw );
        }
    }
    
    /**
     * @param string $source param (GET/POST/cookie/JSON value), uri, path or user_agent
     */
    private function inspect_string( $string, string $source = 'param' ): void {
        if ( empty($string) || ! is_string($string) ) return;
        
        foreach ( self::decoded_variants( $string ) as $variant ) {
            foreach ( $this->rules as $category => $patterns ) {
                $scope = self::SCOPED_CATEGORIES[ $category ] ?? null;
                // Scoped rules only run on their part of the request; the path is part of the URI,
                // so it only gets the path-specific rules
                if ( $scope ? $scope !== $source : 'path' === $source ) {
                    continue;
                }
                foreach ( (array) $patterns as $pattern ) {
                    if ( preg_match($pattern, $variant) ) {
                        $this->block_request( $category, $variant );
                    }
                }
            }
        }
    }

    /**
     * WordPress slashes the superglobals while it loads; before that (auto_prepend_file) they are raw.
     */
    private static function unslash( $value ) {
        return function_exists( 'wp_unslash' ) ? wp_unslash( $value ) : $value;
    }

    /**
     * The value itself plus every further URL-decoded form of it.
     */
    private static function decoded_variants( string $string ): array {
        $variants = array( $string );
        for ( $i = 0; $i < self::MAX_DECODE_PASSES; $i++ ) {
            $decoded = urldecode( $string );
            if ( $decoded === $string ) {
                break;
            }
            $variants[] = $string = $decoded;
        }
        return $variants;
    }
    
    private function block_request( $category, $payload = '' ): void {
        $ip = Metzler_Webshield_Request::client_ip();
        
        // WAF blocks are logged asynchronously via the telemetry buffer file to prevent MySQL crashing during DDoS.
        
        // Push 100% of Telemetry to local Batch File (Extremely Fast, NO API/DB overhead)
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
        $request_uri = $_SERVER['REQUEST_URI'] ?? ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
        $request_method = $_SERVER['REQUEST_METHOD'] ?? ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
        if ( empty($request_method) ) {
            $request_method = (php_sapi_name() === 'cli') ? 'CLI' : 'UNKNOWN';
        }
        $domain = $_SERVER['HTTP_HOST'] ?? ( $_SERVER['SERVER_NAME'] ?? 'unknown' ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput

        $headers = array();
        if ( function_exists('getallheaders') ) {
            $headers = getallheaders();
        } else {
            foreach ($_SERVER as $name => $value) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
                if ( strpos( $name, 'HTTP_' ) === 0 ) {
                    $headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
                }
            }
        }

        // Never pass on credentials or sessions (a false positive may hit a legitimate visitor)
        foreach ( array_keys( $headers ) as $header_name ) {
            if ( in_array( strtolower( $header_name ), array( 'cookie', 'authorization', 'proxy-authorization', 'x-wp-nonce' ), true ) ) {
                unset( $headers[ $header_name ] );
            }
        }

        $telemetry_data = array(
            'time'           => gmdate('c'),
            'domain'         => $domain,
            'ip_address'     => $ip,
            'user_agent'     => base64_encode($user_agent), // base64 encoded for safe storage/transport
            'request_uri'    => base64_encode($request_uri), // base64 encoded for safe storage/transport
            'request_method' => $request_method,
            'attack_type'    => $category,
            'payload'        => base64_encode(substr(urldecode($payload), 0, 1000)), // base64 encoded for safe storage/transport
            'headers'        => $headers,
            'encoding'       => 'base64'
        );

        Metzler_Webshield_Storage::append_telemetry($telemetry_data);
        
        $event_id = md5( $ip . time() );

        if ( function_exists( 'wp_die' ) ) {
            $title = __('Access Blocked', 'metzler-webshield');
            $message = '<h1>' . esc_html__('Access Blocked', 'metzler-webshield') . '</h1>';
            $message .= '<p>' . esc_html__('Your request was classified as potentially dangerous by our Web Application Firewall and blocked for security reasons.', 'metzler-webshield') . '</p>';
            $message .= '<p><strong>' . esc_html__('IP:', 'metzler-webshield') . '</strong> ' . esc_html( $ip ) . '</p>';
            $message .= '<p><strong>' . esc_html__('Event ID:', 'metzler-webshield') . '</strong> ' . esc_html( $event_id ) . '</p>';
            wp_die(wp_kses_post($message), esc_html($title), array('response' => 403));
        }

        // Before WordPress (auto_prepend_file): no translations or wp_die() yet
        if ( ! headers_sent() ) {
            http_response_code( 403 );
            header( 'Content-Type: text/html; charset=utf-8' );
            header( 'Cache-Control: no-store' );
        }
        $escape = static function ( string $text ): string {
            return htmlspecialchars( $text, ENT_QUOTES, 'UTF-8' );
        };
        echo '<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="robots" content="noindex"><title>Access Blocked</title></head><body style="font-family:sans-serif;max-width:640px;margin:10vh auto;padding:0 16px;">' // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- static markup
            . '<h1>Access Blocked</h1><p>Your request was classified as potentially dangerous by our Web Application Firewall and blocked for security reasons.</p>'
            . '<p><strong>IP:</strong> ' . $escape( $ip ) . '</p><p><strong>Event ID:</strong> ' . $escape( $event_id ) . '</p></body></html>'; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped -- escaped above
        exit;
    }
}
