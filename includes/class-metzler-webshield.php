<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class Metzler_Webshield {
    public function __construct() {
        $this->load_dependencies();
    }
    
    private function load_dependencies(): void {
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/class-metzler-webshield-storage.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/class-metzler-webshield-request.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/log/class-metzler-webshield-logger.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/class-metzler-webshield-queue.php';
        
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/scanner/class-metzler-webshield-scanner-core.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/scanner/class-metzler-webshield-scanner-plugins.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/scanner/class-metzler-webshield-scanner-files.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/scanner/class-metzler-webshield-scanner-updates.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/scanner/class-metzler-webshield-scanner-config.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/class-metzler-webshield-fim.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/class-metzler-webshield-quarantine.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/class-metzler-webshield-findings.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/class-metzler-webshield-auto-submit.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/scanner/class-metzler-webshield-scanner-fim.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/scanner/class-metzler-webshield-scanner-config.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/waf/class-metzler-webshield-waf.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/waf/class-metzler-webshield-cloud-rules.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/waf/class-metzler-webshield-rate-limiter.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/waf/class-metzler-webshield-firewall-setup.php';
        
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/class-metzler-webshield-login.php';

        if ( is_admin() ) {
            require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'admin/class-metzler-webshield-admin.php';
        }
    }

    /**
     * Runs the request shields as the very first plugins_loaded callback: every plugin (and add-on filter
     * such as metzler_webshield_waf_rules) is registered by then, but WordPress has not reached init yet.
     */
    public function run_shields(): void {
        // Already inspected before WordPress when extended protection (auto_prepend_file) is active
        if ( get_option('metzler_webshield_enable_waf', '0') === '1' && ! defined( 'METZLER_WEBSHIELD_WAF_DONE' ) ) {
            $waf = new Metzler_Webshield_WAF();
            $waf->run();
        }

        // General Rate Limiter
        if ( get_option('metzler_webshield_enable_rate_limiting', '1') === '1' ) {
            Metzler_Webshield_Rate_Limiter::check_request();
        }
    }

    public function run(): void {
        add_action( 'plugins_loaded', array( $this, 'run_shields' ), PHP_INT_MIN );

        // @selfhosted-start (removed from the WordPress.org build by bin/build.sh)
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/class-metzler-webshield-updater.php';
        $updater = new Metzler_Webshield_Updater( METZLER_WEBSHIELD_PLUGIN_FILE, METZLER_WEBSHIELD_VERSION, METZLER_WEBSHIELD_API_URL, 'mws_remote_update_info' );
        $updater->init();
        // @selfhosted-end

        if ( is_admin() ) {
            $admin = new Metzler_Webshield_Admin();
            $admin->init();
        }
        
        $queue = new Metzler_Webshield_Queue();
        $queue->init();

        $login = new Metzler_Webshield_Login();
        
        add_action( 'metzler_webshield_daily_scan', array( $this, 'cron_verify_license' ) );
        
        $fim = new Metzler_Webshield_FIM();
        $fim->init();

        // Results of files sent to the lab, hourly together with the cloud rules
        add_action( Metzler_Webshield_Cloud_Rules::SYNC_HOOK, array( 'Metzler_Webshield_Findings', 'sync_lab_status' ) );
        add_action( Metzler_Webshield_Cloud_Rules::SYNC_HOOK, array( 'Metzler_Webshield_Auto_Submit', 'run' ) );
        
        $quarantine = new Metzler_Webshield_Quarantine();
        $quarantine->init();
        
        // XML-RPC Hardening
        if ( get_option('metzler_webshield_disable_xmlrpc', '0') === '1' ) {
            add_filter( 'xmlrpc_enabled', '__return_false' );
        }

        // Custom Cron Schedules
        add_filter( 'cron_schedules', array( 'Metzler_Webshield', 'add_cron_schedules' ) );
        
        // Background Cronjob (3 AM Daily)
        add_action( 'metzler_webshield_daily_scan', array( 'Metzler_Webshield_Queue', 'cron_start_scan' ) );
        
        // Background License Check (Hourly)
        add_action( 'metzler_webshield_hourly_license_check', array( $this, 'cron_verify_license' ) );

        // Telemetry Batch Sync (Every 5 Minutes)
        add_action( 'metzler_webshield_five_minute_telemetry', array( $this, 'cron_sync_telemetry' ) );

        // Cloud WAF Rules Sync (Hourly, connected sites only)
        Metzler_Webshield_Cloud_Rules::init();

        // Extended protection: firewall snapshot for the auto_prepend_file mode
        Metzler_Webshield_Firewall_Setup::init();

        // Author / User Enumeration Rate Limiter (Cloudflare- & Proxy-Aware)
        add_action( 'init', array( $this, 'check_author_enumeration' ) );

        // Ensure background crons remain scheduled
        if ( is_admin() ) {
            add_action( 'admin_init', array( 'Metzler_Webshield', 'ensure_scheduled_crons' ) );
            add_action( 'admin_init', array( 'Metzler_Webshield', 'maybe_migrate' ) );
        }

        // Add-ons (e.g. Metzler Webshield Pro) hook in here; all core classes are loaded at this point.
        add_action( 'plugins_loaded', function () {
            do_action( 'metzler_webshield_loaded' );
        }, 1 );
    }

    /**
     * One-time upgrade from 1.x.
     */
    public static function maybe_migrate(): void {
        if ( version_compare( get_option( 'metzler_webshield_version', '1.0.0' ), '2.0.0', '>=' ) ) {
            return;
        }

        delete_transient( 'mws_remote_update_info' );

        update_option( 'metzler_webshield_version', METZLER_WEBSHIELD_VERSION );
    }

    /**
     * True when this site is connected to the Threat Intelligence Cloud (optional, free).
     */
    public static function is_cloud_connected(): bool {
        return (bool) get_option( 'metzler_webshield_is_licensed' ) && get_option( 'metzler_webshield_license_token', '' ) !== '';
    }

    /**
     * Telemetry is only ever sent after the administrator opted in and connected the site.
     */
    public static function telemetry_allowed(): bool {
        return get_option( 'metzler_webshield_enable_telemetry', '0' ) === '1' && self::is_cloud_connected();
    }

    /**
     * True only when the API answered that the key is invalid. Network errors, timeouts, maintenance and
     * server errors (5xx, 429, non-JSON pages) say nothing about the key: the site stays connected, otherwise
     * an API outage would disconnect every site and turn telemetry off for good.
     */
    public static function license_rejected( $response ): bool {
        if ( is_wp_error( $response ) ) {
            return false;
        }
        $code = (int) wp_remote_retrieve_response_code( $response );
        if ( $code < 400 || $code >= 500 || 429 === $code ) {
            return false;
        }
        $data = json_decode( wp_remote_retrieve_body( $response ), true );
        return is_array( $data ) && array_key_exists( 'success', $data ) && false === $data['success'];
    }

    public function cron_verify_license(): void {
        if ( ! get_option( 'metzler_webshield_is_licensed' ) ) {
            return;
        }

        $token = get_option( 'metzler_webshield_license_token' );
        $domain = wp_parse_url( home_url(), PHP_URL_HOST );
        $api_url = defined( 'METZLER_WEBSHIELD_API_URL' ) ? METZLER_WEBSHIELD_API_URL : 'https://api.metzler-webshield.de/api';

        $response = wp_remote_post( $api_url . '/license/verify', array(
            'body' => array(
                'token'  => $token,
                'domain' => $domain
            ),
            'timeout' => 15
        ) );

        if ( self::license_rejected( $response ) ) {
            // The key is invalid or revoked: disconnect the site
            delete_option( 'metzler_webshield_is_licensed' );
            update_option( 'metzler_webshield_enable_telemetry', '0' );
            return;
        }

        if ( ! is_wp_error( $response ) ) {
            $data = json_decode( wp_remote_retrieve_body( $response ), true );

            if ( ! empty( $data['success'] ) ) {
                if ( isset( $data['tier'] ) ) {
                    $tier = sanitize_text_field( $data['tier'] );
                    update_option( 'metzler_webshield_license_tier', $tier );
                }
                if ( ! empty( $data['email'] ) ) {
                    update_option( 'metzler_webshield_verified_email', sanitize_email( $data['email'] ) );
                }
            }
        }
    }

    
    private function sync_historical_telemetry(): void {
        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_logs';
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $results = $wpdb->get_results("SELECT * FROM $table_name WHERE type = 'waf'");
        if (empty($results)) return;

        $domain = wp_parse_url(home_url(), PHP_URL_HOST);
        
        foreach ($results as $row) {
            $ip = '';
            $attack_type = 'Unknown';
            
            // Check if it is a Brute Force log
            if (strpos($row->message, 'Brute-Force prevented:') !== false) {
                if (preg_match('/from IP: ([0-9a-fA-F:\.]+) for user:/', $row->message, $matches)) {
                    $ip = $matches[1];
                }
                $attack_type = 'Brute_Force';
            } 
            // Check if it is a standard WAF block log
            else if (preg_match('/WAF Block: \d+ attacks? from IP ([0-9a-fA-F:\.]+) \((.*?)\)/', $row->message, $matches)) {
                $ip = $matches[1];
                $attack_type = $matches[2]; // May contain several comma-separated types
            }
            
            if (!$ip) continue;

            $telemetry_data = array(
                'time' => function_exists('get_gmt_from_date') ? get_gmt_from_date($row->time, 'c') : gmdate('c', strtotime($row->time)),
                'domain' => $domain,
                'ip_address' => sanitize_text_field($ip),
                'attack_type' => sanitize_text_field($attack_type),
                'severity' => 'high',
                'request_uri' => base64_encode('/historical-sync'),
                'user_agent' => base64_encode('Legacy_Log_Export'),
                'encoding' => 'base64'
            );
            
            Metzler_Webshield_Storage::append_telemetry($telemetry_data);
        }
    }


    public function cron_sync_telemetry(): void {
        self::protect_upload_dir();

        $telemetry_allowed = self::telemetry_allowed();

        // One-time upload of previously logged blocks
        if ( $telemetry_allowed && get_option('metzler_webshield_historical_telemetry_sent', '0') !== '1' ) {
            $this->sync_historical_telemetry();
            update_option('metzler_webshield_historical_telemetry_sent', '1');
        }
        if ( $telemetry_allowed ) {
            Metzler_Webshield_Findings::sync();
        }

        $telemetry_file = Metzler_Webshield_Storage::path(Metzler_Webshield_Storage::TELEMETRY_FILE);
        $processing_file = Metzler_Webshield_Storage::path(Metzler_Webshield_Storage::PROCESSING_FILE);

        if ( ! Metzler_Webshield_Storage::has_pending_telemetry() ) {
            return;
        }

        // Rename atomically so WAF can immediately start a new file
        if ( ! rename($telemetry_file, $processing_file) ) { // phpcs:ignore
            return;
        }

        $lines = Metzler_Webshield_Storage::read_lines($processing_file);
        if ( empty($lines) ) {
            wp_delete_file( $processing_file );
            return;
        }

        $logs = array();
        $ui_summary = array(); // Store aggregated data for local UI

        foreach ( $lines as $line ) {
            $decoded = json_decode($line, true);
            if ( $decoded ) {
                $logs[] = $decoded;
                
                // Group by IP for the local UI (historical and brute force entries are already in the database)
                $ip = $decoded['ip_address'];
                $type = $decoded['attack_type'];
                $user_agent = isset($decoded['user_agent']) ? base64_decode($decoded['user_agent']) : '';
                
                if ( $type !== 'Brute_Force' && $user_agent !== 'Legacy_Log_Export' ) {
                    if ( !isset($ui_summary[$ip]) ) {
                        $ui_summary[$ip] = array('count' => 0, 'types' => array());
                    }
                    $ui_summary[$ip]['count']++;
                    if ( !in_array($type, $ui_summary[$ip]['types']) ) {
                        $ui_summary[$ip]['types'][] = $type;
                    }
                }
            }
            
            // Only send to API if Telemetry is enabled
            if ( $telemetry_allowed ) {
                if ( count($logs) >= 1000 ) {
                    $this->send_telemetry_batch($logs);
                    $logs = array();
                }
            } else {
                $logs = array(); // Telemetry off: only empty the buffer file
            }
        }

        if ( count($logs) > 0 && $telemetry_allowed ) {
            $this->send_telemetry_batch($logs);
        }

        // Write aggregated logs to the local UI table
        if ( !empty($ui_summary) ) {
            require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/log/class-metzler-webshield-logger.php';
            foreach ( $ui_summary as $ip => $data ) {
                $types_str = implode(', ', $data['types']);
                if ( $data['count'] === 1 ) {
                    /* translators: 1: IP address, 2: attack types */
                    $msg = sprintf( __( 'WAF Block: 1 attack from IP %1$s (%2$s) prevented.', 'metzler-webshield' ), $ip, $types_str );
                } else {
                    /* translators: 1: number of attacks, 2: IP address, 3: attack types */
                    $msg = sprintf( __( 'WAF Block: %1$d attacks from IP %2$s (%3$s) prevented.', 'metzler-webshield' ), $data['count'], $ip, $types_str );
                }
                Metzler_Webshield_Logger::log($msg, 'waf', 'success');
            }
        }

        wp_delete_file( $processing_file );
    }

    private function send_telemetry_batch( $logs ): void {
        self::post_signed( '/telemetry/waf/batch', array('logs' => $logs) );
    }

    /**
     * JSON POST to the Threat Intelligence API, authenticated with the key and signed with it.
     */
    public static function post_signed( string $endpoint, array $payload, int $timeout = 15 ) {
        $api_url = defined( 'METZLER_WEBSHIELD_API_URL' ) ? METZLER_WEBSHIELD_API_URL : 'https://api.metzler-webshield.de/api';
        $token = get_option('metzler_webshield_license_token', '');
        if ( $token === '' ) {
            return new WP_Error( 'metzler_webshield_not_connected', 'Not connected.' );
        }
        
        $payload_json = json_encode($payload);
        $signature = hash_hmac('sha256', $payload_json, $token);
        
        return wp_remote_post( $api_url . $endpoint, array(
            'blocking' => true,
            'timeout'  => $timeout,
            'body'     => $payload_json,
            'headers'  => array(
                'Content-Type'        => 'application/json',
                'Authorization'       => 'Bearer ' . $token,
                'X-Signature'         => $signature,
                'X-Webshield-Version' => METZLER_WEBSHIELD_VERSION
            )
        ) );
    }

    public static function add_cron_schedules( $schedules ) {
        if ( ! isset( $schedules['five_minutes'] ) ) {
            $schedules['five_minutes'] = array(
                'interval' => 300,
                'display'  => 'Every 5 Minutes'
            );
        }
        return $schedules;
    }

    public static function protect_upload_dir(): void {
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/class-metzler-webshield-storage.php';
        Metzler_Webshield_Storage::ensure_dir();
        Metzler_Webshield_Storage::migrate_legacy_files();
    }

    public static function ensure_scheduled_crons(): void {
        self::protect_upload_dir();

        // Schedule daily cronjob if not already scheduled
        if ( ! wp_next_scheduled( 'metzler_webshield_daily_scan' ) ) {
            // Schedule for 3:00 AM local time tomorrow
            $three_am = strtotime('tomorrow 03:00:00');
            wp_schedule_event( $three_am, 'daily', 'metzler_webshield_daily_scan' );
        }

        // Schedule hourly check of the optional cloud connection
        if ( ! wp_next_scheduled( 'metzler_webshield_hourly_license_check' ) ) {
            wp_schedule_event( time(), 'hourly', 'metzler_webshield_hourly_license_check' );
        }

        // WAF Rules Sync (Hourly; no request unless the site is connected)
        if ( ! wp_next_scheduled( Metzler_Webshield_Cloud_Rules::SYNC_HOOK ) ) {
            wp_schedule_event( time(), 'hourly', Metzler_Webshield_Cloud_Rules::SYNC_HOOK );
        }

        // Schedule 5-minute telemetry sync
        if ( ! wp_next_scheduled( 'metzler_webshield_five_minute_telemetry' ) ) {
            wp_schedule_event( time(), 'five_minutes', 'metzler_webshield_five_minute_telemetry' );
        }

    }

    public static function activate(): void {
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/log/class-metzler-webshield-logger.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/class-metzler-webshield-queue.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/class-metzler-webshield-fim.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/class-metzler-webshield-quarantine.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/class-metzler-webshield-findings.php';
        Metzler_Webshield_Logger::create_table();
        Metzler_Webshield_Queue::create_table();
        Metzler_Webshield_FIM::create_table();
        Metzler_Webshield_Quarantine::create_table();
        Metzler_Webshield_Findings::create_table();
        
        // Auto-Enable WAF on activation
        if ( get_option('metzler_webshield_enable_waf', false) === false ) {
            update_option('metzler_webshield_enable_waf', '1');
        }
        
        self::protect_upload_dir();
        self::ensure_scheduled_crons();
        update_option( 'metzler_webshield_version', METZLER_WEBSHIELD_VERSION );

        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/waf/class-metzler-webshield-firewall-setup.php';
        Metzler_Webshield_Firewall_Setup::write_snapshot();
        Metzler_Webshield_Firewall_Setup::activate();
    }

    public static function get_client_ip(): string {
        return Metzler_Webshield_Request::client_ip();
    }

    public function check_author_enumeration(): void {
        if ( is_admin() || is_user_logged_in() ) {
            return;
        }

        // Public front-end request without a form, so there is no nonce to verify
        if ( isset($_GET['author']) && is_numeric( sanitize_text_field( wp_unslash( $_GET['author'] ) ) ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
            $ip = self::get_client_ip();

            // Search engines follow ?author= links like any other link
            $user_agent = sanitize_text_field( wp_unslash( $_SERVER['HTTP_USER_AGENT'] ?? '' ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
            if ( Metzler_Webshield_Request::is_verified() && Metzler_Webshield_Rate_Limiter::is_verified_search_bot( $ip, $user_agent ) ) {
                return;
            }
            $transient_key = 'mws_ae_' . md5($ip);
            $count = (int) get_transient($transient_key);
            $count++;
            set_transient($transient_key, $count, 60);

            // Rate limit: Allow up to 3 requests per minute for legitimate tests, block automated scans (> 3)
            if ( $count > 3 ) {
                $telemetry_data = array(
                    'time'           => gmdate('c'),
                    'domain'         => wp_parse_url(home_url(), PHP_URL_HOST),
                    'ip_address'     => $ip,
                    'attack_type'    => 'User_Enumeration',
                    'severity'       => 'medium',
                    'request_uri'    => isset($_SERVER['REQUEST_URI']) ? base64_encode(wp_unslash($_SERVER['REQUEST_URI'])) : '', // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
                    'user_agent'     => isset($_SERVER['HTTP_USER_AGENT']) ? base64_encode(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '', // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
                    'request_method' => sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? 'GET' ) ),
                    'payload'        => base64_encode("Author enumeration rate limit exceeded: {$count} probes in 60s"),
                    'encoding'       => 'base64'
                );
                Metzler_Webshield_Storage::append_telemetry($telemetry_data);

                require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/log/class-metzler-webshield-logger.php';
                Metzler_Webshield_Logger::log(
                    sprintf(
                        /* translators: 1: IP address, 2: Probe count */
                        __('User Enumeration blocked: %1$s exceeded rate limit with %2$d author probes in 60s', 'metzler-webshield'),
                        $ip,
                        $count
                    ),
                    'waf',
                    'success'
                );

                wp_die(
                    '<h1>' . esc_html__('Access Denied', 'metzler-webshield') . '</h1><p>' . esc_html__('Suspicious user enumeration activity detected.', 'metzler-webshield') . '</p>',
                    esc_html__('Access Denied', 'metzler-webshield'),
                    array('response' => 403)
                );
            }
        }
    }

    public static function deactivate(): void {
        // We do not drop tables on deactivation to avoid losing log history
        // Use uninstall.php to delete everything
        
        // Unschedule cronjobs
        wp_clear_scheduled_hook( 'metzler_webshield_daily_scan' );
        wp_clear_scheduled_hook( 'metzler_webshield_hourly_license_check' );
        wp_clear_scheduled_hook( 'metzler_webshield_five_minute_telemetry' );
        wp_clear_scheduled_hook( 'metzler_webshield_sync_waf_rules' );

        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/waf/class-metzler-webshield-firewall-setup.php';
        Metzler_Webshield_Firewall_Setup::deactivate();
    }
}
