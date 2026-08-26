<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class Metzler_Webshield {
    public function __construct() {
        $this->load_dependencies();
    }
    
    private function load_dependencies(): void {
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/log/class-metzler-webshield-logger.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/class-metzler-webshield-queue.php';
        
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/scanner/class-metzler-webshield-scanner-core.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/scanner/class-metzler-webshield-scanner-plugins.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/scanner/class-metzler-webshield-scanner-files.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/scanner/class-metzler-webshield-scanner-updates.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/scanner/class-metzler-webshield-scanner-config.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/class-metzler-webshield-fim.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/class-metzler-webshield-quarantine.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/scanner/class-metzler-webshield-scanner-fim.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/scanner/class-metzler-webshield-scanner-config.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/waf/class-metzler-webshield-waf-installer.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/class-metzler-webshield-login.php';
        
        if ( is_admin() ) {
            require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'admin/class-metzler-webshield-admin.php';
        }
    }
    
    public function run(): void {
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
        
        // WAF Rules Sync (Hourly)
        add_action( 'metzler_webshield_sync_waf_rules', array( $this, 'cron_sync_waf_rules' ) );
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

        if ( ! is_wp_error( $response ) ) {
            $body = wp_remote_retrieve_body( $response );
            $data = json_decode( $body, true );

            if ( ! isset( $data['success'] ) || ! $data['success'] ) {
                // Token is invalid/revoked! Lock the plugin.
                delete_option( 'metzler_webshield_is_licensed' );
                update_option( 'metzler_webshield_enable_telemetry', '0' );
            }
        }
    }

    
    private function sync_historical_telemetry(): void {
        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_logs';
        
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $results = $wpdb->get_results("SELECT * FROM $table_name WHERE type = 'waf'");
        if (empty($results)) return;

        $upload_dir = WP_CONTENT_DIR . '/uploads/metzler-webshield';
        if (!file_exists($upload_dir)) {
            wp_mkdir_p($upload_dir);
        }
        $telemetry_file = $upload_dir . '/telemetry.jsonl';

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
                $attack_type = $matches[2]; // Can be multiple types comma separated, but good enough for history
            }
            
            if (!$ip) continue;

            $telemetry_data = array(
                'time' => $row->time,
                'domain' => $domain,
                'ip_address' => sanitize_text_field($ip),
                'attack_type' => sanitize_text_field($attack_type),
                'severity' => 'high',
                'request_uri' => '/historical-sync',
                'user_agent' => 'Legacy_Log_Export'
            );
            
            @file_put_contents($telemetry_file, json_encode($telemetry_data) . "\n", FILE_APPEND | LOCK_EX);
        }
    }


    public function cron_sync_telemetry(): void {
        if ( get_option('metzler_webshield_enable_telemetry', '0') === '1' ) {
            // Only sync history if they actually have a valid license, so Free users don't burn their one-time sync!
            if ( get_option('metzler_webshield_is_licensed') && get_option('metzler_webshield_historical_telemetry_sent', '0') !== '1' ) {
                $this->sync_historical_telemetry();
                update_option('metzler_webshield_historical_telemetry_sent', '1');
            }
        }
        $upload_dir = WP_CONTENT_DIR . '/uploads/metzler-webshield';
        $telemetry_file = $upload_dir . '/telemetry.jsonl';
        $processing_file = $upload_dir . '/telemetry_processing.jsonl';

        if ( ! file_exists($telemetry_file) || filesize($telemetry_file) === 0 ) {
            return;
        }

        // Rename atomically so WAF can immediately start a new file
        if ( ! rename($telemetry_file, $processing_file) ) { // phpcs:ignore
            return;
        }

        $lines = file($processing_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ( empty($lines) ) {
            @unlink($processing_file); // phpcs:ignore
            return;
        }

        $logs = array();
        $ui_summary = array(); // Store aggregated data for local UI

        foreach ( $lines as $line ) {
            $decoded = json_decode($line, true);
            if ( $decoded ) {
                $logs[] = $decoded;
                
                // Aggregate for UI: Group by IP (Skip Legacy/Historical and Brute_Force because they are already in the DB!)
                $ip = $decoded['ip_address'];
                $type = $decoded['attack_type'];
                $user_agent = $decoded['user_agent'] ?? '';
                
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
            if ( get_option('metzler_webshield_enable_telemetry', '0') === '1' ) {
                if ( count($logs) >= 1000 ) {
                    $this->send_telemetry_batch($logs);
                    $logs = array();
                }
            } else {
                $logs = array(); // Clear logs, just consuming the file so it doesn't grow
            }
        }

        if ( count($logs) > 0 && get_option('metzler_webshield_enable_telemetry', '0') === '1' ) {
            $this->send_telemetry_batch($logs);
        }

        // Write aggregated logs to the local UI table
        if ( !empty($ui_summary) ) {
            require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/log/class-metzler-webshield-logger.php';
            foreach ( $ui_summary as $ip => $data ) {
                $types_str = implode(', ', $data['types']);
                if ( $data['count'] === 1 ) {
                    $msg = sprintf( __("WAF Block: 1 attack from IP %1\$s (%2\$s) prevented.", "metzler-webshield"), $ip, $types_str );
                } else {
                    $msg = sprintf( __("WAF Block: %1\$d attacks from IP %2\$s (%3\$s) prevented.", "metzler-webshield"), $data['count'], $ip, $types_str );
                }
                Metzler_Webshield_Logger::log($msg, 'waf', 'success');
            }
        }

        @unlink($processing_file); // phpcs:ignore
    }

    private function send_telemetry_batch( $logs ): void {
        $api_url = defined( 'METZLER_WEBSHIELD_API_URL' ) ? METZLER_WEBSHIELD_API_URL : 'https://api.metzler-webshield.de/api';
        $token = get_option('metzler_webshield_license_token', '');
        
        $payload_json = json_encode(array('logs' => $logs));
        $signature = hash_hmac('sha256', $payload_json, $token);
        
        wp_remote_post( $api_url . '/telemetry/waf/batch', array(
            'blocking' => true,
            'timeout'  => 15,
            'body'     => $payload_json,
            'headers'  => array(
                'Content-Type'  => 'application/json',
                'Authorization' => 'Bearer ' . $token,
                'X-Signature'   => $signature
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

    public static function activate(): void {
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/log/class-metzler-webshield-logger.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/class-metzler-webshield-queue.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/class-metzler-webshield-fim.php';
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/class-metzler-webshield-quarantine.php';
        Metzler_Webshield_Logger::create_table();
        Metzler_Webshield_Queue::create_table();
        Metzler_Webshield_FIM::create_table();
        Metzler_Webshield_Quarantine::create_table();
        
        // Auto-Enable WAF on activation
        if ( get_option('metzler_webshield_enable_waf', false) === false ) {
            update_option('metzler_webshield_enable_waf', '1');
            require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/waf/class-metzler-webshield-waf-installer.php';
            Metzler_Webshield_WAF_Installer::enable_waf();
        }
        
        // Schedule daily cronjob if not already scheduled
        if ( ! wp_next_scheduled( 'metzler_webshield_daily_scan' ) ) {
            // Schedule for 3:00 AM local time tomorrow
            $three_am = strtotime('tomorrow 03:00:00');
            wp_schedule_event( $three_am, 'daily', 'metzler_webshield_daily_scan' );
        }

        // Schedule hourly license check
        if ( ! wp_next_scheduled( 'metzler_webshield_hourly_license_check' ) ) {
            wp_schedule_event( time(), 'hourly', 'metzler_webshield_hourly_license_check' );
        }

        // Schedule 5-minute telemetry sync
        if ( ! wp_next_scheduled( 'metzler_webshield_five_minute_telemetry' ) ) {
            wp_schedule_event( time(), 'five_minutes', 'metzler_webshield_five_minute_telemetry' );
        }

        // WAF Rules Sync (Hourly)
        if ( ! wp_next_scheduled( 'metzler_webshield_sync_waf_rules' ) ) {
            wp_schedule_event( time(), 'hourly', 'metzler_webshield_sync_waf_rules' );
        }
    }

    public function cron_sync_waf_rules(): void {
        $token = get_option('metzler_webshield_license_token', '');
        if ( empty($token) ) return;

        $api_url = defined( 'METZLER_WEBSHIELD_API_URL' ) ? METZLER_WEBSHIELD_API_URL : 'https://api.metzler-webshield.de/api';
        
        $response = wp_remote_get( $api_url . '/waf/rules', array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $token,
                'Accept'        => 'application/json'
            ),
            'timeout' => 15,
        ));

        if ( is_wp_error($response) ) return;

        $body = wp_remote_retrieve_body($response);
        $data = json_decode($body, true);

        if ( isset($data['success']) && $data['success'] && isset($data['payload']) && isset($data['iv']) ) {
            $upload_dir = WP_CONTENT_DIR . '/uploads/metzler-webshield';
            if ( ! is_dir($upload_dir) ) {
                @mkdir($upload_dir, 0755, true); // phpcs:ignore
                @file_put_contents($upload_dir . '/index.php', "<?php // Silence is golden."); // phpcs:ignore
            }
            
            // We save the RAW encrypted JSON. The WAF will decrypt it on the fly using waf.key
            file_put_contents($upload_dir . '/waf-rules.enc', $body, LOCK_EX); // phpcs:ignore
            
            Metzler_Webshield_Logger::log(__("WAF rules successfully synchronized from Threat Intelligence Cloud.", "metzler-webshield"), "system", "success");
        }
    }

    public static function deactivate(): void {
        // We do not drop tables on deactivation to avoid losing log history
        // Use uninstall.php to delete everything
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/waf/class-metzler-webshield-waf-installer.php';
        Metzler_Webshield_WAF_Installer::disable_waf();
        
        // Unschedule cronjobs
        wp_clear_scheduled_hook( 'metzler_webshield_daily_scan' );
        wp_clear_scheduled_hook( 'metzler_webshield_hourly_license_check' );
        wp_clear_scheduled_hook( 'metzler_webshield_five_minute_telemetry' );
    }
}
