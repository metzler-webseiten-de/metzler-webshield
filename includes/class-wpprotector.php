<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class WPProtector {
    public function __construct() {
        $this->load_dependencies();
    }
    
    private function load_dependencies(): void {
        require_once WPPROTECTOR_PLUGIN_DIR . 'includes/log/class-wpprotector-logger.php';
        require_once WPPROTECTOR_PLUGIN_DIR . 'includes/class-wpprotector-queue.php';
        
        require_once WPPROTECTOR_PLUGIN_DIR . 'includes/scanner/class-wpprotector-scanner-core.php';
        require_once WPPROTECTOR_PLUGIN_DIR . 'includes/scanner/class-wpprotector-scanner-plugins.php';
        require_once WPPROTECTOR_PLUGIN_DIR . 'includes/scanner/class-wpprotector-scanner-files.php';
        require_once WPPROTECTOR_PLUGIN_DIR . 'includes/scanner/class-wpprotector-scanner-updates.php';
        require_once WPPROTECTOR_PLUGIN_DIR . 'includes/scanner/class-wpprotector-scanner-config.php';
        require_once WPPROTECTOR_PLUGIN_DIR . 'includes/class-wpprotector-fim.php';
        require_once WPPROTECTOR_PLUGIN_DIR . 'includes/class-wpprotector-quarantine.php';
        require_once WPPROTECTOR_PLUGIN_DIR . 'includes/scanner/class-wpprotector-scanner-fim.php';
        require_once WPPROTECTOR_PLUGIN_DIR . 'includes/scanner/class-wpprotector-scanner-config.php';
        require_once WPPROTECTOR_PLUGIN_DIR . 'includes/waf/class-wpprotector-waf-installer.php';
        require_once WPPROTECTOR_PLUGIN_DIR . 'includes/class-wpprotector-login.php';
        
        if ( is_admin() ) {
            require_once WPPROTECTOR_PLUGIN_DIR . 'admin/class-wpprotector-admin.php';
        }
    }
    
    public function run(): void {
        if ( is_admin() ) {
            $admin = new WPProtector_Admin();
            $admin->init();
        }
        
        $queue = new WPProtector_Queue();
        $queue->init();

        $login = new WPProtector_Login();
        
        add_action( 'wpprotector_daily_scan', array( $this, 'cron_verify_license' ) );
        
        $fim = new WPProtector_FIM();
        $fim->init();
        
        $quarantine = new WPProtector_Quarantine();
        $quarantine->init();
        
        // XML-RPC Hardening
        if ( get_option('wpprotector_disable_xmlrpc', '0') === '1' ) {
            add_filter( 'xmlrpc_enabled', '__return_false' );
        }

        // Custom Cron Schedules
        add_filter( 'cron_schedules', array( 'WPProtector', 'add_cron_schedules' ) );
        
        // Background Cronjob (3 AM Daily)
        add_action( 'wpprotector_daily_scan', array( 'WPProtector_Queue', 'cron_start_scan' ) );
        
        // Background License Check (Hourly)
        add_action( 'wpprotector_hourly_license_check', array( $this, 'cron_verify_license' ) );

        // Telemetry Batch Sync (Every 5 Minutes)
        add_action( 'wpprotector_five_minute_telemetry', array( $this, 'cron_sync_telemetry' ) );
        
        // WAF Rules Sync (Hourly)
        add_action( 'wpprotector_sync_waf_rules', array( $this, 'cron_sync_waf_rules' ) );
    }

    public function cron_verify_license(): void {
        if ( ! get_option( 'wpprotector_is_licensed' ) ) {
            return;
        }

        $token = get_option( 'wpprotector_license_token' );
        $domain = parse_url( home_url(), PHP_URL_HOST );
        $api_url = defined( 'WPPROTECTOR_API_URL' ) ? WPPROTECTOR_API_URL : 'https://api.wp-protector.de/api';

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
                delete_option( 'wpprotector_is_licensed' );
            }
        }
    }

    public function cron_sync_telemetry(): void {
        $upload_dir = WP_CONTENT_DIR . '/uploads/wpprotector';
        $telemetry_file = $upload_dir . '/telemetry.jsonl';
        $processing_file = $upload_dir . '/telemetry_processing.jsonl';

        if ( ! file_exists($telemetry_file) || filesize($telemetry_file) === 0 ) {
            return;
        }

        // Rename atomically so WAF can immediately start a new file
        if ( ! rename($telemetry_file, $processing_file) ) {
            return;
        }

        $lines = file($processing_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if ( empty($lines) ) {
            @unlink($processing_file);
            return;
        }

        $logs = array();
        $ui_summary = array(); // Store aggregated data for local UI

        foreach ( $lines as $line ) {
            $decoded = json_decode($line, true);
            if ( $decoded ) {
                $logs[] = $decoded;
                
                // Aggregate for UI: Group by IP
                $ip = $decoded['ip_address'];
                $type = $decoded['attack_type'];
                if ( !isset($ui_summary[$ip]) ) {
                    $ui_summary[$ip] = array('count' => 0, 'types' => array());
                }
                $ui_summary[$ip]['count']++;
                if ( !in_array($type, $ui_summary[$ip]['types']) ) {
                    $ui_summary[$ip]['types'][] = $type;
                }
            }
            
            // Only send to API if Telemetry is enabled
            if ( get_option('wpprotector_enable_telemetry', '1') === '1' ) {
                if ( count($logs) >= 1000 ) {
                    $this->send_telemetry_batch($logs);
                    $logs = array();
                }
            } else {
                $logs = array(); // Clear logs, just consuming the file so it doesn't grow
            }
        }

        if ( count($logs) > 0 && get_option('wpprotector_enable_telemetry', '1') === '1' ) {
            $this->send_telemetry_batch($logs);
        }

        // Write aggregated logs to the local UI table
        if ( !empty($ui_summary) ) {
            require_once WPPROTECTOR_PLUGIN_DIR . 'includes/log/class-wpprotector-logger.php';
            foreach ( $ui_summary as $ip => $data ) {
                $types_str = implode(', ', $data['types']);
                if ( $data['count'] === 1 ) {
                    $msg = "WAF Block: 1 Angriff von IP $ip ($types_str) abgewehrt.";
                } else {
                    $msg = "WAF Block: " . $data['count'] . " Angriffe von IP $ip ($types_str) abgewehrt.";
                }
                WPProtector_Logger::log($msg, 'waf', 'success');
            }
        }

        @unlink($processing_file);
    }

    private function send_telemetry_batch( $logs ): void {
        $api_url = defined( 'WPPROTECTOR_API_URL' ) ? WPPROTECTOR_API_URL : 'https://api.wp-protector.de/api';
        $token = get_option('wpprotector_license_token', '');
        
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
        require_once WPPROTECTOR_PLUGIN_DIR . 'includes/log/class-wpprotector-logger.php';
        require_once WPPROTECTOR_PLUGIN_DIR . 'includes/class-wpprotector-queue.php';
        require_once WPPROTECTOR_PLUGIN_DIR . 'includes/class-wpprotector-fim.php';
        require_once WPPROTECTOR_PLUGIN_DIR . 'includes/class-wpprotector-quarantine.php';
        WPProtector_Logger::create_table();
        WPProtector_Queue::create_table();
        WPProtector_FIM::create_table();
        WPProtector_Quarantine::create_table();
        
        // Auto-Enable WAF on activation
        if ( get_option('wpprotector_enable_waf', false) === false ) {
            update_option('wpprotector_enable_waf', '1');
            require_once WPPROTECTOR_PLUGIN_DIR . 'includes/waf/class-wpprotector-waf-installer.php';
            WPProtector_WAF_Installer::enable_waf();
        }
        
        // Schedule daily cronjob if not already scheduled
        if ( ! wp_next_scheduled( 'wpprotector_daily_scan' ) ) {
            // Schedule for 3:00 AM local time tomorrow
            $three_am = strtotime('tomorrow 03:00:00');
            wp_schedule_event( $three_am, 'daily', 'wpprotector_daily_scan' );
        }

        // Schedule hourly license check
        if ( ! wp_next_scheduled( 'wpprotector_hourly_license_check' ) ) {
            wp_schedule_event( time(), 'hourly', 'wpprotector_hourly_license_check' );
        }

        // Schedule 5-minute telemetry sync
        if ( ! wp_next_scheduled( 'wpprotector_five_minute_telemetry' ) ) {
            wp_schedule_event( time(), 'five_minutes', 'wpprotector_five_minute_telemetry' );
        }

        // WAF Rules Sync (Hourly)
        if ( ! wp_next_scheduled( 'wpprotector_sync_waf_rules' ) ) {
            wp_schedule_event( time(), 'hourly', 'wpprotector_sync_waf_rules' );
        }
    }

    public function cron_sync_waf_rules(): void {
        $token = get_option('wpprotector_license_token', '');
        if ( empty($token) ) return;

        $api_url = defined( 'WPPROTECTOR_API_URL' ) ? WPPROTECTOR_API_URL : 'https://api.wp-protector.de/api';
        
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
            $upload_dir = WP_CONTENT_DIR . '/uploads/wpprotector';
            if ( ! is_dir($upload_dir) ) {
                @mkdir($upload_dir, 0755, true);
                @file_put_contents($upload_dir . '/index.php', "<?php // Silence is golden.");
            }
            
            // We save the RAW encrypted JSON. The WAF will decrypt it on the fly using waf.key
            file_put_contents($upload_dir . '/waf-rules.enc', $body, LOCK_EX);
            
            WPProtector_Logger::log(__("WAF rules successfully synchronized from Threat Intelligence Cloud.", "wpprotector"), "system", "success");
        }
    }

    public static function deactivate(): void {
        // We do not drop tables on deactivation to avoid losing log history
        // Use uninstall.php to delete everything
        require_once WPPROTECTOR_PLUGIN_DIR . 'includes/waf/class-wpprotector-waf-installer.php';
        WPProtector_WAF_Installer::disable_waf();
        
        // Unschedule cronjobs
        wp_clear_scheduled_hook( 'wpprotector_daily_scan' );
        wp_clear_scheduled_hook( 'wpprotector_hourly_license_check' );
        wp_clear_scheduled_hook( 'wpprotector_five_minute_telemetry' );
    }
}
