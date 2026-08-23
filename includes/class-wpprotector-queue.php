<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class WPProtector_Queue {
    public static function create_table(): void {
        global $wpdb;
        $table_name = $wpdb->prefix . 'wpprotector_queue';
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE $table_name (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            task_type varchar(50) NOT NULL,
            payload longtext NOT NULL,
            status varchar(20) DEFAULT 'pending' NOT NULL,
            PRIMARY KEY  (id)
        ) $charset_collate;";

        require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
        dbDelta( $sql );
    }

    public function init(): void {
        add_action( 'wp_ajax_wpprotector_start_scan', array( $this, 'ajax_start_scan' ) );
        add_action( 'wp_ajax_wpprotector_process_queue', array( $this, 'ajax_process_queue' ) );
        add_action( 'wp_ajax_wpprotector_get_logs', array( $this, 'ajax_get_logs' ) );
        add_action( 'wp_ajax_wpprotector_do_update', array( $this, 'ajax_do_update' ) );
        add_action( 'wp_ajax_wpprotector_clear_logs', array( $this, 'ajax_clear_logs' ) );
        add_action( 'wp_ajax_wpprotector_create_baseline', array( $this, 'ajax_create_baseline' ) );
        add_action( 'wp_ajax_wpprotector_accept_fim', array( $this, 'ajax_accept_fim' ) );
        add_action( 'wp_ajax_wpprotector_quarantine_file', array( $this, 'ajax_quarantine_file' ) );
        add_action( 'wp_ajax_wpprotector_quarantine_restore', array( $this, 'ajax_quarantine_restore' ) );
        add_action( 'wp_ajax_wpprotector_quarantine_delete', array( $this, 'ajax_quarantine_delete' ) );
        add_action( 'wp_ajax_wpprotector_get_quarantine', array( $this, 'ajax_get_quarantine' ) );
        add_action( 'wp_ajax_wpprotector_cancel_scan', array( $this, 'ajax_cancel_scan' ) );
        add_action( 'wp_ajax_wpprotector_save_settings', array( $this, 'ajax_save_settings' ) );
    }

    public function ajax_start_scan(): void
    {
        check_ajax_referer( 'wpprotector_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        
        if ( ! get_option( 'wpprotector_is_licensed' ) ) {
            wp_send_json_error(array('message' => __('Please activate your license first.', 'wpprotector')));
        }
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'wpprotector_queue';
        $wpdb->query("TRUNCATE TABLE $table_name");
        WPProtector_Logger::cleanup_old_logs();
        
        update_option('wpprotector_last_scan_start', current_time('mysql'));

        WPProtector_Logger::log("System-Scan initialisiert. Überprüfe Dateien und Updates...", "system" );

        $tasks = array();
        
        if ( get_option('wpprotector_enable_updates', '1') === '1' ) {
            $tasks[] = array('type' => 'scan_updates', 'payload' => json_encode(array('step' => 'init')));
        }
        
        if ( get_option('wpprotector_enable_plugins', '1') === '1' ) {
            $tasks[] = array('type' => 'scan_plugins', 'payload' => json_encode(array('step' => 'init')));
        }
        
        if ( get_option('wpprotector_enable_core', '1') === '1' ) {
            $tasks[] = array('type' => 'scan_core', 'payload' => json_encode(array('step' => 'init')));
        }
        
        if ( get_option('wpprotector_enable_files', '1') === '1' ) {
            $tasks[] = array('type' => 'scan_files', 'payload' => json_encode(array('step' => 'init')));
        }
        
        if ( get_option('wpprotector_enable_fim', '1') === '1' ) {
            $tasks[] = array('type' => 'scan_fim', 'payload' => json_encode(array('step' => 'init')));
        }
        
        $tasks[] = array('type' => 'scan_config', 'payload' => json_encode(array('step' => 'init')));

        foreach ($tasks as $task) {
            $wpdb->insert($table_name, array(
                'task_type' => $task['type'],
                'payload' => $task['payload'],
                'status' => 'pending'
            ));
        }

        wp_send_json_success(array('message' => __('Scan queued', 'wpprotector')));
    }

    public function ajax_process_queue(): void {
        check_ajax_referer( 'wpprotector_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'wpprotector_queue';
        
        $task = $wpdb->get_row("SELECT * FROM $table_name WHERE status = 'pending' ORDER BY id ASC LIMIT 1");
        
        if ( ! $task ) {
            WPProtector_Logger::log("Scan abgeschlossen.", "system", "success");
            update_option('wpprotector_last_scan', current_time('mysql'));
            wp_send_json_success(array('status' => 'complete', 'message' => __('Scan completed', 'wpprotector')));
        }

        $result = array('status' => 'success');
        switch ( $task->task_type ) {
            case 'scan_updates':
                $scanner = new WPProtector_Scanner_Updates();
                $result = $scanner->run_step( json_decode($task->payload, true) );
                break;
            case 'scan_core':
                $scanner = new WPProtector_Scanner_Core();
                $result = $scanner->run_step( json_decode($task->payload, true) );
                break;
            case 'scan_plugins':
                $scanner = new WPProtector_Scanner_Plugins();
                $result = $scanner->run_step( json_decode($task->payload, true) );
                break;
            case 'scan_files':
                $scanner = new WPProtector_Scanner_Files();
                $result = $scanner->run_step( json_decode($task->payload, true) );
                break;
            case 'scan_fim':
                $scanner = new WPProtector_Scanner_FIM();
                $result = $scanner->run_step( json_decode($task->payload, true) );
                break;
            case 'scan_config':
                $scanner = new WPProtector_Scanner_Config();
                $result = $scanner->run_step( json_decode($task->payload, true) );
                break;
        }

        if ( isset($result['complete']) && $result['complete'] ) {
            $wpdb->update($table_name, array('status' => 'completed'), array('id' => $task->id));
        } else {
            if ( isset($result['next_payload']) ) {
                $wpdb->update($table_name, array('payload' => json_encode($result['next_payload'])), array('id' => $task->id));
            }
        }
        
        wp_send_json_success(array(
            'status' => 'processing',
            'task' => $task->task_type,
            'message' => $result['message'] ?? 'Processing...'
        ));
    }
    
    public function ajax_get_logs(): void {
        check_ajax_referer( 'wpprotector_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        
        // Force sync telemetry so WAF logs appear instantly in the UI
        require_once WPPROTECTOR_PLUGIN_DIR . 'includes/class-wpprotector.php';
        $wpprotector = new WPProtector();
        $wpprotector->cron_sync_telemetry();
        
        $logs = WPProtector_Logger::get_logs( 100 );
        $last_scan_start = get_option('wpprotector_last_scan_start', '0000-00-00 00:00:00');
        wp_send_json_success(array(
            'logs' => $logs,
            'last_scan_start' => $last_scan_start
        ));
    }
    public function ajax_do_update(): void {
        check_ajax_referer( 'wpprotector_nonce' );
        if ( ! current_user_can( 'update_plugins' ) && ! current_user_can( 'update_core' ) ) wp_die();
        
        $type = isset($_POST['update_type']) ? sanitize_text_field($_POST['update_type']) : '';
        $item = isset($_POST['update_item']) ? sanitize_text_field($_POST['update_item']) : '';
        
        include_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
        include_once ABSPATH . 'wp-admin/includes/file.php';
        
        if ( $type === 'plugin' && !empty($item) ) {
            $upgrader = new Plugin_Upgrader( new Automatic_Upgrader_Skin() );
            $result = $upgrader->upgrade( $item );
            if ( is_wp_error( $result ) || ! $result ) {
                wp_send_json_error(array('message' => __('Update failed.', 'wpprotector')));
            }
            wp_send_json_success(array('message' => __('Successfully updated.', 'wpprotector')));
        } elseif ( $type === 'core' ) {
            $upgrader = new Core_Upgrader( new Automatic_Upgrader_Skin() );
            $core_updates = get_site_transient('update_core');
            if ( isset($core_updates->updates[0]) ) {
                $result = $upgrader->upgrade( $core_updates->updates[0] );
                if ( is_wp_error( $result ) || ! $result ) {
                    wp_send_json_error(array('message' => __('Update failed.', 'wpprotector')));
                }
                wp_send_json_success(array('message' => __('Successfully updated.', 'wpprotector')));
            }
        }
        
        wp_send_json_error(array('message' => __('Invalid request.', 'wpprotector')));
    }

    public function ajax_clear_logs(): void {
        check_ajax_referer( 'wpprotector_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        global $wpdb;
        $table_name = $wpdb->prefix . 'wpprotector_logs';
        $wpdb->query("TRUNCATE TABLE $table_name");
        wp_send_json_success(array('message' => __('Log cleared.', 'wpprotector')));
    }

    public function ajax_create_baseline(): void {
        check_ajax_referer( 'wpprotector_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        $fim = new WPProtector_FIM();
        $count = $fim->build_baseline();
        wp_send_json_success(array('message' => "Baseline mit $count Dateien erfolgreich erstellt."));
    }

    public function ajax_cancel_scan(): void {
        check_ajax_referer( 'wpprotector_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        global $wpdb;
        $table_name = $wpdb->prefix . 'wpprotector_queue';
        $wpdb->query("TRUNCATE TABLE $table_name");
        WPProtector_Logger::log(__("The Smart Scan was aborted by the user.", "wpprotector"), "system", "warning");
        wp_send_json_success();
    }

    public function ajax_accept_fim(): void {
        check_ajax_referer( 'wpprotector_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        $path = isset($_POST['path']) ? sanitize_text_field($_POST['path']) : '';
        if ( ! $path ) wp_send_json_error();
        
        $fim = new WPProtector_FIM();
        $fim->accept_file($path);
        
        WPProtector_Logger::resolve_path_logs($path); // Delete old warnings
        WPProtector_Logger::log("Datei als sicher markiert: $path", "system", "success");
        
        wp_send_json_success();
    }

    public function ajax_quarantine_file(): void {
        check_ajax_referer( 'wpprotector_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        $path = isset($_POST['path']) ? sanitize_text_field($_POST['path']) : '';
        if ( ! $path ) wp_send_json_error();
        
        $quarantine = new WPProtector_Quarantine();
        $result = $quarantine->quarantine_file($path);
        
        if ( $result ) {
            WPProtector_Logger::resolve_path_logs($path); // Delete old warnings
            wp_send_json_success();
        } else {
            wp_send_json_error(array('message' => __('Could not move file to quarantine. (Permissions?)', 'wpprotector')));
        }
    } 

    public function ajax_quarantine_restore(): void {
        check_ajax_referer( 'wpprotector_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        $id = isset($_POST['id']) ? intval($_POST['id']) : 0;
        if ( $id > 0 ) {
            $q = new WPProtector_Quarantine();
            if ( $q->restore_file($id) ) {
                wp_send_json_success();
            }
        }
        wp_send_json_error(array('message' => __('Error during restoration.', 'wpprotector')));
    }

    public function ajax_quarantine_delete(): void {
        check_ajax_referer( 'wpprotector_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        $id = isset($_POST['id']) ? intval($_POST['id']) : 0;
        if ( $id > 0 ) {
            $q = new WPProtector_Quarantine();
            if ( $q->delete_file($id) ) {
                wp_send_json_success();
            }
        }
        wp_send_json_error(array('message' => __('Error during deletion.', 'wpprotector')));
    }

    public function ajax_get_quarantine(): void {
        check_ajax_referer( 'wpprotector_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        $q = new WPProtector_Quarantine();
        wp_send_json_success(array('files' => $q->get_files()));
    }

    public function ajax_save_settings(): void {
        check_ajax_referer( 'wpprotector_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        $enable_fim = isset($_POST['enable_fim']) ? sanitize_text_field($_POST['enable_fim']) : '0';
        $enable_core = isset($_POST['enable_core']) ? sanitize_text_field($_POST['enable_core']) : '0';
        $enable_files = isset($_POST['enable_files']) ? sanitize_text_field($_POST['enable_files']) : '0';
        $enable_updates = isset($_POST['enable_updates']) ? sanitize_text_field($_POST['enable_updates']) : '0';
        $enable_plugins = isset($_POST['enable_plugins']) ? sanitize_text_field($_POST['enable_plugins']) : '0';
        $enable_waf = isset($_POST['enable_waf']) ? sanitize_text_field($_POST['enable_waf']) : '0';
        $disable_xmlrpc = isset($_POST['disable_xmlrpc']) ? sanitize_text_field($_POST['disable_xmlrpc']) : '0';
        $enable_telemetry = isset($_POST['enable_telemetry']) ? sanitize_text_field($_POST['enable_telemetry']) : '1';
        
        update_option('wpprotector_enable_fim', $enable_fim);
        update_option('wpprotector_enable_core', $enable_core);
        update_option('wpprotector_enable_files', $enable_files);
        update_option('wpprotector_enable_updates', $enable_updates);
        update_option('wpprotector_enable_plugins', $enable_plugins);
        update_option('wpprotector_enable_waf', $enable_waf);
        update_option('wpprotector_disable_xmlrpc', $disable_xmlrpc);
        update_option('wpprotector_enable_telemetry', $enable_telemetry);
        
        // Handle WAF installation
        require_once WPPROTECTOR_PLUGIN_DIR . 'includes/waf/class-wpprotector-waf-installer.php';
        if ( $enable_waf === '1' ) {
            WPProtector_WAF_Installer::enable_waf();
        } else {
            WPProtector_WAF_Installer::disable_waf();
        }
        
        wp_send_json_success();
    }
    
    public static function cron_start_scan(): void {
        if ( ! get_option( 'wpprotector_is_licensed' ) ) {
            WPProtector_Logger::log(__("Automatic scan aborted: No valid license found.", "wpprotector"), "system", "error");
            return;
        }

        global $wpdb;
        $table_name = $wpdb->prefix . 'wpprotector_queue';
        $wpdb->query("TRUNCATE TABLE $table_name");
        WPProtector_Logger::cleanup_old_logs();
        
        update_option('wpprotector_last_scan_start', current_time('mysql'));
        WPProtector_Logger::log(__("Automatic background scan (cron) started...", "wpprotector"), "system" );

        $tasks = array();
        
        if ( get_option('wpprotector_enable_updates', '1') === '1' ) {
            $tasks[] = array('type' => 'scan_updates', 'payload' => json_encode(array('step' => 'init')));
        }
        
        if ( get_option('wpprotector_enable_plugins', '1') === '1' ) {
            $tasks[] = array('type' => 'scan_plugins', 'payload' => json_encode(array('step' => 'init')));
        }
        
        if ( get_option('wpprotector_enable_core', '1') === '1' ) {
            $tasks[] = array('type' => 'scan_core', 'payload' => json_encode(array('step' => 'init')));
        }
        
        if ( get_option('wpprotector_enable_files', '1') === '1' ) {
            $tasks[] = array('type' => 'scan_files', 'payload' => json_encode(array('step' => 'init')));
        }
        
        if ( get_option('wpprotector_enable_fim', '1') === '1' ) {
            $tasks[] = array('type' => 'scan_fim', 'payload' => json_encode(array('step' => 'init')));
        }
        
        $tasks[] = array('type' => 'scan_config', 'payload' => json_encode(array('step' => 'init')));

        foreach ($tasks as $task) {
            $wpdb->insert($table_name, array(
                'task_type' => $task['type'],
                'payload' => $task['payload'],
                'status' => 'pending',
                'created_at' => current_time('mysql')
            ));
        }
        
        self::cron_process_queue();
    }
    
    public static function cron_process_queue(): void {
        global $wpdb;
        $table_name = $wpdb->prefix . 'wpprotector_queue';
        
        // Give the cron process enough time to complete
        if ( function_exists('set_time_limit') ) {
            @set_time_limit(300);
        }
        
        $start_time = time();
        $max_execution_time = 240; // 4 minutes
        
        while ( true ) {
            // Check if we are running out of time
            if ( (time() - $start_time) > $max_execution_time ) {
                WPProtector_Logger::log(__("Cron scan paused (time limit reached). It will resume on the next run.", "wpprotector"), "system", "warning");
                break;
            }
            
            $task = $wpdb->get_row("SELECT * FROM $table_name WHERE status = 'pending' ORDER BY id ASC LIMIT 1");
            if ( ! $task ) {
                WPProtector_Logger::log(__("Automatic background scan completed successfully.", "wpprotector"), "system" );
                break;
            }
            
            $result = array();
            switch ($task->task_type) {
                case 'scan_updates':
                    $scanner = new WPProtector_Scanner_Updates();
                    $result = $scanner->run_step( json_decode($task->payload, true) );
                    break;
                case 'scan_core':
                    $scanner = new WPProtector_Scanner_Core();
                    $result = $scanner->run_step( json_decode($task->payload, true) );
                    break;
                case 'scan_plugins':
                    $scanner = new WPProtector_Scanner_Plugins();
                    $result = $scanner->run_step( json_decode($task->payload, true) );
                    break;
                case 'scan_files':
                    $scanner = new WPProtector_Scanner_Files();
                    $result = $scanner->run_step( json_decode($task->payload, true) );
                    break;
                case 'scan_fim':
                    $scanner = new WPProtector_Scanner_FIM();
                    $result = $scanner->run_step( json_decode($task->payload, true) );
                    break;
                case 'scan_config':
                    $scanner = new WPProtector_Scanner_Config();
                    $result = $scanner->run_step( json_decode($task->payload, true) );
                    break;
            }

            if ( isset($result['complete']) && $result['complete'] ) {
                $wpdb->update($table_name, array('status' => 'completed'), array('id' => $task->id));
            } else {
                if ( isset($result['next_payload']) ) {
                    $wpdb->update($table_name, array('payload' => json_encode($result['next_payload'])), array('id' => $task->id));
                }
            }
        }
    }
}
