<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class Metzler_Webshield_Queue {
    public static function create_table(): void {
        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_queue'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        $charset_collate = $wpdb->get_charset_collate(); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter

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
        add_action( 'wp_ajax_metzler_webshield_start_scan', array( $this, 'ajax_start_scan' ) );
        add_action( 'wp_ajax_metzler_webshield_process_queue', array( $this, 'ajax_process_queue' ) );
        add_action( 'wp_ajax_metzler_webshield_get_logs', array( $this, 'ajax_get_logs' ) );
        add_action( 'wp_ajax_metzler_webshield_do_update', array( $this, 'ajax_do_update' ) );
        add_action( 'wp_ajax_metzler_webshield_clear_logs', array( $this, 'ajax_clear_logs' ) );
        add_action( 'wp_ajax_metzler_webshield_create_baseline', array( $this, 'ajax_create_baseline' ) );
        add_action( 'wp_ajax_metzler_webshield_accept_fim', array( $this, 'ajax_accept_fim' ) );
        add_action( 'wp_ajax_metzler_webshield_quarantine_file', array( $this, 'ajax_quarantine_file' ) );
        add_action( 'wp_ajax_metzler_webshield_quarantine_restore', array( $this, 'ajax_quarantine_restore' ) );
        add_action( 'wp_ajax_metzler_webshield_quarantine_delete', array( $this, 'ajax_quarantine_delete' ) );
        add_action( 'wp_ajax_metzler_webshield_get_quarantine', array( $this, 'ajax_get_quarantine' ) );
        add_action( 'wp_ajax_metzler_webshield_cancel_scan', array( $this, 'ajax_cancel_scan' ) );
        add_action( 'wp_ajax_metzler_webshield_save_settings', array( $this, 'ajax_save_settings' ) );
        add_action( 'wp_ajax_metzler_webshield_delete_user', array( $this, 'ajax_delete_user' ) );
    }

    public function ajax_start_scan(): void
    {
        check_ajax_referer( 'metzler_webshield_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        
        $is_licensed = get_option( 'metzler_webshield_is_licensed' );
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_queue'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query("TRUNCATE TABLE $table_name"); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        
        Metzler_Webshield_Logger::cleanup_old_logs();
        
        update_option('metzler_webshield_last_scan_start', current_time('mysql'));

        Metzler_Webshield_Logger::log( __("System scan initialized. Checking files and updates...", "metzler-webshield"), "system" );

        $tasks = array();
        
        if ( get_option('metzler_webshield_enable_updates', '1') === '1' ) {
            $tasks[] = array('type' => 'scan_updates', 'payload' => json_encode(array('step' => 'init')));
        }
        
        // Cloud-only scanners
        if ( $is_licensed ) {
            if ( get_option('metzler_webshield_enable_plugins', '1') === '1' ) {
                $tasks[] = array('type' => 'scan_plugins', 'payload' => json_encode(array('step' => 'init')));
            }
            if ( get_option('metzler_webshield_enable_core', '1') === '1' ) {
                $tasks[] = array('type' => 'scan_core', 'payload' => json_encode(array('step' => 'init')));
            }
        }
        
        if ( get_option('metzler_webshield_enable_files', '1') === '1' ) {
            $tasks[] = array('type' => 'scan_files', 'payload' => json_encode(array('step' => 'init')));
        }
        
        if ( get_option('metzler_webshield_enable_fim', '1') === '1' ) {
            $tasks[] = array('type' => 'scan_fim', 'payload' => json_encode(array('step' => 'init')));
        }
        
        $tasks[] = array('type' => 'scan_config', 'payload' => json_encode(array('step' => 'init')));

        foreach ($tasks as $task) {
            $wpdb->insert($table_name, array( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery
                'task_type' => $task['type'],
                'payload' => $task['payload'],
                'status' => 'pending'
            ));
        }

        wp_send_json_success(array('message' => __('Scan queued', 'metzler-webshield')));
    }

    public function ajax_process_queue(): void {
        check_ajax_referer( 'metzler_webshield_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_queue'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        
        $task = $wpdb->get_row("SELECT * FROM $table_name WHERE status = 'pending' ORDER BY id ASC LIMIT 1"); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        
        if ( ! $task ) {
            Metzler_Webshield_Logger::log( __("Scan completed.", "metzler-webshield"), "system", "success");
            update_option('metzler_webshield_last_scan', current_time('mysql'));
            wp_send_json_success(array('status' => 'complete', 'message' => __('Scan completed', 'metzler-webshield')));
        }

        $result = array('status' => 'success');
        switch ( $task->task_type ) {
            case 'scan_updates':
                $scanner = new Metzler_Webshield_Scanner_Updates();
                $result = $scanner->run_step( json_decode($task->payload, true) );
                break;
            case 'scan_core':
                $scanner = new Metzler_Webshield_Scanner_Core();
                $result = $scanner->run_step( json_decode($task->payload, true) );
                break;
            case 'scan_plugins':
                $scanner = new Metzler_Webshield_Scanner_Plugins();
                $result = $scanner->run_step( json_decode($task->payload, true) );
                break;
            case 'scan_files':
                $scanner = new Metzler_Webshield_Scanner_Files();
                $result = $scanner->run_step( json_decode($task->payload, true) );
                break;
            case 'scan_fim':
                $scanner = new Metzler_Webshield_Scanner_FIM();
                $result = $scanner->run_step( json_decode($task->payload, true) );
                break;
            case 'scan_config':
                $scanner = new Metzler_Webshield_Scanner_Config();
                $result = $scanner->run_step( json_decode($task->payload, true) );
                break;
        }

        if ( isset($result['complete']) && $result['complete'] ) {
            $wpdb->update($table_name, array('status' => 'completed'), array('id' => $task->id)); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery
        } else {
            if ( isset($result['next_payload']) ) {
                $wpdb->update($table_name, array('payload' => json_encode($result['next_payload'])), array('id' => $task->id)); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery
            }
        }
        
        wp_send_json_success(array(
            'status' => 'processing',
            'task' => $task->task_type,
            'message' => $result['message'] ?? 'Processing...'
        ));
    }
    
    public function ajax_get_logs(): void {
        check_ajax_referer( 'metzler_webshield_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        
        // Force sync telemetry so WAF logs appear instantly in the UI
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/class-metzler-webshield.php';
        $metzler_webshield = new Metzler_Webshield();
        $metzler_webshield->cron_sync_telemetry();
        
        $logs = Metzler_Webshield_Logger::get_logs( 100 );
        $last_scan_start = get_option('metzler_webshield_last_scan_start', '0000-00-00 00:00:00');
        wp_send_json_success(array(
            'logs' => $logs,
            'last_scan_start' => $last_scan_start
        ));
    }
    public function ajax_do_update(): void {
        check_ajax_referer( 'metzler_webshield_nonce' );
        if ( ! current_user_can( 'update_plugins' ) && ! current_user_can( 'update_core' ) ) wp_die();
        
        $type = isset($_POST['update_type']) ? sanitize_text_field($_POST['update_type']) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification
        $item = isset($_POST['update_item']) ? sanitize_text_field($_POST['update_item']) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification
        
        include_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
        include_once ABSPATH . 'wp-admin/includes/file.php';
        
        if ( $type === 'plugin' && !empty($item) ) {
            $upgrader = new Plugin_Upgrader( new Automatic_Upgrader_Skin() );
            $result = $upgrader->upgrade( $item );
            if ( is_wp_error( $result ) || ! $result ) {
                wp_send_json_error(array('message' => __('Update failed.', 'metzler-webshield')));
            }
            wp_send_json_success(array('message' => __('Successfully updated.', 'metzler-webshield')));
        } elseif ( $type === 'core' ) {
            $upgrader = new Core_Upgrader( new Automatic_Upgrader_Skin() );
            $core_updates = get_site_transient('update_core');
            if ( isset($core_updates->updates[0]) ) {
                $result = $upgrader->upgrade( $core_updates->updates[0] );
                if ( is_wp_error( $result ) || ! $result ) {
                    wp_send_json_error(array('message' => __('Update failed.', 'metzler-webshield')));
                }
                wp_send_json_success(array('message' => __('Successfully updated.', 'metzler-webshield')));
            }
        }
        
        wp_send_json_error(array('message' => __('Invalid request.', 'metzler-webshield')));
    }

    public function ajax_clear_logs(): void {
        check_ajax_referer( 'metzler_webshield_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_logs'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query("TRUNCATE TABLE $table_name"); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        wp_send_json_success(array('message' => __('Log cleared.', 'metzler-webshield')));
    }

    public function ajax_create_baseline(): void {
        check_ajax_referer( 'metzler_webshield_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        $fim = new Metzler_Webshield_FIM();
        $count = $fim->build_baseline();
        wp_send_json_success(array('message' => "Baseline mit $count Dateien erfolgreich erstellt."));
    }

    public function ajax_cancel_scan(): void {
        check_ajax_referer( 'metzler_webshield_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_queue'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query("TRUNCATE TABLE $table_name"); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        Metzler_Webshield_Logger::log(__("The Smart Scan was aborted by the user.", "metzler-webshield"), "system", "warning");
        wp_send_json_success();
    }

    public function ajax_accept_fim(): void {
        check_ajax_referer( 'metzler_webshield_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        $path = isset($_POST['path']) ? sanitize_text_field($_POST['path']) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification
        if ( ! $path ) wp_send_json_error();
        
        $fim = new Metzler_Webshield_FIM();
        $fim->accept_file($path);
        
        Metzler_Webshield_Logger::resolve_path_logs($path); // Delete old warnings
        Metzler_Webshield_Logger::log(sprintf( __("File marked as safe: %s", "metzler-webshield"), esc_html($path) ), "system", "success");
        
        wp_send_json_success();
    }

    public function ajax_delete_user(): void {
        check_ajax_referer( 'metzler_webshield_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        $user_id = isset($_POST['user_id']) ? intval($_POST['user_id']) : 0;
        
        if ( ! $user_id ) wp_send_json_error();
        
        if ( get_current_user_id() === $user_id ) {
            wp_send_json_error(array('message' => __('You cannot delete yourself!', 'metzler-webshield')));
        }
        
        require_once(ABSPATH.'wp-admin/includes/user.php');
        if ( wp_delete_user($user_id) ) {
            Metzler_Webshield_Logger::log(sprintf(__("Ghost Admin (ID %d) was successfully deleted.", "metzler-webshield"), $user_id), "config", "success");
            wp_send_json_success();
        } else {
            wp_send_json_error(array('message' => __('Could not delete user.', 'metzler-webshield')));
        }
    }

    public function ajax_quarantine_file(): void {
        check_ajax_referer( 'metzler_webshield_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        $path = isset($_POST['path']) ? sanitize_text_field($_POST['path']) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification
        if ( ! $path ) wp_send_json_error();
        
        $quarantine = new Metzler_Webshield_Quarantine();
        $result = $quarantine->quarantine_file($path);
        
        if ( $result ) {
            Metzler_Webshield_Logger::resolve_path_logs($path); // Delete old warnings
            wp_send_json_success();
        } else {
            wp_send_json_error(array('message' => __('Could not move file to quarantine. (Permissions?)', 'metzler-webshield')));
        }
    } 

    public function ajax_quarantine_restore(): void {
        check_ajax_referer( 'metzler_webshield_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        $id = isset($_POST['id']) ? intval($_POST['id']) : 0; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification
        if ( $id > 0 ) {
            $q = new Metzler_Webshield_Quarantine();
            if ( $q->restore_file($id) ) {
                wp_send_json_success();
            }
        }
        wp_send_json_error(array('message' => __('Error during restoration.', 'metzler-webshield')));
    }

    public function ajax_quarantine_delete(): void {
        check_ajax_referer( 'metzler_webshield_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        $id = isset($_POST['id']) ? intval($_POST['id']) : 0; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification
        if ( $id > 0 ) {
            $q = new Metzler_Webshield_Quarantine();
            if ( $q->delete_file($id) ) {
                wp_send_json_success();
            }
        }
        wp_send_json_error(array('message' => __('Error during deletion.', 'metzler-webshield')));
    }

    public function ajax_get_quarantine(): void {
        check_ajax_referer( 'metzler_webshield_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        $q = new Metzler_Webshield_Quarantine();
        wp_send_json_success(array('files' => $q->get_files()));
    }

    public function ajax_save_settings(): void {
        check_ajax_referer( 'metzler_webshield_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        $enable_fim = isset($_POST['enable_fim']) ? sanitize_text_field($_POST['enable_fim']) : '0'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification
        $enable_core = isset($_POST['enable_core']) ? sanitize_text_field($_POST['enable_core']) : '0'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification
        $enable_files = isset($_POST['enable_files']) ? sanitize_text_field($_POST['enable_files']) : '0'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification
        $enable_updates = isset($_POST['enable_updates']) ? sanitize_text_field($_POST['enable_updates']) : '0'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification
        $enable_plugins = isset($_POST['enable_plugins']) ? sanitize_text_field($_POST['enable_plugins']) : '0'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification
        $enable_waf = isset($_POST['enable_waf']) ? sanitize_text_field($_POST['enable_waf']) : '0'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification
        $disable_xmlrpc = isset($_POST['disable_xmlrpc']) ? sanitize_text_field($_POST['disable_xmlrpc']) : '0'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification
        $enable_telemetry = isset($_POST['enable_telemetry']) ? sanitize_text_field($_POST['enable_telemetry']) : '1'; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification
        
        update_option('metzler_webshield_enable_fim', $enable_fim);
        update_option('metzler_webshield_enable_core', $enable_core);
        update_option('metzler_webshield_enable_files', $enable_files);
        update_option('metzler_webshield_enable_updates', $enable_updates);
        update_option('metzler_webshield_enable_plugins', $enable_plugins);
        update_option('metzler_webshield_enable_waf', $enable_waf);
        update_option('metzler_webshield_disable_xmlrpc', $disable_xmlrpc);
        update_option('metzler_webshield_enable_telemetry', $enable_telemetry);
        
        // Handle WAF installation
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/waf/class-metzler-webshield-waf-installer.php';
        if ( $enable_waf === '1' ) {
            Metzler_Webshield_WAF_Installer::enable_waf();
        } else {
            Metzler_Webshield_WAF_Installer::disable_waf();
        }
        
        wp_send_json_success();
    }
    
    public static function cron_start_scan(): void {
        $is_licensed = get_option( 'metzler_webshield_is_licensed' );

        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_queue'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query("TRUNCATE TABLE $table_name"); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        Metzler_Webshield_Logger::cleanup_old_logs();
        
        update_option('metzler_webshield_last_scan_start', current_time('mysql'));
        Metzler_Webshield_Logger::log(__("Automatic background scan (cron) started...", "metzler-webshield"), "system" );

        $tasks = array();
        
        if ( get_option('metzler_webshield_enable_updates', '1') === '1' ) {
            $tasks[] = array('type' => 'scan_updates', 'payload' => json_encode(array('step' => 'init')));
        }
        
        if ( $is_licensed ) {
            if ( get_option('metzler_webshield_enable_plugins', '1') === '1' ) {
                $tasks[] = array('type' => 'scan_plugins', 'payload' => json_encode(array('step' => 'init')));
            }
            if ( get_option('metzler_webshield_enable_core', '1') === '1' ) {
                $tasks[] = array('type' => 'scan_core', 'payload' => json_encode(array('step' => 'init')));
            }
        }
        
        if ( get_option('metzler_webshield_enable_files', '1') === '1' ) {
            $tasks[] = array('type' => 'scan_files', 'payload' => json_encode(array('step' => 'init')));
        }
        
        if ( get_option('metzler_webshield_enable_fim', '1') === '1' ) {
            $tasks[] = array('type' => 'scan_fim', 'payload' => json_encode(array('step' => 'init')));
        }
        
        $tasks[] = array('type' => 'scan_config', 'payload' => json_encode(array('step' => 'init')));

        foreach ($tasks as $task) {
            $wpdb->insert($table_name, array( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery
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
        $table_name = $wpdb->prefix . 'metzler_webshield_queue'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        
        // Give the cron process enough time to complete
        if ( function_exists('set_time_limit') ) {
            @set_time_limit(300); // phpcs:ignore Squiz.PHP.DiscouragedFunctions.Discouraged
        }
        
        $start_time = time();
        $max_execution_time = 240; // 4 minutes
        
        while ( true ) {
            // Check if we are running out of time
            if ( (time() - $start_time) > $max_execution_time ) {
                Metzler_Webshield_Logger::log(__("Cron scan paused (time limit reached). It will resume on the next run.", "metzler-webshield"), "system", "warning");
                break;
            }
            
            $task = $wpdb->get_row("SELECT * FROM $table_name WHERE status = 'pending' ORDER BY id ASC LIMIT 1"); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            if ( ! $task ) {
                Metzler_Webshield_Logger::log(__("Automatic background scan completed successfully.", "metzler-webshield"), "system" );
                break;
            }
            
            $result = array();
            switch ($task->task_type) {
                case 'scan_updates':
                    $scanner = new Metzler_Webshield_Scanner_Updates();
                    $result = $scanner->run_step( json_decode($task->payload, true) );
                    break;
                case 'scan_core':
                    $scanner = new Metzler_Webshield_Scanner_Core();
                    $result = $scanner->run_step( json_decode($task->payload, true) );
                    break;
                case 'scan_plugins':
                    $scanner = new Metzler_Webshield_Scanner_Plugins();
                    $result = $scanner->run_step( json_decode($task->payload, true) );
                    break;
                case 'scan_files':
                    $scanner = new Metzler_Webshield_Scanner_Files();
                    $result = $scanner->run_step( json_decode($task->payload, true) );
                    break;
                case 'scan_fim':
                    $scanner = new Metzler_Webshield_Scanner_FIM();
                    $result = $scanner->run_step( json_decode($task->payload, true) );
                    break;
                case 'scan_config':
                    $scanner = new Metzler_Webshield_Scanner_Config();
                    $result = $scanner->run_step( json_decode($task->payload, true) );
                    break;
            }

            if ( isset($result['complete']) && $result['complete'] ) {
                $wpdb->update($table_name, array('status' => 'completed'), array('id' => $task->id)); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery
            } else {
                if ( isset($result['next_payload']) ) {
                    $wpdb->update($table_name, array('payload' => json_encode($result['next_payload'])), array('id' => $task->id)); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery
                }
            }
        }
    }
}
