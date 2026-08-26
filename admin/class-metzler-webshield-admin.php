<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class Metzler_Webshield_Admin {
    public function init() {
        add_action( 'admin_menu', array( $this, 'add_plugin_admin_menu' ) );
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_styles_scripts' ) );

        add_action( 'wp_ajax_metzler_webshield_request_license', array( $this, 'ajax_request_license' ) );
        add_action( 'wp_ajax_metzler_webshield_verify_license', array( $this, 'ajax_verify_license' ) );
        add_action( 'wp_ajax_metzler_webshield_recheck_license', array( $this, 'ajax_recheck_license' ) );
        add_action( 'wp_ajax_metzler_webshield_remove_license', array( $this, 'ajax_remove_license' ) );
    }

    public function add_plugin_admin_menu() {
        add_menu_page(
            'Metzler Webshield Dashboard', 
            'Metzler Webshield', 
            'manage_options', 
            'metzler-webshield', 
            array( $this, 'display_plugin_setup_page' ),
            'dashicons-shield', 
            3
        );
    }

    public function enqueue_styles_scripts( $hook ) {
        if ( 'toplevel_page_metzler-webshield' !== $hook ) return;
        wp_enqueue_style( 'metzler-webshield-admin', METZLER_WEBSHIELD_PLUGIN_URL . 'assets/css/admin.css', array(), METZLER_WEBSHIELD_VERSION );
        wp_enqueue_script( 'metzler-webshield-admin', METZLER_WEBSHIELD_PLUGIN_URL . 'assets/js/admin.js', array( 'jquery' ), METZLER_WEBSHIELD_VERSION, true );
        wp_localize_script( 'metzler-webshield-admin', 'metzler_webshield_ajax', array(
            'ajax_url'    => admin_url( 'admin-ajax.php' ),
            'nonce'       => wp_create_nonce( 'metzler_webshield_nonce' ),
            'is_licensed' => get_option( 'metzler_webshield_is_licensed', false ),
            'i18n'        => array(
                'please_license'     => __('Please add your license key in the "License" tab first to unlock this feature.', 'metzler-webshield'),
                'requesting'         => __('Requesting...', 'metzler-webshield'),
                'request_key'        => __('Request Key', 'metzler-webshield'),
                'enter_email'        => __('Please enter an email.', 'metzler-webshield'),
                'enter_key'          => __('Please enter a key.', 'metzler-webshield'),
                'verifying'          => __('Verifying...', 'metzler-webshield'),
                'verify_license'     => __('Verify License', 'metzler-webshield'),
                'rechecking'         => __('Checking...', 'metzler-webshield'),
                'license_valid'      => __('License is valid!', 'metzler-webshield'),
                'recheck_now'        => __('Recheck license now', 'metzler-webshield'),
                'delete_confirm'     => __('Are you sure you want to permanently delete this user?', 'metzler-webshield'),
                'deleting'           => __('Deleting...', 'metzler-webshield'),
                'deleted_ghost'      => __('Ghost Admin deleted!', 'metzler-webshield'),
                'delete_error'       => __('Error deleting user.', 'metzler-webshield'),
                'delete_user'        => __('Delete user', 'metzler-webshield'),
                'license_invalid'    => __('License is invalid or expired. Cloud features will be locked now.', 'metzler-webshield'),
                'confirm_remove'     => __('Do you really want to remove this license? Cloud features like Smart Scan and WAF Rule Sync will be deactivated.', 'metzler-webshield'),
                'marked_safe'        => __('Marked as safe.', 'metzler-webshield'),
                'moving'             => __('Moving...', 'metzler-webshield'),
                'moved_quarantine'   => __('Moved to quarantine.', 'metzler-webshield'),
                'move_error'         => __('Error moving file.', 'metzler-webshield'),
                'move_to_quarantine' => __('Move to quarantine', 'metzler-webshield'),
                'quarantine_empty'   => __('The quarantine is empty.', 'metzler-webshield'),
                'restoring'          => __('Restoring...', 'metzler-webshield'),
                'file_restored'      => __('File was restored.', 'metzler-webshield'),
                'confirm_delete'     => __('Should this file really be permanently deleted from the server? This cannot be undone.', 'metzler-webshield'),
                'restore'            => __('Restore', 'metzler-webshield'),
                'delete_permanent'   => __('Delete permanently', 'metzler-webshield'),
                'reading_files'      => __('Reading files, please wait...', 'metzler-webshield'),
                'success'            => __('Success! ', 'metzler-webshield'),
                'read_error'         => __('Error reading files.', 'metzler-webshield'),
                'request_error'      => __('Error during request.', 'metzler-webshield'),
                'invalid_key'        => __('Invalid key.', 'metzler-webshield'),
                // New UI states
                'hero_secure'        => __('Your website is secure.', 'metzler-webshield'),
                'hero_local_secure'  => __('Basic protection active.', 'metzler-webshield'),
                'hero_guards_active' => __('All background guards are active and up to date.', 'metzler-webshield'),
                'hero_local_desc'    => __('Activate a free license to unlock Smart Scan & Cloud Features.', 'metzler-webshield'),
                'hero_risks'         => __('Security risks detected!', 'metzler-webshield'),
                'hero_risks_scan'    => __('Smart Scan is still running, but issues have already been detected.', 'metzler-webshield'),
                'hero_check_log'     => __('Please check the security log.', 'metzler-webshield'),
                'hero_issues_fixed'  => __('All issues have been resolved.', 'metzler-webshield'),
                'hero_scan_running'  => __('Smart Scan running...', 'metzler-webshield'),
                'hero_scan_desc'     => __('Analyzing files and databases...', 'metzler-webshield'),
                'hero_scan_aborted'  => __('Scan aborted', 'metzler-webshield'),
                'hero_aborted_desc'  => __('The Smart Scan was manually aborted.', 'metzler-webshield'),
                'hero_issues_found'  => __('Issues have been detected. Please check the log below.', 'metzler-webshield'),
                'hero_no_threats'    => __('The Smart Scan found no threats.', 'metzler-webshield'),
                'hero_log_cleared'   => __('The log has been cleared.', 'metzler-webshield'),
                'init_scan'          => __('Initializing Smart Scan...', 'metzler-webshield'),
                'confirm_cancel_scan'=> __('Do you really want to cancel the current scan?', 'metzler-webshield'),
                'confirm_clear_log'  => __('Do you really want to clear the entire security log?', 'metzler-webshield'),
            )
        ));
    }

    public function display_plugin_setup_page() {
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'admin/views/view-dashboard.php';
    }

    public function ajax_request_license() {
        check_ajax_referer( 'metzler_webshield_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        
        $email = sanitize_email( sanitize_email(wp_unslash($_POST['email'] ?? '')) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification
        if ( ! is_email( $email ) ) {
            wp_send_json_error( array( 'message' => __( 'Invalid email address.', 'metzler-webshield' ) ) );
        }

        $domain = wp_parse_url( home_url(), PHP_URL_HOST );
        $api_url = defined( 'METZLER_WEBSHIELD_API_URL' ) ? METZLER_WEBSHIELD_API_URL : 'https://api.metzler-webshield.de/api';

        $response = wp_remote_post( $api_url . '/license/request', array(
            'body' => array(
                'email'  => $email,
                'domain' => $domain
            )
        ) );

        if ( is_wp_error( $response ) ) {
            wp_send_json_error( array( 'message' => __( 'API connection error:', 'metzler-webshield' ) . ' ' . $response->get_error_message() ) );
        }

        $body = wp_remote_retrieve_body( $response );
        $data = json_decode( $body, true );

        if ( isset( $data['success'] ) && $data['success'] ) {
            wp_send_json_success( array( 'message' => __( 'License key requested!', 'metzler-webshield' ) ) );
        } else {
            wp_send_json_error( array( 'message' => __( 'Error:', 'metzler-webshield' ) . ' ' . ( $data['message'] ?? __( 'Unknown', 'metzler-webshield' ) ) ) );
        }
    }

    public function ajax_verify_license() {
        check_ajax_referer( 'metzler_webshield_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        
        $token = sanitize_text_field( sanitize_text_field(wp_unslash($_POST['token'] ?? '')) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification
        $email = sanitize_email( sanitize_email(wp_unslash($_POST['email'] ?? '')) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification
        $domain = wp_parse_url( home_url(), PHP_URL_HOST );
        
        $api_url = defined( 'METZLER_WEBSHIELD_API_URL' ) ? METZLER_WEBSHIELD_API_URL : 'https://api.metzler-webshield.de/api';

        $response = wp_remote_post( $api_url . '/license/verify', array(
            'body' => array(
                'token'  => $token,
                'domain' => $domain
            )
        ) );

        if ( is_wp_error( $response ) ) {
            wp_send_json_error( array( 'message' => __( 'API connection error:', 'metzler-webshield' ) . ' ' . $response->get_error_message() ) );
        }

        $body = wp_remote_retrieve_body( $response );
        $data = json_decode( $body, true );

        if ( isset( $data['success'] ) && $data['success'] ) {
            update_option( 'metzler_webshield_license_token', $token );
            update_option( 'metzler_webshield_verified_email', $email );
            update_option( 'metzler_webshield_is_licensed', true );
            
            // Auto-enable telemetry when user opts into the Cloud License
            update_option( 'metzler_webshield_enable_telemetry', '1' );
            
            // Save token to file for high-speed WAF access without DB overhead
            $upload_dir = WP_CONTENT_DIR . '/uploads/metzler-webshield';
            if ( ! is_dir($upload_dir) ) {
                @mkdir($upload_dir, 0755, true); // phpcs:ignore
                @file_put_contents($upload_dir . '/index.php', "<?php // Silence is golden."); // phpcs:ignore
            }
            @file_put_contents($upload_dir . '/waf.key', $token, LOCK_EX); // phpcs:ignore

            wp_send_json_success( array( 'message' => __( 'License verified!', 'metzler-webshield' ) ) );
        } else {
            wp_send_json_error( array( 'message' => __( 'Invalid license key.', 'metzler-webshield' ) ) );
        }
    }

    public function ajax_recheck_license() {
        check_ajax_referer( 'metzler_webshield_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        
        $token = get_option( 'metzler_webshield_license_token' );
        $domain = wp_parse_url( home_url(), PHP_URL_HOST );
        $api_url = defined( 'METZLER_WEBSHIELD_API_URL' ) ? METZLER_WEBSHIELD_API_URL : 'https://api.metzler-webshield.de/api';

        $response = wp_remote_post( $api_url . '/license/verify', array(
            'body' => array(
                'token'  => $token,
                'domain' => $domain
            )
        ) );

        if ( is_wp_error( $response ) ) {
            wp_send_json_error();
        }

        $body = wp_remote_retrieve_body( $response );
        $data = json_decode( $body, true );

        if ( isset( $data['success'] ) && $data['success'] ) {
            wp_send_json_success();
        } else {
            update_option( 'metzler_webshield_is_licensed', false );
            update_option( 'metzler_webshield_enable_telemetry', '0' );
            wp_send_json_error();
        }
    }

    public function ajax_remove_license() {
        check_ajax_referer( 'metzler_webshield_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        
        update_option( 'metzler_webshield_is_licensed', false );
        update_option( 'metzler_webshield_enable_telemetry', '0' );
        delete_option( 'metzler_webshield_license_token' );
        delete_option( 'metzler_webshield_verified_email' );
        
        @unlink(WP_CONTENT_DIR . '/uploads/metzler-webshield/waf.key'); // phpcs:ignore
        @unlink(WP_CONTENT_DIR . '/uploads/metzler-webshield/waf-rules.enc'); // phpcs:ignore

        wp_send_json_success( array( 'message' => __( 'License removed.', 'metzler-webshield' ) ) );
    }
}
