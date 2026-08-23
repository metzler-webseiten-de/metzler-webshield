<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class WPProtector_Admin {
    public function init() {
        add_action( 'admin_menu', array( $this, 'add_plugin_admin_menu' ) );
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_styles_scripts' ) );

        add_action( 'wp_ajax_wpprotector_request_license', array( $this, 'ajax_request_license' ) );
        add_action( 'wp_ajax_wpprotector_verify_license', array( $this, 'ajax_verify_license' ) );
        add_action( 'wp_ajax_wpprotector_recheck_license', array( $this, 'ajax_recheck_license' ) );
        add_action( 'wp_ajax_wpprotector_remove_license', array( $this, 'ajax_remove_license' ) );
    }

    public function add_plugin_admin_menu() {
        add_menu_page(
            'WPProtector Dashboard', 
            'WPProtector', 
            'manage_options', 
            'wpprotector', 
            array( $this, 'display_plugin_setup_page' ),
            'dashicons-shield', 
            3
        );
    }

    public function enqueue_styles_scripts( $hook ) {
        if ( 'toplevel_page_wpprotector' !== $hook ) return;
        wp_enqueue_style( 'wpprotector-admin', WPPROTECTOR_PLUGIN_URL . 'assets/css/admin.css', array(), WPPROTECTOR_VERSION );
        wp_enqueue_script( 'wpprotector-admin', WPPROTECTOR_PLUGIN_URL . 'assets/js/admin.js', array( 'jquery' ), WPPROTECTOR_VERSION, true );
        wp_localize_script( 'wpprotector-admin', 'wpprotector_ajax', array(
            'ajax_url'    => admin_url( 'admin-ajax.php' ),
            'nonce'       => wp_create_nonce( 'wpprotector_nonce' ),
            'is_licensed' => get_option( 'wpprotector_is_licensed', false ),
            'i18n'        => array(
                'please_license'     => __('Please add your license key in the "License" tab first to unlock this feature.', 'wpprotector'),
                'requesting'         => __('Requesting...', 'wpprotector'),
                'request_key'        => __('Request Key', 'wpprotector'),
                'enter_email'        => __('Please enter an email.', 'wpprotector'),
                'enter_key'          => __('Please enter a key.', 'wpprotector'),
                'verifying'          => __('Verifying...', 'wpprotector'),
                'verify_license'     => __('Verify License', 'wpprotector'),
                'rechecking'         => __('Checking...', 'wpprotector'),
                'license_valid'      => __('License is valid!', 'wpprotector'),
                'recheck_now'        => __('Recheck license now', 'wpprotector'),
                'license_invalid'    => __('License is invalid or expired. The plugin will be locked now.', 'wpprotector'),
                'confirm_remove'     => __('Do you really want to remove this license? The firewall and scanner will be deactivated.', 'wpprotector'),
                'marked_safe'        => __('Marked as safe.', 'wpprotector'),
                'moving'             => __('Moving...', 'wpprotector'),
                'moved_quarantine'   => __('Moved to quarantine.', 'wpprotector'),
                'move_error'         => __('Error moving file.', 'wpprotector'),
                'move_to_quarantine' => __('Move to quarantine', 'wpprotector'),
                'quarantine_empty'   => __('The quarantine is empty.', 'wpprotector'),
                'restoring'          => __('Restoring...', 'wpprotector'),
                'file_restored'      => __('File was restored.', 'wpprotector'),
                'confirm_delete'     => __('Should this file really be permanently deleted from the server? This cannot be undone.', 'wpprotector'),
                'restore'            => __('Restore', 'wpprotector'),
                'delete_permanent'   => __('Delete permanently', 'wpprotector'),
                'reading_files'      => __('Reading files, please wait...', 'wpprotector'),
                'success'            => __('Success! ', 'wpprotector'),
                'read_error'         => __('Error reading files.', 'wpprotector'),
                'request_error'      => __('Error during request.', 'wpprotector'),
                'invalid_key'        => __('Invalid key.', 'wpprotector'),
            )
        ));
    }

    public function display_plugin_setup_page() {
        require_once WPPROTECTOR_PLUGIN_DIR . 'admin/views/view-dashboard.php';
    }

    public function ajax_request_license() {
        check_ajax_referer( 'wpprotector_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        
        $email = sanitize_email( $_POST['email'] );
        if ( ! is_email( $email ) ) {
            wp_send_json_error( array( 'message' => __( 'Invalid email address.', 'wpprotector' ) ) );
        }

        $domain = parse_url( home_url(), PHP_URL_HOST );
        $api_url = defined( 'WPPROTECTOR_API_URL' ) ? WPPROTECTOR_API_URL : 'https://api.wp-protector.de/api';

        $response = wp_remote_post( $api_url . '/license/request', array(
            'body' => array(
                'email'  => $email,
                'domain' => $domain
            )
        ) );

        if ( is_wp_error( $response ) ) {
            wp_send_json_error( array( 'message' => __( 'API connection error:', 'wpprotector' ) . ' ' . $response->get_error_message() ) );
        }

        $body = wp_remote_retrieve_body( $response );
        $data = json_decode( $body, true );

        if ( isset( $data['success'] ) && $data['success'] ) {
            wp_send_json_success( array( 'message' => __( 'License key requested!', 'wpprotector' ) ) );
        } else {
            wp_send_json_error( array( 'message' => __( 'Error:', 'wpprotector' ) . ' ' . ( $data['message'] ?? __( 'Unknown', 'wpprotector' ) ) ) );
        }
    }

    public function ajax_verify_license() {
        check_ajax_referer( 'wpprotector_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        
        $token = sanitize_text_field( $_POST['token'] );
        $email = sanitize_email( $_POST['email'] );
        $domain = parse_url( home_url(), PHP_URL_HOST );
        
        $api_url = defined( 'WPPROTECTOR_API_URL' ) ? WPPROTECTOR_API_URL : 'https://api.wp-protector.de/api';

        $response = wp_remote_post( $api_url . '/license/verify', array(
            'body' => array(
                'token'  => $token,
                'domain' => $domain
            )
        ) );

        if ( is_wp_error( $response ) ) {
            wp_send_json_error( array( 'message' => __( 'API connection error:', 'wpprotector' ) . ' ' . $response->get_error_message() ) );
        }

        $body = wp_remote_retrieve_body( $response );
        $data = json_decode( $body, true );

        if ( isset( $data['success'] ) && $data['success'] ) {
            update_option( 'wpprotector_license_token', $token );
            update_option( 'wpprotector_verified_email', $email );
            update_option( 'wpprotector_is_licensed', true );
            
            // Save token to file for high-speed WAF access without DB overhead
            $upload_dir = WP_CONTENT_DIR . '/uploads/wpprotector';
            if ( ! is_dir($upload_dir) ) {
                @mkdir($upload_dir, 0755, true);
                @file_put_contents($upload_dir . '/index.php', "<?php // Silence is golden.");
            }
            @file_put_contents($upload_dir . '/waf.key', $token, LOCK_EX);

            wp_send_json_success( array( 'message' => __( 'License verified!', 'wpprotector' ) ) );
        } else {
            wp_send_json_error( array( 'message' => __( 'Invalid license key.', 'wpprotector' ) ) );
        }
    }

    public function ajax_recheck_license() {
        check_ajax_referer( 'wpprotector_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        
        $token = get_option( 'wpprotector_license_token' );
        $domain = parse_url( home_url(), PHP_URL_HOST );
        $api_url = defined( 'WPPROTECTOR_API_URL' ) ? WPPROTECTOR_API_URL : 'https://api.wp-protector.de/api';

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
            update_option( 'wpprotector_is_licensed', false );
            wp_send_json_error();
        }
    }

    public function ajax_remove_license() {
        check_ajax_referer( 'wpprotector_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        
        update_option( 'wpprotector_is_licensed', false );
        delete_option( 'wpprotector_license_token' );
        delete_option( 'wpprotector_verified_email' );
        
        @unlink(WP_CONTENT_DIR . '/uploads/wpprotector/waf.key');
        @unlink(WP_CONTENT_DIR . '/uploads/wpprotector/waf-rules.enc');

        wp_send_json_success( array( 'message' => __( 'License removed.', 'wpprotector' ) ) );
    }
}
