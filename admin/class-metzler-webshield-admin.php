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
        add_action( 'wp_ajax_metzler_webshield_extended_protection', array( $this, 'ajax_extended_protection' ) );

        // 1. Frontpage Dashboard Widget on wp-admin/index.php
        add_action( 'wp_dashboard_setup', array( $this, 'register_dashboard_widget' ) );

        // 2. Global Persistent Admin Notice when threats are detected
        add_action( 'admin_notices', array( $this, 'render_threat_admin_notice' ) );
        add_action( 'wp_ajax_metzler_webshield_dismiss_threat_notice', array( $this, 'ajax_dismiss_threat_notice' ) );

        // 3. Admin sidebar menu icon sizing
        add_action( 'admin_head', array( $this, 'enqueue_admin_menu_styles' ) );

        // 4. Notice for Pro subscribers without the Pro add-on
        add_action( 'admin_notices', array( $this, 'render_pro_addon_notice' ) );
        add_action( 'wp_ajax_metzler_webshield_dismiss_pro_notice', array( $this, 'ajax_dismiss_pro_notice' ) );
    }

    /**
     * Status texts shown in the hero section and widgets. Add-ons may adjust them.
     */
    public static function ui_texts(): array {
        return (array) apply_filters( 'metzler_webshield_ui_texts', array(
            'hero_secure'        => __( 'Your website is protected.', 'metzler-webshield' ),
            'hero_guards_active' => __( 'Firewall, rate limiter and background scanners are active.', 'metzler-webshield' ),
            'tier_label'         => __( 'Free', 'metzler-webshield' ),
        ) );
    }

    /**
     * Whether an add-on reports an active premium subscription (only used to hide the upgrade banner).
     */
    public static function is_pro(): bool {
        return (bool) apply_filters( 'metzler_webshield_is_pro', false );
    }

    public function enqueue_admin_menu_styles(): void {
        ?>
        <style>
            #adminmenu .toplevel_page_metzler-webshield .wp-menu-image img {
                width: 20px !important;
                height: 20px !important;
                max-width: 20px !important;
                max-height: 20px !important;
                padding: 7px 0 0 0 !important;
                border-radius: 3px;
            }
        </style>
        <?php
    }

    public function add_plugin_admin_menu() {
        add_menu_page(
            'Metzler Webshield Dashboard', 
            'Metzler Webshield', 
            'manage_options', 
            'metzler-webshield', 
            array( $this, 'display_plugin_setup_page' ),
            plugins_url( 'assets/images/logo-icon-20.png', METZLER_WEBSHIELD_PLUGIN_FILE ), 
            80
        );
    }

    public function enqueue_styles_scripts( $hook ) {
        if ( 'toplevel_page_metzler-webshield' !== $hook ) return;
        wp_enqueue_style( 'metzler-webshield-admin', METZLER_WEBSHIELD_PLUGIN_URL . 'assets/css/admin.css', array(), METZLER_WEBSHIELD_VERSION );
        wp_enqueue_script( 'metzler-webshield-chartjs', METZLER_WEBSHIELD_PLUGIN_URL . 'assets/js/chart.min.js', array(), METZLER_WEBSHIELD_VERSION, true );
        wp_enqueue_script( 'metzler-webshield-admin', METZLER_WEBSHIELD_PLUGIN_URL . 'assets/js/admin.js', array( 'jquery', 'metzler-webshield-chartjs' ), METZLER_WEBSHIELD_VERSION, true );
        // Hero texts must match the server-rendered ones in view-dashboard.php
        $ui_texts = self::ui_texts();
        wp_localize_script( 'metzler-webshield-admin', 'metzler_webshield_ajax', array(
            'ajax_url'    => admin_url( 'admin-ajax.php' ),
            'nonce'       => wp_create_nonce( 'metzler_webshield_nonce' ),
            'i18n'        => array(
                'requesting'         => __('Requesting...', 'metzler-webshield'),
                'request_key'        => __('Request Key', 'metzler-webshield'),
                'enter_email'        => __('Please enter an email.', 'metzler-webshield'),
                'enter_key'          => __('Please enter a key.', 'metzler-webshield'),
                'verifying'          => __('Verifying...', 'metzler-webshield'),
                'verify_license'     => __('Connect', 'metzler-webshield'),
                'rechecking'         => __('Checking...', 'metzler-webshield'),
                'license_valid'      => __('Connection is valid!', 'metzler-webshield'),
                'recheck_now'        => __('Recheck connection now', 'metzler-webshield'),
                'delete_confirm'     => __('Are you sure you want to permanently delete this user?', 'metzler-webshield'),
                'deleting'           => __('Deleting...', 'metzler-webshield'),
                'deleted_ghost'      => __('User deleted!', 'metzler-webshield'),
                'delete_error'       => __('Error deleting user.', 'metzler-webshield'),
                'delete_user'        => __('Delete user', 'metzler-webshield'),
                'license_invalid'    => __('The key is invalid or expired. The cloud connection was disabled.', 'metzler-webshield'),
                'confirm_remove'     => __('Do you really want to disconnect this site from the Threat Intelligence Cloud? Cloud firewall rules will be removed and telemetry sharing turned off.', 'metzler-webshield'),
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
                'hero_secure'        => $ui_texts['hero_secure'],
                'hero_guards_active' => $ui_texts['hero_guards_active'],
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
                /* translators: %d: number of remaining logs */
                'more_logs'          => __('... and %d more (see log).', 'metzler-webshield'),
                'log_empty'          => __('The log is empty.', 'metzler-webshield'),
                'updating'           => __('Updating...', 'metzler-webshield'),
                'update_success'     => __('✔ Successfully updated', 'metzler-webshield'),
                'update_error'       => __('Error during update', 'metzler-webshield'),
                'generic_error'      => __('An error occurred.', 'metzler-webshield'),
                'scan_aborted_msg'   => __('Scan aborted: ', 'metzler-webshield'),
                'confirm_disable_extended' => __('Turn off extended protection? The firewall then only inspects requests that load WordPress.', 'metzler-webshield'),
                'connection_error'   => __('Connection problem. Retrying...', 'metzler-webshield'),
                'creating_baseline'  => __('Creating baseline...', 'metzler-webshield'),
                'set_fim_baseline'   => __('Set FIM Baseline', 'metzler-webshield'),
                'saving'             => __('Saving...', 'metzler-webshield'),
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
            wp_send_json_success( array( 'message' => __( 'Key requested! Please check your inbox.', 'metzler-webshield' ) ) );
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
            $tier = sanitize_text_field( $data['tier'] ?? 'free' );
            $verified_email = ! empty( $data['email'] ) ? sanitize_email( $data['email'] ) : $email;

            update_option( 'metzler_webshield_license_token', $token );
            update_option( 'metzler_webshield_verified_email', $verified_email );
            update_option( 'metzler_webshield_license_tier', $tier );
            update_option( 'metzler_webshield_is_licensed', true );
            delete_option( 'metzler_webshield_pro_expired' );

            $telemetry_opt_in = sanitize_text_field(wp_unslash($_POST['telemetry'] ?? '0')) === '1' ? '1' : '0'; // phpcs:ignore WordPress.Security.NonceVerification
            update_option( 'metzler_webshield_enable_telemetry', $telemetry_opt_in );
            do_action( 'metzler_webshield_license_verified', $token, $tier );

            wp_send_json_success( array(
                'tier'    => $tier,
                'message' => __( 'Key verified. This site is now connected.', 'metzler-webshield' ),
            ) );
        } else {
            wp_send_json_error( array( 'message' => __( 'Invalid key.', 'metzler-webshield' ) ) );
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

        if ( Metzler_Webshield::license_rejected( $response ) ) {
            update_option( 'metzler_webshield_is_licensed', false );
            update_option( 'metzler_webshield_enable_telemetry', '0' );
            wp_send_json_error( array( 'message' => __( 'Key verification failed.', 'metzler-webshield' ) ) );
        }

        $data = is_wp_error( $response ) ? null : json_decode( wp_remote_retrieve_body( $response ), true );
        if ( empty( $data['success'] ) ) {
            // Outage or network error: keep the connection, nothing is known about the key
            wp_send_json_error( array(
                'kept'    => true,
                'message' => __( 'The Threat Intelligence Cloud is not reachable right now. The connection is kept; please try again later.', 'metzler-webshield' ),
            ) );
        }

        $tier = sanitize_text_field( $data['tier'] ?? 'free' );
        update_option( 'metzler_webshield_license_tier', $tier );
        if ( ! empty( $data['email'] ) ) {
            update_option( 'metzler_webshield_verified_email', sanitize_email( $data['email'] ) );
        }
        update_option( 'metzler_webshield_is_licensed', true );

        // Fetch the current cloud rules right away instead of waiting for the hourly sync
        Metzler_Webshield_Cloud_Rules::sync();

        wp_send_json_success( array(
            'tier'    => $tier,
            'message' => __( 'Connection status updated.', 'metzler-webshield' ),
        ) );
    }

    public function ajax_remove_license() {
        check_ajax_referer( 'metzler_webshield_nonce', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();
        
        update_option( 'metzler_webshield_is_licensed', false );
        update_option( 'metzler_webshield_enable_telemetry', '0' );
        delete_option( 'metzler_webshield_license_token' );
        delete_option( 'metzler_webshield_verified_email' );
        delete_option( 'metzler_webshield_license_tier' );
        delete_option( 'metzler_webshield_pro_expired' );
        
        Metzler_Webshield_Storage::delete_waf_key(); // legacy (<= 1.x)
        do_action( 'metzler_webshield_license_removed' );

        wp_send_json_success( array( 'message' => __( 'Site disconnected.', 'metzler-webshield' ) ) );
    }

    /**
     * Turns the firewall before WordPress (auto_prepend_file) on or off.
     */
    public function ajax_extended_protection() {
        check_ajax_referer( 'metzler_webshield_nonce' );
        if ( ! current_user_can( 'manage_options' ) ) wp_die();

        if ( sanitize_text_field( wp_unslash( $_POST['enable'] ?? '0' ) ) === '1' ) {
            $result = Metzler_Webshield_Firewall_Setup::enable();
            if ( is_wp_error( $result ) ) {
                wp_send_json_error( array( 'message' => $result->get_error_message() ) );
            }
            Metzler_Webshield_Logger::log( __( 'Extended protection enabled: the firewall now runs before WordPress.', 'metzler-webshield' ), 'system', 'success' );
        } else {
            Metzler_Webshield_Firewall_Setup::disable();
            Metzler_Webshield_Logger::log( __( 'Extended protection disabled.', 'metzler-webshield' ), 'system', 'warning' );
        }

        wp_send_json_success();
    }

    /**
     * Register WordPress Frontpage Dashboard Widgets (wp-admin/index.php).
     */
    public function register_dashboard_widget(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        wp_add_dashboard_widget(
            'metzler_webshield_dashboard_widget',
            __( 'Metzler Webshield — Security Status', 'metzler-webshield' ),
            array( $this, 'render_dashboard_widget' )
        );

        wp_add_dashboard_widget(
            'metzler_webshield_bots_widget',
            __( 'Metzler Webshield — Blocked Bots (24h)', 'metzler-webshield' ),
            array( $this, 'render_bots_widget' )
        );
    }

    /**
     * Render the WordPress Frontpage Dashboard Widget.
     */
    public function render_dashboard_widget(): void {
        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/log/class-metzler-webshield-logger.php';

        $threats = Metzler_Webshield_Logger::get_active_threats( 5 );
        $threat_count = Metzler_Webshield_Logger::count_active_threats();
        $ui_texts = self::ui_texts();
        $last_scan = get_option( 'metzler_webshield_last_scan' );
        $last_scan_text = $last_scan ? date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), strtotime( $last_scan ) ) : esc_html__( 'Never', 'metzler-webshield' );
        $settings_url = admin_url( 'admin.php?page=metzler-webshield' );

        if ( $threat_count > 0 ) :
            ?>
            <div class="mws-dash-widget-alert" style="padding: 4px 0;">
                <div style="display: flex; align-items: flex-start; gap: 12px; margin-bottom: 12px;">
                    <span class="dashicons dashicons-warning" style="color: #d63638; font-size: 28px; width: 28px; height: 28px; margin-top: 2px;"></span>
                    <div>
                        <h4 style="margin: 0 0 4px; font-size: 14px; font-weight: 600; color: #b32d2e;">
                            <?php
                            /* translators: %d: number of detected security risks */
                            printf( esc_html( _n( '%d Security Risk Detected!', '%d Security Risks Detected!', $threat_count, 'metzler-webshield' ) ), (int) $threat_count );
                            ?>
                        </h4>
                        <p style="margin: 0; color: #646970; font-size: 13px;">
                            <?php esc_html_e( 'The automated scanner detected suspicious or modified files on your server.', 'metzler-webshield' ); ?>
                        </p>
                    </div>
                </div>

                <div style="background: #fcf0f1; border-left: 4px solid #d63638; padding: 8px 12px; margin-bottom: 14px; border-radius: 2px;">
                    <ul style="margin: 0; padding-left: 16px; font-size: 12px; color: #50575e; list-style: disc;">
                        <?php foreach ( $threats as $threat ) : ?>
                            <li style="margin-bottom: 4px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                                <strong>[<?php echo esc_html( strtoupper( $threat->type ) ); ?>]</strong> <?php echo esc_html( $threat->message ); ?>
                            </li>
                        <?php endforeach; ?>
                        <?php if ( $threat_count > count( $threats ) ) : ?>
                            <li style="color: #646970; margin-top: 4px;">
                                <em><?php
                                /* translators: %d: number of further detected issues */
                                printf( esc_html__( '+%d additional detected issues...', 'metzler-webshield' ), (int) ( $threat_count - count( $threats ) ) );
                                ?></em>
                            </li>
                        <?php endif; ?>
                    </ul>
                </div>

                <div style="display: flex; justify-content: space-between; align-items: center; pt-2;">
                    <span style="font-size: 12px; color: #646970;">
                        <?php
                        /* translators: %s: date and time of the last scan */
                        printf( esc_html__( 'Last Scan: %s', 'metzler-webshield' ), esc_html( $last_scan_text ) );
                        ?>
                    </span>
                    <a href="<?php echo esc_url( $settings_url ); ?>" class="button button-primary button-small">
                        <?php esc_html_e( 'Review & Resolve in Webshield', 'metzler-webshield' ); ?> &rarr;
                    </a>
                </div>
            </div>
            <?php
        else :
            ?>
            <div class="mws-dash-widget-clean" style="padding: 4px 0;">
                <div style="display: flex; align-items: flex-start; gap: 12px; margin-bottom: 12px;">
                    <img src="<?php echo esc_url( METZLER_WEBSHIELD_PLUGIN_URL . 'assets/images/logo-icon-128.png' ); ?>" alt="Metzler Webshield" style="width: 32px; height: 32px; border-radius: 7px; box-shadow: 0 1px 4px rgba(0,0,0,0.1); margin-top: 2px; flex-shrink: 0;">
                    <div>
                        <h4 style="margin: 0 0 4px; font-size: 14px; font-weight: 600; color: #1d2327;">
                            <?php esc_html_e( 'Website Protected — No Threats Detected', 'metzler-webshield' ); ?>
                        </h4>
                        <p style="margin: 0; color: #646970; font-size: 13px;">
                            <?php esc_html_e( 'All file integrity monitors and background guards are active. Bot attacks are neutralized automatically.', 'metzler-webshield' ); ?>
                        </p>
                    </div>
                </div>

                <div style="display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 14px; padding: 8px 12px; background: #f6f7f7; border-radius: 4px; font-size: 12px; color: #50575e;">
                    <span><strong><?php esc_html_e( 'Tier:', 'metzler-webshield' ); ?></strong> <span style="<?php echo self::is_pro() ? 'color:#008a20; font-weight:600;' : ''; ?>"><?php echo esc_html( $ui_texts['tier_label'] ); ?></span></span>
                    <span><strong><?php esc_html_e( 'Last Scan:', 'metzler-webshield' ); ?></strong> <?php echo esc_html( $last_scan_text ); ?></span>
                </div>

                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <a href="<?php echo esc_url( $settings_url ); ?>" class="button button-secondary button-small">
                        <?php esc_html_e( 'Open Metzler Webshield', 'metzler-webshield' ); ?> &rarr;
                    </a>
                </div>
            </div>
            <?php
        endif;
    }

    /**
     * Render the Blocked Bots (24h) Dashboard Widget.
     */
    public function render_bots_widget(): void {
        // Auto-flush pending telemetry buffer so counts are up-to-date
        if ( Metzler_Webshield_Storage::has_pending_telemetry() ) {
            if ( class_exists( 'Metzler_Webshield' ) ) {
                $shield = new Metzler_Webshield();
                $shield->cron_sync_telemetry();
            }
        }

        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/log/class-metzler-webshield-logger.php';
        $stats = Metzler_Webshield_Logger::get_24h_waf_stats();
        $total = $stats['total'];
        $categories = $stats['categories'];
        $recent_events = $stats['recent_events'];
        $logs_url = admin_url( 'admin.php?page=metzler-webshield#tab-logs' );
        ?>
        <div class="mws-dash-bots-widget" style="padding: 4px 0;">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 12px; padding-bottom: 12px; border-bottom: 1px solid #f0f0f1;">
                <div>
                    <div style="font-size: 26px; font-weight: 700; color: #1d2327; line-height: 1.1;">
                        <?php echo esc_html( number_format_i18n( $total ) ); ?>
                    </div>
                    <div style="font-size: 12px; color: #646970; margin-top: 2px;">
                        <?php esc_html_e( 'Attacks & bots blocked in the last 24 hours', 'metzler-webshield' ); ?>
                    </div>
                </div>
                <img src="<?php echo esc_url( METZLER_WEBSHIELD_PLUGIN_URL . 'assets/images/logo-icon-128.png' ); ?>" alt="Metzler Webshield" style="width: 36px; height: 36px; border-radius: 8px; box-shadow: 0 2px 6px rgba(0,0,0,0.1); flex-shrink: 0;">
            </div>

            <?php if ( ! empty( $categories ) ) : ?>
                <div style="margin-bottom: 12px;">
                    <div style="font-size: 11px; font-weight: 600; text-transform: uppercase; color: #8c8f94; margin-bottom: 6px; letter-spacing: 0.5px;">
                        <?php esc_html_e( 'Top Threat Types', 'metzler-webshield' ); ?>
                    </div>
                    <div style="display: flex; flex-wrap: wrap; gap: 6px;">
                        <?php foreach ( array_slice( $categories, 0, 5, true ) as $cat_name => $cat_count ) : ?>
                            <span style="background: #f0f0f1; border: 1px solid #dcdcde; border-radius: 3px; padding: 2px 7px; font-size: 11px; color: #3c434a;">
                                <strong><?php echo esc_html( str_replace( '_', ' ', $cat_name ) ); ?>:</strong> <?php echo esc_html( number_format_i18n( $cat_count ) ); ?>
                            </span>
                        <?php endforeach; ?>
                    </div>
                </div>
            <?php endif; ?>

            <?php if ( ! empty( $recent_events ) ) : ?>
                <div style="margin-bottom: 14px;">
                    <div style="font-size: 11px; font-weight: 600; text-transform: uppercase; color: #8c8f94; margin-bottom: 6px; letter-spacing: 0.5px;">
                        <?php esc_html_e( 'Recent Interceptions', 'metzler-webshield' ); ?>
                    </div>
                    <ul style="margin: 0; padding: 0; list-style: none; font-size: 12px;">
                        <?php foreach ( $recent_events as $event ) : ?>
                            <li style="display: flex; justify-content: space-between; align-items: center; padding: 4px 0; border-bottom: 1px dotted #f0f0f1;">
                                <span style="font-family: monospace; color: #1d2327;">
                                    <?php echo esc_html( $event['ip'] ); ?>
                                    <span style="color: #646970; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen-Sans, Ubuntu, Cantarell, 'Helvetica Neue', sans-serif;">
                                        (<?php echo esc_html( str_replace( '_', ' ', $event['types'] ) ); ?>)
                                    </span>
                                </span>
                                <span style="color: #8c8f94; font-size: 11px; white-space: nowrap;">
                                    <?php echo esc_html( $event['time_human'] ); ?>
                                </span>
                            </li>
                        <?php endforeach; ?>
                    </ul>
                </div>
            <?php elseif ( 0 === $total ) : ?>
                <p style="margin: 0 0 14px; font-size: 13px; color: #646970;">
                    <?php esc_html_e( 'No automated threats or malicious bots intercepted in the last 24 hours. The firewall is active and inspecting all incoming requests.', 'metzler-webshield' ); ?>
                </p>
            <?php endif; ?>

            <div style="display: flex; justify-content: space-between; align-items: center;">
                <a href="<?php echo esc_url( $logs_url ); ?>" class="button button-secondary button-small">
                    <?php esc_html_e( 'View Security Log', 'metzler-webshield' ); ?> &rarr;
                </a>
            </div>
        </div>
        <?php
    }

    /**
     * Render Global Persistent Admin Notice when server threats are detected.
     */
    public function render_threat_admin_notice(): void {
        if ( ! current_user_can( 'manage_options' ) ) {
            return;
        }

        // Do not show duplicate banner on Metzler Webshield's own dashboard page
        $screen = get_current_screen();
        if ( $screen && 'toplevel_page_metzler-webshield' === $screen->id ) {
            return;
        }

        // Check if user dismissed this notice (resets on next scan run)
        $dismissed = get_transient( 'mws_threat_notice_dismissed_' . get_current_user_id() );
        if ( $dismissed ) {
            return;
        }

        require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/log/class-metzler-webshield-logger.php';
        $threat_count = Metzler_Webshield_Logger::count_active_threats();
        if ( $threat_count <= 0 ) {
            return;
        }

        $settings_url = admin_url( 'admin.php?page=metzler-webshield' );
        $dismiss_nonce = wp_create_nonce( 'metzler_webshield_dismiss_notice' );
        ?>
        <div class="notice notice-error is-dismissible mws-threat-global-notice" data-mws-nonce="<?php echo esc_attr( $dismiss_nonce ); ?>">
            <p style="display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin: 8px 0;">
                <span class="dashicons dashicons-warning" style="color: #d63638; font-size: 20px;"></span>
                <strong style="color: #b32d2e;"><?php esc_html_e( 'Metzler Webshield Security Alert:', 'metzler-webshield' ); ?></strong>
                <span>
                    <?php
                    /* translators: %d: number of detected security threats */
                    printf( esc_html( _n( 'The automated scanner detected %d security threat on your website.', 'The automated scanner detected %d security threats on your website.', $threat_count, 'metzler-webshield' ) ), (int) $threat_count );
                    ?>
                </span>
                <a href="<?php echo esc_url( $settings_url ); ?>" class="button button-small button-primary" style="margin-left: 6px;">
                    <?php esc_html_e( 'Review & Resolve', 'metzler-webshield' ); ?> &rarr;
                </a>
            </p>
        </div>
        <script>
            jQuery(document).on('click', '.mws-threat-global-notice .notice-dismiss', function() {
                var nonce = jQuery('.mws-threat-global-notice').data('mws-nonce');
                jQuery.post(ajaxurl, {
                    action: 'metzler_webshield_dismiss_threat_notice',
                    nonce: nonce
                });
            });
        </script>
        <?php
    }

    /**
     * Handle AJAX dismissal of the threat admin notice.
     */
    public function ajax_dismiss_threat_notice(): void {
        check_ajax_referer( 'metzler_webshield_dismiss_notice', 'nonce' );
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die();
        }

        // Dismiss for 12 hours (cleared automatically when the next nightly scan runs)
        set_transient( 'mws_threat_notice_dismissed_' . get_current_user_id(), true, 12 * HOUR_IN_SECONDS );
        wp_send_json_success();
    }

    /**
     * Points Pro subscribers to the Pro add-on when it is not installed.
     */
    public function render_pro_addon_notice(): void {
        if ( ! current_user_can( 'install_plugins' ) ) {
            return;
        }
        if ( apply_filters( 'metzler_webshield_pro_active', false ) ) {
            return;
        }
        if ( ! get_option( 'metzler_webshield_is_licensed' ) || 'pro' !== get_option( 'metzler_webshield_license_tier', 'free' ) ) {
            return;
        }
        if ( get_user_meta( get_current_user_id(), 'metzler_webshield_pro_notice_dismissed', true ) ) {
            return;
        }

        $dismiss_nonce = wp_create_nonce( 'metzler_webshield_dismiss_notice' );
        ?>
        <div class="notice notice-info is-dismissible mws-pro-addon-notice" data-mws-nonce="<?php echo esc_attr( $dismiss_nonce ); ?>">
            <p>
                <strong><?php esc_html_e( 'Metzler Webshield Pro:', 'metzler-webshield' ); ?></strong>
                <?php esc_html_e( 'Your Pro subscription is active. Pro features are now delivered as a separate add-on. Download it from your customer dashboard and install it to restore vulnerability intelligence and the Pro dashboard integration.', 'metzler-webshield' ); ?>
                <a href="https://dash.metzler-webshield.de/dashboard#pro-addon" target="_blank" rel="noopener"><?php esc_html_e( 'Open customer dashboard', 'metzler-webshield' ); ?> &rarr;</a>
            </p>
        </div>
        <script>
            jQuery(document).on('click', '.mws-pro-addon-notice .notice-dismiss', function() {
                jQuery.post(ajaxurl, {
                    action: 'metzler_webshield_dismiss_pro_notice',
                    nonce: jQuery('.mws-pro-addon-notice').data('mws-nonce')
                });
            });
        </script>
        <?php
    }

    public function ajax_dismiss_pro_notice(): void {
        check_ajax_referer( 'metzler_webshield_dismiss_notice', 'nonce' );
        if ( ! current_user_can( 'install_plugins' ) ) {
            wp_die();
        }
        update_user_meta( get_current_user_id(), 'metzler_webshield_pro_notice_dismissed', 1 );
        wp_send_json_success();
    }
}
