<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class Metzler_Webshield_Login {

    public function __construct() {
        add_action( "login_enqueue_scripts", array( $this, "add_login_js" ) );
        add_filter( "authenticate", array( $this, "verify_login_js" ), 20, 3 );
    }

    public function add_login_js(): void {
        $nonce = wp_create_nonce( "metzler_webshield_login_check" );
        $token_name = esc_attr( md5( "mws_field_" . time() ) );
        $msg = esc_js(__('Bot Protection: Please move your mouse or type to prove you are human.', 'metzler-webshield'));
        
        $js = "
        document.addEventListener('DOMContentLoaded', function() {
            const loginForm = document.getElementById('loginform');
            if (loginForm) {
                let isHuman = false;
                const tokenName = '{$token_name}';

                var setHuman = function() { isHuman = true; };
                document.addEventListener('mousemove', setHuman, {once: true});
                document.addEventListener('keydown', setHuman, {once: true});
                document.addEventListener('touchstart', setHuman, {once: true});

                setTimeout(function() {
                    const input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = 'metzler_webshield_bot_token';

                    const raw = '{$nonce}';
                    const obf = [];
                    for (let i = 0; i < raw.length; i++) obf.push(raw.charCodeAt(i) + 5);
                    
                    loginForm.addEventListener('submit', function(e) {
                        if (!isHuman) {
                            e.preventDefault();
                            const msg = '{$msg}';
                            const errorDiv = document.createElement('div');
                            errorDiv.id = 'login_error';
                            errorDiv.className = 'notice notice-error';
                            errorDiv.innerHTML = '<p><strong>' + msg + '</strong></p>';
                            const existingError = document.getElementById('login_error');
                            if (existingError) existingError.replaceWith(errorDiv);
                            else loginForm.parentNode.insertBefore(errorDiv, loginForm);
                            return;
                        }
                        let clear = '';
                        for (let j = 0; j < obf.length; j++) clear += String.fromCharCode(obf[j] - 5);
                        input.value = clear;
                        
                        if (!document.querySelector('input[name=metzler_webshield_bot_token]')) {
                            loginForm.appendChild(input);
                        }
                    });
                }, 500);
            }
        });
        ";
        wp_register_script('metzler-webshield-login-js', false);
        wp_add_inline_script('metzler-webshield-login-js', $js);
        wp_enqueue_script('metzler-webshield-login-js');
    }

    public function verify_login_js( $user, $username, $password ) {
        if ( empty( $username ) || empty( $password ) || ! isset( $_SERVER["REQUEST_METHOD"] ) || $_SERVER["REQUEST_METHOD"] !== "POST" ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
            return $user;
        }

        if ( defined( "XMLRPC_REQUEST" ) || defined( "REST_REQUEST" ) ) {
            return $user;
        }

        if ( ! isset( $_POST['metzler_webshield_bot_token'] ) || ! wp_verify_nonce( sanitize_text_field(wp_unslash($_POST['metzler_webshield_bot_token'])), "metzler_webshield_login_check" ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification
            
            $ip = $_SERVER["REMOTE_ADDR"] ?? "Unknown"; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
            require_once METZLER_WEBSHIELD_PLUGIN_DIR . "includes/log/class-metzler-webshield-logger.php";
            Metzler_Webshield_Logger::log(
                sprintf(
                    /* translators: %1$s: IP address, %2$s: username */
                    __('Brute-Force prevented: Bot login attempt (No JS) from IP: %1$s for user: %2$s', "metzler-webshield"),
                    sanitize_text_field($ip),
                    sanitize_text_field($username)
                ), 
                "waf", 
                "warning"
            );

            // Write brute force to telemetry file
            $upload_base = wp_upload_dir();
            $upload_dir = $upload_base['basedir'] . '/metzler-webshield';
            if ( ! file_exists($upload_dir) ) {
                wp_mkdir_p($upload_dir);
            }
            $telemetry_data = array(
                'time' => current_time('mysql'),
                'domain' => wp_parse_url(home_url(), PHP_URL_HOST),
                'ip_address' => sanitize_text_field($ip),
                'attack_type' => 'Brute_Force',
                'severity' => 'high',
                'request_uri' => isset($_SERVER['REQUEST_URI']) ? base64_encode(wp_unslash($_SERVER['REQUEST_URI'])) : '', // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
                'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? base64_encode(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '', // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
                'encoding' => 'base64'
            );
            @file_put_contents($upload_dir . '/telemetry.jsonl', json_encode($telemetry_data) . "\n", FILE_APPEND | LOCK_EX);
            
            return new WP_Error(
                "metzler_webshield_bot_blocked",
                "<strong>" . esc_html__("Metzler_Webshield:", "metzler-webshield") . "</strong> " . esc_html__("Access denied. Suspicious bot activity detected. Please enable JavaScript.", "metzler-webshield")
            );
        }

        return $user;
    }

}



