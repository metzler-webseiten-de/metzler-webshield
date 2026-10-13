<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class Metzler_Webshield_Login {

    const TOKEN_ACTION = 'metzler_webshield_login_check';

    public function __construct() {
        add_action( "login_enqueue_scripts", array( $this, "add_login_js" ) );
        add_action( "wp_enqueue_scripts", array( $this, "add_login_js" ) );
        add_action( "wp_ajax_metzler_webshield_login_token", array( $this, "ajax_login_token" ) );
        add_action( "wp_ajax_nopriv_metzler_webshield_login_token", array( $this, "ajax_login_token" ) );
        add_filter( "authenticate", array( $this, "verify_login_js" ), 20, 3 );
    }

    /**
     * Hands out a fresh token on demand. It is never written into the page, so page caches
     * and tabs restored by the browser cannot submit an expired one.
     */
    public function ajax_login_token(): void {
        nocache_headers();
        wp_send_json_success( array( 'token' => wp_create_nonce( self::TOKEN_ACTION ) ) );
    }

    public function add_login_js(): void {
        $endpoint = wp_json_encode( admin_url( 'admin-ajax.php' ) );

        $js = "
        document.addEventListener('DOMContentLoaded', function() {
            // All forms with a password field (login, register, custom login screens)
            const targetForms = Array.from(document.querySelectorAll('form')).filter(form => form.querySelector('input[type=\"password\"]'));
            if (targetForms.length === 0) {
                return;
            }

            const maxAgeMs = 30 * 60 * 1000;
            let token = null;
            let fetchedAt = 0;
            let pending = null;

            const isFresh = () => token !== null && (Date.now() - fetchedAt) < maxAgeMs;

            // Written into every form right away, so AJAX login forms that serialize the form themselves send it too
            const applyToken = () => {
                targetForms.forEach(function(form) {
                    let input = form.querySelector('input[name=metzler_webshield_bot_token]');
                    if (!input) {
                        input = document.createElement('input');
                        input.type = 'hidden';
                        input.name = 'metzler_webshield_bot_token';
                        form.appendChild(input);
                    }
                    input.value = token || '';
                });
            };

            const fetchToken = () => {
                if (pending) {
                    return pending;
                }
                pending = fetch({$endpoint}, {
                    method: 'POST',
                    credentials: 'same-origin',
                    cache: 'no-store',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: 'action=metzler_webshield_login_token'
                })
                    .then(response => response.ok ? response.json() : null)
                    .then(data => {
                        if (data && data.success && data.data && data.data.token) {
                            token = data.data.token;
                            fetchedAt = Date.now();
                            applyToken();
                        }
                    })
                    .catch(() => {})
                    .finally(() => { pending = null; });

                return pending;
            };

            const resubmit = (form, submitter) => {
                if (typeof form.requestSubmit === 'function') {
                    submitter ? form.requestSubmit(submitter) : form.requestSubmit();
                    return;
                }
                if (submitter && submitter.name) {
                    const clone = document.createElement('input');
                    clone.type = 'hidden';
                    clone.name = submitter.name;
                    clone.value = submitter.value;
                    form.appendChild(clone);
                }
                HTMLFormElement.prototype.submit.call(form);
            };

            targetForms.forEach(function(form) {
                // Safari does not focus buttons on click, so pointerdown covers a direct click on the submit button
                ['focusin', 'pointerdown'].forEach(function(type) {
                    form.addEventListener(type, function() {
                        if (!isFresh()) {
                            fetchToken();
                        }
                    }, { passive: true });
                });

                form.addEventListener('submit', function(event) {
                    if (isFresh() || form.metzlerWebshieldRetried) {
                        form.metzlerWebshieldRetried = false;
                        return;
                    }

                    // Autofill + instant submit: wait for the token, then send the form as the user did
                    event.preventDefault();
                    const submitter = event.submitter || null;
                    fetchToken().then(function() {
                        form.metzlerWebshieldRetried = !isFresh();
                        resubmit(form, submitter);
                    });
                });
            });

            // Back/forward cache restores the page without reloading it
            window.addEventListener('pageshow', function(event) {
                if (event.persisted) {
                    token = null;
                }
            });
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

        if ( ! isset( $_POST['metzler_webshield_bot_token'] ) || ! wp_verify_nonce( sanitize_text_field(wp_unslash($_POST['metzler_webshield_bot_token'])), self::TOKEN_ACTION ) ) { // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification

            $ip = class_exists( 'Metzler_Webshield' ) ? Metzler_Webshield::get_client_ip() : ( sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ?? '' ) ) ?: 'Unknown' );
            $login = self::mask_login( sanitize_text_field( $username ) );
            require_once METZLER_WEBSHIELD_PLUGIN_DIR . "includes/log/class-metzler-webshield-logger.php";
            Metzler_Webshield_Logger::log(
                sprintf(
                    /* translators: %1$s: IP address, %2$s: username */
                    __('Brute-Force prevented: Bot login attempt (No JS) from IP: %1$s for user: %2$s', "metzler-webshield"),
                    sanitize_text_field($ip),
                    $login
                ),
                "waf",
                "success"
            );

            // Write brute force to telemetry file
            $telemetry_data = array(
                'time' => gmdate('c'),
                'domain' => wp_parse_url(home_url(), PHP_URL_HOST),
                'ip_address' => sanitize_text_field($ip),
                'attack_type' => 'Brute_Force',
                'severity' => 'high',
                'request_uri' => isset($_SERVER['REQUEST_URI']) ? base64_encode(wp_unslash($_SERVER['REQUEST_URI'])) : '', // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
                'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? base64_encode(wp_unslash($_SERVER['HTTP_USER_AGENT'])) : '', // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
                'request_method' => sanitize_text_field( wp_unslash( $_SERVER['REQUEST_METHOD'] ?? 'POST' ) ),
                'payload' => base64_encode('Username: ' . $login),
                'encoding' => 'base64'
            );
            Metzler_Webshield_Storage::append_telemetry($telemetry_data);

            return new WP_Error(
                "metzler_webshield_bot_blocked",
                "<strong>" . esc_html__("Metzler_Webshield:", "metzler-webshield") . "</strong> " . esc_html__("Access denied. Suspicious bot activity detected. Please enable JavaScript.", "metzler-webshield")
            );
        }

        return $user;
    }

    /**
     * E-mail logins are personal data of the site's visitors: only the first two characters and the domain are kept,
     * which is enough to see which accounts are targeted. Plain usernames such as "admin" stay readable.
     */
    public static function mask_login( string $login ): string {
        $at = strrpos( $login, '@' );
        if ( $at === false ) {
            return $login;
        }

        $local = substr( $login, 0, $at );

        return substr( $local, 0, 2 ) . '***' . substr( $login, $at );
    }

}
