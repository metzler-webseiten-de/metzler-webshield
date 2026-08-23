<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class Metzler_Webshield_Login {

    public function __construct() {
        add_action( "login_enqueue_scripts", array( $this, "add_login_js" ) );
        add_filter( "authenticate", array( $this, "verify_login_js" ), 20, 3 );
    }

    public function add_login_js(): void {
        $nonce = wp_create_nonce( "metzler_webshield_login_check" );
        ?>
        <script type="text/javascript">
            document.addEventListener("DOMContentLoaded", function() {
                const loginForm = document.getElementById("loginform");
                if (loginForm) {
                    let isHuman = false;
                    const tokenName = '<?php echo esc_attr( md5( "mws_field_" . time() ) ); ?>';

                    var setHuman = function() { isHuman = true; };
                    document.addEventListener('mousemove', setHuman, {once: true});
                    document.addEventListener('keydown', setHuman, {once: true});
                    document.addEventListener('touchstart', setHuman, {once: true});

                    setTimeout(function() {
                        const input = document.createElement("input");
                        input.type = "hidden";
                        input.name = "metzler_webshield_bot_token";

                        const raw = "<?php echo esc_attr( $nonce ); ?>";
                        const obf = [];
                        for (let i = 0; i < raw.length; i++) obf.push(raw.charCodeAt(i) + 5);
                        
                        loginForm.addEventListener("submit", function(e) {
                            if (!isHuman) {
                                e.preventDefault();
                                alert("<?php echo esc_js(__('Bot Protection: Please move your mouse or type to prove you are human.', 'metzler-webshield')); ?>");
                                return;
                            }
                            let clear = "";
                            for (let j = 0; j < obf.length; j++) clear += String.fromCharCode(obf[j] - 5);
                            input.value = clear;
                            
                            if (!document.querySelector("input[name=metzler_webshield_bot_token]")) {
                                loginForm.appendChild(input);
                            }
                        });
                    }, 500);
                }
            });
        </script>
        <?php
    }

    public function verify_login_js( $user, $username, $password ) {
        if ( ! get_option('metzler_webshield_is_licensed') ) {
            return $user;
        }

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
            
            return new WP_Error(
                "metzler_webshield_bot_blocked",
                "<strong>" . esc_html__("Metzler_Webshield:", "metzler-webshield") . "</strong> " . esc_html__("Access denied. Suspicious bot activity detected. Please enable JavaScript.", "metzler-webshield")
            );
        }

        return $user;
    }

}



