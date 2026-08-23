<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class WPProtector_Login {

    public function __construct() {
        add_action( "login_enqueue_scripts", array( $this, "add_login_js" ) );
        add_filter( "authenticate", array( $this, "verify_login_js" ), 20, 3 );
    }

    public function add_login_js(): void {
        $nonce = wp_create_nonce( "wpprotector_login_check" );
        ?>
        <script type="text/javascript">
            document.addEventListener("DOMContentLoaded", function() {
                const loginForm = document.getElementById("loginform");
                if (loginForm) {
                    let isHuman = false;
                    const tokenName = '<?php echo md5( "wpp_field_" . time() ); ?>';

                    var setHuman = function() { isHuman = true; };
                    document.addEventListener('mousemove', setHuman, {once: true});
                    document.addEventListener('keydown', setHuman, {once: true});
                    document.addEventListener('touchstart', setHuman, {once: true});

                    setTimeout(function() {
                        const input = document.createElement("input");
                        input.type = "hidden";
                        input.name = "wpprotector_bot_token";

                        const raw = "<?php echo $nonce; ?>";
                        const obf = [];
                        for (let i = 0; i < raw.length; i++) obf.push(raw.charCodeAt(i) + 5);
                        
                        loginForm.addEventListener("submit", function(e) {
                            if (!isHuman) {
                                e.preventDefault();
                                alert("<?php echo esc_js(__('Bot Protection: Please move your mouse or type to prove you are human.', 'wpprotector')); ?>");
                                return;
                            }
                            let clear = "";
                            for (let j = 0; j < obf.length; j++) clear += String.fromCharCode(obf[j] - 5);
                            input.value = clear;
                            
                            if (!document.querySelector("input[name=wpprotector_bot_token]")) {
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
        if ( ! get_option('wpprotector_is_licensed') ) {
            return $user;
        }

        if ( empty( $username ) || empty( $password ) || ! isset( $_SERVER["REQUEST_METHOD"] ) || $_SERVER["REQUEST_METHOD"] !== "POST" ) {
            return $user;
        }

        if ( defined( "XMLRPC_REQUEST" ) || defined( "REST_REQUEST" ) ) {
            return $user;
        }

        if ( ! isset( $_POST["wpprotector_bot_token"] ) || ! wp_verify_nonce( $_POST["wpprotector_bot_token"], "wpprotector_login_check" ) ) {
            
            $ip = $_SERVER["REMOTE_ADDR"] ?? "Unknown";
            require_once WPPROTECTOR_PLUGIN_DIR . "includes/log/class-wpprotector-logger.php";
            WPProtector_Logger::log(
                sprintf(
                    __("Brute-Force prevented: Bot login attempt (No JS) from IP: %s for user: %s", "wpprotector"),
                    sanitize_text_field($ip),
                    sanitize_text_field($username)
                ), 
                "waf", 
                "warning"
            );
            
            return new WP_Error(
                "wpprotector_bot_blocked",
                "<strong>" . esc_html__("WPProtector:", "wpprotector") . "</strong> " . esc_html__("Access denied. Suspicious bot activity detected. Please enable JavaScript.", "wpprotector")
            );
        }

        return $user;
    }

}
