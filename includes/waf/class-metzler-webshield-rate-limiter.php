<?php
/**
 * Metzler Webshield General Rate Limiter & DoS Shield
 *
 * Provides intelligent, high-performance, shared-hosting safe rate limiting
 * against aggressive scrapers, automated floods, and crawlers without harming SEO.
 *
 * @package Metzler_Webshield
 */

if ( ! defined( 'ABSPATH' ) ) {
    exit;
}

class Metzler_Webshield_Rate_Limiter {

    /**
     * Burst window limit in seconds and max allowed dynamic requests.
     */
    const BURST_WINDOW = 15;
    const BURST_LIMIT  = 100;

    /**
     * Sustained window limit in seconds and max allowed dynamic requests.
     */
    const SUSTAINED_WINDOW = 60;
    const SUSTAINED_LIMIT  = 350;

    /**
     * Penalty cooldown time in seconds when rate limit is exceeded.
     */
    const COOLDOWN_SECONDS = 30;

    /**
     * Main entry point for rate limit inspection.
     */
    public static function check_request(): void {
        // 1. Check if rate limiting or under attack mode is enabled
        $rate_limit_enabled   = get_option( 'metzler_webshield_enable_rate_limiting', '1' ) === '1';
        $under_attack_enabled = get_option( 'metzler_webshield_under_attack_mode', '0' ) === '1';

        if ( ! $rate_limit_enabled && ! $under_attack_enabled ) {
            return;
        }

        // 2. Skip CLI and WP-Cron
        if ( ( defined( 'WP_CLI' ) && WP_CLI ) || ( defined( 'DOING_CRON' ) && DOING_CRON ) ) {
            return;
        }

        // 3. Skip static assets completely (CSS, JS, Images, Fonts, etc.)
        $uri = $_SERVER['REQUEST_URI'] ?? ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
        if ( self::is_static_asset( $uri ) ) {
            return;
        }

        // 4. Resolve client IP (Cloudflare, proxy, or direct)
        $client_ip = class_exists( 'Metzler_Webshield' )
            ? Metzler_Webshield::get_client_ip()
            : ( sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ?? '' ) ) ?: '127.0.0.1' );

        // 5. Skip loopback / server requests
        $server_ip = $_SERVER['SERVER_ADDR'] ?? ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
        $host_ip   = isset( $_SERVER['HTTP_HOST'] ) ? gethostbyname( sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ) ) ) : '';
        if ( $client_ip === $server_ip || $client_ip === $host_ip || $client_ip === '127.0.0.1' || $client_ip === '::1' ) {
            return;
        }

        // 6. Skip logged-in users and administrators
        if ( self::is_logged_in_user() ) {
            return;
        }

        // 7. Check if client has a valid clearance pass (cookie)
        if ( self::has_valid_clearance( $client_ip ) ) {
            return;
        }

        // 8. Handle 1-Click Human Verification POST submission
        if ( isset( $_POST['mws_clearance_token'] ) && 'POST' === ( $_SERVER['REQUEST_METHOD'] ?? '' ) ) { // phpcs:ignore WordPress.Security.NonceVerification
            if ( self::verify_clearance_token( sanitize_text_field( wp_unslash( $_POST['mws_clearance_token'] ) ), $client_ip ) ) { // phpcs:ignore WordPress.Security.NonceVerification
                self::set_clearance_cookie( $client_ip );
                // Clean up IP rate limit file so user can immediately browse
                self::clear_ip_bucket( $client_ip );
                
                $redirect_url = esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ?? '/' ) ); // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
                if ( ! headers_sent() ) {
                    if ( function_exists( 'wp_safe_redirect' ) ) {
                        wp_safe_redirect( $redirect_url );
                    } else {
                        header( 'Location: ' . $redirect_url, true, 302 );
                    }
                } else {
                    echo '<meta http-equiv="refresh" content="0;url=' . esc_attr( $redirect_url ) . '">';
                    echo '<script>window.location.href = ' . json_encode( $redirect_url ) . ';</script>';
                }
                exit;
            }
        }

        // 9. Skip verified search engine crawlers (Googlebot, Bingbot)
        $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
        if ( self::is_verified_search_bot( $client_ip, $user_agent ) ) {
            return;
        }

        // 10. Under Attack Mode: Challenge every uncached visitor
        if ( $under_attack_enabled ) {
            self::render_under_attack_page( $client_ip );
        }

        // 11. Record request & evaluate rate limits
        if ( $rate_limit_enabled ) {
            self::record_and_evaluate( $client_ip, $uri, $user_agent );
        }
    }

    /**
     * Checks whether the request URI targets a static asset.
     */
    public static function is_static_asset( string $uri ): bool {
        $path = wp_parse_url( $uri, PHP_URL_PATH );
        if ( empty( $path ) ) {
            return false;
        }
        return (bool) preg_match( '/\.(?:css|js|jpe?g|png|gif|webp|svg|ico|woff2?|ttf|eot|otf|map|mp4|webm|pdf|zip|tar|gz)(?:\?.*)?$/i', $path );
    }

    /**
     * Checks if current request is from an authenticated WordPress user.
     */
    public static function is_logged_in_user(): bool {
        if ( function_exists( 'is_user_logged_in' ) && is_user_logged_in() ) {
            return true;
        }

        // Early WAF phase fallback: check for WordPress logged-in cookies
        foreach ( $_COOKIE as $name => $value ) {
            if ( str_starts_with( $name, 'wordpress_logged_in_' ) && ! empty( $value ) ) {
                return true;
            }
        }

        return false;
    }

    /**
     * Verifies genuine search engine crawlers via reverse DNS and caches the verdict for 24 hours.
     */
    public static function is_verified_search_bot( string $ip, string $user_agent ): bool {
        if ( ! preg_match( '/(Googlebot|bingbot|Baiduspider|YandexBot|DuckDuckBot)/i', $user_agent, $matches ) ) {
            return false;
        }

        $transient_key = 'mws_bot_' . md5( $ip );
        $cached        = get_transient( $transient_key );
        if ( false !== $cached ) {
            return ( '1' === $cached );
        }

        $hostname = gethostbyaddr( $ip );
        $is_valid = false;

        if ( $hostname && $hostname !== $ip ) {
            $bot = strtolower( $matches[1] );
            if ( 'googlebot' === $bot && ( str_ends_with( $hostname, '.googlebot.com' ) || str_ends_with( $hostname, '.google.com' ) ) ) {
                $is_valid = ( gethostbyname( $hostname ) === $ip );
            } elseif ( 'bingbot' === $bot && str_ends_with( $hostname, '.search.msn.com' ) ) {
                $is_valid = ( gethostbyname( $hostname ) === $ip );
            } elseif ( in_array( $bot, array( 'baiduspider', 'yandexbot', 'duckduckbot' ), true ) ) {
                $is_valid = ( gethostbyname( $hostname ) === $ip );
            }
        }

        set_transient( $transient_key, $is_valid ? '1' : '0', DAY_IN_SECONDS );
        return $is_valid;
    }

    /**
     * Resolves the secure storage directory on disk without relying on pluggable or late WP functions.
     */
    private static function get_storage_dir(): string {
        if ( defined( 'WP_CONTENT_DIR' ) ) {
            return WP_CONTENT_DIR . '/uploads/metzler-webshield';
        }
        if ( function_exists( 'wp_upload_dir' ) ) {
            $up = wp_upload_dir();
            return ( $up['basedir'] ?? '' ) . '/metzler-webshield';
        }
        return sys_get_temp_dir() . '/metzler-webshield';
    }

    /**
     * File-based sliding window rate tracker.
     */
    private static function record_and_evaluate( string $ip, string $uri, string $user_agent ): void {
        $upload_dir = self::get_storage_dir();
        $rl_dir     = $upload_dir . '/rl';
        if ( ! is_dir( $rl_dir ) ) {
            @mkdir( $rl_dir, 0755, true );
            @file_put_contents( $rl_dir . '/index.php', "<?php // Silence is golden." ); // phpcs:ignore
        }

        $file = $rl_dir . '/' . md5( $ip ) . '.json';
        $now  = time();

        $data = array(
            'burst'         => array( 'count' => 0, 'start' => $now ),
            'sustained'     => array( 'count' => 0, 'start' => $now ),
            'blocked_until' => 0,
        );

        if ( file_exists( $file ) ) {
            $content = @file_get_contents( $file );
            if ( ! empty( $content ) ) {
                $decoded = json_decode( $content, true );
                if ( is_array( $decoded ) ) {
                    $data = array_merge( $data, $decoded );
                }
            }
        }

        // 1. Check if IP is currently under cooldown penalty
        if ( $now < (int) $data['blocked_until'] ) {
            $remaining = (int) $data['blocked_until'] - $now;
            self::render_challenge_page( $ip, $remaining );
        }

        // 2. Update Burst Window (15 seconds)
        if ( ( $now - (int) $data['burst']['start'] ) >= self::BURST_WINDOW ) {
            $data['burst']['count'] = 1;
            $data['burst']['start'] = $now;
        } else {
            $data['burst']['count']++;
        }

        // 3. Update Sustained Window (60 seconds)
        if ( ( $now - (int) $data['sustained']['start'] ) >= self::SUSTAINED_WINDOW ) {
            $data['sustained']['count'] = 1;
            $data['sustained']['start'] = $now;
        } else {
            $data['sustained']['count']++;
        }

        // 4. Evaluate breach
        if ( $data['burst']['count'] > self::BURST_LIMIT || $data['sustained']['count'] > self::SUSTAINED_LIMIT ) {
            $data['blocked_until'] = $now + self::COOLDOWN_SECONDS;
            @file_put_contents( $file, json_encode( $data ), LOCK_EX );

            self::log_rate_limit_event( $ip, $uri, $user_agent, $data['burst']['count'], $data['sustained']['count'] );
            self::render_challenge_page( $ip, self::COOLDOWN_SECONDS );
        }

        // Save active counters
        @file_put_contents( $file, json_encode( $data ), LOCK_EX );

        // 5. Periodic garbage collection (1 in 500 requests)
        if ( 1 === mt_rand( 1, 500 ) ) {
            self::clean_stale_buckets( $rl_dir );
        }
    }

    /**
     * Log telemetry and security log for rate limit violations.
     */
    private static function log_rate_limit_event( string $ip, string $uri, string $user_agent, int $burst_count, int $sustained_count ): void {
        $upload_dir = self::get_storage_dir();
        $domain     = sanitize_text_field( wp_unslash( $_SERVER['HTTP_HOST'] ?? 'unknown' ) );

        $telemetry_data = array(
            'time'           => gmdate( 'c' ),
            'domain'         => $domain,
            'ip_address'     => $ip,
            'attack_type'    => 'Rate_Limit_Exceeded',
            'severity'       => 'medium',
            'request_uri'    => base64_encode( $uri ),
            'user_agent'     => base64_encode( $user_agent ),
            'request_method' => $_SERVER['REQUEST_METHOD'] ?? 'GET',
            'payload'        => base64_encode( "Rate limit exceeded: {$burst_count} req/15s, {$sustained_count} req/60s" ),
            'encoding'       => 'base64',
        );
        @file_put_contents( $upload_dir . '/telemetry.jsonl', json_encode( $telemetry_data ) . "\n", FILE_APPEND | LOCK_EX );

        if ( defined( 'METZLER_WEBSHIELD_PLUGIN_DIR' ) ) {
            require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/log/class-metzler-webshield-logger.php';
            Metzler_Webshield_Logger::log(
                sprintf(
                    /* translators: 1: IP address, 2: Burst count, 3: Sustained count */
                    __( 'Rate limit exceeded by %1$s (%2$d req/15s, %3$d req/60s) - temporary 30s cooldown applied.', 'metzler-webshield' ),
                    $ip,
                    $burst_count,
                    $sustained_count
                ),
                'waf',
                'warning'
            );
        }
    }

    /**
     * Renders a native WordPress-styled HTTP 429 response page with auto-reload and 1-click verification.
     */
    private static function render_challenge_page( string $ip, int $cooldown_seconds ): void {
        status_header( 429 );
        nocache_headers();
        header( 'Retry-After: ' . max( 5, $cooldown_seconds ) );
        header( 'Content-Type: text/html; charset=UTF-8' );

        $token        = self::generate_clearance_token( $ip );
        $seconds_left = max( 1, $cooldown_seconds );
        ?>
<!DOCTYPE html>
<html lang="<?php echo esc_attr( get_locale() ); ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title><?php echo esc_html__( 'Too Many Requests', 'metzler-webshield' ); ?> &lsaquo; <?php echo esc_html( function_exists( 'get_bloginfo' ) ? get_bloginfo( 'name' ) : get_option( 'blogname', 'WordPress' ) ); ?></title>
    <style>
        html {
            background: #f0f0f1;
        }
        body {
            background: #fff;
            border: 1px solid #c3c4c7;
            color: #3c434a;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
            margin: 50px auto;
            padding: 2em 2.5em;
            max-width: 650px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
            border-radius: 4px;
        }
        h1 {
            border-bottom: 1px solid #dadada;
            clear: both;
            color: #1d2327;
            font-size: 22px;
            margin: 0 0 16px 0;
            padding: 0 0 12px 0;
            font-weight: 600;
        }
        p {
            font-size: 14px;
            line-height: 1.6;
            margin: 16px 0;
        }
        .mws-timer-box {
            background: #f6f7f7;
            border-left: 4px solid #2271b1;
            padding: 12px 16px;
            margin: 20px 0;
            font-size: 14px;
        }
        .mws-countdown {
            font-weight: bold;
            color: #2271b1;
            font-family: monospace;
            font-size: 16px;
        }
        .mws-actions {
            margin-top: 24px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .button {
            background: #2271b1;
            border-color: #2271b1;
            color: #fff;
            text-decoration: none;
            text-shadow: none;
            display: inline-block;
            font-size: 13px;
            line-height: 2.15384615;
            min-height: 32px;
            margin: 0;
            padding: 0 14px;
            cursor: pointer;
            border-width: 1px;
            border-style: solid;
            -webkit-appearance: none;
            border-radius: 3px;
            white-space: nowrap;
            box-sizing: border-box;
            font-weight: 500;
        }
        .button:hover, .button:focus {
            background: #135e96;
            border-color: #135e96;
            color: #fff;
        }
        .mws-footer {
            margin-top: 28px;
            padding-top: 14px;
            border-top: 1px solid #f0f0f1;
            font-size: 11px;
            color: #8c8f94;
        }
    </style>
</head>
<body id="error-page">
    <h1><?php echo esc_html__( 'Too Many Requests', 'metzler-webshield' ); ?></h1>
    <p>
        <?php echo esc_html__( 'You are accessing this website too quickly. To protect the site from automated overload and abuse, your access has been temporarily limited.', 'metzler-webshield' ); ?>
    </p>

    <div class="mws-timer-box">
        <?php echo esc_html__( 'Automatic reload in', 'metzler-webshield' ); ?>:
        <span class="mws-countdown" id="mws-timer"><?php echo esc_html( (string) $seconds_left ); ?></span> <?php echo esc_html__( 'seconds', 'metzler-webshield' ); ?>...
    </div>

    <form method="POST" action="" class="mws-actions">
        <input type="hidden" name="mws_clearance_token" value="<?php echo esc_attr( $token ); ?>">
        <button type="submit" class="button button-primary">
            <?php echo esc_html__( 'I am a human (Continue)', 'metzler-webshield' ); ?>
        </button>
    </form>

    <div class="mws-footer">
        <?php echo esc_html__( 'Protected by Metzler Webshield Security', 'metzler-webshield' ); ?>
    </div>

    <script>
        (function() {
            var seconds = <?php echo (int) $seconds_left; ?>;
            var timerDisplay = document.getElementById('mws-timer');
            var interval = setInterval(function() {
                seconds--;
                if (timerDisplay) {
                    timerDisplay.textContent = seconds;
                }
                if (seconds <= 0) {
                    clearInterval(interval);
                    window.location.reload();
                }
            }, 1000);
        })();
    </script>
</body>
</html>
        <?php
        exit;
    }

    /**
     * Renders an Under Attack Mode security verification page with 1-click challenge and 3-second auto-browser-check.
     */
    private static function render_under_attack_page( string $ip ): void {
        status_header( 503 );
        nocache_headers();
        header( 'Retry-After: 5' );
        header( 'Content-Type: text/html; charset=UTF-8' );

        $token = self::generate_clearance_token( $ip );
        ?>
<!DOCTYPE html>
<html lang="<?php echo esc_attr( get_locale() ); ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="robots" content="noindex, nofollow">
    <title><?php echo esc_html__( 'Security Check', 'metzler-webshield' ); ?> &lsaquo; <?php echo esc_html( function_exists( 'get_bloginfo' ) ? get_bloginfo( 'name' ) : get_option( 'blogname', 'WordPress' ) ); ?></title>
    <style>
        html {
            background: #f0f0f1;
        }
        body {
            background: #fff;
            border: 1px solid #c3c4c7;
            color: #3c434a;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
            margin: 50px auto;
            padding: 2em 2.5em;
            max-width: 650px;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.08);
            border-radius: 4px;
        }
        h1 {
            border-bottom: 1px solid #dadada;
            clear: both;
            color: #1d2327;
            font-size: 22px;
            margin: 0 0 16px 0;
            padding: 0 0 12px 0;
            font-weight: 600;
        }
        p {
            font-size: 14px;
            line-height: 1.6;
            margin: 16px 0;
        }
        .mws-timer-box {
            background: #f6f7f7;
            border-left: 4px solid #d63638;
            padding: 12px 16px;
            margin: 20px 0;
            font-size: 14px;
        }
        .mws-countdown {
            font-weight: bold;
            color: #d63638;
            font-family: monospace;
            font-size: 16px;
        }
        .mws-actions {
            margin-top: 24px;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        .button {
            background: #2271b1;
            border-color: #2271b1;
            color: #fff;
            text-decoration: none;
            text-shadow: none;
            display: inline-block;
            font-size: 13px;
            line-height: 2.15384615;
            min-height: 32px;
            margin: 0;
            padding: 0 14px;
            cursor: pointer;
            border-width: 1px;
            border-style: solid;
            -webkit-appearance: none;
            border-radius: 3px;
            white-space: nowrap;
            box-sizing: border-box;
            font-weight: 500;
        }
        .button:hover, .button:focus {
            background: #135e96;
            border-color: #135e96;
            color: #fff;
        }
        .mws-footer {
            margin-top: 28px;
            padding-top: 14px;
            border-top: 1px solid #f0f0f1;
            font-size: 11px;
            color: #8c8f94;
        }
    </style>
</head>
<body id="error-page">
    <h1><?php echo esc_html__( 'Security Check', 'metzler-webshield' ); ?></h1>
    <p>
        <?php echo esc_html__( 'This website is currently in High Security Mode to protect against an ongoing cyber attack. Please verify that you are a human visitor to proceed.', 'metzler-webshield' ); ?>
    </p>

    <div class="mws-timer-box">
        <?php echo esc_html__( 'Checking your browser before accessing', 'metzler-webshield' ); ?>...
        <span class="mws-countdown" id="mws-timer">3</span> <?php echo esc_html__( 'seconds', 'metzler-webshield' ); ?>
    </div>

    <form method="POST" action="" class="mws-actions" id="mws-challenge-form">
        <input type="hidden" name="mws_clearance_token" value="<?php echo esc_attr( $token ); ?>">
        <button type="submit" class="button button-primary">
            <?php echo esc_html__( 'I am a human (Continue)', 'metzler-webshield' ); ?>
        </button>
    </form>

    <div class="mws-footer">
        <?php echo esc_html__( 'Protected by Metzler Webshield Security', 'metzler-webshield' ); ?>
    </div>

    <script>
        (function() {
            var seconds = 3;
            var timerDisplay = document.getElementById('mws-timer');
            var interval = setInterval(function() {
                seconds--;
                if (timerDisplay) {
                    timerDisplay.textContent = seconds;
                }
                if (seconds <= 0) {
                    clearInterval(interval);
                    var form = document.getElementById('mws-challenge-form');
                    if (form) {
                        form.submit();
                    }
                }
            }, 1000);
        })();
    </script>
</body>
</html>
        <?php
        exit;
    }

    /**
     * Generates a tamper-proof HMAC verification token.
     */
    private static function generate_clearance_token( string $ip ): string {
        $window = (int) floor( time() / 300 ); // 5-minute validity window
        $salt   = defined( 'AUTH_SALT' ) ? AUTH_SALT : 'mws_rate_salt';
        $hash   = hash_hmac( 'sha256', $ip . '|' . $window, $salt );
        return $hash . '|' . $window;
    }

    /**
     * Validates an HMAC clearance verification token.
     */
    private static function verify_clearance_token( string $token, string $ip ): bool {
        $parts = explode( '|', $token );
        if ( 2 !== count( $parts ) ) {
            return false;
        }

        list( $hash, $window ) = $parts;
        $current_window        = (int) floor( time() / 300 );

        // Allow token within current window or immediate previous window (10 min leeway)
        if ( abs( $current_window - (int) $window ) > 1 ) {
            return false;
        }

        $salt          = defined( 'AUTH_SALT' ) ? AUTH_SALT : 'mws_rate_salt';
        $expected_hash = hash_hmac( 'sha256', $ip . '|' . $window, $salt );

        return hash_equals( $expected_hash, $hash );
    }

    /**
     * Verifies if client carries an authentic clearance cookie.
     */
    private static function has_valid_clearance( string $ip ): bool {
        if ( empty( $_COOKIE['mws_clearance'] ) ) {
            return false;
        }

        $cookie_val = sanitize_text_field( wp_unslash( $_COOKIE['mws_clearance'] ) );
        $parts      = explode( '|', $cookie_val );
        if ( 2 !== count( $parts ) ) {
            return false;
        }

        list( $expiry, $hash ) = $parts;
        if ( (int) $expiry < time() ) {
            return false;
        }

        $salt          = defined( 'AUTH_SALT' ) ? AUTH_SALT : 'mws_rate_salt';
        $expected_hash = hash_hmac( 'sha256', $ip . '|' . $expiry, $salt );

        return hash_equals( $expected_hash, $hash );
    }

    /**
     * Sets a 1-hour cryptographic clearance cookie.
     */
    private static function set_clearance_cookie( string $ip, int $duration = 3600 ): void {
        $expiry        = time() + $duration;
        $salt          = defined( 'AUTH_SALT' ) ? AUTH_SALT : 'mws_rate_salt';
        $hash          = hash_hmac( 'sha256', $ip . '|' . $expiry, $salt );
        $value         = $expiry . '|' . $hash;
        $cookie_path   = defined( 'COOKIEPATH' ) ? COOKIEPATH : '/';
        $cookie_domain = defined( 'COOKIE_DOMAIN' ) ? COOKIE_DOMAIN : '';

        if ( ! headers_sent() ) {
            setcookie( 'mws_clearance', $value, $expiry, $cookie_path, $cookie_domain, is_ssl(), true );
        }
        $_COOKIE['mws_clearance'] = $value;
    }

    /**
     * Resets rate limit file for an IP upon successful human verification.
     */
    private static function clear_ip_bucket( string $ip ): void {
        $upload_dir = self::get_storage_dir();
        $file       = $upload_dir . '/rl/' . md5( $ip ) . '.json';
        if ( file_exists( $file ) ) {
            @unlink( $file );
        }
    }

    /**
     * Deletes rate-limit files older than 1 hour.
     */
    private static function clean_stale_buckets( string $rl_dir ): void {
        $files = glob( $rl_dir . '/*.json' );
        if ( empty( $files ) ) {
            return;
        }

        $now = time();
        foreach ( $files as $file ) {
            if ( is_file( $file ) && ( $now - filemtime( $file ) ) > 3600 ) {
                @unlink( $file );
            }
        }
    }
}
