<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Extended protection: runs the WAF via PHP's auto_prepend_file before WordPress.
 *
 * As a normal plugin the WAF only sees requests that load WordPress. Exploits that call a vulnerable plugin
 * file directly (/wp-content/plugins/x/upload.php) never do. With auto_prepend_file, PHP itself loads the
 * firewall before every script of the site.
 *
 * Three pieces:
 * - metzler-webshield-waf.php in the site root (bootstrap): includes includes/waf/prepend.php while the plugin
 *   exists, otherwise does nothing. It stays behind when protection is turned off, because PHP caches .user.ini
 *   for minutes and a missing prepend file would be a fatal error on every request.
 * - the auto_prepend_file directive in .user.ini (PHP-FPM/CGI) or .htaccess (mod_php, LiteSpeed)
 * - waf-config.php in the storage directory (snapshot): rules and settings, since there is no database yet
 */
class Metzler_Webshield_Firewall_Setup {

    const BOOTSTRAP_FILE = 'metzler-webshield-waf.php';
    const SNAPSHOT_FILE  = 'waf-config.php';
    const OPTION         = 'metzler_webshield_extended_protection';
    const SNAPSHOT_VERSION_OPTION = 'metzler_webshield_snapshot_version';
    const MARKER         = 'Metzler Webshield Firewall';

    public static function init(): void {
        add_action( 'metzler_webshield_daily_scan', array( __CLASS__, 'write_snapshot' ) );
        add_action( 'admin_init', array( __CLASS__, 'refresh_after_update' ) );
    }

    /**
     * Writes everything the firewall needs before WordPress loads.
     */
    public static function write_snapshot(): void {
        $cloud_rules = Metzler_Webshield_Cloud_Rules::load();
        $rules       = Metzler_Webshield_WAF::build_rules();

        $config = array(
            'waf'             => get_option( 'metzler_webshield_enable_waf', '0' ) === '1',
            'xmlrpc_disabled' => get_option( 'metzler_webshield_disable_xmlrpc', '0' ) === '1',
            // Built-in rules are left out, so the firewall always uses those of the installed plugin version
            'rules'           => ( empty( $cloud_rules ) && Metzler_Webshield_WAF::local_rules() === $rules ) ? null : $rules,
            'time'            => time(),
        ) + Metzler_Webshield_Request::snapshot();

        Metzler_Webshield_Storage::ensure_dir();
        Metzler_Webshield_Storage::write_guarded( Metzler_Webshield_Storage::path( self::SNAPSHOT_FILE ), (string) wp_json_encode( $config ) );
        update_option( self::SNAPSHOT_VERSION_OPTION, METZLER_WEBSHIELD_VERSION );
    }

    public static function delete_snapshot(): void {
        $file = Metzler_Webshield_Storage::path( self::SNAPSHOT_FILE );
        if ( file_exists( $file ) ) {
            wp_delete_file( $file );
        }
    }

    /**
     * Add-ons and plugin updates can change the rule set, so the snapshot is rebuilt once per version.
     */
    public static function refresh_after_update(): void {
        if ( get_option( self::SNAPSHOT_VERSION_OPTION ) !== METZLER_WEBSHIELD_VERSION ) {
            self::write_snapshot();
        }
    }

    /**
     * @return array{method: string|null, enabled: bool, active: bool, pending: bool, conflict: string, cache_ttl: int}
     */
    public static function status(): array {
        $enabled = get_option( self::OPTION, '0' ) === '1';
        $active  = defined( 'METZLER_WEBSHIELD_BOOTSTRAP_LOADED' );
        $current = (string) ini_get( 'auto_prepend_file' );

        return array(
            'method'    => self::server_method(),
            'enabled'   => $enabled,
            'active'    => $active,
            // .user.ini changes need up to user_ini.cache_ttl seconds (default 5 minutes)
            'pending'   => $enabled && ! $active,
            'conflict'  => ( '' !== $current && ! self::is_bootstrap( $current ) ) ? $current : '',
            'cache_ttl' => (int) ini_get( 'user_ini.cache_ttl' ),
        );
    }

    /**
     * @return true|WP_Error
     */
    public static function enable() {
        $method = self::server_method();
        if ( null === $method ) {
            return new WP_Error( 'unsupported', __( 'This server does not allow PHP settings per directory (.user.ini or .htaccess). Ask your host to set auto_prepend_file, or keep the standard protection.', 'metzler-webshield' ) );
        }

        $current = (string) ini_get( 'auto_prepend_file' );
        if ( '' !== $current && ! self::is_bootstrap( $current ) ) {
            return new WP_Error( 'conflict', sprintf(
                /* translators: %s: file path */
                __( 'Another file is already loaded before WordPress (%s), usually by another security plugin. Only one firewall can use this mode.', 'metzler-webshield' ),
                $current
            ) );
        }

        self::write_snapshot();

        if ( ! self::write_bootstrap() ) {
            return new WP_Error( 'not_writable', __( 'Could not create the firewall file in the WordPress directory (missing write permissions).', 'metzler-webshield' ) );
        }

        if ( ! self::write_directive( $method ) ) {
            return new WP_Error( 'not_writable', sprintf(
                /* translators: %s: file name (.user.ini or .htaccess) */
                __( 'Could not write %s in the WordPress directory (missing write permissions).', 'metzler-webshield' ),
                'htaccess' === $method ? '.htaccess' : '.user.ini'
            ) );
        }

        update_option( self::OPTION, '1' );
        return true;
    }

    /**
     * Removes the directive. The bootstrap stays (see class comment) and does nothing without the plugin.
     */
    public static function disable(): void {
        self::remove_directives();
        update_option( self::OPTION, '0' );
    }

    /**
     * Plugin deactivated: no firewall before WordPress until it is activated again.
     */
    public static function deactivate(): void {
        self::remove_directives();
        self::delete_snapshot();
    }

    /**
     * Plugin (re)activated: restore extended protection if it was on.
     */
    public static function activate(): void {
        if ( get_option( self::OPTION, '0' ) === '1' ) {
            self::enable();
        }
    }

    /**
     * Plugin deleted: remove everything, the bootstrap only once PHP no longer loads it (cached .user.ini).
     */
    public static function uninstall(): void {
        self::remove_directives();
        if ( ! self::is_bootstrap( (string) ini_get( 'auto_prepend_file' ) ) ) {
            $bootstrap = self::bootstrap_path();
            if ( file_exists( $bootstrap ) ) {
                wp_delete_file( $bootstrap );
            }
        }
    }

    public static function bootstrap_path(): string {
        return self::home_path() . self::BOOTSTRAP_FILE;
    }

    /**
     * True when an auto_prepend_file/auto_append_file directive in a .user.ini, .htaccess or php.ini loads
     * anything but a known firewall. Malware uses these directives to run on every request.
     */
    public static function has_foreign_prepend( string $content ): bool {
        if ( ! preg_match_all( '/auto_(?:prepend|append)_file["\'\s=]+([^"\'\s;#]+)/i', $content, $matches ) ) {
            return false;
        }
        foreach ( $matches[1] as $target ) {
            if ( 'none' === strtolower( $target ) ) {
                continue;
            }
            $in_root = wp_normalize_path( dirname( $target ) ) === untrailingslashit( wp_normalize_path( self::home_path() ) );
            // Our bootstrap, or Wordfence's (sites may run both plugins)
            if ( ! self::is_bootstrap( $target ) && ! ( $in_root && 'wordfence-waf.php' === basename( $target ) ) ) {
                return true;
            }
        }
        return false;
    }

    /**
     * .user.ini works with PHP-FPM/CGI, php_value in .htaccess with mod_php and LiteSpeed.
     */
    private static function server_method(): ?string {
        $sapi = PHP_SAPI;
        if ( 'apache2handler' === $sapi || 'litespeed' === $sapi ) {
            return 'htaccess';
        }
        if ( ( false !== strpos( $sapi, 'cgi' ) || false !== strpos( $sapi, 'fpm' ) ) && '' !== (string) ini_get( 'user_ini.filename' ) ) {
            return 'user_ini';
        }
        return null;
    }

    private static function is_bootstrap( string $path ): bool {
        return '' !== $path && wp_normalize_path( $path ) === wp_normalize_path( self::bootstrap_path() );
    }

    /**
     * Directory of the site's index.php (differs from ABSPATH when WordPress lives in a subdirectory).
     */
    private static function home_path(): string {
        if ( ! function_exists( 'get_home_path' ) ) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        return trailingslashit( get_home_path() );
    }

    private static function write_bootstrap(): bool {
        $prepend = wp_normalize_path( METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/waf/prepend.php' );
        $storage = wp_normalize_path( Metzler_Webshield_Storage::dir() );

        $code  = "<?php\n";
        $code .= "// Metzler Webshield firewall: loaded before WordPress via auto_prepend_file (.user.ini / .htaccess).\n";
        $code .= "// Managed by the Metzler Webshield plugin. Does nothing when the plugin is removed.\n";
        $code .= "// Remove the auto_prepend_file line from .user.ini / .htaccess before deleting this file.\n";
        $code .= "if ( ! defined( 'METZLER_WEBSHIELD_BOOTSTRAP_LOADED' ) ) {\n";
        $code .= "\tdefine( 'METZLER_WEBSHIELD_BOOTSTRAP_LOADED', true );\n";
        $code .= "\tif ( is_file( " . var_export( $prepend, true ) . " ) ) {\n"; // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export -- builds a PHP string literal
        $code .= "\t\tif ( ! defined( 'METZLER_WEBSHIELD_STORAGE_DIR' ) ) {\n";
        $code .= "\t\t\tdefine( 'METZLER_WEBSHIELD_STORAGE_DIR', " . var_export( $storage, true ) . " );\n"; // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export
        $code .= "\t\t}\n";
        $code .= "\t\tinclude_once " . var_export( $prepend, true ) . ";\n"; // phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_var_export
        $code .= "\t}\n";
        $code .= "}\n";

        return false !== @file_put_contents( self::bootstrap_path(), $code, LOCK_EX ); // phpcs:ignore
    }

    private static function write_directive( string $method ): bool {
        $bootstrap = wp_normalize_path( self::bootstrap_path() );
        if ( false !== strpbrk( $bootstrap, "\"\r\n" ) ) {
            return false;
        }

        if ( 'htaccess' === $method ) {
            // php_value outside these modules (e.g. PHP-FPM) would be a 500 error for the whole site
            $lines = array();
            foreach ( array( 'mod_php7.c', 'mod_php.c', 'LiteSpeed', 'lsapi_module' ) as $module ) {
                $lines[] = '<IfModule ' . $module . '>';
                $lines[] = 'php_value auto_prepend_file "' . $bootstrap . '"';
                $lines[] = '</IfModule>';
            }
            if ( ! function_exists( 'insert_with_markers' ) ) {
                require_once ABSPATH . 'wp-admin/includes/misc.php';
            }
            return insert_with_markers( self::home_path() . '.htaccess', self::MARKER, $lines );
        }

        $file    = self::home_path() . (string) ini_get( 'user_ini.filename' );
        $content = file_exists( $file ) ? (string) file_get_contents( $file ) : ''; // phpcs:ignore
        $content = self::strip_user_ini_block( $content );
        $block   = '; BEGIN ' . self::MARKER . "\nauto_prepend_file = \"" . $bootstrap . "\"\n; END " . self::MARKER . "\n";

        return false !== @file_put_contents( $file, rtrim( $content ) . ( '' !== trim( $content ) ? "\n\n" : '' ) . $block, LOCK_EX ); // phpcs:ignore
    }

    private static function remove_directives(): void {
        $home = self::home_path();

        if ( file_exists( $home . '.htaccess' ) ) {
            if ( ! function_exists( 'insert_with_markers' ) ) {
                require_once ABSPATH . 'wp-admin/includes/misc.php';
            }
            insert_with_markers( $home . '.htaccess', self::MARKER, array() );
        }

        $ini = $home . ( (string) ini_get( 'user_ini.filename' ) ?: '.user.ini' );
        if ( file_exists( $ini ) ) {
            $content = (string) file_get_contents( $ini ); // phpcs:ignore
            $cleaned = self::strip_user_ini_block( $content );
            if ( $cleaned !== $content ) {
                @file_put_contents( $ini, '' !== trim( $cleaned ) ? rtrim( $cleaned ) . "\n" : '', LOCK_EX ); // phpcs:ignore
            }
        }
    }

    /**
     * INI files take ";" comments, so WordPress' insert_with_markers() ("#") can't be used here.
     */
    private static function strip_user_ini_block( string $content ): string {
        $pattern = '/\n*; BEGIN ' . preg_quote( self::MARKER, '/' ) . '\n.*?; END ' . preg_quote( self::MARKER, '/' ) . '\n?/s';
        return (string) preg_replace( $pattern, "\n", $content );
    }
}
