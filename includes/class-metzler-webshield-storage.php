<?php
if ( ! defined( 'ABSPATH' ) && ! defined( 'METZLER_WEBSHIELD_WAF_PREPENDED' ) ) exit;

/**
 * Private on-disk storage for security data (telemetry buffer, WAF key, rate-limit buckets).
 *
 * The directory lives inside wp-content/uploads and is therefore web-reachable. .htaccess / web.config
 * only protect Apache, LiteSpeed and IIS — Nginx ignores them. To stay safe on every server, all sensitive
 * files use a .php extension and start with an exit guard, so a direct HTTP request returns an empty body.
 *
 * Deliberately free of late WordPress functions so the WAF and rate limiter can use it early.
 */
class Metzler_Webshield_Storage {

    const GUARD = "<?php exit; ?>\n";

    const TELEMETRY_FILE  = 'telemetry.php';
    const PROCESSING_FILE = 'telemetry-processing.php';
    const WAF_KEY_FILE    = 'waf-key.php';

    public static function dir(): string {
        // Set by the firewall bootstrap (auto_prepend_file), which runs before WordPress defines WP_CONTENT_DIR
        if ( defined( 'METZLER_WEBSHIELD_STORAGE_DIR' ) ) {
            return METZLER_WEBSHIELD_STORAGE_DIR;
        }
        if ( defined( 'WP_CONTENT_DIR' ) ) {
            return WP_CONTENT_DIR . '/uploads/metzler-webshield';
        }
        if ( function_exists( 'wp_upload_dir' ) ) {
            $up = wp_upload_dir();
            return ( $up['basedir'] ?? '' ) . '/metzler-webshield';
        }
        return sys_get_temp_dir() . '/metzler-webshield';
    }

    public static function path( string $file ): string {
        return self::dir() . '/' . $file;
    }

    /**
     * Creates the storage directory (or a subdirectory) with deny rules for every common web server.
     */
    public static function ensure_dir( string $sub = '' ): string {
        $dir = self::dir() . ( $sub !== '' ? '/' . $sub : '' );
        if ( ! is_dir( $dir ) ) {
            @mkdir( $dir, 0755, true ); // phpcs:ignore
        }

        foreach ( self::protection_files() as $name => $content ) {
            if ( ! file_exists( $dir . '/' . $name ) ) {
                @file_put_contents( $dir . '/' . $name, $content ); // phpcs:ignore
            }
        }

        return $dir;
    }

    private static function protection_files(): array {
        return array(
            '.htaccess'  => "# Deny direct web access to security data\n<IfModule mod_authz_core.c>\n    Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n    Order Deny,Allow\n    Deny from all\n</IfModule>\n",
            'web.config' => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<configuration>\n  <system.webServer>\n    <authorization>\n      <deny users=\"*\" />\n    </authorization>\n  </system.webServer>\n</configuration>\n",
            'index.php'  => "<?php // Silence is golden.",
        );
    }

    /**
     * True for files this class wrote itself, so the malware/FIM scanners don't flag them.
     * Only exact protection templates or files starting with the exit guard qualify — anything
     * after the guard can never execute, so a planted shell cannot hide behind this check.
     */
    public static function is_own_file( string $path ): bool {
        $dir  = str_replace( '\\', '/', self::dir() ) . '/';
        $path = str_replace( '\\', '/', $path );
        if ( strpos( $path, $dir ) !== 0 || ! is_file( $path ) ) {
            return false;
        }

        $templates = self::protection_files();
        $name      = basename( $path );
        if ( isset( $templates[ $name ] ) ) {
            return @file_get_contents( $path ) === $templates[ $name ]; // phpcs:ignore
        }

        $fh = @fopen( $path, 'r' ); // phpcs:ignore
        if ( ! $fh ) {
            return false;
        }
        $head = fread( $fh, strlen( self::GUARD ) ); // phpcs:ignore
        fclose( $fh ); // phpcs:ignore
        return $head === self::GUARD;
    }

    /**
     * Appends one telemetry event. The exit guard is written under the same lock as the first line,
     * so concurrent writers can never produce a file that starts with raw data.
     */
    public static function append_telemetry( array $data ): void {
        self::ensure_dir();
        self::append_line( self::path( self::TELEMETRY_FILE ), json_encode( $data ) );
    }

    private static function append_line( string $file, string $line ): void {
        $fh = @fopen( $file, 'c' ); // phpcs:ignore
        if ( ! $fh ) {
            return;
        }
        if ( flock( $fh, LOCK_EX ) ) {
            fseek( $fh, 0, SEEK_END );
            if ( ftell( $fh ) === 0 ) {
                fwrite( $fh, self::GUARD ); // phpcs:ignore
            }
            fwrite( $fh, $line . "\n" ); // phpcs:ignore
            fflush( $fh );
            flock( $fh, LOCK_UN );
        }
        fclose( $fh ); // phpcs:ignore
    }

    public static function has_pending_telemetry(): bool {
        $file = self::path( self::TELEMETRY_FILE );
        return file_exists( $file ) && filesize( $file ) > strlen( self::GUARD );
    }

    /**
     * Reads a JSONL file, skipping the exit guard.
     */
    public static function read_lines( string $file ): array {
        $lines = @file( $file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES ); // phpcs:ignore
        if ( empty( $lines ) ) {
            return array();
        }
        return array_values( array_filter( $lines, function ( $line ) {
            return strpos( $line, '<?php' ) !== 0;
        } ) );
    }

    /**
     * Writes a single guarded blob (key files, rate-limit buckets).
     */
    public static function write_guarded( string $file, string $content ): void {
        @file_put_contents( $file, self::GUARD . $content, LOCK_EX ); // phpcs:ignore
    }

    public static function read_guarded( string $file ): string {
        $content = @file_get_contents( $file ); // phpcs:ignore
        if ( ! is_string( $content ) ) {
            return '';
        }
        if ( strpos( $content, self::GUARD ) === 0 ) {
            $content = substr( $content, strlen( self::GUARD ) );
        }
        return $content;
    }

    public static function save_waf_key( string $token ): void {
        self::ensure_dir();
        self::write_guarded( self::path( self::WAF_KEY_FILE ), $token );
    }

    public static function get_waf_key(): string {
        $file = self::path( self::WAF_KEY_FILE );
        if ( file_exists( $file ) ) {
            return trim( self::read_guarded( $file ) );
        }
        // Not yet migrated (see migrate_legacy_files)
        $legacy = self::path( 'waf.key' );
        return file_exists( $legacy ) ? trim( (string) @file_get_contents( $legacy ) ) : ''; // phpcs:ignore
    }

    public static function delete_waf_key(): void {
        @unlink( self::path( self::WAF_KEY_FILE ) ); // phpcs:ignore
        @unlink( self::path( 'waf.key' ) ); // phpcs:ignore
    }

    /**
     * Moves data out of the old, publicly downloadable files (<= 1.0.1) and deletes them.
     */
    public static function migrate_legacy_files(): void {
        $dir = self::dir();

        foreach ( array( 'telemetry_processing.jsonl', 'telemetry.jsonl' ) as $legacy ) {
            $file = $dir . '/' . $legacy;
            if ( ! file_exists( $file ) ) {
                continue;
            }
            $lines = @file( $file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES ); // phpcs:ignore
            @unlink( $file ); // phpcs:ignore
            foreach ( (array) $lines as $line ) {
                self::append_line( self::path( self::TELEMETRY_FILE ), $line );
            }
        }

        $legacy_key = $dir . '/waf.key';
        if ( file_exists( $legacy_key ) ) {
            $token = trim( (string) @file_get_contents( $legacy_key ) ); // phpcs:ignore
            // A legacy file can only have been written by an older plugin version (e.g. after a downgrade),
            // so it is always newer than an existing waf-key.php.
            if ( $token !== '' ) {
                self::write_guarded( self::path( self::WAF_KEY_FILE ), $token );
            }
            @unlink( $legacy_key ); // phpcs:ignore
        }

        // Rate-limit buckets are short-lived; old plain JSON ones can simply go.
        $old_buckets = glob( $dir . '/rl/*.json' );
        if ( ! empty( $old_buckets ) ) {
            foreach ( $old_buckets as $bucket ) {
                @unlink( $bucket ); // phpcs:ignore
            }
        }
    }
}
