<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Sends files that are neither WordPress.org originals nor known to Metzler Webshield to the lab
 * (typically premium plugins and themes), so false alarms and new malware can be analyzed.
 *
 * Two steps: with telemetry sharing on, only the hashes are compared with the API ("lookup").
 * Contents are uploaded only for unknown files and only with the separate choice
 * "send this time" or "always send" (option metzler_webshield_auto_submit, "ask" by default).
 * Uploads are limited to 50 files per day; uploads, configuration, backups and the plugin itself are never sent.
 */
class Metzler_Webshield_Auto_Submit {

    const OPTION            = 'metzler_webshield_auto_submit';
    const MODES             = array( 'ask', 'always', 'never' );
    const DB_VERSION        = '1';
    const DB_VERSION_OPTION = 'metzler_webshield_files_db_version';
    const DAILY_TRANSIENT   = 'metzler_webshield_auto_submit_daily';
    const BACKOFF_TRANSIENT = 'metzler_webshield_auto_submit_backoff';
    const DAILY_LIMIT       = 50;
    const UPLOADS_PER_RUN   = 20;
    const LOOKUP_BATCH      = 5000;
    const TIME_BUDGET       = 20;

    private static function table(): string {
        global $wpdb;
        return $wpdb->prefix . 'metzler_webshield_files';
    }

    public static function create_table(): void {
        global $wpdb;
        $table_name = self::table(); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        $charset_collate = $wpdb->get_charset_collate(); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter

        $sql = "CREATE TABLE $table_name (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            path_hash char(32) NOT NULL,
            rel_path text NOT NULL,
            sha256 char(64) NOT NULL,
            size bigint(20) unsigned NOT NULL DEFAULT 0,
            mtime bigint(20) unsigned NOT NULL DEFAULT 0,
            state varchar(16) NOT NULL DEFAULT 'new',
            checked_at datetime NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY path_hash (path_hash),
            KEY state (state)
        ) $charset_collate;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( $sql );
        update_option( self::DB_VERSION_OPTION, self::DB_VERSION );
    }

    private static function ensure_table(): void {
        if ( get_option( self::DB_VERSION_OPTION ) !== self::DB_VERSION ) {
            self::create_table();
        }
    }

    public static function mode(): string {
        $mode = get_option( self::OPTION, 'ask' );
        return in_array( $mode, self::MODES, true ) ? $mode : 'ask';
    }

    /**
     * The hash comparison is part of telemetry sharing, so nothing happens without it.
     */
    public static function available(): bool {
        return Metzler_Webshield::telemetry_allowed() && self::mode() !== 'never';
    }

    /**
     * Hourly: find new or changed files, compare their hashes, upload what was agreed to.
     */
    public static function run(): void {
        if ( ! self::available() || get_transient( self::BACKOFF_TRANSIENT ) ) return;
        // WordPress.org originals are only known after a plugin scan, without it everything would look unknown
        if ( ! is_array( get_transient( 'metzler_webshield_plugin_verified' ) ) ) return;

        self::ensure_table();
        $started = microtime( true );
        self::collect( $started );
        self::lookup();
        self::upload( $started );
    }

    private static function collect( float $started ): void {
        global $wpdb;
        $table_name = self::table(); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        $verified = get_transient( 'metzler_webshield_plugin_verified' );
        $verified = is_array( $verified ) ? $verified : array();
        $own_dir = wp_normalize_path( METZLER_WEBSHIELD_PLUGIN_DIR );
        $abspath = wp_normalize_path( ABSPATH );
        $now = current_time( 'mysql', true );

        $known = array();
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        foreach ( $wpdb->get_results( "SELECT path_hash, size, mtime FROM $table_name" ) as $row ) {
            $known[ $row->path_hash ] = $row->size . '|' . $row->mtime;
        }

        $roots = array( WP_PLUGIN_DIR, defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins', get_theme_root() );
        foreach ( $roots as $root ) {
            if ( ! is_dir( $root ) ) continue;
            try {
                $iterator = new RecursiveIteratorIterator( new RecursiveDirectoryIterator( $root, FilesystemIterator::SKIP_DOTS ) );
                foreach ( $iterator as $file ) {
                    if ( microtime( true ) - $started > self::TIME_BUDGET ) return; // The rest follows next hour
                    if ( ! $file->isFile() ) continue;

                    $full = wp_normalize_path( $file->getPathname() );
                    if ( str_starts_with( $full, $own_dir ) || ! str_starts_with( $full, $abspath ) ) continue;
                    $rel_path = substr( $full, strlen( $abspath ) );
                    if ( ! Metzler_Webshield_Scanner_Core::is_executable_file( $rel_path ) || isset( $verified[ $rel_path ] ) ) continue;
                    if ( Metzler_Webshield_Findings::is_blocked_sample( $rel_path ) || $file->getSize() > Metzler_Webshield_Findings::SAMPLE_MAX_SIZE ) continue;

                    $path_hash = md5( $rel_path );
                    $signature = $file->getSize() . '|' . $file->getMTime();
                    if ( isset( $known[ $path_hash ] ) && $known[ $path_hash ] === $signature ) continue;

                    // New or changed: compare it again
                    // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
                    $wpdb->query( $wpdb->prepare(
                        "INSERT INTO $table_name (path_hash, rel_path, sha256, size, mtime, state, checked_at) VALUES (%s, %s, %s, %d, %d, 'new', %s)
                         ON DUPLICATE KEY UPDATE sha256 = VALUES(sha256), size = VALUES(size), mtime = VALUES(mtime), state = 'new', checked_at = VALUES(checked_at)",
                        $path_hash, $rel_path, (string) hash_file( 'sha256', $full ), $file->getSize(), $file->getMTime(), $now
                    ) );
                }
            } catch ( Exception $e ) {
                continue;
            }
        }
    }

    private static function lookup(): void {
        global $wpdb;
        $table_name = self::table(); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $rows = $wpdb->get_results( $wpdb->prepare( "SELECT id, sha256 FROM $table_name WHERE state = 'new' LIMIT %d", self::LOOKUP_BATCH ) );
        if ( empty( $rows ) ) return;

        $files = array();
        foreach ( $rows as $row ) {
            $files[] = array( 'sha256' => $row->sha256 );
        }
        $response = Metzler_Webshield::post_signed( '/samples/lookup', array( 'files' => $files ), 30 );
        if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) !== 200 ) {
            set_transient( self::BACKOFF_TRANSIENT, 1, HOUR_IN_SECONDS );
            return;
        }

        $data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
        $unknown = array_flip( (array) ( $data['unknown'] ?? array() ) );
        foreach ( $rows as $row ) {
            $wpdb->update( $table_name, array( 'state' => isset( $unknown[ $row->sha256 ] ) ? 'unknown' : 'known' ), array( 'id' => $row->id ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter
        }
    }

    /**
     * Uploads files the owner agreed to: "queued" by "send this time", all unknown ones with "always".
     */
    public static function upload( float $started ): int {
        if ( ! self::available() ) return 0;
        self::ensure_table();

        global $wpdb;
        $table_name = self::table(); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        $sent_today = (int) get_transient( self::DAILY_TRANSIENT );
        $budget = min( self::UPLOADS_PER_RUN, self::DAILY_LIMIT - $sent_today );
        if ( $budget <= 0 ) return 0;

        $states = self::mode() === 'always' ? "'queued','unknown'" : "'queued'";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $rows = $wpdb->get_results( $wpdb->prepare( "SELECT * FROM $table_name WHERE state IN ($states) ORDER BY id ASC LIMIT %d", $budget ) );

        $sent = 0;
        foreach ( $rows as $row ) {
            if ( microtime( true ) - $started > self::TIME_BUDGET ) break;
            $abs_path = wp_normalize_path( ABSPATH . $row->rel_path );
            if ( ! is_file( $abs_path ) || hash_file( 'sha256', $abs_path ) !== $row->sha256 ) {
                $wpdb->update( $table_name, array( 'state' => 'new' ), array( 'id' => $row->id ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter
                continue;
            }

            $response = Metzler_Webshield_Findings::send_sample( array(
                'sha256'    => $row->sha256,
                'rel_path'  => $row->rel_path,
                'size'      => (int) $row->size,
                'mtime'     => (int) $row->mtime,
                'source'    => 'unknown-file',
                'component' => Metzler_Webshield_Findings::component_of( $abs_path ),
                'auto'      => true,
            ), $abs_path );
            if ( is_wp_error( $response ) ) {
                set_transient( self::BACKOFF_TRANSIENT, 1, HOUR_IN_SECONDS );
                break;
            }

            $wpdb->update( $table_name, array( 'state' => 'submitted' ), array( 'id' => $row->id ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $sent++;
        }

        if ( $sent > 0 ) {
            set_transient( self::DAILY_TRANSIENT, $sent_today + $sent, DAY_IN_SECONDS );
        }
        return $sent;
    }

    /**
     * Unknown files waiting for the owner's choice (only shown while the mode is "ask").
     */
    public static function pending( int $limit = 50 ): array {
        if ( get_option( self::DB_VERSION_OPTION ) !== self::DB_VERSION ) return array( 'count' => 0, 'files' => array() );
        global $wpdb;
        $table_name = self::table(); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        // phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $count = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table_name WHERE state = 'unknown'" );
        $files = $count > 0 ? $wpdb->get_col( $wpdb->prepare( "SELECT rel_path FROM $table_name WHERE state = 'unknown' ORDER BY rel_path ASC LIMIT %d", $limit ) ) : array();
        // phpcs:enable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        return array( 'count' => $count, 'files' => $files );
    }

    public static function should_ask(): bool {
        return self::mode() === 'ask' && self::available() && self::pending( 1 )['count'] > 0;
    }

    /**
     * The owner's answer in the dashboard card: "once", "always" or "never".
     */
    public static function choose( string $choice ): int {
        global $wpdb;
        if ( $choice === 'never' ) {
            update_option( self::OPTION, 'never' );
            return 0;
        }
        if ( $choice === 'always' ) {
            update_option( self::OPTION, 'always' );
        }
        self::ensure_table();
        $wpdb->query( "UPDATE " . self::table() . " SET state = 'queued' WHERE state = 'unknown'" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.NotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        // Start right away within the limits, the rest follows hourly
        return self::upload( microtime( true ) );
    }
}
