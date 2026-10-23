<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Compares the PHP files of plugins and themes that are not WordPress.org originals (typically premium
 * plugins) with Metzler Webshield, so false alarms can be fixed and modified copies are found.
 *
 * With telemetry sharing on, hash, path, size and plugin version of these files go to the API ("lookup"),
 * never the content. The answer says which files the lab decided as clean, those are skipped by the file
 * scanner like WordPress.org originals and their open warnings are resolved. All files are compared again
 * every few hours, so approvals made later and revoked approvals reach the site as well. Files the lab
 * decided as malicious or suspicious are reported in the log with a quarantine button.
 *
 * Contents are only uploaded for files the lab does not know yet and that either a scanner reported or
 * differ from the vendor's original of their plugin version, and only with the separate choice
 * "send this time" or "always send" (option metzler_webshield_auto_submit, "ask" by default).
 * Uploads are limited to 50 files per day; uploads, configuration, backups and the plugin itself are never sent.
 */
class Metzler_Webshield_Auto_Submit {

    const OPTION            = 'metzler_webshield_auto_submit';
    const MODES             = array( 'ask', 'always', 'never' );
    const DB_VERSION        = '2';
    const DB_VERSION_OPTION = 'metzler_webshield_files_db_version';
    const DAILY_TRANSIENT   = 'metzler_webshield_auto_submit_daily';
    const BACKOFF_TRANSIENT = 'metzler_webshield_auto_submit_backoff';
    const DAILY_LIMIT       = 50;
    const UPLOADS_PER_RUN   = 20;
    const LOOKUP_BATCH      = 5000;
    const RECHECK_AFTER     = 6 * 3600;
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
        $installed = get_option( self::DB_VERSION_OPTION );
        if ( $installed === self::DB_VERSION ) return;
        self::create_table();
        if ( $installed === '1' ) {
            // 2.0.7 marked every unknown file for upload, now only reported or modified ones are wanted
            global $wpdb;
            $table_name = self::table(); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
            // phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query( "UPDATE $table_name SET state = 'new' WHERE state IN ('unknown','queued','known')" );
            $wpdb->query( "UPDATE $table_name SET checked_at = '2000-01-01 00:00:00'" );
            // phpcs:enable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
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
        self::refresh();
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
        $rows = $wpdb->get_results( $wpdb->prepare( "SELECT id, path_hash, rel_path, sha256, size, state FROM $table_name WHERE state = 'new' LIMIT %d", self::LOOKUP_BATCH ) );
        if ( empty( $rows ) ) return;
        self::compare( $rows );
    }

    /**
     * Decisions change after the first lookup: the lab approves files, revokes an approval or wants a file
     * that differs from an original uploaded later. Every file is compared again at most every few hours.
     */
    private static function refresh(): void {
        if ( get_transient( self::BACKOFF_TRANSIENT ) ) return;
        global $wpdb;
        $table_name = self::table(); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $rows = $wpdb->get_results( $wpdb->prepare(
            "SELECT id, path_hash, rel_path, sha256, size, state FROM $table_name WHERE state != 'new' AND checked_at < %s ORDER BY checked_at ASC LIMIT %d",
            gmdate( 'Y-m-d H:i:s', time() - self::RECHECK_AFTER ),
            self::LOOKUP_BATCH
        ) );

        // Files of removed or updated plugins are forgotten
        $gone = array();
        foreach ( $rows as $index => $row ) {
            if ( ! is_file( ABSPATH . $row->rel_path ) ) {
                $gone[] = (int) $row->id;
                unset( $rows[ $index ] );
            }
        }
        foreach ( array_chunk( $gone, 500 ) as $chunk ) {
            $in = implode( ',', $chunk );
            $wpdb->query( "DELETE FROM $table_name WHERE id IN ($in)" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        }

        if ( ! empty( $rows ) ) {
            self::compare( array_values( $rows ) );
        }
    }

    /**
     * Compares files with the API and sets what happens with each of them:
     * "clean" was approved by the lab and is skipped by the scanner, "unknown" is wanted for analysis
     * because a scanner reported it or it differs from the original of its plugin version, "known"
     * needs nothing. Files already sent keep their state unless they became clean, files the owner
     * queued stay queued while they are still wanted.
     */
    private static function compare( array $rows ): void {
        $answer = self::ask( $rows );
        if ( $answer === null ) return;
        $flagged = self::flagged( $rows );

        $states = array();
        $cleaned = array();
        $harmful = array();
        foreach ( $rows as $row ) {
            $wanted = isset( $answer['request'][ $row->sha256 ] )
                || ( isset( $answer['unknown'][ $row->sha256 ] ) && isset( $flagged[ $row->path_hash . '|' . $row->sha256 ] ) );
            if ( isset( $answer['malicious'][ $row->sha256 ] ) || isset( $answer['suspicious'][ $row->sha256 ] ) ) {
                $state = isset( $answer['malicious'][ $row->sha256 ] ) ? 'malicious' : 'suspicious';
                if ( $row->state !== $state ) $harmful[ $state ][] = $row->rel_path; // Warned once per decision
            } elseif ( isset( $answer['clean'][ $row->sha256 ] ) ) {
                if ( $row->state !== 'clean' ) $cleaned[] = $row->rel_path;
                $state = 'clean';
            } elseif ( $row->state === 'submitted' ) {
                $state = 'submitted';
            } elseif ( $wanted ) {
                $state = $row->state === 'queued' ? 'queued' : 'unknown';
            } else {
                $state = 'known'; // Also an approval that was revoked: the scanner checks the file again
            }
            $states[ $state ][] = $row->id;
        }
        self::set_states( $states );
        self::resolve_clean( $cleaned );
        self::warn_harmful( $harmful );
    }

    /**
     * Files the lab decided as malicious or suspicious: a warning with a quarantine button, recorded as a
     * finding like a scanner result. Files the owner sent in themselves get the lab result through their ticket.
     */
    private static function warn_harmful( array $harmful ): void {
        $ticket_paths = array_flip( wp_list_pluck( Metzler_Webshield_Findings::lab_tickets(), 'path' ) );
        foreach ( $harmful as $status => $rel_paths ) {
            foreach ( $rel_paths as $rel_path ) {
                $abs_path = ABSPATH . $rel_path;
                if ( ! is_file( $abs_path ) || isset( $ticket_paths[ $rel_path ] ) ) continue;
                $actions = '<br><button type="button" class="button button-small button-primary metzler-webshield-q-move" data-path="' . esc_attr( $rel_path ) . '" style="background:#d63638;border-color:#d63638;">' . esc_html__( 'Move to quarantine', 'metzler-webshield' ) . '</button>';
                if ( $status === 'malicious' ) {
                    /* translators: %s: file path */
                    Metzler_Webshield_Logger::log( sprintf( __( 'Critical: the lab confirmed malware in %s', 'metzler-webshield' ), esc_html( $rel_path ) ) . $actions, 'files', 'error' );
                } else {
                    /* translators: %s: file path */
                    Metzler_Webshield_Logger::log( sprintf( __( 'The lab rated this file as suspicious, it differs from the original of its plugin or contains questionable code. Move it to quarantine if the site works without it: %s', 'metzler-webshield' ), esc_html( $rel_path ) ) . $actions, 'files', 'warning' );
                }
                Metzler_Webshield_Findings::report( $rel_path, $abs_path, 'lab', 'lab-' . $status );
            }
        }
    }

    /**
     * Files a scanner reported with exactly this content, as "path_hash|sha256" keys.
     */
    private static function flagged( array $rows ): array {
        $findings_table = Metzler_Webshield_Findings::table_if_exists();
        if ( $findings_table === '' ) return array();
        global $wpdb;
        $flagged = array();
        foreach ( array_chunk( array_unique( wp_list_pluck( $rows, 'path_hash' ) ), 500 ) as $chunk ) {
            $in = implode( ',', array_map( function ( $hash ) { return "'" . esc_sql( $hash ) . "'"; }, $chunk ) );
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            foreach ( $wpdb->get_results( "SELECT path_hash, sha256 FROM $findings_table WHERE path_hash IN ($in)" ) as $finding ) {
                $flagged[ $finding->path_hash . '|' . $finding->sha256 ] = true;
            }
        }
        return $flagged;
    }

    /**
     * Compares files with the API: hash, path relative to the WordPress directory, size and plugin version.
     *
     * @return array|null Flipped lists {unknown, clean, malicious, suspicious, request}, null while the API is unreachable
     */
    private static function ask( array $rows ): ?array {
        $files = array();
        foreach ( $rows as $row ) {
            $files[] = array(
                'sha256'    => $row->sha256,
                'rel_path'  => $row->rel_path,
                'size'      => (int) $row->size,
                'component' => Metzler_Webshield_Findings::component_of( wp_normalize_path( ABSPATH . $row->rel_path ) ),
            );
        }
        $response = Metzler_Webshield::post_signed( '/samples/lookup', array( 'files' => $files ), 30 );
        if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) !== 200 ) {
            set_transient( self::BACKOFF_TRANSIENT, 1, HOUR_IN_SECONDS );
            return null;
        }

        $data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
        return array(
            'unknown'    => array_flip( (array) ( $data['unknown'] ?? array() ) ),
            'clean'      => array_flip( (array) ( $data['clean'] ?? array() ) ),
            'malicious'  => array_flip( (array) ( $data['malicious'] ?? array() ) ),
            'suspicious' => array_flip( (array) ( $data['suspicious'] ?? array() ) ),
            'request'    => array_flip( (array) ( $data['request'] ?? array() ) ),
        );
    }

    /**
     * @param array $states state => row ids; the check time is set to now
     */
    private static function set_states( array $states ): void {
        global $wpdb;
        $table_name = self::table(); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        $now = current_time( 'mysql', true );
        foreach ( $states as $state => $ids ) {
            foreach ( array_chunk( $ids, 500 ) as $chunk ) {
                $in = implode( ',', array_map( 'intval', $chunk ) );
                // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
                $wpdb->query( $wpdb->prepare( "UPDATE $table_name SET state = %s, checked_at = %s WHERE id IN ($in)", $state, $now ) );
            }
        }
    }

    /**
     * Files the lab just approved: their open warnings are resolved.
     */
    private static function resolve_clean( array $rel_paths ): void {
        if ( empty( $rel_paths ) ) return;
        foreach ( $rel_paths as $rel_path ) {
            Metzler_Webshield_Logger::resolve_path_logs( $rel_path );
        }
        /* translators: %d: number of files */
        Metzler_Webshield_Logger::log( sprintf( _n( '%d file of a premium plugin or theme was confirmed as clean by the Metzler Webshield lab, its warnings were resolved.', '%d files of premium plugins or themes were confirmed as clean by the Metzler Webshield lab, their warnings were resolved.', count( $rel_paths ), 'metzler-webshield' ), count( $rel_paths ) ), 'system', 'success' );
    }

    /**
     * True if the lab decided the file's current content as clean, the file scanner then skips it
     * like a WordPress.org original. A changed file has a different hash and is scanned again.
     */
    public static function is_cloud_clean( string $rel_path, string $abs_path ): bool {
        if ( get_option( self::DB_VERSION_OPTION ) !== self::DB_VERSION || ! self::available() ) return false;
        global $wpdb;
        $table_name = self::table(); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $sha256 = $wpdb->get_var( $wpdb->prepare( "SELECT sha256 FROM $table_name WHERE path_hash = %s AND state = 'clean'", md5( $rel_path ) ) );
        return is_string( $sha256 ) && hash_equals( $sha256, (string) hash_file( 'sha256', $abs_path ) );
    }

    /**
     * Uploads files the owner agreed to: "queued" by "send this time", all unknown ones with "always".
     * Files a scanner reported go first. Right before the upload the hashes are compared again,
     * so files another site sent in meanwhile do not use up the daily limit.
     */
    public static function upload( float $started ): int {
        if ( ! self::available() || get_transient( self::BACKOFF_TRANSIENT ) ) return 0;
        self::ensure_table();

        global $wpdb;
        $table_name = self::table(); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        $sent_today = (int) get_transient( self::DAILY_TRANSIENT );
        $budget = min( self::UPLOADS_PER_RUN, self::DAILY_LIMIT - $sent_today );
        if ( $budget <= 0 ) return 0;

        $states = self::mode() === 'always' ? "'queued','unknown'" : "'queued'";
        $findings_table = Metzler_Webshield_Findings::table_if_exists();
        $detection = $findings_table === ''
            ? "''"
            : "COALESCE( ( SELECT x.detection FROM $findings_table x WHERE x.path_hash = f.path_hash AND x.sha256 = f.sha256 LIMIT 1 ), '' )";
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $rows = $wpdb->get_results( $wpdb->prepare( "SELECT f.*, $detection AS detection FROM $table_name f WHERE f.state IN ($states) ORDER BY $detection = '', f.id ASC LIMIT %d", $budget * 5 ) );
        if ( empty( $rows ) ) return 0;

        $answer = self::ask( $rows );
        if ( $answer === null ) return 0;
        $skipped = array();
        $cleaned = array();
        foreach ( $rows as $index => $row ) {
            if ( isset( $answer['unknown'][ $row->sha256 ] ) ) continue;
            if ( isset( $answer['clean'][ $row->sha256 ] ) ) {
                $skipped['clean'][] = $row->id;
                $cleaned[] = $row->rel_path;
            } else {
                $skipped['known'][] = $row->id;
            }
            unset( $rows[ $index ] );
        }
        self::set_states( $skipped );
        self::resolve_clean( $cleaned );

        $sent = 0;
        foreach ( array_slice( $rows, 0, $budget ) as $row ) {
            if ( microtime( true ) - $started > self::TIME_BUDGET ) break;
            $abs_path = wp_normalize_path( ABSPATH . $row->rel_path );
            if ( ! is_file( $abs_path ) || hash_file( 'sha256', $abs_path ) !== $row->sha256 ) {
                $wpdb->update( $table_name, array( 'state' => 'new' ), array( 'id' => $row->id ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter
                continue;
            }

            $meta = array(
                'sha256'    => $row->sha256,
                'rel_path'  => $row->rel_path,
                'size'      => (int) $row->size,
                'mtime'     => (int) $row->mtime,
                'source'    => 'unknown-file',
                'component' => Metzler_Webshield_Findings::component_of( $abs_path ),
                'auto'      => true,
            );
            if ( $row->detection !== '' ) {
                $meta['detection'] = $row->detection; // The lab holds reported files back from bulk approvals
            }
            $response = Metzler_Webshield_Findings::send_sample( $meta, $abs_path );
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
     * Files wanted for analysis waiting for the owner's choice (only shown while the mode is "ask").
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
