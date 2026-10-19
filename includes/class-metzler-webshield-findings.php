<?php
if ( ! defined( 'ABSPATH' ) ) exit;

/**
 * Structured record of every file the scanners report and what the site owner did with it.
 *
 * With telemetry sharing enabled, new findings and verdicts are sent to the Threat Intelligence API:
 * WordPress-relative path, SHA-256, size, modification time, rule id and the plugin or theme it
 * belongs to. Never the file content, the absolute path or a user name. Findings recorded while
 * telemetry is off are never sent later.
 *
 * Separately, a site owner who is unsure can send a single reported file to the lab ("Prüflabor").
 * That needs a connected site but no telemetry opt-in: the click on the file is the consent.
 */
class Metzler_Webshield_Findings {

    const DB_VERSION        = '1';
    const DB_VERSION_OPTION = 'metzler_webshield_findings_db_version';
    const BATCH_SIZE        = 500;
    const BACKOFF_TRANSIENT = 'metzler_webshield_findings_backoff';

    const LAB_TICKETS_OPTION  = 'metzler_webshield_lab_tickets';
    const LAB_DAILY_TRANSIENT = 'metzler_webshield_lab_daily';
    const LAB_DAILY_LIMIT     = 10;
    const SAMPLE_MAX_SIZE     = 2 * 1024 * 1024;

    private static function table(): string {
        global $wpdb;
        return $wpdb->prefix . 'metzler_webshield_findings';
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
            source varchar(32) NOT NULL,
            detection varchar(64) NOT NULL,
            component_type varchar(16) NOT NULL DEFAULT '',
            component_slug varchar(191) NOT NULL DEFAULT '',
            component_version varchar(64) NOT NULL DEFAULT '',
            user_verdict varchar(16) NOT NULL DEFAULT '',
            lab_status varchar(16) NOT NULL DEFAULT '',
            lab_ticket varchar(64) NOT NULL DEFAULT '',
            shareable tinyint(1) NOT NULL DEFAULT 0,
            found_at datetime NOT NULL,
            last_seen datetime NOT NULL,
            sent_at datetime DEFAULT NULL,
            verdict_sent_at datetime DEFAULT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY finding (path_hash,sha256,detection),
            KEY path_hash (path_hash)
        ) $charset_collate;";

        require_once ABSPATH . 'wp-admin/includes/upgrade.php';
        dbDelta( $sql );
        update_option( self::DB_VERSION_OPTION, self::DB_VERSION );
    }

    /**
     * Plugin updates do not run the activation hook, so the table is created on first use.
     */
    private static function ensure_table(): void {
        if ( get_option( self::DB_VERSION_OPTION ) !== self::DB_VERSION ) {
            self::create_table();
        }
    }

    /**
     * Records a finding. A file reported again with the same content and rule only updates last_seen.
     */
    public static function report( string $rel_path, string $abs_path, string $source, string $detection ): void {
        if ( ! is_file( $abs_path ) || ! is_readable( $abs_path ) ) return;
        self::ensure_table();

        global $wpdb;
        $table_name = self::table(); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        $rel_path = ltrim( str_replace( '\\', '/', $rel_path ), '/' );
        $component = self::component_of( $abs_path );
        $now = current_time( 'mysql', true );
        $shareable = Metzler_Webshield::telemetry_allowed() ? 1 : 0;

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query( $wpdb->prepare(
            "INSERT INTO $table_name (path_hash, rel_path, sha256, size, mtime, source, detection, component_type, component_slug, component_version, shareable, found_at, last_seen)
             VALUES (%s, %s, %s, %d, %d, %s, %s, %s, %s, %s, %d, %s, %s)
             ON DUPLICATE KEY UPDATE last_seen = VALUES(last_seen)",
            md5( $rel_path ),
            $rel_path,
            (string) hash_file( 'sha256', $abs_path ),
            (int) filesize( $abs_path ),
            (int) filemtime( $abs_path ),
            $source,
            $detection,
            $component['type'],
            $component['slug'],
            $component['version'],
            $shareable,
            $now,
            $now
        ) );
    }

    /**
     * The site owner's decision about a reported file: safe, quarantined, restored or deleted.
     */
    public static function set_verdict( string $rel_path, string $verdict ): void {
        self::ensure_table();

        global $wpdb;
        $table_name = self::table(); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        $rel_path = ltrim( str_replace( '\\', '/', $rel_path ), '/' );
        // Only pending for the API if sharing is on now, so nothing is sent for decisions made while it was off
        $verdict_sent_at = Metzler_Webshield::telemetry_allowed() ? null : current_time( 'mysql', true );

        $wpdb->update( $table_name, // phpcs:ignore WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter
            array( 'user_verdict' => $verdict, 'verdict_sent_at' => $verdict_sent_at ),
            array( 'path_hash' => md5( $rel_path ) )
        );
    }

    /**
     * Sends pending findings and verdicts. Called by the telemetry cron, only while sharing is allowed.
     * Errors (API down, endpoint not deployed yet) keep the events pending for the next run.
     */
    public static function sync(): void {
        if ( ! Metzler_Webshield::telemetry_allowed() ) return;
        if ( get_option( self::DB_VERSION_OPTION ) !== self::DB_VERSION ) return; // Nothing was ever recorded
        // The telemetry sync also runs while the dashboard polls the log, an unreachable API must not slow that down
        if ( get_transient( self::BACKOFF_TRANSIENT ) ) return;

        global $wpdb;
        $table_name = self::table(); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter

        // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $rows = $wpdb->get_results( $wpdb->prepare(
            "SELECT * FROM $table_name
             WHERE shareable = 1 AND ( sent_at IS NULL OR ( user_verdict != '' AND verdict_sent_at IS NULL ) )
             ORDER BY id ASC LIMIT %d",
            self::BATCH_SIZE
        ) );
        if ( empty( $rows ) ) return;

        $env = array(
            'wp'        => get_bloginfo( 'version' ),
            'php'       => PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION,
            'webshield' => METZLER_WEBSHIELD_VERSION,
        );
        $events = array();
        foreach ( $rows as $row ) {
            $event = array(
                'event'     => $row->sent_at === null ? 'found' : 'verdict',
                'found_at'  => gmdate( 'c', strtotime( $row->found_at . ' UTC' ) ),
                'rel_path'  => $row->rel_path,
                'sha256'    => $row->sha256,
                'size'      => (int) $row->size,
                'mtime'     => (int) $row->mtime,
                'source'    => $row->source,
                'detection' => $row->detection,
                'component' => array( 'type' => $row->component_type, 'slug' => $row->component_slug, 'version' => $row->component_version ),
                'env'       => $env,
            );
            if ( $row->user_verdict !== '' ) {
                $event['user_verdict'] = $row->user_verdict;
            }
            $events[] = $event;
        }

        $response = Metzler_Webshield::post_signed( '/telemetry/findings/batch', array( 'events' => $events ) );
        if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) !== 200 ) {
            set_transient( self::BACKOFF_TRANSIENT, 1, 15 * MINUTE_IN_SECONDS );
            return;
        }

        // A "found" event carries the verdict known at that time, so both are done
        $ids = implode( ',', array_map( 'intval', wp_list_pluck( $rows, 'id' ) ) );
        $now = current_time( 'mysql', true );
        // phpcs:disable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->query( $wpdb->prepare( "UPDATE $table_name SET sent_at = %s WHERE id IN ($ids) AND sent_at IS NULL", $now ) );
        $wpdb->query( $wpdb->prepare( "UPDATE $table_name SET verdict_sent_at = %s WHERE id IN ($ids) AND user_verdict != ''", $now ) );
        // phpcs:enable WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
    }

    /**
     * Files that are never sent, whatever a scanner reported: configuration with credentials,
     * database dumps, backups, and the plugin's own storage apart from the quarantine.
     */
    public static function is_blocked_sample( string $rel_path ): bool {
        $rel_path = strtolower( ltrim( str_replace( '\\', '/', $rel_path ), '/' ) );
        $basename = basename( $rel_path );
        if ( in_array( $basename, array( 'wp-config.php', 'wp-config-sample.php', '.env' ), true ) || str_starts_with( $basename, '.env.' ) ) {
            return true;
        }
        if ( preg_match( '/\.(sql|sql\.gz|sqlite|db|zip|tar|tgz|gz|bz2|7z|rar|wpress|bak|log)$/', $basename ) ) {
            return true;
        }
        return str_contains( $rel_path, '/metzler-webshield/' ) && str_contains( $rel_path, 'uploads/' );
    }

    /**
     * Sends a reported file to the lab. Only files the scanners reported or that sit in the
     * quarantine can be sent, so the button can never be used to read arbitrary files.
     *
     * @return string|WP_Error The ticket.
     */
    public static function submit_sample( string $rel_path, string $note = '' ) {
        $rel_path = ltrim( str_replace( '\\', '/', $rel_path ), '/' );
        if ( $rel_path === '' || str_contains( $rel_path, '..' ) ) {
            return new WP_Error( 'invalid', __( 'Invalid file.', 'metzler-webshield' ) );
        }
        if ( ! Metzler_Webshield::is_cloud_connected() ) {
            return new WP_Error( 'not_connected', __( 'Sending files for analysis needs a connection to the Threat Intelligence Cloud. A free key is enough, see the "Threat Cloud" tab.', 'metzler-webshield' ) );
        }
        if ( self::is_blocked_sample( $rel_path ) ) {
            return new WP_Error( 'blocked', __( 'This file is never sent, it may contain credentials or personal data.', 'metzler-webshield' ) );
        }

        self::ensure_table();
        $finding = self::latest_finding( $rel_path );
        $quarantine = new Metzler_Webshield_Quarantine();
        $record = $quarantine->find_by_path( $rel_path );

        if ( $record ) {
            $abs_path = $quarantine->path_of( $record );
        } elseif ( $finding ) {
            $abs_path = wp_normalize_path( ABSPATH . $rel_path );
        } else {
            return new WP_Error( 'not_a_finding', __( 'Only files reported by the scanner or in quarantine can be sent for analysis.', 'metzler-webshield' ) );
        }

        if ( ! is_file( $abs_path ) || ! is_readable( $abs_path ) ) {
            return new WP_Error( 'missing', __( 'The file no longer exists.', 'metzler-webshield' ) );
        }
        if ( filesize( $abs_path ) > self::SAMPLE_MAX_SIZE ) {
            return new WP_Error( 'too_large', __( 'The file is larger than 2 MB and cannot be sent.', 'metzler-webshield' ) );
        }

        $sha256 = (string) hash_file( 'sha256', $abs_path );
        if ( $finding && ! $record && $sha256 !== $finding->sha256 ) {
            return new WP_Error( 'changed', __( 'The file changed since the last scan. Please run a new scan first.', 'metzler-webshield' ) );
        }
        foreach ( self::lab_tickets() as $ticket ) {
            if ( $ticket['path'] === $rel_path && $ticket['sha256'] === $sha256 && $ticket['status'] === 'received' ) {
                return new WP_Error( 'pending', __( 'This file is already being analyzed.', 'metzler-webshield' ) );
            }
        }

        $sent_today = (int) get_transient( self::LAB_DAILY_TRANSIENT );
        if ( $sent_today >= self::LAB_DAILY_LIMIT ) {
            return new WP_Error( 'limit', __( 'You have reached the limit of 10 files per day. Please try again tomorrow.', 'metzler-webshield' ) );
        }

        $component = self::component_of( $record ? wp_normalize_path( ABSPATH . $rel_path ) : $abs_path );
        $response = self::send_sample( array(
            'sha256'       => $sha256,
            'rel_path'     => $rel_path,
            'size'         => (int) filesize( $abs_path ),
            'mtime'        => $finding ? (int) $finding->mtime : (int) filemtime( $abs_path ),
            'source'       => $finding ? $finding->source : 'quarantine',
            'detection'    => $finding ? $finding->detection : '',
            'component'    => $component,
            'user_verdict' => $record ? 'quarantined' : ( $finding ? $finding->user_verdict : '' ),
            'note'         => mb_substr( $note, 0, 500 ),
            'auto'         => false,
        ), $abs_path );
        if ( is_wp_error( $response ) ) {
            return $response;
        }

        set_transient( self::LAB_DAILY_TRANSIENT, $sent_today + 1, DAY_IN_SECONDS );
        $tickets = self::lab_tickets();
        $tickets[ $response['ticket'] ] = array( 'path' => $rel_path, 'sha256' => $sha256, 'status' => $response['status'], 'sent' => time() );
        update_option( self::LAB_TICKETS_OPTION, $tickets, false );
        self::set_lab_status( $rel_path, 'submitted', $response['ticket'] );

        /* translators: 1: file path, 2: ticket */
        Metzler_Webshield_Logger::log( sprintf( __( 'File sent for analysis: %1$s (ticket %2$s). You will receive the result by email and here in the log.', 'metzler-webshield' ), esc_html( $rel_path ), esc_html( $response['ticket'] ) ), 'system', 'success' );

        // Already judged files come back with the decision right away
        if ( $response['status'] !== 'received' ) {
            self::apply_lab_result( $response['ticket'], $response['status'], '' );
        }
        return $response['ticket'];
    }

    /**
     * Uploads one file with its metadata. The content is part of the signed JSON body.
     *
     * @return array|WP_Error {ticket, status}
     */
    public static function send_sample( array $meta, string $abs_path ) {
        $content = file_get_contents( $abs_path ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_get_contents_file_get_contents
        if ( $content === false ) {
            return new WP_Error( 'missing', __( 'The file could not be read.', 'metzler-webshield' ) );
        }
        $meta['content_base64'] = base64_encode( $content ); // phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode
        $meta['env'] = array(
            'wp'        => get_bloginfo( 'version' ),
            'php'       => PHP_MAJOR_VERSION . '.' . PHP_MINOR_VERSION,
            'webshield' => METZLER_WEBSHIELD_VERSION,
        );

        $response = Metzler_Webshield::post_signed( '/samples/submit', $meta, 45 );
        if ( is_wp_error( $response ) ) {
            return new WP_Error( 'unreachable', __( 'The Threat Intelligence API could not be reached. Please try again later.', 'metzler-webshield' ) );
        }

        $code = (int) wp_remote_retrieve_response_code( $response );
        $data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
        if ( $code === 200 && ! empty( $data['ticket'] ) ) {
            return array( 'ticket' => sanitize_text_field( $data['ticket'] ), 'status' => sanitize_key( $data['status'] ?? 'received' ) );
        }

        $messages = array(
            401 => __( 'The connection to the Threat Intelligence Cloud is no longer valid. Please check it in the "Threat Cloud" tab.', 'metzler-webshield' ),
            403 => __( 'The connection to the Threat Intelligence Cloud is no longer valid. Please check it in the "Threat Cloud" tab.', 'metzler-webshield' ),
            413 => __( 'The file is larger than 2 MB and cannot be sent.', 'metzler-webshield' ),
            429 => __( 'The daily limit for files sent for analysis has been reached. Please try again tomorrow.', 'metzler-webshield' ),
        );
        return new WP_Error( 'rejected', $messages[ $code ] ?? __( 'The file could not be sent. Please try again later.', 'metzler-webshield' ) );
    }

    /**
     * Fetches the result of open lab tickets (hourly). A clean file is marked as safe automatically.
     */
    public static function sync_lab_status(): void {
        if ( ! Metzler_Webshield::is_cloud_connected() ) return;

        $tickets = self::lab_tickets();
        $open = array_keys( array_filter( $tickets, function ( $ticket ) {
            return $ticket['status'] === 'received';
        } ) );

        // Finished tickets are kept 30 days so the log can refer to them, then forgotten
        foreach ( $tickets as $id => $ticket ) {
            if ( $ticket['status'] !== 'received' && $ticket['sent'] < time() - 30 * DAY_IN_SECONDS ) {
                unset( $tickets[ $id ] );
            }
        }
        update_option( self::LAB_TICKETS_OPTION, $tickets, false );
        if ( empty( $open ) ) return;

        $response = Metzler_Webshield::post_signed( '/samples/status', array( 'tickets' => array_slice( $open, 0, 200 ) ) );
        if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) !== 200 ) return;

        $data = json_decode( (string) wp_remote_retrieve_body( $response ), true );
        foreach ( (array) ( $data['tickets'] ?? array() ) as $result ) {
            $status = sanitize_key( $result['status'] ?? '' );
            if ( empty( $result['ticket'] ) || $status === '' || $status === 'received' ) continue;
            self::apply_lab_result( sanitize_text_field( $result['ticket'] ), $status, sanitize_textarea_field( (string) ( $result['analyst_note'] ?? '' ) ) );
        }
    }

    private static function apply_lab_result( string $ticket_id, string $status, string $analyst_note ): void {
        $tickets = self::lab_tickets();
        if ( ! isset( $tickets[ $ticket_id ] ) ) return;
        $path = $tickets[ $ticket_id ]['path'];
        $tickets[ $ticket_id ]['status'] = $status;
        update_option( self::LAB_TICKETS_OPTION, $tickets, false );
        self::set_lab_status( $path, $status, $ticket_id );

        $quarantine = new Metzler_Webshield_Quarantine();
        $quarantined = (bool) $quarantine->find_by_path( $path );
        $note = $analyst_note !== '' ? '<br>' . esc_html( $analyst_note ) : '';

        switch ( $status ) {
            case 'clean':
                if ( ! $quarantined ) {
                    Metzler_Webshield_Queue::mark_safe( $path );
                }
                $message = $quarantined
                    /* translators: %s: file path */
                    ? sprintf( __( 'Lab result: the file is clean, it is not malware. You can restore it from the quarantine: %s', 'metzler-webshield' ), esc_html( $path ) )
                    /* translators: %s: file path */
                    : sprintf( __( 'Lab result: the file is clean, it is not malware. The finding was marked as safe: %s', 'metzler-webshield' ), esc_html( $path ) );
                Metzler_Webshield_Logger::log( $message . $note, 'system', 'success' );
                break;
            case 'malicious':
                if ( $quarantined ) {
                    /* translators: %s: file path */
                    Metzler_Webshield_Logger::log( sprintf( __( 'Lab result: the file contains malware. It is in quarantine, delete it there: %s', 'metzler-webshield' ), esc_html( $path ) ) . $note, 'system', 'warning' );
                } else {
                    $actions = '<br><button type="button" class="button button-small button-primary metzler-webshield-q-move" data-path="' . esc_attr( $path ) . '" style="background:#d63638;border-color:#d63638;">' . esc_html__( 'Move to quarantine', 'metzler-webshield' ) . '</button>';
                    /* translators: %s: file path */
                    Metzler_Webshield_Logger::log( sprintf( __( 'Critical: the lab confirmed malware in %s', 'metzler-webshield' ), esc_html( $path ) ) . $note . $actions, 'files', 'error' );
                }
                break;
            case 'suspicious':
                /* translators: %s: file path */
                Metzler_Webshield_Logger::log( sprintf( __( 'Lab result: the file is suspicious. Keep it in quarantine as long as the site works without it: %s', 'metzler-webshield' ), esc_html( $path ) ) . $note, $quarantined ? 'system' : 'files', 'warning' );
                break;
            default:
                /* translators: %s: file path */
                Metzler_Webshield_Logger::log( sprintf( __( 'Lab result: the file could not be judged: %s', 'metzler-webshield' ), esc_html( $path ) ) . $note, 'system', 'info' );
        }
    }

    /**
     * "Send for analysis" button for the log, only on connected sites.
     */
    public static function lab_button( string $rel_path ): string {
        if ( ! Metzler_Webshield::is_cloud_connected() || self::is_blocked_sample( $rel_path ) ) return '';
        return ' <button type="button" class="button button-small metzler-webshield-q-lab" data-path="' . esc_attr( $rel_path ) . '">' . esc_html__( 'Send for analysis', 'metzler-webshield' ) . '</button>';
    }

    public static function lab_tickets(): array {
        $tickets = get_option( self::LAB_TICKETS_OPTION, array() );
        return is_array( $tickets ) ? $tickets : array();
    }

    private static function latest_finding( string $rel_path ) {
        global $wpdb;
        $table_name = self::table(); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        return $wpdb->get_row( $wpdb->prepare( "SELECT * FROM $table_name WHERE path_hash = %s ORDER BY last_seen DESC, id DESC LIMIT 1", md5( $rel_path ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
    }

    private static function set_lab_status( string $rel_path, string $status, string $ticket ): void {
        global $wpdb;
        $wpdb->update( self::table(), array( 'lab_status' => $status, 'lab_ticket' => $ticket ), array( 'path_hash' => md5( $rel_path ) ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter
    }

    /**
     * Which plugin, theme or part of WordPress a file belongs to.
     */
    public static function component_of( string $abs_path ): array {
        $path = wp_normalize_path( $abs_path );
        $none = array( 'type' => 'other', 'slug' => '', 'version' => '' );

        $roots = array(
            'plugin'    => WP_PLUGIN_DIR,
            'mu-plugin' => defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins',
            'theme'     => get_theme_root(),
            'uploads'   => wp_upload_dir( null, false )['basedir'],
        );
        foreach ( $roots as $type => $root ) {
            $root = trailingslashit( wp_normalize_path( $root ) );
            if ( ! str_starts_with( $path, $root ) ) continue;
            if ( $type === 'uploads' || $type === 'mu-plugin' ) {
                return array( 'type' => $type, 'slug' => '', 'version' => '' );
            }

            $first = explode( '/', substr( $path, strlen( $root ) ) )[0];
            if ( $type === 'theme' ) {
                $theme = wp_get_theme( $first );
                return array( 'type' => 'theme', 'slug' => $first, 'version' => $theme->exists() ? (string) $theme->get( 'Version' ) : '' );
            }
            return array( 'type' => 'plugin', 'slug' => preg_replace( '/\.php$/', '', $first ), 'version' => self::plugin_version( $first ) );
        }

        $abspath = trailingslashit( wp_normalize_path( ABSPATH ) );
        if ( str_starts_with( $path, $abspath . 'wp-admin/' ) || str_starts_with( $path, $abspath . 'wp-includes/' ) || dirname( $path ) . '/' === $abspath ) {
            return array( 'type' => 'core', 'slug' => 'wordpress', 'version' => get_bloginfo( 'version' ) );
        }
        return $none;
    }

    private static function plugin_version( string $dir_or_file ): string {
        static $versions = null;
        if ( $versions === null ) {
            if ( ! function_exists( 'get_plugins' ) ) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }
            $versions = array();
            foreach ( get_plugins() as $file => $data ) {
                $key = dirname( $file ) === '.' ? $file : dirname( $file );
                $versions[ $key ] = (string) $data['Version'];
            }
        }
        return $versions[ $dir_or_file ] ?? '';
    }
}
