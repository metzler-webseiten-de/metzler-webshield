<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class Metzler_Webshield_Logger {
    public static function create_table() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_logs'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        $charset_collate = $wpdb->get_charset_collate(); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter

        $sql = "CREATE TABLE $table_name (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            time datetime DEFAULT '0000-00-00 00:00:00' NOT NULL,
            type varchar(50) NOT NULL,
            message text NOT NULL,
            severity varchar(20) DEFAULT 'info' NOT NULL,
            PRIMARY KEY  (id)
        ) $charset_collate;";

        require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
        dbDelta( $sql );
    }

    public static function log( $message, $type = 'general', $severity = 'info' ) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_logs'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        $wpdb->insert( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery
            $table_name, 
            array( 
                'time' => current_time('mysql'), 
                'type' => $type, 
                'message' => $message,
                'severity' => $severity
            ) 
        );
    }
    
    public static function get_logs( $limit = 50 ) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_logs'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM $table_name ORDER BY id DESC LIMIT %d", $limit ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
    }

    public static function cleanup_old_logs() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_logs'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        
        // Keep logs for the last 7 days to maintain history but avoid bloat
        $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->prepare("DELETE FROM $table_name WHERE time < %s", gmdate('Y-m-d H:i:s', strtotime('-7 days'))) // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        );
    }
    
    public static function resolve_path_logs($path) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_logs'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        
        // Mark all warnings/errors containing this path as 'resolved' instead of deleting them.
        // This preserves history for forensics/reporting while removing them from active threats.
        $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->prepare( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
                "UPDATE $table_name SET severity = 'resolved' WHERE message LIKE %s AND severity != 'success'", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
                '%' . $wpdb->esc_like($path) . '%' // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
            )
        );
    }

    /**
     * Resolves the warnings of the given log types written up to the given log id, i.e. before a scan that
     * has just checked the same things again. Install notices of older versions (log type "plugins") are kept.
     */
    public static function resolve_superseded( int $up_to_id, array $types ): void {
        if ( $up_to_id <= 0 || empty( $types ) ) return;
        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_logs'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        $placeholders = implode( ',', array_fill( 0, count( $types ), '%s' ) );
        $wpdb->query( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->prepare( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
                "UPDATE $table_name SET severity = 'resolved' WHERE id <= %d AND severity IN ('warning', 'error') AND type IN ($placeholders) AND message NOT LIKE %s", // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.PreparedSQLPlaceholders.UnfinishedPrepare
                array_merge( array( $up_to_id ), array_values( $types ), array( '%' . $wpdb->esc_like( 'data-path="install:' ) . '%' ) )
            )
        );
    }

    /**
     * Get active security threats on the server.
     * Excludes 'waf' (blocked bots/attacks) and 'system' messages.
     *
     * @param int $limit
     * @return array
     */
    public static function get_active_threats( int $limit = 50 ): array {
        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_logs'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter

        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- trusted table name ($wpdb->prefix + constant); %i needs WP 6.2
        return $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->prepare(
                "SELECT * FROM $table_name 
                 WHERE severity IN ('warning', 'error') 
                   AND type NOT IN ('waf', 'system')
                 ORDER BY id DESC LIMIT %d",
                $limit
            )
        ) ?: array();
        // phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
    }

    /**
     * Count active security threats on the server.
     * Excludes 'waf' (blocked bots/attacks) and 'system' messages.
     *
     * @return int
     */
    public static function count_active_threats(): int {
        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_logs'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter

        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- trusted table name ($wpdb->prefix + constant), no user input
        return (int) $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter
            "SELECT COUNT(*) FROM $table_name 
             WHERE severity IN ('warning', 'error') 
               AND type NOT IN ('waf', 'system')"
        );
        // phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared
    }

    /**
     * Get statistics on blocked bots and attacks in the last 24 hours.
     *
     * @return array
     */
    public static function get_24h_waf_stats(): array {
        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_logs'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter

        // 24 hours ago in the site's timezone (matching current_time('mysql'))
        $since = wp_date( 'Y-m-d H:i:s', time() - DAY_IN_SECONDS );

        // phpcs:disable WordPress.DB.PreparedSQL.InterpolatedNotPrepared -- trusted table name ($wpdb->prefix + constant); %i needs WP 6.2
        $rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->prepare(
                "SELECT * FROM $table_name 
                 WHERE type = 'waf' AND time >= %s 
                 ORDER BY id DESC",
                $since
            )
        ) ?: array();
        // phpcs:enable WordPress.DB.PreparedSQL.InterpolatedNotPrepared

        $total_attacks = 0;
        $categories = array();
        $recent_events = array();

        foreach ( $rows as $row ) {
            $event = self::parse_waf_event( (string) $row->message );
            $count = $event['count'];
            $types = $event['types'];
            $ip    = $event['ip'];

            $total_attacks += $count;
            foreach ( $types as $cat ) {
                $categories[ $cat ] = ( $categories[ $cat ] ?? 0 ) + $count;
            }

            if ( count( $recent_events ) < 5 ) {
                $recent_events[] = array(
                    'ip'         => $ip ?: '-',
                    'types'      => ! empty( $types ) ? implode( ', ', $types ) : __( 'Bot / Attack', 'metzler-webshield' ),
                    'count'      => $count,
                    'time'       => $row->time,
                    'time_human' => human_time_diff( strtotime( $row->time ), current_time( 'timestamp' ) ) . ' ' . __( 'ago', 'metzler-webshield' ),
                );
            }
        }

        arsort( $categories );

        return array(
            'total'         => $total_attacks,
            'categories'    => $categories,
            'recent_events' => $recent_events,
        );
    }

    /**
     * Reads count, IP and attack types from a logged WAF message.
     *
     * The patterns are built from the same format strings the plugin logs with, in English and in the
     * site language, so translated log lines are understood too. Unknown lines fall back to the first
     * IP address found in the text.
     *
     * @return array{count: int, ip: string, types: string[]}
     */
    private static function parse_waf_event( string $message ): array {
        $events = array(
            array(
                'formats' => array(
                    'WAF Block: 1 attack from IP %1$s (%2$s) prevented.',
                    /* translators: 1: IP address, 2: attack types */
                    __( 'WAF Block: 1 attack from IP %1$s (%2$s) prevented.', 'metzler-webshield' ),
                ),
                'ip'      => 1,
                'types'   => 2,
            ),
            array(
                'formats' => array(
                    'WAF Block: %1$d attacks from IP %2$s (%3$s) prevented.',
                    /* translators: 1: number of attacks, 2: IP address, 3: attack types */
                    __( 'WAF Block: %1$d attacks from IP %2$s (%3$s) prevented.', 'metzler-webshield' ),
                ),
                'count'   => 1,
                'ip'      => 2,
                'types'   => 3,
            ),
            array(
                'formats' => array(
                    'Brute-Force prevented: Bot login attempt (No JS) from IP: %1$s for user: %2$s',
                    /* translators: %1$s: IP address, %2$s: username */
                    __( 'Brute-Force prevented: Bot login attempt (No JS) from IP: %1$s for user: %2$s', 'metzler-webshield' ),
                ),
                'ip'      => 1,
                'type'    => 'Brute_Force',
            ),
            array(
                'formats' => array(
                    'User Enumeration blocked: %1$s exceeded rate limit with %2$d author probes in 60s',
                    /* translators: 1: IP address, 2: Probe count */
                    __( 'User Enumeration blocked: %1$s exceeded rate limit with %2$d author probes in 60s', 'metzler-webshield' ),
                ),
                'ip'      => 1,
                'type'    => 'User_Enumeration',
            ),
        );

        foreach ( $events as $event ) {
            foreach ( array_unique( $event['formats'] ) as $format ) {
                if ( ! preg_match( self::format_to_regex( $format ), $message, $m ) ) {
                    continue;
                }

                $types = isset( $event['types'] )
                    ? array_values( array_filter( array_map( 'trim', explode( ',', $m[ 'p' . $event['types'] ] ) ) ) )
                    : array( $event['type'] );

                return array(
                    'count' => isset( $event['count'] ) ? max( 1, (int) $m[ 'p' . $event['count'] ] ) : 1,
                    'ip'    => trim( $m[ 'p' . $event['ip'] ] ),
                    'types' => $types,
                );
            }
        }

        $ip = '';
        foreach ( preg_split( '/\s+/', $message ) as $token ) {
            $token = trim( $token, '()[],;' );
            if ( filter_var( $token, FILTER_VALIDATE_IP ) ) {
                $ip = $token;
                break;
            }
        }

        return array( 'count' => 1, 'ip' => $ip, 'types' => array() );
    }

    /**
     * Turns a sprintf format with numbered placeholders (%1$s, %2$d) into a regex with named groups p1, p2, ...
     */
    private static function format_to_regex( string $format ): string {
        $parts = preg_split( '/%(\d+)\$([sd])/', $format, -1, PREG_SPLIT_DELIM_CAPTURE );
        $regex = '';

        for ( $i = 0, $n = count( $parts ); $i < $n; $i += 3 ) {
            $regex .= preg_quote( $parts[ $i ], '/' );
            if ( isset( $parts[ $i + 2 ] ) ) {
                $regex .= 'd' === $parts[ $i + 2 ] ? '(?P<p' . $parts[ $i + 1 ] . '>\d+)' : '(?P<p' . $parts[ $i + 1 ] . '>.+?)';
            }
        }

        return '/^' . $regex . '$/su';
    }
}
