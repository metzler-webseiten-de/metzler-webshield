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
     * Get active security threats on the server.
     * Excludes 'waf' (blocked bots/attacks) and 'system' messages.
     *
     * @param int $limit
     * @return array
     */
    public static function get_active_threats( int $limit = 50 ): array {
        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_logs'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter

        return $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->prepare(
                "SELECT * FROM $table_name 
                 WHERE severity IN ('warning', 'error') 
                   AND type NOT IN ('waf', 'system')
                 ORDER BY id DESC LIMIT %d",
                $limit
            )
        ) ?: array();
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

        return (int) $wpdb->get_var( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter
            "SELECT COUNT(*) FROM $table_name 
             WHERE severity IN ('warning', 'error') 
               AND type NOT IN ('waf', 'system')"
        );
    }

    /**
     * Get statistics on blocked bots and attacks in the last 24 hours.
     *
     * @return array
     */
    public static function get_24h_waf_stats(): array {
        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_logs'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter

        // 24 hours ago in local time format (matching current_time('mysql'))
        $since = date( 'Y-m-d H:i:s', current_time( 'timestamp' ) - DAY_IN_SECONDS );

        $rows = $wpdb->get_results( // phpcs:ignore WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->prepare(
                "SELECT * FROM $table_name 
                 WHERE type = 'waf' AND time >= %s 
                 ORDER BY id DESC",
                $since
            )
        ) ?: array();

        $total_attacks = 0;
        $categories = array();
        $recent_events = array();

        foreach ( $rows as $row ) {
            $count = 1;
            if ( preg_match( '/(?:WAF Block:\s*(\d+)\s*attack)/i', $row->message, $m ) ) {
                $count = (int) $m[1];
            }
            $total_attacks += $count;

            // Extract categories inside parentheses e.g. (Bad_Bots, Browser_Integrity)
            $types = array();
            if ( preg_match( '/\(([^)]+)\)\s*prevented/i', $row->message, $m ) ) {
                $types = array_map( 'trim', explode( ',', $m[1] ) );
                foreach ( $types as $cat ) {
                    $categories[ $cat ] = ( $categories[ $cat ] ?? 0 ) + $count;
                }
            }

            // Extract IP
            $ip = '';
            if ( preg_match( '/from IP\s*([^\s(]+)/i', $row->message, $m ) ) {
                $ip = trim( $m[1] );
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
}
