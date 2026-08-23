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
}
