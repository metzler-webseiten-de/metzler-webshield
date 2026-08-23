<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class WPProtector_Logger {
    public static function create_table() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'wpprotector_logs';
        $charset_collate = $wpdb->get_charset_collate();

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
        $table_name = $wpdb->prefix . 'wpprotector_logs';
        $wpdb->insert( 
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
        $table_name = $wpdb->prefix . 'wpprotector_logs';
        return $wpdb->get_results( $wpdb->prepare( "SELECT * FROM $table_name ORDER BY id DESC LIMIT %d", $limit ) );
    }

    public static function cleanup_old_logs() {
        global $wpdb;
        $table_name = $wpdb->prefix . 'wpprotector_logs';
        
        // Keep logs for the last 7 days to maintain history but avoid bloat
        $wpdb->query(
            $wpdb->prepare("DELETE FROM $table_name WHERE time < %s", date('Y-m-d H:i:s', strtotime('-7 days')))
        );
    }
    
    public static function resolve_path_logs($path) {
        global $wpdb;
        $table_name = $wpdb->prefix . 'wpprotector_logs';
        
        // Mark all warnings/errors containing this path as 'resolved' instead of deleting them.
        // This preserves history for forensics/reporting while removing them from active threats.
        $wpdb->query(
            $wpdb->prepare(
                "UPDATE $table_name SET severity = 'resolved' WHERE message LIKE %s AND severity != 'success'",
                '%' . $wpdb->esc_like($path) . '%'
            )
        );
    }
}
