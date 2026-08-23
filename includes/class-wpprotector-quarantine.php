<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class WPProtector_Quarantine {

    private string $quarantine_dir;

    public function __construct() {
        $this->quarantine_dir = WP_CONTENT_DIR . '/wpprotector-quarantine';
    }

    public static function create_table(): void {
        global $wpdb;
        $table_name = $wpdb->prefix . 'wpprotector_quarantine';
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE $table_name (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            original_path varchar(500) NOT NULL,
            quarantine_path varchar(500) NOT NULL,
            time datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            PRIMARY KEY  (id)
        ) $charset_collate;";

        require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
        dbDelta( $sql );
    }

    public function init(): void {
        if ( ! file_exists($this->quarantine_dir) ) {
            wp_mkdir_p($this->quarantine_dir);
        }
        
        $htaccess_path = $this->quarantine_dir . '/.htaccess';
        if ( ! file_exists($htaccess_path) ) {
            file_put_contents($htaccess_path, "Deny from all\n<Files *>\nOrder Allow,Deny\nDeny from all\n</Files>");
        }

        $index_path = $this->quarantine_dir . '/index.php';
        if ( ! file_exists($index_path) ) {
            file_put_contents($index_path, "<?php // Silence is golden.");
        }
        
        $this->auto_cleanup();
    }
    
    private function auto_cleanup(): void {
        global $wpdb;
        $table_name = $wpdb->prefix . 'wpprotector_quarantine';
        
        $old_files = $wpdb->get_results($wpdb->prepare("SELECT * FROM $table_name WHERE time < %s", date('Y-m-d H:i:s', strtotime('-30 days'))));
        
        foreach ($old_files as $file) {
            $this->delete_file($file->id);
        }
    }

    public function quarantine_file($relative_path): bool {
        // Prevent path traversal
        if ( str_contains( $relative_path, '..' ) ) return false;

        $abs_path = ABSPATH . ltrim($relative_path, '/\\');
        if ( ! file_exists($abs_path) ) return false;

        $file_name = basename($abs_path);
        $new_name = uniqid('locked_') . '_' . $file_name . '.quarantine';
        $dest_path = $this->quarantine_dir . '/' . $new_name;

        if ( rename($abs_path, $dest_path) ) {
            global $wpdb;
            $table_name = $wpdb->prefix . 'wpprotector_quarantine';
            $wpdb->insert($table_name, array(
                'original_path' => $relative_path,
                'quarantine_path' => $new_name,
                'time' => current_time('mysql')
            ));
            
            WPProtector_Logger::log(__("File moved to quarantine: ", "wpprotector") . esc_html($relative_path), "system", "success");
            return true;
        }
        return false;
    }

    public function restore_file($id): bool {
        global $wpdb;
        $table_name = $wpdb->prefix . 'wpprotector_quarantine';
        $record = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table_name WHERE id = %d", $id));
        
        if ( $record ) {
            $source_path = $this->quarantine_dir . DIRECTORY_SEPARATOR . $record->quarantine_path;
            $dest_path = ABSPATH . ltrim(str_replace('\\', '/', $record->original_path), '/');
            
            if ( file_exists($source_path) ) {
                wp_mkdir_p(dirname($dest_path));
                if ( rename($source_path, $dest_path) ) {
                    $wpdb->delete($table_name, array('id' => $id));
                    WPProtector_Logger::log(__("File restored from quarantine: ", "wpprotector") . esc_html($record->original_path), "system" );
                    return true;
                }
            } else {
                $wpdb->delete($table_name, array('id' => $id));
            }
        }
        return false;
    }

    public function delete_file($id): bool {
        global $wpdb;
        $table_name = $wpdb->prefix . 'wpprotector_quarantine';
        $record = $wpdb->get_row($wpdb->prepare("SELECT * FROM $table_name WHERE id = %d", $id));
        
        if ( $record ) {
            $source_path = $this->quarantine_dir . '/' . $record->quarantine_path;
            if ( file_exists($source_path) ) {
                unlink($source_path);
            }
            $wpdb->delete($table_name, array('id' => $id));
            return true;
        }
        return false;
    }
    
    public function get_files(): array|object|null {
        global $wpdb;
        $table_name = $wpdb->prefix . 'wpprotector_quarantine';
        return $wpdb->get_results("SELECT * FROM $table_name ORDER BY id DESC");
    }
}
