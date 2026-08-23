<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class WPProtector_FIM {
    
    public static function create_table(): void {
        global $wpdb;
        $table_name = $wpdb->prefix . 'wpprotector_fim';
        $charset_collate = $wpdb->get_charset_collate();

        $sql = "CREATE TABLE $table_name (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            file_path varchar(500) NOT NULL,
            file_hash varchar(32) NOT NULL,
            updated_at datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY file_path (file_path(191))
        ) $charset_collate;";

        require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
        dbDelta( $sql );
    }
    
    public function init(): void {
        add_action('upgrader_process_complete', array($this, 'on_update_complete'), 10, 2);
    }

    public function on_update_complete(): void {
        $this->build_baseline(); 
        WPProtector_Logger::log("FIM Baseline wurde nach einem WP-Update automatisch aktualisiert.", "system" );
    }

    public function build_baseline(): int {
        self::create_table();
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'wpprotector_fim';
        
        $wp_content = WP_CONTENT_DIR;
        $files = $this->get_all_php_files($wp_content);
        
        $wpdb->query("TRUNCATE TABLE $table_name");
        
        $wpdb->query("START TRANSACTION");
        
        foreach ($files as $file) {
            $normalized_file = wp_normalize_path($file);
            $normalized_content = wp_normalize_path(WP_CONTENT_DIR);
            $relative_to_content = ltrim(str_ireplace($normalized_content, '', $normalized_file), '/');
            $relative_path = 'wp-content/' . $relative_to_content;
            
            $wpdb->insert($table_name, array(
                'file_path' => $relative_path,
                'file_hash' => md5_file($file),
                'updated_at' => current_time('mysql')
            ));
        }
        
        $wpdb->query("COMMIT");
        
        update_option('wpprotector_fim_last_baseline', current_time('mysql'));
        return count($files);
    }
    
    public function accept_file($relative_path): bool {
        if ( str_contains( $relative_path, '..' ) ) return false;
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'wpprotector_fim';
        
        $relative_path = ltrim(wp_normalize_path($relative_path), '/');
        $abs_path = wp_normalize_path(ABSPATH) . $relative_path;
        
        if ( file_exists($abs_path) ) {
            $hash = md5_file($abs_path);
            $wpdb->replace($table_name, array(
                'file_path' => $relative_path,
                'file_hash' => $hash,
                'updated_at' => current_time('mysql')
            ));
            return true;
        }
        return false;
    }
    
    private function get_all_php_files($base): array {
        $files = array();
        if ( ! is_dir($base) ) return $files;
        
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );
            
            foreach ( $iterator as $path ) {
                if ( $path->isFile() && strtolower($path->getExtension()) === 'php' ) {
                    $files[] = $path->getPathname();
                }
            }
        } catch (Exception ) {}
        
        return $files;
    }
}
