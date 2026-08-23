<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class WPProtector_Scanner_FIM {
    public function run_step($payload): array {
        $step = $payload['step'] ?? 'init';
        
        if ( $step === 'init' ) {
            $last_baseline = get_option('wpprotector_fim_last_baseline');
            if ( ! $last_baseline ) {
                WPProtector_Logger::log(__("Initial system baseline is being generated in the background...", "wpprotector"), "system" );
                $fim = new WPProtector_FIM();
                $fim->build_baseline();
                WPProtector_Logger::log(__("System baseline set successfully. All future file changes will now be monitored.", "wpprotector"), "system", "success");
                return array('complete' => true); // No need to scan right after building it
            }

            WPProtector_Logger::log(__("Starting File Integrity Monitoring across wp-content...", "wpprotector"), "system" );
            
            new WPProtector_FIM();

            return array(
                'complete' => false,
                'next_payload' => array('step' => 'process', 'index' => 0),
                'message' => 'FIM-Scanner läuft...'
            );
        }
        
        if ( $step === 'process' ) {
            global $wpdb;
            $table_name = $wpdb->prefix . 'wpprotector_fim';
            
            $wp_content = WP_CONTENT_DIR;
            $files = $this->get_all_php_files($wp_content);
            $index = isset($payload['index']) ? intval($payload['index']) : 0;
            $batch_size = 200; 
            
            $total = count($files);
            $end = min($index + $batch_size, $total);
            
            // fetch all baseline hashes for this batch to save queries
            // Actually, querying them one by one is slow. We query them all at once.
            for ( $i = $index; $i < $end; $i++ ) {
                $file = $files[$i];
                
                // Bulletproof relative path extraction based on WP_CONTENT_DIR
                $normalized_file = wp_normalize_path($file);
                $normalized_content = wp_normalize_path(WP_CONTENT_DIR);
                $relative_to_content = ltrim(str_ireplace($normalized_content, '', $normalized_file), '/');
                $relative_path = 'wp-content/' . $relative_to_content;
                
                $actual_hash = md5_file($file);
                
                $baseline_row = $wpdb->get_row($wpdb->prepare("SELECT file_hash FROM $table_name WHERE file_path = %s", $relative_path));
                
                if ( ! $baseline_row ) {
                    // File is new!
                    $actions = '<br><button type="button" class="button button-small wpprotector-q-safe" data-path="'.esc_attr($relative_path).'">Als sicher markieren</button> ';
                    $actions .= '<button type="button" class="button button-small button-primary wpprotector-q-move" data-path="'.esc_attr($relative_path).'" style="background:#d63638;border-color:#d63638;">In Quarantäne verschieben</button>';
                    WPProtector_Logger::log(__("FIM Alert: New, unknown file found -> ", "wpprotector") . esc_html($relative_path) . $actions, "system", "error");
                } else if ( $baseline_row->file_hash !== $actual_hash ) {
                    // File is modified!
                    $actions = '<br><button type="button" class="button button-small wpprotector-q-safe" data-path="'.esc_attr($relative_path).'">Als sicher markieren</button> ';
                    $actions .= '<button type="button" class="button button-small button-primary wpprotector-q-move" data-path="'.esc_attr($relative_path).'" style="background:#d63638;border-color:#d63638;">In Quarantäne verschieben</button>';
                    WPProtector_Logger::log(__("FIM Alert: File modified after snapshot -> ", "wpprotector") . esc_html($relative_path) . $actions, "system", "error");
                }
            }
            
            if ( $end >= $total ) {
                WPProtector_Logger::log("File Integrity Monitoring abgeschlossen. (Geprüft: $total Dateien)", "system", "success");
                return array('complete' => true, 'message' => 'FIM Scan abgeschlossen');
            }
            
            return array(
                'complete' => false,
                'next_payload' => array('step' => 'process', 'index' => $end),
                'message' => 'FIM-Scan (' . $end . '/' . $total . ')...'
            );
        }
        
        return array('complete' => true);
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
