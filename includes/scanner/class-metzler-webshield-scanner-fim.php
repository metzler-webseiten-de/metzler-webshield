<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class Metzler_Webshield_Scanner_FIM {
    public function run_step($payload): array {
        $step = $payload['step'] ?? 'init';
        
        if ( $step === 'init' ) {
            $last_baseline = get_option('metzler_webshield_fim_last_baseline');
            if ( ! $last_baseline ) {
                Metzler_Webshield_Logger::log(__("Initial system baseline is being generated in the background...", "metzler-webshield"), "system" );
                $fim = new Metzler_Webshield_FIM();
                $fim->build_baseline();
                Metzler_Webshield_Logger::log(__("System baseline set successfully. All future file changes will now be monitored.", "metzler-webshield"), "system", "success");
                return array('complete' => true); // No need to scan right after building it
            }

            Metzler_Webshield_Logger::log(__("Starting File Integrity Monitoring across wp-content...", "metzler-webshield"), "system" );
            
            new Metzler_Webshield_FIM();

            return array(
                'complete' => false,
                'next_payload' => array('step' => 'process', 'index' => 0),
                'message' => __('FIM scanner running...', 'metzler-webshield')
            );
        }
        
        if ( $step === 'process' ) {
            global $wpdb;
            $table_name = $wpdb->prefix . 'metzler_webshield_fim'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
            
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
                
                $baseline_row = $wpdb->get_row($wpdb->prepare("SELECT file_hash FROM $table_name WHERE file_path = %s", $relative_path)); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
                
                if ( ! $baseline_row ) {
                    // File is new!
                    $actions = '<br><button type="button" class="button button-small metzler-webshield-q-safe" data-path="'.esc_attr($relative_path).'">' . esc_html__('Mark as safe', 'metzler-webshield') . '</button> ';
                    $actions .= '<button type="button" class="button button-small button-primary metzler-webshield-q-move" data-path="'.esc_attr($relative_path).'" style="background:#d63638;border-color:#d63638;">' . esc_html__('Move to quarantine', 'metzler-webshield') . '</button>';
                    Metzler_Webshield_Logger::log(sprintf( __("FIM Alert: New, unknown file found -> %s%s", "metzler-webshield"), esc_html($relative_path), $actions ), "system", "error");
                } else if ( $baseline_row->file_hash !== $actual_hash ) {
                    // File is modified!
                    $actions = '<br><button type="button" class="button button-small metzler-webshield-q-safe" data-path="'.esc_attr($relative_path).'">' . esc_html__('Mark as safe', 'metzler-webshield') . '</button> ';
                    $actions .= '<button type="button" class="button button-small button-primary metzler-webshield-q-move" data-path="'.esc_attr($relative_path).'" style="background:#d63638;border-color:#d63638;">' . esc_html__('Move to quarantine', 'metzler-webshield') . '</button>';
                    Metzler_Webshield_Logger::log(sprintf( __("FIM Alert: File modified after snapshot -> %s%s", "metzler-webshield"), esc_html($relative_path), $actions ), "system", "error");
                }
            }
            
            if ( $end >= $total ) {
                Metzler_Webshield_Logger::log(sprintf( __("File Integrity Monitoring completed. (Checked: %d files)", "metzler-webshield"), $total ), "system", "success");
                return array('complete' => true, 'message' => __('FIM scan completed', 'metzler-webshield'));
            }
            
            return array(
                'complete' => false,
                'next_payload' => array('step' => 'process', 'index' => $end),
                'message' => sprintf(__('FIM scan (%1$d/%2$d)...', 'metzler-webshield'), $end, $total)
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
