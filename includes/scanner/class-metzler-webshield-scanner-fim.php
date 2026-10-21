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

            $files = $this->get_all_php_files(WP_CONTENT_DIR);
            $next_payload = array('step' => 'process', 'index' => 0);
            // Without a writable storage directory the list travels in the payload
            if ( ! Metzler_Webshield_Storage::save_scan_list( 'fim', $files ) ) {
                $next_payload['files'] = $files;
            }

            return array(
                'complete' => false,
                'next_payload' => $next_payload,
                'message' => __('FIM scanner running...', 'metzler-webshield')
            );
        }
        
        if ( $step === 'process' ) {
            $files = $payload['files'] ?? Metzler_Webshield_Storage::load_scan_list( 'fim' );
            $baseline = $this->load_baseline();
            $index = isset($payload['index']) ? intval($payload['index']) : 0;
            $batch_size = 200; 
            
            $total = count($files);
            $end = min($index + $batch_size, $total);
            
            $whitelist = get_option( 'metzler_webshield_whitelist', array() );
            if ( ! is_array( $whitelist ) ) $whitelist = array();

            for ( $i = $index; $i < $end; $i++ ) {
                $file = $files[$i];
                
                // Bulletproof relative path extraction based on WP_CONTENT_DIR
                $normalized_file = wp_normalize_path($file);
                $normalized_content = wp_normalize_path(WP_CONTENT_DIR);
                $relative_to_content = ltrim(str_ireplace($normalized_content, '', $normalized_file), '/');
                $relative_path = 'wp-content/' . $relative_to_content;

                if ( in_array( $relative_path, $whitelist, true ) ) {
                    continue;
                }
                
                $actual_hash = md5_file($file);
                $path_hash   = md5($relative_path);
                
                $baseline_hash = $baseline['hash'][$path_hash] ?? $baseline['path'][$relative_path] ?? null;

                // Logs, caches and empty index.php files that plugins rewrite all the time, none of them can run code
                if ( $baseline_hash !== $actual_hash && Metzler_Webshield_Scanner_Files::is_inert_php($file) ) {
                    continue;
                }

                if ( $baseline_hash === null ) {
                    // File is new!
                    $actions = '<br><button type="button" class="button button-small metzler-webshield-q-safe" data-path="'.esc_attr($relative_path).'">' . esc_html__('Mark as safe', 'metzler-webshield') . '</button> ';
                    $actions .= '<button type="button" class="button button-small button-primary metzler-webshield-q-move" data-path="'.esc_attr($relative_path).'" style="background:#d63638;border-color:#d63638;">' . esc_html__('Move to quarantine', 'metzler-webshield') . '</button>';
                    $actions .= Metzler_Webshield_Findings::lab_button( $relative_path );
                    /* translators: 1: file path, 2: action buttons */
                    Metzler_Webshield_Logger::log(sprintf( __('FIM Alert: New, unknown file found -> %1$s%2$s', 'metzler-webshield'), esc_html($relative_path), $actions ), "fim", "error");
                    Metzler_Webshield_Findings::report( $relative_path, $file, 'fim', 'fim-new' );
                } else if ( $baseline_hash !== $actual_hash ) {
                    // File is modified!
                    $actions = '<br><button type="button" class="button button-small metzler-webshield-q-safe" data-path="'.esc_attr($relative_path).'">' . esc_html__('Mark as safe', 'metzler-webshield') . '</button> ';
                    $actions .= '<button type="button" class="button button-small button-primary metzler-webshield-q-move" data-path="'.esc_attr($relative_path).'" style="background:#d63638;border-color:#d63638;">' . esc_html__('Move to quarantine', 'metzler-webshield') . '</button>';
                    $actions .= Metzler_Webshield_Findings::lab_button( $relative_path );
                    /* translators: 1: file path, 2: action buttons */
                    Metzler_Webshield_Logger::log(sprintf( __('FIM Alert: File modified after snapshot -> %1$s%2$s', 'metzler-webshield'), esc_html($relative_path), $actions ), "fim", "error");
                    Metzler_Webshield_Findings::report( $relative_path, $file, 'fim', 'fim-modified' );
                }
            }
            
            if ( $end >= $total ) {
                /* translators: %d: number of files checked */
                Metzler_Webshield_Logger::log(sprintf( __("File Integrity Monitoring completed. (Checked: %d files)", "metzler-webshield"), $total ), "system", "success");
                return array('complete' => true, 'message' => __('FIM scan completed', 'metzler-webshield'));
            }
            
            return array(
                'complete' => false,
                'next_payload' => isset($payload['files']) ? array('step' => 'process', 'files' => $files, 'index' => $end) : array('step' => 'process', 'index' => $end),
                /* translators: 1: current index, 2: total files */
                'message' => sprintf(__('FIM scan (%1$d/%2$d)...', 'metzler-webshield'), $end, $total)
            );
        }
        
        return array('complete' => true);
    }
    
    /**
     * The whole baseline in one query instead of one query per file. Rows from before
     * path_hash existed are matched by their path.
     */
    private function load_baseline(): array {
        static $baseline = null;
        if ( $baseline !== null ) return $baseline;
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_fim'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        $rows = $wpdb->get_results("SELECT path_hash, file_path, file_hash FROM $table_name", ARRAY_A) ?: array(); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        
        $baseline = array('hash' => array(), 'path' => array());
        foreach ( $rows as $row ) {
            if ( $row['path_hash'] !== '' ) {
                $baseline['hash'][$row['path_hash']] = $row['file_hash'];
            } else {
                $baseline['path'][$row['file_path']] = $row['file_hash'];
            }
        }
        return $baseline;
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
                if ( $path->isFile() && strtolower($path->getExtension()) === 'php' && ! Metzler_Webshield_Storage::is_own_file($path->getPathname()) ) {
                    $files[] = $path->getPathname();
                }
            }
        } catch (Exception $e) {}
        
        return $files;
    }
}
