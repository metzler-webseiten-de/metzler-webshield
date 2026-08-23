<?php
class WPProtector_Scanner_Plugins {
    
    public function run_step($payload): array {
        $step = $payload['step'] ?? 'init';
        
        if ( $step === 'init' ) {
            WPProtector_Logger::log(__("Collecting list of installed plugins...", "wpprotector"), "plugins" );
            
            if ( ! function_exists( 'get_plugins' ) ) {
                require_once ABSPATH . 'wp-admin/includes/plugin.php';
            }
            $all_plugins = get_plugins();
            
            $plugins_to_check = array();
            foreach ( $all_plugins as $plugin_file => $plugin_data ) {
                $plugins_to_check[] = array(
                    'file' => $plugin_file,
                    'name' => $plugin_data['Name'],
                    'version' => $plugin_data['Version']
                );
            }
            
            return array(
                'complete' => false,
                'next_payload' => array('step' => 'process', 'plugins' => $plugins_to_check, 'index' => 0),
                'message' => 'Lade Plugin-Signaturen...'
            );
        }
        
        if ( $step === 'process' ) {
            $plugins = $payload['plugins'] ?? array();
            $index = isset($payload['index']) ? intval($payload['index']) : 0;
            $batch_size = 3; 
            
            $total = count($plugins);
            $end = min($index + $batch_size, $total);
            
            $modifications_found = 0;
            
            for ( $i = $index; $i < $end; $i++ ) {
                $plugin = $plugins[$i];
                $slug = dirname($plugin['file']);
                $version = $plugin['version'];
                $name = $plugin['name'];
                
                if ( $slug === '.' ) continue;
                
                $response = wp_remote_get( "https://downloads.wordpress.org/plugin-checksums/{$slug}/{$version}.json", array('timeout' => 15) );
                
                if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) !== 200 ) {
                    WPProtector_Logger::log("Keine wp.org Signatur für Plugin verfügbar: {$name}", "plugins" );
                    continue;
                }
                
                $body = wp_remote_retrieve_body( $response );
                $data = json_decode( $body, true );
                
                if ( isset($data['files']) && is_array($data['files']) ) {
                    $plugin_dir = WP_PLUGIN_DIR . '/' . $slug;
                    
                    // 1. Check if core files are modified
                    foreach ( $data['files'] as $file_name => $hashes ) {
                        $local_file = $plugin_dir . '/' . $file_name;
                        
                        if ( file_exists($local_file) ) {
                            $actual_hash = md5_file($local_file);
                            $is_valid = false;
                            
                            if ( isset($hashes['md5']) && is_array($hashes['md5']) && in_array($actual_hash, $hashes['md5']) ) {
                                $is_valid = true;
                            } elseif ( isset($hashes['md5']) && is_string($hashes['md5']) && $hashes['md5'] === $actual_hash ) {
                                $is_valid = true;
                            }
                            
                            if ( ! $is_valid ) {
                                // Check FIM Baseline
                                global $wpdb;
                                $relative_path = ltrim(str_replace(ABSPATH, '', $local_file), '/\\');
                                $relative_path = str_replace('\\', '/', $relative_path);
                                
                                $baseline = $wpdb->get_row($wpdb->prepare("SELECT file_hash FROM {$wpdb->prefix}wpprotector_fim WHERE file_path = %s", $relative_path));
                                if ( ! $baseline || $baseline->file_hash !== $actual_hash ) {
                                    $modifications_found++;
                                    $actions = '<br><button type="button" class="button button-small wpprotector-q-safe" data-path="'.esc_attr($relative_path).'">Als sicher markieren</button> ';
                                    $actions .= '<button type="button" class="button button-small button-primary wpprotector-q-move" data-path="'.esc_attr($relative_path).'" style="background:#d63638;border-color:#d63638;">In Quarantäne verschieben</button>';
                                    WPProtector_Logger::log("Plugin-Datei modifiziert: {$name} -> " . esc_html($file_name) . $actions, "plugins", "error");
                                }
                            }
                        }
                    }
                    
                    // 2. Check for rogue files not in checksums
                    $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($plugin_dir, FilesystemIterator::SKIP_DOTS));
                    foreach ( $iterator as $file ) {
                        if ( $file->isFile() ) {
                            $local_file = $file->getPathname();
                            $relative_path = ltrim(str_replace(wp_normalize_path($plugin_dir), '', wp_normalize_path($local_file)), '/');
                            $relative_path = str_replace('\\', '/', $relative_path); // normalize for WP API
                            
                            if ( ! isset($data['files'][$relative_path]) ) {
                                global $wpdb;
                                $full_relative = ltrim(str_replace(ABSPATH, '', $local_file), '/\\');
                                $full_relative = str_replace('\\', '/', $full_relative);
                                
                                $baseline = $wpdb->get_row($wpdb->prepare("SELECT file_hash FROM {$wpdb->prefix}wpprotector_fim WHERE file_path = %s", $full_relative));
                                if ( ! $baseline || $baseline->file_hash !== md5_file($local_file) ) {
                                    $actions = '<br><button type="button" class="button button-small wpprotector-q-safe" data-path="'.esc_attr($full_relative).'">Als sicher markieren</button> ';
                                    $actions .= '<button type="button" class="button button-small button-primary wpprotector-q-move" data-path="'.esc_attr($full_relative).'" style="background:#d63638;border-color:#d63638;">In Quarantäne verschieben</button>';
                                    WPProtector_Logger::log("Kritisch: Unbekannte Datei im Plugin (Rogue File): {$name} -> " . esc_html($relative_path) . $actions, "plugins", "error");
                                }
                            }
                        }
                    }
                }
            }
            
            if ( $end >= $total ) {
                WPProtector_Logger::log(__("Plugin signature check completed.", "wpprotector"), "plugins", "success");
                return array('complete' => true, 'message' => 'Plugin Scan abgeschlossen');
            }
            
            return array(
                'complete' => false,
                'next_payload' => array('step' => 'process', 'plugins' => $plugins, 'index' => $end),
                'message' => 'Prüfe Plugins (' . $end . '/' . $total . ')...'
            );
        }
        
        return array('complete' => true);
    }
}
