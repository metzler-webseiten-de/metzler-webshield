<?php
class Metzler_Webshield_Scanner_Plugins {
    
    public function run_step($payload): array {
        $step = $payload['step'] ?? 'init';
        
        if ( $step === 'init' ) {
            Metzler_Webshield_Logger::log(__("Collecting list of installed plugins...", "metzler-webshield"), "plugins" );
            
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
                'message' => __('Loading plugin signatures...', 'metzler-webshield')
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
                
                $api_url = defined( 'METZLER_WEBSHIELD_API_URL' ) ? METZLER_WEBSHIELD_API_URL : 'https://api.metzler-webshield.de/api';
                $token = get_option( 'metzler_webshield_license_token' );
                $response = wp_remote_get( $api_url . "/scanner/threat-intel/plugin/{$slug}/{$version}", array(
                    'timeout' => 15,
                    'headers' => array(
                        'Authorization' => 'Bearer ' . $token,
                    )
                ) );
                
                if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) !== 200 ) {
                    Metzler_Webshield_Logger::log(sprintf( __("No wp.org signature available for plugin: %s", "metzler-webshield"), $name ), "plugins" );
                    continue;
                }
                
                $body = wp_remote_retrieve_body( $response );
                $data = json_decode( $body, true );
                
                // 1. Process Threat Intelligence (Vulnerabilities)
                if ( !empty($data['vulnerabilities']) && is_array($data['vulnerabilities']) ) {
                    foreach ( $data['vulnerabilities'] as $vuln ) {
                        $title = isset($vuln['title']) ? $vuln['title'] : __('Unknown vulnerability', 'metzler-webshield');
                        Metzler_Webshield_Logger::log(
                            sprintf(
                                /* translators: 1: Plugin name, 2: Vulnerability title */
                                __('CRITICAL: Known vulnerability found in plugin %1$s: %2$s', 'metzler-webshield'),
                                $name,
                                $title
                            ), 
                            "plugins", 
                            "critical" 
                        );
                    }
                }
                
                // 2. Extract checksums from Threat Intel wrapper
                $checksums_data = isset($data['checksums']) ? $data['checksums'] : $data;
                
                if ( isset($checksums_data['files']) && is_array($checksums_data['files']) ) {
                    $plugin_dir = WP_PLUGIN_DIR . '/' . $slug;
                    
                    // 1. Check if core files are modified
                    foreach ( $checksums_data['files'] as $file_name => $hashes ) {
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
                                
                                $baseline = $wpdb->get_row($wpdb->prepare("SELECT file_hash FROM {$wpdb->prefix}metzler_webshield_fim WHERE file_path = %s", $relative_path)); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter
                                if ( ! $baseline || $baseline->file_hash !== $actual_hash ) {
                                    $modifications_found++;
                                    $actions = '<br><button type="button" class="button button-small metzler-webshield-q-safe" data-path="'.esc_attr($relative_path).'">' . esc_html__('Mark as safe', 'metzler-webshield') . '</button> ';
                                    $actions .= '<button type="button" class="button button-small button-primary metzler-webshield-q-move" data-path="'.esc_attr($relative_path).'" style="background:#d63638;border-color:#d63638;">' . esc_html__('Move to quarantine', 'metzler-webshield') . '</button>';
                                    Metzler_Webshield_Logger::log(sprintf( __("Plugin file modified: %s -> %s%s", "metzler-webshield"), $name, esc_html($file_name), $actions ), "plugins", "error");
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
                                
                                $baseline = $wpdb->get_row($wpdb->prepare("SELECT file_hash FROM {$wpdb->prefix}metzler_webshield_fim WHERE file_path = %s", $full_relative)); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter
                                if ( ! $baseline || $baseline->file_hash !== md5_file($local_file) ) {
                                    $actions = '<br><button type="button" class="button button-small metzler-webshield-q-safe" data-path="'.esc_attr($full_relative).'">' . esc_html__('Mark as safe', 'metzler-webshield') . '</button> ';
                                    $actions .= '<button type="button" class="button button-small button-primary metzler-webshield-q-move" data-path="'.esc_attr($full_relative).'" style="background:#d63638;border-color:#d63638;">' . esc_html__('Move to quarantine', 'metzler-webshield') . '</button>';
                                    Metzler_Webshield_Logger::log(sprintf( __("Critical: Unknown file in plugin (Rogue File): %s -> %s%s", "metzler-webshield"), $name, esc_html($relative_path), $actions ), "plugins", "error");
                                }
                            }
                        }
                    }
                }
            }
            
            if ( $end >= $total ) {
                Metzler_Webshield_Logger::log(__("Plugin signature check completed.", "metzler-webshield"), "plugins", "success");
                return array('complete' => true, 'message' => __('Plugin scan completed', 'metzler-webshield'));
            }
            
            return array(
                'complete' => false,
                'next_payload' => array('step' => 'process', 'plugins' => $plugins, 'index' => $end),
                'message' => sprintf(__('Checking plugins (%1$d/%2$d)...', 'metzler-webshield'), $end, $total)
            );
        }
        
        return array('complete' => true);
    }
}
