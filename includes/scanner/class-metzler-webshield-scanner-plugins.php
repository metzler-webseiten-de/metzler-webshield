<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class Metzler_Webshield_Scanner_Plugins {
    
    public function run_step($payload): array {
        $step = $payload['step'] ?? 'init';
        
        if ( $step === 'init' ) {
            Metzler_Webshield_Logger::log(__("Collecting list of installed plugins...", "metzler-webshield"), "plugins" );
            delete_transient( 'metzler_webshield_plugin_verified' );
            
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
            
            $whitelist = get_option('metzler_webshield_whitelist', array());
            if ( ! is_array($whitelist) ) $whitelist = array();
            
            // PHP files matching wp.org are skipped by the heuristic file scanner
            $verified = get_transient( 'metzler_webshield_plugin_verified' );
            if ( ! is_array($verified) ) $verified = array();
            
            for ( $i = $index; $i < $end; $i++ ) {
                $plugin = $plugins[$i];
                $slug = dirname($plugin['file']);
                $version = $plugin['version'];
                $name = $plugin['name'];
                
                if ( $slug === '.' ) continue;
                
                $response = wp_remote_get( 'https://downloads.wordpress.org/plugin-checksums/' . rawurlencode( $slug ) . '/' . rawurlencode( $version ) . '.json', array(
                    'timeout' => 15,
                ) );
                
                if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) !== 200 ) {
                    /* translators: %s: Plugin name */
                    Metzler_Webshield_Logger::log(sprintf( __("No wp.org signature available for plugin: %s", "metzler-webshield"), $name ), "plugins" );
                    continue;
                }
                
                $checksums_data = json_decode( wp_remote_retrieve_body( $response ), true );
                
                if ( isset($checksums_data['files']) && is_array($checksums_data['files']) ) {
                    $plugin_dir = WP_PLUGIN_DIR . '/' . $slug;
                    
                    // 1. Check if core files are modified
                    foreach ( $checksums_data['files'] as $file_name => $hashes ) {
                        $local_file = $plugin_dir . '/' . $file_name;
                        
                        if ( file_exists($local_file) ) {
                            $actual_hash = md5_file($local_file);
                            $relative_path = ltrim(str_replace(ABSPATH, '', $local_file), '/\\');
                            $relative_path = str_replace('\\', '/', $relative_path);
                            
                            if ( Metzler_Webshield_Scanner_Core::hash_matches( $hashes['md5'] ?? null, $actual_hash ) ) {
                                if ( Metzler_Webshield_Scanner_Core::is_executable_file( $file_name ) ) {
                                    $verified[$relative_path] = $actual_hash;
                                }
                                continue;
                            }
                            
                            if ( ! in_array($relative_path, $whitelist, true) ) {
                                $actions = '<br><button type="button" class="button button-small metzler-webshield-q-safe" data-path="'.esc_attr($relative_path).'">' . esc_html__('Mark as safe', 'metzler-webshield') . '</button> ';
                                $actions .= '<button type="button" class="button button-small button-primary metzler-webshield-q-move" data-path="'.esc_attr($relative_path).'" style="background:#d63638;border-color:#d63638;">' . esc_html__('Move to quarantine', 'metzler-webshield') . '</button>';
                                $actions .= Metzler_Webshield_Findings::lab_button( $relative_path );
                                /* translators: 1: plugin name, 2: file name, 3: action buttons */
                                Metzler_Webshield_Logger::log(sprintf( __('Plugin file modified: %1$s -> %2$s%3$s', 'metzler-webshield'), $name, esc_html($file_name), $actions ), "plugins", "error");
                                Metzler_Webshield_Findings::report( $relative_path, $local_file, 'plugins', 'plugin-modified' );
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
                            
                            if ( isset($checksums_data['files'][$relative_path]) ) continue;
                            
                            $full_relative = ltrim(str_replace(ABSPATH, '', $local_file), '/\\');
                            $full_relative = str_replace('\\', '/', $full_relative);
                            if ( in_array($full_relative, $whitelist, true) ) continue;
                            
                            if ( Metzler_Webshield_Scanner_Files::is_protection_file( $local_file ) ) {
                                /* translators: 1: plugin name, 2: file name */
                                Metzler_Webshield_Logger::log(sprintf( __('Protection file created by the plugin (only restricts access): %1$s -> %2$s', 'metzler-webshield'), $name, esc_html($relative_path) ), "plugins", "info");
                                continue;
                            }
                            
                            // Plugins generate stylesheets, scripts and images at runtime, only executable files are a threat
                            if ( ! Metzler_Webshield_Scanner_Core::is_executable_file( $relative_path ) ) {
                                /* translators: 1: plugin name, 2: file name */
                                Metzler_Webshield_Logger::log(sprintf( __('Additional non-executable file in plugin (usually generated by the plugin itself): %1$s -> %2$s', 'metzler-webshield'), $name, esc_html($relative_path) ), "plugins", "info");
                                continue;
                            }
                            
                            $actions = '<br><button type="button" class="button button-small metzler-webshield-q-safe" data-path="'.esc_attr($full_relative).'">' . esc_html__('Mark as safe', 'metzler-webshield') . '</button> ';
                            $actions .= '<button type="button" class="button button-small button-primary metzler-webshield-q-move" data-path="'.esc_attr($full_relative).'" style="background:#d63638;border-color:#d63638;">' . esc_html__('Move to quarantine', 'metzler-webshield') . '</button>';
                            $actions .= Metzler_Webshield_Findings::lab_button( $full_relative );
                            /* translators: 1: plugin name, 2: file name, 3: action buttons */
                            Metzler_Webshield_Logger::log(sprintf( __('Critical: Unknown file in plugin (Rogue File): %1$s -> %2$s%3$s', 'metzler-webshield'), $name, esc_html($relative_path), $actions ), "plugins", "error");
                            Metzler_Webshield_Findings::report( $full_relative, $local_file, 'plugins', 'plugin-rogue' );
                        }
                    }
                }
            }
            
            set_transient( 'metzler_webshield_plugin_verified', $verified, DAY_IN_SECONDS );
            
            if ( $end >= $total ) {
                Metzler_Webshield_Logger::log(__("Plugin signature check completed.", "metzler-webshield"), "plugins", "success");
                return array('complete' => true, 'message' => __('Plugin scan completed', 'metzler-webshield'));
            }
            
            return array(
                'complete' => false,
                'next_payload' => array('step' => 'process', 'plugins' => $plugins, 'index' => $end),
                /* translators: 1: current index, 2: total plugins */
                'message' => sprintf(__('Checking plugins (%1$d/%2$d)...', 'metzler-webshield'), $end, $total)
            );
        }
        
        return array('complete' => true);
    }
}
