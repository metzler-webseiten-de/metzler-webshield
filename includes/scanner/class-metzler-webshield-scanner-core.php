<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class Metzler_Webshield_Scanner_Core {
    public function run_step($payload): array {
        $step = $payload['step'] ?? 'init';
        
        if ( $step === 'init' ) {
            global $wp_version;
            $locale = get_locale();
            
            Metzler_Webshield_Logger::log(sprintf( __('Loading Core checksums for WordPress %1$s (%2$s) from WordPress.org...', 'metzler-webshield'), $wp_version, $locale ), "core" );
            
            $api_url = defined( 'METZLER_WEBSHIELD_API_URL' ) ? METZLER_WEBSHIELD_API_URL : 'https://api.metzler-webshield.de/api';
            $token = get_option( 'metzler_webshield_license_token' );
            $url = $api_url . "/scanner/threat-intel/core?version=$wp_version&locale=$locale";
            $response = wp_remote_get( $url, array(
                'timeout' => 15,
                'headers' => array(
                    'Authorization' => 'Bearer ' . $token,
                )
            ) );
            
            if ( is_wp_error( $response ) ) {
                Metzler_Webshield_Logger::log(__("Error retrieving Core checksums.", "metzler-webshield"), "core", "error");
                return array('complete' => true);
            }
            
            $body = wp_remote_retrieve_body( $response );
            $data = json_decode( $body, true );
            
            // 1. Process Threat Intelligence (Vulnerabilities)
            if ( !empty($data['vulnerabilities']) && is_array($data['vulnerabilities']) ) {
                foreach ( $data['vulnerabilities'] as $vuln ) {
                    $title = isset($vuln['title']) ? $vuln['title'] : __('Unknown vulnerability', 'metzler-webshield');
                    Metzler_Webshield_Logger::log(
                        sprintf(
                            /* translators: %s: Vulnerability title */
                            __('CRITICAL: Known Core vulnerability found: %s', 'metzler-webshield'),
                            $title
                        ), 
                        "core", 
                        "critical" 
                    );
                }
            }
            
            // 2. Extract checksums from Threat Intel wrapper
            $api_data = isset($data['checksums']) ? $data['checksums'] : $data;
            
            // Handle offers wrapper from wp.org if passed through raw
            if ( isset($api_data['offers']) && is_array($api_data['offers']) && !empty($api_data['offers']) ) {
                $api_data = $api_data['offers'][0];
            }
            
            if ( ! isset($api_data['checksums']) || ! is_array($api_data['checksums']) ) {
                // Check if api_data IS the checksum array directly (no wrapper)
                if ( is_array($api_data) && !empty($api_data) && !isset($api_data['checksums']) && !isset($api_data['offers']) ) {
                    $checksums = $api_data;
                } else {
                    Metzler_Webshield_Logger::log(__("Invalid response from WordPress.org API.", "metzler-webshield"), "core", "error");
                    return array('complete' => true);
                }
            } else {
                $checksums = $api_data['checksums'];
            }
            $files = array_keys($checksums);
            
            // wp-content (Plugins, Themes) should not be checked by the core scanner
            $files = array_filter($files, function($f) {
                return ! str_starts_with( $f, 'wp-content/' );
            });
            $files = array_values($files);
            
            set_transient( 'metzler_webshield_core_checksums', $checksums, HOUR_IN_SECONDS );
            
            return array(
                'complete' => false,
                'next_payload' => array('step' => 'process', 'files' => $files, 'index' => 0),
                'message' => __('Core checksums loaded. Starting file check...', 'metzler-webshield')
            );
        }
        
        if ( $step === 'process' ) {
            $files = $payload['files'] ?? array();
            $index = isset($payload['index']) ? intval($payload['index']) : 0;
            $batch_size = 200; 
            
            $checksums = get_transient( 'metzler_webshield_core_checksums' );
            if ( ! $checksums ) {
                Metzler_Webshield_Logger::log(__("Error: Checksums lost in cache.", "metzler-webshield"), "core", "error");
                return array('complete' => true);
            }
            
            $total = count($files);
            $end = min($index + $batch_size, $total);
            
            for ( $i = $index; $i < $end; $i++ ) {
                $file = $files[$i];
	            // Some API versions return array of hashes for a file
                if ( is_array($checksums[$file]) ) {
                     $expected_md5 = $checksums[$file][0];
                } else {
                     $expected_md5 = $checksums[$file];
                }
                
                $abs_path = ABSPATH . $file;
                
                if ( file_exists( $abs_path ) ) {
                    $actual_md5 = md5_file( $abs_path );
                    // Fallback to check if the actual md5 is in the array of accepted hashes if wp api provides multiple
	                if ( is_array($checksums[$file]) ) {
                        $is_valid = in_array($actual_md5, $checksums[$file]);
                    } else {
                        $is_valid = ($actual_md5 === $expected_md5);
                    }
                    
                    if ( ! $is_valid ) {
                        Metzler_Webshield_Logger::log(sprintf( __("Core file modified: %s", "metzler-webshield"), esc_html($file) ), "core", "error");
                    }
                }
            }
            
            if ( $end >= $total ) {
                Metzler_Webshield_Logger::log(__("WordPress Core file check completed.", "metzler-webshield"), "core", "success");
                // delete_transient( 'metzler_webshield_core_checksums' ); // Removed so the file scanner can reuse it for performance!
                return array('complete' => true, 'message' => __('Core scan completed', 'metzler-webshield'));
            }
            
            return array(
                'complete' => false,
                'next_payload' => array('step' => 'process', 'files' => $files, 'index' => $end),
                'message' => sprintf(__('Checking core files (%1$d/%2$d)...', 'metzler-webshield'), $end, $total)
            );
        }
        
        return array('complete' => true);
    }
}
