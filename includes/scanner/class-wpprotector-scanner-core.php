<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class WPProtector_Scanner_Core {
    public function run_step($payload): array {
        $step = $payload['step'] ?? 'init';
        
        if ( $step === 'init' ) {
            global $wp_version;
            $locale = get_locale();
            
            WPProtector_Logger::log("Lade Core-Checksums für WordPress $wp_version ($locale) von WordPress.org...", "core" );
            
            $url = "https://api.wordpress.org/core/checksums/1.0/?version=$wp_version&locale=$locale";
            $response = wp_remote_get( $url );
            
            if ( is_wp_error( $response ) ) {
                WPProtector_Logger::log(__("Error retrieving Core checksums.", "wpprotector"), "core", "error");
                return array('complete' => true);
            }
            
            $body = wp_remote_retrieve_body( $response );
            $data = json_decode( $body, true );
            
            // wp.org returns an object where checksums might be deeply nested or simple, depending on version, 
            // but for 1.0 it is usually $data['checksums']
            if ( ! isset($data['checksums']) || ! is_array($data['checksums']) ) {
                WPProtector_Logger::log(__("Invalid response from WordPress.org API.", "wpprotector"), "core", "error");
                return array('complete' => true);
            }
            
            $checksums = $data['checksums'];
            $files = array_keys($checksums);
            
            // wp-content (Plugins, Themes) should not be checked by the core scanner
            $files = array_filter($files, function($f) {
                return ! str_starts_with( $f, 'wp-content/' );
            });
            $files = array_values($files);
            
            set_transient( 'wpprotector_core_checksums', $checksums, HOUR_IN_SECONDS );
            
            return array(
                'complete' => false,
                'next_payload' => array('step' => 'process', 'files' => $files, 'index' => 0),
                'message' => 'Core-Checksums geladen. Beginne Dateiprüfung...'
            );
        }
        
        if ( $step === 'process' ) {
            $files = $payload['files'] ?? array();
            $index = isset($payload['index']) ? intval($payload['index']) : 0;
            $batch_size = 200; 
            
            $checksums = get_transient( 'wpprotector_core_checksums' );
            if ( ! $checksums ) {
                WPProtector_Logger::log(__("Error: Checksums lost in cache.", "wpprotector"), "core", "error");
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
                        WPProtector_Logger::log(__("Core file modified: ", "wpprotector") . esc_html($file), "core", "error");
                    }
                }
            }
            
            if ( $end >= $total ) {
                WPProtector_Logger::log(__("WordPress Core file check completed.", "wpprotector"), "core", "success");
                delete_transient( 'wpprotector_core_checksums' );
                return array('complete' => true, 'message' => 'Core Scan abgeschlossen');
            }
            
            return array(
                'complete' => false,
                'next_payload' => array('step' => 'process', 'files' => $files, 'index' => $end),
                'message' => 'Prüfe Core-Dateien (' . $end . '/' . $total . ')...'
            );
        }
        
        return array('complete' => true);
    }
}
