<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class Metzler_Webshield_Scanner_Files {
    public function run_step($payload): array {
        $step = $payload['step'] ?? 'init';
        
        if ( $step === 'init' ) {
            Metzler_Webshield_Logger::log(__("Starting heuristic malware search (complete file system scan)...", "metzler-webshield"), "files" );
            
            $directories = array();
            
            // 1. wp-content (Plugins, Themes, Uploads, mu-plugins, etc. complete)
            $content_dir = WP_CONTENT_DIR;
            $directories = array_merge($directories, $this->get_all_directories($content_dir));
            $directories[] = $content_dir;
            
            // 2. ABSPATH (Root directory, wp-admin, wp-includes complete)
            $root_dir = rtrim(ABSPATH, '/\\');
            // To prevent timeouts when generating directory lists, we include root and 
            // direct subfolders (heuristics work on file level).
            // For maximum security, we actually scan everything completely (since FIM hashes drastically speed up the scan).
            $directories = array_merge($directories, $this->get_all_directories($root_dir));
            $directories[] = $root_dir;
            
            $directories = array_unique($directories);
            
            return array(
                'complete' => false,
                'next_payload' => array('step' => 'process', 'directories' => array_values($directories), 'index' => 0),
                'message' => 'Scanning file system...'
            );
        }
        
        if ( $step === 'process' ) {
            $directories = $payload['directories'] ?? array();
            $index = isset($payload['index']) ? intval($payload['index']) : 0;
            $batch_size = 20; 
            
            $total = count($directories);
            $end = min($index + $batch_size, $total);
            $upload_dir = wp_upload_dir();
            $uploads_base = str_replace('\\', '/', $upload_dir['basedir']);
            
            $bad_extensions = array('php', 'phtml', 'php5', 'sh', 'exe', 'pl', 'cgi');
            $bad_filenames = array('.htaccess', '.user.ini', 'php.ini', 'web.config');
              
              // Load WordPress Core Checksums to skip valid core files for massive performance boost
              $core_checksums = get_transient( 'metzler_webshield_core_checksums' );
              if ( !is_array($core_checksums) ) $core_checksums = array();
            
            // Malware Signatures (Heuristics) - Obfuscated in code to prevent self-detection (False Positive on scanner itself)
            $malware_patterns = array(
                // 1. Generic Obfuscation & Dynamic Execution
                '\\$[a-zA-Z-�][a-zA-Z0-9_-�]*\s*\(\s*\\$_(POST|GET|REQUEST|FILES)' => __('Dynamic function execution with user input (Dropper heuristic)', 'metzler-webshield'),
                'str_rot13\s*\(\s*["\'\']\w+["\'\']\s*\)' => __('str_rot13 on static strings (Obfuscation heuristic)', 'metzler-webshield'),
                '(system|shell_exec|exec|passthru)\s*\(\s*(base64_decode|gzinflate|str_rot13|\\$_(POST|GET|REQUEST|COOKIE|HEADER))' => __('Dangerous system commands with user input', 'metzler-webshield'),
                'file_put_contents\s*\(\s*.*?\s*,\s*base64_decode' => __('File Dropper heuristic (Base64 to file)', 'metzler-webshield'),
                'eval\s*\(\s*gzuncompress\s*\(\s*base64_decode' => __('Gzuncompress/Base64 obfuscation', 'metzler-webshield'),
                'preg_replace\s*\(\s*["\'\']\/(.*?)\/e["\'\']' => __('preg_replace /e code execution', 'metzler-webshield'),
                'assert\s*\(\s*base64_decode' => __('Assert Base64 code execution', 'metzler-webshield'),
                // 2. Legacy/Specific Signatures
                'eval\s*\(\s*base64_decode\s*\(' => __('Base64-encoded backdoor (Dropper)', 'metzler-webshield'),
                'preg_replace\s*\(\s*[\'"](.)(.*?)\\\\1[a-z]*e[a-z]*[\'"]' => __('Deprecated preg_replace injection (/e modifier)', 'metzler-webshield'),
                'FilesM[a]n' => __('Web Shell signature (WSO/F-Man)', 'metzler-webshield'),
                'b37[4]k' => __('Web Shell signature (b3-74k)', 'metzler-webshield'),
                '\\$GLOBALS\\[\\w+\\]\s*\(\s*\\$GLOBALS' => __('Hidden variable-function injection', 'metzler-webshield'),
                '\\$_POST\\[\\w+\\]\s*\(\s*\\$_POST' => 'Direkte POST-Payload Ausführung', // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification
                'assert\s*\(\s*\\$_' => __('Assert injection (PHP <= 7.1)', 'metzler-webshield'),
                'eval\s*\(\s*gzinflate\s*\(\s*base64_decode' => __('Compressed Base64 backdoor', 'metzler-webshield')
            );
            
            for ( $i = $index; $i < $end; $i++ ) {
                $dir = $directories[$i];
                if ( ! is_dir($dir) ) continue;
                
                $files = scandir($dir);
                foreach ( $files as $file ) {
                    if ( $file === '.' || $file === '..' ) continue;
                    
                    $full_path = $dir . DIRECTORY_SEPARATOR . $file;
                    if ( is_file($full_path) ) {
                        $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
                        $basename = strtolower(basename($file));
                        $normalized_path = str_replace('\\', '/', $full_path);
                        $is_in_uploads = ( str_starts_with( $normalized_path, $uploads_base ) );
                        
                        $threat_found = false;
                        $threat_reason = '';
                        
                        // Rule 1: No executable file is allowed in Uploads (except empty index.php)
                        if ( $is_in_uploads ) {
                            if ( in_array($ext, $bad_extensions) || in_array($basename, $bad_filenames) ) {
                                if ( $basename === 'index.php' ) {
                                    $content = trim(file_get_contents($full_path));
                                    if ( $content === '<?php' || str_contains( $content, 'Silence is golden' ) || $content === '<?php // Silence is golden.' || $content === '' ) {
                                        continue;
                                    }
                                }
                                $threat_found = true;
                                $threat_reason = 'Ausführbare Datei im Upload-Verzeichnis.';
                            }
                        }
                        
                        // Rule 2: Secure .htaccess and web.config (also in Root)
                        if ( !$threat_found && $basename === '.htaccess' ) {
                            $content = strtolower(file_get_contents($full_path));
                            if ( preg_match('/php_flag\s+engine\s+(on|1)/i', $content) ||
                                 preg_match('/php_value\s+(auto_prepend_file|auto_append_file)/i', $content) ||
                                 preg_match('/(sethandler|addhandler|addtype)\s+[^>\n]*php/i', $content) ) {
                                $threat_found = true;
                                $threat_reason = 'Gefährliche PHP-Aktivierung in .htaccess Datei.';
                            }
                        }
                        if ( !$threat_found && $basename === 'web.config' ) {
                            $content = strtolower(file_get_contents($full_path));
                            if ( str_contains( $content, 'php' ) && str_contains( $content, 'handler' ) ) {
                                $threat_found = true;
                                $threat_reason = 'Gefährlicher Handler in web.config Datei.';
                            }
                        }
                        
                        // Rule 3: Scan PHP files (anywhere) for malware heuristics
                        if ( !$threat_found && in_array($ext, array('php', 'phtml', 'php5')) ) {
                            
                            // Heuristic scan
                            $content = file_get_contents($full_path);
                            foreach ( $malware_patterns as $pattern => $name ) {
                                if ( preg_match('/' . $pattern . '/is', $content) ) {
                                    $threat_found = true;
                                    $threat_reason = 'Malware-Signatur gefunden: ' . $name;
                                    break;
                                }
                            }
                        }
                        
                        if ( $threat_found ) {
                            $relative_path = ltrim(str_replace(ABSPATH, '', $full_path), '/\\');
                            $relative_path = str_replace('\\', '/', $relative_path);
                            
                            $actions = '<br><button type="button" class="button button-small metzler-webshield-q-safe" data-path="'.esc_attr($relative_path).'">Als sicher markieren</button> ';
                            $actions .= '<button type="button" class="button button-small button-primary metzler-webshield-q-move" data-path="'.esc_attr($relative_path).'" style="background:#d63638;border-color:#d63638;">In Quarantäne verschieben</button>';
                            
                            Metzler_Webshield_Logger::log(sprintf( __('Critical: %1$s (%2$s)%3$s', 'metzler-webshield'), $threat_reason, $relative_path, $actions ), "files", "error");
                        }
                    }
                }
            }
            
            if ( $end >= $total ) {
                Metzler_Webshield_Logger::log(__("Deep scan of the file system completed.", "metzler-webshield"), "files", "success");
                return array('complete' => true, 'message' => __('Deep scan completed.', 'metzler-webshield'));
            }
            
            return array(
                'complete' => false,
                'next_payload' => array('step' => 'process', 'directories' => $directories, 'index' => $end),
                'message' => sprintf(__('Scanning directories (%d/%d)...', 'metzler-webshield'), $end, $total)
            );
        }
        
        return array('complete' => true);
    }
    
    private function get_all_directories($base) {
        $dirs = array();
        if ( ! is_dir($base) ) return $dirs;
        
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::SELF_FIRST
            );
            
            foreach ( $iterator as $path ) {
                if ( $path->isDir() ) {
                    $dirs[] = $path->getPathname();
                }
            }
        } catch (Exception $e) {
            Metzler_Webshield_Logger::log(sprintf( __("Could not read directory: %s", "metzler-webshield"), $e->getMessage() ), "files", "warning");
        }
        
        return $dirs;
    }
}
