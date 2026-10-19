<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class Metzler_Webshield_Scanner_Files {
    public function run_step($payload): array {
        $step = $payload['step'] ?? 'init';
        
        if ( $step === 'init' ) {
            Metzler_Webshield_Logger::log(__("Starting heuristic malware search (complete file system scan)...", "metzler-webshield"), "files" );
            
            // ABSPATH covers wp-admin, wp-includes and usually wp-content, which only needs its own walk when it lives elsewhere
            $root_dir = rtrim(ABSPATH, '/\\');
            $content_dir = rtrim(WP_CONTENT_DIR, '/\\');
            $directories = $this->get_all_directories($root_dir);
            $directories[] = $root_dir;
            if ( ! str_starts_with( wp_normalize_path($content_dir) . '/', wp_normalize_path($root_dir) . '/' ) ) {
                $directories = array_merge($directories, $this->get_all_directories($content_dir));
                $directories[] = $content_dir;
            }
            
            $directories = array_values(array_unique($directories));
            $next_payload = array('step' => 'process', 'index' => 0);
            // Without a writable storage directory the list travels in the payload
            if ( ! Metzler_Webshield_Storage::save_scan_list( 'directories', $directories ) ) {
                $next_payload['directories'] = $directories;
            }
            
            return array(
                'complete' => false,
                'next_payload' => $next_payload,
                'message' => 'Scanning file system...'
            );
        }
        
        if ( $step === 'process' ) {
            $directories = $payload['directories'] ?? Metzler_Webshield_Storage::load_scan_list( 'directories' );
            $index = isset($payload['index']) ? intval($payload['index']) : 0;
            $batch_size = 20; 
            
            $total = count($directories);
            $end = min($index + $batch_size, $total);
            $upload_dir = wp_upload_dir();
            $uploads_base = str_replace('\\', '/', $upload_dir['basedir']);
            
            $bad_extensions = array('php', 'phtml', 'php5', 'sh', 'exe', 'pl', 'cgi');
            $bad_filenames = array('.user.ini', 'php.ini', 'web.config');
              
              // Core and plugin files that match the official wp.org checksums are skipped
              $core_checksums = get_transient( 'metzler_webshield_core_checksums' );
              if ( !is_array($core_checksums) ) $core_checksums = array();
              $core_checksums_en = get_transient( 'metzler_webshield_core_checksums_en' );
              if ( !is_array($core_checksums_en) ) $core_checksums_en = array();
              $plugin_verified = get_transient( 'metzler_webshield_plugin_verified' );
              if ( !is_array($plugin_verified) ) $plugin_verified = array();
              $whitelist = get_option( 'metzler_webshield_whitelist', array() );
              if ( !is_array($whitelist) ) $whitelist = array();
            
            // Malware Signatures (Heuristics) - Obfuscated in code to prevent self-detection (False Positive on scanner itself)
            $malware_patterns = array(
                // 1. Generic Obfuscation & Dynamic Execution
                'dyn-exec-input' => array( '\\$[a-zA-Z-�][a-zA-Z0-9_-�]*\s*\(\s*\\$_(POST|GET|REQUEST|FILES)', __('Dynamic function execution with user input (Dropper heuristic)', 'metzler-webshield') ),
                'rot13-static' => array( 'str_rot13\s*\(\s*["\'\']\w+["\'\']\s*\)', __('str_rot13 on static strings (Obfuscation heuristic)', 'metzler-webshield') ),
                'system-cmd-input' => array( '(system|shell_exec|exec|passthru)\s*\(\s*(base64_decode|gzinflate|str_rot13|\\$_(POST|GET|REQUEST|COOKIE|HEADER))', __('Dangerous system commands with user input', 'metzler-webshield') ),
                'dropper-base64-file' => array( 'file_put_contents\s*\([^;]*?,\s*base64_decode', __('File Dropper heuristic (Base64 to file)', 'metzler-webshield') ), // [^;] keeps the match inside one statement
                'eval-gzuncompress-base64' => array( 'eval\s*\(\s*gzuncompress\s*\(\s*base64_decode', __('Gzuncompress/Base64 obfuscation', 'metzler-webshield') ),
                'preg-replace-e' => array( 'preg_replace\s*\(\s*["\'\']\/(.*?)\/e["\'\']', __('preg_replace /e code execution', 'metzler-webshield') ),
                'assert-base64' => array( 'assert\s*\(\s*base64_decode', __('Assert Base64 code execution', 'metzler-webshield') ),
                // 2. Legacy/Specific Signatures
                'eval-base64' => array( 'eval\s*\(\s*base64_decode\s*\(', __('Base64-encoded backdoor (Dropper)', 'metzler-webshield') ),
                'preg-replace-e-legacy' => array( 'preg_replace\s*\(\s*[\'"](.)(.*?)\\\\1[a-z]*e[a-z]*[\'"]', __('Deprecated preg_replace injection (/e modifier)', 'metzler-webshield') ),
                'wso-shell' => array( 'FilesM[a]n', __('Web Shell signature (WSO/F-Man)', 'metzler-webshield') ),
                'b3-74k-shell' => array( 'b37[4]k', __('Web Shell signature (b3-74k)', 'metzler-webshield') ),
                'globals-var-func' => array( '\\$GLOBALS\\[\\w+\\]\s*\(\s*\\$GLOBALS', __('Hidden variable-function injection', 'metzler-webshield') ),
                'post-payload-exec' => array( '\\$_POST\\[\\w+\\]\s*\(\s*\\$_POST', __('Direct POST payload execution', 'metzler-webshield') ), // phpcs:ignore WordPress.Security.ValidatedSanitizedInput, WordPress.Security.NonceVerification
                'assert-input' => array( 'assert\s*\(\s*\\$_', __('Assert injection (PHP <= 7.1)', 'metzler-webshield') ),
                'eval-gzinflate-base64' => array( 'eval\s*\(\s*gzinflate\s*\(\s*base64_decode', __('Compressed Base64 backdoor', 'metzler-webshield') ),
                // 3. Campaign signatures (lock360 backdoor)
                'lock360-split-name' => array( '["\'][.]["\']\s*[.]\s*["\']ht[a]ccess["\']|["\']robots["\']\s*[.]\s*["\'][.]txt["\']', __('Split .htaccess/robots.txt file name to evade scanners (lock360 backdoor)', 'metzler-webshield') ),
                'lock360-curl-ua' => array( 'CURLOPT_USERAGENT\s*,\s*["\'][a-z0-9]["\']\s*\)', __('Single character cURL user agent of a remote controlled backdoor (lock360)', 'metzler-webshield') )
            );
            
            for ( $i = $index; $i < $end; $i++ ) {
                $dir = $directories[$i];
                if ( ! is_dir($dir) ) continue;
                
                $files = scandir($dir);
                foreach ( $files as $file ) {
                    if ( $file === '.' || $file === '..' ) continue;
                    
                    $full_path = $dir . DIRECTORY_SEPARATOR . $file;
                    if ( is_file($full_path) ) {
                        $relative_path = ltrim(str_replace(ABSPATH, '', $full_path), '/\\');
                        $relative_path = str_replace('\\', '/', $relative_path);
                        if ( in_array($relative_path, $whitelist, true) || Metzler_Webshield_Storage::is_own_file($full_path) ) {
                            continue;
                        }

                        $ext = strtolower(pathinfo($file, PATHINFO_EXTENSION));
                        $basename = strtolower(basename($file));
                        $normalized_path = str_replace('\\', '/', $full_path);
                        $is_in_uploads = ( str_starts_with( $normalized_path, $uploads_base ) );
                        
                        $threat_found = false;
                        $threat_reason = '';
                        $threat_rule = '';
                        
                        // Rule 1: No executable code files allowed in Uploads
                        if ( $is_in_uploads ) {
                            if ( in_array($ext, $bad_extensions, true) || in_array($basename, $bad_filenames, true) ) {
                                $is_safe_dummy = false;
                                if ( $basename === 'index.php' ) {
                                    $content = trim(file_get_contents($full_path));
                                    $is_safe_dummy = self::is_strictly_dummy_index($content);
                                }
                                if ( ! $is_safe_dummy ) {
                                    $threat_found = true;
                                    $threat_rule = 'uploads-exec';
                                    $threat_reason = __('Executable code file in uploads directory.', 'metzler-webshield');
                                }
                            }
                        }
                        
                        // Rule 2: Secure .htaccess and web.config (also in Root)
                        if ( !$threat_found && $basename === '.htaccess' ) {
                            $content = file_get_contents($full_path);
                            // auto_prepend_file is fine for the firewall bootstrap (extended protection), not for anything else
                            if ( preg_match('/php_flag\s+engine\s+(on|1)/i', $content) ||
                                 Metzler_Webshield_Firewall_Setup::has_foreign_prepend( $content ) ||
                                 preg_match('/(sethandler|addhandler|addtype)\s+[^>\n]*php/i', $content) ) {
                                $threat_found = true;
                                $threat_rule = 'htaccess-php-handler';
                                $threat_reason = __('Dangerous PHP activation in .htaccess file.', 'metzler-webshield');
                            } elseif ( $this->is_backdoor_allowlist_htaccess( $content ) ) {
                                $threat_found = true;
                                $threat_rule = 'htaccess-lock360';
                                $threat_reason = __('.htaccess blocks all PHP files except a list of backdoor names (lock360 pattern).', 'metzler-webshield');
                            }
                        }
                        if ( !$threat_found && ( $basename === '.user.ini' || $basename === 'php.ini' ) ) {
                            if ( Metzler_Webshield_Firewall_Setup::has_foreign_prepend( (string) file_get_contents($full_path) ) ) {
                                $threat_found = true;
                                $threat_rule = 'ini-prepend';
                                $threat_reason = __('PHP file injected into every request via auto_prepend_file.', 'metzler-webshield');
                            }
                        }
                        if ( !$threat_found && $basename === 'web.config' ) {
                            $content = strtolower(file_get_contents($full_path));
                            if ( str_contains( $content, 'php' ) && str_contains( $content, 'handler' ) ) {
                                $threat_found = true;
                                $threat_rule = 'webconfig-handler';
                                $threat_reason = __('Dangerous handler in web.config file.', 'metzler-webshield');
                            }
                        }
                        
                        // Rule 3: Scan PHP files (anywhere) for malware heuristics
                        if ( !$threat_found && in_array($ext, array('php', 'phtml', 'php5')) && ! $this->is_verified_original( $relative_path, $full_path, $core_checksums, $core_checksums_en, $plugin_verified ) ) {
                            
                            // Heuristic scan
                            $content = file_get_contents($full_path);
                            foreach ( $malware_patterns as $rule_id => $rule ) {
                                if ( preg_match('/' . $rule[0] . '/is', $content) ) {
                                    $threat_found = true;
                                    $threat_rule = $rule_id;
                                    $threat_reason = __('Malware signature found:', 'metzler-webshield') . ' ' . $rule[1];
                                    break;
                                }
                            }
                        }
                        
                        if ( $threat_found ) {
                            $relative_path = ltrim(str_replace(ABSPATH, '', $full_path), '/\\');
                            $relative_path = str_replace('\\', '/', $relative_path);
                            
                            $actions = '<br><button type="button" class="button button-small metzler-webshield-q-safe" data-path="'.esc_attr($relative_path).'">' . esc_html__('Mark as safe', 'metzler-webshield') . '</button> ';
                            $actions .= '<button type="button" class="button button-small button-primary metzler-webshield-q-move" data-path="'.esc_attr($relative_path).'" style="background:#d63638;border-color:#d63638;">' . esc_html__('Move to quarantine', 'metzler-webshield') . '</button>';
                            $actions .= Metzler_Webshield_Findings::lab_button( $relative_path );
                            
                            /* translators: 1: threat reason, 2: file path, 3: action buttons */
                            Metzler_Webshield_Logger::log(sprintf( __('Critical: %1$s (%2$s)%3$s', 'metzler-webshield'), $threat_reason, $relative_path, $actions ), "files", "error");
                            Metzler_Webshield_Findings::report( $relative_path, $full_path, 'files', $threat_rule );
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
                'next_payload' => isset($payload['directories']) ? array('step' => 'process', 'directories' => $directories, 'index' => $end) : array('step' => 'process', 'index' => $end),
                /* translators: 1: current index, 2: total directories */
                'message' => sprintf(__('Scanning directories (%1$d/%2$d)...', 'metzler-webshield'), $end, $total)
            );
        }
        
        return array('complete' => true);
    }
    
    /**
     * Files plugins create to lock down their own folders (backup storage, caches): a silent
     * index.php, or .htaccess / web.config that only restrict access. Anything that enables PHP,
     * grants access or rewrites requests does not qualify.
     */
    public static function is_protection_file( string $path ): bool {
        $content = (string) @file_get_contents( $path ); // phpcs:ignore
        switch ( strtolower( basename( $path ) ) ) {
            case 'index.php':
                return self::is_strictly_dummy_index( trim( $content ) );
            case '.htaccess':
                // Access granted only to non-executable files (e.g. <FilesMatch "\.log$">) is fine
                $content = preg_replace_callback( '/<Files(?:Match)?\s+"?([^">]*)"?\s*>.*?<\/Files(?:Match)?>/is', function ( $block ) {
                    $allows_code = preg_match( '/ph(p|t|ar)|\.\*|^\*$|^\.$/i', $block[1] );
                    return $allows_code ? $block[0] : '';
                }, $content );
                return ! preg_match( '/php_(flag|value|admin_flag|admin_value)|auto_(prepend|append)_file|(sethandler|addhandler|addtype|forcetype)\s+[^\n]*php|allow\s+from\s+all|require\s+all\s+granted|rewrite(rule|cond)/i', $content );
            case 'web.config':
                return ! preg_match( '/handler|rewrite|<allow\s/i', $content );
        }
        return false;
    }

    /**
     * The lock360 backdoor denies every PHP file and then allows only its own entry points,
     * which breaks the site while keeping the backdoor reachable. Hardening rules deny PHP
     * without re-allowing a whole list of file names.
     */
    private function is_backdoor_allowlist_htaccess( string $content ): bool {
        if ( ! preg_match_all('/<FilesMatch\s+"([^"]*)"\s*>(.*?)<\/FilesMatch>/is', $content, $blocks, PREG_SET_ORDER) ) {
            return false;
        }
        $denies_php = false;
        $allowed_names = 0;
        foreach ( $blocks as $block ) {
            $is_deny  = (bool) preg_match('/deny\s+from\s+all|require\s+all\s+denied/i', $block[2]);
            $is_allow = (bool) preg_match('/allow\s+from\s+all|require\s+all\s+granted/i', $block[2]);
            if ( $is_deny && stripos($block[1], 'php') !== false && ! preg_match('/\.php\b.*\|/i', $block[1]) ) {
                $denies_php = true;
            }
            if ( $is_allow ) {
                $allowed_names = max( $allowed_names, preg_match_all('/[\w-]+(?:\\\\)?\.php/i', $block[1]) );
            }
        }
        return $denies_php && $allowed_names >= 3;
    }

    private function is_verified_original( string $relative_path, string $full_path, array $core_checksums, array $core_checksums_en, array $plugin_verified ): bool {
        $expected = array();
        foreach ( array( $core_checksums, $core_checksums_en, $plugin_verified ) as $source ) {
            if ( isset($source[$relative_path]) ) {
                $expected[] = $source[$relative_path];
            }
        }
        if ( empty($expected) ) {
            return false;
        }
        $actual = md5_file($full_path);
        foreach ( $expected as $hashes ) {
            if ( Metzler_Webshield_Scanner_Core::hash_matches( $hashes, $actual ) ) {
                return true;
            }
        }
        return false;
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
            /* translators: %s: error message */
            Metzler_Webshield_Logger::log(sprintf( __("Could not read directory: %s", "metzler-webshield"), $e->getMessage() ), "files", "warning");
        }
        
        return $dirs;
    }

    /**
     * Verify that an index.php file contains strictly dummy silence comments, exit/die,
     * or directory listing prevention headers (e.g., 404 Not Found),
     * with ZERO executable statements, functions, variables, or payloads.
     */
    public static function is_strictly_dummy_index( string $content ): bool {
        // Standard silence and directory protection files are strictly under 500 bytes
        if ( strlen( $content ) > 500 ) {
            return false;
        }

        // Plain text without any opening tag is never executed (also no short tags like <? or <?=)
        if ( strpos( $content, '<?' ) === false ) {
            return true;
        }

        $tokens = token_get_all( $content );
        $allowed_strings = array( 'defined', 'header', 'http_response_code', 'exit', 'die' );

        foreach ( $tokens as $token ) {
            if ( is_array( $token ) ) {
                $type = $token[0];
                $val  = $token[1];

                // Allowed non-executable tokens: PHP open tag, comments, phpdoc, whitespace, close tag, exit/die
                if ( in_array( $type, array( T_OPEN_TAG, T_CLOSE_TAG, T_WHITESPACE, T_COMMENT, T_DOC_COMMENT, T_EXIT ), true ) ) {
                    continue;
                }
                // Allowed safe protection functions / WP check
                if ( $type === T_STRING && in_array( strtolower( $val ), $allowed_strings, true ) ) {
                    continue;
                }
                // Allowed server variable (e.g. $_SERVER['SERVER_PROTOCOL'])
                if ( $type === T_VARIABLE && $val === '$_SERVER' ) {
                    continue;
                }
                // Allowed string literals & HTTP status codes (e.g. 'ABSPATH', ' 404 Not Found', 404)
                if ( $type === T_CONSTANT_ENCAPSED_STRING || $type === T_LNUMBER ) {
                    continue;
                }
                // Allowed boolean logic (e.g. defined('ABSPATH') || exit;)
                if ( in_array( $type, array( T_BOOLEAN_OR, T_BOOLEAN_AND ), true ) ) {
                    continue;
                }

                // Any other PHP token (malicious functions, user variables, eval, backticks, assignments) -> alert!
                return false;
            } else {
                // Allowed punctuation associated with exit, header(), defined(), array access, string concatenation
                if ( in_array( $token, array( ';', '(', ')', '!', '[', ']', '.', ',' ), true ) ) {
                    continue;
                }

                // Any other character (e.g. assignment '=', execution backtick '`') means executable content!
                return false;
            }
        }

        return true;
    }
}

