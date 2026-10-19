<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class Metzler_Webshield_Scanner_Core {
    public function run_step($payload): array {
        $step = $payload['step'] ?? 'init';
        
        if ( $step === 'init' ) {
            global $wp_version;
            $locale = get_locale();
            
            /* translators: 1: WordPress version, 2: Locale */
            Metzler_Webshield_Logger::log(sprintf( __('Loading Core checksums for WordPress %1$s (%2$s) from WordPress.org...', 'metzler-webshield'), $wp_version, $locale ), "core" );
            
            $url = add_query_arg(
                array(
                    'version' => $wp_version,
                    'locale'  => $locale,
                ),
                'https://api.wordpress.org/core/checksums/1.0/'
            );
            $response = wp_remote_get( $url, array( 'timeout' => 15 ) );
            
            if ( is_wp_error( $response ) ) {
                Metzler_Webshield_Logger::log(__("Error retrieving Core checksums.", "metzler-webshield"), "core", "error");
                return array('complete' => true);
            }
            
            $api_data = json_decode( wp_remote_retrieve_body( $response ), true );
            $en_checksums = array();
            
            if ( $locale !== 'en_US' ) {
                $response = wp_remote_get( add_query_arg( array( 'version' => $wp_version, 'locale' => 'en_US' ), 'https://api.wordpress.org/core/checksums/1.0/' ), array( 'timeout' => 15 ) );
                $en_data = is_wp_error( $response ) ? array() : json_decode( wp_remote_retrieve_body( $response ), true );
                if ( ! empty($en_data['checksums']) && is_array($en_data['checksums']) ) {
                    if ( empty($api_data['checksums']) ) {
                        // Localized releases without own checksums fall back to en_US
                        $api_data = $en_data;
                    } else {
                        // Updates via the en_US package leave localized sites with en_US versions of locale specific files
                        $en_checksums = $en_data['checksums'];
                    }
                }
            }
            
            if ( empty($api_data['checksums']) || ! is_array($api_data['checksums']) ) {
                Metzler_Webshield_Logger::log(__("Invalid response from WordPress.org API.", "metzler-webshield"), "core", "error");
                return array('complete' => true);
            }
            $checksums = $api_data['checksums'];
            
            set_transient( 'metzler_webshield_core_checksums', $checksums, HOUR_IN_SECONDS );
            set_transient( 'metzler_webshield_core_checksums_en', $en_checksums, HOUR_IN_SECONDS );
            
            return array(
                'complete' => false,
                'next_payload' => array('step' => 'process', 'index' => 0),
                'message' => __('Core checksums loaded. Starting file check...', 'metzler-webshield')
            );
        }
        
        if ( $step === 'process' ) {
            $index = isset($payload['index']) ? intval($payload['index']) : 0;
            $batch_size = 200; 
            
            $checksums = get_transient( 'metzler_webshield_core_checksums' );
            if ( ! $checksums ) {
                Metzler_Webshield_Logger::log(__("Error: Checksums lost in cache.", "metzler-webshield"), "core", "error");
                return array('complete' => true);
            }
            
            // wp-content (Plugins, Themes) should not be checked by the core scanner
            $files = array_values(array_filter(array_keys($checksums), function($f) {
                return ! str_starts_with( $f, 'wp-content/' );
            }));
            
            $en_checksums = get_transient( 'metzler_webshield_core_checksums_en' );
            if ( ! is_array($en_checksums) ) $en_checksums = array();
            $whitelist = get_option('metzler_webshield_whitelist', array());
            if ( ! is_array($whitelist) ) $whitelist = array();
            
            $total = count($files);
            $end = min($index + $batch_size, $total);
            
            for ( $i = $index; $i < $end; $i++ ) {
                $file = $files[$i];
                $abs_path = ABSPATH . $file;
                
                if ( ! file_exists( $abs_path ) || in_array($file, $whitelist, true) ) {
                    continue;
                }
                
                $actual_md5 = md5_file( $abs_path );
                if ( self::hash_matches( $checksums[$file], $actual_md5 ) ) {
                    continue;
                }
                
                if ( isset($en_checksums[$file]) && self::hash_matches( $en_checksums[$file], $actual_md5 ) ) {
                    /* translators: %s: file path */
                    Metzler_Webshield_Logger::log(sprintf( __('Core file matches the English WordPress package instead of the installed language package (harmless, usually caused by an update via the English package): %s', 'metzler-webshield'), esc_html($file) ), "core", "info");
                    continue;
                }
                
                // Files shipped only with the language package (e.g. liesmich.html) are never executed
                if ( ! empty($en_checksums) && ! isset($en_checksums[$file]) && ! self::is_executable_file( $file ) ) {
                    /* translators: %s: file path */
                    Metzler_Webshield_Logger::log(sprintf( __('Language package file differs from the current version (harmless, not executable): %s', 'metzler-webshield'), esc_html($file) ), "core", "info");
                    continue;
                }
                
                $actions = '<br><button type="button" class="button button-small metzler-webshield-q-safe" data-path="'.esc_attr($file).'">' . esc_html__('Mark as safe', 'metzler-webshield') . '</button> ';
                $actions .= '<button type="button" class="button button-small button-primary metzler-webshield-q-move" data-path="'.esc_attr($file).'" style="background:#d63638;border-color:#d63638;">' . esc_html__('Move to quarantine', 'metzler-webshield') . '</button>';
                $actions .= Metzler_Webshield_Findings::lab_button( $file );
                /* translators: 1: file path, 2: action buttons */
                Metzler_Webshield_Logger::log(sprintf( __('Core file modified: %1$s%2$s', 'metzler-webshield'), esc_html($file), $actions ), "core", "error");
                Metzler_Webshield_Findings::report( $file, $abs_path, 'core', 'core-modified' );
            }
            
            if ( $end >= $total ) {
                return array(
                    'complete' => false,
                    'next_payload' => array('step' => 'unknown'),
                    'message' => __('Searching for unknown files in core directories...', 'metzler-webshield')
                );
            }

            return array(
                'complete' => false,
                'next_payload' => array('step' => 'process', 'index' => $end),
                /* translators: 1: current index, 2: total files */
                'message' => sprintf(__('Checking core files (%1$d/%2$d)...', 'metzler-webshield'), $end, $total)
            );
        }

        if ( $step === 'unknown' ) {
            $this->report_unknown_files();
            Metzler_Webshield_Logger::log(__("WordPress Core file check completed.", "metzler-webshield"), "core", "success");
            // The checksums stay cached for the file scanner
            return array('complete' => true, 'message' => __('Core scan completed', 'metzler-webshield'));
        }

        return array('complete' => true);
    }

    /**
     * Files in wp-admin/, wp-includes/ and wp-*.php in the root that are not part of WordPress.
     * Nothing but WordPress itself belongs there, so backdoors like to hide between the core files.
     */
    private function report_unknown_files(): void {
        $checksums = get_transient( 'metzler_webshield_core_checksums' );
        if ( ! is_array($checksums) ) return;
        $en_checksums = get_transient( 'metzler_webshield_core_checksums_en' );
        if ( is_array($en_checksums) ) $checksums += $en_checksums;
        $whitelist = get_option('metzler_webshield_whitelist', array());
        if ( ! is_array($whitelist) ) $whitelist = array();

        $root = rtrim(wp_normalize_path(ABSPATH), '/');
        $candidates = array();

        foreach ( (array) glob( $root . '/wp-*' ) as $path ) {
            $name = basename($path);
            if ( is_file($path) && $name !== 'wp-config.php' ) {
                $candidates[] = $name;
            }
        }

        foreach ( array('wp-admin', 'wp-includes') as $dir ) {
            if ( ! is_dir($root . '/' . $dir) ) continue;
            try {
                $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root . '/' . $dir, FilesystemIterator::SKIP_DOTS));
                foreach ( $iterator as $file ) {
                    if ( $file->isFile() ) {
                        $candidates[] = ltrim(substr(wp_normalize_path($file->getPathname()), strlen($root)), '/');
                    }
                }
            } catch ( Exception $e ) {
                /* translators: %s: error message */
                Metzler_Webshield_Logger::log(sprintf( __("Could not read directory: %s", "metzler-webshield"), $e->getMessage() ), "core", "warning");
            }
        }

        foreach ( $candidates as $file ) {
            if ( isset($checksums[$file]) || in_array($file, $whitelist, true) ) continue;

            // Translations may live in wp-includes/languages when wp-content/languages does not exist
            if ( str_starts_with($file, 'wp-includes/languages/') && preg_match('/\.(mo|po|json|l10n\.php)$/i', $file) ) continue;

            if ( ! self::is_executable_file( $file ) ) {
                /* translators: %s: file path */
                Metzler_Webshield_Logger::log(sprintf( __('Additional non-executable file in WordPress core directory (e.g. a backup or log file): %s', 'metzler-webshield'), esc_html($file) ), "core", "info");
                continue;
            }

            $actions = '<br><button type="button" class="button button-small metzler-webshield-q-safe" data-path="'.esc_attr($file).'">' . esc_html__('Mark as safe', 'metzler-webshield') . '</button> ';
            $actions .= '<button type="button" class="button button-small button-primary metzler-webshield-q-move" data-path="'.esc_attr($file).'" style="background:#d63638;border-color:#d63638;">' . esc_html__('Move to quarantine', 'metzler-webshield') . '</button>';
            $actions .= Metzler_Webshield_Findings::lab_button( $file );
            /* translators: 1: file path, 2: action buttons */
            Metzler_Webshield_Logger::log(sprintf( __('Critical: Unknown file in WordPress core directory: %1$s%2$s', 'metzler-webshield'), esc_html($file), $actions ), "core", "error");
            Metzler_Webshield_Findings::report( $file, ABSPATH . $file, 'core', 'core-unknown' );
        }
    }

    /**
     * The checksum APIs return either one hash or a list of accepted hashes per file.
     */
    public static function hash_matches( $expected, $actual ): bool {
        if ( is_array($expected) ) {
            return in_array($actual, $expected, true);
        }
        return is_string($expected) && $expected === $actual;
    }

    /**
     * Files the web server can execute or that change how it executes files.
     */
    public static function is_executable_file( string $path ): bool {
        $basename = strtolower(basename($path));
        if ( in_array($basename, array('.htaccess', '.user.ini', 'php.ini', 'web.config'), true) ) {
            return true;
        }
        $ext = strtolower(pathinfo($basename, PATHINFO_EXTENSION));
        return in_array($ext, array('php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'php8', 'phar', 'pht', 'phps', 'inc', 'sh', 'cgi', 'pl', 'py', 'exe'), true);
    }
}
