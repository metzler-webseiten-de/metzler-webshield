<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class Metzler_Webshield_FIM {
    
    public static function create_table(): void {
        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_fim'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        $charset_collate = $wpdb->get_charset_collate(); // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter

        $sql = "CREATE TABLE $table_name (
            id bigint(20) NOT NULL AUTO_INCREMENT,
            path_hash varchar(32) NOT NULL,
            file_path text NOT NULL,
            file_hash varchar(32) NOT NULL,
            updated_at datetime DEFAULT CURRENT_TIMESTAMP NOT NULL,
            PRIMARY KEY  (id),
            UNIQUE KEY path_hash (path_hash)
        ) $charset_collate;";

        require_once( ABSPATH . 'wp-admin/includes/upgrade.php' );
        dbDelta( $sql );

        // Ensure old 191-character prefix index is removed to avoid duplicate key collisions on long paths.
        // Only if it exists: dropping a missing index is a database error, which WP-CLI and WP_DEBUG print.
        if ( $wpdb->get_var( "SHOW INDEX FROM $table_name WHERE Key_name = 'file_path'" ) ) { // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
            $wpdb->query( "ALTER TABLE $table_name DROP INDEX file_path" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.SchemaChange, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
        }
    }
    
    public function init(): void {
        add_action('upgrader_process_complete', array($this, 'on_update_complete'), 10, 2);
    }

    /**
     * Refreshes the baseline only for what the upgrader wrote. Rebuilding all of wp-content here would
     * accept every file planted since the last scan, and an install pushed with a leaked remote
     * management key would accept its own backdoor.
     */
    public function on_update_complete( $upgrader = null, $hook_extra = array() ): void {
        if ( ! get_option('metzler_webshield_fim_last_baseline') ) return; // The first scan builds the baseline

        $hook_extra = is_array($hook_extra) ? $hook_extra : array();
        $type = $hook_extra['type'] ?? '';
        $paths = array();

        if ( $type === 'plugin' || $type === 'theme' ) {
            if ( ( $hook_extra['action'] ?? '' ) === 'install' ) {
                $result = is_object($upgrader) && isset($upgrader->result) && is_array($upgrader->result) ? $upgrader->result : array();
                if ( ! empty($result['destination']) ) {
                    $paths[] = $result['destination'];
                    // Before the refresh, the baseline still knows whether the directory existed
                    $this->log_install( $type, $result['destination'], $this->in_baseline($result['destination']) );
                }
            } else {
                // Single updates pass 'plugin'/'theme', bulk updates 'plugins'/'themes'
                foreach ( (array) ( $hook_extra[$type . 's'] ?? $hook_extra[$type] ?? array() ) as $item ) {
                    if ( $type === 'plugin' ) {
                        $paths[] = dirname($item) === '.' ? WP_PLUGIN_DIR . '/' . $item : WP_PLUGIN_DIR . '/' . dirname($item);
                    } else {
                        $paths[] = get_theme_root($item) . '/' . $item;
                    }
                }
            }
        } elseif ( $type === 'translation' ) {
            $paths[] = WP_LANG_DIR;
        } elseif ( $type === 'core' ) {
            $paths[] = WP_LANG_DIR;
            // Bundled themes and plugins a core update copies into wp-content, set by update-core.php
            foreach ( array_keys( (array) ( $GLOBALS['_new_bundled_files'] ?? array() ) ) as $bundled ) {
                $paths[] = WP_CONTENT_DIR . '/' . $bundled;
            }
        }

        if ( $this->refresh_paths($paths) > 0 ) {
            Metzler_Webshield_Logger::log( __("FIM Baseline was automatically updated for the updated components.", "metzler-webshield"), "system" );
        }
    }

    /**
     * Replaces the baseline rows below each path with the files that are there now.
     * Whole plugin or theme roots are skipped, they would accept unrelated files.
     */
    private function refresh_paths( array $paths ): int {
        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_fim'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter

        $content = untrailingslashit(wp_normalize_path(WP_CONTENT_DIR));
        $roots = array_map( function ( $dir ) {
            return untrailingslashit(wp_normalize_path($dir));
        }, array( WP_CONTENT_DIR, WP_PLUGIN_DIR, get_theme_root() ) );

        $refreshed = 0;
        foreach ( array_unique($paths) as $path ) {
            $path = untrailingslashit(wp_normalize_path($path));
            if ( in_array($path, $roots, true) || ! str_starts_with($path, $content . '/') ) continue;

            $relative = self::relative_path($path);
            // Rows of files the update removed or replaced
            $wpdb->query( $wpdb->prepare( "DELETE FROM $table_name WHERE file_path = %s OR file_path LIKE %s", $relative, $wpdb->esc_like($relative) . '/%' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

            $files = is_dir($path) ? $this->get_all_php_files($path) : array();
            if ( is_file($path) && strtolower(pathinfo($path, PATHINFO_EXTENSION)) === 'php' ) {
                $files[] = $path;
            }
            foreach ( $files as $file ) {
                $file_relative = self::relative_path($file);
                $wpdb->replace($table_name, array( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery
                    'path_hash'  => md5($file_relative),
                    'file_path'  => $file_relative,
                    'file_hash'  => md5_file($file),
                    'updated_at' => current_time('mysql')
                ));
            }
            $refreshed++;
        }
        return $refreshed;
    }

    /**
     * A legitimate install looks the same as one pushed by an attacker, so every new install is reported.
     * Replacing an installed plugin or theme with an uploaded package (a manual update) is only noted.
     */
    private function log_install( string $type, string $destination, bool $replaced ): void {
        $relative = self::relative_path( untrailingslashit( wp_normalize_path($destination) ) );
        $user = wp_get_current_user();
        $by = $user->exists() ? $user->user_login : __('no logged-in user (cron, WP-CLI or remote request)', 'metzler-webshield');

        if ( $replaced ) {
            /* translators: 1: plugin or theme directory, 2: user login */
            Metzler_Webshield_Logger::log( sprintf( __('Installed plugin or theme replaced with an uploaded package: %1$s (by %2$s).', 'metzler-webshield'), esc_html($relative), esc_html($by) ), "plugins", "info" );
            return;
        }

        $message = $type === 'theme'
            /* translators: 1: theme directory, 2: user login */
            ? sprintf( __('New theme installed: %1$s (by %2$s). If you did not install it yourself, check it immediately: remote management tools with leaked keys are used to install backdoors.', 'metzler-webshield'), esc_html($relative), esc_html($by) )
            /* translators: 1: plugin directory, 2: user login */
            : sprintf( __('New plugin installed: %1$s (by %2$s). If you did not install it yourself, check it immediately: remote management tools with leaked keys are used to install backdoors.', 'metzler-webshield'), esc_html($relative), esc_html($by) );
        // The trailing slash keeps the token from matching other directories that start with the same name
        $message .= '<br><button type="button" class="button button-small metzler-webshield-q-safe" data-path="install:' . esc_attr($relative) . '/">' . esc_html__('Mark as safe', 'metzler-webshield') . '</button>';

        Metzler_Webshield_Logger::log( $message, "plugins", "warning" );
    }

    private function in_baseline( string $path ): bool {
        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_fim'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        $relative = self::relative_path( untrailingslashit( wp_normalize_path($path) ) );
        return (bool) $wpdb->get_var( $wpdb->prepare( "SELECT 1 FROM $table_name WHERE file_path LIKE %s LIMIT 1", $wpdb->esc_like($relative) . '/%' ) ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
    }

    private static function relative_path( string $file ): string {
        $normalized_file = wp_normalize_path($file);
        $normalized_content = wp_normalize_path(WP_CONTENT_DIR);
        return 'wp-content/' . ltrim(str_ireplace($normalized_content, '', $normalized_file), '/');
    }

    public function build_baseline(): int {
        self::create_table();

        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_fim'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter

        $wp_content = WP_CONTENT_DIR;
        $files = $this->get_all_php_files($wp_content);

        $wpdb->query("TRUNCATE TABLE $table_name"); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter

        $wpdb->query("START TRANSACTION"); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter

        foreach ($files as $file) {
            $relative_path = self::relative_path($file);

            $wpdb->insert($table_name, array( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery
                'path_hash'  => md5($relative_path),
                'file_path'  => $relative_path,
                'file_hash'  => md5_file($file),
                'updated_at' => current_time('mysql')
            ));
        }
        
        $wpdb->query("COMMIT"); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter
        
        update_option('metzler_webshield_fim_last_baseline', current_time('mysql'));
        return count($files);
    }
    
    public function accept_file($relative_path): bool {
        if ( str_contains( $relative_path, '..' ) ) return false;
        
        global $wpdb;
        $table_name = $wpdb->prefix . 'metzler_webshield_fim'; // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter
        
        $relative_path = ltrim(wp_normalize_path($relative_path), '/');
        $abs_path = wp_normalize_path(ABSPATH) . $relative_path;
        
        if ( file_exists($abs_path) ) {
            $hash = md5_file($abs_path);
            $wpdb->replace($table_name, array( // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
                'path_hash'  => md5($relative_path),
                'file_path'  => $relative_path,
                'file_hash'  => $hash,
                'updated_at' => current_time('mysql')
            ));
            return true;
        }
        return false;
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
