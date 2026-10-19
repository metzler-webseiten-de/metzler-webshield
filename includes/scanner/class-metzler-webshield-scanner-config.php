<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class Metzler_Webshield_Scanner_Config {
    public function run_step($payload): array {
        $step = $payload['step'] ?? 'init';
        
        if ( $step === 'init' ) {
            Metzler_Webshield_Logger::log(__("Starting Config & Hardening checks...", "metzler-webshield"), "config");
            
            // 1. PHP Version
            $php_version = phpversion();
            if ( version_compare($php_version, '8.0', '<') ) {
                /* translators: %s: PHP version */
                Metzler_Webshield_Logger::log(sprintf(__("Security risk: Very old PHP version in use (%s). Please update to at least PHP 8.0.", "metzler-webshield"), $php_version), "config", "warning");
            } else {
                /* translators: %s: PHP version */
                Metzler_Webshield_Logger::log(sprintf( __("PHP version is up to date (%s).", "metzler-webshield"), $php_version ), "config", "success");
            }
            
            // 2. WP_DEBUG Mode
            if ( defined('WP_DEBUG') && WP_DEBUG ) {
                Metzler_Webshield_Logger::log(__("Critical: WP_DEBUG is enabled. This can reveal server paths and vulnerabilities to attackers. Please disable it in wp-config.php.", "metzler-webshield"), "config", "error");
            }
            
            // 3. Admin User Check
            $admin_user = get_user_by('login', 'admin');
            if ( $admin_user ) {
                Metzler_Webshield_Logger::log(__("Critical: A user named 'admin' exists. This is the main target for brute-force attacks. Please rename or delete it.", "metzler-webshield"), "config", "error");
            }
            
                        // 3.5 Ghost Admin Check
            global $wpdb;
            // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching
            $raw_admins = $wpdb->get_results("
                SELECT u.ID, u.user_login 
                FROM {$wpdb->users} u
                INNER JOIN {$wpdb->usermeta} m ON u.ID = m.user_id
                WHERE m.meta_key = '{$wpdb->prefix}capabilities'
                AND m.meta_value LIKE '%\"administrator\"%'
            ");
            
            $raw_admin_ids = array();
            foreach ($raw_admins as $admin) {
                $raw_admin_ids[] = (int) $admin->ID;
            }
            
            $wp_admins = get_users(array('role' => 'administrator', 'fields' => 'ID'));
            $wp_admin_ids = array_map('intval', $wp_admins);
            
            $ghost_admins = array_diff($raw_admin_ids, $wp_admin_ids);
            
            if (!empty($ghost_admins)) {
                foreach ($raw_admins as $admin) {
                    if (in_array((int)$admin->ID, $ghost_admins)) {
                        /* translators: 1: username, 2: user id */
                        $ghost_msg = sprintf(__('CRITICAL MALWARE ALERT: Ghost Admin detected! User \'%1$s\' (ID %2$d) has Administrator privileges in the database but is actively hidden from WordPress by malware!', 'metzler-webshield'), $admin->user_login, $admin->ID);
                        $ghost_msg .= '<br><button type="button" class="button button-small button-primary metzler-webshield-delete-user" data-user-id="'.esc_attr($admin->ID).'" style="background:#d63638;border-color:#d63638;">'.esc_html__('Delete user', 'metzler-webshield').'</button>';
                        Metzler_Webshield_Logger::log($ghost_msg, "config", "error");
                        continue;
                    }
                }
            } else {
                Metzler_Webshield_Logger::log(__("Ghost Admin Check passed: No hidden administrators found.", "metzler-webshield"), "config", "success");
            }

            // 3.6 Administrator rights outside the administrator role
            $this->check_privileged_non_admins();

            // 4. wp-config.php Permissions Check
            $config_path = ABSPATH . 'wp-config.php';
            if ( ! file_exists($config_path) ) {
                $config_path = dirname(ABSPATH) . '/wp-config.php';
            }
            
            if ( file_exists($config_path) ) {
                // fileperms returns something like 33206
                $perms = substr(sprintf('%o', fileperms($config_path)), -4);
                // Standard secure perms are 0644, 0640, 0600, 0444, 0440, 0400
                $insecure_perms = array('0777', '0666', '0755');
                if ( in_array($perms, $insecure_perms) ) {
                    /* translators: %s: file permissions */
                    Metzler_Webshield_Logger::log(sprintf( __("Security risk: wp-config.php has insecure file permissions (%s). Recommended is 0644 or 0400.", "metzler-webshield"), $perms ), "config", "warning");
                }
            }
            
            Metzler_Webshield_Logger::log(__("Config & Hardening check completed.", "metzler-webshield"), "config", "success");
            return array('complete' => true, 'message' => __('Hardening scan completed', 'metzler-webshield'));
        }
        
        return array('complete' => true);
    }

    /**
     * Installing or editing code is reserved for administrators. Backdoor accounts get such rights
     * under an inconspicuous role (e.g. an editor that can install plugins), so the role list stays clean.
     */
    private function check_privileged_non_admins(): void {
        global $wpdb;
        $critical = array(
            'install_plugins', 'upload_plugins', 'activate_plugins', 'update_plugins', 'delete_plugins', 'edit_plugins',
            'install_themes', 'upload_themes', 'update_themes', 'delete_themes', 'edit_themes', 'edit_files',
            'update_core', 'unfiltered_upload'
        );
        $found = false;

        // Roles besides administrator that grant these rights
        $user_counts = null;
        foreach ( wp_roles()->roles as $role => $data ) {
            if ( $role === 'administrator' ) continue;
            $granted = array_values( array_intersect( $critical, array_keys( array_filter( (array) ( $data['capabilities'] ?? array() ) ) ) ) );
            if ( empty($granted) ) continue;

            if ( $user_counts === null ) $user_counts = count_users();
            $found = true;
            /* translators: 1: role name, 2: capabilities, 3: number of users */
            Metzler_Webshield_Logger::log(sprintf( __('Role \'%1$s\' grants administrator rights (%2$s) and has %3$d user(s). Unless a plugin you trust set this up on purpose, remove these rights from the role.', 'metzler-webshield'), esc_html($role), esc_html(implode(', ', $granted)), (int) ( $user_counts['avail_roles'][$role] ?? 0 ) ), "config", "warning");
        }

        // Rights assigned to single users, stored next to the roles in the capabilities meta
        $conditions = array();
        foreach ( $critical as $cap ) {
            $conditions[] = $wpdb->prepare( 'meta_value LIKE %s', '%' . $wpdb->esc_like( '"' . $cap . '"' ) . '%' );
        }
        $meta_key = $wpdb->get_blog_prefix() . 'capabilities';
        // phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.InterpolatedNotPrepared
        $user_ids = $wpdb->get_col( $wpdb->prepare( "SELECT user_id FROM {$wpdb->usermeta} WHERE meta_key = %s AND (" . implode( ' OR ', $conditions ) . ")", $meta_key ) );

        foreach ( $user_ids as $user_id ) {
            $user = get_userdata( (int) $user_id );
            if ( ! $user || in_array( 'administrator', $user->roles, true ) || is_super_admin( $user->ID ) ) continue;
            $granted = array_values( array_intersect( $critical, array_keys( array_filter( $user->caps ) ) ) );
            if ( empty($granted) ) continue;

            $found = true;
            /* translators: 1: username, 2: user id, 3: roles, 4: capabilities */
            $msg = sprintf( __('Critical: User \'%1$s\' (ID %2$d, role: %3$s) has administrator rights assigned directly (%4$s). Backdoor accounts created through leaked remote management keys look like this.', 'metzler-webshield'), esc_html($user->user_login), $user->ID, esc_html( implode(', ', $user->roles) ?: '-' ), esc_html(implode(', ', $granted)) );
            $msg .= '<br><button type="button" class="button button-small button-primary metzler-webshield-delete-user" data-user-id="'.esc_attr($user->ID).'" style="background:#d63638;border-color:#d63638;">'.esc_html__('Delete user', 'metzler-webshield').'</button>';
            Metzler_Webshield_Logger::log($msg, "config", "error");
        }

        if ( ! $found ) {
            Metzler_Webshield_Logger::log(__("Rights check passed: Only administrators can install or edit plugins, themes and core files.", "metzler-webshield"), "config", "success");
        }
    }
}
