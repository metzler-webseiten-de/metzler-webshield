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
                Metzler_Webshield_Logger::log(sprintf(__("Security risk: Very old PHP version in use (%s). Please update to at least PHP 8.0.", "metzler-webshield"), $php_version), "config", "warning");
            } else {
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
                        $ghost_msg = sprintf(__("CRITICAL MALWARE ALERT: Ghost Admin detected! User '%s' (ID %d) has Administrator privileges in the database but is actively hidden from WordPress by malware!", "metzler-webshield"), $admin->user_login, $admin->ID);
                        $ghost_msg .= '<br><button type="button" class="button button-small button-primary metzler-webshield-delete-user" data-user-id="'.esc_attr($admin->ID).'" style="background:#d63638;border-color:#d63638;">'.esc_html__('Delete user', 'metzler-webshield').'</button>';
                        Metzler_Webshield_Logger::log($ghost_msg, "config", "error");
                        continue;
                    }
                }
            } else {
                Metzler_Webshield_Logger::log(__("Ghost Admin Check passed: No hidden administrators found.", "metzler-webshield"), "config", "success");
            }
            
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
                    Metzler_Webshield_Logger::log(sprintf( __("Security risk: wp-config.php has insecure file permissions (%s). Recommended is 0644 or 0400.", "metzler-webshield"), $perms ), "config", "warning");
                }
            }
            
            Metzler_Webshield_Logger::log(__("Config & Hardening check completed.", "metzler-webshield"), "config", "success");
            return array('complete' => true, 'message' => __('Hardening scan completed', 'metzler-webshield'));
        }
        
        return array('complete' => true);
    }
}
