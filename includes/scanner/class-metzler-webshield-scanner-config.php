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
                Metzler_Webshield_Logger::log("Sicherheitsrisiko: Sehr alte PHP Version im Einsatz ($php_version). Bitte auf mindestens PHP 8.0 aktualisieren.", "config", "warning");
            } else {
                Metzler_Webshield_Logger::log("PHP Version ist aktuell ($php_version).", "config", "success");
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
                    Metzler_Webshield_Logger::log("Sicherheitsrisiko: wp-config.php hat unsichere Dateirechte ($perms). Empfohlen wird 0644 oder 0400.", "config", "warning");
                }
            }
            
            Metzler_Webshield_Logger::log(__("Config & Hardening check completed.", "metzler-webshield"), "config", "success");
            return array('complete' => true, 'message' => 'Hardening Scan abgeschlossen');
        }
        
        return array('complete' => true);
    }
}
