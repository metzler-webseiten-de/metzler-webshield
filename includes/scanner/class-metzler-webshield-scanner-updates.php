<?php
if ( ! defined( 'ABSPATH' ) ) exit;
class Metzler_Webshield_Scanner_Updates {
    public function run_step($payload): array {
        $step = $payload['step'] ?? 'init';
        
        if ( $step === 'init' ) {
            Metzler_Webshield_Logger::log(__("Checking for available software updates...", "metzler-webshield"), "updates" );
            
            return array(
                'complete' => false,
                'next_payload' => array('step' => 'process_core'),
                'message' => 'Prüfe WordPress-Version...'
            );
        }
        
        if ( $step === 'process_core' ) {
            $core_updates = get_site_transient('update_core');
            $has_core_update = false;
            
            if ( $core_updates && isset($core_updates->updates) && is_array($core_updates->updates) ) {
                foreach ( $core_updates->updates as $update ) {
                    if ( $update->response === 'upgrade' ) {
                        $has_core_update = true;
                        $button = '<button class="button button-small metzler-webshield-update-btn" data-update-type="core" data-update-item="core">Core Update ausführen</button>';
                        Metzler_Webshield_Logger::log(__("Outdated WordPress version. Recommended: Update to ", "metzler-webshield") . esc_html($update->version) . " " . $button, "updates", "warning");
                        break;
                    }
                }
            }
            
            if ( ! $has_core_update ) {
                Metzler_Webshield_Logger::log(__("WordPress Core is up to date.", "metzler-webshield"), "updates", "success");
            }
            
            return array(
                'complete' => false,
                'next_payload' => array('step' => 'process_plugins'),
                'message' => 'Prüfe Plugin-Updates...'
            );
        }
        
        if ( $step === 'process_plugins' ) {
            $plugin_updates = get_site_transient('update_plugins');
            $has_plugin_updates = false;
            
            if ( $plugin_updates && isset($plugin_updates->response) && is_array($plugin_updates->response) ) {
                foreach ( $plugin_updates->response as $plugin_file => $plugin_data ) {
                    $has_plugin_updates = true;
                    // Try to get plugin name nicely if possible, else filename
                    if ( ! function_exists( 'get_plugins' ) ) {
                        require_once ABSPATH . 'wp-admin/includes/plugin.php';
                    }
                    $all_plugins = get_plugins();
                    $plugin_name = isset($all_plugins[$plugin_file]) ? $all_plugins[$plugin_file]['Name'] : $plugin_file;
                    
                    $button = '<button class="button button-small metzler-webshield-update-btn" data-update-type="plugin" data-update-item="' . esc_attr($plugin_file) . '">Plugin aktualisieren</button>';
                    Metzler_Webshield_Logger::log(__("Outdated plugin: ", "metzler-webshield") . esc_html($plugin_name) . " (Neue Version verfügbar) " . $button, "updates", "warning");
                }
            }
            
            if ( ! $has_plugin_updates ) {
                Metzler_Webshield_Logger::log(__("All plugins are up to date.", "metzler-webshield"), "updates", "success");
            }
            
            return array('complete' => true, 'message' => 'Update-Prüfung abgeschlossen');
        }
        
        return array('complete' => true);
    }
}
