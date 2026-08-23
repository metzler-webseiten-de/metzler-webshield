<?php
if ( ! defined( 'ABSPATH' ) ) {
    die;
}

class Metzler_Webshield_WAF_Installer {
    
    public static function enable_waf(): bool {
        $mu_dir = WP_CONTENT_DIR . '/mu-plugins';
        $boot_file = $mu_dir . '/metzler-webshield-waf-boot.php';
        
        // Ensure mu-plugins directory exists
        if ( ! is_dir($mu_dir) ) {
            if ( ! wp_mkdir_p($mu_dir) ) {
                Metzler_Webshield_Logger::log("WAF Installation fehlgeschlagen: Konnte mu-plugins Verzeichnis nicht erstellen ($mu_dir)", "system", "error");
                return false;
            }
        }
        
        $plugin_dir = dirname( __FILE__, 3 );
        $waf_class_path = $plugin_dir . '/includes/waf/class-metzler-webshield-waf.php';
        
        // Bootstrap content
        $content = "<?php\n";
        $content .= "/**\n";
        $content .= " * Plugin Name: Metzler_Webshield WAF Bootstrapper\n";
        $content .= " * Description: Loads the real-time firewall (WAF) before all other plugins.\n";
        $content .= " * Author: Metzler_Webshield\n";
        $content .= " */\n";
        $content .= "if ( ! defined( 'ABSPATH' ) ) die;\n\n";
        $content .= "// Reference to the main WAF class in the Metzler_Webshield folder\n";
        $content .= "\$waf_file = '" . addslashes($waf_class_path) . "';\n";
        $content .= "if ( file_exists(\$waf_file) ) {\n";
        $content .= "    require_once \$waf_file;\n";
        $content .= "    if ( class_exists('Metzler_Webshield_WAF') ) {\n";
        $content .= "        \$metzler_webshield_waf = new Metzler_Webshield_WAF();\n";
        $content .= "        \$metzler_webshield_waf->run();\n";
        $content .= "    }\n";
        $content .= "}\n";
        
        // Write the file
        $result = @file_put_contents($boot_file, $content); // phpcs:ignore PluginCheck.CodeAnalysis.WriteFile.PluginDirectoryWrite
        if ($result === false) {
            $error = error_get_last();
            $err_msg = $error['message'] ?? 'Unknown error';
            Metzler_Webshield_Logger::log("WAF Installation fehlgeschlagen: Konnte Datei nicht schreiben ($boot_file). Fehler: $err_msg", "system", "error");
            return false;
        }
        
        Metzler_Webshield_Logger::log(__("WAF MU-Plugin installed successfully.", "metzler-webshield"), "system", "success");
        return true;
    }
    
    public static function disable_waf(): bool {
        $boot_file = WP_CONTENT_DIR . '/mu-plugins/metzler-webshield-waf-boot.php';
        if ( file_exists($boot_file) ) {
            return unlink($boot_file); // phpcs:ignore
        }
        return true;
    }
    
    public static function is_waf_active(): bool {
        $boot_file = WP_CONTENT_DIR . '/mu-plugins/metzler-webshield-waf-boot.php';
        return file_exists($boot_file);
    }
}
