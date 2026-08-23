<?php // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
// If uninstall not called from WordPress, then exit. // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
if ( ! defined( "WP_UNINSTALL_PLUGIN" ) ) { // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    exit; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
} // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
 // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
// 1. Drop Custom Tables // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
global $wpdb; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
$tables = array( // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    $wpdb->prefix . "metzler_webshield_logs", // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.NamingConventions.PrefixAllGlobals
    $wpdb->prefix . "metzler_webshield_queue", // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.NamingConventions.PrefixAllGlobals
    $wpdb->prefix . "metzler_webshield_fim", // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.NamingConventions.PrefixAllGlobals
    $wpdb->prefix . "metzler_webshield_quarantine" // phpcs:ignore PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.NamingConventions.PrefixAllGlobals
); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
 // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
foreach ( $tables as $table ) { // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    $wpdb->query( "DROP TABLE IF EXISTS {$table}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.NamingConventions.PrefixAllGlobals, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, WordPress.DB.DirectDatabaseQuery.SchemaChange
} // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
 // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
// 2. Delete Plugin Options // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
$options = array( // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    "metzler_webshield_db_version", // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    "metzler_webshield_is_licensed", // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    "metzler_webshield_license_token", // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    "metzler_webshield_verified_email", // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    "metzler_webshield_enable_waf", // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    "metzler_webshield_enable_fim", // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    "metzler_webshield_disable_xmlrpc", // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    "metzler_webshield_enable_telemetry" // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
 // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
foreach ( $options as $option ) { // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    delete_option( $option ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
} // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
 // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
// 3. Remove MU-Plugin (WAF) // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
$mu_dir = defined("WPMU_PLUGIN_DIR") ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . "/mu-plugins"; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
$mu_file = $mu_dir . "/metzler-webshield-waf-boot.php"; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
 // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
if ( file_exists( $mu_file ) ) { // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    @wp_delete_file( $mu_file ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
} // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
 // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
// 4. Remove Uploads Directory (Quarantine & Telemetry JSONL) // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
$upload_dir = WP_CONTENT_DIR . "/uploads/metzler-webshield"; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
 // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
if ( is_dir( $upload_dir ) ) { // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    $files = glob( $upload_dir . "/*" ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    foreach ( $files as $file ) { // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
        if ( is_file( $file ) ) { // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
            @wp_delete_file( $file ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
        } // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    } // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    @rmdir( $upload_dir ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir
} // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
 // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
// 5. Clear Scheduled Crons // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
wp_clear_scheduled_hook( "metzler_webshield_daily_scan" ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
wp_clear_scheduled_hook( "metzler_webshield_hourly_license_check" ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
wp_clear_scheduled_hook( "metzler_webshield_five_minute_telemetry" ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
wp_clear_scheduled_hook( "metzler_webshield_sync_waf_rules" ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
 // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
