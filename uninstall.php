<?php
// If uninstall not called from WordPress, then exit.
if ( ! defined( "WP_UNINSTALL_PLUGIN" ) ) {
    exit;
}

// 1. Drop Custom Tables
global $wpdb;
$tables = array(
    $wpdb->prefix . "wpprotector_logs",
    $wpdb->prefix . "wpprotector_queue",
    $wpdb->prefix . "wpprotector_fim",
    $wpdb->prefix . "wpprotector_quarantine"
);

foreach ( $tables as $table ) {
    $wpdb->query( "DROP TABLE IF EXISTS {$table}" );
}

// 2. Delete Plugin Options
$options = array(
    "wpprotector_db_version",
    "wpprotector_is_licensed",
    "wpprotector_license_token",
    "wpprotector_verified_email",
    "wpprotector_enable_waf",
    "wpprotector_enable_fim",
    "wpprotector_disable_xmlrpc",
    "wpprotector_enable_telemetry"
);

foreach ( $options as $option ) {
    delete_option( $option );
}

// 3. Remove MU-Plugin (WAF)
$mu_dir = defined("WPMU_PLUGIN_DIR") ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . "/mu-plugins";
$mu_file = $mu_dir . "/wpprotector-waf-boot.php";

if ( file_exists( $mu_file ) ) {
    @unlink( $mu_file );
}

// 4. Remove Uploads Directory (Quarantine & Telemetry JSONL)
$upload_dir = WP_CONTENT_DIR . "/uploads/wpprotector";

if ( is_dir( $upload_dir ) ) {
    $files = glob( $upload_dir . "/*" );
    foreach ( $files as $file ) {
        if ( is_file( $file ) ) {
            @unlink( $file );
        }
    }
    @rmdir( $upload_dir );
}

// 5. Clear Scheduled Crons
wp_clear_scheduled_hook( "wpprotector_daily_scan" );
wp_clear_scheduled_hook( "wpprotector_hourly_license_check" );
wp_clear_scheduled_hook( "wpprotector_five_minute_telemetry" );
wp_clear_scheduled_hook( "wpprotector_sync_waf_rules" );

