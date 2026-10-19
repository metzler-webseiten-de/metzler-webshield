<?php
/**
 * Removes all data of Metzler Webshield.
 *
 * @package Metzler_Webshield
 */

// If uninstall not called from WordPress, then exit.
if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit;
}

global $wpdb;

// 1. Drop custom tables
$metzler_webshield_tables = array(
	$wpdb->prefix . 'metzler_webshield_logs',
	$wpdb->prefix . 'metzler_webshield_queue',
	$wpdb->prefix . 'metzler_webshield_fim',
	$wpdb->prefix . 'metzler_webshield_quarantine',
	$wpdb->prefix . 'metzler_webshield_findings',
	$wpdb->prefix . 'metzler_webshield_files',
);

foreach ( $metzler_webshield_tables as $metzler_webshield_table ) {
	$wpdb->query( "DROP TABLE IF EXISTS {$metzler_webshield_table}" ); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, WordPress.DB.PreparedSQL.InterpolatedNotPrepared, PluginCheck.Security.DirectDB.UnescapedDBParameter
}

// 2. Delete plugin options
$metzler_webshield_options = array(
	'metzler_webshield_version',
	'metzler_webshield_db_version',
	'metzler_webshield_is_licensed',
	'metzler_webshield_license_token',
	'metzler_webshield_license_tier',
	'metzler_webshield_pro_expired',
	'metzler_webshield_verified_email',
	'metzler_webshield_enable_waf',
	'metzler_webshield_enable_fim',
	'metzler_webshield_enable_core',
	'metzler_webshield_enable_files',
	'metzler_webshield_enable_updates',
	'metzler_webshield_enable_plugins',
	'metzler_webshield_disable_xmlrpc',
	'metzler_webshield_enable_rate_limiting',
	'metzler_webshield_under_attack_mode',
	'metzler_webshield_enable_telemetry',
	'metzler_webshield_historical_telemetry_sent',
	'metzler_webshield_fim_last_baseline',
	'metzler_webshield_last_scan',
	'metzler_webshield_last_scan_start',
	'metzler_webshield_whitelist',
	'metzler_webshield_rules_synced',
	'metzler_webshield_extended_protection',
	'metzler_webshield_snapshot_version',
	'metzler_webshield_findings_db_version',
	'metzler_webshield_files_db_version',
	'metzler_webshield_auto_submit',
	'metzler_webshield_lab_tickets',
);

foreach ( $metzler_webshield_options as $metzler_webshield_option ) {
	delete_option( $metzler_webshield_option );
}

delete_transient( 'metzler_webshield_core_checksums' );
delete_transient( 'metzler_webshield_core_checksums_en' );
delete_transient( 'metzler_webshield_plugin_verified' );
delete_transient( 'metzler_webshield_quarantine_cleanup' );
delete_transient( 'metzler_webshield_findings_backoff' );
delete_transient( 'metzler_webshield_lab_daily' );
delete_transient( 'metzler_webshield_auto_submit_daily' );
delete_transient( 'metzler_webshield_auto_submit_backoff' );
delete_transient( 'metzler_webshield_global_stats' );
delete_transient( 'mws_remote_update_info' );
delete_metadata( 'user', 0, 'metzler_webshield_pro_notice_dismissed', '', true );

// 3. Remove legacy MU-plugin (WAF bootstrapper of beta versions)
$metzler_webshield_mu_dir  = defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR : WP_CONTENT_DIR . '/mu-plugins';
$metzler_webshield_mu_file = $metzler_webshield_mu_dir . '/metzler-webshield-waf-boot.php';

if ( file_exists( $metzler_webshield_mu_file ) ) {
	wp_delete_file( $metzler_webshield_mu_file );
}

// 4. Remove the firewall directive (.user.ini / .htaccess) of the extended protection
require_once __DIR__ . '/includes/waf/class-metzler-webshield-firewall-setup.php';
Metzler_Webshield_Firewall_Setup::uninstall();

// 5. Remove uploads directory (quarantine, telemetry buffer, rate-limit buckets)
$metzler_webshield_upload_base = wp_upload_dir();
$metzler_webshield_upload_dir  = $metzler_webshield_upload_base['basedir'] . '/metzler-webshield';

if ( is_dir( $metzler_webshield_upload_dir ) ) {
	$metzler_webshield_iterator = new RecursiveIteratorIterator(
		new RecursiveDirectoryIterator( $metzler_webshield_upload_dir, FilesystemIterator::SKIP_DOTS ),
		RecursiveIteratorIterator::CHILD_FIRST
	);
	foreach ( $metzler_webshield_iterator as $metzler_webshield_path ) {
		if ( $metzler_webshield_path->isDir() ) {
			@rmdir( $metzler_webshield_path->getPathname() ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir, WordPress.PHP.NoSilencedErrors.Discouraged
		} else {
			wp_delete_file( $metzler_webshield_path->getPathname() );
		}
	}
	@rmdir( $metzler_webshield_upload_dir ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_operations_rmdir, WordPress.PHP.NoSilencedErrors.Discouraged
}

// 6. Clear scheduled crons
wp_clear_scheduled_hook( 'metzler_webshield_daily_scan' );
wp_clear_scheduled_hook( 'metzler_webshield_hourly_license_check' );
wp_clear_scheduled_hook( 'metzler_webshield_five_minute_telemetry' );
wp_clear_scheduled_hook( 'metzler_webshield_sync_waf_rules' );
