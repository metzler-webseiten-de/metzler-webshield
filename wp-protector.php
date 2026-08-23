<?php
/**
 * Plugin Name:       WPProtector
 * Plugin URI:        https://wp-protector.de
 * Description:       DSGVO-konforme WordPress AntiVirus & Firewall Solution made in Germany.
 * Version:           1.0.2
 * Author:            metzler-webseiten.de
 * Author URI:        https://metzler-webseiten.de
 * License:           GPL-2.0+
 * Text Domain:       wpprotector
 * Requires PHP:      7.4
 * Requires at least: 6.0
 * Tested up to:      7.1
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

const WPPROTECTOR_VERSION = '1.0.0';
const WPPROTECTOR_API_URL = 'https://api.wp-protector.de/api';
define( 'WPPROTECTOR_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'WPPROTECTOR_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

require WPPROTECTOR_PLUGIN_DIR . 'includes/class-wpprotector.php';

function run_wpprotector(): void
{
	$plugin = new WPProtector();
	$plugin->run();
}
run_wpprotector();

add_action( 'plugins_loaded', 'wpprotector_load_textdomain' );
function wpprotector_load_textdomain(): void {
    load_plugin_textdomain( 'wpprotector', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' );
}

register_activation_hook( __FILE__, array( 'WPProtector', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'WPProtector', 'deactivate' ) );
