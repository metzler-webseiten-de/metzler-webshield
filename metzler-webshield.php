<?php
/**
 * Plugin Name:       Metzler Webshield
 * Plugin URI:        https://metzler-webshield.de
 * Description:       DSGVO-konforme WordPress AntiVirus & Firewall Solution made in Germany.
 * Version:           1.0.0
 * Author:            metzler-webseiten.de
 * Author URI:        https://metzler-webseiten.de
 * License:           GPL-2.0+
 * Text Domain:       metzler-webshield
 * Requires PHP:      7.4
 * Requires at least: 6.0
 * Tested up to:      7.1
 */

// If this file is called directly, abort.
if ( ! defined( 'WPINC' ) ) {
	die;
}

const METZLER_WEBSHIELD_VERSION = '1.0.0';
const METZLER_WEBSHIELD_API_URL = 'https://api.metzler-webshield.de/api';
define( 'METZLER_WEBSHIELD_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'METZLER_WEBSHIELD_PLUGIN_URL', plugin_dir_url( __FILE__ ) );

require METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/class-metzler-webshield.php';

function run_metzler_webshield(): void { // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
	$plugin = new Metzler_Webshield();
	$plugin->run();
}
run_metzler_webshield();

add_action( 'plugins_loaded', 'metzler_webshield_load_textdomain' );
function metzler_webshield_load_textdomain(): void {
    // phpcs:ignore PluginCheck.CodeAnalysis.DiscouragedFunctions.load_plugin_textdomainFound
    load_plugin_textdomain( 'metzler-webshield', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' );
}

register_activation_hook( __FILE__, array( 'Metzler_Webshield', 'activate' ) );
register_deactivation_hook( __FILE__, array( 'Metzler_Webshield', 'deactivate' ) );



