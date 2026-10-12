<?php
/**
 * Firewall entry point before WordPress (auto_prepend_file).
 *
 * Loaded by metzler-webshield-waf.php in the site root, which the plugin registers in .user.ini or .htaccess.
 * It runs before every PHP file of the site, so exploits that call plugin files directly
 * (/wp-content/plugins/x/upload.php) are inspected too. Only the WAF runs here: rate limiting and login
 * protection need WordPress and keep running in the plugin.
 *
 * Nothing in here may ever take the site down, wp-admin included: any error just skips the firewall
 * and the plugin's own WAF run takes over once WordPress has loaded.
 */

// Direct requests and CLI: the bootstrap defines the storage path, nothing else does
if ( ! defined( 'METZLER_WEBSHIELD_STORAGE_DIR' ) || defined( 'METZLER_WEBSHIELD_WAF_PREPENDED' ) || PHP_SAPI === 'cli' ) {
	return;
}

( static function () {
	try {
		$raw = @file_get_contents( METZLER_WEBSHIELD_STORAGE_DIR . '/waf-config.php' ); // phpcs:ignore
		if ( ! is_string( $raw ) ) {
			return;
		}
		$guard = "<?php exit; ?>\n";
		if ( strpos( $raw, $guard ) === 0 ) {
			$raw = substr( $raw, strlen( $guard ) );
		}
		$config = json_decode( $raw, true );
		if ( ! is_array( $config ) || empty( $config['waf'] ) ) {
			return;
		}

		// During a plugin update files can be missing for a moment; a failed require can't be caught
		$dir = dirname( __DIR__ );
		foreach ( array( '/waf/class-metzler-webshield-waf.php', '/waf/class-metzler-webshield-cloud-rules.php', '/class-metzler-webshield-storage.php', '/class-metzler-webshield-request.php' ) as $file ) {
			if ( ! is_file( $dir . $file ) ) {
				return;
			}
		}

		define( 'METZLER_WEBSHIELD_WAF_PREPENDED', true );
		require_once __DIR__ . '/class-metzler-webshield-waf.php';

		Metzler_Webshield_Request::configure( (array) ( $config['own_ips'] ?? array() ), (array) ( $config['trusted_proxies'] ?? array() ) );
		( new Metzler_Webshield_WAF( $config ) )->run();

		// Only now the plugin may skip its own WAF run: after an error above it still inspects the request
		define( 'METZLER_WEBSHIELD_WAF_DONE', true );
	} catch ( \Throwable $e ) { // phpcs:ignore Generic.CodeAnalysis.EmptyStatement.DetectedCatch -- never break the site
	}
} )();
