<?php
/**
 * Self-Hosted Updater for Metzler Webshield
 *
 * Intercepts WordPress core update checks and plugin details requests
 * to deliver updates from the Metzler Webshield API.
 *
 * @package Metzler_Webshield
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

class Metzler_Webshield_Updater {

	/**
	 * Plugin file path relative to wp-content/plugins
	 */
	private string $plugin_file;

	/**
	 * Plugin directory slug (e.g. 'metzler-webshield')
	 */
	private string $plugin_slug;

	/**
	 * Current installed plugin version
	 */
	private string $version;

	/**
	 * Base URL for the Metzler Webshield API
	 */
	private string $api_url;

	/**
	 * Cache key for the remote update info transient
	 */
	private const TRANSIENT_KEY = 'mws_remote_update_info';

	public function __construct( string $plugin_file, string $version, string $api_url ) {
		$this->plugin_file = plugin_basename( $plugin_file );
		$this->plugin_slug = dirname( $this->plugin_file );
		$this->version     = $version;
		$this->api_url     = trailingslashit( $api_url );
	}

	public function init(): void {
		// Hook on read (e.g. wp-admin/plugins.php list table)
		add_filter( 'site_transient_update_plugins', array( $this, 'check_for_update' ) );

		// Hook on write (when WordPress updates transient cache in DB)
		add_filter( 'pre_set_site_transient_update_plugins', array( $this, 'check_for_update' ) );

		// Hook WordPress 5.8+ Update URI hostname filter
		$api_host = wp_parse_url( $this->api_url, PHP_URL_HOST );
		if ( ! empty( $api_host ) ) {
			add_filter( "update_plugins_{$api_host}", array( $this, 'filter_update_plugins_host' ), 10, 4 );
		}

		// Ensure native auto-updates toggle is always displayed in plugins list table
		add_filter( 'plugin_auto_update_setting_html', array( $this, 'filter_auto_update_setting_html' ), 10, 3 );

		// Plugin information modal popup
		add_filter( 'plugins_api', array( $this, 'plugin_info_popup' ), 20, 3 );

		// Normalization of unzipped folder name
		add_filter( 'upgrader_source_selection', array( $this, 'upgrader_source_selection' ), 10, 4 );

		// Cache invalidation
		add_action( 'upgrader_process_complete', array( $this, 'clear_cache' ), 10, 2 );
	}

	/**
	 * Intercept the update_plugins site transient and inject update information.
	 *
	 * @param object $transient
	 * @return object
	 */
	public function check_for_update( $transient ) {
		if ( empty( $transient ) || ! is_object( $transient ) ) {
			$transient = new stdClass();
		}

		if ( ! isset( $transient->response ) || ! is_array( $transient->response ) ) {
			$transient->response = array();
		}
		if ( ! isset( $transient->no_update ) || ! is_array( $transient->no_update ) ) {
			$transient->no_update = array();
		}

		$remote = $this->get_remote_info();

		if ( $remote && ! empty( $remote->version ) && version_compare( $this->version, $remote->version, '<' ) ) {
			$item = (object) array(
				'id'            => $this->plugin_file,
				'slug'          => $this->plugin_slug,
				'plugin'        => $this->plugin_file,
				'new_version'   => $remote->version,
				'url'           => $remote->homepage ?? 'https://metzler-webshield.de',
				'package'       => $remote->download_url ?? '',
				'tested'        => $remote->tested ?? '',
				'requires'      => $remote->requires ?? '6.0',
				'requires_php'  => $remote->requires_php ?? '7.4',
				'icons'         => (array) ( $remote->icons ?? array() ),
				'banners'       => (array) ( $remote->banners ?? array() ),
				'compatibility' => new stdClass(),
			);

			$transient->response[ $this->plugin_file ] = $item;
			unset( $transient->no_update[ $this->plugin_file ] );
		} else {
			// Plugin is up-to-date or remote info is temporarily cached/unreachable.
			// WordPress requires an entry in response or no_update to set 'update-supported' => true.
			// Without this, the 'Automatic Updates' column is left empty by WordPress!
			$item = (object) array(
				'id'           => $this->plugin_file,
				'slug'         => $this->plugin_slug,
				'plugin'       => $this->plugin_file,
				'new_version'  => ( $remote && ! empty( $remote->version ) ) ? $remote->version : $this->version,
				'url'          => ( $remote && ! empty( $remote->homepage ) ) ? $remote->homepage : 'https://metzler-webshield.de',
				'package'      => '',
				'tested'       => ( $remote && ! empty( $remote->tested ) ) ? $remote->tested : '',
				'requires'     => ( $remote && ! empty( $remote->requires ) ) ? $remote->requires : '6.0',
				'requires_php' => ( $remote && ! empty( $remote->requires_php ) ) ? $remote->requires_php : '7.4',
			);

			$transient->no_update[ $this->plugin_file ] = $item;
			unset( $transient->response[ $this->plugin_file ] );
		}

		return $transient;
	}

	/**
	 * WordPress 5.8+ official Update URI filter callback.
	 *
	 * @param array|false $update
	 * @param array       $plugin_data
	 * @param string      $plugin_file
	 * @param array       $locales
	 * @return array|false
	 */
	public function filter_update_plugins_host( $update, array $plugin_data, string $plugin_file, $locales ) {
		if ( $plugin_file !== $this->plugin_file ) {
			return $update;
		}

		$remote = $this->get_remote_info();
		if ( ! $remote || empty( $remote->version ) ) {
			return array(
				'id'           => $plugin_data['UpdateURI'] ?? $this->api_url,
				'slug'         => $this->plugin_slug,
				'version'      => $this->version,
				'url'          => 'https://metzler-webshield.de',
				'package'      => '',
				'tested'       => '',
				'requires'     => '6.0',
				'requires_php' => '7.4',
			);
		}

		return array(
			'id'           => $plugin_data['UpdateURI'] ?? $this->api_url,
			'slug'         => $this->plugin_slug,
			'version'      => $remote->version,
			'url'          => $remote->homepage ?? 'https://metzler-webshield.de',
			'package'      => $remote->download_url ?? '',
			'tested'       => $remote->tested ?? '',
			'requires'     => $remote->requires ?? '6.0',
			'requires_php' => $remote->requires_php ?? '7.4',
			'icons'        => (array) ( $remote->icons ?? array() ),
			'banners'      => (array) ( $remote->banners ?? array() ),
		);
	}

	/**
	 * Ensure the Auto-Updates toggle link is always available in wp-admin/plugins.php.
	 *
	 * @param string $html
	 * @param string $plugin_file
	 * @param array  $plugin_data
	 * @return string
	 */
	public function filter_auto_update_setting_html( string $html, string $plugin_file, array $plugin_data ): string {
		if ( $plugin_file !== $this->plugin_file ) {
			return $html;
		}

		// If WordPress core already rendered a toggle link, keep it!
		if ( false !== strpos( $html, 'toggle-auto-update' ) ) {
			return $html;
		}

		// Generate the standard WordPress native toggle link
		$auto_updates = (array) get_site_option( 'auto_update_plugins', array() );
		$is_enabled   = in_array( $this->plugin_file, $auto_updates, true );

		$action = $is_enabled ? 'disable' : 'enable';
		$text   = $is_enabled ? __( 'Disable auto-updates' ) : __( 'Enable auto-updates' );

		$url = add_query_arg(
			array(
				'action'        => "{$action}-auto-update",
				'plugin'        => $this->plugin_file,
				'paged'         => 1,
				'plugin_status' => 'all',
			),
			'plugins.php'
		);

		return sprintf(
			'<a href="%s" class="toggle-auto-update aria-button-if-js" data-wp-action="%s">' .
			'<span class="dashicons dashicons-update spin hidden" aria-hidden="true"></span>' .
			'<span class="label">%s</span>' .
			'</a>',
			wp_nonce_url( $url, 'updates' ),
			$action,
			esc_html( $text )
		);
	}

	/**
	 * Intercept the plugins_api call when viewing plugin details popup in admin.
	 *
	 * @param mixed  $result
	 * @param string $action
	 * @param object $args
	 * @return mixed
	 */
	public function plugin_info_popup( $result, $action, $args ) {
		if ( 'plugin_information' !== $action ) {
			return $result;
		}

		if ( ! isset( $args->slug ) || $args->slug !== $this->plugin_slug ) {
			return $result;
		}

		$remote = $this->get_remote_info();
		if ( ! $remote ) {
			return $result;
		}

		return (object) array(
			'name'           => $remote->name ?? 'Metzler Webshield',
			'slug'           => $this->plugin_slug,
			'version'        => $remote->version,
			'author'         => $remote->author ?? '<a href="https://metzler-webseiten.de">metzler-webseiten.de</a>',
			'author_profile' => $remote->author_profile ?? 'https://metzler-webseiten.de',
			'homepage'       => $remote->homepage ?? 'https://metzler-webshield.de',
			'requires'       => $remote->requires ?? '6.0',
			'tested'         => $remote->tested ?? '7.1',
			'requires_php'   => $remote->requires_php ?? '7.4',
			'download_link'  => $remote->download_url ?? '',
			'trunk'          => $remote->download_url ?? '',
			'last_updated'   => $remote->last_updated ?? '',
			'sections'       => (array) ( $remote->sections ?? array() ),
			'banners'        => (array) ( $remote->banners ?? array() ),
			'icons'          => (array) ( $remote->icons ?? array() ),
		);
	}

	/**
	 * Ensure the unzipped folder name matches the plugin slug so it installs cleanly.
	 *
	 * @param string      $source        File path of temporary directory holding unpacked files.
	 * @param string      $remote_source File path of the directory holding unpacked files.
	 * @param WP_Upgrader $upgrader      WP_Upgrader instance.
	 * @param array       $hook_extra    Array of extra arguments passed to upgrader.
	 * @return string
	 */
	public function upgrader_source_selection( $source, $remote_source, $upgrader, $hook_extra = array() ) {
		if ( ! isset( $hook_extra['plugin'] ) || $hook_extra['plugin'] !== $this->plugin_file ) {
			return $source;
		}

		global $wp_filesystem;
		if ( ! $wp_filesystem ) {
			return $source;
		}

		$correct_source = trailingslashit( $remote_source ) . $this->plugin_slug . '/';

		if ( trailingslashit( $source ) !== $correct_source ) {
			if ( $wp_filesystem->move( $source, $correct_source ) ) {
				return $correct_source;
			}
		}

		return $source;
	}

	/**
	 * Clear cached update data on successful upgrade.
	 *
	 * @param WP_Upgrader $upgrader_object
	 * @param array       $options
	 */
	public function clear_cache( $upgrader_object = null, $options = array() ): void {
		if ( isset( $options['action'], $options['type'] ) && 'update' === $options['action'] && 'plugin' === $options['type'] ) {
			delete_transient( self::TRANSIENT_KEY );
		}
	}

	/**
	 * Fetch release info from the API, with transient caching.
	 *
	 * @return object|false
	 */
	private function get_remote_info() {
		$force_check = isset( $_GET['force-check'] ) && ! empty( $_GET['force-check'] ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		if ( ! $force_check ) {
			$cached = get_transient( self::TRANSIENT_KEY );
			if ( false !== $cached && is_object( $cached ) ) {
				// If we previously cached a network/Cloudflare failure, stay in backoff
				if ( ! empty( $cached->error ) ) {
					return false;
				}
				return $cached;
			}
		}

		$domain = wp_parse_url( home_url(), PHP_URL_HOST );
		$token  = get_option( 'metzler_webshield_license_token', '' );

		$response = wp_remote_post(
			$this->api_url . 'plugin/update-check',
			array(
				'timeout' => 5,
				'headers' => array(
					'Accept'       => 'application/json',
					'Content-Type' => 'application/json',
				),
				'body'    => wp_json_encode(
					array(
						'version' => $this->version,
						'domain'  => $domain,
						'token'   => $token,
					)
				),
			)
		);

		// If Cloudflare blocks (403/503/challenge) or network fails, apply negative caching
		// with randomized jitter (2 to 3 hours) to prevent thundering herd / retry storms.
		if ( is_wp_error( $response ) || wp_remote_retrieve_response_code( $response ) !== 200 ) {
			$backoff = ( 2 * HOUR_IN_SECONDS ) + wp_rand( 0, 3600 );
			set_transient( self::TRANSIENT_KEY, (object) array( 'error' => true, 'timestamp' => time() ), $backoff );
			return false;
		}

		$body = json_decode( wp_remote_retrieve_body( $response ) );
		if ( empty( $body ) || ! isset( $body->version ) ) {
			$backoff = ( 2 * HOUR_IN_SECONDS ) + wp_rand( 0, 3600 );
			set_transient( self::TRANSIENT_KEY, (object) array( 'error' => true, 'timestamp' => time() ), $backoff );
			return false;
		}

		// Cache successful response for 6-8 hours with random jitter to distribute server load
		$ttl = ( 6 * HOUR_IN_SECONDS ) + wp_rand( 0, 7200 );
		set_transient( self::TRANSIENT_KEY, $body, $ttl );

		return $body;
	}
}
