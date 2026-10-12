<?php
if ( ! defined( 'ABSPATH' ) && ! defined( 'METZLER_WEBSHIELD_WAF_PREPENDED' ) ) {
    exit;
}

require_once dirname( __DIR__ ) . '/class-metzler-webshield-storage.php';

/**
 * Optional cloud WAF rules for connected sites.
 *
 * The rule set is plain data (category => regex[]) delivered by the Threat Intelligence API. The API
 * decides the channel by the key: community keys receive rules with a 7-day delay, Pro keys in real time.
 * The response is encrypted with the site's own key and only decrypted here, so it can't be read from the
 * web-reachable uploads directory.
 */
class Metzler_Webshield_Cloud_Rules {

    const RULES_FILE    = 'waf-rules.enc';
    const SYNCED_OPTION = 'metzler_webshield_rules_synced';
    const SYNC_HOOK     = 'metzler_webshield_sync_waf_rules';

    public static function init(): void {
        add_action( self::SYNC_HOOK, array( __CLASS__, 'sync' ) );
        add_action( 'metzler_webshield_license_verified', array( __CLASS__, 'sync' ), 10, 0 );
        add_action( 'metzler_webshield_license_removed', array( __CLASS__, 'delete' ) );
    }

    private static function token(): string {
        if ( ! get_option( 'metzler_webshield_is_licensed' ) ) {
            return '';
        }
        return (string) get_option( 'metzler_webshield_license_token', '' );
    }

    public static function sync(): void {
        $token = self::token();
        if ( $token === '' ) {
            return;
        }

        $api_url = defined( 'METZLER_WEBSHIELD_API_URL' ) ? METZLER_WEBSHIELD_API_URL : 'https://api.metzler-webshield.de/api';

        $response = wp_remote_get( $api_url . '/waf/rules', array(
            'headers' => array(
                'Authorization' => 'Bearer ' . $token,
                'Accept'        => 'application/json',
            ),
            'timeout' => 15,
        ) );

        if ( is_wp_error( $response ) ) {
            return;
        }

        $body = wp_remote_retrieve_body( $response );
        $data = json_decode( $body, true );

        if ( isset( $data['success'], $data['payload'], $data['iv'] ) && $data['success'] ) {
            Metzler_Webshield_Storage::ensure_dir();
            file_put_contents( Metzler_Webshield_Storage::path( self::RULES_FILE ), $body, LOCK_EX ); // phpcs:ignore
            update_option( self::SYNCED_OPTION, time() );
            self::refresh_firewall_snapshot();

            Metzler_Webshield_Logger::log( __( 'WAF rules successfully synchronized from Threat Intelligence Cloud.', 'metzler-webshield' ), 'system', 'success' );
        }
    }

    /**
     * Returns the synchronized rule set, or an empty array if the site is not connected or nothing was synced yet.
     */
    public static function load(): array {
        $token = self::token();
        $file  = Metzler_Webshield_Storage::path( self::RULES_FILE );
        if ( $token === '' || ! file_exists( $file ) ) {
            return array();
        }

        $data = json_decode( (string) file_get_contents( $file ), true ); // phpcs:ignore
        if ( ! isset( $data['payload'], $data['iv'] ) ) {
            return array();
        }

        $key       = substr( hash( 'sha256', $token, true ), 0, 32 );
        $decrypted = openssl_decrypt( base64_decode( $data['payload'] ), 'aes-256-cbc', $key, OPENSSL_RAW_DATA, base64_decode( $data['iv'] ) );
        $rules     = $decrypted ? json_decode( $decrypted, true ) : null;

        return is_array( $rules ) ? $rules : array();
    }

    public static function last_synced(): int {
        return (int) get_option( self::SYNCED_OPTION, 0 );
    }

    public static function delete(): void {
        wp_delete_file( Metzler_Webshield_Storage::path( self::RULES_FILE ) );
        delete_option( self::SYNCED_OPTION );
        self::refresh_firewall_snapshot();
    }

    /**
     * The firewall before WordPress (auto_prepend_file) reads its rules from the snapshot.
     */
    private static function refresh_firewall_snapshot(): void {
        if ( class_exists( 'Metzler_Webshield_Firewall_Setup' ) ) {
            Metzler_Webshield_Firewall_Setup::write_snapshot();
        }
    }
}
