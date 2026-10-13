<?php
if ( ! defined( 'ABSPATH' ) && ! defined( 'METZLER_WEBSHIELD_WAF_PREPENDED' ) ) exit;

/**
 * Who is really sending the request.
 *
 * Proxy headers (CF-Connecting-IP, X-Forwarded-For, X-Real-IP) are set by the client unless a proxy in front
 * of the site overwrites them. A forwarded IP is "verified" when the connection itself comes from a proxy we
 * know: Cloudflare, a private/loopback address (reverse proxy on the same host or network) or an address from
 * the optional metzler_webshield_trusted_proxies filter / METZLER_WEBSHIELD_TRUSTED_PROXIES constant.
 *
 * Any other connection that carries a proxy header may be an unknown CDN or load balancer, or a client forging
 * the header. The forwarded IP is then still used to tell visitors apart (otherwise every visitor behind such a
 * proxy would share one rate limit), but it is unverified and never earns an exemption: nobody can pose as
 * Googlebot or as the server itself by sending a header.
 *
 * Deliberately free of late WordPress functions so the WAF and rate limiter can use it early.
 */
class Metzler_Webshield_Request {

    /** https://www.cloudflare.com/ips/ */
    const CLOUDFLARE_RANGES = array(
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
        '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
        '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
        '2a06:98c0::/29', '2c0f:f248::/32',
    );

    private static ?string $client_ip = null;
    private static bool $verified = true;
    private static ?array $own_ips = null;
    private static ?array $preset_proxies = null;

    /**
     * Used by the firewall bootstrap before WordPress runs: there are no options, transients or filters yet,
     * so the server IPs and proxies come from the snapshot the plugin wrote.
     */
    public static function configure( array $own_ips, array $trusted_proxies ): void {
        self::$own_ips        = array_values( array_filter( $own_ips, 'is_string' ) );
        self::$preset_proxies = array_values( array_filter( $trusted_proxies, 'is_string' ) );
    }

    /**
     * IPs of this server and the configured proxies, for the firewall snapshot.
     */
    public static function snapshot(): array {
        return array(
            'own_ips'         => self::own_ips(),
            'trusted_proxies' => self::configured_proxies(),
        );
    }

    public static function client_ip(): string {
        if ( null !== self::$client_ip ) {
            return self::$client_ip;
        }

        $remote = self::server_value( 'REMOTE_ADDR' );
        if ( ! filter_var( $remote, FILTER_VALIDATE_IP ) ) {
            $remote = '127.0.0.1';
        }

        if ( self::is_trusted_proxy( $remote ) ) {
            self::$client_ip = self::forwarded_ip( $remote );
            self::$verified  = true;
        } else {
            $claimed         = self::claimed_ip();
            self::$client_ip = $claimed ?? $remote;
            self::$verified  = null === $claimed;
        }
        return self::$client_ip;
    }

    /**
     * False when client_ip() comes from a proxy header of an unknown sender. Exemptions (search engine,
     * own server) must only be granted for verified IPs.
     */
    public static function is_verified(): bool {
        self::client_ip();
        return self::$verified;
    }

    /**
     * True for a verified request from the server itself.
     */
    public static function is_own_server_request(): bool {
        return self::is_verified() && self::is_own_server( self::client_ip() );
    }

    /**
     * True for requests the server sends to itself (loopback, WP-Cron, Site Health, page builders).
     * The site's IP comes from the configured home URL, never from the client-controlled Host header.
     */
    public static function is_own_server( string $ip ): bool {
        if ( '' === $ip ) {
            return false;
        }
        if ( '::1' === $ip || self::ip_in_range( $ip, '127.0.0.0/8' ) ) {
            return true;
        }
        return in_array( $ip, self::own_ips(), true );
    }

    public static function ip_in_range( string $ip, string $cidr ): bool {
        if ( strpos( $cidr, '/' ) === false ) {
            return $ip === $cidr;
        }
        list( $subnet, $bits ) = explode( '/', $cidr, 2 );

        $ip_bin     = @inet_pton( $ip ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged -- invalid input just doesn't match
        $subnet_bin = @inet_pton( $subnet ); // phpcs:ignore WordPress.PHP.NoSilencedErrors.Discouraged
        if ( false === $ip_bin || false === $subnet_bin || strlen( $ip_bin ) !== strlen( $subnet_bin ) ) {
            return false;
        }

        $bits  = (int) $bits;
        $bytes = intdiv( $bits, 8 );
        if ( strncmp( $ip_bin, $subnet_bin, $bytes ) !== 0 ) {
            return false;
        }
        $rest = $bits % 8;
        if ( 0 === $rest ) {
            return true;
        }
        $mask = chr( ( 0xFF << ( 8 - $rest ) ) & 0xFF );
        return ( $ip_bin[ $bytes ] & $mask ) === ( $subnet_bin[ $bytes ] & $mask );
    }

    private static function forwarded_ip( string $remote ): string {
        // Only Cloudflare itself may set CF-Connecting-IP
        $cf_ip = self::server_value( 'HTTP_CF_CONNECTING_IP' );
        if ( self::in_ranges( $remote, self::CLOUDFLARE_RANGES ) && filter_var( $cf_ip, FILTER_VALIDATE_IP ) ) {
            return $cf_ip;
        }

        // Every proxy appends the address it received the request from, so the client's own (forgeable)
        // entries are on the left: walk from the right and take the first address that isn't our proxy.
        $forwarded = self::server_value( 'HTTP_X_FORWARDED_FOR' );
        if ( '' !== $forwarded ) {
            foreach ( array_reverse( explode( ',', $forwarded ) ) as $hop ) {
                $hop = trim( $hop );
                if ( ! filter_var( $hop, FILTER_VALIDATE_IP ) ) {
                    break;
                }
                if ( ! self::is_trusted_proxy( $hop ) ) {
                    return $hop;
                }
            }
        }

        $real_ip = self::server_value( 'HTTP_X_REAL_IP' );
        if ( filter_var( $real_ip, FILTER_VALIDATE_IP ) ) {
            return $real_ip;
        }

        return $remote;
    }

    /**
     * IP from proxy headers sent by an unknown party. The rightmost X-Forwarded-For entry is the one the
     * nearest proxy appended; entries further left are whatever the client claimed.
     */
    private static function claimed_ip(): ?string {
        $forwarded = self::server_value( 'HTTP_X_FORWARDED_FOR' );
        if ( '' !== $forwarded ) {
            $hops = explode( ',', $forwarded );
            $last = trim( (string) end( $hops ) );
            if ( filter_var( $last, FILTER_VALIDATE_IP ) ) {
                return $last;
            }
        }
        foreach ( array( 'HTTP_X_REAL_IP', 'HTTP_CF_CONNECTING_IP' ) as $header ) {
            $ip = self::server_value( $header );
            if ( filter_var( $ip, FILTER_VALIDATE_IP ) ) {
                return $ip;
            }
        }
        return null;
    }

    private static function is_trusted_proxy( string $ip ): bool {
        // Private and reserved ranges (10/8, 172.16/12, 192.168/16, 127/8, fc00::/7, ...) can't come from the internet
        if ( ! filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE ) ) {
            return true;
        }
        if ( self::in_ranges( $ip, self::CLOUDFLARE_RANGES ) ) {
            return true;
        }
        return self::in_ranges( $ip, self::configured_proxies() );
    }

    /**
     * Optional: proxies with public IPs (load balancer, other CDNs) whose forwarded IPs count as verified.
     * Not needed for rate limiting to work, only for search engine verification behind such a proxy.
     * define( 'METZLER_WEBSHIELD_TRUSTED_PROXIES', '203.0.113.10, 198.51.100.0/24' );
     */
    private static function configured_proxies(): array {
        if ( null !== self::$preset_proxies ) {
            return self::$preset_proxies;
        }
        $proxies = defined( 'METZLER_WEBSHIELD_TRUSTED_PROXIES' )
            ? array_filter( array_map( 'trim', explode( ',', (string) METZLER_WEBSHIELD_TRUSTED_PROXIES ) ) )
            : array();

        if ( function_exists( 'apply_filters' ) ) {
            $proxies = (array) apply_filters( 'metzler_webshield_trusted_proxies', $proxies );
        }
        return $proxies;
    }

    private static function in_ranges( string $ip, array $ranges ): bool {
        foreach ( $ranges as $range ) {
            if ( self::ip_in_range( $ip, (string) $range ) ) {
                return true;
            }
        }
        return false;
    }

    private static function own_ips(): array {
        if ( null !== self::$own_ips ) {
            return self::$own_ips;
        }

        $ips    = array();
        $server = self::server_value( 'SERVER_ADDR' );
        if ( '' !== $server ) {
            $ips[] = $server;
        }

        // The DNS lookup of the own domain is cached
        $cached = function_exists( 'get_transient' ) ? get_transient( 'mws_own_ips' ) : false;
        if ( is_array( $cached ) ) {
            $resolved = $cached;
        } else {
            $resolved = array();
            $host     = function_exists( 'get_option' ) ? parse_url( (string) get_option( 'home' ), PHP_URL_HOST ) : ''; // phpcs:ignore WordPress.WP.AlternativeFunctions.parse_url_parse_url -- also runs before WordPress
            if ( $host ) {
                $resolved = gethostbynamel( $host ) ?: array();
            }
            if ( function_exists( 'set_transient' ) ) {
                set_transient( 'mws_own_ips', $resolved, 3600 );
            }
        }

        self::$own_ips = array_values( array_unique( array_merge( $ips, $resolved ) ) );
        return self::$own_ips;
    }

    private static function server_value( string $key ): string {
        // Only IP headers are read here; valid IPs contain nothing WordPress would slash, and wp_unslash()
        // doesn't exist yet when the firewall runs before WordPress
        return isset( $_SERVER[ $key ] ) ? trim( (string) $_SERVER[ $key ] ) : ''; // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
    }
}
