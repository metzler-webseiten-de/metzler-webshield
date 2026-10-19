<?php
/**
 * Sends the recorded findings with the HTTP layer stubbed out and checks what would leave the site:
 * signed with the key, only WordPress-relative paths, no absolute path, no user names.
 * Run with `wp eval-file telemetry.php` after a scan with telemetry sharing enabled.
 */
global $wpdb;

$requests = array();
add_filter( 'pre_http_request', function ( $preempt, $args, $url ) use ( &$requests ) {
    $requests[] = array( 'url' => $url, 'args' => $args );
    return array( 'headers' => array(), 'body' => '{"success":true}', 'response' => array( 'code' => 200, 'message' => 'OK' ), 'cookies' => array() );
}, 10, 3 );

$fail = function ( string $message ) {
    echo "::error::$message\n";
    exit( 1 );
};

$table = $wpdb->prefix . 'metzler_webshield_findings';
$recorded = (int) $wpdb->get_var( "SELECT COUNT(*) FROM $table" );
if ( $recorded === 0 ) $fail( 'No findings recorded, nothing to send.' );

Metzler_Webshield_Findings::sync();
if ( count( $requests ) !== 1 ) $fail( 'Expected one request, got ' . count( $requests ) . '.' );

$request = $requests[0];
$body = $request['args']['body'];
$token = get_option( 'metzler_webshield_license_token' );
$events = json_decode( $body, true )['events'] ?? array();

if ( ! str_ends_with( $request['url'], '/telemetry/findings/batch' ) ) $fail( 'Wrong endpoint: ' . $request['url'] );
if ( ( $request['args']['headers']['X-Signature'] ?? '' ) !== hash_hmac( 'sha256', $body, $token ) ) $fail( 'Body is not signed with the key.' );
if ( count( $events ) !== $recorded ) $fail( "Sent " . count( $events ) . " events for $recorded findings." );
if ( str_contains( $body, wp_normalize_path( ABSPATH ) ) || str_contains( $body, rtrim( ABSPATH, '/' ) ) ) $fail( 'The absolute path leaked into the payload.' );
foreach ( get_users( array( 'fields' => 'user_login' ) ) as $login ) {
    if ( str_contains( $body, '"' . $login . '"' ) || str_contains( $body, 'by ' . $login ) ) $fail( "User name $login leaked into the payload." );
}
foreach ( $events as $event ) {
    if ( $event['event'] !== 'found' || $event['rel_path'][0] === '/' || ! preg_match( '/^[a-f0-9]{64}$/', $event['sha256'] ) || $event['detection'] === '' ) {
        $fail( 'Malformed event: ' . wp_json_encode( $event ) );
    }
}
echo 'sent: ' . count( $events ) . " findings\n";

// Nothing pending afterwards, a verdict becomes exactly one new event
$requests = array();
Metzler_Webshield_Findings::sync();
if ( count( $requests ) !== 0 ) $fail( 'Findings were sent twice.' );

$path = $events[0]['rel_path'];
Metzler_Webshield_Findings::set_verdict( $path, 'safe' );
Metzler_Webshield_Findings::sync();
$verdicts = json_decode( $requests[0]['args']['body'] ?? '{}', true )['events'] ?? array();
if ( count( $verdicts ) < 1 || $verdicts[0]['event'] !== 'verdict' || $verdicts[0]['user_verdict'] !== 'safe' || $verdicts[0]['rel_path'] !== $path ) {
    $fail( 'Verdict not sent as expected: ' . wp_json_encode( $verdicts ) );
}
echo "sent: verdict for $path\n";

// Without telemetry sharing nothing leaves the site
update_option( 'metzler_webshield_enable_telemetry', '0' );
$requests = array();
Metzler_Webshield_Findings::set_verdict( $path, 'quarantined' );
Metzler_Webshield_Findings::sync();
update_option( 'metzler_webshield_enable_telemetry', '1' );
Metzler_Webshield_Findings::sync();
if ( count( $requests ) !== 0 ) $fail( 'A verdict made while sharing was off was sent.' );

WP_CLI::success( 'Findings telemetry sends only what it should.' );
