<?php
/**
 * Lab and automatic submission with the HTTP layer stubbed out: what may be sent, what is refused,
 * and what happens with the result. Run with `wp eval-file lab.php` after the sample scan.
 */
global $wpdb;

$requests = array();
$api = array( 'status' => 'clean', 'unknown' => null );
add_filter( 'pre_http_request', function ( $preempt, $args, $url ) use ( &$requests, &$api ) {
    $requests[] = array( 'url' => $url, 'args' => $args );
    $body = json_decode( $args['body'] ?? '{}', true );
    if ( str_ends_with( $url, '/samples/submit' ) ) {
        $data = array( 'success' => true, 'ticket' => 'T' . count( $requests ), 'status' => 'received' );
    } elseif ( str_ends_with( $url, '/samples/status' ) ) {
        $data = array( 'success' => true, 'tickets' => array_map( function ( $t ) use ( $api ) {
            return array( 'ticket' => $t, 'status' => $api['status'], 'analyst_note' => 'E2E note' );
        }, $body['tickets'] ?? array() ) );
    } elseif ( str_ends_with( $url, '/samples/lookup' ) ) {
        $data = array( 'success' => true, 'unknown' => $api['unknown'] ?? wp_list_pluck( $body['files'] ?? array(), 'sha256' ) );
    } else {
        $data = array( 'success' => true );
    }
    return array( 'headers' => array(), 'body' => wp_json_encode( $data ), 'response' => array( 'code' => 200, 'message' => 'OK' ), 'cookies' => array() );
}, 10, 3 );

$fail = function ( string $message ) {
    echo "::error::$message\n";
    exit( 1 );
};
$token = get_option( 'metzler_webshield_license_token' );
$verify_signed = function ( array $request ) use ( $token, $fail ) {
    if ( ( $request['args']['headers']['X-Signature'] ?? '' ) !== hash_hmac( 'sha256', $request['args']['body'], $token ) ) {
        $fail( 'Request to ' . $request['url'] . ' is not signed with the key.' );
    }
};

// 1. Refused: credentials, files that were never reported
foreach ( array( 'wp-config.php', 'wp-content/plugins/akismet/readme.txt', '../etc/passwd' ) as $path ) {
    $result = Metzler_Webshield_Findings::submit_sample( $path );
    if ( ! is_wp_error( $result ) ) $fail( "Sending $path was not refused." );
}
if ( $requests ) $fail( 'A refused file caused a request.' );
echo "refused: credentials, unreported and invalid paths\n";

// 2. A reported file goes out with its content, signed, and only once
$path = 'wp-content/mw-e2e-new.php';
$ticket = Metzler_Webshield_Findings::submit_sample( $path, 'E2E: unsure about this file' );
if ( is_wp_error( $ticket ) ) $fail( 'Sending a reported file failed: ' . $ticket->get_error_message() );
$sent = json_decode( $requests[0]['args']['body'], true );
$verify_signed( $requests[0] );
if ( base64_decode( $sent['content_base64'] ) !== file_get_contents( ABSPATH . $path ) ) $fail( 'Sent content differs from the file.' );
if ( $sent['rel_path'] !== $path || $sent['auto'] !== false || $sent['note'] !== 'E2E: unsure about this file' || $sent['detection'] !== 'fim-new' ) $fail( 'Wrong metadata: ' . wp_json_encode( array_diff_key( $sent, array( 'content_base64' => 1 ) ) ) );
if ( str_contains( $requests[0]['args']['body'], rtrim( ABSPATH, '/' ) ) ) $fail( 'The absolute path leaked into the sample request.' );
if ( ! is_wp_error( Metzler_Webshield_Findings::submit_sample( $path ) ) ) $fail( 'The same file was sent twice while being analyzed.' );
echo "sent: $path as ticket $ticket\n";

// 3. A clean result marks the finding as safe
$requests = array();
Metzler_Webshield_Findings::sync_lab_status();
$verify_signed( $requests[0] );
if ( ! in_array( $path, (array) get_option( 'metzler_webshield_whitelist', array() ), true ) ) $fail( 'A clean lab result did not mark the file as safe.' );
echo "clean result: $path marked as safe\n";

// 4. Automatic submission: hashes first, contents only after the owner's choice
update_option( Metzler_Webshield_Auto_Submit::OPTION, 'ask' );
$requests = array();
Metzler_Webshield_Auto_Submit::run();
$urls = wp_list_pluck( $requests, 'url' );
if ( ! in_array( true, array_map( function ( $u ) { return str_ends_with( $u, '/samples/lookup' ); }, $urls ), true ) ) $fail( 'No hash lookup happened.' );
foreach ( $urls as $url ) {
    if ( str_ends_with( $url, '/samples/submit' ) ) $fail( 'Contents were uploaded without the owners choice.' );
}
$lookup = json_decode( $requests[0]['args']['body'], true );
foreach ( $lookup['files'] as $file ) {
    if ( array_keys( $file ) !== array( 'sha256' ) ) $fail( 'The lookup sent more than hashes.' );
}
if ( ! Metzler_Webshield_Auto_Submit::should_ask() ) $fail( 'The dashboard does not ask about the unknown files.' );
echo 'lookup: ' . count( $lookup['files'] ) . " hashes, nothing uploaded while asking\n";

$requests = array();
$sent_count = Metzler_Webshield_Auto_Submit::choose( 'once' );
$verified = (array) get_transient( 'metzler_webshield_plugin_verified' );
$uploads = array_values( array_filter( $requests, function ( $r ) { return str_ends_with( $r['url'], '/samples/submit' ); } ) );
if ( $sent_count < 1 || count( $uploads ) !== $sent_count ) $fail( "Send this time uploaded $sent_count files." );
if ( $sent_count > Metzler_Webshield_Auto_Submit::UPLOADS_PER_RUN ) $fail( 'More uploads than allowed per run.' );
foreach ( $uploads as $upload ) {
    $verify_signed( $upload );
    $data = json_decode( $upload['args']['body'], true );
    $rel = $data['rel_path'];
    if ( $data['auto'] !== true ) $fail( "Automatic upload of $rel not marked as automatic." );
    if ( str_contains( $rel, '/uploads/' ) || str_contains( $rel, 'plugins/metzler-webshield/' ) || isset( $verified[ $rel ] ) || Metzler_Webshield_Findings::is_blocked_sample( $rel ) ) {
        $fail( "Uploaded a file that must never be sent automatically: $rel" );
    }
}
echo "send this time: $sent_count unknown files uploaded\n";

update_option( Metzler_Webshield_Auto_Submit::OPTION, 'never' );
$requests = array();
Metzler_Webshield_Auto_Submit::run();
if ( $requests ) $fail( 'Requests were made with "never".' );

WP_CLI::success( 'Lab and automatic submission send only what they should.' );
