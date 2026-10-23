<?php
/**
 * Lab and automatic submission with the HTTP layer stubbed out: what may be sent, what is refused,
 * and what happens with the result. Run with `wp eval-file lab.php` after the sample scan.
 */
global $wpdb;

$requests = array();
$api = array( 'status' => 'clean', 'unknown' => null, 'clean' => array(), 'request' => array(), 'malicious' => array(), 'suspicious' => array() );
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
        $data = array( 'success' => true, 'unknown' => $api['unknown'] ?? wp_list_pluck( $body['files'] ?? array(), 'sha256' ), 'clean' => $api['clean'], 'request' => $api['request'], 'malicious' => $api['malicious'], 'suspicious' => $api['suspicious'] );
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

// 4. Automatic submission: hash, path and plugin version first, contents only of reported files after the owner's choice
// A premium plugin file nobody reported: compared, never uploaded unless the lab asks for it
$premium_rel = 'wp-content/plugins/mw-e2e-premium/mw-e2e-premium.php';
wp_mkdir_p( ABSPATH . dirname( $premium_rel ) );
file_put_contents( ABSPATH . $premium_rel, "<?php\n/*\n * Plugin Name: MW E2E Premium\n * Version: 1.0.0\n */\n" );
$premium_sha = hash_file( 'sha256', ABSPATH . $premium_rel );

update_option( Metzler_Webshield_Auto_Submit::OPTION, 'ask' );
$requests = array();
Metzler_Webshield_Auto_Submit::run();
$lookups = array_values( array_filter( $requests, function ( $r ) { return str_ends_with( $r['url'], '/samples/lookup' ); } ) );
if ( ! $lookups ) $fail( 'No hash lookup happened.' );
foreach ( $requests as $request ) {
    if ( str_ends_with( $request['url'], '/samples/submit' ) ) $fail( 'Contents were uploaded without the owners choice.' );
}
$compared = array();
foreach ( $lookups as $lookup ) {
    foreach ( json_decode( $lookup['args']['body'], true )['files'] as $file ) {
        if ( array_diff( array_keys( $file ), array( 'sha256', 'rel_path', 'size', 'component' ) ) ) $fail( 'The lookup sent more than hash, path, size and component.' );
        $compared[ $file['rel_path'] ] = $file;
    }
}
if ( ( $compared[ $premium_rel ]['component']['slug'] ?? '' ) !== 'mw-e2e-premium' || $compared[ $premium_rel ]['component']['version'] !== '1.0.0' ) $fail( 'The premium file was not compared with its plugin version.' );
if ( ! Metzler_Webshield_Auto_Submit::should_ask() ) $fail( 'The dashboard does not ask about the reported unknown files.' );
if ( in_array( $premium_rel, Metzler_Webshield_Auto_Submit::pending()['files'], true ) ) $fail( 'An unreported premium file is offered for upload.' );
echo 'lookup: ' . count( $compared ) . " files compared, nothing uploaded while asking\n";

$requests = array();
$sent_count = Metzler_Webshield_Auto_Submit::choose( 'once' );
$verified = (array) get_transient( 'metzler_webshield_plugin_verified' );
$findings_table = Metzler_Webshield_Findings::table_if_exists();
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
    $reported = $wpdb->get_var( $wpdb->prepare( "SELECT COUNT(*) FROM $findings_table WHERE path_hash = %s AND sha256 = %s", md5( $rel ), $data['sha256'] ) );
    if ( ! $reported || empty( $data['detection'] ) ) $fail( "Uploaded a file no scanner reported: $rel" );
}
echo "send this time: $sent_count reported files uploaded\n";

// 5. A file that differs from an original is uploaded when the lab asks for it
$age_checks = function () use ( $wpdb ) {
    $wpdb->query( "UPDATE {$wpdb->prefix}metzler_webshield_files SET checked_at = '2000-01-01 00:00:00'" );
};
update_option( Metzler_Webshield_Auto_Submit::OPTION, 'always' );
$api['request'] = array( $premium_sha );
$age_checks();
$requests = array();
Metzler_Webshield_Auto_Submit::run();
$uploaded = array_map( function ( $r ) { return json_decode( $r['args']['body'], true )['rel_path']; }, array_filter( $requests, function ( $r ) { return str_ends_with( $r['url'], '/samples/submit' ); } ) );
if ( ! in_array( $premium_rel, $uploaded, true ) ) $fail( 'A file the lab asked for was not uploaded.' );
$api['request'] = array();
echo "requested: $premium_rel uploaded\n";

// 6. A lab approval reaches the site with the next comparison, a revoked one as well
$approved_abs = ABSPATH . $premium_rel;
$api['unknown'] = array();
$api['clean'] = array( $premium_sha );
$age_checks();
Metzler_Webshield_Auto_Submit::run();
if ( ! Metzler_Webshield_Auto_Submit::is_cloud_clean( $premium_rel, $approved_abs ) ) $fail( "The lab approval of $premium_rel did not reach the site." );
$api['clean'] = array();
$age_checks();
Metzler_Webshield_Auto_Submit::run();
if ( Metzler_Webshield_Auto_Submit::is_cloud_clean( $premium_rel, $approved_abs ) ) $fail( 'A revoked approval still counts as clean.' );
echo "approval: $premium_rel skipped by the scanner while approved\n";

// 7. A malware verdict reaches the site as a critical warning with a quarantine button, once
$api['malicious'] = array( $premium_sha );
$age_checks();
Metzler_Webshield_Auto_Submit::run();
$age_checks();
Metzler_Webshield_Auto_Submit::run();
$warnings = $wpdb->get_col( $wpdb->prepare( "SELECT message FROM {$wpdb->prefix}metzler_webshield_logs WHERE severity = 'error' AND message LIKE %s", '%' . $wpdb->esc_like( 'confirmed malware in ' . $premium_rel ) . '%' ) );
if ( count( $warnings ) !== 1 ) $fail( 'The malware verdict was reported ' . count( $warnings ) . ' times instead of once.' );
if ( ! str_contains( $warnings[0], 'metzler-webshield-q-move' ) ) $fail( 'The malware warning has no quarantine button.' );
$api['malicious'] = array();
echo "malware verdict: $premium_rel reported with a quarantine button\n";

update_option( Metzler_Webshield_Auto_Submit::OPTION, 'never' );
$requests = array();
Metzler_Webshield_Auto_Submit::run();
if ( $requests ) $fail( 'Requests were made with "never".' );

WP_CLI::success( 'Lab and automatic submission send only what they should.' );
