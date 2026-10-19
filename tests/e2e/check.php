<?php
/**
 * Evaluates the scan log, run with `wp eval-file check.php clean|detect <expected.txt>`.
 *
 * clean:  every warning or error is a false positive
 * detect: every line of expected.txt needs an active threat whose message contains its expected text,
 *         counted like the dashboard does, so a finding the dashboard hides counts as not detected
 */
global $wpdb;

$mode = $args[0] ?? 'clean';
$rows = $mode === 'clean'
    ? $wpdb->get_results(
        "SELECT type, severity, message FROM {$wpdb->prefix}metzler_webshield_logs
         WHERE severity IN ('warning', 'error') AND type <> 'waf' ORDER BY id"
    )
    : Metzler_Webshield_Logger::get_active_threats( 1000 );
$messages = array_map( function ( $row ) {
    return sprintf( '[%s/%s] %s', $row->type, $row->severity, trim( preg_replace( '/<br>.*/s', '', $row->message ) ) );
}, $rows );

if ( $mode === 'clean' ) {
    if ( empty( $messages ) ) {
        WP_CLI::success( 'Clean site: no warnings or errors.' );
        return;
    }
    foreach ( $messages as $message ) {
        echo "::error::False positive: $message\n";
    }
    WP_CLI::warning( count( $messages ) . ' false positive(s) on the clean site.' );
    exit( 1 );
}

$missing = 0;
foreach ( file( $args[1], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES ) as $line ) {
    if ( $line[0] === '#' ) continue;
    list( , $target, $expected ) = array_map( 'trim', explode( '|', $line ) );
    $found = false;
    foreach ( $messages as $message ) {
        if ( strpos( $message, $expected ) !== false ) {
            $found = true;
            break;
        }
    }
    if ( $found ) {
        echo "detected: $target\n";
    } else {
        echo "::error::Not detected: $target (expected \"$expected\")\n";
        $missing++;
    }
}

if ( $missing > 0 ) {
    WP_CLI::warning( "$missing sample(s) not detected." );
    exit( 1 );
}
WP_CLI::success( 'All samples detected.' );
