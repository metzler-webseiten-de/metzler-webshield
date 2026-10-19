<?php
/**
 * Evaluates the scan log, run with `wp eval-file check.php clean|detect <expected.txt>`.
 *
 * clean:    every warning or error is a false positive, and no file may be recorded as a finding
 * findings: every planted sample of expected.txt is recorded as a finding with its current SHA-256
 * detect: every line of expected.txt needs an active threat whose message contains its expected text,
 *         counted like the dashboard does, so a finding the dashboard hides counts as not detected
 */
global $wpdb;

$mode = $args[0] ?? 'clean';
$findings_table = $wpdb->prefix . 'metzler_webshield_findings';
$findings_exist = $wpdb->get_var( $wpdb->prepare( 'SHOW TABLES LIKE %s', $findings_table ) ) === $findings_table;

if ( $mode === 'findings' ) {
    $missing = 0;
    foreach ( file( $args[1], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES ) as $line ) {
        if ( $line[0] === '#' ) continue;
        list( $sample, $target ) = array_map( 'trim', explode( '|', $line ) );
        if ( $sample[0] === '@' && $sample !== '@append' ) continue; // Not a file
        $hash = $findings_exist ? $wpdb->get_var( $wpdb->prepare( "SELECT sha256 FROM $findings_table WHERE rel_path = %s ORDER BY id DESC LIMIT 1", $target ) ) : null;
        if ( $hash === hash_file( 'sha256', ABSPATH . $target ) ) {
            echo "recorded: $target\n";
        } else {
            echo "::error::Not recorded as finding: $target\n";
            $missing++;
        }
    }
    if ( $missing > 0 ) {
        WP_CLI::warning( "$missing sample(s) not recorded as findings." );
        exit( 1 );
    }
    WP_CLI::success( 'All samples recorded as findings.' );
    return;
}
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
    if ( $findings_exist ) {
        foreach ( $wpdb->get_col( "SELECT CONCAT(detection, ' ', rel_path) FROM $findings_table" ) as $finding ) {
            $messages[] = "[finding] $finding";
        }
    }
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
