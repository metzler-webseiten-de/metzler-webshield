<div class="wrap metzler-webshield-wrap">
    
    <?php
if ( ! defined( 'ABSPATH' ) ) exit;
    global $wpdb;
    
    $last_scan = get_option('metzler_webshield_last_scan'); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    $last_scan_text = $last_scan ? date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), strtotime($last_scan) ) : esc_html__('Never', 'metzler-webshield'); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    
    // SSR: Fetch Logs and Calculate Threats
    $logs = Metzler_Webshield_Logger::get_logs(); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    $active_threats = array(); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    $last_scan_time = $last_scan ? strtotime($last_scan) : 0; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    
    foreach ($logs as $metzler_webshield_log) {
        if ( ($metzler_webshield_log->severity === 'warning' || $metzler_webshield_log->severity === 'error') && strtotime($metzler_webshield_log->time) >= $last_scan_time ) {
            $active_threats[] = $metzler_webshield_log; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
        }
    }
    $issues_found = count($active_threats); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    $hero_status = $issues_found > 0 ? 'warning' : 'safe'; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    
    $is_licensed = get_option('metzler_webshield_is_licensed', false); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    $active_tab_class = 'nav-tab-active'; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    $license_tab_active = ''; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    $fim_count = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}metzler_webshield_files"); // phpcs:ignore WordPress.DB.DirectDatabaseQuery
    ?>
    <nav class="nav-tab-wrapper metzler-webshield-nav-tabs" style="margin-bottom: 20px;">
        <a href="#tab-dashboard" class="nav-tab <?php echo esc_attr($active_tab_class); ?> metzler-webshield-tab-link" data-tab="tab-dashboard"><?php echo esc_html__("Overview", "metzler-webshield"); ?></a>
        <a href="#tab-logs" class="nav-tab metzler-webshield-tab-link" data-tab="tab-logs"><?php echo esc_html__("Log", "metzler-webshield"); ?></a>
        <a href="#tab-quarantine" class="nav-tab metzler-webshield-tab-link" data-tab="tab-quarantine"><?php echo esc_html__("Quarantine", "metzler-webshield"); ?></a>
        <a href="#tab-settings" class="nav-tab metzler-webshield-tab-link" data-tab="tab-settings"><?php echo esc_html__("Settings", "metzler-webshield"); ?></a>
        <a href="#tab-license" class="nav-tab <?php echo esc_attr($license_tab_active); ?> metzler-webshield-tab-link" data-tab="tab-license"><?php echo esc_html__("License", "metzler-webshield"); ?></a>
    </nav>

    
    <div id="tab-dashboard" class="metzler-webshield-tab-content" style="display:block;">
    <!-- Hero Status Section (The Big Shield) -->
    <div id="metzler-webshield-hero" class="metzler-webshield-hero status-<?php echo esc_attr($hero_status); ?>">
        <div class="metzler-webshield-hero-inner">
            <div class="hero-icon">
                <span class="dashicons <?php echo esc_attr($hero_status) === 'safe' ? 'dashicons-shield' : 'dashicons-warning'; ?>"></span>
            </div>
            <div class="hero-content">
                <h1 id="hero-title"><?php echo esc_attr($hero_status) === 'safe' ? ($is_licensed ? esc_html__('Your website is secure.', 'metzler-webshield') : esc_html__('Basic protection active.', 'metzler-webshield')) : esc_html__('Security risks detected!', 'metzler-webshield'); ?></h1>
                <p id="hero-subtitle"><?php echo esc_attr($hero_status) === 'safe' ? ($is_licensed ? esc_html__('All background guards are active and up to date.', 'metzler-webshield') : esc_html__('Activate a free license to unlock Smart Scan & Cloud Features.', 'metzler-webshield')) : esc_html__('Please check the security log.', 'metzler-webshield'); ?></p>
                
                <div id="metzler-webshield-scan-controls">
                    <button id="btn-start-scan" class="button button-primary button-hero metzler-webshield-smart-scan-btn">
                        <?php echo esc_html__("Run Smart Scan", "metzler-webshield"); ?>
                    </button>
                </div>

                <!-- Progress UI (Hidden by default) -->
                <div id="scan-progress-wrapper" style="display:none;">
                    <div class="progress-bar-bg">
                        <div id="scan-progress-fill" class="progress-bar-fill"></div>
                    </div>
                    
                    <!-- Wordfence/Avast style scan stages -->
                    <div id="scan-stages-wrapper" style="margin-top:20px; display:flex; flex-direction:column; gap:8px;">
                        <div class="scan-stage" data-stage="init" style="display:none;">
                            <span class="dashicons dashicons-update stage-icon"></span> <span class="stage-text"><?php echo esc_html__("Initializing scan engine...", "metzler-webshield"); ?></span>
                        </div>
                        <div class="scan-stage" data-stage="scan_updates" style="display:none;">
                            <span class="dashicons dashicons-marker stage-icon"></span> <span class="stage-text"><?php echo esc_html__("Checking for known vulnerabilities (Updates)...", "metzler-webshield"); ?></span>
                        </div>
                        <div class="scan-stage" data-stage="scan_plugins" style="display:none;">
                            <span class="dashicons dashicons-admin-plugins stage-icon"></span> <span class="stage-text"><?php echo esc_html__("Analyzing plugins and themes...", "metzler-webshield"); ?></span>
                        </div>
                        <div class="scan-stage" data-stage="scan_core" style="display:none;">
                            <span class="dashicons dashicons-wordpress stage-icon"></span> <span class="stage-text"><?php echo esc_html__("Comparing WordPress Core with original signatures...", "metzler-webshield"); ?></span>
                        </div>
                        <div class="scan-stage" data-stage="scan_files" style="display:none;">
                            <span class="dashicons dashicons-media-archive stage-icon"></span> <span class="stage-text"><?php echo esc_html__("Deep scan of the file system...", "metzler-webshield"); ?></span>
                        </div>
                        <div class="scan-stage" data-stage="scan_fim" style="display:none;">
                            <span class="dashicons dashicons-shield stage-icon"></span> <span class="stage-text"><?php echo esc_html__("Performing File Integrity Monitoring (FIM)...", "metzler-webshield"); ?></span>
                        </div>
                        <div class="scan-stage" data-stage="scan_config" style="display:none;">
                            <span class="dashicons dashicons-admin-settings stage-icon"></span> <span class="stage-text"><?php echo esc_html__("Checking server configuration and firewall...", "metzler-webshield"); ?></span>
                        </div>
                        <div class="scan-stage" data-stage="complete" style="display:none;">
                            <span class="dashicons dashicons-yes-alt stage-icon" style="color:#00a32a;"></span> <span class="stage-text" style="color:#00a32a; font-weight:bold;"><?php echo esc_html__("Scan successfully completed.", "metzler-webshield"); ?></span>
                        </div>
                    </div>
                    
                    <div class="scan-feedback" style="margin-top:20px; background:#f6f7f7; padding:10px; border-radius:4px; border:1px solid #c3c4c7;">
                        <div style="display:flex; justify-content:space-between; align-items:center; margin-top:10px;">
                            <div style="flex-grow:1; margin-right:10px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap;">
                                <span id="scan-status-text"><?php echo esc_html__("Starting...", "metzler-webshield"); ?></span> 
                            </div>
                            <button id="btn-cancel-scan" class="button button-small" style="color:#d63638; flex-shrink:0;"><?php echo esc_html__("Cancel Scan", "metzler-webshield"); ?></button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Reassurance Stats -->
    <div class="metzler-webshield-stats-bar">
        <div class="stat-item">
            <span class="dashicons dashicons-yes-alt"></span>
            <div class="stat-text">
                <strong id="stat-files-scanned"><?php echo esc_html(number_format_i18n((int)$fim_count)); ?></strong>
                <span><?php echo esc_html__("Scanned Files", "metzler-webshield"); ?></span>
            </div>
        </div>
        <div class="stat-item">
            <span class="dashicons dashicons-clock"></span>
            <div class="stat-text">
                <strong id="stat-last-scan"><?php echo esc_html($last_scan_text); ?></strong>
                <span><?php echo esc_html__("Last Smart Scan", "metzler-webshield"); ?></span>
            </div>
        </div>
    </div>

    <!-- Active Threats UI -->
    <div id="metzler-webshield-active-threats" style="<?php echo $issues_found > 0 ? 'margin-top:20px;' : 'display:none; margin-top:20px;'; ?>">
        <div class="postbox metzler-webshield-postbox" style="border-left: 4px solid #d63638;">
            <h2 class="hndle" style="color: #d63638;">
                <span class="dashicons dashicons-warning"></span>
                <span><?php echo esc_html__("Active threats found!", "metzler-webshield"); ?></span>
            </h2>
            <div class="inside">
                <p><?php echo esc_html__("Your system requires immediate attention. The following issues were detected:", "metzler-webshield"); ?></p>
                <ul id="active-threats-list" style="list-style-type: disc; margin-left: 20px; font-weight: 500;">
                    <?php 
                    $limit = 5; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
                    $count = 0; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
                    foreach ($active_threats as $metzler_webshield_t) {
                        if ($count < $limit) {
                            echo '<li style="margin-bottom:10px;">' . wp_kses_post($metzler_webshield_t->message) . '</li>';
                        }
                        $count++; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
                    }
                    if ($count > $limit) {
                        echo '<li><em>' . 
/* translators: %d: number of hidden events */
esc_html(sprintf(esc_html__('... and %d more (see log).', 'metzler-webshield'), ($count - $limit))) . '</em></li>';
                    }
                    ?>
                </ul>
                <p style="margin-top:15px;">
                    <a href="#" class="button button-secondary" onclick="jQuery('.metzler-webshield-tab-link[data-tab=\'tab-logs\']').click(); return false;"><?php echo esc_html__("View details in the log", "metzler-webshield"); ?></a>
                </p>
            </div>
        </div>
    </div>

    <!-- Main Content Grid -->
    <div id="poststuff">
        <div id="post-body" class="metabox-holder columns-1">
            <div id="post-body-content">
                <!-- System-Info Box moved here -->
                <div class="postbox metzler-webshield-postbox">
                    <h2 class="hndle">
                        <span class="dashicons dashicons-desktop"></span>
                        <span><?php echo esc_html__("System Information", "metzler-webshield"); ?></span>
                    </h2>
                    <div class="inside" style="display:flex; gap:30px;">
                        <p><strong>Server IP:</strong> <?php // phpcs:ignore WordPress.Security.ValidatedSanitizedInput
 echo esc_html(sanitize_text_field(wp_unslash($_SERVER['SERVER_ADDR'] ?? '')) ?: __('Unknown', 'metzler-webshield')); ?></p>
                        <p><strong>PHP Version:</strong> <?php echo esc_html(phpversion()); ?></p>
                        <p><strong>WordPress:</strong> <?php echo esc_html(get_bloginfo("version")); ?></p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    </div> <!-- End Tab Dashboard -->
    
    <!-- Tab Protokoll (Experten-Ansicht) -->
    <div id="tab-logs" class="metzler-webshield-tab-content" style="display:none;">
                <div class="postbox metzler-webshield-postbox">
                    <h2 class="hndle">
                        <span class="dashicons dashicons-list-view"></span>
                        <span><?php echo esc_html__("Detailed Security Log", "metzler-webshield"); ?></span>
                    </h2>
                    <div class="inside">
                        <div class="tablenav top">
                            <div class="alignleft actions">
                                <button id="btn-refresh-logs" class="button"><?php echo esc_html__("Refresh", "metzler-webshield"); ?></button>
                                <button id="btn-clear-logs" class="button" style="margin-left:5px;"><?php echo esc_html__("Clear Log", "metzler-webshield"); ?></button>
                            </div>
                        </div>
                        <table class="wp-list-table widefat fixed striped">
                            <thead>
                                <tr>
                                    <th style="width: 15%;"><?php echo esc_html__("Timestamp", "metzler-webshield"); ?></th>
                                    <th style="width: 15%;"><?php echo esc_html__("Module", "metzler-webshield"); ?></th>
                                    <th><?php echo esc_html__("Event", "metzler-webshield"); ?></th>
                                </tr>
                            </thead>
                            <tbody id="metzler-webshield-log-body">
                                <?php if (empty($logs)): ?>
                                    <tr><td colspan="3" style="text-align:center;"><?php echo esc_html__("The log is empty.", "metzler-webshield"); ?></td></tr>
                                <?php else: ?>
                                    <?php foreach ($logs as $metzler_webshield_log): ?>
                                        <tr class="metzler-webshield-row-<?php echo esc_attr($metzler_webshield_log->severity); ?>">
                                            <td><?php echo esc_html(date_i18n(get_option('time_format'), strtotime($metzler_webshield_log->time))); ?></td>
                                            <td><span class="metzler-webshield-log-module"><?php echo esc_html($metzler_webshield_log->type); ?></span></td>
                                            <td class="metzler-webshield-log-severity-<?php echo esc_attr($metzler_webshield_log->severity); ?>"><?php echo wp_kses_post($metzler_webshield_log->message); ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
    <!-- End Tab Protokoll -->
    
    <!-- Tab <?php echo esc_html__("Quarantine", "metzler-webshield"); ?> -->
    <div id="tab-quarantine" class="metzler-webshield-tab-content" style="display:none;">
        <div class="postbox metzler-webshield-postbox">
            <h2 class="hndle">
                <span class="dashicons dashicons-lock"></span>
                <span><?php echo esc_html__("Isolated Files", "metzler-webshield"); ?></span>
            </h2>
            <div class="inside">
                <p><?php echo esc_html__("Files in quarantine have been neutralized and can no longer be executed by the web server. They will be permanently deleted automatically after 30 days.", "metzler-webshield"); ?></p>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th style="width: 20%;"><?php echo esc_html__("Isolated on", "metzler-webshield"); ?></th>
                            <th><?php echo esc_html__("Original Path", "metzler-webshield"); ?></th>
                            <th style="width: 25%;"><?php echo esc_html__("Actions", "metzler-webshield"); ?></th>
                        </tr>
                    </thead>
                    <tbody id="metzler-webshield-quarantine-body">
                        <?php 
                        $q_files = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}metzler_webshield_quarantine ORDER BY time DESC"); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.NamingConventions.PrefixAllGlobals
                        if (empty($q_files)): 
                        ?>
                            <tr><td colspan="3" style="text-align:center;"><?php echo esc_html__("No files in quarantine.", "metzler-webshield"); ?></td></tr>
                        <?php else: ?>
                            <?php foreach ($q_files as $metzler_webshield_q_file): ?>
                                <tr>
                                    <td><?php echo esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($metzler_webshield_q_file->time))); ?></td>
                                    <td><code style="word-break:break-all;"><?php echo esc_html($metzler_webshield_q_file->original_path); ?></code></td>
                                    <td>
                                        <button type="button" class="button button-small metzler-webshield-q-restore" data-id="<?php echo esc_attr($metzler_webshield_q_file->id); ?>"><?php echo esc_html__("Restore", "metzler-webshield"); ?></button>
                                        <button type="button" class="button button-small button-link-delete metzler-webshield-q-delete" data-id="<?php echo esc_attr($metzler_webshield_q_file->id); ?>" style="color:#d63638; margin-left:10px;"><?php echo esc_html__("Delete", "metzler-webshield"); ?></button>
                                    </td>
                                </tr>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    
    <!-- Tab Settings -->
    <div id="tab-settings" class="metzler-webshield-tab-content" style="display:none;">
        <div class="postbox metzler-webshield-postbox">
            <h2 class="hndle">
                <span class="dashicons dashicons-admin-settings"></span>
                <span><?php echo esc_html__("Module Settings", "metzler-webshield"); ?></span>
            </h2>
            <div class="inside">
                <table class="form-table metzler-webshield-settings-table">
                    <tr>
                        <th scope="row"><?php echo esc_html__("Outdated Plugins & Themes", "metzler-webshield"); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" id="metzler-webshield-setting-updates" <?php echo get_option('metzler_webshield_enable_updates', '1') ? 'checked' : ''; ?>>
                                <strong><?php echo esc_html__("Check for available updates", "metzler-webshield"); ?></strong>
                            </label>
                            <p class="description"><?php echo esc_html__("Checks if plugins or themes are outdated and should be updated (security risk).", "metzler-webshield"); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo esc_html__("Plugin Signature Check", "metzler-webshield"); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" id="metzler-webshield-setting-plugins" <?php echo get_option('metzler_webshield_enable_plugins', '1') ? 'checked' : ''; ?>>
                                <strong><?php echo esc_html__("Check plugin files", "metzler-webshield"); ?></strong>
                            </label>
                            <p class="description"><?php echo esc_html__("Compares all your plugin files with the original signatures from WordPress.org. Detects injected code in official plugins.", "metzler-webshield"); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo esc_html__("WordPress Core Signature Check", "metzler-webshield"); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" id="metzler-webshield-setting-core" <?php echo get_option('metzler_webshield_enable_core', '1') ? 'checked' : ''; ?>>
                                <strong><?php echo esc_html__("Check core files", "metzler-webshield"); ?></strong>
                            </label>
                            <p class="description"><?php echo esc_html__("Compares all WordPress core files (wp-includes, wp-admin) with original signatures from WordPress.org. Can be disabled if incompatible with server firewalls.", "metzler-webshield"); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo esc_html__("Deep Scan (Malware Heuristics)", "metzler-webshield"); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" id="metzler-webshield-setting-files" <?php echo get_option('metzler_webshield_enable_files', '1') ? 'checked' : ''; ?>>
                                <strong><?php echo esc_html__("Scan file system for malware", "metzler-webshield"); ?></strong>
                            </label>
                            <p class="description"><?php echo esc_html__("Scans the root directory, theme, and uploads for known malware signatures and obfuscated scripts (backdoors/web shells).", "metzler-webshield"); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo esc_html__("File Integrity Monitoring (FIM)", "metzler-webshield"); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" id="metzler-webshield-setting-fim" <?php echo get_option('metzler_webshield_enable_fim', '1') ? 'checked' : ''; ?>>
                                <strong><?php echo esc_html__("Enable strict system baseline", "metzler-webshield"); ?></strong>
                            </label>
                            <?php
                            global $wpdb;
                            $fim_count = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}metzler_webshield_fim"); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.NamingConventions.PrefixAllGlobals
                            ?>
                            <p class="metzler-webshield-stat-highlight"><?php echo 
/* translators: %d: number of files */
sprintf(esc_html__("Currently in database baseline: %d files", "metzler-webshield"), intval($fim_count)); ?></p>
                            <p class="description">
                                <?php echo esc_html__("The FIM (File Integrity Monitoring) module creates a fingerprint of all files on your server during the first start.", "metzler-webshield"); ?>
                                <?php echo esc_html__("If a file is changed afterwards without an official update (e.g. through a hacker upload via FTP), the system immediately triggers an alarm.", "metzler-webshield"); ?>
                                <em><?php echo esc_html__("Recommended for maximum security. If there are strong false alarms caused by exotic caching plugins, this additional module can be deactivated here.", "metzler-webshield"); ?></em>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo esc_html__("Real-time Firewall (WAF)", "metzler-webshield"); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" id="metzler-webshield-setting-waf" <?php echo get_option('metzler_webshield_enable_waf', '0') ? 'checked' : ''; ?>>
                                <strong><?php echo esc_html__("Block attacks before execution", "metzler-webshield"); ?></strong>
                            </label>
                            <?php 
                                require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/waf/class-metzler-webshield-waf-installer.php';
                                $waf_active = Metzler_Webshield_WAF_Installer::is_waf_active(); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
                            ?>
                            <p class="metzler-webshield-stat-highlight <?php echo $waf_active ? 'waf-active' : 'waf-inactive'; ?>">
                                <?php echo esc_html__("Status:", "metzler-webshield") . " " . ($waf_active ? esc_html__('Active (MU-Plugin installed)', 'metzler-webshield') : esc_html__('Inactive (MU-Plugin not found)', 'metzler-webshield')); ?>
                            </p>
                            <p class="description"><?php echo esc_html__("The Web Application Firewall intercepts SQL injections, malicious Cross-Site Scripting (XSS), and hacker bots in milliseconds before WordPress is even fully loaded. Uses extremely fast ModSecurity-based patterns.", "metzler-webshield"); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo esc_html__("XML-RPC Interface (Hardening)", "metzler-webshield"); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" id="metzler-webshield-setting-xmlrpc" <?php echo get_option('metzler_webshield_disable_xmlrpc', '0') ? 'checked' : ''; ?>>
                                <strong><?php echo esc_html__("Disable XML-RPC (Recommended)", "metzler-webshield"); ?></strong>
                            </label>
                            <p class="description"><?php echo esc_html__("Blocks access to the outdated `xmlrpc.php` interface, which is frequently abused by botnets for brute-force and DDoS attacks.", "metzler-webshield"); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo esc_html__("Telemetry & Threat Intelligence", "metzler-webshield"); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" id="metzler-webshield-setting-telemetry" <?php echo get_option('metzler_webshield_enable_telemetry', '0') ? 'checked' : ''; ?>>
                                <strong><?php echo esc_html__("Send attack data for network analysis (GDPR-compliant)", "metzler-webshield"); ?></strong>
                            </label>
                            <p class="description"><?php echo esc_html__("Helps train our global security network. Only metadata (IP addresses and malicious payloads) of clearly blocked attackers is reported (legitimate interest under Art. 6(1)(f) GDPR). Normal website visitors are not tracked.", "metzler-webshield"); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo esc_html__("Manual Baseline Creation", "metzler-webshield"); ?></th>
                        <td>
                            <button type="button" id="btn-rebuild-fim" class="button"><?php echo esc_html__("Rebuild system baseline now", "metzler-webshield"); ?></button>
                            <span id="fim-rebuild-feedback" class="metzler-webshield-action-feedback"></span>
                            <p class="description"><?php echo esc_html__("Instantly rebuilds the fingerprint of all files. Useful if you have just intentionally modified files via FTP.", "metzler-webshield"); ?></p>
                        </td>
                    </tr>
                </table>
                <p class="submit metzler-webshield-submit-area">
                    <button type="button" id="btn-save-settings" class="button button-primary button-large"><?php echo esc_html__("Save Settings", "metzler-webshield"); ?></button>
                    <span id="settings-save-feedback" class="metzler-webshield-action-feedback" style="color:#00a32a; display:none;"><?php echo esc_html__("Saved!", "metzler-webshield"); ?></span>
                </p>
            </div>
        </div>
    </div>
    
    <!-- Tab License -->
    <div id="tab-license" class="metzler-webshield-tab-content" style="display:none;">
        <div class="postbox metzler-webshield-postbox">
            <h2 class="hndle">
                <span class="dashicons dashicons-admin-network"></span>
                <span><?php echo esc_html__("Licensing", "metzler-webshield"); ?></span>
            </h2>
            <div class="inside">
                <?php if ($is_licensed): ?>
                    <div style="padding: 20px; background: #e7f7ed; border-left: 4px solid #00a32a; margin-bottom: 20px;">
                        <h3 style="margin-top:0; color: #00a32a;"><span class="dashicons dashicons-yes-alt"></span> <?php echo esc_html__("Plugin is licensed", "metzler-webshield"); ?></h3>
                        <p><?php echo 
/* translators: %s: domain name */
sprintf(wp_kses_post(__("Your domain <strong>%s</strong> is successfully licensed and protected.", "metzler-webshield")), esc_html(wp_parse_url(home_url(), PHP_URL_HOST))); ?></p>
                        <p><?php echo esc_html__("Verified Email:", "metzler-webshield"); ?> <strong><?php echo esc_html(get_option('metzler_webshield_verified_email')); ?></strong></p>
                        
                        <div style="margin-top: 20px;">
                            <button type="button" id="btn-recheck-license" class="button button-secondary"><?php echo esc_html__("Recheck license now", "metzler-webshield"); ?></button>
                            <button type="button" id="btn-remove-license" class="button button-link-delete" style="color: #d63638; margin-left: 10px;"><?php echo esc_html__("Remove license", "metzler-webshield"); ?></button>
                            <span id="license-recheck-feedback" class="metzler-webshield-action-feedback"></span>
                        </div>
                    </div>
                <?php else: ?>
                    <div style="padding: 20px; background: #fff8e5; border-left: 4px solid #f0b849; margin-bottom: 20px;">
                        <h3 style="margin-top:0;"><span class="dashicons dashicons-lock"></span> <?php echo esc_html__("License Required", "metzler-webshield"); ?></h3>
                        <p><?php echo esc_html__("Please request a free license key to use Metzler_Webshield on this domain.", "metzler-webshield"); ?></p>
                    </div>
                    
                    <div style="margin-bottom: 30px;">
                        <h4><?php echo esc_html__("1. Request License Key", "metzler-webshield"); ?></h4>
                        <table class="form-table">
                            <tr>
                                <th scope="row"><?php echo esc_html__("Your Email Address", "metzler-webshield"); ?></th>
                                <td>
                                    <?php $current_user = wp_get_current_user(); ?>
                                    <input type="email" id="metzler-webshield-license-email" class="regular-text" value="<?php echo esc_attr($current_user->user_email); ?>">
                                    <button type="button" id="btn-request-license" class="button button-secondary"><?php echo esc_html__("Request Key", "metzler-webshield"); ?></button>
                                    <span id="license-request-feedback" class="metzler-webshield-action-feedback"></span>
                                    <p class="description"><?php echo esc_html__("The key will be sent to this email address.", "metzler-webshield"); ?></p>
                                </td>
                            </tr>
                        </table>
                    </div>
                    
                    <div style="margin-bottom: 20px;">
                        <h4><?php echo esc_html__("2. Verify License Key", "metzler-webshield"); ?></h4>
                        <table class="form-table">
                            <tr>
                                <th scope="row"><?php echo esc_html__("Enter License Key", "metzler-webshield"); ?></th>
                                <td>
                                    <input type="text" id="metzler-webshield-license-token" class="regular-text" placeholder="<?php echo esc_attr__("E.g. A1B2C3D4E5F6G7H8", "metzler-webshield"); ?>">
                                    <button type="button" id="btn-verify-license" class="button button-primary"><?php echo esc_html__("Verify License", "metzler-webshield"); ?></button>
                                    <span id="license-verify-feedback" class="metzler-webshield-action-feedback"></span>
                                </td>
                            </tr>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
        </div>
    </div>
    
    <!-- Spacer for WP Footer -->
    <div style="clear:both; height:80px; width:100%;"></div>
    
</div>


