<div class="wrap wpprotector-wrap">
    
    <?php
if ( ! defined( 'ABSPATH' ) ) exit;
    global $wpdb;
    
    $last_scan = get_option('wpprotector_last_scan');
    $last_scan_text = $last_scan ? date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), strtotime($last_scan) ) : 'Nie';
    
    // SSR: Fetch Logs and Calculate Threats
    $logs = WPProtector_Logger::get_logs();
    $active_threats = array();
    $last_scan_time = $last_scan ? strtotime($last_scan) : 0;
    
    foreach ($logs as $log) {
        if ( ($log->severity === 'warning' || $log->severity === 'error') && strtotime($log->time) >= $last_scan_time ) {
            $active_threats[] = $log;
        }
    }
    $issues_found = count($active_threats);
    $hero_status = $issues_found > 0 ? 'warning' : 'safe';
    
    $is_licensed = get_option('wpprotector_is_licensed', false);
    $active_tab_class = $is_licensed ? 'nav-tab-active' : '';
    $license_tab_active = !$is_licensed ? 'nav-tab-active' : '';
    ?>
    <nav class="nav-tab-wrapper wpprotector-nav-tabs" style="margin-bottom: 20px;">
        <a href="#tab-dashboard" class="nav-tab <?php echo esc_attr($active_tab_class); ?> wpprotector-tab-link" data-tab="tab-dashboard"><?php echo esc_html__("Overview", "wpprotector"); ?></a>
        <a href="#tab-logs" class="nav-tab wpprotector-tab-link" data-tab="tab-logs"><?php echo esc_html__("Log", "wpprotector"); ?></a>
        <a href="#tab-quarantine" class="nav-tab wpprotector-tab-link" data-tab="tab-quarantine"><?php echo esc_html__("Quarantine", "wpprotector"); ?></a>
        <a href="#tab-settings" class="nav-tab wpprotector-tab-link" data-tab="tab-settings"><?php echo esc_html__("Settings", "wpprotector"); ?></a>
        <a href="#tab-license" class="nav-tab <?php echo esc_attr($license_tab_active); ?> wpprotector-tab-link" data-tab="tab-license"><?php echo esc_html__("License", "wpprotector"); ?></a>
    </nav>

    
    <div id="tab-dashboard" class="wpprotector-tab-content" style="display:<?php echo $is_licensed ? 'block' : 'none'; ?>;">
    <!-- Hero Status Section (The Big Shield) -->
    <div id="wpprotector-hero" class="wpprotector-hero status-<?php echo $hero_status; ?>">
        <div class="wpprotector-hero-inner">
            <div class="hero-icon">
                <span class="dashicons <?php echo $hero_status === 'safe' ? 'dashicons-shield' : 'dashicons-warning'; ?>"></span>
            </div>
            <div class="hero-content">
                <h1 id="hero-title"><?php echo $hero_status === 'safe' ? __('Your website is secure.', 'wpprotector') : __('Security risks detected!', 'wpprotector'); ?></h1>
                <p id="hero-subtitle"><?php echo $hero_status === 'safe' ? esc_html__('All background guards are active and up to date.', 'wpprotector') : esc_html__('Please check the security log.', 'wpprotector'); ?></p>
                
                <div id="wpprotector-scan-controls">
                    <button id="btn-start-scan" class="button button-primary button-hero wpprotector-smart-scan-btn">
                        <?php echo esc_html__("Run Smart Scan", "wpprotector"); ?>
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
                            <span class="dashicons dashicons-update stage-icon"></span> <span class="stage-text"><?php echo esc_html__("Initializing scan engine...", "wpprotector"); ?></span>
                        </div>
                        <div class="scan-stage" data-stage="scan_updates" style="display:none;">
                            <span class="dashicons dashicons-marker stage-icon"></span> <span class="stage-text"><?php echo esc_html__("Checking for known vulnerabilities (Updates)...", "wpprotector"); ?></span>
                        </div>
                        <div class="scan-stage" data-stage="scan_plugins" style="display:none;">
                            <span class="dashicons dashicons-admin-plugins stage-icon"></span> <span class="stage-text"><?php echo esc_html__("Analyzing plugins and themes...", "wpprotector"); ?></span>
                        </div>
                        <div class="scan-stage" data-stage="scan_core" style="display:none;">
                            <span class="dashicons dashicons-wordpress stage-icon"></span> <span class="stage-text"><?php echo esc_html__("Comparing WordPress Core with original signatures...", "wpprotector"); ?></span>
                        </div>
                        <div class="scan-stage" data-stage="scan_files" style="display:none;">
                            <span class="dashicons dashicons-media-archive stage-icon"></span> <span class="stage-text"><?php echo esc_html__("Deep scan of the file system...", "wpprotector"); ?></span>
                        </div>
                        <div class="scan-stage" data-stage="scan_fim" style="display:none;">
                            <span class="dashicons dashicons-shield stage-icon"></span> <span class="stage-text"><?php echo esc_html__("Performing File Integrity Monitoring (FIM)...", "wpprotector"); ?></span>
                        </div>
                        <div class="scan-stage" data-stage="scan_config" style="display:none;">
                            <span class="dashicons dashicons-admin-settings stage-icon"></span> <span class="stage-text"><?php echo esc_html__("Checking server configuration and firewall...", "wpprotector"); ?></span>
                        </div>
                        <div class="scan-stage" data-stage="complete" style="display:none;">
                            <span class="dashicons dashicons-yes-alt stage-icon" style="color:#00a32a;"></span> <span class="stage-text" style="color:#00a32a; font-weight:bold;"><?php echo esc_html__("Scan successfully completed.", "wpprotector"); ?></span>
                        </div>
                    </div>
                    
                    <div class="scan-feedback" style="margin-top:20px; background:#f6f7f7; padding:10px; border-radius:4px; border:1px solid #c3c4c7;">
                        <div style="flex-shrink:0; min-width: 150px;">
                            <span id="scan-status-text"><?php echo esc_html__("Starting...", "wpprotector"); ?></span> 
                        </div>
                        <div id="scan-rapid-path" class="rapid-path-feedback" style="flex-grow:1; margin:0 15px; text-align:left; color:#646970; font-family:monospace; font-size:11px;"></div>
                        <button id="btn-cancel-scan" class="button button-small" style="color:#d63638; flex-shrink:0;"><?php echo esc_html__("Cancel Scan", "wpprotector"); ?></button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- Reassurance Stats -->
    <div class="wpprotector-stats-bar">
        <div class="stat-item">
            <span class="dashicons dashicons-yes-alt"></span>
            <div class="stat-text">
                <strong id="stat-files-scanned">0</strong>
                <span><?php echo esc_html__("Scanned Files", "wpprotector"); ?></span>
            </div>
        </div>
        <div class="stat-item">
            <span class="dashicons dashicons-clock"></span>
            <div class="stat-text">
                <strong id="stat-last-scan"><?php echo esc_html($last_scan_text); ?></strong>
                <span><?php echo esc_html__("Last Smart Scan", "wpprotector"); ?></span>
            </div>
        </div>
    </div>

    <!-- Active Threats UI -->
    <div id="wpprotector-active-threats" style="<?php echo $issues_found > 0 ? 'margin-top:20px;' : 'display:none; margin-top:20px;'; ?>">
        <div class="postbox wpprotector-postbox" style="border-left: 4px solid #d63638;">
            <h2 class="hndle" style="color: #d63638;">
                <span class="dashicons dashicons-warning"></span>
                <span><?php echo esc_html__("Active threats found!", "wpprotector"); ?></span>
            </h2>
            <div class="inside">
                <p><?php echo esc_html__("Your system requires immediate attention. The following issues were detected:", "wpprotector"); ?></p>
                <ul id="active-threats-list" style="list-style-type: disc; margin-left: 20px; font-weight: 500;">
                    <?php 
                    $limit = 5;
                    $count = 0;
                    foreach ($active_threats as $t) {
                        if ($count < $limit) {
                            echo '<li style="margin-bottom:10px;">' . wp_kses_post($t->message) . '</li>';
                        }
                        $count++;
                    }
                    if ($count > $limit) {
                        echo '<li><em>' . sprintf(__('... and %d more (see log).', 'wpprotector'), ($count - $limit)) . '</em></li>';
                    }
                    ?>
                </ul>
                <p style="margin-top:15px;">
                    <a href="#" class="button button-secondary" onclick="jQuery('.wpprotector-tab-link[data-tab=\'tab-logs\']').click(); return false;"><?php echo esc_html__("View details in the log", "wpprotector"); ?></a>
                </p>
            </div>
        </div>
    </div>

    <!-- Main Content Grid -->
    <div id="poststuff">
        <div id="post-body" class="metabox-holder columns-1">
            <div id="post-body-content">
                <!-- System-Info Box moved here -->
                <div class="postbox wpprotector-postbox">
                    <h2 class="hndle">
                        <span class="dashicons dashicons-desktop"></span>
                        <span><?php echo esc_html__("System Information", "wpprotector"); ?></span>
                    </h2>
                    <div class="inside" style="display:flex; gap:30px;">
                        <p><strong>Server IP:</strong> <?php echo esc_html($_SERVER['SERVER_ADDR'] ?? 'Unbekannt'); ?></p>
                        <p><strong>PHP Version:</strong> <?php echo phpversion(); ?></p>
                        <p><strong>WordPress:</strong> <?php echo get_bloginfo('version'); ?></p>
                    </div>
                </div>
            </div>
        </div>
    </div>
    </div> <!-- End Tab Dashboard -->
    
    <!-- Tab Protokoll (Experten-Ansicht) -->
    <div id="tab-logs" class="wpprotector-tab-content" style="display:none;">
                <div class="postbox wpprotector-postbox">
                    <h2 class="hndle">
                        <span class="dashicons dashicons-list-view"></span>
                        <span><?php echo esc_html__("Detailed Security Log", "wpprotector"); ?></span>
                    </h2>
                    <div class="inside">
                        <div class="tablenav top">
                            <div class="alignleft actions">
                                <button id="btn-refresh-logs" class="button"><?php echo esc_html__("Refresh", "wpprotector"); ?></button>
                                <button id="btn-clear-logs" class="button" style="margin-left:5px;"><?php echo esc_html__("Clear Log", "wpprotector"); ?></button>
                            </div>
                        </div>
                        <table class="wp-list-table widefat fixed striped">
                            <thead>
                                <tr>
                                    <th style="width: 15%;"><?php echo esc_html__("Timestamp", "wpprotector"); ?></th>
                                    <th style="width: 15%;"><?php echo esc_html__("Module", "wpprotector"); ?></th>
                                    <th><?php echo esc_html__("Event", "wpprotector"); ?></th>
                                </tr>
                            </thead>
                            <tbody id="wpprotector-log-body">
                                <?php if (empty($logs)): ?>
                                    <tr><td colspan="3" style="text-align:center;"><?php echo esc_html__("The log is empty.", "wpprotector"); ?></td></tr>
                                <?php else: ?>
                                    <?php foreach ($logs as $log): ?>
                                        <tr class="wpprotector-row-<?php echo esc_attr($log->severity); ?>">
                                            <td><?php echo esc_html(date_i18n(get_option('time_format'), strtotime($log->time))); ?></td>
                                            <td><span class="wpprotector-log-module"><?php echo esc_html($log->type); ?></span></td>
                                            <td class="wpprotector-log-severity-<?php echo esc_attr($log->severity); ?>"><?php echo wp_kses_post($log->message); ?></td>
                                        </tr>
                                    <?php endforeach; ?>
                                <?php endif; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
    <!-- End Tab Protokoll -->
    
    <!-- Tab <?php echo esc_html__("Quarantine", "wpprotector"); ?> -->
    <div id="tab-quarantine" class="wpprotector-tab-content" style="display:none;">
        <div class="postbox wpprotector-postbox">
            <h2 class="hndle">
                <span class="dashicons dashicons-lock"></span>
                <span><?php echo esc_html__("Isolated Files", "wpprotector"); ?></span>
            </h2>
            <div class="inside">
                <p><?php echo esc_html__("Files in quarantine have been neutralized and can no longer be executed by the web server. They will be permanently deleted automatically after 30 days.", "wpprotector"); ?></p>
                <table class="wp-list-table widefat fixed striped">
                    <thead>
                        <tr>
                            <th style="width: 20%;"><?php echo esc_html__("Isolated on", "wpprotector"); ?></th>
                            <th><?php echo esc_html__("Original Path", "wpprotector"); ?></th>
                            <th style="width: 25%;"><?php echo esc_html__("Actions", "wpprotector"); ?></th>
                        </tr>
                    </thead>
                    <tbody id="wpprotector-quarantine-body">
                        <?php 
                        $q_files = $wpdb->get_results("SELECT * FROM {$wpdb->prefix}wpprotector_quarantine ORDER BY time DESC");
                        if (empty($q_files)): 
                        ?>
                            <tr><td colspan="3" style="text-align:center;"><?php echo esc_html__("No files in quarantine.", "wpprotector"); ?></td></tr>
                        <?php else: ?>
                            <?php foreach ($q_files as $q_file): ?>
                                <tr>
                                    <td><?php echo esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($q_file->time))); ?></td>
                                    <td><code style="word-break:break-all;"><?php echo esc_html($q_file->original_path); ?></code></td>
                                    <td>
                                        <button type="button" class="button button-small wpprotector-q-restore" data-id="<?php echo esc_attr($q_file->id); ?>"><?php echo esc_html__("Restore", "wpprotector"); ?></button>
                                        <button type="button" class="button button-small button-link-delete wpprotector-q-delete" data-id="<?php echo esc_attr($q_file->id); ?>" style="color:#d63638; margin-left:10px;"><?php echo esc_html__("Delete", "wpprotector"); ?></button>
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
    <div id="tab-settings" class="wpprotector-tab-content" style="display:none;">
        <div class="postbox wpprotector-postbox">
            <h2 class="hndle">
                <span class="dashicons dashicons-admin-settings"></span>
                <span><?php echo esc_html__("Module Settings", "wpprotector"); ?></span>
            </h2>
            <div class="inside">
                <table class="form-table wpprotector-settings-table">
                    <tr>
                        <th scope="row"><?php echo esc_html__("Outdated Plugins & Themes", "wpprotector"); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" id="wpprotector-setting-updates" <?php echo get_option('wpprotector_enable_updates', '1') ? 'checked' : ''; ?>>
                                <strong><?php echo esc_html__("Check for available updates", "wpprotector"); ?></strong>
                            </label>
                            <p class="description"><?php echo esc_html__("Checks if plugins or themes are outdated and should be updated (security risk).", "wpprotector"); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo esc_html__("Plugin Signature Check", "wpprotector"); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" id="wpprotector-setting-plugins" <?php echo get_option('wpprotector_enable_plugins', '1') ? 'checked' : ''; ?>>
                                <strong><?php echo esc_html__("Check plugin files", "wpprotector"); ?></strong>
                            </label>
                            <p class="description"><?php echo esc_html__("Compares all your plugin files with the original signatures from WordPress.org. Detects injected code in official plugins.", "wpprotector"); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo esc_html__("WordPress Core Signature Check", "wpprotector"); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" id="wpprotector-setting-core" <?php echo get_option('wpprotector_enable_core', '1') ? 'checked' : ''; ?>>
                                <strong><?php echo esc_html__("Check core files", "wpprotector"); ?></strong>
                            </label>
                            <p class="description"><?php echo esc_html__("Compares all WordPress core files (wp-includes, wp-admin) with original signatures from WordPress.org. Can be disabled if incompatible with server firewalls.", "wpprotector"); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo esc_html__("Deep Scan (Malware Heuristics)", "wpprotector"); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" id="wpprotector-setting-files" <?php echo get_option('wpprotector_enable_files', '1') ? 'checked' : ''; ?>>
                                <strong><?php echo esc_html__("Scan file system for malware", "wpprotector"); ?></strong>
                            </label>
                            <p class="description"><?php echo esc_html__("Scans the root directory, theme, and uploads for known malware signatures and obfuscated scripts (backdoors/web shells).", "wpprotector"); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo esc_html__("File Integrity Monitoring (FIM)", "wpprotector"); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" id="wpprotector-setting-fim" <?php echo get_option('wpprotector_enable_fim', '1') ? 'checked' : ''; ?>>
                                <strong><?php echo esc_html__("Enable strict system baseline", "wpprotector"); ?></strong>
                            </label>
                            <?php
                            global $wpdb;
                            $fim_count = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}wpprotector_fim");
                            ?>
                            <p class="wpprotector-stat-highlight"><?php echo sprintf(esc_html__("Currently in database baseline: %d files", "wpprotector"), intval($fim_count)); ?></p>
                            <p class="description">
                                <?php echo esc_html__("The FIM (File Integrity Monitoring) module creates a fingerprint of all files on your server during the first start.", "wpprotector"); ?>
                                <?php echo esc_html__("If a file is changed afterwards without an official update (e.g. through a hacker upload via FTP), the system immediately triggers an alarm.", "wpprotector"); ?>
                                <em><?php echo esc_html__("Recommended for maximum security. If there are strong false alarms caused by exotic caching plugins, this additional module can be deactivated here.", "wpprotector"); ?></em>
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo esc_html__("Real-time Firewall (WAF)", "wpprotector"); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" id="wpprotector-setting-waf" <?php echo get_option('wpprotector_enable_waf', '0') ? 'checked' : ''; ?>>
                                <strong><?php echo esc_html__("Block attacks before execution", "wpprotector"); ?></strong>
                            </label>
                            <?php 
                                require_once WPPROTECTOR_PLUGIN_DIR . 'includes/waf/class-wpprotector-waf-installer.php';
                                $waf_active = WPProtector_WAF_Installer::is_waf_active(); 
                            ?>
                            <p class="wpprotector-stat-highlight <?php echo $waf_active ? 'waf-active' : 'waf-inactive'; ?>">
                                <?php echo esc_html__("Status:", "wpprotector") . " " . ($waf_active ? __('Active (MU-Plugin installed)', 'wpprotector') : __('Inactive (MU-Plugin not found)', 'wpprotector')); ?>
                            </p>
                            <p class="description"><?php echo esc_html__("The Web Application Firewall intercepts SQL injections, malicious Cross-Site Scripting (XSS), and hacker bots in milliseconds before WordPress is even fully loaded. Uses extremely fast ModSecurity-based patterns.", "wpprotector"); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo esc_html__("XML-RPC Interface (Hardening)", "wpprotector"); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" id="wpprotector-setting-xmlrpc" <?php echo get_option('wpprotector_disable_xmlrpc', '0') ? 'checked' : ''; ?>>
                                <strong><?php echo esc_html__("Disable XML-RPC (Recommended)", "wpprotector"); ?></strong>
                            </label>
                            <p class="description"><?php echo esc_html__("Blocks access to the outdated `xmlrpc.php` interface, which is frequently abused by botnets for brute-force and DDoS attacks.", "wpprotector"); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo esc_html__("Telemetry & Threat Intelligence", "wpprotector"); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" id="wpprotector-setting-telemetry" <?php echo get_option('wpprotector_enable_telemetry', '1') ? 'checked' : ''; ?>>
                                <strong><?php echo esc_html__("Send attack data for network analysis (GDPR-compliant)", "wpprotector"); ?></strong>
                            </label>
                            <p class="description"><?php echo esc_html__("Helps train our global security network. Only metadata (IP addresses and malicious payloads) of clearly blocked attackers is reported (legitimate interest under Art. 6(1)(f) GDPR). Normal website visitors are not tracked.", "wpprotector"); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo esc_html__("Manual Baseline Creation", "wpprotector"); ?></th>
                        <td>
                            <button type="button" id="btn-rebuild-fim" class="button"><?php echo esc_html__("Rebuild system baseline now", "wpprotector"); ?></button>
                            <span id="fim-rebuild-feedback" class="wpprotector-action-feedback"></span>
                            <p class="description"><?php echo esc_html__("Instantly rebuilds the fingerprint of all files. Useful if you have just intentionally modified files via FTP.", "wpprotector"); ?></p>
                        </td>
                    </tr>
                </table>
                <p class="submit wpprotector-submit-area">
                    <button type="button" id="btn-save-settings" class="button button-primary button-large"><?php echo esc_html__("Save Settings", "wpprotector"); ?></button>
                    <span id="settings-save-feedback" class="wpprotector-action-feedback" style="color:#00a32a; display:none;"><?php echo esc_html__("Saved!", "wpprotector"); ?></span>
                </p>
            </div>
        </div>
    </div>
    
    <!-- Tab License -->
    <div id="tab-license" class="wpprotector-tab-content" style="display:<?php echo $is_licensed ? 'none' : 'block'; ?>;">
        <div class="postbox wpprotector-postbox">
            <h2 class="hndle">
                <span class="dashicons dashicons-admin-network"></span>
                <span><?php echo esc_html__("Licensing", "wpprotector"); ?></span>
            </h2>
            <div class="inside">
                <?php if ($is_licensed): ?>
                    <div style="padding: 20px; background: #e7f7ed; border-left: 4px solid #00a32a; margin-bottom: 20px;">
                        <h3 style="margin-top:0; color: #00a32a;"><span class="dashicons dashicons-yes-alt"></span> <?php echo esc_html__("Plugin is licensed", "wpprotector"); ?></h3>
                        <p><?php echo sprintf(wp_kses_post(__("Your domain <strong>%s</strong> is successfully licensed and protected.", "wpprotector")), esc_html(parse_url(home_url(), PHP_URL_HOST))); ?></p>
                        <p><?php echo esc_html__("Verified Email:", "wpprotector"); ?> <strong><?php echo esc_html(get_option('wpprotector_verified_email')); ?></strong></p>
                        
                        <div style="margin-top: 20px;">
                            <button type="button" id="btn-recheck-license" class="button button-secondary"><?php echo esc_html__("Recheck license now", "wpprotector"); ?></button>
                            <button type="button" id="btn-remove-license" class="button button-link-delete" style="color: #d63638; margin-left: 10px;"><?php echo esc_html__("Remove license", "wpprotector"); ?></button>
                            <span id="license-recheck-feedback" class="wpprotector-action-feedback"></span>
                        </div>
                    </div>
                <?php else: ?>
                    <div style="padding: 20px; background: #fff8e5; border-left: 4px solid #f0b849; margin-bottom: 20px;">
                        <h3 style="margin-top:0;"><span class="dashicons dashicons-lock"></span> <?php echo esc_html__("License Required", "wpprotector"); ?></h3>
                        <p><?php echo esc_html__("Please request a free license key to use WPProtector on this domain.", "wpprotector"); ?></p>
                    </div>
                    
                    <div style="margin-bottom: 30px;">
                        <h4><?php echo esc_html__("1. Request License Key", "wpprotector"); ?></h4>
                        <table class="form-table">
                            <tr>
                                <th scope="row"><?php echo esc_html__("Your Email Address", "wpprotector"); ?></th>
                                <td>
                                    <?php $current_user = wp_get_current_user(); ?>
                                    <input type="email" id="wpprotector-license-email" class="regular-text" value="<?php echo esc_attr($current_user->user_email); ?>">
                                    <button type="button" id="btn-request-license" class="button button-secondary"><?php echo esc_html__("Request Key", "wpprotector"); ?></button>
                                    <span id="license-request-feedback" class="wpprotector-action-feedback"></span>
                                    <p class="description"><?php echo esc_html__("The key will be sent to this email address.", "wpprotector"); ?></p>
                                </td>
                            </tr>
                        </table>
                    </div>
                    
                    <div style="margin-bottom: 20px;">
                        <h4><?php echo esc_html__("2. Verify License Key", "wpprotector"); ?></h4>
                        <table class="form-table">
                            <tr>
                                <th scope="row"><?php echo esc_html__("Enter License Key", "wpprotector"); ?></th>
                                <td>
                                    <input type="text" id="wpprotector-license-token" class="regular-text" placeholder="<?php echo esc_attr__("E.g. A1B2C3D4E5F6G7H8", "wpprotector"); ?>">
                                    <button type="button" id="btn-verify-license" class="button button-primary"><?php echo esc_html__("Verify License", "wpprotector"); ?></button>
                                    <span id="license-verify-feedback" class="wpprotector-action-feedback"></span>
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
