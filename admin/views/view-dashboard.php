<div class="wrap metzler-webshield-wrap">
    
    <?php
if ( ! defined( 'ABSPATH' ) ) exit;
    global $wpdb;
    
    $last_scan = get_option('metzler_webshield_last_scan'); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    $last_scan_text = $last_scan ? date_i18n( get_option( 'date_format' ) . ' ' . get_option( 'time_format' ), strtotime($last_scan) ) : esc_html__('Never', 'metzler-webshield'); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    
    // Auto-flush telemetry buffer so SSR renders the newest logs immediately
    $upload_dir = WP_CONTENT_DIR . '/uploads/metzler-webshield';
    if ( file_exists($upload_dir . '/telemetry.jsonl') && filesize($upload_dir . '/telemetry.jsonl') > 0 ) {
        $metzler_webshield = new Metzler_Webshield();
        $metzler_webshield->cron_sync_telemetry();
    }

    // SSR: Fetch Active Server Threats (excludes blocked bots/WAF traffic)
    require_once METZLER_WEBSHIELD_PLUGIN_DIR . 'includes/log/class-metzler-webshield-logger.php';
    $active_threats = Metzler_Webshield_Logger::get_active_threats(); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    $issues_found = count($active_threats); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    $hero_status = $issues_found > 0 ? 'warning' : 'safe'; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals

    // SSR: Fetch Recent Logs for the Log tab
    $logs = Metzler_Webshield_Logger::get_logs( 100 ); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    
    $is_licensed = get_option('metzler_webshield_is_licensed', false); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    $license_tier = get_option('metzler_webshield_license_tier', 'free'); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    $is_pro = $is_licensed && ('pro' === $license_tier); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    $current_domain = wp_parse_url(home_url(), PHP_URL_HOST); // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
    $raw_tab = isset($_GET['tab']) ? sanitize_key($_GET['tab']) : 'dashboard'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
    $tab_alias_map = array(
        'overview'   => 'tab-dashboard',
        'dashboard'  => 'tab-dashboard',
        'log'        => 'tab-logs',
        'logs'       => 'tab-logs',
        'quarantine' => 'tab-quarantine',
        'settings'   => 'tab-settings',
        'setting'    => 'tab-settings',
        'license'    => 'tab-license',
        'licence'    => 'tab-license',
    );
    if (isset($tab_alias_map[$raw_tab])) {
        $current_tab = $tab_alias_map[$raw_tab];
    } else {
        $current_tab = strpos($raw_tab, 'tab-') === 0 ? $raw_tab : 'tab-' . $raw_tab;
    }
    $valid_tabs = array('tab-dashboard', 'tab-logs', 'tab-quarantine', 'tab-settings', 'tab-license');
    if (!in_array($current_tab, $valid_tabs, true)) {
        $current_tab = 'tab-dashboard';
    }
    ?>
    <div class="metzler-webshield-brand-header" style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px; padding-top: 12px;">
        <div style="display: flex; align-items: center; gap: 14px;">
            <img src="<?php echo esc_url( METZLER_WEBSHIELD_PLUGIN_URL . 'assets/images/logo-icon-128.png' ); ?>" alt="Metzler Webshield" style="width: 44px; height: 44px; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.08);">
            <div>
                <h1 style="margin: 0; font-size: 22px; font-weight: 700; line-height: 1.2; color: #1d2327;">Metzler Webshield</h1>
                <p style="margin: 3px 0 0; font-size: 13px; color: #646970;">
                    <?php esc_html_e( 'Enterprise Security & Real-Time Firewall', 'metzler-webshield' ); ?>
                    <span style="display: inline-block; margin-left: 8px; padding: 2px 8px; border-radius: 10px; font-size: 11px; font-weight: 600; background: #e0e0e0; color: #3c434a;">v<?php echo esc_html( METZLER_WEBSHIELD_VERSION ); ?></span>
                </p>
            </div>
        </div>
    </div>

    <nav class="nav-tab-wrapper metzler-webshield-nav-tabs" style="margin-bottom: 20px;">
        <a href="#tab-dashboard" class="nav-tab <?php echo $current_tab === 'tab-dashboard' ? 'nav-tab-active' : ''; ?> metzler-webshield-tab-link" data-tab="tab-dashboard"><?php echo esc_html__("Overview", "metzler-webshield"); ?></a>
        <a href="#tab-logs" class="nav-tab <?php echo $current_tab === 'tab-logs' ? 'nav-tab-active' : ''; ?> metzler-webshield-tab-link" data-tab="tab-logs"><?php echo esc_html__("Log", "metzler-webshield"); ?></a>
        <a href="#tab-quarantine" class="nav-tab <?php echo $current_tab === 'tab-quarantine' ? 'nav-tab-active' : ''; ?> metzler-webshield-tab-link" data-tab="tab-quarantine"><?php echo esc_html__("Quarantine", "metzler-webshield"); ?></a>
        <a href="#tab-settings" class="nav-tab <?php echo $current_tab === 'tab-settings' ? 'nav-tab-active' : ''; ?> metzler-webshield-tab-link" data-tab="tab-settings"><?php echo esc_html__("Settings", "metzler-webshield"); ?></a>
        <a href="#tab-license" class="nav-tab <?php echo $current_tab === 'tab-license' ? 'nav-tab-active' : ''; ?> metzler-webshield-tab-link" data-tab="tab-license">
            <?php echo esc_html__("License", "metzler-webshield"); ?>
            <?php if ($is_pro): ?>
                <span class="mws-tier-pill mws-tier-pill-pro"><?php echo esc_html__("PRO", "metzler-webshield"); ?></span>
            <?php elseif ($is_licensed): ?>
                <span class="mws-tier-pill mws-tier-pill-free"><?php echo esc_html__("FREE", "metzler-webshield"); ?></span>
            <?php endif; ?>
        </a>
    </nav>

    <script>
    (function() {
        var hash = window.location.hash;
        if (hash) {
            var clean = hash.replace(/^#/, '').toLowerCase().trim();
            var map = {
                'overview': 'tab-dashboard', 'dashboard': 'tab-dashboard',
                'tab-overview': 'tab-dashboard', 'tab-dashboard': 'tab-dashboard',
                'log': 'tab-logs', 'logs': 'tab-logs',
                'tab-log': 'tab-logs', 'tab-logs': 'tab-logs',
                'quarantine': 'tab-quarantine', 'tab-quarantine': 'tab-quarantine',
                'settings': 'tab-settings', 'setting': 'tab-settings',
                'tab-settings': 'tab-settings', 'tab-setting': 'tab-settings',
                'license': 'tab-license', 'licence': 'tab-license',
                'tab-license': 'tab-license', 'tab-licence': 'tab-license'
            };
            var target = map[clean] || (clean.indexOf('tab-') === 0 ? clean : 'tab-' + clean);
            var valid = ['tab-dashboard', 'tab-logs', 'tab-quarantine', 'tab-settings', 'tab-license'];
            if (valid.indexOf(target) !== -1) {
                var applyInitialTab = function() {
                    var contents = document.querySelectorAll('.metzler-webshield-tab-content');
                    for (var i = 0; i < contents.length; i++) {
                        contents[i].style.display = 'none';
                    }
                    var targetEl = document.getElementById(target);
                    if (targetEl) targetEl.style.display = 'block';

                    var links = document.querySelectorAll('.metzler-webshield-tab-link');
                    for (var j = 0; j < links.length; j++) {
                        links[j].classList.remove('nav-tab-active');
                        if (links[j].getAttribute('data-tab') === target) {
                            links[j].classList.add('nav-tab-active');
                        }
                    }
                };
                if (document.readyState === 'loading') {
                    document.addEventListener('DOMContentLoaded', applyInitialTab);
                } else {
                    applyInitialTab();
                }
            }
        }
    })();
    </script>
    
    <div id="tab-dashboard" class="metzler-webshield-tab-content" style="display:<?php echo $current_tab === 'tab-dashboard' ? 'block' : 'none'; ?>;">

    <!-- Hero Status Section (The Big Shield) -->
    <div id="metzler-webshield-hero" class="metzler-webshield-hero status-<?php echo esc_attr($hero_status); ?>">
        <div class="metzler-webshield-hero-inner">
            <div class="hero-icon">
                <span class="dashicons <?php echo esc_attr($hero_status) === 'safe' ? 'dashicons-shield' : 'dashicons-warning'; ?>"></span>
            </div>
            <div class="hero-content">
                <h1 id="hero-title"><?php echo esc_attr($hero_status) === 'safe' ? ($is_licensed ? ($is_pro ? esc_html__('Your website is fully secured with Pro.', 'metzler-webshield') : esc_html__('Your website is secure (Community Tier).', 'metzler-webshield')) : esc_html__('Basic protection active.', 'metzler-webshield')) : esc_html__('Security risks detected!', 'metzler-webshield'); ?></h1>
                <p id="hero-subtitle"><?php echo esc_attr($hero_status) === 'safe' ? ($is_licensed ? ($is_pro ? esc_html__('All background guards and Pro cloud firewall rules are active.', 'metzler-webshield') : esc_html__('Community Free protection active. Upgrade to Pro for advanced cloud firewall rules and central management.', 'metzler-webshield')) : esc_html__('Activate a free license to unlock Smart Scan & Cloud Features.', 'metzler-webshield')) : esc_html__('Please check the security log.', 'metzler-webshield'); ?></p>
                
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
            <span class="dashicons dashicons-clock"></span>
            <div class="stat-text">
                <strong id="stat-last-scan"><?php echo esc_html($last_scan_text); ?></strong>
                <span><?php echo esc_html__("Last Smart Scan", "metzler-webshield"); ?></span>
            </div>
        </div>
    </div>

    <?php if (! $is_pro): ?>
        <div class="metzler-webshield-upgrade-banner">
            <div class="upgrade-banner-content">
                <div class="upgrade-banner-badge"><?php echo esc_html__("RECOMMENDED UPGRADE", "metzler-webshield"); ?></div>
                <h3 class="upgrade-banner-title"><?php echo esc_html__("Upgrade to Metzler Webshield Pro", "metzler-webshield"); ?></h3>
                <p class="upgrade-banner-desc"><?php echo esc_html__("Get faster cloud firewall updates (Community rules are 7 days behind), centralized multi-site monitoring, and deep attack forensics for your domain.", "metzler-webshield"); ?></p>
                <div class="upgrade-banner-features">
                    <span class="upgrade-feature-item"><span class="dashicons dashicons-yes-alt"></span> <?php echo esc_html__("Faster WAF Updates (Community rules are 7 days behind)", "metzler-webshield"); ?></span>
                    <span class="upgrade-feature-item"><span class="dashicons dashicons-yes-alt"></span> <?php echo esc_html__("Centralized Cloud Dashboard (dash.metzler-webshield.de)", "metzler-webshield"); ?></span>
                    <span class="upgrade-feature-item"><span class="dashicons dashicons-yes-alt"></span> <?php echo esc_html__("Deep Attack Forensics & Bot Protection", "metzler-webshield"); ?></span>
                </div>
            </div>
            <div class="upgrade-banner-cta">
                <a href="https://dash.metzler-webshield.de/billing/pricing?domain=<?php echo esc_attr(urlencode($current_domain)); ?>" target="_blank" rel="noopener" class="button button-primary upgrade-cta-btn">
                    <span><?php echo esc_html__("Upgrade to Pro", "metzler-webshield"); ?></span>
                    <span class="dashicons dashicons-external"></span>
                </a>
                <a href="https://dash.metzler-webshield.de/dashboard" target="_blank" rel="noopener" class="upgrade-dashboard-link">
                    <?php echo esc_html__("Already have slots? Assign in Dashboard", "metzler-webshield"); ?> &rarr;
                </a>
            </div>
        </div>
    <?php endif; ?>

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
                    <a href="#tab-logs" class="button button-secondary"><?php echo esc_html__("View details in the log", "metzler-webshield"); ?></a>
                </p>
            </div>
        </div>
    </div>

    <!-- Main Content Grid -->
    <div id="poststuff">
        <div id="post-body" class="metabox-holder columns-1">
            <div id="post-body-content">
                <!-- Global Attack Statistics Widget -->
                <div class="postbox metzler-webshield-postbox">
                    <h2 class="hndle">
                        <span class="dashicons dashicons-chart-area"></span>
                        <span><?php echo esc_html__("Metzler Webshield Global Intelligence", "metzler-webshield"); ?></span>
                    </h2>
                    <div class="inside" style="position: relative;">
                        <p style="margin-top: 0; color: #646970;">
                            <?php echo esc_html__("Blocked attacks across the global network in the last 24 hours.", "metzler-webshield"); ?>
                        </p>
                        
                        <div style="height: 250px; width: 100%;">
                            <canvas id="metzlerGlobalAttacksChart"></canvas>
                        </div>
                        <div id="metzler-chart-loader" style="position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);">
                            <span class="spinner is-active" style="float: none; margin: 0;"></span>
                        </div>
                        
                        <?php
                        // Server-side Fetch to protect admin privacy (no direct browser calls to external APIs)
                        $metzler_webshield_global_stats_json = get_transient('metzler_webshield_global_stats');
                        if ( false === $metzler_webshield_global_stats_json ) {
                            $metzler_webshield_api_response = wp_remote_get('https://api.metzler-webshield.de/api/stats/attacks-24h', array('timeout' => 3));
                            if ( ! is_wp_error( $metzler_webshield_api_response ) && wp_remote_retrieve_response_code( $metzler_webshield_api_response ) === 200 ) {
                                // Safely decode and re-encode to ensure it's valid JSON and harmless
                                $metzler_webshield_decoded = json_decode( wp_remote_retrieve_body( $metzler_webshield_api_response ), true );
                                $metzler_webshield_global_stats_json = wp_json_encode( $metzler_webshield_decoded ?: array('labels' => array(), 'data' => array()) );
                                set_transient('metzler_webshield_global_stats', $metzler_webshield_global_stats_json, 5 * MINUTE_IN_SECONDS);
                            } else {
                                // Fallback empty data if API is down
                                $metzler_webshield_global_stats_json = wp_json_encode(array('labels' => array(), 'data' => array()));
                            }
                        }
                        ?>
                        
                        <!-- Render chart -->
                        <script>
                            document.addEventListener('DOMContentLoaded', function() {
                                document.getElementById('metzler-chart-loader').style.display = 'none';
                                
                                const data = <?php echo $metzler_webshield_global_stats_json; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped ?>;
                                
                                if (!data.labels || data.labels.length === 0) {
                                    document.getElementById('metzler-chart-loader').style.display = 'block';
                                    document.getElementById('metzler-chart-loader').innerHTML = '<?php echo esc_js(__("Could not load statistics.", "metzler-webshield")); ?>';
                                    return;
                                }
                                
                                // Convert API UTC timestamps to the admin's local browser timezone
                                let displayLabels = data.labels;
                                if (data.timestamps && data.timestamps.length > 0) {
                                    displayLabels = data.timestamps.map(ts => {
                                        const date = new Date(ts);
                                        // Format as HH:00 in local timezone
                                        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
                                    });
                                }

                                const ctx = document.getElementById('metzlerGlobalAttacksChart').getContext('2d');
                                new Chart(ctx, {
                                    type: 'line',
                                    data: {
                                        labels: displayLabels,
                                        datasets: [{
                                            label: '<?php echo esc_js(__("Blocked Attacks", "metzler-webshield")); ?>',
                                            data: data.data,
                                            backgroundColor: 'rgba(0, 163, 42, 0.1)',
                                            borderColor: 'rgba(0, 163, 42, 1)',
                                            borderWidth: 2,
                                            pointRadius: 2,
                                            pointBackgroundColor: 'rgba(0, 163, 42, 1)',
                                            fill: true,
                                            tension: 0.3
                                        }]
                                    },
                                    options: {
                                        responsive: true,
                                        maintainAspectRatio: false,
                                        plugins: {
                                            legend: {
                                                display: false
                                            },
                                            tooltip: {
                                                mode: 'index',
                                                intersect: false,
                                            }
                                        },
                                        scales: {
                                            y: {
                                                beginAtZero: true,
                                                ticks: {
                                                    precision: 0
                                                }
                                            },
                                            x: {
                                                grid: {
                                                    display: false
                                                }
                                            }
                                        }
                                    }
                                });
                            });
                        </script>
                    </div>
                </div>

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
    <div id="tab-logs" class="metzler-webshield-tab-content" style="display:<?php echo $current_tab === 'tab-logs' ? 'block' : 'none'; ?>;">
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
                                            <td><?php echo esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'), strtotime($metzler_webshield_log->time))); ?></td>
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
    <div id="tab-quarantine" class="metzler-webshield-tab-content" style="display:<?php echo $current_tab === 'tab-quarantine' ? 'block' : 'none'; ?>;">
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
    <div id="tab-settings" class="metzler-webshield-tab-content" style="display:<?php echo $current_tab === 'tab-settings' ? 'block' : 'none'; ?>;">
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
                            $metzler_webshield_fim_count = $wpdb->get_var("SELECT COUNT(*) FROM {$wpdb->prefix}metzler_webshield_fim"); // phpcs:ignore WordPress.DB.DirectDatabaseQuery, PluginCheck.Security.DirectDB.UnescapedDBParameter, WordPress.NamingConventions.PrefixAllGlobals
                            ?>
                            <p class="metzler-webshield-stat-highlight"><?php echo 
/* translators: %d: number of files */
sprintf(esc_html__("Currently in database baseline: %d files", "metzler-webshield"), intval($metzler_webshield_fim_count)); ?></p>
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
                                $waf_active = get_option('metzler_webshield_enable_waf', '0') === '1'; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
                            ?>
                            <p class="metzler-webshield-stat-highlight <?php echo $waf_active ? 'waf-active' : 'waf-inactive'; ?>">
                                <?php echo esc_html__("Status:", "metzler-webshield") . " " . ($waf_active ? esc_html__('Active', 'metzler-webshield') : esc_html__('Inactive', 'metzler-webshield')); ?>
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
                        <th scope="row"><?php echo esc_html__("Rate Limiting & DoS Shield", "metzler-webshield"); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" id="metzler-webshield-setting-ratelimit" <?php echo get_option('metzler_webshield_enable_rate_limiting', '1') === '1' ? 'checked' : ''; ?>>
                                <strong><?php echo esc_html__("Enable general rate limiting (Recommended)", "metzler-webshield"); ?></strong>
                            </label>
                            <p class="description"><?php echo esc_html__("Protects your server against aggressive scrapers, automated floods, and bots by limiting excessive request bursts per IP. Verified search engines (Google, Bing), static assets, and logged-in administrators are automatically exempt.", "metzler-webshield"); ?></p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row"><?php echo esc_html__("Under Attack Mode", "metzler-webshield"); ?></th>
                        <td>
                            <label>
                                <input type="checkbox" id="metzler-webshield-setting-under-attack" <?php echo get_option('metzler_webshield_under_attack_mode', '0') === '1' ? 'checked' : ''; ?>>
                                <strong style="color: #d63638;"><?php echo esc_html__("Enable 'Under Attack' Mode (Emergency DDoS Shield)", "metzler-webshield"); ?></strong>
                            </label>
                            <?php 
                                $under_attack_active = get_option('metzler_webshield_under_attack_mode', '0') === '1'; // phpcs:ignore WordPress.NamingConventions.PrefixAllGlobals
                            ?>
                            <p class="metzler-webshield-stat-highlight <?php echo $under_attack_active ? 'waf-active' : 'waf-inactive'; ?>" style="<?php echo $under_attack_active ? 'background: #fcf0f1; border-color: #d63638; color: #d63638;' : ''; ?>">
                                <?php echo esc_html__("Status:", "metzler-webshield") . " " . ($under_attack_active ? esc_html__('Active (All new visitors must pass security check)', 'metzler-webshield') : esc_html__('Inactive (Normal operation)', 'metzler-webshield')); ?>
                            </p>
                            <p class="description"><?php echo esc_html__("Activate during heavy active DDoS attacks or bot floods. Every new anonymous visitor must pass a 1-click human verification before reaching WordPress, completely shielding your database. Verified search engines (Googlebot, Bingbot) and logged-in administrators are automatically exempt.", "metzler-webshield"); ?></p>
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
    <div id="tab-license" class="metzler-webshield-tab-content" style="display:<?php echo $current_tab === 'tab-license' ? 'block' : 'none'; ?>;">
        <div class="postbox metzler-webshield-postbox">
            <h2 class="hndle">
                <span class="dashicons dashicons-admin-network"></span>
                <span><?php echo esc_html__("License & Subscription", "metzler-webshield"); ?></span>
            </h2>
            <div class="inside">
                <?php if ($is_licensed): ?>
                    <?php if ($is_pro): ?>
                        <!-- PRO ACTIVE CARD -->
                        <div class="mws-license-card mws-license-card-pro">
                            <div class="mws-license-header">
                                <div class="mws-license-title-wrap">
                                    <span class="dashicons dashicons-shield-alt mws-license-icon" style="color: #00a32a;"></span>
                                    <div>
                                        <h3 class="mws-license-title"><?php echo esc_html__("Metzler Webshield Pro is Active", "metzler-webshield"); ?></h3>
                                        <p class="mws-license-subtitle"><?php echo esc_html__("Your domain is protected with advanced cloud firewall rules and cloud threat intelligence.", "metzler-webshield"); ?></p>
                                    </div>
                                </div>
                                <span class="mws-status-badge mws-status-badge-pro"><?php echo esc_html__("PRO ACTIVE", "metzler-webshield"); ?></span>
                            </div>

                            <div class="mws-license-details">
                                <div class="mws-detail-row">
                                    <span class="mws-detail-label"><?php echo esc_html__("Protected Domain:", "metzler-webshield"); ?></span>
                                    <span class="mws-detail-value"><code><?php echo esc_html($current_domain); ?></code></span>
                                </div>
                                <div class="mws-detail-row">
                                    <span class="mws-detail-label"><?php echo esc_html__("WAF Rule Channel:", "metzler-webshield"); ?></span>
                                    <span class="mws-detail-value" style="color: #008a20; font-weight: 600;">
                                        <span class="dashicons dashicons-yes-alt" style="vertical-align: text-top; font-size: 16px;"></span>
                                        <?php echo esc_html__("Advanced Cloud Threat Stream", "metzler-webshield"); ?>
                                    </span>
                                </div>
                                <div class="mws-detail-row">
                                    <span class="mws-detail-label"><?php echo esc_html__("Account Email:", "metzler-webshield"); ?></span>
                                    <span class="mws-detail-value"><?php echo esc_html(get_option('metzler_webshield_verified_email', '-')); ?></span>
                                </div>
                            </div>

                            <div class="mws-license-actions">
                                <a href="https://dash.metzler-webshield.de/dashboard/<?php echo esc_attr(urlencode($current_domain)); ?>" target="_blank" rel="noopener" class="button button-primary button-large mws-btn-inline-icon">
                                    <span><?php echo esc_html__("Open Cloud Dashboard", "metzler-webshield"); ?></span>
                                    <span class="dashicons dashicons-external"></span>
                                </a>
                                <button type="button" id="btn-recheck-license" class="button button-secondary"><?php echo esc_html__("Recheck License", "metzler-webshield"); ?></button>
                                <button type="button" id="btn-remove-license" class="button button-link-delete" style="color: #d63638; margin-left: 10px;"><?php echo esc_html__("Remove License", "metzler-webshield"); ?></button>
                                <span id="license-recheck-feedback" class="metzler-webshield-action-feedback"></span>
                            </div>
                        </div>

                    <?php else: ?>
                        <!-- FREE TIER CARD -->
                        <div class="mws-license-card mws-license-card-free">
                            <div class="mws-license-header">
                                <div class="mws-license-title-wrap">
                                    <span class="dashicons dashicons-shield mws-license-icon" style="color: #2271b1;"></span>
                                    <div>
                                        <h3 class="mws-license-title"><?php echo esc_html__("Metzler Webshield Community (Free Tier)", "metzler-webshield"); ?></h3>
                                        <p class="mws-license-subtitle"><?php echo esc_html__("Basic security activated. Upgrade to Pro to unlock advanced cloud firewall rules and central management.", "metzler-webshield"); ?></p>
                                    </div>
                                </div>
                                <span class="mws-status-badge mws-status-badge-free"><?php echo esc_html__("FREE TIER", "metzler-webshield"); ?></span>
                            </div>

                            <div class="mws-license-details">
                                <div class="mws-detail-row">
                                    <span class="mws-detail-label"><?php echo esc_html__("Protected Domain:", "metzler-webshield"); ?></span>
                                    <span class="mws-detail-value"><code><?php echo esc_html($current_domain); ?></code></span>
                                </div>
                                <div class="mws-detail-row">
                                    <span class="mws-detail-label"><?php echo esc_html__("Account Email:", "metzler-webshield"); ?></span>
                                    <span class="mws-detail-value"><?php echo esc_html(get_option('metzler_webshield_verified_email', '-')); ?></span>
                                </div>
                                <div class="mws-detail-row">
                                    <span class="mws-detail-label"><?php echo esc_html__("WAF Rule Channel:", "metzler-webshield"); ?></span>
                                    <span class="mws-detail-value" style="color: #646970;">
                                        <?php echo esc_html__("Community Rules (7 days behind Pro updates)", "metzler-webshield"); ?>
                                    </span>
                                </div>
                            </div>

                            <div class="mws-license-actions">
                                <a href="https://dash.metzler-webshield.de/billing/pricing?domain=<?php echo esc_attr(urlencode($current_domain)); ?>" target="_blank" rel="noopener" class="button button-primary mws-btn-inline-icon">
                                    <span><?php echo esc_html__("Upgrade to Pro", "metzler-webshield"); ?></span>
                                    <span class="dashicons dashicons-external"></span>
                                </a>
                                <button type="button" id="btn-recheck-license" class="button button-secondary"><?php echo esc_html__("Recheck License", "metzler-webshield"); ?></button>
                                <button type="button" id="btn-remove-license" class="button button-link-delete" style="color: #d63638; margin-left: 10px;"><?php echo esc_html__("Remove License", "metzler-webshield"); ?></button>
                                <span id="license-recheck-feedback" class="metzler-webshield-action-feedback"></span>
                            </div>
                        </div>
                    <?php endif; ?>
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
                                    <br><br>
                                    <label>
                                        <input type="checkbox" id="metzler-webshield-license-telemetry" value="1">
                                        <?php echo esc_html__("I agree to share anonymous telemetry data to improve threat intelligence (optional).", "metzler-webshield"); ?>
                                    </label>
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

