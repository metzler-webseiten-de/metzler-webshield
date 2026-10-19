=== Metzler Webshield ===
Contributors: metzler-webseiten, metzlerwp
Tags: security, firewall, waf, malware scanner, antivirus
Requires at least: 6.0
Tested up to: 7.1
Stable tag: 2.0.6
Requires PHP: 7.4
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

A lightweight WordPress AntiVirus & Firewall (WAF) solution made in Germany. GDPR-compliant and focused on security.

== Description ==

Metzler Webshield is an enterprise-grade security solution for WordPress. It utilizes an early-loading architecture to intercept attacks before WordPress fully loads, aiming to provide strong security with minimal overhead.

### Core Features

*   **Real-time Web Application Firewall (WAF):** Blocks SQL Injections, Cross-Site Scripting (XSS), path traversal and malicious bots before they reach WordPress.
*   **Rate Limiting & Under Attack Mode:** Throttles aggressive scrapers and floods; an emergency mode lets only verified humans through.
*   **File Integrity Monitoring (FIM):** Tracks all file changes in your WP environment and alerts you to unauthorized modifications or hacker uploads.
*   **Core & Plugin Signature Check:** Compares WordPress core and plugin files with the official checksums from WordPress.org.
*   **Heuristic Malware Scanner:** Performs deep-scans on your file system to detect obfuscated backdoors, web shells, and malicious code injections.
*   **Bot Protection:** Defends your login screen against automated brute-force attacks and user enumeration.
*   **Smart Quarantine:** Safely isolates suspicious files, allowing for easy 1-click restoration.
*   **GDPR-Compliant:** Made in Germany. Designed with privacy in mind. Normal website visitors are never tracked.

All features of this plugin work locally and without an account. Optionally, you can connect your site to the Metzler Webshield Threat Intelligence Cloud with a free key: the firewall then receives the community cloud rules every hour (published 7 days after the Pro channel), and you can choose to share attack telemetry.

An optional, separately distributed Pro add-on (available at metzler-webshield.de) adds vulnerability intelligence; with a Pro subscription the cloud rules arrive without delay. This plugin does not contain or download any Pro code.

== External services ==

This plugin connects to the following services:

**WordPress.org checksums** (`api.wordpress.org`, `downloads.wordpress.org`)
When a Smart Scan runs (manually or by the daily scheduled scan) with the core or plugin signature check enabled, the plugin requests the official checksums for your WordPress version and locale and for the slug and version of each installed plugin. No personal data is sent. [WordPress.org Privacy Policy](https://wordpress.org/about/privacy/)

**Metzler Webshield Threat Intelligence API** (`api.metzler-webshield.de`)
When you open the Metzler Webshield dashboard page, anonymous global attack statistics are loaded (`/stats/attacks-24h`, cached for 5 minutes) to display the "Global Intelligence" chart. No site, user or visitor data is included in this request.

Everything else is optional. Nothing else is sent unless you use the "Threat Cloud" tab:

*   When you request a free key, your email address and your site's domain are sent (`/license/request`).
*   When you connect with a key, and once per hour while connected, the key and your site's domain are sent to verify the connection (`/license/verify`).
*   While connected, the firewall rule set is downloaded once per hour (`/waf/rules`, authenticated with your key). The rules are delivered encrypted with your key and stored in `wp-content/uploads/metzler-webshield/`; they contain only detection patterns, never executable code.
*   Only if you additionally opt in to telemetry sharing (off by default), metadata of requests blocked by the firewall is sent every 5 minutes (`/telemetry/waf/batch`): time, domain, IP address of the blocked client, request URI, request method, user agent, attack type, matched payload and request headers (cookies and authorization headers are removed). On first opt-in, previously logged blocks are sent once as well. You can turn telemetry off at any time in the settings or by disconnecting.
*   With telemetry sharing enabled, files reported by the scanner are sent as well (`/telemetry/findings/batch`): SHA-256 hash, size, modification time, path relative to the WordPress directory, the rule that matched, the plugin or theme slug and version the file belongs to, your WordPress, PHP and plugin version, and whether you marked the file as safe, moved it to quarantine, restored or deleted it. Never the file content, the absolute server path or user names. Files reported while telemetry was off are not sent later.
*   When you click "Send for analysis" on a reported or quarantined file, that single file is uploaded with its metadata (`/samples/submit`): content, hash, size, path relative to the WordPress directory, the rule that matched, the plugin or theme it belongs to and an optional note from you. Configuration files, database dumps and backups can never be sent. You receive the result by email to the address the key was requested with; the plugin fetches it hourly (`/samples/status`) and marks clean files as safe. Files sent in are deleted at the latest 90 days after the analysis.
*   Unknown files (setting "Unknown files", off until you choose): with telemetry sharing enabled, hashes of PHP files of plugins and themes that are not WordPress.org originals are compared with the API (`/samples/lookup`). Only if you choose "Send this time" or "Always send automatically", unknown files are uploaded like above, at most 50 per day, never files from the uploads folder. Unjudged files are deleted 90 days after they were received unless sites still report them.

This service is provided by Metzler IT: [Terms of Service](https://metzler-webshield.de/terms), [Privacy Policy](https://metzler-webshield.de/privacy).

== Third-party libraries ==

*   Chart.js 4.5.1 (MIT License) – https://github.com/chartjs/Chart.js – bundled as `assets/js/chart.min.js`, unmodified build from the official release.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/metzler-webshield` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress. The firewall is enabled automatically.
3. Navigate to the new 'Metzler Webshield' menu in your WordPress admin dashboard and run your first Smart Scan.
4. Optional: connect the site in the 'Threat Cloud' tab to share attack telemetry.

== Frequently Asked Questions ==

= Does this slow down my website? =
Metzler Webshield is designed for performance. The WAF runs early during the WordPress boot process to minimize execution time.

= Do I need an account? =
No. All protection features work without an account. A free key is only needed for the community cloud firewall rules and for sharing attack telemetry.

= Does the plugin send data to external servers? =
Only checksum requests to WordPress.org during scans and an anonymous request for the global statistics chart on the plugin's dashboard page. Anything else requires your explicit action, see "External services".

= Does it conflict with caching plugins? =
No. Since Metzler Webshield runs early, it typically blocks bad requests before they hit your cache.

== Changelog ==

= 2.0.6 =
* Added: Every new plugin or theme installation is reported with the user who installed it. Backdoor plugins installed through leaked remote management keys look exactly like a normal installation. Replacing an installed plugin or theme with an uploaded package (a manual update) is only noted in the log.
* Added: The config scan reports users and roles other than administrator that can install, update or edit plugins, themes or core files, like backdoor accounts that hide administrator rights behind the editor role.
* Added: "Send for analysis" on files reported by the scanner and in the quarantine (requires a connection to the Threat Intelligence Cloud, a free key is enough): the file is checked by Metzler Webshield, the result arrives by email and in the log, and a clean file is marked as safe automatically. Configuration files, database dumps and backups can never be sent.
* Added: Setting "Unknown files": PHP files of plugins and themes that are neither WordPress.org originals nor known to Metzler Webshield (e.g. premium plugins) can be sent for analysis, once or automatically, at most 50 per day. Nothing is sent until you choose, files from the uploads folder never.
* Added: With telemetry sharing enabled, files reported by the scanner are shared as hash, size, path relative to the WordPress directory and the rule that matched, together with whether you marked them as safe or moved them to quarantine, so false alarms can be fixed faster. File contents are never sent automatically.
* Fixed: After an update, File Integrity Monitoring only refreshes its snapshot for the updated plugins, themes and language files instead of all of wp-content, which silently accepted every file planted since the last scan.
* Fixed: New and modified files found by File Integrity Monitoring were only listed in the log and did not count as threats in the dashboard, the dashboard widget and the admin notice.

= 2.0.5 =
* Added: The core scan reports unknown PHP and .htaccess files in wp-admin, wp-includes and the wp-*.php files in the root directory, where backdoors like to hide between the WordPress files.
* Added: Malware signatures for the lock360 backdoor campaign: split .htaccess/robots.txt file names, a single character cURL user agent and .htaccess files that block all PHP files except a list of backdoor entry points.
* Fixed: The malware scanner no longer reports plugin and core files that match the official WordPress.org checksums (e.g. UpdraftPlus) as malware.
* Fixed: Protection files that plugins create for their own folders (e.g. .htaccess, web.config and index.php in All-in-One WP Migration's storage folder) are no longer reported as unknown plugin files.
* Fixed: Database error when the plugin was activated for the first time. The quarantine cleanup now runs once a day instead of on every page load.
* Changed: Additional non-executable files in plugins (stylesheets, scripts, images generated by the plugin itself) are listed as information instead of critical threats.
* Changed: On sites in other languages than English, core files from an update via the English package and outdated language files (e.g. liesmich.html) are listed as harmless information instead of modified core files.
* Changed: The Smart Scan is much faster, especially on large sites and slow hosting: each request now processes several seconds of work instead of a single small batch, file lists are no longer rewritten to the database after every step, and File Integrity Monitoring loads its snapshot with one query instead of one query per file.

= 2.0.4 =
* Fixed: Real visitors were sometimes blocked as bots when logging in, mostly in Safari on iPhone, iPad and Mac. The login check token is now fetched fresh when the form is used instead of being embedded in the page, so cached pages and restored browser tabs no longer send an expired token.
* Fixed: Login forms that submit via AJAX (e.g. learning platforms, page builders) now send the bot check token.
* Changed: Logging in no longer requires a mouse movement or key press first; autofill and password managers work without extra interaction.
* Changed: E-mail addresses in blocked login attempts are masked (e.g. ok***@example.com) in the local log and in telemetry.

= 2.0.3 =
* Fixed: robots.txt, ads.txt, sitemaps, favicon.ico and /.well-known/ (security.txt, Let's Encrypt) are no longer blocked for crawlers without an Accept header or with tool User-Agents. A blocked robots.txt made Google ignore its rules or pause crawling. Attack payloads in these requests are still blocked.
* Fixed: The integrity check no longer logs the database error "Can't DROP 'file_path'" on new installations.

= 2.0.2 =
* Fixed: An outage or server error of the Threat Intelligence Cloud no longer disconnects the site and turns telemetry off. Only a key the API explicitly rejects disconnects it.
* Changed: "Recheck connection" also fetches the current cloud firewall rules right away.

= 2.0.1 =
* Security: Clients can no longer pose as Googlebot or as the server itself with forged proxy headers (X-Forwarded-For, CF-Connecting-IP) to skip rate limiting. Forwarded IPs only earn exemptions when they come from Cloudflare or a reverse proxy in a private network.
* Security: Search engine crawlers are verified against the hostnames each engine publishes, also over IPv6. All Google crawlers are recognized (AdsBot, Storebot, GoogleOther, Google-InspectionTool, ...), not only "Googlebot".
* Fixed: Verified search engines are no longer blocked by the user enumeration protection when they follow ?author= links.
* Security: The firewall inspects JSON request bodies (REST API) and multiply URL-encoded payloads.
* Fixed: Fewer false positives: SQL injection and XSS rules look for query structure instead of words like "select ... from", and bot signatures only apply to the User-Agent (a search for "curl" is no longer blocked).
* Performance: The server's own IP is resolved once per hour instead of on every request.
* New: Extended protection (Settings). The firewall runs before WordPress via auto_prepend_file, so it also stops exploits that call vulnerable plugin files directly. Set up with one click through .user.ini or .htaccess, removed again on deactivation.
* Security: The malware scanner detects auto_prepend_file/auto_append_file directives in .user.ini and php.ini that load foreign code on every request.
* Fixed: Turning off "Real-time Firewall (WAF)" in the settings had no effect; the firewall kept running.

= 2.0.0 =
* Changed: All features now work without a license key. Core and plugin signatures are loaded directly from WordPress.org.
* Changed: The connection to the Threat Intelligence Cloud is optional. Connected sites receive the community cloud rules; telemetry is opt-in.
* Changed: Vulnerability intelligence moved to the separate Pro add-on.
* Changed: Prepared for distribution through WordPress.org.
* Privacy: Telemetry is off by default; cookies and authorization headers are never included.
* Fixed: Blocked brute-force and user-enumeration attempts no longer appear as active threats on the dashboard.
* Fixed: The "Blocked Bots (24h)" widget shows IP address and attack type for brute-force and user-enumeration blocks, also on translated sites.
* Fixed: The "File Dropper" heuristic no longer matches file writes and unrelated base64_decode() calls across separate statements (false positives).

= 1.0.2 =
* Security: Telemetry buffer, WAF key and rate-limit data are no longer downloadable on Nginx and other servers that ignore .htaccess. Files are stored as guarded PHP files and migrated automatically.

= 1.0.1 =
* Added self-hosted automatic update mechanism with WordPress 5.8+ Update URI protection.
* Added Pro tier status indicator, expiration alerts, and direct dashboard integration.
* Added WordPress Dashboard Widget showing blocked bot statistics over the last 24 hours.
* Improved File Integrity Monitoring (FIM) database indexing using MD5 path hashes to resolve collisions on long file paths (e.g. Google Site Kit).
* Enhanced heuristic file scanner with AST tokenizer to safely allow directory listing dummies (WPForms, WordPress Core) while strictly blocking web shells and payloads.
* Fixed deep-linking for log tabs (#tab-logs) and ensured logs load properly on initial dashboard view.
* Added whitelist verification across file and integrity scans for resolved false positives.
* Improved resilience against network timeouts and Cloudflare rate limiting with negative caching and jitter.
* Fully localized all admin interface strings into English.

= 1.0.0 =
* Initial release with Real-Time WAF, Malware Scanner, FIM, and Quarantine.

== Upgrade Notice ==

= 2.0.0 =
Pro subscribers: vulnerability intelligence is now provided by the separate Pro add-on. Download it from your customer dashboard.
