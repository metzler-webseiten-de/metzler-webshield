=== Metzler Webshield ===
Contributors: metzler-webseiten, metzlerwp
Tags: security, firewall, waf, malware scanner, antivirus
Requires at least: 6.0
Tested up to: 7.1
Stable tag: 1.0.0
Requires PHP: 7.4
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

A lightweight WordPress AntiVirus & Firewall (WAF) solution made in Germany. GDPR-compliant and focused on security.

== Description ==

Metzler Webshield is an enterprise-grade security solution for WordPress. It utilizes an early-loading architecture to intercept attacks before WordPress fully loads, aiming to provide strong security with minimal overhead.

### Core Features

*   **Real-time Web Application Firewall (WAF):** Blocks SQL Injections, Cross-Site Scripting (XSS), and malicious bots instantly before they can reach your site.
*   **Low-Overhead Architecture:** We keep your local installation lightweight by synchronizing the latest threat definitions directly from our Threat Intelligence Cloud.
*   **File Integrity Monitoring (FIM):** Tracks all file changes in your WP environment and alerts you to unauthorized modifications or hacker uploads.
*   **Heuristic Malware Scanner:** Performs deep-scans on your file system to detect obfuscated backdoors, web shells, and malicious code injections.
*   **Bot Protection:** Defends your login screen against automated brute-force attacks.
*   **Smart Quarantine:** Automatically and safely isolates suspicious files without immediately breaking your site, allowing for easy 1-click restoration.
*   **GDPR-Compliant:** Made in Germany. Designed with privacy in mind. Normal website visitors are never tracked.

== External services ==

This plugin connects to the Metzler Webshield Threat Intelligence API (`api.metzler-webshield.de`) to obtain the latest WAF rules, vulnerability definitions, and core checksums. It is also used to verify your license token.
If you opt-in to telemetry, the plugin will send metadata of blocked attacks (IP addresses and malicious payloads) to our Threat Intelligence API to help train our global security network.
This service is provided by Metzler IT: [Terms of Service](https://metzler-webshield.de/terms), [Privacy Policy](https://metzler-webshield.de/privacy).

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/metzler-webshield` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. Navigate to the new 'Metzler Webshield' menu in your WordPress admin dashboard.
4. Enter your email to request a free license key and activate the real-time protection.
5. Head to the settings tab to perform your initial system scan.

== Frequently Asked Questions ==

= Does this slow down my website? =
Metzler Webshield is designed for performance. The WAF runs early during the WordPress boot process to minimize execution time.

= Are my firewall rules updated automatically? =
Yes. The plugin syncs the latest threat definitions from our Threat Intelligence API automatically in the background.

= Does it conflict with caching plugins? =
No. Since Metzler Webshield runs early, it typically blocks bad requests before they hit your cache.
