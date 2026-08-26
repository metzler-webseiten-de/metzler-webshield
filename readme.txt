=== Metzler Webshield ===
Contributors: metzler-webseiten
Tags: security, firewall, waf, malware scanner, antivirus
Requires at least: 6.0
Tested up to: 7.1
Stable tag: 1.0.0
Requires PHP: 7.4
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

A lightning-fast, highly optimized WordPress AntiVirus & Firewall (WAF) solution made in Germany. GDPR-compliant and extremely lightweight.

== Description ==

Metzler_Webshield is an enterprise-grade, yet extremely lightweight security solution for WordPress. Unlike bloated security plugins that slow down your website and overload your database, Metzler_Webshield utilizes a high-speed MU-Plugin (Must-Use) architecture. 

It intercepts attacks milliseconds before WordPress even loads, ensuring zero performance impact on your TTFB (Time to First Byte).

### Core Features

*   **Real-time Web Application Firewall (WAF):** Blocks SQL Injections, Cross-Site Scripting (XSS), and malicious bots instantly before they can reach your site.
*   **Zero-Overhead Architecture:** We keep your local installation lightweight and incredibly fast by synchronizing the latest threat definitions directly from our Threat Intelligence Cloud.
*   **File Integrity Monitoring (FIM):** Tracks all file changes in your WP environment and alerts you to unauthorized modifications or hacker uploads.
*   **Heuristic Malware Scanner:** Performs deep-scans on your file system to detect obfuscated backdoors, web shells, and malicious code injections.
*   **Bot Protection:** Defends your login screen against automated brute-force attacks without requiring annoying CAPTCHAs.
*   **Smart Quarantine:** Automatically and safely isolates suspicious files without immediately breaking your site, allowing for easy 1-click restoration.
*   **GDPR-Compliant:** Made in Germany. Designed with privacy in mind. Normal website visitors are never tracked, and optional threat telemetry relies strictly on legitimate security interests.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/metzler-webshield` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. Navigate to the new 'Metzler_Webshield' menu in your WordPress admin dashboard.
4. Enter your email to request a free license key and activate the real-time protection.
5. Head to the settings tab to perform your initial system scan.

== Frequently Asked Questions ==

= Does this slow down my website? =
No. Metzler_Webshield is designed for maximum performance. The WAF runs as an MU-Plugin, meaning it executes before the WordPress database is even queried. It adds less than 1ms to your page load time.

= Are my firewall rules updated automatically? =
Yes. The plugin syncs the latest threat definitions from our Threat Intelligence API automatically in the background.

= Does it conflict with caching plugins? =
No. Since Metzler_Webshield runs before caching mechanisms (like WP Rocket or W3 Total Cache) are triggered, it blocks bad requests before they hit your cache.
