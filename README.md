# Metzler Webshield

[![WordPress Version](https://img.shields.io/badge/WordPress-6.0%2B-blue.svg)](https://wordpress.org/)
[![PHP Version](https://img.shields.io/badge/PHP-7.4%2B-777bb4.svg)](https://php.net/)
[![License](https://img.shields.io/badge/License-GPLv2-green.svg)](https://www.gnu.org/licenses/gpl-2.0.html)

Metzler Webshield is a lightweight security and Web Application Firewall (WAF) plugin for WordPress. The firewall and rate limiter run as the very first `plugins_loaded` callback, before WordPress initializes themes and requests are routed.

## Features

* **Real-Time WAF:** Blocks SQL Injection (SQLi), Cross-Site Scripting (XSS), path traversal and malicious bot traffic.
* **Rate Limiting & Under Attack Mode:** Throttles floods and scrapers; verified search engines and logged-in users are exempt.
* **Malware Scanner:** Scans the local filesystem for webshells, backdoors and obfuscated code.
* **Signature Checks:** Compares core and plugin files with the official WordPress.org checksums.
* **File Integrity Monitoring (FIM):** Creates a baseline of all files to detect unauthorized modifications.
* **Smart Quarantine:** Isolates suspicious files with one-click restoration.
* **GDPR-Compliant:** Does not track legitimate website visitors. Telemetry is opt-in and restricted to blocked requests.

## Architecture

1. **Metzler Webshield (this plugin, GPLv2, distributed via WordPress.org):** All local protection. Works without an account.
2. **Metzler Webshield Pro (separate add-on):** Vulnerability intelligence and Pro dashboard integration. It hooks into this plugin through actions and filters; this plugin never downloads Pro code.
3. **Threat Intelligence API (`api.metzler-webshield.de`, proprietary service):** Only contacted after the administrator connects the site (free key) and, for telemetry, opts in. Connected sites sync the cloud WAF rules hourly; the API serves community keys a 7-day-delayed channel and Pro keys the real-time channel. See `readme.txt` → *External services*.

### Extension hooks

| Hook | Type | Purpose |
|---|---|---|
| `metzler_webshield_loaded` | action | Fired on `plugins_loaded` (priority 1) once all classes are loaded |
| `metzler_webshield_waf_rules` | filter | Replace/extend the WAF rule set (`category => regex[]`) |
| `metzler_webshield_scan_tasks` | filter | Add scan task types to the Smart Scan queue |
| `metzler_webshield_run_scan_task` | filter | Execute a custom task: `( null, $type, $payload )` → `array( 'complete' => bool, 'next_payload' => array, 'message' => string )` |
| `metzler_webshield_admin_tabs` | filter | Add dashboard tabs (`id => label`); render via `metzler_webshield_render_tab_{id}` |
| `metzler_webshield_settings_rows` | action | Output additional `<tr>` rows in the settings table |
| `metzler_webshield_license_card` | action | Output content at the top of the Threat Cloud tab |
| `metzler_webshield_ui_texts` | filter | Hero/widget texts (`hero_secure`, `hero_guards_active`, `tier_label`) |
| `metzler_webshield_is_pro` / `metzler_webshield_pro_active` | filter | Hide the upgrade banner / the "install Pro add-on" notice |
| `metzler_webshield_license_verified` / `metzler_webshield_license_removed` | action | Cloud connection changed |

## Building releases

`bin/build.sh` creates two ZIPs in `dist/`:

* `metzler-webshield-selfhosted.zip` – includes the self-hosted updater (`Update URI` → `api.metzler-webshield.de`). Publish it at `PLUGIN_DOWNLOAD_URL` of the API.
* `metzler-webshield-wporg.zip` – for WordPress.org: the updater file, the `Update URI` header and all `@selfhosted-start … @selfhosted-end` blocks are removed.

Once the plugin is live on WordPress.org, publish the wporg ZIP as the last self-hosted release; sites update to it and receive all further updates from WordPress.org.

## Installation

1. Upload the `metzler-webshield` folder to your `/wp-content/plugins/` directory.
2. Activate the plugin via the WordPress Admin panel. The firewall is enabled automatically.
3. Run the first Smart Scan from the Metzler Webshield dashboard.
4. Optional: connect the site in the *Threat Cloud* tab to share attack telemetry.

## License & Terms

The PHP source code of this WordPress plugin is licensed under the [GNU General Public License v2.0](LICENSE). 

**Note on API Usage:** The Metzler Webshield Threat Intelligence API is a proprietary service. Its use is optional and subject to the Metzler Webshield Terms of Service.

## Branding Guidelines

The "Metzler_Webshield" name and logo are the exclusive branding of Metzler Webseiten. If you choose to fork or distribute a modified version of this plugin, you must remove all Metzler_Webshield branding and logos.
