# Metzler Webshield

[![WordPress Version](https://img.shields.io/badge/WordPress-6.0%2B-blue.svg)](https://wordpress.org/)
[![PHP Version](https://img.shields.io/badge/PHP-7.4%2B-777bb4.svg)](https://php.net/)
[![License](https://img.shields.io/badge/License-GPLv2-green.svg)](https://www.gnu.org/licenses/gpl-2.0.html)

Metzler Webshield is a lightweight security plugin and Web Application Firewall (WAF) for WordPress.

## Features

* **Web Application Firewall:** Blocks SQL injection, cross-site scripting (XSS), path traversal and malicious bots.
* **Rate Limiting:** Throttles floods and scrapers; verified search engines and logged-in users are exempt.
* **Malware Scanner:** Finds webshells, backdoors and obfuscated code.
* **Checksum Verification:** Compares WordPress core and plugin files with the official WordPress.org checksums.
* **File Integrity Monitoring:** Detects new and modified files and reports every new plugin or theme installation.
* **Hardening Checks:** Reports hidden administrators and non-admin users or roles that can install or edit code.
* **Quarantine:** Isolates suspicious files with one-click restore.
* **Analysis Lab (optional):** Send a reported file for analysis and get the result by email; unknown plugin and theme files can be sent once or automatically.
* **Privacy-friendly:** Legitimate visitors are not tracked. All protection features work locally without an account; the analysis lab needs a free Threat Cloud key.

## Installation

1. Upload the `metzler-webshield` folder to `/wp-content/plugins/`.
2. Activate the plugin in the WordPress admin. The firewall is enabled automatically.
3. Run the first scan from the Metzler Webshield dashboard.

## Developer hooks

| Hook | Type | Purpose |
|---|---|---|
| `metzler_webshield_loaded` | action | Fired on `plugins_loaded` (priority 1) once all classes are loaded |
| `metzler_webshield_waf_rules` | filter | Replace or extend the WAF rule set (`category => regex[]`) |
| `metzler_webshield_scan_tasks` | filter | Add scan task types to the scan queue |
| `metzler_webshield_run_scan_task` | filter | Execute a custom task: `( null, $type, $payload )` → `array( 'complete' => bool, 'next_payload' => array, 'message' => string )` |
| `metzler_webshield_admin_tabs` | filter | Add dashboard tabs (`id => label`); render via `metzler_webshield_render_tab_{id}` |
| `metzler_webshield_settings_rows` | action | Output additional `<tr>` rows in the settings table |
| `metzler_webshield_trusted_proxies` | filter | Proxies with public IPs whose forwarded client IPs are trusted |

## Tests

`tests/e2e/run.sh` needs only Docker. It installs WordPress with 25 popular plugins, scans the clean site (every warning or error is a false positive), then plants the inert samples from `tests/e2e/samples/` and checks that each one is reported. It also checks what the telemetry, lab and lookup requests would send, with the HTTP layer stubbed out. The same test runs on GitHub Actions.

## License

The plugin is licensed under the [GNU General Public License v2.0](LICENSE). The optional Threat Intelligence service is not part of this repository; see `readme.txt` → *External services*.

The "Metzler Webshield" name and logo belong to Metzler Webseiten. Forks and modified versions must not use them.
