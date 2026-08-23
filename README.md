# WPProtector

[![WordPress Version](https://img.shields.io/badge/WordPress-6.0%2B-blue.svg)](https://wordpress.org/)
[![PHP Version](https://img.shields.io/badge/PHP-7.4%2B-777bb4.svg)](https://php.net/)
[![License](https://img.shields.io/badge/License-GPLv2-green.svg)](https://www.gnu.org/licenses/gpl-2.0.html)

WPProtector is a lightweight security and Web Application Firewall (WAF) plugin for WordPress. It is designed to have minimal impact on server performance by utilizing a Must-Use (MU) plugin architecture and offloading threat intelligence to a centralized API.

## Features

* **Real-Time WAF:** Intercepts requests early in the WordPress boot process to block SQL Injection (SQLi), Cross-Site Scripting (XSS), and malicious bot traffic.
* **Malware Scanner:** Scans the local filesystem for known malware signatures, webshells, and backdoors.
* **File Integrity Monitoring (FIM):** Creates a baseline of WordPress core and plugin files to detect unauthorized modifications.
* **Smart Quarantine:** Isolates suspicious files into a secure sandbox with a one-click restoration option.
* **GDPR-Compliant:** Does not track legitimate website visitors. Threat telemetry is restricted to blocking data of active attackers (Art. 6(1)(f) GDPR).

## Architecture

To prevent database bloat and excessive server load, WPProtector operates on a split-logic model:

1. **The Plugin (GPLv2):** The local WordPress client handles request interception (via an MU-Plugin), local file scanning, and the native WordPress UI.
2. **The API (Proprietary Service):** Threat intelligence, IP blocklists, and malware signatures are maintained centrally on the WPProtector API (`api.wp-protector.de`). The plugin communicates with this API to receive the latest security definitions. 

## Installation

1. Upload the `wpprotector` folder to your `/wp-content/plugins/` directory.
2. Activate the plugin via the WordPress Admin panel.
3. Navigate to the WPProtector menu in the dashboard.
4. Request and verify a license key via your email address to enable the API connection.
5. The MU-Plugin will automatically be deployed to `/wp-content/mu-plugins/`.

## License & Terms

The PHP source code of this WordPress plugin is licensed under the [GNU General Public License v2.0](LICENSE). 

**Note on API Usage:** While the plugin code is open-source, the WPProtector Threat Intelligence API is a proprietary service. The use of the API, threat definitions, and network infrastructure is subject to the WPProtector Terms of Service. A valid license key is required to access the API.

## Branding Guidelines

The "WPProtector" name and logo are the exclusive branding of Metzler Webseiten. If you choose to fork or distribute a modified version of this plugin, you must remove all WPProtector branding and logos.
