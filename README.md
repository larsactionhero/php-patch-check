# php-patch-check
A WordPress plugin that displays a PHP security-status notice to administrators on every WordPress admin page. It checks whether the server’s PHP version is patched against <a href="https://www.cve.org/CVERecord?id=CVE-2026-109618" target="_blank">CVE-2026-109618</a> / <a href="https://www.cve.org/CVERecord?id=CVE-2026-109619" target="_blank">CVE-2026-109619</a>

## Status messages

The plugin displays one of three statuses:

- **Patched** — The PHP version meets the listed patched-version threshold.
- **Status unclear** — The version is below the threshold, but may have been patched by the server’s package manager without a version-number change. Ask your hosting provider whether the security updates of **October 21, 2026** have been applied.
- **Not patched** — The version is below the threshold and is not identified as patched. Contact your hosting provider or switch PHP versions.

## Patched versions

| PHP branch | Patched from |
|---|---:|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |
| 8.1 and older | No official fix listed; end of life |

Newer PHP branches count as patched. Package-managed PHP builds, such as those from Debian, Ubuntu, or RHEL, may include security fixes without changing the version number, so their status may be unclear.

## Installation

1. Download the plugin ZIP file.
2. In WordPress, go to **Plugins → Add New Plugin → Upload Plugin**.
3. Upload the ZIP and install the plugin.

## Source

[PHP Patch Check – plugin page](https://www.larsactionhero.com/git/php-patch-check/)