=== Patch Check for PHP ===
Contributors: larsactionhero
Tags: php, security, cve, patch, admin notice
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 7.4
Stable tag: 1.0.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Shows administrators whether the server's PHP version is patched against CVE-2026-109618 and CVE-2026-109619.

== Description ==

Patch Check for PHP displays a security-status notice to administrators in the WordPress admin area. It compares the PHP version your server is running with the patched releases published on 21 October 2026 for CVE-2026-109618 and CVE-2026-109619.

The notice shows one of three statuses:

* **Patched** – the PHP version meets the patched-version threshold.
* **Status unclear** – the version is below the threshold, but PHP appears to come from a distribution package (Debian, Ubuntu, RHEL, etc.). Such packages are often patched via backports without a version change. Ask your hosting provider whether the security updates of 21 October 2026 have been applied.
* **Not patched** – the version is below the threshold and no distribution build was detected. Contact your hosting provider or switch PHP versions.

**Patched versions**

* PHP 8.5: 8.5.12
* PHP 8.4: 8.4.27
* PHP 8.3: 8.3.36
* PHP 8.2: 8.2.35
* PHP 8.1 and older: no official fix listed (end of life)

Newer PHP branches count as patched.

When the server is patched, the notice offers a button to remove the plugin, since it is no longer needed.

= Privacy =

The plugin does not collect, store or transmit any data. All checks run locally on your server. It does not contact external services.

= Source code =

Development takes place on [GitHub](https://github.com/larsactionhero/php-patch-check). Plugin page: [larsactionhero.com](https://www.larsactionhero.com/git/php-patch-check/).

== Installation ==

1. Upload the plugin folder to `/wp-content/plugins/`, or install it via **Plugins → Add New Plugin**.
2. Activate the plugin through the **Plugins** screen.
3. The status notice appears in the admin area for users with the `manage_options` capability.

== Frequently Asked Questions ==

= Who can see the notice? =

Only users with the `manage_options` capability (administrators; super admins in the network admin).

= My server shows "Status unclear". What should I do? =

Ask your hosting provider whether the security updates of 21 October 2026 for CVE-2026-109618 and CVE-2026-109619 have been applied to your PHP build.

= Does the plugin work on unpatched PHP versions? =

Yes. It runs on PHP 7.4 and newer, so it can warn you precisely when your PHP is outdated.

= Does the plugin send data anywhere? =

No.

== Changelog ==

= 1.0.0 =
* Initial release for the WordPress Plugin Directory.
* Renamed function prefix to `phppatchcheck_`.
* Lowered "Requires PHP" to 7.4 so the plugin can be activated on unpatched servers.
* Added readme.txt, LICENSE and .distignore.
* Success notice is now dismissible.

== Upgrade Notice ==

= 1.0.0 =
Initial release.
