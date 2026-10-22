<?php
/**
 * Plugin Name: PHP Patch Check
 * Description: Shows notice if your PHP version is patched against CVE-2026-109618 / CVE-2026-109619.
 * Version: 1.0
 * Requires PHP: 8.2.35
 * License: GPL-2.0-or-later
 * Text Domain: php-patch-check
 * Domain Path: /languages
 * Author: Lars Ortlepp / larsactionhero.com
 */

defined( 'ABSPATH' ) || exit;

/**
 * minimum patched release per branch (PHP release of 2026-10-21):
 * 8.5.12, 8.4.27, 8.3.36, 8.2.35. PHP 8.1 and older receive no official fix.
 */
function ppc_patched_versions() {
	return array(
		'8.5' => 12,
		'8.4' => 27,
		'8.3' => 36,
		'8.2' => 35,
	);
}

/**
 * Pure check logic (no side effects, therefore testable).
 */
function ppc_check( $major, $minor, $release, $extra = '' ) {
	$branch = (int) $major . '.' . (int) $minor;
	$map    = ppc_patched_versions();

	if ( isset( $map[ $branch ] ) ) {
		if ( (int) $release < $map[ $branch ] ) {
			return false;
		}
		// pre-releases (dev/alpha/beta/RC) of the fix release do not count as patched.
		if ( (int) $release === $map[ $branch ] && preg_match( '/dev|alpha|beta|rc/i', (string) $extra ) ) {
			return false;
		}
		return true;
	}
	// newer than 8.5 = patched; 8.1 and older = not patched
	return version_compare( $branch, '8.5', '>' );
}

/**
 * reads ID / ID_LIKE from /etc/os-release (empty string if unreadable, e.g. open_basedir).
 */
function ppc_os_release_ids() {
	$content = @is_readable( '/etc/os-release' ) ? @file_get_contents( '/etc/os-release' ) : false;
	if ( ! is_string( $content ) ) {
		return '';
	}
	$ids = '';
	if ( preg_match_all( '/^(?:ID|ID_LIKE)=["\']?([^"\'\r\n]+)/mi', $content, $m ) ) {
		$ids = strtolower( implode( ' ', $m[1] ) );
	}
	return $ids;
}

/**
 * detects distribution packages (Debian, Ubuntu, RHEL family, SUSE, Remi/Sury ...).
 * These are often patched via backports without changing the version number.
 *
 * Detection (any match):
 * 1. Package suffix in the PHP version string (e.g. "-1~deb12u1", ".el9").
 * 2. Linux with a non-empty, non-prerelease suffix.
 * 3. System PHP binary (/usr/bin, /usr/sbin, /usr/lib - not /usr/local) on a known distribution
 *    (official Ubuntu packages, for example, show no suffix in the version string).
 */
function ppc_is_distro_build( $extra, $os_family = 'Linux', $binary = '', $os_ids = '' ) {
	$extra = (string) $extra;
	if ( preg_match( '/deb\d|ubuntu|\.?el\d|\.fc\d|rhel|centos|alma|rocky|suse|amzn|alpine|remi|sury/i', $extra ) ) {
		return true;
	}
	if ( 'Linux' !== $os_family ) {
		return false;
	}
	if ( '' !== trim( $extra ) && ! preg_match( '/^-?(dev|alpha|beta|rc)/i', $extra ) ) {
		return true;
	}
	$is_system_binary = (bool) preg_match( '#^/usr/(bin|sbin|lib)/#', (string) $binary );
	$is_known_distro  = (bool) preg_match( '/debian|ubuntu|rhel|centos|fedora|almalinux|rocky|suse|sles|amzn/', (string) $os_ids );
	return $is_system_binary && $is_known_distro;
}

function ppc_is_patched() {
	return ppc_check( PHP_MAJOR_VERSION, PHP_MINOR_VERSION, PHP_RELEASE_VERSION, PHP_EXTRA_VERSION );
}

/**
 * Loads the translations from /languages (php-patch-check-<locale>.mo).
 * English is the default (source strings); German is used for German locales.
 */
function ppc_load_textdomain() {
	load_plugin_textdomain( 'php-patch-check', false, dirname( plugin_basename( __FILE__ ) ) . '/languages' );
}
add_action( 'init', 'ppc_load_textdomain' );

function ppc_render_notice() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}

	$version = PHP_VERSION;
	$button  = '';

	if ( ppc_is_patched() ) {
		if ( current_user_can( 'delete_plugins' ) && ! ( defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS ) ) {
			$url    = wp_nonce_url( admin_url( 'admin-post.php?action=ppc_uninstall' ), 'ppc_uninstall' );
			$button = ' <a href="' . esc_url( $url ) . '" class="button button-primary" style="margin-left:10px;">' . esc_html__( 'Uninstall plugin', 'php-patch-check' ) . '</a>';
		}
		$class = 'notice-success';
		/* translators: %s: PHP version, e.g. 8.3.36 */
		$title = sprintf( __( 'PHP %s is patched.', 'php-patch-check' ), $version );
		$text  = __( 'Your server is protected against CVE-2026-109618 and CVE-2026-109619.', 'php-patch-check' );
	} elseif ( ppc_is_distro_build( PHP_EXTRA_VERSION, PHP_OS_FAMILY, PHP_BINARY, ppc_os_release_ids() ) ) {
		$class = 'notice-warning';
		/* translators: %s: PHP version, e.g. 8.3.6 */
		$title = sprintf( __( 'PHP %s: status cannot be determined reliably.', 'php-patch-check' ), $version );
		$text  = __( 'This PHP version most likely comes from the package manager of your server (e.g. Debian, Ubuntu or RHEL). Such packages are often patched without changing the version number, so your server may already be protected. Please ask your hosting provider whether the security updates of 21 October 2026 for CVE-2026-109618 and CVE-2026-109619 have been applied.', 'php-patch-check' );
	} else {
		$class = 'notice-error';
		/* translators: %s: PHP version, e.g. 8.1.30 */
		$title = sprintf( __( 'PHP %s is NOT patched.', 'php-patch-check' ), $version );
		$text  = __( 'Your hosting provider has not yet closed the vulnerabilities CVE-2026-109618 and CVE-2026-109619. Patched versions are PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35. Please contact your hosting provider or switch the PHP version.', 'php-patch-check' );
	}

	echo '<div class="notice ' . esc_attr( $class ) . '"><p><strong>' . esc_html( $title ) . '</strong> ' . esc_html( $text ) . $button . '</p></div>'; // phpcs:ignore WordPress.Security.EscapeOutput -- $button is escaped above.
}
add_action( 'admin_notices', 'ppc_render_notice' );
add_action( 'network_admin_notices', 'ppc_render_notice' );

function ppc_uninstall() {
	if ( ! current_user_can( 'delete_plugins' ) ) {
		wp_die( esc_html__( 'You do not have permission to do this.', 'php-patch-check' ), 403 );
	}
	check_admin_referer( 'ppc_uninstall' );

	require_once ABSPATH . 'wp-admin/includes/plugin.php';
	require_once ABSPATH . 'wp-admin/includes/file.php';

	$plugin = plugin_basename( __FILE__ );
	deactivate_plugins( $plugin, false, is_plugin_active_for_network( $plugin ) );
	delete_plugins( array( $plugin ) );

	wp_safe_redirect( admin_url( 'plugins.php' ) );
	exit;
}
add_action( 'admin_post_ppc_uninstall', 'ppc_uninstall' );
