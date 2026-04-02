<?php
/**
 * Plugin Name: Bouncer
 * Plugin URI: https://regionallyfamous.com/bouncer
 * Description: A plugin behavior firewall for WordPress. Monitors what your plugins actually do — database queries, outbound HTTP, hook registrations, file changes — and uses AI to catch threats before they cause damage.
 * Version: 1.0.7
 * Requires at least: 7.0
 * Requires PHP: 8.1
 * Author: Regionally Famous
 * Author URI: https://regionallyfamous.com
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Text Domain: bouncer
 * Domain Path: /languages
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

// Everything below this gate uses PHP 8.1+ syntax; skip parsing it on older runtimes.
if ( version_compare( PHP_VERSION, '8.1', '<' ) ) {
	if ( ! defined( 'BOUNCER_PLUGIN_FILE' ) ) {
		define( 'BOUNCER_PLUGIN_FILE', __FILE__ );
	}
	require_once plugin_dir_path( __FILE__ ) . 'includes/bouncer-php-requirement.php';
	register_activation_hook( __FILE__, 'bouncer_abort_activation_low_php' );
	add_action( 'admin_notices', 'bouncer_admin_notice_low_php' );
	return;
}

/**
 * Whether the site meets Bouncer’s WordPress minimum (7.0), including 7.0 betas/RCs.
 *
 * Raw `version_compare( $wp_version, '7.0' )` treats `7.0-RC2` as below `7.0`; core’s
 * `is_wp_version_compatible()` handles pre-releases correctly.
 *
 * @return bool
 */
function bouncer_meets_minimum_wp(): bool {
	if ( function_exists( 'is_wp_version_compatible' ) ) {
		return is_wp_version_compatible( '7.0' );
	}

	global $wp_version;
	if ( ! isset( $wp_version ) || ! is_string( $wp_version ) ) {
		return false;
	}

	if ( ! preg_match( '/^(\d+\.\d+(?:\.\d+)?)/', $wp_version, $matches ) ) {
		return false;
	}

	return version_compare( $matches[1], '7.0', '>=' );
}

if ( ! bouncer_meets_minimum_wp() ) {
	if ( ! defined( 'BOUNCER_PLUGIN_FILE' ) ) {
		define( 'BOUNCER_PLUGIN_FILE', __FILE__ );
	}
	require_once plugin_dir_path( __FILE__ ) . 'includes/bouncer-wp-requirement.php';
	register_activation_hook( __FILE__, 'bouncer_abort_activation_low_wp' );
	add_action( 'admin_notices', 'bouncer_admin_notice_low_wp' );
	return;
}

define( 'BOUNCER_VERSION', '1.0.7' );
define( 'BOUNCER_PLUGIN_FILE', __FILE__ );
define( 'BOUNCER_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );
define( 'BOUNCER_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'BOUNCER_PLUGIN_BASENAME', plugin_basename( __FILE__ ) );
/** Capability for Bouncer admin, REST, and AJAX (mirrors core-style dedicated caps). */
define( 'BOUNCER_CAP', 'manage_bouncer' );

require_once BOUNCER_PLUGIN_DIR . 'includes/bouncer-pending-violations-lock.php';

/**
 * Whether the current user may use Bouncer (dedicated cap, with manage_options fallback).
 *
 * @return bool
 */
function bouncer_current_user_can_manage() {
	return current_user_can( BOUNCER_CAP );
}

/**
 * @param string              $tab  Screen tab: dashboard|events|manifests|settings.
 * @param array<string,mixed> $args Extra query arguments (merged; may override tab).
 * @return string Full URL to a Bouncer screen under Tools.
 */
function bouncer_admin_url( string $tab = 'dashboard', array $args = array() ): string {
	$query = array_merge(
		array( 'page' => 'bouncer' ),
		'dashboard' === $tab ? array() : array( 'tab' => $tab ),
		$args
	);
	return add_query_arg( $query, admin_url( 'tools.php' ) );
}

/**
 * Users with manage_options may use Bouncer; custom roles can hold manage_bouncer alone.
 *
 * Parameters intentionally untyped so a bad filter cannot trigger TypeError on PHP 8+.
 *
 * @param mixed $allcaps All capabilities for the user.
 * @param mixed $caps    Requested capabilities.
 * @param mixed $args    Capability check arguments.
 * @param mixed $user    User object.
 * @return mixed
 */
function bouncer_map_capabilities_to_manage_bouncer( $allcaps, $caps, $args, $user ) { // phpcs:ignore WordPress.WP.Capabilities.Unknown
	if ( ! is_array( $allcaps ) ) {
		return $allcaps;
	}
	if ( ! is_array( $caps ) || ! in_array( BOUNCER_CAP, $caps, true ) ) {
		return $allcaps;
	}
	if ( ! empty( $allcaps['manage_options'] ) ) {
		$allcaps[ BOUNCER_CAP ] = true;
	}
	return $allcaps;
}
add_filter( 'user_has_cap', 'bouncer_map_capabilities_to_manage_bouncer', 10, 4 );

/**
 * Grant manage_bouncer to Administrators once (covers upgrades without re-activation).
 */
function bouncer_ensure_capabilities(): void {
	$rev = (int) get_option( 'bouncer_cap_revision', 0 );
	if ( $rev >= 1 ) {
		return;
	}
	$role = get_role( 'administrator' );
	if ( $role && ! $role->has_cap( BOUNCER_CAP ) ) {
		$role->add_cap( BOUNCER_CAP );
	}
	update_option( 'bouncer_cap_revision', 1 );
}
add_action( 'init', 'bouncer_ensure_capabilities', 5 );

/**
 * Autoloader for Bouncer classes.
 *
 * @param string $class_name The class name to load.
 */
function bouncer_autoloader( $class_name ) {
	if ( 'Bouncer' === $class_name ) {
		require_once BOUNCER_PLUGIN_DIR . 'includes/class-bouncer.php';
		return;
	}

	if ( 0 !== strpos( $class_name, 'Bouncer_' ) ) {
		return;
	}

	$file = 'class-' . strtolower( str_replace( '_', '-', $class_name ) ) . '.php';
	$path = BOUNCER_PLUGIN_DIR . 'includes/' . $file;

	if ( file_exists( $path ) ) {
		require_once $path;
	}
}
spl_autoload_register( 'bouncer_autoloader' );

/**
 * Load translations on init (WP 6.7+ requires text domains at init or later).
 */
function bouncer_load_textdomain() {
	load_plugin_textdomain( 'bouncer', false, dirname( BOUNCER_PLUGIN_BASENAME ) . '/languages' );
}
add_action( 'init', 'bouncer_load_textdomain', 0 );

/**
 * Log a caught exception/error (respects WP_DEBUG for stack traces).
 *
 * @param string    $context Short label, e.g. "activation".
 * @param Throwable $e     The error.
 */
function bouncer_log_throwable( string $context, \Throwable $e ): void {
	$msg = 'Bouncer ' . $context . ': ' . $e->getMessage();
	if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		error_log( $msg . "\n" . $e->getTraceAsString() );
	} else {
		// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
		error_log( $msg );
	}
}

/**
 * Plugin activation handler.
 */
function bouncer_activate() {
	try {
		require_once BOUNCER_PLUGIN_DIR . 'includes/class-bouncer-activator.php';
		Bouncer_Activator::activate();
	} catch ( \Throwable $e ) {
		bouncer_log_throwable( 'activation', $e );
		set_transient( 'bouncer_activation_error', wp_strip_all_tags( $e->getMessage() ), 5 * MINUTE_IN_SECONDS );
		if ( ! function_exists( 'deactivate_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		deactivate_plugins( plugin_basename( BOUNCER_PLUGIN_FILE ), true );
		wp_die(
			'<p>' . esc_html( wp_strip_all_tags( $e->getMessage() ) ) . '</p>',
			esc_html__( 'Plugin could not be activated', 'bouncer' ),
			array(
				'response'  => 500,
				'back_link' => true,
			)
		);
	}
}
register_activation_hook( __FILE__, 'bouncer_activate' );

/**
 * Plugin deactivation handler.
 */
function bouncer_deactivate() {
	try {
		require_once BOUNCER_PLUGIN_DIR . 'includes/class-bouncer-activator.php';
		Bouncer_Activator::deactivate();
	} catch ( \Throwable $e ) {
		bouncer_log_throwable( 'deactivation', $e );
	}
}
register_deactivation_hook( __FILE__, 'bouncer_deactivate' );

/**
 * Show a one-time admin notice if an activation error transient remains (edge cases).
 */
function bouncer_maybe_show_activation_error_notice(): void {
	if ( ! current_user_can( 'activate_plugins' ) ) {
		return;
	}
	$msg = get_transient( 'bouncer_activation_error' );
	if ( ! is_string( $msg ) || '' === $msg ) {
		return;
	}
	delete_transient( 'bouncer_activation_error' );
	echo '<div class="notice notice-error is-dismissible"><p><strong>' . esc_html__( 'Bouncer', 'bouncer' ) . ':</strong> ';
	echo esc_html( $msg );
	echo '</p></div>';
}
add_action( 'admin_notices', 'bouncer_maybe_show_activation_error_notice', 5 );

/**
 * Admin notice after a runtime init failure.
 */
function bouncer_render_init_error_notice(): void {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}
	$msg = get_transient( 'bouncer_init_error' );
	if ( ! is_string( $msg ) || '' === $msg ) {
		return;
	}
	delete_transient( 'bouncer_init_error' );
	echo '<div class="notice notice-error is-dismissible"><p><strong>' . esc_html__( 'Bouncer', 'bouncer' ) . ':</strong> ';
	echo esc_html( $msg );
	echo ' ' . esc_html__( 'Check debug.log for details if WP_DEBUG is enabled.', 'bouncer' );
	echo '</p></div>';
}

/**
 * Initialize the plugin.
 */
function bouncer_init() {
	try {
		$bouncer = Bouncer::get_instance();
		$bouncer->init();
	} catch ( \Throwable $e ) {
		bouncer_log_throwable( 'init', $e );
		set_transient( 'bouncer_init_error', wp_strip_all_tags( $e->getMessage() ), 5 * MINUTE_IN_SECONDS );
		add_action( 'admin_notices', 'bouncer_render_init_error_notice', 1 );
	}
}
add_action( 'plugins_loaded', 'bouncer_init', 5 );

if ( defined( 'WP_CLI' ) && WP_CLI ) {
	require_once BOUNCER_PLUGIN_DIR . 'includes/class-bouncer-cli.php';
	WP_CLI::add_command( 'bouncer', 'Bouncer_CLI_Command' );
}
