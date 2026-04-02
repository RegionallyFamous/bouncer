<?php
/**
 * Loaded only when PHP is below Bouncer’s minimum (8.1).
 * Keep syntax compatible with older WordPress-supported PHP (7.0+).
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

/**
 * Stop activation on unsupported PHP with a clear message.
 */
function bouncer_abort_activation_low_php() {
	if ( ! function_exists( 'deactivate_plugins' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}
	$file = defined( 'BOUNCER_PLUGIN_FILE' ) ? BOUNCER_PLUGIN_FILE : __FILE__;
	deactivate_plugins( plugin_basename( $file ), true );
	wp_die(
		wp_kses_post(
			sprintf(
				/* translators: %s: PHP version number. */
				__( 'Bouncer requires PHP 8.1 or newer. This server is running PHP %s.', 'bouncer' ),
				PHP_VERSION
			)
		),
		esc_html__( 'Plugin could not be activated', 'bouncer' ),
		array(
			'response'  => 200,
			'back_link' => true,
		)
	);
}

/**
 * Admin notice when the main plugin file exited early due to PHP version.
 */
function bouncer_admin_notice_low_php() {
	if ( ! current_user_can( 'activate_plugins' ) ) {
		return;
	}
	echo '<div class="notice notice-error"><p>';
	echo wp_kses_post(
		sprintf(
			/* translators: %s: PHP version number. */
			__( 'Bouncer requires PHP 8.1 or newer. This site is running PHP %s.', 'bouncer' ),
			PHP_VERSION
		)
	);
	echo '</p></div>';
}
