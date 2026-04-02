<?php
/**
 * Loaded only when WordPress is below Bouncer’s minimum (7.0).
 * Keep syntax compatible with the host WordPress-supported PHP version.
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

/**
 * Stop activation on unsupported WordPress with a clear message.
 */
function bouncer_abort_activation_low_wp() {
	if ( ! function_exists( 'deactivate_plugins' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}
	global $wp_version;
	$running_wp = isset( $wp_version ) ? $wp_version : '0';
	$file       = defined( 'BOUNCER_PLUGIN_FILE' ) ? BOUNCER_PLUGIN_FILE : __FILE__;
	deactivate_plugins( plugin_basename( $file ), true );
	wp_die(
		wp_kses_post(
			sprintf(
				/* translators: %s: WordPress version number running on the site. */
				__( 'Bouncer requires WordPress 7.0 or newer. This site is running WordPress %s.', 'bouncer' ),
				esc_html( $running_wp )
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
 * Admin notice when the main plugin file exited early due to WordPress version.
 */
function bouncer_admin_notice_low_wp() {
	if ( ! current_user_can( 'activate_plugins' ) ) {
		return;
	}
	global $wp_version;
	$running_wp = isset( $wp_version ) ? $wp_version : '0';
	echo '<div class="notice notice-error"><p>';
	echo wp_kses_post(
		sprintf(
			/* translators: %s: WordPress version number running on the site. */
			__( 'Bouncer requires WordPress 7.0 or newer. This site is running WordPress %s. Upgrade WordPress or deactivate Bouncer.', 'bouncer' ),
			'<strong>' . esc_html( $running_wp ) . '</strong>'
		)
	);
	echo '</p></div>';
}
