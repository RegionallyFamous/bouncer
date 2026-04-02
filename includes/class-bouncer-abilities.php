<?php
/**
 * WordPress Abilities API integration when available (core 6.9+).
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

/**
 * Registers readonly abilities for site security posture.
 */
class Bouncer_Abilities {

	public static function init(): void {
		add_action( 'wp_abilities_api_init', array( __CLASS__, 'register_abilities' ) );
	}

	public static function register_abilities(): void {
		if ( ! function_exists( 'wp_register_ability' ) ) {
			return;
		}

		try {
			wp_register_ability(
				'bouncer/site-status',
				array(
					'label'               => __( 'Bouncer site status', 'bouncer' ),
					'description'         => __( 'Returns Bouncer operating mode and database drop-in flags.', 'bouncer' ),
					'execute_callback'    => array( __CLASS__, 'execute_status' ),
					'permission_callback' => array( __CLASS__, 'permission_status' ),
				)
			);
		} catch ( \Throwable $e ) {
			if ( defined( 'WP_DEBUG' ) && WP_DEBUG ) {
				// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
				error_log( 'Bouncer Abilities registration skipped: ' . $e->getMessage() );
			}
		}
	}

	/**
	 * @param mixed ...$args Ignored; core may pass input.
	 * @return array<string, string>
	 */
	public static function execute_status( ...$args ): array {
		unset( $args );
		return array(
			'mode'                 => (string) get_option( 'bouncer_mode', 'monitor' ),
			'db_dropin_installed'  => get_option( 'bouncer_db_dropin_installed' ) ? 'yes' : 'no',
			'db_dropin_conflict'   => get_option( 'bouncer_db_dropin_conflict' ) ? 'yes' : 'no',
		);
	}

	/**
	 * @param mixed ...$args Ignored; core may pass request context.
	 */
	public static function permission_status( ...$args ): bool {
		unset( $args );
		return current_user_can( BOUNCER_CAP );
	}
}
