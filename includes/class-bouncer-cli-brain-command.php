<?php
/**
 * WP-CLI: Bouncer Brain helper file.
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

/**
 * @phpstan-ignore-next-line
 */
class Bouncer_CLI_Brain_Command extends WP_CLI_Command {

	/**
	 * Assert a user with manage_bouncer is loaded (use --user=1, etc.).
	 */
	private function assert_can_manage(): void {
		if ( ! function_exists( 'wp_get_current_user' ) ) {
			\WP_CLI::error( 'WordPress is not loaded.' );
		}
		$user = wp_get_current_user();
		if ( ! $user || ! $user->ID ) {
			\WP_CLI::error( 'Specify a user with the manage_bouncer capability, e.g. --user=1' );
		}
		if ( ! current_user_can( BOUNCER_CAP ) ) {
			\WP_CLI::error( 'The selected user cannot manage Bouncer. Try a different --user= value.' );
		}
	}

	/**
	 * Download the optional on-server Bouncer Brain helper file into uploads.
	 *
	 * ## OPTIONS
	 *
	 * [--force]
	 * : Download even if a file already exists (replaces managed path file).
	 */
	public function download( $args, $assoc_args ) {
		unset( $args );
		$this->assert_can_manage();
		$force = ! empty( $assoc_args['force'] );
		\WP_CLI::log( __( 'Downloading Bouncer Brain helper file…', 'bouncer' ) );
		$result = Bouncer_Brain_Model::download( $force );
		if ( ! $result['success'] ) {
			\WP_CLI::error( $result['message'] );
		}
		if ( '' !== $result['path'] ) {
			\WP_CLI::log( $result['path'] );
		}
		\WP_CLI::success( $result['message'] );
	}
}
