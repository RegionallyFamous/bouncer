<?php
/**
 * REST API monitoring (unauthenticated write attempts).
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

/**
 * Logs potentially risky REST traffic for review.
 */
class Bouncer_Rest_Monitor {

	private Bouncer_Logger $logger;

	public function __construct( Bouncer_Logger $logger ) {
		$this->logger = $logger;
	}

	public function init(): void {
		add_filter( 'rest_pre_dispatch', array( $this, 'pre_dispatch' ), 5, 3 );
	}

	/**
	 * @param mixed           $result  Response to replace the normal response, or null.
	 * @param WP_REST_Server  $server  REST server.
	 * @param WP_REST_Request $request Request used to generate the response.
	 * @return mixed
	 */
	public function pre_dispatch( $result, $server, $request ) {
		unset( $server );
		if ( ! get_option( 'bouncer_rest_monitoring', true ) ) {
			return $result;
		}

		if ( ! $request instanceof WP_REST_Request ) {
			return $result;
		}

		$method = strtoupper( $request->get_method() );
		if ( ! in_array( $method, array( 'POST', 'PUT', 'PATCH', 'DELETE' ), true ) ) {
			return $result;
		}

		if ( is_user_logged_in() ) {
			return $result;
		}

		$route = $request->get_route();
		if ( '' === $route ) {
			return $result;
		}

		$this->logger->log(
			Bouncer_Logger::SEVERITY_WARNING,
			Bouncer_Logger::CHANNEL_REST,
			'',
			'rest_unauthenticated_write',
			sprintf(
				/* translators: 1: HTTP method, 2: REST route */
				__( 'Unauthenticated %1$s to %2$s', 'bouncer' ),
				$method,
				$route
			),
			array(
				'method' => $method,
				'route'  => $route,
			)
		);

		return $result;
	}
}
