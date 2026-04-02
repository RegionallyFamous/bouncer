<?php
/**
 * Webhook delivery (HMAC-signed) and optional email digests.
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

/**
 * Queues outbound notifications without blocking the request.
 */
class Bouncer_Notifications {

	/** @var array<int, array<string, mixed>> */
	private static array $webhook_queue = array();

	public static function init(): void {
		add_action( 'bouncer_event_recorded', array( __CLASS__, 'queue_webhook_row' ), 10, 1 );
		add_action( 'shutdown', array( __CLASS__, 'flush_webhook_queue' ), 30 );
		add_action( 'bouncer_event_digest', array( __CLASS__, 'send_digest_email' ) );
		add_action( 'update_option_bouncer_digest_enabled', array( __CLASS__, 'on_digest_toggle' ), 10, 3 );
		add_action( 'update_option_bouncer_digest_frequency', array( __CLASS__, 'on_digest_frequency' ), 10, 3 );
	}

	/**
	 * @param mixed $old Old value.
	 * @param mixed $val New value.
	 */
	public static function on_digest_toggle( $old, $val ): void {
		unset( $old, $val );
		self::sync_digest_schedule();
	}

	/**
	 * @param mixed $old Old value.
	 * @param mixed $val New value.
	 */
	public static function on_digest_frequency( $old, $val ): void {
		unset( $old, $val );
		self::sync_digest_schedule();
	}

	public static function sync_digest_schedule(): void {
		wp_clear_scheduled_hook( 'bouncer_event_digest' );
		if ( ! get_option( 'bouncer_digest_enabled' ) ) {
			return;
		}
		$freq = get_option( 'bouncer_digest_frequency', 'daily' );
		$rec  = 'weekly' === $freq ? 'weekly' : 'daily';
		wp_schedule_event( time() + HOUR_IN_SECONDS, $rec, 'bouncer_event_digest' );
	}

	/**
	 * @param array<string, mixed> $row Buffered event row.
	 */
	public static function queue_webhook_row( array $row ): void {
		$url = trim( (string) get_option( 'bouncer_webhook_url', '' ) );
		if ( '' === $url || ! wp_http_validate_url( $url ) ) {
			return;
		}
		if ( ! apply_filters( 'bouncer_webhook_skip_url_safety', false, $url )
			&& ! Bouncer_Url_Safety::is_safe_remote_http_url( $url ) ) {
			return;
		}

		$min = (string) get_option( 'bouncer_webhook_min_severity', 'warning' );
		$rank = array( 'info' => 0, 'warning' => 1, 'critical' => 2, 'emergency' => 3 );
		$sev = isset( $row['severity'] ) ? (string) $row['severity'] : 'info';
		if ( ( $rank[ $sev ] ?? 0 ) < ( $rank[ $min ] ?? 1 ) ) {
			return;
		}

		self::$webhook_queue[] = $row;
	}

	public static function flush_webhook_queue(): void {
		if ( empty( self::$webhook_queue ) ) {
			return;
		}

		$url = trim( (string) get_option( 'bouncer_webhook_url', '' ) );
		if ( '' === $url || ! wp_http_validate_url( $url ) ) {
			self::$webhook_queue = array();
			return;
		}
		if ( ! apply_filters( 'bouncer_webhook_skip_url_safety', false, $url )
			&& ! Bouncer_Url_Safety::is_safe_remote_http_url( $url ) ) {
			self::$webhook_queue = array();
			return;
		}

		$secret = (string) get_option( 'bouncer_webhook_secret', '' );
		$body   = wp_json_encode(
			array(
				'site'   => home_url( '/' ),
				'events' => self::$webhook_queue,
				'sent_at'=> gmdate( 'c' ),
			),
			JSON_UNESCAPED_SLASHES
		);

		$headers = array(
			'Content-Type' => 'application/json; charset=utf-8',
		);
		if ( '' !== $secret ) {
			$headers['X-Bouncer-Signature'] = hash_hmac( 'sha256', (string) $body, $secret );
		}

		wp_remote_post(
			$url,
			array(
				'timeout' => 8,
				'body'    => $body,
				'headers' => $headers,
			)
		);

		self::$webhook_queue = array();
	}

	public static function send_digest_email(): void {
		if ( ! get_option( 'bouncer_digest_enabled' ) ) {
			return;
		}

		$to = sanitize_email( (string) get_option( 'bouncer_notify_email', get_option( 'admin_email' ) ) );
		if ( ! is_email( $to ) ) {
			return;
		}

		$logger = Bouncer::get_instance()->logger;
		$counts = $logger->get_severity_counts( 'weekly' === get_option( 'bouncer_digest_frequency', 'daily' ) ? 7 : 1 );

		$total = array_sum( $counts );
		if ( $total < 1 ) {
			return;
		}

		$subject = sprintf(
			/* translators: %s: site hostname */
			__( '[Bouncer] Event digest for %s', 'bouncer' ),
			wp_parse_url( home_url(), PHP_URL_HOST ) ?: 'WordPress'
		);

		$lines = array(
			__( 'Bouncer event summary:', 'bouncer' ),
			'',
			sprintf( "info: %d", $counts['info'] ),
			sprintf( "warning: %d", $counts['warning'] ),
			sprintf( "critical: %d", $counts['critical'] ),
			sprintf( "emergency: %d", $counts['emergency'] ),
			'',
			__( 'View the dashboard:', 'bouncer' ) . ' ' . bouncer_admin_url(),
		);

		wp_mail( $to, $subject, implode( "\n", $lines ) );
	}
}
