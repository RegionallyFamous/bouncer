<?php
/**
 * SSRF mitigation for admin-configured outbound URLs (webhooks, model download).
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

/**
 * Rejects URLs whose host resolves to non-public IP space (RFC1918, loopback, link-local, metadata).
 */
class Bouncer_Url_Safety {

	/**
	 * Whether the URL is http(s) and resolves only to “public” addresses.
	 *
	 * @param string $url Raw URL.
	 * @return bool
	 */
	public static function is_safe_remote_http_url( string $url ): bool {
		$url = trim( $url );
		if ( '' === $url || ! wp_http_validate_url( $url ) ) {
			return false;
		}

		$parsed = wp_parse_url( $url );
		if ( ! is_array( $parsed ) || empty( $parsed['host'] ) ) {
			return false;
		}

		$scheme = isset( $parsed['scheme'] ) ? strtolower( (string) $parsed['scheme'] ) : '';
		if ( ! in_array( $scheme, array( 'http', 'https' ), true ) ) {
			return false;
		}

		$host = strtolower( (string) $parsed['host'] );

		/**
		 * Short-circuit: block obvious metadata / local hostnames.
		 *
		 * @param bool   $reject Whether to reject.
		 * @param string $host   Hostname or bracketed IPv6.
		 */
		if ( apply_filters( 'bouncer_url_safety_reject_host', self::is_blocked_hostname( $host ), $host ) ) {
			return false;
		}

		// Strip IPv6 brackets.
		if ( str_starts_with( $host, '[' ) && str_ends_with( $host, ']' ) ) {
			$host = substr( $host, 1, -1 );
		}

		if ( filter_var( $host, FILTER_VALIDATE_IP ) ) {
			return self::is_public_ip( $host );
		}

		$ips = @gethostbynamel( $host ); // phpcs:ignore WordPress.PHP.NoSilencedErrors
		if ( ! is_array( $ips ) || array() === $ips ) {
			return (bool) apply_filters( 'bouncer_url_safety_allow_unresolvable_host', false, $host );
		}

		foreach ( $ips as $ip ) {
			if ( ! self::is_public_ip( $ip ) ) {
				return false;
			}
		}

		return true;
	}

	/**
	 * @param string $host Lowercase hostname (not IPv6 bracketed).
	 */
	private static function is_blocked_hostname( string $host ): bool {
		$blocked = array(
			'localhost',
			'metadata.google.internal',
			'metadata',
		);
		if ( in_array( $host, $blocked, true ) ) {
			return true;
		}
		if ( str_starts_with( $host, '127.' ) ) {
			return true;
		}
		return false;
	}

	/**
	 * True if the address is globally routable (not private, reserved, loopback, link-local).
	 */
	private static function is_public_ip( string $ip ): bool {
		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ) ) {
			return (bool) filter_var(
				$ip,
				FILTER_VALIDATE_IP,
				FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
			);
		}

		if ( filter_var( $ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ) ) {
			return (bool) filter_var(
				$ip,
				FILTER_VALIDATE_IP,
				FILTER_FLAG_IPV6 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
			);
		}

		return false;
	}
}
