<?php
/**
 * Rate limits expensive REST / admin scan actions (manifest + optional AI).
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

/**
 * Per-user per-minute token bucket using one transient per clock minute.
 */
class Bouncer_Rest_Scan_Limiter {

	/**
	 * @return bool True if the request may proceed.
	 */
	public static function allow(): bool {
		$uid = get_current_user_id();
		if ( $uid < 1 ) {
			return false;
		}

		$max = (int) apply_filters( 'bouncer_rest_scan_max_per_minute', 12 );
		$max = max( 1, min( 60, $max ) );

		$bucket = (int) floor( time() / 60 );
		$key    = 'bouncer_rl_scan_' . $uid . '_' . $bucket;
		$count  = (int) get_transient( $key );

		if ( $count >= $max ) {
			return false;
		}

		set_transient( $key, $count + 1, 120 );
		return true;
	}
}
