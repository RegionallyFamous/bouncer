<?php
/**
 * Best-effort mutex for bouncer_pending_violations (db.php flush vs hook auditor processor).
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

if ( ! function_exists( 'bouncer_pending_violations_lock_acquire' ) ) {
	/**
	 * @return bool True if lock acquired.
	 */
	function bouncer_pending_violations_lock_acquire(): bool {
		if ( add_option( 'bouncer_pending_violations_lock', time(), '', false ) ) {
			return true;
		}
		$t = (int) get_option( 'bouncer_pending_violations_lock', 0 );
		if ( $t > 0 && ( time() - $t ) > 30 ) {
			delete_option( 'bouncer_pending_violations_lock' );
			return (bool) add_option( 'bouncer_pending_violations_lock', time(), '', false );
		}
		return false;
	}

	function bouncer_pending_violations_lock_release(): void {
		delete_option( 'bouncer_pending_violations_lock' );
	}
}
