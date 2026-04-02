<?php
/**
 * User-facing Quick Look copy helpers (plain language, no jargon in returned strings).
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

/**
 * Plain-language summaries for plugin checks (no jargon in returned strings).
 */
class Bouncer_AI_Experience {

	public const TRAFFIC_CALM   = 'calm';
	public const TRAFFIC_WATCH = 'watch';
	public const TRAFFIC_ALERT = 'alert';

	/**
	 * One-line verdict from risk score only (e.g. manifest list table).
	 */
	public static function headline_for_score( int $score ): string {
		if ( $score <= 20 ) {
			return __( 'Nothing spicy detected — routine footprint.', 'bouncer' );
		}
		if ( $score <= 50 ) {
			return __( 'Mostly fine — worth a quick skim.', 'bouncer' );
		}
		if ( $score <= 80 ) {
			return __( 'Heads up — a few sharp edges here.', 'bouncer' );
		}
		return __( 'Red-flag territory — take a close look.', 'bouncer' );
	}

	/**
	 * Traffic-light bucket for styling.
	 */
	public static function traffic_for_score( int $score ): string {
		if ( $score <= 20 ) {
			return self::TRAFFIC_CALM;
		}
		if ( $score <= 50 ) {
			return self::TRAFFIC_WATCH;
		}
		if ( $score <= 80 ) {
			return self::TRAFFIC_WATCH;
		}
		return self::TRAFFIC_ALERT;
	}

	/**
	 * Risk score explained in one short sentence for humans.
	 */
	public static function score_sentence( int $score ): string {
		if ( $score <= 20 ) {
			return __( 'Risk looks low based on what Bouncer saw in the structure check.', 'bouncer' );
		}
		if ( $score <= 50 ) {
			return __( 'Risk is medium — a mix of normal plugin stuff and a few things to notice.', 'bouncer' );
		}
		if ( $score <= 80 ) {
			return __( 'Risk is elevated — several signals bumped the score.', 'bouncer' );
		}
		return __( 'Risk is high — multiple strong signals in the structure check.', 'bouncer' );
	}

	/**
	 * Full Quick Look: headline, bullets, traffic, score explanation.
	 *
	 * @param array<string, mixed> $manifest Full manifest array including capabilities.
	 * @return array{headline: string, bullets: string[], traffic: string, score_sentence: string, score: int}
	 */
	public static function quick_look( array $manifest ): array {
		$score = (int) ( $manifest['risk_score'] ?? 0 );
		$bullets = self::build_bullets( $manifest );

		if ( count( $bullets ) < 1 ) {
			$bullets[] = __( 'No dramatic patterns jumped out in the automatic pass.', 'bouncer' );
		}
		if ( count( $bullets ) < 2 ) {
			$bullets[] = __( 'Keep an eye on the event log after updates — real behavior matters most.', 'bouncer' );
		}
		$bullets = array_slice( $bullets, 0, 3 );

		return array(
			'headline'        => self::headline_for_score( $score ),
			'bullets'         => $bullets,
			'traffic'         => self::traffic_for_score( $score ),
			'score_sentence'  => self::score_sentence( $score ),
			'score'           => $score,
		);
	}

	/**
	 * @param array<string, mixed> $manifest Manifest array.
	 * @return string[]
	 */
	private static function build_bullets( array $manifest ): array {
		$caps = isset( $manifest['capabilities'] ) && is_array( $manifest['capabilities'] ) ? $manifest['capabilities'] : array();
		$apis = isset( $caps['apis'] ) && is_array( $caps['apis'] ) ? $caps['apis'] : array();
		$db   = isset( $caps['database'] ) && is_array( $caps['database'] ) ? $caps['database'] : array(
			'read'  => array(),
			'write' => array(),
		);
		$http = isset( $caps['http_outbound'] ) && is_array( $caps['http_outbound'] ) ? $caps['http_outbound'] : array();
		$hooks = isset( $caps['hooks'] ) && is_array( $caps['hooks'] ) ? $caps['hooks'] : array(
			'sensitive_hooks' => array(),
		);
		$susp = isset( $caps['suspicious_patterns'] ) && is_array( $caps['suspicious_patterns'] ) ? $caps['suspicious_patterns'] : array();

		$out = array();

		if ( ! empty( $apis['uses_eval'] ) ) {
			$out[] = __( 'Uses dynamic code execution — powerful, so make sure you trust updates from the author.', 'bouncer' );
		}
		if ( ! empty( $apis['uses_exec'] ) ) {
			$out[] = __( 'Can run system-level commands — double-check you expect that from this plugin.', 'bouncer' );
		}
		if ( ! empty( $apis['uses_raw_curl'] ) ) {
			$out[] = __( 'Makes low-level network calls outside WordPress’s usual helpers — not automatically bad, but worth knowing.', 'bouncer' );
		}

		$writes = isset( $db['write'] ) && is_array( $db['write'] ) ? $db['write'] : array();
		$sensitive = array_intersect( $writes, array( 'users', 'usermeta', 'options' ) );
		if ( ! empty( $sensitive ) ) {
			$out[] = __( 'Writes to sensitive site tables (users or settings) — normal for some plugins, unusual for others.', 'bouncer' );
		}

		$n_http = count( $http );
		if ( $n_http > 5 ) {
			$out[] = __( 'Talks to many different domains — fine for suites and connectors, odd for a tiny plugin.', 'bouncer' );
		} elseif ( $n_http > 2 ) {
			$out[] = __( 'Reaches out to several domains — matches many modern plugins that use APIs or CDNs.', 'bouncer' );
		}

		$sh = isset( $hooks['sensitive_hooks'] ) && is_array( $hooks['sensitive_hooks'] ) ? $hooks['sensitive_hooks'] : array();
		if ( count( $sh ) > 2 ) {
			$out[] = __( 'Hooks deeply into login and account flows — common for security and membership plugins.', 'bouncer' );
		}

		if ( count( $susp ) > 0 ) {
			$out[] = __( 'Some patterns looked like encoding or obfuscation — often harmless, sometimes worth a second look.', 'bouncer' );
		}

		return $out;
	}
}
