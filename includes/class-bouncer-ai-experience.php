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
	 * Risk band for AI / Deep Dive alignment (matches Quick Look numeric score).
	 *
	 * @return string low|medium|high
	 */
	public static function severity_band_for_score( int $score ): string {
		if ( $score <= 20 ) {
			return 'low';
		}
		if ( $score <= 80 ) {
			return 'medium';
		}

		return 'high';
	}

	/**
	 * Translated Low / Medium / High label for the same bands as severity_band_for_score().
	 */
	public static function severity_label_for_score( int $score ): string {
		if ( $score <= 20 ) {
			return __( 'Low', 'bouncer' );
		}
		if ( $score <= 80 ) {
			return __( 'Medium', 'bouncer' );
		}

		return __( 'High', 'bouncer' );
	}

	/**
	 * One-line verdict from risk score only (e.g. manifest list table).
	 */
	public static function headline_for_score( int $score ): string {
		if ( $score <= 20 ) {
			return __( 'Pretty chill — looks like everyday plugin stuff.', 'bouncer' );
		}
		if ( $score <= 50 ) {
			return __( 'Mostly mellow — still worth a quick scroll.', 'bouncer' );
		}
		if ( $score <= 80 ) {
			return __( 'A few eyebrow-raisers — give it a closer read.', 'bouncer' );
		}
		return __( 'Strong signals — worth a careful look before you shrug it off.', 'bouncer' );
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
			return __( 'The automatic pass didn’t see much that worries us.', 'bouncer' );
		}
		if ( $score <= 50 ) {
			return __( 'There’s a little spice—normal for many plugins, just know it’s there.', 'bouncer' );
		}
		if ( $score <= 80 ) {
			return __( 'Several things stacked up—nothing automatic says “panic,” but stay curious.', 'bouncer' );
		}
		return __( 'Quite a few signals fired—treat this one as worth a human second opinion.', 'bouncer' );
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
			$bullets[] = __( 'Nothing dramatic jumped out in the quick automatic pass.', 'bouncer' );
		}
		if ( count( $bullets ) < 2 ) {
			$bullets[] = __( 'After updates, peek the event log—what happens live beats any static score.', 'bouncer' );
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
			$out[] = __( 'Can run changeable code on the fly—handy, but only if you trust the author’s updates.', 'bouncer' );
		}
		if ( ! empty( $apis['uses_exec'] ) ) {
			$out[] = __( 'Can ask the server to run commands—fine for some tools, surprising for others.', 'bouncer' );
		}
		if ( ! empty( $apis['uses_raw_curl'] ) ) {
			$out[] = __( 'Talks to the network without WordPress’s usual wrappers—not evil, just “know it’s there.”', 'bouncer' );
		}

		$writes = isset( $db['write'] ) && is_array( $db['write'] ) ? $db['write'] : array();
		$sensitive = array_intersect( $writes, array( 'users', 'usermeta', 'options' ) );
		if ( ! empty( $sensitive ) ) {
			$out[] = __( 'Touches member or site-setting tables—common for big plugins, odd for tiny ones.', 'bouncer' );
		}

		$n_http = count( $http );
		if ( $n_http > 5 ) {
			$out[] = __( 'Phones a lot of different domains—normal for suites, quirky for a one-trick plugin.', 'bouncer' );
		} elseif ( $n_http > 2 ) {
			$out[] = __( 'Checks in with a handful of domains—pretty normal for anything with APIs or CDNs.', 'bouncer' );
		}

		$sh = isset( $hooks['sensitive_hooks'] ) && is_array( $hooks['sensitive_hooks'] ) ? $hooks['sensitive_hooks'] : array();
		if ( count( $sh ) > 2 ) {
			$out[] = __( 'Plugs into login and account flows a lot—typical for security and membership tools.', 'bouncer' );
		}

		if ( count( $susp ) > 0 ) {
			$out[] = __( 'Saw some dense or encoded-looking bits—usually fine, occasionally worth a human peek.', 'bouncer' );
		}

		return $out;
	}
}
