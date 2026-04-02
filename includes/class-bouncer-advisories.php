<?php
/**
 * Known vulnerability lookups via WPVulnerability (opt-in, external API).
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

/**
 * Fetches and interprets WPVulnerability.net plugin data.
 */
class Bouncer_Advisories {

	private const API_BASE = 'https://www.wpvulnerability.net/plugin/';

	private const TRANSIENT_PREFIX = 'bouncer_adv_';

	private const CACHE_SECONDS = 12 * HOUR_IN_SECONDS;

	/**
	 * Whether the installed version is affected by a vulnerability entry.
	 *
	 * @param string               $installed Semver-ish installed version.
	 * @param array<string, mixed> $vuln      Single vulnerability object from API.
	 */
	public static function vuln_affects_version( string $installed, array $vuln ): bool {
		$op = isset( $vuln['operator'] ) && is_array( $vuln['operator'] ) ? $vuln['operator'] : array();
		if ( ! empty( $op['unfixed'] ) && '1' === (string) $op['unfixed'] ) {
			return true;
		}

		$max_ver = isset( $op['max_version'] ) ? (string) $op['max_version'] : '';
		$min_ver = isset( $op['min_version'] ) ? (string) $op['min_version'] : '';

		if ( '' === $max_ver && '' === $min_ver ) {
			return false;
		}

		$max_cmp = isset( $op['max_operator'] ) ? strtolower( (string) $op['max_operator'] ) : 'le';
		$min_cmp = isset( $op['min_operator'] ) ? strtolower( (string) $op['min_operator'] ) : 'ge';

		if ( '' !== $max_ver && ! self::compare_version( $installed, $max_ver, $max_cmp ) ) {
			return false;
		}
		if ( '' !== $min_ver && ! self::compare_version( $installed, $min_ver, $min_cmp ) ) {
			return false;
		}

		return true;
	}

	/**
	 * @param string $installed Current version.
	 * @param string $boundary  Boundary from API.
	 * @param string $operator  le|lt|ge|gt|eq.
	 */
	private static function compare_version( string $installed, string $boundary, string $operator ): bool {
		switch ( $operator ) {
			case 'lt':
				return version_compare( $installed, $boundary, '<' );
			case 'le':
				return version_compare( $installed, $boundary, '<=' );
			case 'gt':
				return version_compare( $installed, $boundary, '>' );
			case 'ge':
				return version_compare( $installed, $boundary, '>=' );
			case 'eq':
				return version_compare( $installed, $boundary, '=' );
			default:
				return version_compare( $installed, $boundary, '<=' );
		}
	}

	/**
	 * Raw API payload for a plugin slug (cached).
	 *
	 * @return array<string, mixed>|null
	 */
	public static function get_plugin_data( string $slug ): ?array {
		$slug = strtolower( sanitize_text_field( $slug ) );
		if ( ! preg_match( '/^[a-z0-9\-]+$/', $slug ) || strlen( $slug ) > 200 ) {
			return null;
		}

		$key = self::TRANSIENT_PREFIX . md5( $slug );
		$cached = get_transient( $key );
		if ( false !== $cached && is_array( $cached ) ) {
			return $cached;
		}

		$url  = self::API_BASE . rawurlencode( $slug ) . '/';
		$resp = wp_safe_remote_get(
			$url,
			array(
				'timeout' => 12,
				'headers' => array( 'Accept' => 'application/json' ),
			)
		);

		if ( is_wp_error( $resp ) || 200 !== wp_remote_retrieve_response_code( $resp ) ) {
			set_transient( $key, array( '_error' => true ), 5 * MINUTE_IN_SECONDS );
			return null;
		}

		$body = json_decode( wp_remote_retrieve_body( $resp ), true );
		if ( ! is_array( $body ) || ! empty( $body['error'] ) ) {
			set_transient( $key, array( '_error' => true ), 5 * MINUTE_IN_SECONDS );
			return null;
		}

		$data = isset( $body['data'] ) && is_array( $body['data'] ) ? $body['data'] : null;
		if ( null === $data ) {
			set_transient( $key, array( '_empty' => true ), self::CACHE_SECONDS );
			return null;
		}

		set_transient( $key, $data, self::CACHE_SECONDS );
		return $data;
	}

	/**
	 * Vulnerabilities affecting the given installed version.
	 *
	 * @return array<int, array<string, mixed>>
	 */
	public static function get_affecting_for_version( string $slug, string $installed_version ): array {
		$data = self::get_plugin_data( $slug );
		if ( null === $data || empty( $data['vulnerability'] ) || ! is_array( $data['vulnerability'] ) ) {
			return array();
		}

		$out = array();
		foreach ( $data['vulnerability'] as $v ) {
			if ( is_array( $v ) && self::vuln_affects_version( $installed_version, $v ) ) {
				$out[] = $v;
			}
		}
		return $out;
	}

	/**
	 * Primary CVE/source label for a vulnerability entry.
	 */
	public static function vuln_primary_label( array $vuln ): string {
		if ( ! empty( $vuln['source'] ) && is_array( $vuln['source'] ) ) {
			foreach ( $vuln['source'] as $src ) {
				if ( is_array( $src ) && ! empty( $src['name'] ) ) {
					return (string) $src['name'];
				}
			}
		}
		return isset( $vuln['name'] ) ? (string) $vuln['name'] : '';
	}

	/**
	 * Primary link for details.
	 */
	public static function vuln_primary_link( array $vuln ): string {
		if ( ! empty( $vuln['source'] ) && is_array( $vuln['source'] ) ) {
			foreach ( $vuln['source'] as $src ) {
				if ( is_array( $src ) && ! empty( $src['link'] ) ) {
					return esc_url_raw( (string) $src['link'] );
				}
			}
		}
		return '';
	}
}
