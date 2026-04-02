<?php
/**
 * Installed plugin discovery for Bouncer admin and scans.
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

/**
 * Maps WordPress plugin files to directory slugs and exposes install checks.
 */
class Bouncer_Installed_Plugins {

	/**
	 * @var array<string, array{name: string, file: string, version: string, active: bool}>|null
	 */
	private static ?array $cache = null;

	/**
	 * Directory slug from plugin basename (e.g. akismet/akismet.php → akismet).
	 */
	public static function slug_from_plugin_file( string $plugin_file ): string {
		$dir = dirname( $plugin_file );
		if ( '.' === $dir ) {
			return basename( $plugin_file, '.php' );
		}

		return $dir;
	}

	/**
	 * Whether a string is a safe plugin slug segment (folder or single-file name).
	 */
	public static function is_valid_slug_format( string $slug ): bool {
		return (bool) preg_match( '/^[a-zA-Z0-9._-]+$/', $slug );
	}

	/**
	 * All installed plugins keyed by slug (one entry per plugin package).
	 *
	 * @return array<string, array{name: string, file: string, version: string, active: bool}>
	 */
	public static function get_by_slug(): array {
		if ( null !== self::$cache ) {
			return self::$cache;
		}

		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$plugins = get_plugins();
		$out     = array();

		foreach ( $plugins as $file => $data ) {
			$slug = self::slug_from_plugin_file( $file );
			if ( '' === $slug || ! self::is_valid_slug_format( $slug ) ) {
				continue;
			}

			$active = is_plugin_active( $file );
			if ( is_multisite() && ! $active ) {
				$active = is_plugin_active_for_network( $file );
			}

			$out[ $slug ] = array(
				'name'    => isset( $data['Name'] ) ? (string) $data['Name'] : $slug,
				'file'    => $file,
				'version' => isset( $data['Version'] ) ? (string) $data['Version'] : '',
				'active'  => $active,
			);
		}

		ksort( $out, SORT_STRING | SORT_FLAG_CASE );

		self::$cache = $out;

		return self::$cache;
	}

	/**
	 * Sorted list of slugs for JS batch scans.
	 *
	 * @return string[]
	 */
	public static function get_slug_list(): array {
		return array_keys( self::get_by_slug() );
	}

	public static function is_installed_slug( string $slug ): bool {
		if ( ! self::is_valid_slug_format( $slug ) ) {
			return false;
		}

		return array_key_exists( $slug, self::get_by_slug() );
	}

	public static function flush_cache(): void {
		self::$cache = null;
	}
}
