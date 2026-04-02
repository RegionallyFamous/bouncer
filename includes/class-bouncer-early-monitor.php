<?php
/**
 * Early monitoring hooks loaded via mu-plugin.
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

/**
 * Provides early-loading monitoring. Hooks run before regular plugins.
 */
class Bouncer_Early_Monitor {

	public static function init(): void {
		// Heavy full-hook snapshots only when hook auditing is enabled (saves CPU on every request).
		if ( ! (bool) get_option( 'bouncer_hook_auditing', true ) ) {
			return;
		}

		add_action( 'muplugins_loaded', array( __CLASS__, 'snapshot_core_hooks' ), 0 );
		add_action( 'plugins_loaded', array( __CLASS__, 'snapshot_plugin_hooks' ), 999 );
	}

	/**
	 * Snapshot hooks before regular plugins load (baseline).
	 */
	public static function snapshot_core_hooks(): void {
		global $wp_filter;

		$snapshot = array();
		foreach ( $wp_filter as $tag => $hook_obj ) {
			if ( $hook_obj instanceof \WP_Hook ) {
				$snapshot[ $tag ] = array_keys( $hook_obj->callbacks );
			}
		}

		$GLOBALS['bouncer_core_hooks_snapshot'] = $snapshot;
	}

	/**
	 * Snapshot hooks after all plugins load, with source attribution.
	 */
	public static function snapshot_plugin_hooks(): void {
		global $wp_filter;

		$snapshot = array();
		foreach ( $wp_filter as $tag => $hook_obj ) {
			if ( ! ( $hook_obj instanceof \WP_Hook ) ) {
				continue;
			}
			foreach ( $hook_obj->callbacks as $priority => $callbacks ) {
				foreach ( $callbacks as $id => $cb_data ) {
					$source                               = self::identify_source( $cb_data['function'] );
					$snapshot[ $tag ][ $priority ][ $id ] = $source;
				}
			}
		}

		$GLOBALS['bouncer_plugin_hooks_snapshot'] = $snapshot;
	}

	/**
	 * Identify which plugin/theme/core a callback belongs to.
	 *
	 * Uses Reflection carefully with try/catch to handle edge cases
	 * (closures without source, internal functions, etc.).
	 *
	 * @param callable $callback The callback.
	 * @return string Plugin slug, 'core', 'theme:name', or 'unknown'.
	 */
	public static function identify_source( $callback ): string {
		$file = '';

		try {
			if ( is_string( $callback ) && function_exists( $callback ) ) {
				$ref  = new \ReflectionFunction( $callback );
				$file = $ref->getFileName();
			} elseif ( is_array( $callback ) && 2 === count( $callback ) ) {
				$class  = is_object( $callback[0] ) ? get_class( $callback[0] ) : $callback[0];
				$method = $callback[1];
				if ( is_string( $class ) && method_exists( $class, $method ) ) {
					$ref  = new \ReflectionMethod( $class, $method );
					$file = $ref->getFileName();
				}
			} elseif ( $callback instanceof \Closure ) {
				$ref  = new \ReflectionFunction( $callback );
				$file = $ref->getFileName();
			}
		} catch ( \ReflectionException $e ) {
			return 'unknown';
		}

		if ( ! is_string( $file ) || '' === $file ) {
			return 'unknown';
		}

		// Plugin?
		$plugin_dir = WP_PLUGIN_DIR . '/';
		if ( str_starts_with( $file, $plugin_dir ) ) {
			$relative = substr( $file, strlen( $plugin_dir ) );
			$slash    = strpos( $relative, '/' );
			return ( false !== $slash ) ? substr( $relative, 0, $slash ) : 'unknown';
		}

		// MU-plugin?
		$mu_dir = WPMU_PLUGIN_DIR . '/';
		if ( str_starts_with( $file, $mu_dir ) ) {
			return 'mu-plugin';
		}

		// Theme?
		$theme_dir = get_theme_root() . '/';
		if ( str_starts_with( $file, $theme_dir ) ) {
			$relative = substr( $file, strlen( $theme_dir ) );
			$slash    = strpos( $relative, '/' );
			return 'theme:' . ( ( false !== $slash ) ? substr( $relative, 0, $slash ) : 'unknown' );
		}

		// Core.
		if ( str_starts_with( $file, ABSPATH ) ) {
			return 'core';
		}

		return 'unknown';
	}
}
