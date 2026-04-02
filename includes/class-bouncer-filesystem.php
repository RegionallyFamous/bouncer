<?php
/**
 * WordPress Filesystem API wrapper for writes (Plugin Check / WPCS compliance).
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

/**
 * Centralizes file writes through WP_Filesystem.
 */
class Bouncer_Filesystem {

	/**
	 * Cached filesystem handle.
	 *
	 * @var WP_Filesystem_Base|null
	 */
	private static $fs = null;

	/**
	 * Forget cached handle (e.g. after tests).
	 */
	public static function reset_cache(): void {
		self::$fs = null;
	}

	/**
	 * Initialize WP_Filesystem (direct transport on typical hosts).
	 *
	 * @return bool True if a filesystem object is available.
	 */
	public static function ensure(): bool {
		if ( self::$fs instanceof WP_Filesystem_Base ) {
			return true;
		}

		require_once ABSPATH . 'wp-admin/includes/file.php';

		$url = site_url( '/' );
		ob_start();
		$creds = request_filesystem_credentials( $url, '', false, false, null );
		ob_end_clean();

		if ( false === $creds ) {
			return false;
		}

		if ( ! WP_Filesystem( $creds ) ) {
			return false;
		}

		global $wp_filesystem;
		if ( ! $wp_filesystem instanceof WP_Filesystem_Base ) {
			return false;
		}

		self::$fs = $wp_filesystem;
		return true;
	}

	/**
	 * Write a file using the WordPress filesystem layer.
	 *
	 * @param string $path Absolute path.
	 * @param string $contents File contents.
	 * @return bool True on success.
	 */
	public static function put_contents( string $path, string $contents ): bool {
		if ( ! self::ensure() ) {
			return false;
		}
		$path = wp_normalize_path( $path );
		$dir  = wp_normalize_path( dirname( $path ) );
		if ( ! self::$fs->is_dir( $dir ) ) {
			if ( ! self::$fs->mkdir( $dir, FS_CHMOD_DIR ) && ! self::$fs->is_dir( $dir ) ) {
				return false;
			}
		}
		return self::$fs->put_contents( $path, $contents, FS_CHMOD_FILE );
	}

	/**
	 * Read a file through the filesystem API.
	 *
	 * @param string $path Absolute path.
	 * @return string|false Contents or false.
	 */
	public static function get_contents( string $path ) {
		if ( ! self::ensure() ) {
			return false;
		}
		return self::$fs->get_contents( wp_normalize_path( $path ) );
	}

	/**
	 * Copy a file between paths.
	 *
	 * @param string $from Absolute source path.
	 * @param string $to   Absolute destination path.
	 * @return bool True on success.
	 */
	public static function copy( string $from, string $to ): bool {
		if ( ! self::ensure() ) {
			return false;
		}
		$from = wp_normalize_path( $from );
		$to   = wp_normalize_path( $to );
		$dir  = dirname( $to );
		if ( ! self::$fs->is_dir( $dir ) ) {
			if ( ! self::$fs->mkdir( $dir, FS_CHMOD_DIR ) && ! self::$fs->is_dir( $dir ) ) {
				return false;
			}
		}
		return self::$fs->copy( $from, $to, true, FS_CHMOD_FILE );
	}

	/**
	 * Delete a single file.
	 *
	 * @param string $path Absolute path to a file.
	 * @return bool True on success.
	 */
	public static function delete_file( string $path ): bool {
		if ( ! self::ensure() ) {
			return false;
		}
		$path = wp_normalize_path( $path );
		if ( ! self::$fs->exists( $path ) ) {
			return true;
		}
		return self::$fs->delete( $path, false, 'f' );
	}

	/**
	 * Remove a directory tree (uninstall).
	 *
	 * @param string $path Absolute directory path.
	 * @return bool True on success or if path does not exist.
	 */
	public static function delete_tree( string $path ): bool {
		if ( ! self::ensure() ) {
			return false;
		}
		$path = wp_normalize_path( $path );
		if ( ! self::$fs->exists( $path ) ) {
			return true;
		}
		return self::$fs->delete( $path, true );
	}
}
