<?php
/**
 * Optional Bouncer Brain model download (not bundled in the plugin zip).
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

/**
 * Downloads and stores the on-server helper file under uploads, updates option path.
 */
class Bouncer_Brain_Model {

	public const OPTION_PATH = 'bouncer_local_brain_model_path';

	/** @var int Default max download size (bytes). */
	private const DEFAULT_MAX_BYTES = 629145600; // 600 MB.

	/**
	 * Filterable download URL (constant + filter `bouncer_brain_model_url`).
	 */
	public static function get_model_url(): string {
		$default = defined( 'BOUNCER_BRAIN_MODEL_URL' ) ? (string) BOUNCER_BRAIN_MODEL_URL : '';
		$url       = (string) apply_filters( 'bouncer_brain_model_url', $default );
		return trim( $url );
	}

	/**
	 * Expected SHA-256 hex (optional). Empty skips checksum verification.
	 */
	public static function get_expected_sha256(): string {
		$default = defined( 'BOUNCER_BRAIN_MODEL_SHA256' ) ? (string) BOUNCER_BRAIN_MODEL_SHA256 : '';
		$h       = (string) apply_filters( 'bouncer_brain_model_sha256', $default );
		$h       = strtolower( preg_replace( '/\s+/', '', $h ) );
		return preg_match( '/^[a-f0-9]{64}$/', $h ) ? $h : '';
	}

	/**
	 * @return int Max bytes for the download body.
	 */
	public static function get_max_bytes(): int {
		$max = (int) apply_filters( 'bouncer_brain_max_bytes', self::DEFAULT_MAX_BYTES );
		return max( 1048576, $max ); // At least 1 MB.
	}

	/**
	 * Directory: wp-content/uploads/bouncer/brain
	 *
	 * @return string Absolute path or empty if uploads unavailable.
	 */
	public static function get_storage_directory(): string {
		$upload = wp_upload_dir();
		if ( ! empty( $upload['error'] ) ) {
			return '';
		}
		$base = trailingslashit( wp_normalize_path( $upload['basedir'] ) );
		return $base . 'bouncer/brain';
	}

	/**
	 * Default managed file path (single canonical name).
	 */
	public static function get_managed_model_path(): string {
		$dir = self::get_storage_directory();
		if ( '' === $dir ) {
			return '';
		}
		$filename = (string) apply_filters( 'bouncer_brain_model_filename', 'bouncer-brain-model.onnx' );
		$filename = sanitize_file_name( $filename );
		if ( '' === $filename ) {
			$filename = 'bouncer-brain-model.onnx';
		}
		return wp_normalize_path( $dir . '/' . $filename );
	}

	/**
	 * Whether the path is under our uploads/bouncer/brain tree.
	 */
	public static function is_managed_path( string $path ): bool {
		$path = wp_normalize_path( $path );
		$dir  = wp_normalize_path( self::get_storage_directory() );
		if ( '' === $dir || '' === $path ) {
			return false;
		}
		$prefix = trailingslashit( $dir );
		return str_starts_with( $path, $prefix );
	}

	/**
	 * Write Apache-compatible deny rules into the brain directory.
	 */
	public static function write_directory_protection( string $directory ): void {
		$directory = wp_normalize_path( trailingslashit( $directory ) );
		if ( '' === $directory || ! is_dir( $directory ) ) {
			return;
		}
		$htaccess = $directory . '.htaccess';
		$rules    = "# Bouncer — deny direct web access to Brain files\n<IfModule mod_authz_core.c>\n  Require all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\n  Deny from all\n</IfModule>\n";
		// Only write if missing or not ours (avoid clobbering custom rules).
		$existing = Bouncer_Filesystem::get_contents( $htaccess );
		if ( false === $existing || '' === trim( (string) $existing ) ) {
			Bouncer_Filesystem::put_contents( $htaccess, $rules );
		}
	}

	/**
	 * Download the model to the managed path and set the option.
	 *
	 * @param bool $force Re-download even if file exists.
	 * @return array{success:bool,message:string,path:string}
	 */
	public static function download( bool $force = false ): array {
		$url = self::get_model_url();
		if ( '' === $url ) {
			return array(
				'success' => false,
				'message' => __( 'The on-server helper file is not published for this build yet. Check back after an update, or ask your host to allow manual upload to the path below.', 'bouncer' ),
				'path'    => '',
			);
		}

		if ( ! apply_filters( 'bouncer_brain_download_skip_url_safety', false, $url )
			&& ! Bouncer_Url_Safety::is_safe_remote_http_url( $url ) ) {
			return array(
				'success' => false,
				'message' => __( 'That download address is not allowed (link-local and private networks are blocked for safety).', 'bouncer' ),
				'path'    => '',
			);
		}

		$dest = self::get_managed_model_path();
		if ( '' === $dest ) {
			return array(
				'success' => false,
				'message' => __( 'Could not resolve your uploads folder. Check that wp-content/uploads is writable.', 'bouncer' ),
				'path'    => '',
			);
		}

		$dir = dirname( $dest );
		if ( ! $force && is_readable( $dest ) ) {
			$expected = self::get_expected_sha256();
			if ( '' !== $expected ) {
				$actual = hash_file( 'sha256', $dest );
				if ( is_string( $actual ) && strtolower( $actual ) === $expected ) {
					update_option( self::OPTION_PATH, $dest );
					return array(
						'success' => true,
						'message' => __( 'The helper file is already installed and matches the expected checksum.', 'bouncer' ),
						'path'    => $dest,
					);
				}
			} elseif ( filesize( $dest ) > 0 ) {
				update_option( self::OPTION_PATH, $dest );
				return array(
					'success' => true,
					'message' => __( 'The helper file is already on disk. Use “Download again” if you need to replace it.', 'bouncer' ),
					'path'    => $dest,
				);
			}
		}

		if ( ! Bouncer_Filesystem::ensure() ) {
			return array(
				'success' => false,
				'message' => __( 'WordPress could not access the filesystem. Confirm FTP/SSH credentials or folder permissions.', 'bouncer' ),
				'path'    => '',
			);
		}

		require_once ABSPATH . 'wp-admin/includes/file.php';

		$tmp = download_url( $url, 600 );
		if ( is_wp_error( $tmp ) ) {
			return array(
				'success' => false,
				/* translators: %s: error message */
				'message' => sprintf( __( 'Download failed: %s', 'bouncer' ), $tmp->get_error_message() ),
				'path'    => '',
			);
		}

		$size = @filesize( $tmp );
		if ( false === $size || $size < 1 ) {
			wp_delete_file( $tmp );
			return array(
				'success' => false,
				'message' => __( 'Downloaded file was empty or unreadable.', 'bouncer' ),
				'path'    => '',
			);
		}

		if ( $size > self::get_max_bytes() ) {
			wp_delete_file( $tmp );
			return array(
				'success' => false,
				'message' => __( 'Downloaded file was larger than the allowed limit. Aborted for safety.', 'bouncer' ),
				'path'    => '',
			);
		}

		$expected = self::get_expected_sha256();
		if ( '' !== $expected ) {
			$actual = hash_file( 'sha256', $tmp );
			if ( ! is_string( $actual ) || strtolower( $actual ) !== $expected ) {
				wp_delete_file( $tmp );
				return array(
					'success' => false,
					'message' => __( 'Downloaded file did not match the expected checksum. Nothing was installed.', 'bouncer' ),
					'path'    => '',
				);
			}
		}

		if ( ! Bouncer_Filesystem::copy( $tmp, $dest ) ) {
			wp_delete_file( $tmp );
			return array(
				'success' => false,
				'message' => __( 'Could not save the file into uploads. Check disk space and permissions.', 'bouncer' ),
				'path'    => '',
			);
		}

		wp_delete_file( $tmp );
		self::write_directory_protection( $dir );
		update_option( self::OPTION_PATH, $dest );

		return array(
			'success' => true,
			'message' => __( 'The on-server helper file is installed. If your host supports Bouncer Brain, you’re all set.', 'bouncer' ),
			'path'    => $dest,
		);
	}

	/**
	 * Remove managed file and clear option when it points at managed storage.
	 *
	 * @return array{success:bool,message:string}
	 */
	public static function remove_managed(): array {
		$path = (string) get_option( self::OPTION_PATH, '' );
		$path = wp_normalize_path( trim( $path ) );
		if ( '' === $path || ! self::is_managed_path( $path ) ) {
			return array(
				'success' => false,
				'message' => __( 'The saved path is not the standard download location, so we didn’t delete anything. Clear the advanced path field if you need to point elsewhere.', 'bouncer' ),
			);
		}

		if ( ! Bouncer_Filesystem::ensure() ) {
			return array(
				'success' => false,
				'message' => __( 'WordPress could not access the filesystem to remove the file.', 'bouncer' ),
			);
		}

		Bouncer_Filesystem::delete_file( $path );
		delete_option( self::OPTION_PATH );

		return array(
			'success' => true,
			'message' => __( 'Removed the downloaded helper file and reset the saved path.', 'bouncer' ),
		);
	}
}
