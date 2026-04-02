<?php
/**
 * File integrity monitor.
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

/**
 * SHA-256 file integrity with baseline comparison and WP.org verification.
 */
class Bouncer_File_Integrity {

	private Bouncer_Logger $logger;

	/** @var string[] Extensions to monitor. */
	private static array $monitored_ext = array( 'php', 'js', 'jsx', 'ts', 'tsx' );

	/** @var array<string, true> Keyed for O(1) lookup. */
	private static array $monitored_ext_map = array(
		'php' => true,
		'js'  => true,
		'jsx' => true,
		'ts'  => true,
		'tsx' => true,
	);

	public function __construct( Bouncer_Logger $logger ) {
		$this->logger = $logger;
	}

	public function init(): void {
		// Cron handler wired in main Bouncer class.
	}

	/**
	 * Record file checksums baseline for a plugin.
	 *
	 * @return int Number of files baselined.
	 */
	public function record_baseline( string $plugin_slug ): int {
		global $wpdb;

		$wpdb->delete( $wpdb->prefix . 'bouncer_checksums', array( 'plugin_slug' => $plugin_slug ), array( '%s' ) );

		$files = $this->get_plugin_files( $plugin_slug );
		if ( empty( $files ) ) {
			return 0;
		}

		// Batch insert for speed.
		$values = array();
		$params = array();

		foreach ( $files as $file ) {
			$full_path = WP_PLUGIN_DIR . '/' . $file;
			if ( ! is_file( $full_path ) || ! is_readable( $full_path ) ) {
				continue;
			}

			$checksum = hash_file( 'sha256', $full_path );
			if ( false === $checksum ) {
				continue;
			}

			$values[] = '(%s, %s, %s, %d)';
			$params[] = $plugin_slug;
			$params[] = $file;
			$params[] = $checksum;
			$params[] = filesize( $full_path );

			// Flush in batches of 50.
			if ( count( $values ) >= 50 ) {
				$sql = "INSERT INTO {$wpdb->prefix}bouncer_checksums (plugin_slug, file_path, checksum_sha256, file_size) VALUES " . implode( ', ', $values );
				// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
				$wpdb->query( $wpdb->prepare( $sql, $params ) );
				$values = array();
				$params = array();
			}
		}

		// Flush remaining.
		if ( ! empty( $values ) ) {
			$sql = "INSERT INTO {$wpdb->prefix}bouncer_checksums (plugin_slug, file_path, checksum_sha256, file_size) VALUES " . implode( ', ', $values );
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			$wpdb->query( $wpdb->prepare( $sql, $params ) );
		}

		return count( $files );
	}

	/**
	 * Check all active plugins for file integrity.
	 */
	public function check_all_plugins(): void {
		$active = get_option( 'active_plugins', array() );

		foreach ( $active as $plugin_file ) {
			$slug = dirname( $plugin_file );
			if ( '.' === $slug ) {
				$slug = basename( $plugin_file, '.php' );
			}
			$this->check_plugin( $slug );
		}
	}

	/**
	 * Check a single plugin against baseline checksums.
	 *
	 * @return array<int, array{type: string, file: string}> Changes detected.
	 */
	public function check_plugin( string $plugin_slug ): array {
		global $wpdb;
		$changes = array();

		$baselines = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT file_path, checksum_sha256 FROM {$wpdb->prefix}bouncer_checksums WHERE plugin_slug = %s",
				$plugin_slug
			),
			OBJECT_K
		);

		if ( empty( $baselines ) ) {
			$this->record_baseline( $plugin_slug );
			return $changes;
		}

		$current_files = $this->get_plugin_files( $plugin_slug );

		// Check modified/deleted files.
		foreach ( $baselines as $file_path => $baseline ) {
			$full_path = WP_PLUGIN_DIR . '/' . $file_path;

			if ( ! file_exists( $full_path ) ) {
				$changes[] = array(
					'type' => 'deleted',
					'file' => $file_path,
				);
				$this->logger->log(
					Bouncer_Logger::SEVERITY_CRITICAL,
					Bouncer_Logger::CHANNEL_FILES,
					$plugin_slug,
					'file_deleted',
					sprintf( 'File "%s" in "%s" was deleted outside an update.', $file_path, $plugin_slug ),
					array( 'file' => $file_path )
				);
				continue;
			}

			$current_checksum = hash_file( 'sha256', $full_path );
			if ( false !== $current_checksum && $current_checksum !== $baseline->checksum_sha256 ) {
				$changes[] = array(
					'type' => 'modified',
					'file' => $file_path,
				);
				$this->logger->log(
					Bouncer_Logger::SEVERITY_EMERGENCY,
					Bouncer_Logger::CHANNEL_FILES,
					$plugin_slug,
					'file_modified',
					sprintf( 'File "%s" in "%s" modified outside update. Possible injection.', $file_path, $plugin_slug ),
					array(
						'file'     => $file_path,
						'expected' => $baseline->checksum_sha256,
						'actual'   => $current_checksum,
					)
				);

				if ( Bouncer::get_instance()->is_enforce_mode() ) {
					$this->emergency_deactivate( $plugin_slug );
				}
			}
		}

		// Check for new files.
		foreach ( $current_files as $file ) {
			if ( ! isset( $baselines[ $file ] ) ) {
				$changes[] = array(
					'type' => 'added',
					'file' => $file,
				);
				$this->logger->log(
					Bouncer_Logger::SEVERITY_WARNING,
					Bouncer_Logger::CHANNEL_FILES,
					$plugin_slug,
					'file_added',
					sprintf( 'New file "%s" in "%s" outside an update.', $file, $plugin_slug ),
					array( 'file' => $file )
				);
			}
		}

		return $changes;
	}

	/**
	 * Verify against WordPress.org repository checksums.
	 *
	 * @return array{verified: bool, mismatches: string[]}|\WP_Error
	 */
	public function verify_against_repository( string $plugin_slug, string $version ) {
		$url      = sprintf( 'https://downloads.wordpress.org/plugin-checksums/%s/%s.json', rawurlencode( $plugin_slug ), rawurlencode( $version ) );
		$response = wp_remote_get( $url, array( 'timeout' => 15 ) );

		if ( is_wp_error( $response ) ) {
			return $response;
		}

		if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
			return new \WP_Error( 'checksums_unavailable', sprintf( 'Checksums not available for %s v%s.', $plugin_slug, $version ) );
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		if ( empty( $data['files'] ) ) {
			return new \WP_Error( 'no_checksums', 'No checksum data in response.' );
		}

		$result = array(
			'verified'   => true,
			'mismatches' => array(),
		);

		foreach ( $data['files'] as $file_path => $checksums ) {
			$full_path = WP_PLUGIN_DIR . '/' . $plugin_slug . '/' . $file_path;
			if ( ! file_exists( $full_path ) || ! isset( $checksums['md5'] ) ) {
				continue;
			}

			if ( md5_file( $full_path ) !== $checksums['md5'] ) {
				$result['verified']     = false;
				$result['mismatches'][] = $file_path;

				$this->logger->log(
					Bouncer_Logger::SEVERITY_EMERGENCY,
					Bouncer_Logger::CHANNEL_FILES,
					$plugin_slug,
					'repository_mismatch',
					sprintf( 'File "%s" in "%s" does not match WordPress.org. Possible tampering.', $file_path, $plugin_slug ),
					array( 'file' => $file_path )
				);
			}
		}

		return $result;
	}

	/**
	 * Get all monitored files for a plugin (relative to WP_PLUGIN_DIR).
	 *
	 * Skips vendor/ and node_modules/ directories for performance.
	 *
	 * @return string[]
	 */
	private function get_plugin_files( string $plugin_slug ): array {
		$plugin_path = WP_PLUGIN_DIR . '/' . $plugin_slug;
		$files       = array();

		if ( ! is_dir( $plugin_path ) ) {
			$single = $plugin_slug . '.php';
			return file_exists( WP_PLUGIN_DIR . '/' . $single ) ? array( $single ) : array();
		}

		$iterator = new \RecursiveIteratorIterator(
			new \RecursiveCallbackFilterIterator(
				new \RecursiveDirectoryIterator( $plugin_path, \RecursiveDirectoryIterator::SKIP_DOTS ),
				function ( $current, $key, $iterator ) {
					// Skip vendor/node_modules for speed.
					if ( $current->isDir() ) {
						$name = $current->getFilename();
						return 'vendor' !== $name && 'node_modules' !== $name && '.' !== $name[0];
					}
					return true;
				}
			),
			\RecursiveIteratorIterator::LEAVES_ONLY
		);

		foreach ( $iterator as $file ) {
			if ( ! $file->isFile() ) {
				continue;
			}

			$ext = strtolower( $file->getExtension() );
			if ( ! isset( self::$monitored_ext_map[ $ext ] ) ) {
				continue;
			}

			$files[] = $plugin_slug . '/' . $iterator->getSubPathname();
		}

		return $files;
	}

	/**
	 * Emergency deactivate a compromised plugin.
	 * Handles both standard and network-activated plugins.
	 */
	private function emergency_deactivate( string $plugin_slug ): void {
		// Standard activation.
		$active  = get_option( 'active_plugins', array() );
		$updated = array_filter( $active, fn( $p ) => ! str_starts_with( $p, $plugin_slug . '/' ) );

		if ( count( $updated ) < count( $active ) ) {
			update_option( 'active_plugins', array_values( $updated ) );
		}

		// Network activation (multisite).
		if ( is_multisite() ) {
			$network = get_site_option( 'active_sitewide_plugins', array() );
			$changed = false;
			foreach ( array_keys( $network ) as $p ) {
				if ( str_starts_with( $p, $plugin_slug . '/' ) ) {
					unset( $network[ $p ] );
					$changed = true;
				}
			}
			if ( $changed ) {
				update_site_option( 'active_sitewide_plugins', $network );
			}
		}

		$this->logger->log(
			Bouncer_Logger::SEVERITY_EMERGENCY,
			Bouncer_Logger::CHANNEL_FILES,
			$plugin_slug,
			'emergency_deactivated',
			sprintf( 'Plugin "%s" emergency-deactivated due to file integrity violation.', $plugin_slug )
		);
	}
}
