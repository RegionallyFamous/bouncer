<?php
/**
 * Plugin manifest manager.
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

/**
 * Generates per-plugin capability manifests via single-pass static analysis.
 */
class Bouncer_Manifest {

	/**
	 * Per-request manifest rows (null = no row). Keyed by plugin slug.
	 *
	 * @var array<string, array<string, mixed>|null>
	 */
	private static array $manifest_request_cache = array();

	/** @var array<string, string> Dangerous function → category mapping. */
	private static array $dangerous_functions = array(
		'eval'              => 'code_execution',
		'assert'            => 'code_execution',
		'create_function'   => 'code_execution',
		'exec'              => 'system_command',
		'shell_exec'        => 'system_command',
		'system'            => 'system_command',
		'passthru'          => 'system_command',
		'proc_open'         => 'system_command',
		'popen'             => 'system_command',
		'pcntl_exec'        => 'system_command',
		'curl_init'         => 'raw_http',
		'curl_exec'         => 'raw_http',
		'fsockopen'         => 'raw_http',
		'base64_decode'     => 'obfuscation',
		'file_put_contents' => 'file_write',
		'fwrite'            => 'file_write',
	);

	/** @var string Single combined regex for dangerous function detection. Built once. */
	private static ?string $dangerous_regex = null;

	/**
	 * Generate a manifest for a plugin via single-pass static analysis.
	 *
	 * @return array<string, mixed>|null
	 */
	public function generate_for_plugin( string $plugin_slug ): ?array {
		$files = $this->get_php_files( $plugin_slug );
		if ( empty( $files ) ) {
			return null;
		}

		$version  = $this->get_plugin_version( $plugin_slug );
		$analysis = $this->create_empty_analysis();

		// Build dangerous function regex once.
		if ( null === self::$dangerous_regex ) {
			$funcs                 = implode( '|', array_map( 'preg_quote', array_keys( self::$dangerous_functions ) ) );
			self::$dangerous_regex = '/\b(' . $funcs . ')\s*\(/';
		}

		// Single-pass analysis per file.
		foreach ( $files as $file ) {
			$content = @file_get_contents( $file ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			if ( false === $content || '' === $content ) {
				continue;
			}
			$this->analyze_file_single_pass( $content, $analysis, $file );
		}

		// Deduplicate.
		foreach ( array( 'database.read', 'database.write', 'http_outbound', 'hooks.registers', 'hooks.sensitive_hooks', 'cron_jobs' ) as $path ) {
			$parts = explode( '.', $path );
			$ref   = &$analysis;
			foreach ( $parts as $p ) {
				$ref = &$ref[ $p ];
			}
			$ref = array_values( array_unique( $ref ) );
		}

		$risk_score = $this->calculate_risk_score( $analysis );

		$manifest = array(
			'plugin'        => $plugin_slug,
			'version'       => $version,
			'generated_at'  => gmdate( 'Y-m-d\TH:i:s\Z' ),
			'generated_by'  => 'static',
			'capabilities'  => $analysis,
			'risk_score'    => $risk_score,
			'ai_assessment' => null,
		);

		$this->save_manifest( $plugin_slug, $version, $manifest, $risk_score );

		// JSON file for external tools.
		$json_dir = WP_CONTENT_DIR . '/bouncer/manifests/';
		if ( is_dir( $json_dir ) ) {
			require_once __DIR__ . '/class-bouncer-filesystem.php';
			Bouncer_Filesystem::put_contents(
				$json_dir . $plugin_slug . '.json',
				wp_json_encode( $manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES )
			);
		}

		return $manifest;
	}

	/**
	 * Single-pass file analysis. Runs all pattern checks in one read.
	 */
	private function analyze_file_single_pass( string $content, array &$a, string $filepath ): void {
		$relative = str_replace( WP_PLUGIN_DIR . '/', '', $filepath );

		// Table references: $wpdb->prefix . 'tablename'.
		if ( preg_match_all( '/\$wpdb\s*->\s*prefix\s*\.\s*[\'"](\w+)[\'"]/', $content, $m ) ) {
			foreach ( $m[1] as $t ) {
				$a['database']['read'][] = $t;
			}
		}

		// Write operations.
		if ( preg_match_all( '/\$wpdb\s*->\s*(?:insert|update|delete|replace)\s*\(\s*\$wpdb\s*->\s*prefix\s*\.\s*[\'"](\w+)[\'"]/', $content, $m ) ) {
			foreach ( $m[1] as $t ) {
				$a['database']['write'][] = $t;
			}
		}

		// Outbound HTTP domains.
		if ( preg_match_all( '/wp_(?:safe_)?remote_(?:get|post|head|request)\s*\(\s*[\'"]https?:\/\/([^\/"\']+)/', $content, $m ) ) {
			foreach ( $m[1] as $d ) {
				$a['http_outbound'][] = $d;
			}
		}
		if ( preg_match_all( '/CURLOPT_URL[^\'"]*([\'"](https?:\/\/([^\/\'"]+)))/', $content, $m ) ) {
			foreach ( $m[3] as $d ) {
				$a['http_outbound'][] = $d;
			}
		}

		// Hook registrations.
		if ( preg_match_all( '/add_(?:action|filter)\s*\(\s*[\'"]([^\'"]+)[\'"]/', $content, $m ) ) {
			$sensitive     = array(
				'authenticate',
				'wp_login',
				'wp_logout',
				'wp_mail',
				'update_option',
				'delete_option',
				'set_user_role',
				'wp_insert_user',
				'delete_user',
				'switch_theme',
				'upgrader_process_complete',
				'phpmailer_init',
			);
			$sensitive_map = array_flip( $sensitive );
			foreach ( $m[1] as $hook ) {
				$a['hooks']['registers'][] = $hook;
				if ( isset( $sensitive_map[ $hook ] ) ) {
					$a['hooks']['sensitive_hooks'][] = $hook;
				}
			}
		}

		// Dangerous functions (single combined regex).
		if ( preg_match_all( self::$dangerous_regex, $content, $m ) ) {
			foreach ( $m[1] as $func ) {
				$a['apis']['dangerous_functions'][] = $func;
				$cat                                = self::$dangerous_functions[ $func ] ?? '';
				if ( 'code_execution' === $cat ) {
					$a['apis']['uses_eval'] = true; }
				if ( 'system_command' === $cat ) {
					$a['apis']['uses_exec'] = true; }
				if ( 'raw_http' === $cat ) {
					$a['apis']['uses_raw_curl'] = true; }
			}
		}

		// wp_mail.
		if ( preg_match( '/\bwp_mail\s*\(/', $content ) ) {
			$a['apis']['sends_email'] = true;
		}

		// Cron registrations.
		if ( preg_match_all( '/wp_schedule_(?:event|single_event)\s*\([^)]*[\'"]([^\'"]+)[\'"]/', $content, $m ) ) {
			foreach ( $m[1] as $hook ) {
				$a['cron_jobs'][] = $hook;
			}
		}

		// Suspicious patterns.
		$suspicious = array(
			'/\$\{[\'"][a-z]+[\'"]\s*\.\s*[\'"][a-z]+[\'"]\}/' => 'dynamic_function_construction',
			'/\$[a-zA-Z_]+\s*\(\s*\$/'              => 'variable_function_call',
			'/eval\s*\(\s*\$/'                      => 'eval_of_variable',
			'/preg_replace\s*\(\s*[\'"].*\/e[\'"]/' => 'preg_replace_eval',
		);
		foreach ( $suspicious as $pattern => $label ) {
			if ( preg_match( $pattern, $content ) ) {
				$a['suspicious_patterns'][] = array(
					'pattern' => $label,
					'file'    => $relative,
				);
			}
		}
	}

	/**
	 * @return array<string, mixed>
	 */
	private function create_empty_analysis(): array {
		return array(
			'database'            => array(
				'read'  => array(),
				'write' => array(),
			),
			'http_outbound'       => array(),
			'filesystem'          => array(
				'read'  => array(),
				'write' => array(),
			),
			'hooks'               => array(
				'registers'       => array(),
				'sensitive_hooks' => array(),
			),
			'apis'                => array(
				'uses_eval'           => false,
				'uses_exec'           => false,
				'uses_raw_curl'       => false,
				'sends_email'         => false,
				'dangerous_functions' => array(),
			),
			'suspicious_patterns' => array(),
			'cron_jobs'           => array(),
		);
	}

	/**
	 * Calculate risk score (0-100).
	 */
	private function calculate_risk_score( array $a ): int {
		$score = 0;

		if ( $a['apis']['uses_eval'] ) {
			$score += 25; }
		if ( $a['apis']['uses_exec'] ) {
			$score += 30; }
		if ( $a['apis']['uses_raw_curl'] ) {
			$score += 10; }

		$score += min( 30, count( $a['suspicious_patterns'] ) * 10 );
		$score += min( 15, count( $a['hooks']['sensitive_hooks'] ) * 3 );

		$outbound = count( $a['http_outbound'] );
		if ( $outbound > 5 ) {
			$score += 10;
		} elseif ( $outbound > 2 ) {
			$score += 5;
		}

		$sensitive_writes = array_intersect( $a['database']['write'], array( 'users', 'usermeta', 'options' ) );
		$score           += count( $sensitive_writes ) * 10;

		return min( 100, $score );
	}

	private function save_manifest( string $slug, string $version, array $manifest, int $risk ): void {
		global $wpdb;

		$existing = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT id FROM {$wpdb->prefix}bouncer_manifests WHERE plugin_slug = %s AND plugin_version = %s",
				$slug,
				$version
			)
		);

		$data = array(
			'manifest'     => wp_json_encode( $manifest ),
			'generated_at' => current_time( 'mysql', true ),
			'risk_score'   => $risk,
		);

		if ( $existing ) {
			$wpdb->update( $wpdb->prefix . 'bouncer_manifests', $data, array( 'id' => $existing ), array( '%s', '%s', '%d' ), array( '%d' ) );
		} else {
			$data['plugin_slug']    = $slug;
			$data['plugin_version'] = $version;
			$wpdb->insert( $wpdb->prefix . 'bouncer_manifests', $data, array( '%s', '%s', '%d', '%s', '%s' ) );
		}

		unset( self::$manifest_request_cache[ $slug ] );
	}

	/**
	 * @return array<string, array<string, mixed>|null> Keyed by plugin slug; null when no manifest.
	 */
	public function get_latest_manifests_for_slugs( array $slugs ): array {
		$slugs = array_values(
			array_unique(
				array_filter(
					array_map(
						static function ( $s ) {
							return is_string( $s ) ? trim( $s ) : '';
						},
						$slugs
					),
					static function ( $s ) {
						return '' !== $s && preg_match( '/^[a-zA-Z0-9._-]+$/', $s );
					}
				)
			)
		);

		$need_db = array();
		foreach ( $slugs as $slug ) {
			if ( ! array_key_exists( $slug, self::$manifest_request_cache ) ) {
				$need_db[] = $slug;
			}
		}

		if ( ! empty( $need_db ) ) {
			global $wpdb;
			$placeholders = implode( ', ', array_fill( 0, count( $need_db ), '%s' ) );
			$sql          = "SELECT plugin_slug, manifest, risk_score, ai_assessment, generated_at FROM {$wpdb->prefix}bouncer_manifests WHERE plugin_slug IN ({$placeholders}) ORDER BY plugin_slug ASC, generated_at DESC";
			// phpcs:ignore WordPress.DB.PreparedSQLPlaceholders.ReplacementsWrongNumber -- count matches IN list.
			$rows = $wpdb->get_results( $wpdb->prepare( $sql, ...$need_db ) );

			$seen = array();
			foreach ( $rows as $row ) {
				$slug = $row->plugin_slug;
				if ( isset( $seen[ $slug ] ) ) {
					continue;
				}
				$seen[ $slug ] = true;

				$manifest = json_decode( $row->manifest, true );
				if ( ! is_array( $manifest ) ) {
					self::$manifest_request_cache[ $slug ] = null;
					continue;
				}

				$manifest['risk_score']    = (int) $row->risk_score;
				$manifest['ai_assessment'] = $row->ai_assessment;
				$manifest['generated_at']  = $row->generated_at;

				self::$manifest_request_cache[ $slug ] = $manifest;
			}

			foreach ( $need_db as $slug ) {
				if ( ! array_key_exists( $slug, self::$manifest_request_cache ) ) {
					self::$manifest_request_cache[ $slug ] = null;
				}
			}
		}

		$out = array();
		foreach ( $slugs as $slug ) {
			$out[ $slug ] = self::$manifest_request_cache[ $slug ] ?? null;
		}

		return $out;
	}

	/**
	 * @return array<string, mixed>|null
	 */
	public function get_manifest( string $plugin_slug ): ?array {
		if ( array_key_exists( $plugin_slug, self::$manifest_request_cache ) ) {
			return self::$manifest_request_cache[ $plugin_slug ];
		}

		global $wpdb;
		$row = $wpdb->get_row(
			$wpdb->prepare(
				"SELECT manifest, risk_score, ai_assessment, generated_at FROM {$wpdb->prefix}bouncer_manifests WHERE plugin_slug = %s ORDER BY generated_at DESC LIMIT 1",
				$plugin_slug
			)
		);

		if ( ! $row ) {
			self::$manifest_request_cache[ $plugin_slug ] = null;
			return null;
		}

		$manifest = json_decode( $row->manifest, true );
		if ( ! is_array( $manifest ) ) {
			self::$manifest_request_cache[ $plugin_slug ] = null;
			return null;
		}

		$manifest['risk_score']    = (int) $row->risk_score;
		$manifest['ai_assessment'] = $row->ai_assessment;
		$manifest['generated_at']  = $row->generated_at;

		self::$manifest_request_cache[ $plugin_slug ] = $manifest;
		return $manifest;
	}

	public function has_manifest( string $plugin_slug ): bool {
		return null !== $this->get_manifest( $plugin_slug );
	}

	/** @return array */
	public function get_all_manifests(): array {
		global $wpdb;
		return $wpdb->get_results(
			"SELECT plugin_slug, plugin_version, risk_score, ai_assessment, generated_at, generated_by FROM {$wpdb->prefix}bouncer_manifests ORDER BY risk_score DESC"
		) ?: array();
	}

	/**
	 * Get PHP files for a plugin. Skips vendor/node_modules.
	 *
	 * @return string[] Full paths.
	 */
	private function get_php_files( string $plugin_slug ): array {
		$plugin_path = WP_PLUGIN_DIR . '/' . $plugin_slug;

		if ( ! is_dir( $plugin_path ) ) {
			$single = WP_PLUGIN_DIR . '/' . $plugin_slug . '.php';
			return file_exists( $single ) ? array( $single ) : array();
		}

		$files    = array();
		$iterator = new \RecursiveIteratorIterator(
			new \RecursiveCallbackFilterIterator(
				new \RecursiveDirectoryIterator( $plugin_path, \RecursiveDirectoryIterator::SKIP_DOTS ),
				function ( $current ) {
					if ( $current->isDir() ) {
						$n = $current->getFilename();
						return 'vendor' !== $n && 'node_modules' !== $n && '.' !== $n[0];
					}
					return true;
				}
			),
			\RecursiveIteratorIterator::LEAVES_ONLY
		);

		foreach ( $iterator as $file ) {
			if ( $file->isFile() && 'php' === strtolower( $file->getExtension() ) ) {
				$files[] = $file->getPathname();
			}
		}

		return $files;
	}

	private function get_plugin_version( string $plugin_slug ): string {
		if ( ! function_exists( 'get_plugin_data' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}

		$dir  = WP_PLUGIN_DIR . '/' . $plugin_slug;
		$main = $dir . '/' . $plugin_slug . '.php';

		if ( file_exists( $main ) ) {
			$data = get_plugin_data( $main, false, false );
			if ( ! empty( $data['Version'] ) ) {
				return $data['Version'];
			}
		}

		// Scan for main plugin file.
		$pattern = $dir . '/*.php';
		foreach ( glob( $pattern ) ?: array() as $file ) {
			$data = get_plugin_data( $file, false, false );
			if ( ! empty( $data['Version'] ) ) {
				return $data['Version'];
			}
		}

		return 'unknown';
	}
}
