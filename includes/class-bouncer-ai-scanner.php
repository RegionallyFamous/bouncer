<?php
/**
 * AI-powered plugin scanner using Claude via WP 7.0 Connectors API.
 *
 * Uses the WordPress 7.0 Connectors API for API key management when
 * available, falling back to Bouncer's own setting for WP < 7.0.
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

/**
 * Analyzes plugin code via Claude API using structural fingerprints only.
 *
 * PRIVACY: This class NEVER sends raw source code. Only structural metadata.
 */
class Bouncer_Ai_Scanner {

	private const API_ENDPOINT = 'https://api.anthropic.com/v1/messages';
	private const MODEL        = 'claude-sonnet-4-20250514';
	private const API_VERSION  = '2023-06-01';
	private const TIMEOUT      = 60;

	/**
	 * WordPress 7.0 Connectors API connector ID for Anthropic.
	 */
	private const CONNECTOR_ID = 'anthropic';

	private Bouncer_Logger $logger;
	private Bouncer_Manifest $manifest;

	/**
	 * Resolved API key (cached per request).
	 *
	 * @var string|null
	 */
	private ?string $resolved_api_key = null;

	/**
	 * Constructor.
	 *
	 * No longer requires an API key parameter — key resolution is handled
	 * internally via the WP 7.0 Connectors API or Bouncer settings fallback.
	 *
	 * @param Bouncer_Logger   $logger   Logger instance.
	 * @param Bouncer_Manifest $manifest Manifest manager.
	 * @param string           $api_key  Legacy API key (used as fallback for WP < 7.0).
	 */
	public function __construct( Bouncer_Logger $logger, Bouncer_Manifest $manifest, string $api_key = '' ) {
		$this->logger   = $logger;
		$this->manifest = $manifest;

		// Legacy key is used as lowest-priority fallback.
		if ( '' !== $api_key ) {
			$this->resolved_api_key = $api_key;
		}
	}

	public function init(): void {}

	/**
	 * Check if AI scanning is available (API key resolvable).
	 *
	 * @return bool
	 */
	public function is_available(): bool {
		return '' !== $this->get_api_key();
	}

	/**
	 * Resolve the API key using the WP 7.0 Connectors API priority chain,
	 * falling back to Bouncer's own setting for older WordPress versions.
	 *
	 * Priority:
	 * 1. WP 7.0 Connectors API (which itself checks env → constant → DB)
	 * 2. ANTHROPIC_API_KEY environment variable (direct check)
	 * 3. ANTHROPIC_API_KEY PHP constant (direct check)
	 * 4. Bouncer's own bouncer_ai_api_key setting (legacy fallback)
	 *
	 * @return string API key or empty string.
	 */
	public function get_api_key(): string {
		if ( null !== $this->resolved_api_key && '' !== $this->resolved_api_key ) {
			return $this->resolved_api_key;
		}

		// Method 1: WP 7.0+ Connectors API.
		if ( function_exists( 'wp_get_connector' ) ) {
			$connector = wp_get_connector( self::CONNECTOR_ID );
			if ( $connector && ! empty( $connector['authentication'] ) ) {
				$setting_name = $connector['authentication']['setting_name'] ?? '';

				// The Connectors API checks env → constant → DB internally.
				// We check the same chain the connector system uses.
				$provider_id = strtoupper( self::CONNECTOR_ID );
				$env_key     = $provider_id . '_API_KEY';

				// Environment variable.
				$env_val = getenv( $env_key );
				if ( false !== $env_val && '' !== $env_val ) {
					$this->resolved_api_key = $env_val;
					return $this->resolved_api_key;
				}

				// PHP constant.
				if ( defined( $env_key ) ) {
					$this->resolved_api_key = constant( $env_key );
					return $this->resolved_api_key;
				}

				// Database setting (managed by Settings > Connectors screen).
				if ( '' !== $setting_name ) {
					$db_val = get_option( $setting_name, '' );
					if ( '' !== $db_val ) {
						$this->resolved_api_key = $db_val;
						return $this->resolved_api_key;
					}
				}
			}
		}

		// Method 2: Direct env/constant check (for WP < 7.0 or if connector not registered).
		$env_val = getenv( 'ANTHROPIC_API_KEY' );
		if ( false !== $env_val && '' !== $env_val ) {
			$this->resolved_api_key = $env_val;
			return $this->resolved_api_key;
		}

		if ( defined( 'ANTHROPIC_API_KEY' ) ) {
			$this->resolved_api_key = ANTHROPIC_API_KEY;
			return $this->resolved_api_key;
		}

		// Method 3: Bouncer's own legacy setting.
		$bouncer_key = get_option( 'bouncer_ai_api_key', '' );
		if ( '' !== $bouncer_key ) {
			$this->resolved_api_key = $bouncer_key;
			return $this->resolved_api_key;
		}

		$this->resolved_api_key = '';
		return '';
	}

	/**
	 * Get the source of the current API key (for admin display).
	 *
	 * @return string 'connector', 'environment', 'constant', 'bouncer_setting', or 'none'.
	 */
	public function get_api_key_source(): string {
		if ( function_exists( 'wp_is_connector_registered' ) && wp_is_connector_registered( self::CONNECTOR_ID ) ) {
			$connector = wp_get_connector( self::CONNECTOR_ID );
			$setting   = $connector['authentication']['setting_name'] ?? '';

			$env_key = strtoupper( self::CONNECTOR_ID ) . '_API_KEY';

			if ( false !== getenv( $env_key ) && '' !== getenv( $env_key ) ) {
				return 'connector_env';
			}
			if ( defined( $env_key ) ) {
				return 'connector_constant';
			}
			if ( '' !== $setting && '' !== get_option( $setting, '' ) ) {
				return 'connector_db';
			}
		}

		if ( false !== getenv( 'ANTHROPIC_API_KEY' ) && '' !== getenv( 'ANTHROPIC_API_KEY' ) ) {
			return 'environment';
		}
		if ( defined( 'ANTHROPIC_API_KEY' ) ) {
			return 'constant';
		}
		if ( '' !== get_option( 'bouncer_ai_api_key', '' ) ) {
			return 'bouncer_setting';
		}

		return 'none';
	}

	/**
	 * Scan a plugin and return AI analysis.
	 *
	 * @return array<string, mixed>|null
	 */
	public function scan_plugin( string $plugin_slug ): ?array {
		$api_key = $this->get_api_key();
		if ( '' === $api_key ) {
			$this->logger->log(
				Bouncer_Logger::SEVERITY_WARNING,
				Bouncer_Logger::CHANNEL_AI,
				$plugin_slug,
				'ai_no_key',
				sprintf( 'AI scan skipped for "%s" — no API key configured.', $plugin_slug )
			);
			return null;
		}

		$plugin_path = WP_PLUGIN_DIR . '/' . $plugin_slug;
		if ( ! is_dir( $plugin_path ) ) {
			return null;
		}

		$fingerprint = $this->build_fingerprint( $plugin_slug, $plugin_path );
		if ( empty( $fingerprint['files'] ) ) {
			return null;
		}

		$static_manifest = $this->manifest->get_manifest( $plugin_slug );
		$prompt          = $this->build_prompt( $plugin_slug, $fingerprint, $static_manifest );
		$response        = $this->call_api( $prompt, $api_key );

		if ( null === $response ) {
			$this->logger->log(
				Bouncer_Logger::SEVERITY_WARNING,
				Bouncer_Logger::CHANNEL_AI,
				$plugin_slug,
				'ai_scan_failed',
				sprintf( 'AI scan failed for "%s".', $plugin_slug )
			);
			return null;
		}

		$result = $this->parse_response( $response );
		if ( ! $result ) {
			return null;
		}

		$this->update_manifest_with_ai( $plugin_slug, $result );

		$severity = ( 'high' === ( $result['risk_level'] ?? 'low' ) )
			? Bouncer_Logger::SEVERITY_CRITICAL
			: Bouncer_Logger::SEVERITY_INFO;

		$this->logger->log(
			$severity,
			Bouncer_Logger::CHANNEL_AI,
			$plugin_slug,
			'ai_scan_complete',
			sprintf( 'AI scan for "%s": risk=%s.', $plugin_slug, $result['risk_level'] ?? 'unknown' ),
			array(
				'risk_level' => $result['risk_level'] ?? 'unknown',
				'summary'    => $result['summary'] ?? '',
			)
		);

		return $result;
	}

	/**
	 * Build structural fingerprint. NO raw source code included.
	 */
	private function build_fingerprint( string $slug, string $path ): array {
		$fp = array(
			'plugin_slug'   => $slug,
			'file_count'    => 0,
			'total_lines'   => 0,
			'files'         => array(),
			'functions'     => array(),
			'classes'       => array(),
			'hooks'         => array(),
			'api_calls'     => array(),
			'db_operations' => array(),
			'http_calls'    => array(),
			'suspicious'    => array(),
		);

		$iterator = new \RecursiveIteratorIterator(
			new \RecursiveCallbackFilterIterator(
				new \RecursiveDirectoryIterator( $path, \RecursiveDirectoryIterator::SKIP_DOTS ),
				function ( $c ) {
					if ( $c->isDir() ) {
						$n = $c->getFilename();
						return 'vendor' !== $n && 'node_modules' !== $n && '.' !== $n[0];
					}
					return true;
				}
			),
			\RecursiveIteratorIterator::LEAVES_ONLY
		);

		foreach ( $iterator as $file ) {
			if ( ! $file->isFile() || 'php' !== strtolower( $file->getExtension() ) || $fp['file_count'] >= 100 ) {
				continue;
			}

			$content = @file_get_contents( $file->getPathname() ); // phpcs:ignore WordPress.WP.AlternativeFunctions
			if ( false === $content ) {
				continue; }

			$relative   = str_replace( $path . '/', '', $file->getPathname() );
			$line_count = substr_count( $content, "\n" ) + 1;
			++$fp['file_count'];
			$fp['total_lines'] += $line_count;
			$fp['files'][]      = array(
				'path'  => $relative,
				'lines' => $line_count,
				'size'  => $file->getSize(),
			);

			if ( preg_match_all( '/function\s+([a-zA-Z_]\w*)\s*\(/', $content, $m ) ) {
				foreach ( $m[1] as $f ) {
					$fp['functions'][] = $relative . '::' . $f; }
			}
			if ( preg_match_all( '/class\s+([a-zA-Z_]\w*)/', $content, $m ) ) {
				foreach ( $m[1] as $c ) {
					$fp['classes'][] = $c; }
			}
			if ( preg_match_all( '/add_(?:action|filter)\s*\(\s*[\'"]([^\'"]+)[\'"]/', $content, $m ) ) {
				foreach ( $m[1] as $h ) {
					$fp['hooks'][] = $h; }
			}

			$dangerous = array( 'eval', 'exec', 'shell_exec', 'system', 'passthru', 'proc_open', 'curl_init', 'base64_decode' );
			foreach ( $dangerous as $func ) {
				if ( preg_match( '/\b' . preg_quote( $func, '/' ) . '\s*\(/', $content ) ) {
					$fp['api_calls'][] = $relative . '::' . $func;
				}
			}

			if ( preg_match_all( '/\$wpdb\s*->\s*(insert|update|delete|replace|query|get_var|get_row|get_results)\s*\(/', $content, $m ) ) {
				foreach ( $m[1] as $op ) {
					$fp['db_operations'][] = $relative . '::$wpdb->' . $op; }
			}
			if ( preg_match_all( '/wp_remote_(?:get|post|head|request)\s*\(\s*[\'"]https?:\/\/([^\/"\']+)/', $content, $m ) ) {
				foreach ( $m[1] as $d ) {
					$fp['http_calls'][] = $d; }
			}

			$patterns = array(
				'/eval\s*\(\s*\$/'              => 'eval_of_variable',
				'/\$[a-zA-Z_]+\s*\(\s*\$/'      => 'variable_function_call',
				'/preg_replace\s*\([\'"].*\/e/' => 'preg_replace_eval',
			);
			foreach ( $patterns as $pat => $label ) {
				if ( preg_match( $pat, $content ) ) {
					$fp['suspicious'][] = $relative . ': ' . $label; }
			}
		}

		$fp['hooks']     = array_values( array_unique( $fp['hooks'] ) );
		$fp['api_calls'] = array_values( array_unique( $fp['api_calls'] ) );
		return $fp;
	}

	private function build_prompt( string $slug, array $fp, ?array $manifest ): string {
		$fp_json = wp_json_encode( $fp, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES );
		$m_json  = $manifest ? wp_json_encode( $manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) : 'None';

		$prompt  = "You are a WordPress plugin security analyst for Bouncer. Analyze this structural fingerprint (no source code — metadata only).\n\n";
		$prompt .= "## Plugin: {$slug}\n\n";
		$prompt .= "## Structural Fingerprint\n```json\n{$fp_json}\n```\n\n";
		$prompt .= "## Existing Static Manifest\n```json\n{$m_json}\n```\n\n";
		$prompt .= "## Tasks\n";
		$prompt .= "1. **Summary**: 2-3 sentences describing what this plugin does based on evidence.\n";
		$prompt .= "2. **Risk**: Rate \"low\", \"medium\", or \"high\" with explanation.\n";
		$prompt .= "3. **Concerns**: Security concerns ranked by severity.\n";
		$prompt .= "4. **Manifest refinements**: Suggested additions/corrections.\n\n";
		$prompt .= "Respond ONLY in JSON (no markdown, no preamble):\n";
		$prompt .= "{\n";
		$prompt .= '  "summary": "...",' . "\n";
		$prompt .= '  "risk_level": "low|medium|high",' . "\n";
		$prompt .= '  "risk_explanation": "...",' . "\n";
		$prompt .= '  "concerns": [{"severity": "info|warning|critical", "title": "...", "description": "...", "location": "...", "likely_legitimate": true}],' . "\n";
		$prompt .= '  "manifest_refinements": {"http_outbound_add": [], "database_tables_add": [], "sensitive_hooks_add": [], "notes": ""},' . "\n";
		$prompt .= '  "plain_language_report": "2-3 sentence report for a non-technical site owner"' . "\n";
		$prompt .= "}\n";

		return $prompt;
	}

	/**
	 * Call Claude API with resolved key.
	 */
	private function call_api( string $prompt, string $api_key ): ?string {
		$response = wp_remote_post(
			self::API_ENDPOINT,
			array(
				'timeout' => self::TIMEOUT,
				'headers' => array(
					'Content-Type'      => 'application/json',
					'x-api-key'         => $api_key,
					'anthropic-version' => self::API_VERSION,
				),
				'body'    => wp_json_encode(
					array(
						'model'      => self::MODEL,
						'max_tokens' => 4096,
						'messages'   => array(
							array(
								'role'    => 'user',
								'content' => $prompt,
							),
						),
					)
				),
			)
		);

		if ( is_wp_error( $response ) ) {
			$this->logger->log( Bouncer_Logger::SEVERITY_WARNING, Bouncer_Logger::CHANNEL_AI, '', 'api_error', 'Claude API: ' . $response->get_error_message() );
			return null;
		}

		if ( 200 !== wp_remote_retrieve_response_code( $response ) ) {
			$this->logger->log( Bouncer_Logger::SEVERITY_WARNING, Bouncer_Logger::CHANNEL_AI, '', 'api_error', sprintf( 'Claude API HTTP %d.', wp_remote_retrieve_response_code( $response ) ) );
			return null;
		}

		$data = json_decode( wp_remote_retrieve_body( $response ), true );
		return $data['content'][0]['text'] ?? null;
	}

	private function parse_response( string $response ): ?array {
		$clean  = preg_replace( '/^```(?:json)?\s*/m', '', $response );
		$clean  = preg_replace( '/\s*```$/m', '', $clean );
		$parsed = json_decode( trim( $clean ), true );

		if ( is_array( $parsed ) && isset( $parsed['risk_level'] ) ) {
			return $parsed; }
		if ( preg_match( '/\{[\s\S]*\}/', $response, $m ) ) {
			$parsed = json_decode( $m[0], true );
			if ( is_array( $parsed ) && isset( $parsed['risk_level'] ) ) {
				return $parsed; }
		}
		return null;
	}

	private function update_manifest_with_ai( string $slug, array $result ): void {
		global $wpdb;
		$assessment = sprintf( '%s risk. %s %s', ucfirst( $result['risk_level'] ?? 'unknown' ), $result['risk_explanation'] ?? '', $result['plain_language_report'] ?? '' );
		$wpdb->query(
			$wpdb->prepare(
				"UPDATE {$wpdb->prefix}bouncer_manifests SET ai_assessment = %s, generated_by = 'ai' WHERE plugin_slug = %s ORDER BY generated_at DESC LIMIT 1",
				mb_substr( $assessment, 0, 5000 ),
				$slug
			)
		);
	}
}
