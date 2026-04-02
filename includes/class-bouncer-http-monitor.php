<?php
/**
 * Outbound HTTP request monitor.
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

/**
 * Monitors outbound HTTP requests via WP_Http and attributes them
 * to the originating plugin with manifest-based allowlist enforcement.
 */
class Bouncer_Http_Monitor {

	private Bouncer_Logger $logger;
	private Bouncer_Manifest $manifest;

	/** @var bool Whether HTTP violations should block the request (Enforce mode). */
	private bool $enforce_mode;

	/** @var array<string, true> WordPress API domains — always allowed. */
	private static array $wp_domains = array(
		'api.wordpress.org'       => true,
		'downloads.wordpress.org' => true,
		'wordpress.org'           => true,
		'w.org'                   => true,
		's.w.org'                 => true,
		'translate.wordpress.org' => true,
	);

	/** @var int Minimum POST body size to flag as potential exfiltration. */
	private const EXFIL_THRESHOLD = 10240;

	public function __construct( Bouncer_Logger $logger, Bouncer_Manifest $manifest, bool $enforce_mode = false ) {
		$this->logger       = $logger;
		$this->manifest     = $manifest;
		$this->enforce_mode = $enforce_mode;
	}

	public function init(): void {
		add_filter( 'pre_http_request', array( $this, 'intercept_request' ), 1, 3 );
	}

	/**
	 * Intercept outbound HTTP requests before they fire.
	 *
	 * @param false|array|\WP_Error $preempt Response to preempt with, or false.
	 * @param array                 $args    Request arguments.
	 * @param string                $url     The URL being requested.
	 * @return false|array|\WP_Error
	 */
	public function intercept_request( $preempt, $args, $url ) {
		if ( false !== $preempt ) {
			return $preempt;
		}

		$attribution = $this->attribute_request();

		// Skip core, Bouncer, mu-plugins, unknown.
		if ( in_array( $attribution['source'], array( 'core', 'bouncer', 'mu-plugin', 'unknown' ), true ) ) {
			return false;
		}

		$parsed = wp_parse_url( $url );
		$domain = $parsed['host'] ?? '';

		if ( '' === $domain || isset( self::$wp_domains[ $domain ] ) ) {
			return false;
		}

		$plugin_slug = $attribution['source'];
		$manifest    = $this->manifest->get_manifest( $plugin_slug );
		$method      = strtoupper( $args['method'] ?? 'GET' );

		if ( $manifest && ! empty( $manifest['capabilities']['http_outbound'] ) ) {
			if ( ! $this->domain_matches_allowlist( $domain, $manifest['capabilities']['http_outbound'] ) ) {
				$this->logger->log(
					Bouncer_Logger::SEVERITY_WARNING,
					Bouncer_Logger::CHANNEL_HTTP,
					$plugin_slug,
					'unauthorized_outbound',
					sprintf( 'Plugin "%s" attempted HTTP %s to undeclared domain "%s".', $plugin_slug, $method, $domain ),
					array(
						'url'    => esc_url_raw( $url ),
						'domain' => $domain,
						'method' => $method,
						'file'   => $attribution['file'],
					)
				);

				// Block in enforce mode.
				if ( $this->enforce_mode ) {
					$this->logger->log(
						Bouncer_Logger::SEVERITY_CRITICAL,
						Bouncer_Logger::CHANNEL_HTTP,
						$plugin_slug,
						'outbound_blocked',
						sprintf( 'Blocked HTTP request from "%s" to "%s".', $plugin_slug, $domain )
					);
					return new \WP_Error( 'bouncer_blocked', __( 'Blocked by Bouncer security policy.', 'bouncer' ) );
				}
			}
		} elseif ( $this->should_log_discovery_event() ) {
			// No manifest — discovery mode (sampled to limit log volume).
			$this->logger->log(
				Bouncer_Logger::SEVERITY_INFO,
				Bouncer_Logger::CHANNEL_HTTP,
				$plugin_slug,
				'outbound_request',
				sprintf( 'Plugin "%s" made %s request to "%s" (discovery mode).', $plugin_slug, $method, $domain ),
				array(
					'url'    => esc_url_raw( $url ),
					'domain' => $domain,
					'method' => $method,
				)
			);
		}

		// Exfiltration check: large POST bodies.
		if ( 'POST' === $method && ! empty( $args['body'] ) ) {
			$body_size = is_string( $args['body'] ) ? strlen( $args['body'] ) : 0;
			if ( $body_size > self::EXFIL_THRESHOLD ) {
				$this->logger->log(
					Bouncer_Logger::SEVERITY_WARNING,
					Bouncer_Logger::CHANNEL_HTTP,
					$plugin_slug,
					'large_outbound_post',
					sprintf( 'Plugin "%s" sent %s bytes via POST to "%s".', $plugin_slug, number_format( $body_size ), $domain ),
					array(
						'url'       => esc_url_raw( $url ),
						'body_size' => $body_size,
					)
				);
			}
		}

		return false;
	}

	/**
	 * Attribute an HTTP request to its originating plugin.
	 *
	 * @return array{source: string, file: string}
	 */
	/**
	 * Random subsample for discovery-mode INFO logs (default 1 in 4).
	 */
	private function should_log_discovery_event(): bool {
		$d = (int) apply_filters( 'bouncer_http_discovery_log_sample_denominator', 4 );
		$d = max( 1, min( 100, $d ) );
		return 1 === wp_rand( 1, $d );
	}

	private function attribute_request(): array {
		$trace      = debug_backtrace( DEBUG_BACKTRACE_IGNORE_ARGS, 12 ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions
		$plugin_dir = WP_PLUGIN_DIR . '/';

		foreach ( $trace as $frame ) {
			$file = $frame['file'] ?? '';
			if ( '' === $file ) {
				continue;
			}

			// Skip HTTP and Bouncer internals.
			if ( false !== strpos( $file, 'class-wp-http' ) || false !== strpos( $file, '/http' ) || false !== strpos( $file, '/bouncer/' ) ) {
				continue;
			}

			if ( str_starts_with( $file, $plugin_dir ) ) {
				$relative = substr( $file, strlen( $plugin_dir ) );
				$slash    = strpos( $relative, '/' );
				return array(
					'source' => ( false !== $slash ) ? substr( $relative, 0, $slash ) : $relative,
					'file'   => $relative,
				);
			}
		}

		return array(
			'source' => 'unknown',
			'file'   => '',
		);
	}

	/**
	 * Check domain against allowlist (supports *.example.com wildcards).
	 *
	 * @param string   $domain       Domain to check.
	 * @param string[] $allowed_list Allowed domains/patterns.
	 * @return bool
	 */
	private function domain_matches_allowlist( string $domain, array $allowed_list ): bool {
		foreach ( $allowed_list as $allowed ) {
			if ( $domain === $allowed ) {
				return true;
			}

			if ( str_starts_with( $allowed, '*.' ) ) {
				$root = substr( $allowed, 2 );
				if ( $domain === $root || str_ends_with( $domain, '.' . $root ) ) {
					return true;
				}
			}
		}
		return false;
	}
}
