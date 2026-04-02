<?php
/**
 * Core Bouncer orchestrator.
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

/**
 * Main Bouncer singleton. Initializes and coordinates all components.
 */
class Bouncer {

	private static ?Bouncer $instance = null;

	public Bouncer_Logger $logger;
	public Bouncer_Manifest $manifest;
	public ?Bouncer_Http_Monitor $http_monitor     = null;
	public ?Bouncer_Hook_Auditor $hook_auditor     = null;
	public ?Bouncer_File_Integrity $file_integrity = null;
	public ?Bouncer_Ai_Scanner $ai_scanner         = null;

	public static function get_instance(): self {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	private function __construct() {}

	/**
	 * Initialize all components.
	 */
	public function init(): void {
		$this->logger   = new Bouncer_Logger();
		$this->manifest = new Bouncer_Manifest();

		// Activate database monitoring if db.php drop-in is installed.
		$this->activate_db_monitoring();

		if ( $this->get_setting( 'http_monitoring' ) ) {
			$this->http_monitor = new Bouncer_Http_Monitor( $this->logger, $this->manifest, $this->is_enforce_mode() );
			$this->http_monitor->init();
		}

		if ( $this->get_setting( 'hook_auditing' ) ) {
			$this->hook_auditor = new Bouncer_Hook_Auditor( $this->logger, $this->manifest );
			$this->hook_auditor->init();
		}

		if ( $this->get_setting( 'file_integrity' ) ) {
			$this->file_integrity = new Bouncer_File_Integrity( $this->logger );
			$this->file_integrity->init();
		}

		// AI Scanner — resolve after Connectors registry exists (init + wp_connectors_init).
		$this->refresh_ai_scanner();
		add_action( 'init', array( $this, 'refresh_ai_scanner' ), 20 );
		add_action( 'wp_connectors_init', array( $this, 'refresh_ai_scanner' ), 50 );

		if ( is_admin() ) {
			Bouncer_Site_Health::init();
			( new Bouncer_Admin( $this ) )->init();
		}

		( new Bouncer_Rest_Monitor( $this->logger ) )->init();
		Bouncer_Notifications::init();
		Bouncer_Abilities::init();

		/**
		 * Fires after Bouncer has registered hooks and loaded components.
		 *
		 * @param Bouncer $bouncer Main instance.
		 */
		do_action( 'bouncer_initialized', $this );

		add_action( 'upgrader_process_complete', array( $this, 'on_plugin_update' ), 10, 2 );
		add_action( 'activated_plugin', array( $this, 'on_plugin_activated' ), 10, 2 );
		add_action( 'bouncer_file_integrity_check', array( $this, 'run_file_integrity_check' ) );
		add_action( 'bouncer_cleanup_old_events', array( $this, 'cleanup_old_events' ) );
		add_action( 'rest_api_init', array( $this, 'register_rest_routes' ) );
	}

	/**
	 * Activate the db.php drop-in monitoring if installed.
	 */
	private function activate_db_monitoring(): void {
		if ( ! defined( 'BOUNCER_DB_DROPIN_LOADED' ) || ! $this->get_setting( 'db_monitoring' ) ) {
			return;
		}

		global $wpdb;
		if ( $wpdb instanceof Bouncer_DB ) {
			// Activate monitoring (respects sampling rate).
			if ( $this->should_monitor_request() ) {
				$wpdb->bouncer_activate();
			}

			// Load manifests for active plugins into the db monitor (one batched query).
			$slugs  = array();
			$active = get_option( 'active_plugins', array() );
			foreach ( $active as $plugin_file ) {
				$slug = dirname( $plugin_file );
				if ( '.' === $slug ) {
					$slug = basename( $plugin_file, '.php' );
				}
				$slugs[] = $slug;
			}
			if ( is_multisite() ) {
				$network = get_site_option( 'active_sitewide_plugins', array() );
				foreach ( array_keys( $network ) as $plugin_file ) {
					$slug = dirname( $plugin_file );
					if ( '.' === $slug ) {
						$slug = basename( $plugin_file, '.php' );
					}
					$slugs[] = $slug;
				}
			}
			$slugs     = array_values( array_unique( $slugs ) );
			$manifests = $this->manifest->get_latest_manifests_for_slugs( $slugs );
			foreach ( $manifests as $slug => $m ) {
				if ( $m ) {
					$wpdb->bouncer_load_manifest( $slug, $m );
				}
			}
		}
	}

	/**
	 * Deep Dive scanner when the setting is on and an API key resolves (Connectors registry + env/constant).
	 */
	public function get_ai_scanner_if_available(): ?Bouncer_Ai_Scanner {
		if ( ! $this->get_setting( 'ai_scanning' ) ) {
			return null;
		}
		$scanner = new Bouncer_Ai_Scanner( $this->logger, $this->manifest );

		return $scanner->is_available() ? $scanner : null;
	}

	/**
	 * Refresh cached AI scanner (after init / wp_connectors_init).
	 */
	public function refresh_ai_scanner(): void {
		$this->ai_scanner = $this->get_ai_scanner_if_available();
	}

	/** @return mixed */
	public function get_setting( string $key, $default = false ) {
		return get_option( "bouncer_{$key}", $default );
	}

	public function update_setting( string $key, $value ): bool {
		return update_option( "bouncer_{$key}", $value );
	}

	public function is_enforce_mode(): bool {
		return 'enforce' === $this->get_setting( 'mode', 'monitor' );
	}

	public function should_monitor_request(): bool {
		$rate = (int) $this->get_setting( 'sampling_rate', 100 );
		if ( $rate >= 100 ) {
			$sample = true;
		} elseif ( $rate <= 0 ) {
			$sample = false;
		} else {
			$sample = wp_rand( 1, 100 ) <= $rate;
		}

		/**
		 * Filters whether this request should be monitored (sampling already applied).
		 *
		 * @param bool    $sample  Whether to monitor.
		 * @param Bouncer $bouncer Bouncer instance.
		 */
		return (bool) apply_filters( 'bouncer_should_monitor_request', $sample, $this );
	}

	/**
	 * Handle plugin update/install.
	 */
	public function on_plugin_update( $upgrader, array $options ): void {
		if ( 'plugin' !== ( $options['type'] ?? '' ) ) {
			return;
		}

		$slugs = array();
		if ( 'install' === ( $options['action'] ?? '' ) && isset( $upgrader->result['destination_name'] ) ) {
			$slugs[] = $upgrader->result['destination_name'];
		} elseif ( ! empty( $options['plugins'] ) ) {
			foreach ( (array) $options['plugins'] as $pf ) {
				$s = dirname( $pf );
				if ( '.' !== $s ) {
					$slugs[] = $s;
				}
			}
		}

		foreach ( $slugs as $slug ) {
			$m = $this->manifest->generate_for_plugin( $slug );

			$ai_scanner = $this->get_ai_scanner_if_available();
			if ( $ai_scanner ) {
				$ai_scanner->scan_plugin( $slug );
			}
			if ( $this->file_integrity ) {
				$this->file_integrity->record_baseline( $slug );
			}

			$this->logger->log( 'info', 'lifecycle', $slug, 'plugin_updated', sprintf( 'Plugin "%s" installed/updated.', $slug ) );
		}
	}

	public function on_plugin_activated( string $plugin_file, bool $network ): void {
		$slug = dirname( $plugin_file );
		if ( '.' === $slug ) {
			$slug = basename( $plugin_file, '.php' );
		}

		if ( ! $this->manifest->has_manifest( $slug ) ) {
			$this->manifest->generate_for_plugin( $slug );
		}
		if ( $this->hook_auditor ) {
			$this->hook_auditor->record_baseline( $slug );
		}
		if ( $this->file_integrity ) {
			$this->file_integrity->record_baseline( $slug );
		}

		$this->logger->log( 'info', 'lifecycle', $slug, 'plugin_activated', sprintf( 'Plugin "%s" activated.', $slug ) );
	}

	public function run_file_integrity_check(): void {
		if ( $this->file_integrity ) {
			$this->file_integrity->check_all_plugins();
		}
	}

	public function cleanup_old_events(): void {
		$this->logger->cleanup( (int) $this->get_setting( 'log_retention_days', 30 ) );
	}

	/**
	 * Register REST API routes.
	 */
	public function register_rest_routes(): void {
		$admin_check = function () {
			return bouncer_current_user_can_manage();
		};

		register_rest_route(
			'bouncer/v1',
			'/events',
			array(
				'methods'             => 'GET',
				'callback'            => function ( $req ) {
					return rest_ensure_response(
						$this->logger->get_events(
							array(
								'severity' => $req->get_param( 'severity' ),
								'channel'  => $req->get_param( 'channel' ),
								'plugin'   => $req->get_param( 'plugin' ),
								'per_page' => $req->get_param( 'per_page' ) ?: 50,
								'page'     => $req->get_param( 'page' ) ?: 1,
							)
						)
					);
				},
				'permission_callback' => $admin_check,
				'args'                => array(
					'severity' => array(
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
					),
					'channel'  => array(
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
					),
					'plugin'   => array(
						'type'              => 'string',
						'sanitize_callback' => 'sanitize_text_field',
					),
					'per_page' => array(
						'type'              => 'integer',
						'default'           => 50,
						'sanitize_callback' => 'absint',
					),
					'page'     => array(
						'type'              => 'integer',
						'default'           => 1,
						'sanitize_callback' => 'absint',
					),
				),
			)
		);

		register_rest_route(
			'bouncer/v1',
			'/manifest/(?P<slug>[a-zA-Z0-9._-]+)',
			array(
				'methods'             => 'GET',
				'callback'            => function ( $req ) {
					$slug = sanitize_text_field( $req['slug'] );
					if ( ! Bouncer_Installed_Plugins::is_installed_slug( $slug ) ) {
						return new \WP_Error( 'not_found', __( 'Plugin is not installed.', 'bouncer' ), array( 'status' => 404 ) );
					}
					$m = $this->manifest->get_manifest( $slug );
					return $m ? rest_ensure_response( $m ) : new \WP_Error( 'not_found', 'No manifest.', array( 'status' => 404 ) );
				},
				'permission_callback' => $admin_check,
			)
		);

		register_rest_route(
			'bouncer/v1',
			'/scan/(?P<slug>[a-zA-Z0-9._-]+)',
			array(
				'methods'             => 'POST',
				'callback'            => function ( $req ) {
					if ( ! Bouncer_Rest_Scan_Limiter::allow() ) {
						return new \WP_Error(
							'bouncer_rate_limited',
							__( 'Too many scan requests. Wait a minute and try again.', 'bouncer' ),
							array( 'status' => 429 )
						);
					}
					$slug = sanitize_text_field( $req['slug'] );
					if ( ! Bouncer_Installed_Plugins::is_installed_slug( $slug ) ) {
						return new \WP_Error( 'not_found', __( 'Plugin is not installed.', 'bouncer' ), array( 'status' => 404 ) );
					}
					$run_ai = $req->get_param( 'run_ai' );
					$run_ai = null === $run_ai ? true : rest_sanitize_boolean( $run_ai );

					$m = $this->manifest->generate_for_plugin( $slug );
					$ai = null;
					if ( $run_ai ) {
						$ai_scanner = $this->get_ai_scanner_if_available();
						if ( $ai_scanner ) {
							$ai = $ai_scanner->scan_plugin( $slug );
						}
					}
					return rest_ensure_response(
						array(
							'manifest'  => $m,
							'ai_result' => $ai,
						)
					);
				},
				'permission_callback' => $admin_check,
				'args'                => array(
					'run_ai' => array(
						'description'       => __( 'If false, only regenerate the manifest (skip Deep Dive / Claude).', 'bouncer' ),
						'type'              => 'boolean',
						'default'           => true,
						'sanitize_callback' => 'rest_sanitize_boolean',
					),
				),
			)
		);
	}
}
