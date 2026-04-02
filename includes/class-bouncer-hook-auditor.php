<?php
/**
 * Hook registration auditor.
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

/**
 * Monitors WordPress hook registrations and detects anomalies.
 */
class Bouncer_Hook_Auditor {

	private Bouncer_Logger $logger;
	private Bouncer_Manifest $manifest;

	/** @var array<string, true> Sensitive hooks — keyed for O(1) lookup. */
	private static array $sensitive_hooks = array(
		'authenticate'               => true,
		'wp_authenticate_user'       => true,
		'wp_login'                   => true,
		'wp_logout'                  => true,
		'update_option'              => true,
		'delete_option'              => true,
		'wp_insert_user'             => true,
		'profile_update'             => true,
		'user_register'              => true,
		'delete_user'                => true,
		'set_user_role'              => true,
		'wp_mail'                    => true,
		'phpmailer_init'             => true,
		'upgrader_process_complete'  => true,
		'activated_plugin'           => true,
		'deactivated_plugin'         => true,
		'wp_redirect'                => true,
		'allowed_redirect_hosts'     => true,
		'upload_mimes'               => true,
		'wp_handle_upload'           => true,
		'rest_authentication_errors' => true,
		'rest_pre_dispatch'          => true,
	);

	public function __construct( Bouncer_Logger $logger, Bouncer_Manifest $manifest ) {
		$this->logger   = $logger;
		$this->manifest = $manifest;
	}

	public function init(): void {
		add_action( 'wp_loaded', array( $this, 'audit_hooks' ), 999 );
	}

	/**
	 * Audit hook registrations against manifests. Runs once per request.
	 */
	public function audit_hooks(): void {
		static $audited = false;
		if ( $audited ) {
			return;
		}
		$audited = true;

		// Process pending db.php violations.
		$this->process_pending_violations();

		$snapshot = $GLOBALS['bouncer_plugin_hooks_snapshot'] ?? null;
		if ( empty( $snapshot ) ) {
			return;
		}

		// Only audit sensitive hooks (don't iterate all hooks).
		foreach ( self::$sensitive_hooks as $hook_name => $_ ) {
			if ( ! isset( $snapshot[ $hook_name ] ) ) {
				continue;
			}

			foreach ( $snapshot[ $hook_name ] as $priority => $callbacks ) {
				foreach ( $callbacks as $callback_id => $source ) {
					if ( 'core' === $source || 'unknown' === $source || 'mu-plugin' === $source || 'bouncer' === $source || str_starts_with( $source, 'theme:' ) ) {
						continue;
					}

					$plugin_manifest = $this->manifest->get_manifest( $source );

					if ( $plugin_manifest && ! empty( $plugin_manifest['capabilities']['hooks']['sensitive_hooks'] ) ) {
						if ( ! in_array( $hook_name, $plugin_manifest['capabilities']['hooks']['sensitive_hooks'], true ) ) {
							$this->logger->log(
								Bouncer_Logger::SEVERITY_WARNING,
								Bouncer_Logger::CHANNEL_HOOKS,
								$source,
								'undeclared_sensitive_hook',
								sprintf( 'Plugin "%s" on sensitive hook "%s" (priority %d) — not in manifest.', $source, $hook_name, $priority ),
								array(
									'hook'     => $hook_name,
									'priority' => $priority,
								)
							);
						}
					} elseif ( ! $plugin_manifest ) {
						$this->logger->log(
							Bouncer_Logger::SEVERITY_INFO,
							Bouncer_Logger::CHANNEL_HOOKS,
							$source,
							'sensitive_hook_discovery',
							sprintf( 'Plugin "%s" on sensitive hook "%s" (discovery mode).', $source, $hook_name ),
							array(
								'hook'     => $hook_name,
								'priority' => $priority,
							)
						);
					}
				}
			}
		}

		// Suspicious priority check (only on sensitive + high-traffic hooks).
		foreach ( $snapshot as $hook_name => $priorities ) {
			foreach ( $priorities as $priority => $callbacks ) {
				if ( $priority > 0 && $priority < 99999 ) {
					continue;
				}
				foreach ( $callbacks as $callback_id => $source ) {
					if ( 'core' === $source || 'unknown' === $source || 'mu-plugin' === $source || 'bouncer' === $source ) {
						continue;
					}
					$this->logger->log(
						Bouncer_Logger::SEVERITY_WARNING,
						Bouncer_Logger::CHANNEL_HOOKS,
						$source,
						'suspicious_priority',
						sprintf( 'Plugin "%s" on "%s" with extreme priority %d.', $source, $hook_name, $priority ),
						array(
							'hook'     => $hook_name,
							'priority' => $priority,
						)
					);
				}
			}
		}
	}

	/**
	 * Record hook baseline for a plugin.
	 */
	public function record_baseline( string $plugin_slug ): void {
		global $wpdb;

		$wpdb->delete( $wpdb->prefix . 'bouncer_hook_baselines', array( 'plugin_slug' => $plugin_slug ), array( '%s' ) );

		$snapshot = $GLOBALS['bouncer_plugin_hooks_snapshot'] ?? array();

		foreach ( $snapshot as $hook_name => $priorities ) {
			foreach ( $priorities as $priority => $callbacks ) {
				foreach ( $callbacks as $callback_id => $source ) {
					if ( $source !== $plugin_slug ) {
						continue;
					}
					$wpdb->insert(
						$wpdb->prefix . 'bouncer_hook_baselines',
						array(
							'plugin_slug'        => $plugin_slug,
							'hook_name'          => mb_substr( $hook_name, 0, 200 ),
							'callback_signature' => mb_substr( $callback_id, 0, 500 ),
							'priority'           => (int) $priority,
						),
						array( '%s', '%s', '%s', '%d' )
					);
				}
			}
		}
	}

	/**
	 * Flush pending db.php violations into the logger.
	 */
	private function process_pending_violations(): void {
		if ( ! function_exists( 'bouncer_pending_violations_lock_acquire' ) ) {
			require_once BOUNCER_PLUGIN_DIR . 'includes/bouncer-pending-violations-lock.php';
		}

		$locked = false;
		for ( $i = 0; $i < 15 && ! $locked; $i++ ) {
			$locked = bouncer_pending_violations_lock_acquire();
			if ( ! $locked ) {
				usleep( 5000 );
			}
		}
		if ( ! $locked ) {
			return;
		}

		try {
			$pending = get_option( 'bouncer_pending_violations', array() );
			if ( empty( $pending ) || ! is_array( $pending ) ) {
				return;
			}

			update_option( 'bouncer_pending_violations', array(), false );

			foreach ( $pending as $v ) {
				if ( ! is_array( $v ) || empty( $v['severity'] ) ) {
					continue;
				}
				$this->logger->log(
					$v['severity'],
					$v['channel'] ?? 'database',
					$v['plugin_slug'] ?? '',
					$v['event_type'] ?? 'unknown',
					$v['message'] ?? '',
					$v['context'] ?? array()
				);
			}
		} finally {
			bouncer_pending_violations_lock_release();
		}
	}
}
