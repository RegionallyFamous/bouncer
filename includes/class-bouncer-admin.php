<?php
/**
 * Admin interface for Bouncer.
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

/**
 * Handles all WordPress admin UI: menu pages, dashboard,
 * settings, event log viewer, and plugin status badges.
 */
class Bouncer_Admin {

	/**
	 * Main Bouncer instance.
	 *
	 * @var Bouncer
	 */
	private $bouncer;

	/**
	 * Constructor.
	 *
	 * @param Bouncer $bouncer Main Bouncer instance.
	 */
	public function __construct( Bouncer $bouncer ) {
		$this->bouncer = $bouncer;
	}

	/**
	 * Initialize admin hooks.
	 */
	public function init() {
		add_filter(
			'option_page_capability_bouncer_settings',
			static function () {
				return BOUNCER_CAP;
			}
		);

		add_action( 'admin_init', array( $this, 'redirect_admin_php_bouncer_to_tools' ), 1 );
		add_action( 'admin_init', array( $this, 'redirect_legacy_tool_submenus' ), 2 );
		add_action( 'admin_menu', array( $this, 'add_menu_pages' ) );
		add_action( 'admin_init', array( $this, 'register_settings' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
		add_action( 'enqueue_block_editor_assets', array( $this, 'enqueue_block_editor_assets' ) );
		add_action( 'admin_init', array( $this, 'register_privacy_suggested_text' ) );
		add_action( 'load-tools_page_bouncer', array( $this, 'setup_events_screen_options' ) );
		add_filter( 'set_screen_option_bouncer_events_per_page', array( $this, 'set_events_per_page_screen_option' ), 10, 3 );

		// Add risk badge column to plugins list.
		add_filter( 'manage_plugins_columns', array( $this, 'add_plugin_column' ) );
		add_action( 'manage_plugins_custom_column', array( $this, 'render_plugin_column' ), 10, 3 );

		// Admin notices.
		add_action( 'admin_notices', array( $this, 'show_admin_notices' ) );

		// AJAX handlers.
		add_action( 'wp_ajax_bouncer_scan_plugin', array( $this, 'ajax_scan_plugin' ) );
		add_action( 'wp_ajax_bouncer_scan_batch', array( $this, 'ajax_scan_batch' ) );
		add_action( 'wp_ajax_bouncer_generate_manifest', array( $this, 'ajax_generate_manifest' ) );
		add_action( 'wp_ajax_bouncer_dismiss_notice', array( $this, 'ajax_dismiss_notice' ) );
	}

	/**
	 * Tools submenu with in-page tabs (Dashboard, Event Log, Manifests, Settings).
	 */
	public function add_menu_pages() {
		if ( ! bouncer_current_user_can_manage() ) {
			return;
		}

		add_submenu_page(
			'tools.php',
			__( 'Bouncer', 'bouncer' ),
			__( 'Bouncer', 'bouncer' ),
			BOUNCER_CAP,
			'bouncer',
			array( $this, 'render_app' )
		);
	}

	/**
	 * Redirect admin.php?page=bouncer (old top-level URLs) to Tools.
	 */
	public function redirect_admin_php_bouncer_to_tools(): void {
		if ( ! bouncer_current_user_can_manage() ) {
			return;
		}

		$pagenow = isset( $GLOBALS['pagenow'] ) ? $GLOBALS['pagenow'] : '';
		if ( 'admin.php' !== $pagenow || empty( $_GET['page'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}

		if ( 'bouncer' !== sanitize_key( wp_unslash( $_GET['page'] ) ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}

		$query = array( 'page' => 'bouncer' );
		if ( ! empty( $_GET['tab'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			$query['tab'] = sanitize_key( wp_unslash( $_GET['tab'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		}
		$passthrough = array( 'plugin', 'severity', 'orderby', 'order', 'paged' );
		foreach ( $passthrough as $key ) {
			if ( isset( $_GET[ $key ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				$query[ $key ] = 'paged' === $key
					? absint( wp_unslash( $_GET[ $key ] ) ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended
					: sanitize_text_field( wp_unslash( $_GET[ $key ] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			}
		}

		wp_safe_redirect( add_query_arg( $query, admin_url( 'tools.php' ) ) );
		exit;
	}

	/**
	 * Redirect legacy split Tools submenu slugs to the unified Bouncer screen.
	 */
	public function redirect_legacy_tool_submenus(): void {
		if ( ! bouncer_current_user_can_manage() ) {
			return;
		}

		$pagenow = isset( $GLOBALS['pagenow'] ) ? $GLOBALS['pagenow'] : '';
		if ( 'tools.php' !== $pagenow || empty( $_GET['page'] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			return;
		}

		$page = sanitize_key( wp_unslash( $_GET['page'] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		// Do not map `bouncer` here — that is the canonical Tools submenu slug; redirecting it to
		// tools.php?page=bouncer would loop (same URL) and triggers ERR_TOO_MANY_REDIRECTS.
		$map  = array(
			'bouncer-events'    => 'events',
			'bouncer-manifests' => 'manifests',
			'bouncer-settings'  => 'settings',
		);

		if ( ! isset( $map[ $page ] ) ) {
			return;
		}

		$tab   = $map[ $page ];
		$query = array( 'page' => 'bouncer' );
		if ( 'dashboard' !== $tab ) {
			$query['tab'] = $tab;
		}

		$passthrough = array( 'plugin', 'severity', 'orderby', 'order', 'paged' );
		foreach ( $passthrough as $key ) {
			if ( isset( $_GET[ $key ] ) ) { // phpcs:ignore WordPress.Security.NonceVerification.Recommended
				$query[ $key ] = 'paged' === $key
					? absint( wp_unslash( $_GET[ $key ] ) ) // phpcs:ignore WordPress.Security.NonceVerification.Recommended
					: sanitize_text_field( wp_unslash( $_GET[ $key ] ) ); // phpcs:ignore WordPress.Security.NonceVerification.Recommended
			}
		}

		wp_safe_redirect( add_query_arg( $query, admin_url( 'tools.php' ) ) );
		exit;
	}

	/**
	 * @return string One of dashboard|events|manifests|settings.
	 */
	private function resolve_tab(): string {
		$tab     = isset( $_GET['tab'] ) ? sanitize_key( wp_unslash( $_GET['tab'] ) ) : 'dashboard'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$allowed = array( 'dashboard', 'events', 'manifests', 'settings' );
		return in_array( $tab, $allowed, true ) ? $tab : 'dashboard';
	}

	/**
	 * Tab navigation (WordPress nav-tab pattern).
	 *
	 * @param string $current Current tab slug.
	 */
	private function render_tab_nav( string $current ): void {
		$tabs = array(
			'dashboard' => __( 'Dashboard', 'bouncer' ),
			'events'    => __( 'Event Log', 'bouncer' ),
			'manifests' => __( 'Manifests', 'bouncer' ),
			'settings'  => __( 'Settings', 'bouncer' ),
		);

		echo '<nav class="nav-tab-wrapper bouncer-nav-tab-wrapper wp-clearfix" aria-label="' . esc_attr__( 'Bouncer sections', 'bouncer' ) . '">';
		foreach ( $tabs as $slug => $label ) {
			$url   = bouncer_admin_url( $slug );
			$class = 'nav-tab' . ( $current === $slug ? ' nav-tab-active' : '' );
			printf(
				'<a href="%1$s" class="%2$s">%3$s</a>',
				esc_url( $url ),
				esc_attr( $class ),
				esc_html( $label )
			);
		}
		echo '</nav>';
	}

	/**
	 * Single entry point: shell + tab content.
	 */
	public function render_app(): void {
		if ( ! bouncer_current_user_can_manage() ) {
			return;
		}

		$tab = $this->resolve_tab();
		?>
		<div class="wrap bouncer-wrap">
			<main id="bouncer-main" class="bouncer-main" role="main">
			<h1 class="bouncer-title wp-heading-inline">
				<span class="dashicons dashicons-shield" aria-hidden="true"></span>
				<?php esc_html_e( 'Bouncer', 'bouncer' ); ?>
			</h1>
			<?php $this->render_tab_nav( $tab ); ?>
			<hr class="wp-header-end" />
			<?php
			switch ( $tab ) {
				case 'dashboard':
					$this->render_dashboard_inner();
					break;
				case 'events':
					$this->render_events_inner();
					break;
				case 'manifests':
					$this->render_manifests_inner();
					break;
				case 'settings':
					$this->render_settings_inner();
					break;
			}
			?>
			</main>
		</div>
		<?php
	}

	/**
	 * Per-screen options for the event log list table.
	 */
	public function setup_events_screen_options(): void {
		if ( 'events' !== $this->resolve_tab() ) {
			return;
		}

		add_screen_option(
			'per_page',
			array(
				'label'   => __( 'Events per page', 'bouncer' ),
				'default' => 50,
				'option'  => 'bouncer_events_per_page',
			)
		);
	}

	/**
	 * @param mixed  $keep   Previous value (often false).
	 * @param string $option Option name.
	 * @param mixed  $value  Submitted value.
	 * @return int
	 */
	public function set_events_per_page_screen_option( $keep, string $option, $value ): int {
		unset( $keep, $option );
		return max( 1, min( 200, (int) $value ) );
	}

	/**
	 * Suggested privacy policy text (core Privacy guide pattern).
	 */
	public function register_privacy_suggested_text(): void {
		if ( ! function_exists( 'wp_add_privacy_policy_content' ) ) {
			return;
		}
		$content  = '<p>' . esc_html__( 'Bouncer records security and monitoring events (which may include request paths, plugin identifiers, and IP addresses) to detect unusual plugin behavior. Retention is controlled in Bouncer’s settings.', 'bouncer' ) . '</p>';
		$content .= '<p>' . esc_html__( 'If AI scanning is enabled, Bouncer sends structural fingerprints of plugin code to your configured AI provider—not raw source files—according to that provider’s terms.', 'bouncer' ) . '</p>';
		wp_add_privacy_policy_content( 'Bouncer', $content );
	}

	/**
	 * Register settings.
	 */
	public function register_settings(): void {
		// Mode: only 'monitor' or 'enforce'.
		register_setting(
			'bouncer_settings',
			'bouncer_mode',
			array(
				'type'              => 'string',
				'capability'        => BOUNCER_CAP,
				'sanitize_callback' => function ( $val ) {
					return in_array( $val, array( 'monitor', 'enforce' ), true ) ? $val : 'monitor';
				},
			)
		);

		// Boolean toggles.
		$booleans = array(
			'bouncer_db_monitoring',
			'bouncer_http_monitoring',
			'bouncer_hook_auditing',
			'bouncer_file_integrity',
			'bouncer_ai_scanning',
			'bouncer_community_telemetry',
			'bouncer_rest_monitoring',
			'bouncer_digest_enabled',
			'bouncer_notify_on_warning',
			'bouncer_notify_on_critical',
			'bouncer_notify_on_emergency',
		);
		foreach ( $booleans as $key ) {
			register_setting(
				'bouncer_settings',
				$key,
				array(
					'type'              => 'boolean',
					'capability'        => BOUNCER_CAP,
					'sanitize_callback' => 'rest_sanitize_boolean',
				)
			);
		}

		// Sampling rate: 0-100.
		register_setting(
			'bouncer_settings',
			'bouncer_sampling_rate',
			array(
				'type'              => 'integer',
				'capability'        => BOUNCER_CAP,
				'sanitize_callback' => function ( $val ) {
					return max( 0, min( 100, (int) $val ) );
				},
			)
		);

		// Log retention: 1-365 days.
		register_setting(
			'bouncer_settings',
			'bouncer_log_retention_days',
			array(
				'type'              => 'integer',
				'capability'        => BOUNCER_CAP,
				'sanitize_callback' => function ( $val ) {
					return max( 1, min( 365, (int) $val ) );
				},
			)
		);

		// Notification email.
		register_setting(
			'bouncer_settings',
			'bouncer_notify_email',
			array(
				'type'              => 'string',
				'capability'        => BOUNCER_CAP,
				'sanitize_callback' => 'sanitize_email',
			)
		);

		register_setting(
			'bouncer_settings',
			'bouncer_webhook_url',
			array(
				'type'              => 'string',
				'capability'        => BOUNCER_CAP,
				'sanitize_callback' => static function ( $v ) {
					$v = esc_url_raw( trim( (string) $v ) );
					return $v ? $v : '';
				},
			)
		);

		register_setting(
			'bouncer_settings',
			'bouncer_webhook_secret',
			array(
				'type'              => 'string',
				'capability'        => BOUNCER_CAP,
				'sanitize_callback' => 'sanitize_text_field',
			)
		);

		register_setting(
			'bouncer_settings',
			'bouncer_digest_frequency',
			array(
				'type'              => 'string',
				'capability'        => BOUNCER_CAP,
				'sanitize_callback' => static function ( $v ) {
					return in_array( $v, array( 'daily', 'weekly' ), true ) ? $v : 'daily';
				},
			)
		);

		register_setting(
			'bouncer_settings',
			'bouncer_webhook_min_severity',
			array(
				'type'              => 'string',
				'capability'        => BOUNCER_CAP,
				'sanitize_callback' => static function ( $v ) {
					return in_array( $v, array( 'info', 'warning', 'critical', 'emergency' ), true ) ? $v : 'warning';
				},
			)
		);
	}

	/**
	 * Block editor integration (pre-publish panel).
	 */
	public function enqueue_block_editor_assets(): void {
		wp_enqueue_script(
			'bouncer-block-editor',
			BOUNCER_PLUGIN_URL . 'assets/js/bouncer-editor.js',
			array( 'wp-plugins', 'wp-edit-post', 'wp-element', 'wp-components', 'wp-i18n' ),
			BOUNCER_VERSION,
			true
		);
	}

	/**
	 * Enqueue admin assets.
	 *
	 * @param string $hook Current admin page hook.
	 */
	public function enqueue_assets( $hook ) {
		// Load on the Bouncer Tools screen and plugins list.
		$bouncer_pages = array(
			'tools_page_bouncer',
			'plugins.php',
		);

		if ( ! in_array( $hook, $bouncer_pages, true ) ) {
			return;
		}

		wp_enqueue_style(
			'bouncer-admin',
			BOUNCER_PLUGIN_URL . 'assets/css/bouncer-admin.css',
			array(),
			BOUNCER_VERSION
		);

		wp_enqueue_script(
			'bouncer-admin',
			BOUNCER_PLUGIN_URL . 'assets/js/bouncer-admin.js',
			array( 'jquery' ),
			BOUNCER_VERSION,
			true
		);

		$batch_max = $this->bouncer->get_ai_scanner_if_available()
			? (int) apply_filters( 'bouncer_scan_batch_max_with_ai', 3 )
			: (int) apply_filters( 'bouncer_scan_batch_max_quick_only', 10 );

		wp_localize_script(
			'bouncer-admin',
			'bouncerAdmin',
			array(
				'ajaxUrl'              => admin_url( 'admin-ajax.php' ),
				'nonce'                => wp_create_nonce( 'bouncer_admin' ),
				'installedPluginSlugs' => Bouncer_Installed_Plugins::get_slug_list(),
				'scanBatchSize'        => max( 1, min( 20, $batch_max ) ),
				'strings'              => array(
					'scanning'       => __( 'Scanning...', 'bouncer' ),
					'complete'       => __( 'Scan complete', 'bouncer' ),
					'error'          => __( 'Scan failed', 'bouncer' ),
					'confirm'        => __( 'Are you sure?', 'bouncer' ),
					'scanAll'        => __( 'Scan all installed plugins', 'bouncer' ),
					'scanAllRunning' => __( 'Scanning plugins…', 'bouncer' ),
					/* translators: 1: number finished, 2: total plugins */
					'scanAllProgress' => __( 'Scanned %1$d of %2$d…', 'bouncer' ),
					'scanAllDone'     => __( 'All scans finished. Reloading…', 'bouncer' ),
					'rateLimited'     => __( 'Rate limited — wait a minute, then click the button again to finish remaining plugins.', 'bouncer' ),
					'scanAllEmpty'    => __( 'No installed plugins to scan in this context.', 'bouncer' ),
					/* translators: %d: number of plugins not yet scanned */
					'continueScanLeft' => __( 'Continue scan (%d left)', 'bouncer' ),
				),
			)
		);
	}

	/**
	 * Dashboard tab body (shell is render_app).
	 */
	private function render_dashboard_inner(): void {
		$counts         = $this->bouncer->logger->get_severity_counts( 7 );
		$plugin_summary = $this->bouncer->logger->get_plugin_summary( 7 );
		$mode           = $this->bouncer->get_setting( 'mode', 'monitor' );
		$db_dropin      = get_option( 'bouncer_db_dropin_installed', false );
		$db_conflict    = get_option( 'bouncer_db_dropin_conflict', false );

		?>
			<h2 class="screen-reader-text"><?php esc_html_e( 'Overview', 'bouncer' ); ?></h2>

			<div class="bouncer-mode-badge bouncer-mode-<?php echo esc_attr( $mode ); ?>">
				<?php
				if ( 'enforce' === $mode ) {
					esc_html_e( 'Enforce Mode', 'bouncer' );
				} else {
					esc_html_e( 'Monitor Mode', 'bouncer' );
				}
				?>
			</div>

			<div class="bouncer-enforce-summary notice notice-info">
				<p>
					<?php
					$fi_on = $this->bouncer->get_setting( 'file_integrity' );
					if ( 'enforce' === $mode && $fi_on ) {
						esc_html_e( 'Monitor mode only records events. Enforce mode can block outbound HTTP requests that violate a plugin manifest and can emergency-deactivate a plugin when file integrity monitoring detects unauthorized file changes. Database violations are logged but queries are not blocked.', 'bouncer' );
					} elseif ( 'enforce' === $mode && ! $fi_on ) {
						esc_html_e( 'Monitor mode only records events. Enforce mode can block outbound HTTP requests that violate a plugin manifest. File integrity monitoring is currently off in Settings, so Bouncer will not auto-deactivate plugins for file tampering until you turn that channel on. Database violations are logged but queries are not blocked.', 'bouncer' );
					} else {
						esc_html_e( 'Monitor mode only records events. In Enforce mode, Bouncer can block outbound HTTP that violates a manifest and can deactivate plugins when file integrity monitoring is on and detects tampering. Database violations are logged but queries are not blocked.', 'bouncer' );
					}
					?>
				</p>
			</div>

			<?php $this->render_ai_modes_intro(); ?>

			<?php $this->render_installed_plugins_scan_panel(); ?>

			<?php if ( $db_conflict ) : ?>
				<div class="notice notice-warning">
					<p>
						<?php esc_html_e( 'WordPress only loads one database drop-in at wp-content/db.php. Another file is already there, so Bouncer did not overwrite it.', 'bouncer' ); ?>
					</p>
					<p>
						<?php esc_html_e( 'Database query attribution is disabled. Other Bouncer channels (HTTP monitoring, hook auditing, file integrity, etc.) still work.', 'bouncer' ); ?>
					</p>
					<p>
						<?php esc_html_e( 'To use Bouncer\'s SQL attribution, remove or replace that drop-in only if the other plugin no longer needs it, then deactivate and reactivate Bouncer.', 'bouncer' ); ?>
					</p>
				</div>
			<?php endif; ?>

			<div class="bouncer-stats-grid">
				<div class="bouncer-stat bouncer-stat-info">
					<span class="bouncer-stat-number"><?php echo esc_html( number_format( $counts['info'] ) ); ?></span>
					<span class="bouncer-stat-label"><?php esc_html_e( 'Info Events', 'bouncer' ); ?></span>
				</div>
				<div class="bouncer-stat bouncer-stat-warning">
					<span class="bouncer-stat-number"><?php echo esc_html( number_format( $counts['warning'] ) ); ?></span>
					<span class="bouncer-stat-label"><?php esc_html_e( 'Warnings', 'bouncer' ); ?></span>
				</div>
				<div class="bouncer-stat bouncer-stat-critical">
					<span class="bouncer-stat-number"><?php echo esc_html( number_format( $counts['critical'] ) ); ?></span>
					<span class="bouncer-stat-label"><?php esc_html_e( 'Critical', 'bouncer' ); ?></span>
				</div>
				<div class="bouncer-stat bouncer-stat-emergency">
					<span class="bouncer-stat-number"><?php echo esc_html( number_format( $counts['emergency'] ) ); ?></span>
					<span class="bouncer-stat-label"><?php esc_html_e( 'Emergencies', 'bouncer' ); ?></span>
				</div>
			</div>

			<div class="bouncer-channels-status">
				<h2><?php esc_html_e( 'Monitoring Channels', 'bouncer' ); ?></h2>
				<table class="widefat striped">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Channel', 'bouncer' ); ?></th>
							<th><?php esc_html_e( 'Status', 'bouncer' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<tr>
							<td><?php esc_html_e( 'Database Query Attribution', 'bouncer' ); ?></td>
							<td><?php echo $db_dropin && ! $db_conflict ? '<span class="bouncer-status-active">&#9679; Active</span>' : '<span class="bouncer-status-inactive">&#9679; Inactive</span>'; ?></td>
						</tr>
						<tr>
							<td><?php esc_html_e( 'Outbound HTTP Monitoring', 'bouncer' ); ?></td>
							<td><?php echo $this->bouncer->get_setting( 'http_monitoring' ) ? '<span class="bouncer-status-active">&#9679; Active</span>' : '<span class="bouncer-status-inactive">&#9679; Inactive</span>'; ?></td>
						</tr>
						<tr>
							<td><?php esc_html_e( 'Hook Registration Auditing', 'bouncer' ); ?></td>
							<td><?php echo $this->bouncer->get_setting( 'hook_auditing' ) ? '<span class="bouncer-status-active">&#9679; Active</span>' : '<span class="bouncer-status-inactive">&#9679; Inactive</span>'; ?></td>
						</tr>
						<tr>
							<td><?php esc_html_e( 'File Integrity Monitoring', 'bouncer' ); ?></td>
							<td><?php echo $this->bouncer->get_setting( 'file_integrity' ) ? '<span class="bouncer-status-active">&#9679; Active</span>' : '<span class="bouncer-status-inactive">&#9679; Inactive</span>'; ?></td>
						</tr>
						<tr>
							<td><?php esc_html_e( 'Quick Look (automatic)', 'bouncer' ); ?></td>
							<td><span class="bouncer-status-active">&#9679; <?php esc_html_e( 'Always on', 'bouncer' ); ?></span></td>
						</tr>
						<tr>
							<td><?php esc_html_e( 'Deep Dive (Claude)', 'bouncer' ); ?></td>
							<td>
								<?php
								$deep = false;
								if ( $this->bouncer->get_setting( 'ai_scanning' ) ) {
									$deep = null !== $this->bouncer->get_ai_scanner_if_available();
								}
								echo $deep
									? '<span class="bouncer-status-active">&#9679; ' . esc_html__( 'Active', 'bouncer' ) . '</span>'
									: '<span class="bouncer-status-inactive">&#9679; ' . esc_html__( 'Off or needs a key', 'bouncer' ) . '</span>';
								?>
							</td>
						</tr>
						<tr>
							<td><?php esc_html_e( 'REST unauthenticated write logging', 'bouncer' ); ?></td>
							<td><?php echo $this->bouncer->get_setting( 'rest_monitoring' ) ? '<span class="bouncer-status-active">&#9679; Active</span>' : '<span class="bouncer-status-inactive">&#9679; Inactive</span>'; ?></td>
						</tr>
					</tbody>
				</table>
			</div>

			<?php if ( ! empty( $plugin_summary ) ) : ?>
			<div class="bouncer-plugin-summary">
				<h2><?php esc_html_e( 'Plugin Activity (Last 7 Days)', 'bouncer' ); ?></h2>
				<table class="widefat striped">
					<thead>
						<tr>
							<th><?php esc_html_e( 'Plugin', 'bouncer' ); ?></th>
							<th><?php esc_html_e( 'Warnings', 'bouncer' ); ?></th>
							<th><?php esc_html_e( 'Critical', 'bouncer' ); ?></th>
							<th><?php esc_html_e( 'Emergencies', 'bouncer' ); ?></th>
							<th><?php esc_html_e( 'Total Events', 'bouncer' ); ?></th>
							<th><?php esc_html_e( 'Actions', 'bouncer' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $plugin_summary as $plugin ) : ?>
						<tr>
							<td><strong><?php echo esc_html( $plugin->plugin_slug ); ?></strong></td>
							<td><?php echo $plugin->warnings > 0 ? '<span class="bouncer-count-warning">' . esc_html( $plugin->warnings ) . '</span>' : '0'; ?></td>
							<td><?php echo $plugin->criticals > 0 ? '<span class="bouncer-count-critical">' . esc_html( $plugin->criticals ) . '</span>' : '0'; ?></td>
							<td><?php echo $plugin->emergencies > 0 ? '<span class="bouncer-count-emergency">' . esc_html( $plugin->emergencies ) . '</span>' : '0'; ?></td>
							<td><?php echo esc_html( $plugin->total_events ); ?></td>
							<td>
								<a href="<?php echo esc_url( bouncer_admin_url( 'events', array( 'plugin' => $plugin->plugin_slug ) ) ); ?>">
									<?php esc_html_e( 'View Events', 'bouncer' ); ?>
								</a>
								|
								<a href="<?php echo esc_url( bouncer_admin_url( 'manifests', array( 'plugin' => $plugin->plugin_slug ) ) ); ?>">
									<?php esc_html_e( 'Manifest', 'bouncer' ); ?>
								</a>
							</td>
						</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
			<?php endif; ?>
		<?php
	}

	/**
	 * Dashboard: plain-language intro to Quick Look vs Deep Dive (Claude).
	 */
	private function render_ai_modes_intro(): void {
		$ai_on   = $this->bouncer->get_setting( 'ai_scanning' );
		$deep_ok = null !== $this->bouncer->get_ai_scanner_if_available();
		?>
		<div class="bouncer-ai-modes-intro" role="region" aria-labelledby="bouncer-ai-modes-heading">
			<h2 id="bouncer-ai-modes-heading"><?php esc_html_e( 'How Bouncer reads plugins', 'bouncer' ); ?></h2>
			<p class="description bouncer-ai-modes-lede">
				<?php
				if ( $ai_on && $deep_ok ) {
					esc_html_e( 'Quick Look runs on your server for every scan. Deep Dive (Claude) is enabled and your Anthropic key is configured, so full scans can include AI-written analysis.', 'bouncer' );
				} elseif ( $ai_on && ! $deep_ok ) {
					esc_html_e( 'Quick Look runs on your server. Deep Dive is switched on in Settings, but no Anthropic API key is available yet — add one under Settings → Connectors (or ANTHROPIC_API_KEY) to unlock AI summaries.', 'bouncer' );
				} else {
					esc_html_e( 'Quick Look runs on your server for every scan. Deep Dive (Claude) is optional: turn it on under Tools → Bouncer → Settings when you want AI-written analysis.', 'bouncer' );
				}
				?>
			</p>
			<div class="bouncer-ai-modes-grid">
				<div class="bouncer-ai-mode-card bouncer-ai-mode-quick">
					<span class="dashicons dashicons-search" aria-hidden="true"></span>
					<h3><?php esc_html_e( 'Quick Look', 'bouncer' ); ?></h3>
					<p><?php esc_html_e( 'Static analysis on your server: risk score, capability hints, and plain-English bullets. No external API.', 'bouncer' ); ?></p>
				</div>
				<div class="bouncer-ai-mode-card bouncer-ai-mode-deep">
					<span class="dashicons dashicons-welcome-learn-more" aria-hidden="true"></span>
					<h3><?php esc_html_e( 'Deep Dive (Claude)', 'bouncer' ); ?></h3>
					<p>
						<?php
						if ( $deep_ok ) {
							esc_html_e( 'Anthropic Claude adds a longer narrative from structural fingerprints only (not raw source files), subject to Anthropic’s terms.', 'bouncer' );
						} elseif ( $ai_on ) {
							esc_html_e( 'Ready when an API key is configured in Settings → Connectors or via ANTHROPIC_API_KEY.', 'bouncer' );
						} else {
							esc_html_e( 'Optional: enable under Tools → Bouncer → Settings, then add your key in Settings → Connectors.', 'bouncer' );
						}
						?>
					</p>
				</div>
			</div>
		</div>
		<?php
	}

	/**
	 * Dashboard: link to manifests + scan-all (same script as Manifests tab).
	 */
	private function render_installed_plugins_scan_panel(): void {
		$installed = Bouncer_Installed_Plugins::get_by_slug();
		$n         = count( $installed );
		if ( $n < 1 ) {
			return;
		}
		$rows = $this->get_latest_manifest_rows_by_slug();
		$have = 0;
		foreach ( array_keys( $installed ) as $slug ) {
			if ( isset( $rows[ $slug ] ) ) {
				++$have;
			}
		}
		$url = bouncer_admin_url( 'manifests' );
		?>
		<div class="bouncer-installed-scan-panel">
			<h2><?php esc_html_e( 'Plugin scans', 'bouncer' ); ?></h2>
			<p class="description">
				<?php
				echo esc_html(
					sprintf(
						/* translators: 1: number of plugins with a stored manifest, 2: total installed plugins */
						__( 'Bouncer sees %2$d installed plugin(s); %1$d have a stored Quick Look manifest right now.', 'bouncer' ),
						$have,
						$n
					)
				);
				?>
			</p>
			<p>
				<a class="button button-primary" href="<?php echo esc_url( $url ); ?>"><?php esc_html_e( 'Open Manifests & scan tools', 'bouncer' ); ?></a>
			</p>
		</div>
		<?php
	}

	/**
	 * Latest DB row per plugin slug (by generated_at).
	 *
	 * @return array<string, object>
	 */
	private function get_latest_manifest_rows_by_slug(): array {
		$rows = $this->bouncer->manifest->get_all_manifests();
		$by   = array();
		foreach ( $rows as $row ) {
			$slug = $row->plugin_slug;
			if ( ! isset( $by[ $slug ] ) ) {
				$by[ $slug ] = $row;
				continue;
			}
			$prev = strtotime( $by[ $slug ]->generated_at );
			$cur  = strtotime( $row->generated_at );
			if ( $cur >= $prev ) {
				$by[ $slug ] = $row;
			}
		}

		return $by;
	}

	/**
	 * Event log tab body.
	 */
	private function render_events_inner(): void {
		$list_table = new Bouncer_Events_List_Table( $this->bouncer->logger );
		$list_table->prepare_items();

		?>
			<h2 class="screen-reader-text"><?php esc_html_e( 'Event Log', 'bouncer' ); ?></h2>

			<form id="bouncer-events-filter" class="bouncer-events-filter" method="get" action="<?php echo esc_url( admin_url( 'tools.php' ) ); ?>" aria-label="<?php esc_attr_e( 'Filter and browse Bouncer security events', 'bouncer' ); ?>">
				<input type="hidden" name="page" value="bouncer" />
				<input type="hidden" name="tab" value="events" />
				<?php $list_table->display(); ?>
			</form>
		<?php
	}

	/**
	 * Manifests tab body.
	 */
	private function render_manifests_inner(): void {
		$specific_plugin = isset( $_GET['plugin'] ) ? sanitize_text_field( wp_unslash( $_GET['plugin'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification

		if ( $specific_plugin ) {
			$this->render_single_manifest( $specific_plugin );
			return;
		}

		$installed = Bouncer_Installed_Plugins::get_by_slug();
		$by_slug   = $this->get_latest_manifest_rows_by_slug();
		$n_inst    = count( $installed );
		$deep_ok   = null !== $this->bouncer->get_ai_scanner_if_available();
		$ai_on     = $this->bouncer->get_setting( 'ai_scanning' );

		$scanned = 0;
		foreach ( array_keys( $installed ) as $slug ) {
			if ( isset( $by_slug[ $slug ] ) ) {
				++$scanned;
			}
		}

		?>
			<h2 class="screen-reader-text"><?php esc_html_e( 'Plugin Manifests', 'bouncer' ); ?></h2>

			<div class="bouncer-manifests-toolbar" id="bouncer-manifests-tools">
				<p class="description">
					<?php
					if ( $n_inst < 1 ) {
						esc_html_e( 'WordPress did not report any installed plugins in this site context.', 'bouncer' );
					} else {
						echo esc_html(
							sprintf(
								/* translators: 1: plugins with a manifest, 2: total installed */
								__( 'This site has %2$d installed plugin(s). %1$d have a Quick Look manifest saved; use Scan to refresh or create one.', 'bouncer' ),
								$scanned,
								$n_inst
							)
						);
						if ( $deep_ok ) {
							echo ' ';
							esc_html_e( 'Deep Dive (Claude) will run on each scan while your API key is available.', 'bouncer' );
						} elseif ( $ai_on ) {
							echo ' ';
							esc_html_e( 'Deep Dive is enabled but no API key is configured — scans will refresh Quick Look only until you add a key under Settings → Connectors.', 'bouncer' );
						} else {
							echo ' ';
							esc_html_e( 'Deep Dive is off in Settings — scans only update Quick Look unless you enable it and add an Anthropic key.', 'bouncer' );
						}
					}
					?>
				</p>
				<?php if ( $n_inst > 0 ) : ?>
				<p>
					<button type="button" class="button button-primary bouncer-scan-all-installed">
						<?php esc_html_e( 'Scan all installed plugins', 'bouncer' ); ?>
					</button>
					<span class="description bouncer-scan-all-status" style="margin-left:8px;" aria-live="polite"></span>
				</p>
				<?php endif; ?>
			</div>

			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Plugin', 'bouncer' ); ?></th>
						<th><?php esc_html_e( 'Status', 'bouncer' ); ?></th>
						<th><?php esc_html_e( 'Version', 'bouncer' ); ?></th>
						<th><?php esc_html_e( 'At a glance', 'bouncer' ); ?></th>
						<th><?php esc_html_e( 'Deep Dive', 'bouncer' ); ?></th>
						<th><?php esc_html_e( 'Generated', 'bouncer' ); ?></th>
						<th><?php esc_html_e( 'Actions', 'bouncer' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php if ( $n_inst < 1 ) : ?>
						<tr><td colspan="7"><?php esc_html_e( 'No installed plugins found.', 'bouncer' ); ?></td></tr>
					<?php else : ?>
						<?php foreach ( $installed as $slug => $info ) : ?>
							<?php
							$m = $by_slug[ $slug ] ?? null;
							?>
						<tr>
							<td>
								<strong><?php echo esc_html( $info['name'] ); ?></strong>
								<div class="description"><?php echo esc_html( $slug ); ?></div>
							</td>
							<td>
								<?php
								if ( $info['active'] ) {
									echo '<span class="bouncer-status-active">&#9679; ' . esc_html__( 'Active', 'bouncer' ) . '</span>';
								} else {
									echo '<span class="bouncer-status-inactive">&#9679; ' . esc_html__( 'Inactive', 'bouncer' ) . '</span>';
								}
								?>
							</td>
							<td><?php echo $m ? esc_html( $m->plugin_version ) : '—'; ?></td>
							<td>
								<?php
								if ( $m ) {
									echo wp_kses_post( $this->render_risk_badge( (int) $m->risk_score ) );
									echo '<div class="bouncer-quick-line">' . esc_html( wp_trim_words( Bouncer_AI_Experience::headline_for_score( (int) $m->risk_score ), 14, '…' ) ) . '</div>';
								} else {
									echo '<em>' . esc_html__( 'Not scanned yet', 'bouncer' ) . '</em>';
								}
								?>
							</td>
							<td>
								<?php
								if ( $m && ! empty( $m->ai_assessment ) ) {
									echo esc_html( wp_trim_words( $m->ai_assessment, 18 ) );
								} elseif ( $m && $deep_ok ) {
									echo '<em>' . esc_html__( 'None on file — rescan to generate', 'bouncer' ) . '</em>';
								} elseif ( $m && $ai_on && ! $deep_ok ) {
									echo '<em>' . esc_html__( 'Waiting for API key', 'bouncer' ) . '</em>';
								} elseif ( $m ) {
									echo '<em>' . esc_html__( 'Deep Dive off', 'bouncer' ) . '</em>';
								} else {
									echo '—';
								}
								?>
							</td>
							<td><?php echo $m ? esc_html( wp_date( 'M j, Y', strtotime( $m->generated_at ) ) ) : '—'; ?></td>
							<td>
								<a href="<?php echo esc_url( bouncer_admin_url( 'manifests', array( 'plugin' => $slug ) ) ); ?>">
									<?php esc_html_e( 'View', 'bouncer' ); ?>
								</a>
								|
								<a href="#" class="bouncer-rescan" data-plugin="<?php echo esc_attr( $slug ); ?>">
									<?php esc_html_e( 'Scan', 'bouncer' ); ?>
								</a>
							</td>
						</tr>
						<?php endforeach; ?>
					<?php endif; ?>
				</tbody>
			</table>
			<?php
			$orphans = array_diff( array_keys( $by_slug ), array_keys( $installed ) );
			if ( ! empty( $orphans ) ) :
				?>
			<h3><?php esc_html_e( 'Manifests for removed plugins', 'bouncer' ); ?></h3>
			<p class="description"><?php esc_html_e( 'These entries remain in the database but the plugin is no longer installed. You can ignore them or clean the table on uninstall.', 'bouncer' ); ?></p>
			<table class="widefat striped">
				<thead>
					<tr>
						<th><?php esc_html_e( 'Plugin slug', 'bouncer' ); ?></th>
						<th><?php esc_html_e( 'Generated', 'bouncer' ); ?></th>
					</tr>
				</thead>
				<tbody>
					<?php foreach ( $orphans as $oslug ) : ?>
						<?php $or = $by_slug[ $oslug ]; ?>
					<tr>
						<td><code><?php echo esc_html( $oslug ); ?></code></td>
						<td><?php echo esc_html( wp_date( 'M j, Y', strtotime( $or->generated_at ) ) ); ?></td>
					</tr>
					<?php endforeach; ?>
				</tbody>
			</table>
			<?php endif; ?>
		<?php
	}

	/**
	 * Render a single plugin manifest detail view.
	 *
	 * @param string $plugin_slug Plugin slug.
	 */
	private function render_single_manifest( $plugin_slug ) {
		if ( ! Bouncer_Installed_Plugins::is_valid_slug_format( $plugin_slug ) ) {
			?>
			<p><a href="<?php echo esc_url( bouncer_admin_url( 'manifests' ) ); ?>" class="button"><?php esc_html_e( '← All manifests', 'bouncer' ); ?></a></p>
			<div class="notice notice-error"><p><?php esc_html_e( 'That plugin identifier is not valid.', 'bouncer' ); ?></p></div>
			<?php
			return;
		}

		if ( ! Bouncer_Installed_Plugins::is_installed_slug( $plugin_slug ) ) {
			?>
			<p><a href="<?php echo esc_url( bouncer_admin_url( 'manifests' ) ); ?>" class="button"><?php esc_html_e( '← All manifests', 'bouncer' ); ?></a></p>
			<div class="notice notice-error">
				<p>
					<?php
					echo esc_html(
						sprintf(
							/* translators: %s: plugin slug */
							__( 'No installed plugin uses the slug “%s”. Open Manifests to pick from your installed plugins.', 'bouncer' ),
							$plugin_slug
						)
					);
					?>
				</p>
			</div>
			<?php
			return;
		}

		$manifest = $this->bouncer->manifest->get_manifest( $plugin_slug );
		$info     = Bouncer_Installed_Plugins::get_by_slug()[ $plugin_slug ];
		$deep_ok  = null !== $this->bouncer->get_ai_scanner_if_available();
		$ai_on    = $this->bouncer->get_setting( 'ai_scanning' );

		?>
			<p>
				<a href="<?php echo esc_url( bouncer_admin_url( 'manifests' ) ); ?>" class="button"><?php esc_html_e( '← All manifests', 'bouncer' ); ?></a>
			</p>
			<h2>
				<?php
				/* translators: 1: plugin name, 2: slug */
				printf( esc_html__( 'Manifest: %1$s (%2$s)', 'bouncer' ), esc_html( $info['name'] ), esc_html( $plugin_slug ) );
				?>
			</h2>

			<?php if ( ! $manifest ) : ?>
				<div class="notice notice-warning">
					<p><?php esc_html_e( 'This plugin is installed, but Bouncer has not saved a Quick Look manifest for it yet.', 'bouncer' ); ?></p>
				</div>
				<button type="button" class="button button-primary bouncer-rescan" data-plugin="<?php echo esc_attr( $plugin_slug ); ?>">
					<?php esc_html_e( 'Run first scan', 'bouncer' ); ?>
				</button>
			<?php else : ?>
				<?php
				$ql = Bouncer_AI_Experience::quick_look( $manifest );
				?>
				<div class="bouncer-quick-look-card bouncer-traffic-<?php echo esc_attr( $ql['traffic'] ); ?>">
					<h3><?php esc_html_e( 'Quick Look', 'bouncer' ); ?></h3>
					<p class="bouncer-quick-headline"><?php echo esc_html( $ql['headline'] ); ?></p>
					<p class="bouncer-quick-score-note">
						<?php
						echo esc_html(
							sprintf(
								/* translators: 1: score 0-100, 2: plain sentence */
								__( 'Bouncer score: %1$d/100 — %2$s', 'bouncer' ),
								$ql['score'],
								$ql['score_sentence']
							)
						);
						?>
					</p>
					<ul class="bouncer-quick-bullets">
						<?php foreach ( $ql['bullets'] as $bullet ) : ?>
							<li><?php echo esc_html( $bullet ); ?></li>
						<?php endforeach; ?>
					</ul>
					<p class="bouncer-quick-badge-wrap"><?php echo wp_kses_post( $this->render_risk_badge( (int) $manifest['risk_score'] ) ); ?></p>
				</div>

				<?php if ( ! empty( $manifest['ai_assessment'] ) ) : ?>
				<details class="bouncer-deep-dive-block">
					<summary><?php esc_html_e( 'Deep Dive (Claude) — full story (tap to expand)', 'bouncer' ); ?></summary>
					<div class="bouncer-deep-dive-body">
						<?php echo esc_html( $manifest['ai_assessment'] ); ?>
					</div>
				</details>
				<?php else : ?>
				<p class="description bouncer-deep-dive-empty">
					<?php
					if ( ! $ai_on ) {
						esc_html_e( 'No Deep Dive text on file. Turn on Deep Dive under Tools → Bouncer → Settings, add an Anthropic key, then run the scan again.', 'bouncer' );
					} elseif ( $ai_on && ! $deep_ok ) {
						esc_html_e( 'No Deep Dive text on file. Deep Dive is enabled, but no API key is available — configure Settings → Connectors (or ANTHROPIC_API_KEY), then scan again.', 'bouncer' );
					} else {
						esc_html_e( 'No Deep Dive text on file yet. Your key is configured — click “Run Quick Look again” below to generate it.', 'bouncer' );
					}
					?>
				</p>
				<?php endif; ?>

				<h2><?php esc_html_e( 'Technical details (for troubleshooting)', 'bouncer' ); ?></h2>
				<pre class="bouncer-manifest-json"><?php echo esc_html( wp_json_encode( $manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) ); ?></pre>

				<button type="button" class="button bouncer-rescan" data-plugin="<?php echo esc_attr( $plugin_slug ); ?>">
					<?php esc_html_e( 'Run Quick Look again', 'bouncer' ); ?>
				</button>
				<span class="description" style="margin-left:8px;">
					<?php
					if ( $deep_ok ) {
						esc_html_e( 'This scan refreshes Quick Look and runs Deep Dive (Claude) because your API key is available.', 'bouncer' );
					} elseif ( $ai_on ) {
						esc_html_e( 'This scan refreshes Quick Look only until an Anthropic API key is configured.', 'bouncer' );
					} else {
						esc_html_e( 'This scan refreshes Quick Look. Enable Deep Dive in Settings to add Claude analysis.', 'bouncer' );
					}
					?>
				</span>
			<?php endif; ?>
		<?php
	}

	/**
	 * Settings tab body.
	 */
	private function render_settings_inner(): void {
		?>
			<h2 class="screen-reader-text"><?php esc_html_e( 'Settings', 'bouncer' ); ?></h2>

			<form method="post" action="options.php">
				<?php
				settings_fields( 'bouncer_settings' );
				wp_referer_field();
				?>

				<h2><?php esc_html_e( 'Operating Mode', 'bouncer' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Mode', 'bouncer' ); ?></th>
						<td>
							<select name="bouncer_mode">
								<option value="monitor" <?php selected( get_option( 'bouncer_mode' ), 'monitor' ); ?>><?php esc_html_e( 'Monitor — Log everything, block nothing', 'bouncer' ); ?></option>
								<option value="enforce" <?php selected( get_option( 'bouncer_mode' ), 'enforce' ); ?>><?php esc_html_e( 'Enforce — Actively block policy violations', 'bouncer' ); ?></option>
							</select>
							<p class="description"><?php esc_html_e( 'Start in Monitor mode to learn your plugins\' behavior before enabling enforcement.', 'bouncer' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Sampling Rate', 'bouncer' ); ?></th>
						<td>
							<input type="number" name="bouncer_sampling_rate" min="0" max="100" value="<?php echo esc_attr( get_option( 'bouncer_sampling_rate', 100 ) ); ?>" /> %
							<p class="description"><?php esc_html_e( 'Percentage of requests to monitor. Use 100% in staging, lower in production for performance.', 'bouncer' ); ?></p>
						</td>
					</tr>
				</table>

				<h2><?php esc_html_e( 'Monitoring Channels', 'bouncer' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Database Monitoring', 'bouncer' ); ?></th>
						<td><label><input type="checkbox" name="bouncer_db_monitoring" value="1" <?php checked( get_option( 'bouncer_db_monitoring' ) ); ?> /> <?php esc_html_e( 'Monitor database queries and attribute to plugins', 'bouncer' ); ?></label></td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'HTTP Monitoring', 'bouncer' ); ?></th>
						<td><label><input type="checkbox" name="bouncer_http_monitoring" value="1" <?php checked( get_option( 'bouncer_http_monitoring' ) ); ?> /> <?php esc_html_e( 'Monitor outbound HTTP requests', 'bouncer' ); ?></label></td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Hook Auditing', 'bouncer' ); ?></th>
						<td><label><input type="checkbox" name="bouncer_hook_auditing" value="1" <?php checked( get_option( 'bouncer_hook_auditing' ) ); ?> /> <?php esc_html_e( 'Audit hook registrations for anomalies', 'bouncer' ); ?></label></td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'File Integrity', 'bouncer' ); ?></th>
						<td><label><input type="checkbox" name="bouncer_file_integrity" value="1" <?php checked( get_option( 'bouncer_file_integrity' ) ); ?> /> <?php esc_html_e( 'Monitor plugin files for unauthorized changes', 'bouncer' ); ?></label></td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'REST monitoring', 'bouncer' ); ?></th>
						<td><label><input type="checkbox" name="bouncer_rest_monitoring" value="1" <?php checked( get_option( 'bouncer_rest_monitoring', true ) ); ?> /> <?php esc_html_e( 'Log unauthenticated POST/PUT/PATCH/DELETE REST requests', 'bouncer' ); ?></label></td>
					</tr>
				</table>

				<h2><?php esc_html_e( 'Smarter summaries (optional)', 'bouncer' ); ?></h2>
				<p class="description"><?php esc_html_e( 'Quick Look always runs on your server. Turn on Deep Dive for Claude (Anthropic) when you add a key.', 'bouncer' ); ?></p>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Deep Dive (Claude)', 'bouncer' ); ?></th>
						<td>
							<label><input type="checkbox" name="bouncer_ai_scanning" value="1" <?php checked( get_option( 'bouncer_ai_scanning' ) ); ?> /> <?php esc_html_e( 'Explain plugin updates in plain English via Anthropic Claude when you add a key', 'bouncer' ); ?></label>
							<p class="description">
								<?php
								echo wp_kses_post(
									sprintf(
										/* translators: 1: Anthropic terms URL, 2: privacy URL */
										__( 'Deep Dive sends structural fingerprints (not your source files) to Anthropic when it runs. Their <a href="%1$s" rel="noopener noreferrer" target="_blank">Commercial Terms</a> and <a href="%2$s" rel="noopener noreferrer" target="_blank">Privacy Policy</a> apply.', 'bouncer' ),
										'https://www.anthropic.com/legal/commercial-terms',
										'https://www.anthropic.com/legal/privacy'
									)
								);
								?>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Key status', 'bouncer' ); ?></th>
						<td>
							<?php
							$scanner = $this->bouncer->get_ai_scanner_if_available();
							if ( ! $scanner ) {
								$scanner = new Bouncer_Ai_Scanner( $this->bouncer->logger, $this->bouncer->manifest );
							}
							$source = $scanner->get_api_key_source();

							$source_labels = array(
								'connector_env'      => __( 'Connected via environment variable (ANTHROPIC_API_KEY)', 'bouncer' ),
								'connector_constant' => __( 'Connected via PHP constant (ANTHROPIC_API_KEY)', 'bouncer' ),
								'connector_db'       => __( 'Connected via Settings → Connectors', 'bouncer' ),
								'none'               => __( 'No key yet — Deep Dive is on pause', 'bouncer' ),
							);

							$label   = $source_labels[ $source ] ?? $source_labels['none'];
							$has_key = 'none' !== $source;
							?>

							<?php if ( $has_key ) : ?>
								<span class="bouncer-status-active">&#9679; <?php echo esc_html( $label ); ?></span>
							<?php else : ?>
								<span class="bouncer-status-inactive">&#9679; <?php echo esc_html( $label ); ?></span>
							<?php endif; ?>

							<p class="description">
								<?php
								printf(
									/* translators: %s: URL to Connectors settings page */
									wp_kses_post( __( 'Add or manage your Anthropic API key under <a href="%s">Settings &rarr; Connectors</a>, or use the ANTHROPIC_API_KEY environment variable / PHP constant.', 'bouncer' ) ),
									esc_url( admin_url( 'options-general.php?page=connectors' ) )
								);
								?>
							</p>
						</td>
					</tr>
				</table>

				<h2><?php esc_html_e( 'Notifications', 'bouncer' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Email', 'bouncer' ); ?></th>
						<td><input type="email" name="bouncer_notify_email" class="regular-text" value="<?php echo esc_attr( get_option( 'bouncer_notify_email', get_option( 'admin_email' ) ) ); ?>" /></td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Notify On', 'bouncer' ); ?></th>
						<td>
							<label><input type="checkbox" name="bouncer_notify_on_warning" value="1" <?php checked( get_option( 'bouncer_notify_on_warning' ) ); ?> /> <?php esc_html_e( 'Warnings', 'bouncer' ); ?></label><br>
							<label><input type="checkbox" name="bouncer_notify_on_critical" value="1" <?php checked( get_option( 'bouncer_notify_on_critical' ) ); ?> /> <?php esc_html_e( 'Critical events', 'bouncer' ); ?></label><br>
							<label><input type="checkbox" name="bouncer_notify_on_emergency" value="1" <?php checked( get_option( 'bouncer_notify_on_emergency' ) ); ?> /> <?php esc_html_e( 'Emergencies', 'bouncer' ); ?></label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Email digest', 'bouncer' ); ?></th>
						<td>
							<label><input type="checkbox" name="bouncer_digest_enabled" value="1" <?php checked( get_option( 'bouncer_digest_enabled' ) ); ?> /> <?php esc_html_e( 'Send periodic severity summaries to the email above', 'bouncer' ); ?></label>
							<p class="description">
								<label for="bouncer-digest-frequency"><?php esc_html_e( 'Frequency', 'bouncer' ); ?></label>
								<select name="bouncer_digest_frequency" id="bouncer-digest-frequency">
									<option value="daily" <?php selected( get_option( 'bouncer_digest_frequency', 'daily' ), 'daily' ); ?>><?php esc_html_e( 'Daily', 'bouncer' ); ?></option>
									<option value="weekly" <?php selected( get_option( 'bouncer_digest_frequency', 'daily' ), 'weekly' ); ?>><?php esc_html_e( 'Weekly', 'bouncer' ); ?></option>
								</select>
							</p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Webhook', 'bouncer' ); ?></th>
						<td>
							<label for="bouncer-webhook-url"><?php esc_html_e( 'Endpoint URL', 'bouncer' ); ?></label><br />
							<input type="url" name="bouncer_webhook_url" id="bouncer-webhook-url" class="large-text code" value="<?php echo esc_attr( get_option( 'bouncer_webhook_url', '' ) ); ?>" placeholder="https://example.com/hooks/bouncer" />
							<p class="description"><?php esc_html_e( 'POST JSON batches of new events. Empty disables delivery.', 'bouncer' ); ?></p>
							<label for="bouncer-webhook-secret"><?php esc_html_e( 'Signing secret', 'bouncer' ); ?></label><br />
							<input type="password" name="bouncer_webhook_secret" id="bouncer-webhook-secret" class="regular-text" value="<?php echo esc_attr( get_option( 'bouncer_webhook_secret', '' ) ); ?>" autocomplete="off" />
							<p class="description"><?php esc_html_e( 'Optional. When set, Bouncer sends header X-Bouncer-Signature: HMAC-SHA256 of the raw JSON body.', 'bouncer' ); ?></p>
							<label for="bouncer-webhook-min-sev"><?php esc_html_e( 'Minimum severity for webhooks', 'bouncer' ); ?></label>
							<select name="bouncer_webhook_min_severity" id="bouncer-webhook-min-sev">
								<?php
								$wm = get_option( 'bouncer_webhook_min_severity', 'warning' );
								foreach ( array( 'info', 'warning', 'critical', 'emergency' ) as $sev ) {
									printf(
										'<option value="%1$s" %2$s>%3$s</option>',
										esc_attr( $sev ),
										selected( $wm, $sev, false ),
										esc_html( ucfirst( $sev ) )
									);
								}
								?>
							</select>
						</td>
					</tr>
				</table>

				<h2><?php esc_html_e( 'Data', 'bouncer' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Log Retention', 'bouncer' ); ?></th>
						<td>
							<input type="number" name="bouncer_log_retention_days" min="1" max="365" value="<?php echo esc_attr( get_option( 'bouncer_log_retention_days', 30 ) ); ?>" /> <?php esc_html_e( 'days', 'bouncer' ); ?>
						</td>
					</tr>
				</table>

				<?php submit_button(); ?>
			</form>
		<?php
	}

	/**
	 * Add Bouncer column to plugins list.
	 *
	 * @param array $columns Existing columns.
	 * @return array Modified columns.
	 */
	public function add_plugin_column( $columns ) {
		if ( ! bouncer_current_user_can_manage() ) {
			return $columns;
		}
		$columns['bouncer_risk'] = __( 'Bouncer', 'bouncer' );
		return $columns;
	}

	/**
	 * Render the Bouncer column content for each plugin.
	 *
	 * @param string $column_name Column name.
	 * @param string $plugin_file Plugin file path.
	 * @param array  $plugin_data Plugin data.
	 */
	public function render_plugin_column( $column_name, $plugin_file, $plugin_data ) {
		if ( 'bouncer_risk' !== $column_name ) {
			return;
		}

		if ( ! bouncer_current_user_can_manage() ) {
			return;
		}

		$slug = dirname( $plugin_file );
		if ( '.' === $slug ) {
			$slug = basename( $plugin_file, '.php' );
		}

		// Skip Bouncer itself.
		if ( 'bouncer' === $slug ) {
			echo '<span class="bouncer-badge bouncer-badge-info">' . esc_html__( 'Self', 'bouncer' ) . '</span>';
			return;
		}

		$manifest = $this->bouncer->manifest->get_manifest( $slug );

		if ( ! $manifest ) {
			echo '<span class="bouncer-badge bouncer-badge-unknown">' . esc_html__( 'Unscanned', 'bouncer' ) . '</span>';
			return;
		}

		echo wp_kses_post( $this->render_risk_badge( $manifest['risk_score'] ) );
	}

	/**
	 * Render a risk score badge.
	 *
	 * @param int $score Risk score (0-100).
	 * @return string HTML badge.
	 */
	private function render_risk_badge( $score ) {
		$score = intval( $score );
		if ( $score <= 20 ) {
			$class = 'bouncer-risk-low';
			$label = __( 'Low', 'bouncer' );
		} elseif ( $score <= 50 ) {
			$class = 'bouncer-risk-medium';
			$label = __( 'Medium', 'bouncer' );
		} else {
			$class = 'bouncer-risk-high';
			$label = __( 'High', 'bouncer' );
		}

		$headline = class_exists( 'Bouncer_AI_Experience' ) ? Bouncer_AI_Experience::headline_for_score( $score ) : '';
		$title    = $headline
			? sprintf(
				/* translators: 1: plain-English headline, 2: numeric score */
				__( '%1$s — score %2$d/100', 'bouncer' ),
				$headline,
				$score
			)
			: sprintf(
				/* translators: %d: risk score */
				__( 'Risk score: %d/100', 'bouncer' ),
				$score
			);

		return sprintf(
			'<span class="bouncer-risk-badge %s" title="%s">%s (%d)</span>',
			esc_attr( $class ),
			esc_attr( $title ),
			esc_html( $label ),
			$score
		);
	}

	/**
	 * Show admin notices.
	 */
	public function show_admin_notices() {
		if ( ! bouncer_current_user_can_manage() ) {
			return;
		}

		if ( $this->bouncer->get_setting( 'ai_scanning' ) ) {
			if ( ! $this->bouncer->get_ai_scanner_if_available() ) {
				echo '<div class="notice notice-warning"><p>';
				printf(
					wp_kses_post(
						/* translators: %s: URL to the Connectors settings admin page. */
						__( '<strong>Bouncer:</strong> Deep Dive is on, but no Anthropic API key is configured yet. Quick Look still works. Add a key in <a href="%s">Settings → Connectors</a> (or set ANTHROPIC_API_KEY in the environment / as a PHP constant).', 'bouncer' )
					),
					esc_url( admin_url( 'options-general.php?page=connectors' ) )
				);
				echo '</p></div>';
			}
		}
	}

	/**
	 * AJAX: Trigger a plugin scan.
	 */
	public function ajax_scan_plugin() {
		check_ajax_referer( 'bouncer_admin', 'nonce' );

		if ( ! bouncer_current_user_can_manage() ) {
			wp_send_json_error( __( 'Permission denied.', 'bouncer' ) );
		}

		if ( ! Bouncer_Rest_Scan_Limiter::allow() ) {
			wp_send_json_error(
				array(
					'message' => __( 'Too many scans in a short window. Wait a minute and try again.', 'bouncer' ),
					'code'    => 'rate_limited',
				)
			);
		}

		$plugin_slug = isset( $_POST['plugin'] ) ? sanitize_text_field( wp_unslash( $_POST['plugin'] ) ) : '';
		if ( empty( $plugin_slug ) || ! Bouncer_Installed_Plugins::is_valid_slug_format( $plugin_slug ) ) {
			wp_send_json_error( __( 'Invalid plugin slug.', 'bouncer' ) );
		}

		if ( ! Bouncer_Installed_Plugins::is_installed_slug( $plugin_slug ) ) {
			wp_send_json_error( __( 'That plugin is not installed.', 'bouncer' ) );
		}

		$manifest = $this->bouncer->manifest->generate_for_plugin( $plugin_slug );

		// Run Deep Dive (Claude) if available (resolve lazily — Connectors load after Bouncer’s early bootstrap).
		$ai_result      = null;
		$ai_scanner     = $this->bouncer->get_ai_scanner_if_available();
		if ( $ai_scanner ) {
			$ai_result = $ai_scanner->scan_plugin( $plugin_slug );
		}

		wp_send_json_success(
			array(
				'manifest'  => $manifest,
				'ai_result' => $ai_result,
			)
		);
	}

	/**
	 * AJAX: Scan up to N installed plugins in one request (one rate-limit slot).
	 */
	public function ajax_scan_batch() {
		check_ajax_referer( 'bouncer_admin', 'nonce' );

		if ( ! bouncer_current_user_can_manage() ) {
			wp_send_json_error( __( 'Permission denied.', 'bouncer' ) );
		}

		if ( ! Bouncer_Rest_Scan_Limiter::allow() ) {
			wp_send_json_error(
				array(
					'message' => __( 'Too many scans in a short window. Wait a minute and try again.', 'bouncer' ),
					'code'    => 'rate_limited',
				)
			);
		}

		// phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized -- JSON array of slugs; each entry is sanitized in the loop below.
		$raw = isset( $_POST['slugs'] ) ? wp_unslash( $_POST['slugs'] ) : '[]';
		$arr = json_decode( $raw, true );
		if ( ! is_array( $arr ) ) {
			wp_send_json_error( __( 'Invalid request.', 'bouncer' ) );
		}

		$max = $this->bouncer->get_ai_scanner_if_available()
			? (int) apply_filters( 'bouncer_scan_batch_max_with_ai', 3 )
			: (int) apply_filters( 'bouncer_scan_batch_max_quick_only', 10 );
		$max = max( 1, min( 20, $max ) );

		$ai_scanner = $this->bouncer->get_ai_scanner_if_available();
		$results    = array();

		$n = 0;
		foreach ( $arr as $item ) {
			if ( $n >= $max ) {
				break;
			}
			if ( ! is_string( $item ) ) {
				continue;
			}
			$slug = sanitize_text_field( $item );
			if ( ! Bouncer_Installed_Plugins::is_valid_slug_format( $slug ) || ! Bouncer_Installed_Plugins::is_installed_slug( $slug ) ) {
				continue;
			}

			$manifest = $this->bouncer->manifest->generate_for_plugin( $slug );
			$ai       = null;
			if ( $ai_scanner ) {
				$ai = $ai_scanner->scan_plugin( $slug );
			}

			$results[] = array(
				'slug'        => $slug,
				'manifest_ok' => null !== $manifest,
				'deep_dive'   => null !== $ai,
			);
			++$n;
		}

		wp_send_json_success(
			array(
				'results'   => $results,
				'processed' => count( $results ),
			)
		);
	}

	/**
	 * AJAX: Generate manifest for a plugin.
	 */
	public function ajax_generate_manifest() {
		check_ajax_referer( 'bouncer_admin', 'nonce' );

		if ( ! bouncer_current_user_can_manage() ) {
			wp_send_json_error( __( 'Permission denied.', 'bouncer' ) );
		}

		if ( ! Bouncer_Rest_Scan_Limiter::allow() ) {
			wp_send_json_error(
				array(
					'message' => __( 'Too many scans in a short window. Wait a minute and try again.', 'bouncer' ),
					'code'    => 'rate_limited',
				)
			);
		}

		$plugin_slug = isset( $_POST['plugin'] ) ? sanitize_text_field( wp_unslash( $_POST['plugin'] ) ) : '';
		if ( empty( $plugin_slug ) || ! Bouncer_Installed_Plugins::is_valid_slug_format( $plugin_slug ) ) {
			wp_send_json_error( __( 'Invalid plugin slug.', 'bouncer' ) );
		}

		if ( ! Bouncer_Installed_Plugins::is_installed_slug( $plugin_slug ) ) {
			wp_send_json_error( __( 'That plugin is not installed.', 'bouncer' ) );
		}

		$manifest = $this->bouncer->manifest->generate_for_plugin( $plugin_slug );
		wp_send_json_success( array( 'manifest' => $manifest ) );
	}

	/**
	 * AJAX: Dismiss a notice.
	 */
	public function ajax_dismiss_notice() {
		check_ajax_referer( 'bouncer_admin', 'nonce' );

		if ( ! bouncer_current_user_can_manage() ) {
			wp_send_json_error( __( 'Permission denied.', 'bouncer' ) );
		}

		$notice = isset( $_POST['notice'] ) ? sanitize_key( wp_unslash( $_POST['notice'] ) ) : '';
		if ( $notice && preg_match( '/^[a-z0-9_]+$/', $notice ) ) {
			update_option( 'bouncer_dismissed_' . $notice, true );
		}

		wp_send_json_success();
	}
}
