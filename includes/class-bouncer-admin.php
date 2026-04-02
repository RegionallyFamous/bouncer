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
					'scanning'       => __( 'Looking under the hood…', 'bouncer' ),
					'complete'       => __( 'All set — that scan’s done', 'bouncer' ),
					'error'          => __( 'That scan didn’t finish — want to try again?', 'bouncer' ),
					'confirm'        => __( 'Sure you want to do that?', 'bouncer' ),
					'scanAll'        => __( 'Scan every installed plugin', 'bouncer' ),
					'scanAllRunning' => __( 'Working through your plugins…', 'bouncer' ),
					/* translators: 1: number finished, 2: total plugins */
					'scanAllProgress' => __( 'Checked %1$d of %2$d…', 'bouncer' ),
					'scanAllDone'     => __( 'Finished the batch — refreshing the page…', 'bouncer' ),
					'rateLimited'     => __( 'Whoa — slow down a minute, then hit the button again to finish the rest.', 'bouncer' ),
					'scanAllEmpty'    => __( 'No plugins to scan here right now.', 'bouncer' ),
					/* translators: %d: number of plugins not yet scanned */
					'continueScanLeft' => __( 'Keep going (%d left)', 'bouncer' ),
				),
			)
		);
	}

	/**
	 * Risk band slug for table row accents (matches render_risk_badge thresholds).
	 *
	 * @param int $score Risk score 0–100.
	 * @return string low|medium|high
	 */
	private function risk_row_class_for_score( int $score ): string {
		if ( $score <= 20 ) {
			return 'low';
		}
		if ( $score <= 50 ) {
			return 'medium';
		}
		return 'high';
	}

	/**
	 * Prioritized “what needs attention” strip for the dashboard.
	 *
	 * @param array<string, int> $counts Severity counts (last 7 days).
	 */
	private function render_dashboard_at_a_glance( array $counts ): void {
		$db_dropin   = (bool) get_option( 'bouncer_db_dropin_installed', false );
		$db_conflict = (bool) get_option( 'bouncer_db_dropin_conflict', false );
		$mode        = $this->bouncer->get_setting( 'mode', 'monitor' );
		$db_works    = $db_dropin && ! $db_conflict;
		$db_wanted   = $this->bouncer->get_setting( 'db_monitoring' );

		$installed = Bouncer_Installed_Plugins::get_by_slug();
		$by_slug   = $this->get_latest_manifest_rows_by_slug();
		$unscanned = 0;
		foreach ( array_keys( $installed ) as $slug ) {
			if ( ! isset( $by_slug[ $slug ] ) ) {
				++$unscanned;
			}
		}

		$items = array();

		if ( (int) $counts['emergency'] > 0 || (int) $counts['critical'] > 0 ) {
			$sev = (int) $counts['emergency'] > 0 ? 'emergency' : 'critical';
			$items[] = array(
				'priority' => 1,
				'tier'     => 'urgent',
				'icon'     => 'dashicons-warning',
				'title'    => __( 'Something loud happened in the last week', 'bouncer' ),
				'hint'     => __( 'There are serious entries in your event log worth reviewing soon.', 'bouncer' ),
				'url'      => bouncer_admin_url( 'events', array( 'severity' => $sev ) ),
				'link'     => __( 'Peek the Event Log →', 'bouncer' ),
			);
		}

		if ( $db_conflict ) {
			$items[] = array(
				'priority' => 2,
				'tier'     => 'serious',
				'icon'     => 'dashicons-database',
				'title'    => __( 'Another tool is already sitting on your database door', 'bouncer' ),
				'hint'     => __( 'We can’t tag database queries to a plugin until that’s sorted. Your other watches still run.', 'bouncer' ),
				'url'      => bouncer_admin_url( 'settings' ),
				'link'     => __( 'What to do next (Settings) →', 'bouncer' ),
			);
		}

		if ( 'enforce' === $mode && ! $this->bouncer->get_setting( 'http_monitoring' ) ) {
			$items[] = array(
				'priority' => 3,
				'tier'     => 'serious',
				'icon'     => 'dashicons-admin-site-alt3',
				'title'    => __( 'Outbound web watching is snoozing', 'bouncer' ),
				'hint'     => __( 'You’re in “stop the bad stuff” mode, but HTTP checking is off—odd external calls won’t get caught.', 'bouncer' ),
				'url'      => bouncer_admin_url( 'settings' ),
				'link'     => __( 'Turn it on in Settings →', 'bouncer' ),
			);
		}

		if ( 'enforce' === $mode && ! $this->bouncer->get_setting( 'file_integrity' ) ) {
			$items[] = array(
				'priority' => 3,
				'tier'     => 'serious',
				'icon'     => 'dashicons-shield',
				'title'    => __( 'File tamper auto-response is paused', 'bouncer' ),
				'hint'     => __( 'Enforce mode is on, but file integrity is off—Bouncer won’t auto-step in if plugin files change unexpectedly.', 'bouncer' ),
				'url'      => bouncer_admin_url( 'settings' ),
				'link'     => __( 'Wake that watch in Settings →', 'bouncer' ),
			);
		}

		if ( $db_wanted && ! $db_works && ! $db_conflict ) {
			$items[] = array(
				'priority' => 3,
				'tier'     => '',
				'icon'     => 'dashicons-database',
				'title'    => __( 'Database tagging isn’t fully hooked up yet', 'bouncer' ),
				'hint'     => __( 'You asked to watch the database, but the extra hook isn’t active—usually a quick settings or reinstall step.', 'bouncer' ),
				'url'      => bouncer_admin_url( 'settings' ),
				'link'     => __( 'Check Settings →', 'bouncer' ),
			);
		}

		if ( $this->bouncer->get_setting( 'ai_scanning' ) && null === $this->bouncer->get_ai_scanner_if_available() ) {
			$items[] = array(
				'priority' => 4,
				'tier'     => '',
				'icon'     => 'dashicons-welcome-learn-more',
				'title'    => __( 'Deep Dive is waiting on a key', 'bouncer' ),
				'hint'     => __( 'Quick Look still runs on your server. Add your Anthropic key when you want the longer story.', 'bouncer' ),
				'url'      => admin_url( 'options-general.php?page=connectors' ),
				'link'     => __( 'Open Connectors →', 'bouncer' ),
			);
		}

		if ( $unscanned > 0 && count( $installed ) > 0 ) {
			$items[] = array(
				'priority' => 4,
				'tier'     => '',
				'icon'     => 'dashicons-admin-plugins',
				'title'    => sprintf(
					/* translators: %d: number of plugins without a saved manifest */
					__( '%d plugin(s) haven’t had a Quick Look yet', 'bouncer' ),
					$unscanned
				),
				'hint'     => __( 'Cheat sheets help Bouncer know what each plugin is allowed to do.', 'bouncer' ),
				'url'      => bouncer_admin_url( 'manifests' ),
				'link'     => __( 'Run scans in Manifests →', 'bouncer' ),
			);
		}

		usort(
			$items,
			static function ( $a, $b ) {
				return (int) $a['priority'] <=> (int) $b['priority'];
			}
		);

		$has_urgent = false;
		foreach ( $items as $it ) {
			if ( 1 === (int) $it['priority'] ) {
				$has_urgent = true;
				break;
			}
		}

		if ( empty( $items ) ) {
			$band_class = 'bouncer-at-a-glance__band--calm';
			$title      = __( 'Nice and quiet at the door', 'bouncer' );
			$lede       = __( 'You’re good — nothing needs your attention right now. The cards below are there when you want more detail.', 'bouncer' );
		} elseif ( $has_urgent ) {
			$band_class = 'bouncer-at-a-glance__band--alert';
			$title      = __( 'Heads up — start with the big stuff', 'bouncer' );
			$lede       = __( 'We lined up the loudest items first so you know where to tap.', 'bouncer' );
		} else {
			$band_class = 'bouncer-at-a-glance__band--watch';
			$title      = __( 'A few things could use a peek', 'bouncer' );
			$lede       = __( 'Nothing scary by default—just some friendly nudges when something’s off.', 'bouncer' );
		}

		?>
		<section class="bouncer-at-a-glance" aria-labelledby="bouncer-glance-heading">
			<div class="bouncer-at-a-glance__band <?php echo esc_attr( $band_class ); ?>">
				<div class="bouncer-at-a-glance__headline">
					<span class="bouncer-at-a-glance__eyebrow"><?php esc_html_e( 'At a glance', 'bouncer' ); ?></span>
					<h2 id="bouncer-glance-heading" class="bouncer-at-a-glance__title"><?php echo esc_html( $title ); ?></h2>
					<p class="bouncer-at-a-glance__lede"><?php echo esc_html( $lede ); ?></p>
				</div>
				<?php if ( ! empty( $items ) ) : ?>
				<ul class="bouncer-at-a-glance__list">
					<?php foreach ( $items as $item ) : ?>
					<li class="bouncer-glance-item<?php echo $item['tier'] ? ' bouncer-glance-item--' . esc_attr( $item['tier'] ) : ''; ?>">
						<span class="dashicons <?php echo esc_attr( $item['icon'] ); ?>" aria-hidden="true"></span>
						<div class="bouncer-glance-item__body">
							<span class="bouncer-glance-item__title"><?php echo esc_html( $item['title'] ); ?></span>
							<span class="bouncer-glance-item__hint"><?php echo esc_html( $item['hint'] ); ?></span>
							<a class="bouncer-glance-item__link" href="<?php echo esc_url( $item['url'] ); ?>"><?php echo esc_html( $item['link'] ); ?></a>
						</div>
					</li>
					<?php endforeach; ?>
				</ul>
				<?php endif; ?>
			</div>
		</section>
		<?php
	}

	/**
	 * Dashboard severity metric cards with drill-down links.
	 *
	 * @param array<string, int> $counts Severity counts (last 7 days).
	 */
	private function render_dashboard_metric_cards( array $counts ): void {
		$defs = array(
			array(
				'key'   => 'info',
				'class' => 'bouncer-metric-card--info',
				'label' => __( 'FYI notes', 'bouncer' ),
			),
			array(
				'key'   => 'warning',
				'class' => 'bouncer-metric-card--warning',
				'label' => __( 'Worth a look', 'bouncer' ),
			),
			array(
				'key'   => 'critical',
				'class' => 'bouncer-metric-card--critical',
				'label' => __( 'Serious flags', 'bouncer' ),
			),
			array(
				'key'   => 'emergency',
				'class' => 'bouncer-metric-card--emergency',
				'label' => __( 'Big deals', 'bouncer' ),
			),
		);
		?>
		<div class="bouncer-metrics" role="list">
			<?php foreach ( $defs as $def ) : ?>
				<?php
				$n = isset( $counts[ $def['key'] ] ) ? (int) $counts[ $def['key'] ] : 0;
				?>
			<div class="bouncer-metric-card <?php echo esc_attr( $def['class'] ); ?>" role="listitem">
				<span class="bouncer-metric-card__value"><?php echo esc_html( number_format( $n ) ); ?></span>
				<span class="bouncer-metric-card__label"><?php echo esc_html( $def['label'] ); ?></span>
				<?php if ( $n > 0 ) : ?>
				<a class="bouncer-metric-card__link" href="<?php echo esc_url( bouncer_admin_url( 'events', array( 'severity' => $def['key'] ) ) ); ?>">
					<?php esc_html_e( 'Take a look →', 'bouncer' ); ?>
				</a>
				<?php endif; ?>
			</div>
			<?php endforeach; ?>
		</div>
		<?php
	}

	/**
	 * Dashboard: channel status as responsive cards.
	 */
	private function render_dashboard_channel_grid(): void {
		$db_dropin   = (bool) get_option( 'bouncer_db_dropin_installed', false );
		$db_conflict = (bool) get_option( 'bouncer_db_dropin_conflict', false );
		$db_ok       = $db_dropin && ! $db_conflict;

		$deep_ready = $this->bouncer->get_setting( 'ai_scanning' ) && null !== $this->bouncer->get_ai_scanner_if_available();
		$ai_enabled = $this->bouncer->get_setting( 'ai_scanning' );

		$http_on   = (bool) $this->bouncer->get_setting( 'http_monitoring' );
		$hook_on   = (bool) $this->bouncer->get_setting( 'hook_auditing' );
		$file_on   = (bool) $this->bouncer->get_setting( 'file_integrity' );
		$rest_on   = (bool) $this->bouncer->get_setting( 'rest_monitoring' );

		$channels = array(
			array(
				'name'       => __( 'Database query tags', 'bouncer' ),
				'card_tone'  => $db_ok ? 'on' : ( $db_conflict ? 'maybe' : 'off' ),
				'pill'       => $db_ok ? __( 'Watching', 'bouncer' ) : ( $db_conflict ? __( 'Needs attention', 'bouncer' ) : __( 'Not watching', 'bouncer' ) ),
				'pill_c'     => $db_ok ? 'on' : ( $db_conflict ? 'key' : 'off' ),
				'hint'       => $db_ok
					? __( 'We can tell which plugin touched the database on each request.', 'bouncer' )
					: ( $db_conflict
						? __( 'Another db.php is in place—see Settings for the friendly version of what that means.', 'bouncer' )
						: __( 'Flip this on in Settings when you want SQL lines tied to plugins.', 'bouncer' ) ),
				'action_url' => $db_ok ? '' : bouncer_admin_url( 'settings' ),
				'action_txt' => __( 'Open Settings →', 'bouncer' ),
			),
			array(
				'name'       => __( 'Outbound web calls', 'bouncer' ),
				'card_tone'  => $http_on ? 'on' : 'off',
				'pill'       => $http_on ? __( 'Watching', 'bouncer' ) : __( 'Snoozing', 'bouncer' ),
				'pill_c'     => $http_on ? 'on' : 'off',
				'hint'       => __( 'Spots unexpected trips to the wider internet.', 'bouncer' ),
				'action_url' => $http_on ? '' : bouncer_admin_url( 'settings' ),
				'action_txt' => __( 'Flip it on in Settings →', 'bouncer' ),
			),
			array(
				'name'       => __( 'Hook sign-in sheet', 'bouncer' ),
				'card_tone'  => $hook_on ? 'on' : 'off',
				'pill'       => $hook_on ? __( 'Watching', 'bouncer' ) : __( 'Snoozing', 'bouncer' ),
				'pill_c'     => $hook_on ? 'on' : 'off',
				'hint'       => __( 'Keeps an eye on who registers sensitive WordPress hooks.', 'bouncer' ),
				'action_url' => $hook_on ? '' : bouncer_admin_url( 'settings' ),
				'action_txt' => __( 'Flip it on in Settings →', 'bouncer' ),
			),
			array(
				'name'       => __( 'File fingerprints', 'bouncer' ),
				'card_tone'  => $file_on ? 'on' : 'off',
				'pill'       => $file_on ? __( 'Watching', 'bouncer' ) : __( 'Snoozing', 'bouncer' ),
				'pill_c'     => $file_on ? 'on' : 'off',
				'hint'       => __( 'Notices when plugin files change without a hall pass.', 'bouncer' ),
				'action_url' => $file_on ? '' : bouncer_admin_url( 'settings' ),
				'action_txt' => __( 'Flip it on in Settings →', 'bouncer' ),
			),
			array(
				'name'       => __( 'Quick Look (automatic)', 'bouncer' ),
				'card_tone'  => 'on',
				'pill'       => __( 'Always on', 'bouncer' ),
				'pill_c'     => 'on',
				'hint'       => __( 'Runs on your server for every scan—no outside API.', 'bouncer' ),
				'action_url' => '',
				'action_txt' => '',
			),
			array(
				'name'       => __( 'Deep Dive (Claude)', 'bouncer' ),
				'card_tone'  => $deep_ready ? 'on' : ( $ai_enabled ? 'maybe' : 'off' ),
				'pill'       => $deep_ready ? __( 'Ready', 'bouncer' ) : ( $ai_enabled ? __( 'Needs a key', 'bouncer' ) : __( 'Optional / off', 'bouncer' ) ),
				'pill_c'     => $deep_ready ? 'on' : ( $ai_enabled ? 'key' : 'off' ),
				'hint'       => $deep_ready
					? __( 'Longer plain-English story when you scan.', 'bouncer' )
					: ( $ai_enabled
						? __( 'Add a key under Connectors to unlock AI summaries.', 'bouncer' )
						: __( 'Enable under Settings if you want Claude’s take.', 'bouncer' ) ),
				'action_url' => $deep_ready ? '' : ( $ai_enabled ? admin_url( 'options-general.php?page=connectors' ) : bouncer_admin_url( 'settings' ) ),
				'action_txt' => $deep_ready ? '' : ( $ai_enabled ? __( 'Add a key →', 'bouncer' ) : __( 'Flip it on in Settings →', 'bouncer' ) ),
			),
			array(
				'name'       => __( 'REST write attempts (guests)', 'bouncer' ),
				'card_tone'  => $rest_on ? 'on' : 'off',
				'pill'       => $rest_on ? __( 'Watching', 'bouncer' ) : __( 'Snoozing', 'bouncer' ),
				'pill_c'     => $rest_on ? 'on' : 'off',
				'hint'       => __( 'Logs POST/PUT/PATCH/DELETE when someone isn’t logged in.', 'bouncer' ),
				'action_url' => $rest_on ? '' : bouncer_admin_url( 'settings' ),
				'action_txt' => __( 'Flip it on in Settings →', 'bouncer' ),
			),
		);

		?>
		<h2 class="bouncer-channels-heading"><?php esc_html_e( 'What we’re watching', 'bouncer' ); ?></h2>
		<div class="bouncer-channel-grid" role="list">
			<?php foreach ( $channels as $ch ) : ?>
			<div class="bouncer-channel-card bouncer-channel-card--<?php echo esc_attr( $ch['card_tone'] ); ?>" role="listitem">
				<h3 class="bouncer-channel-card__name"><?php echo esc_html( $ch['name'] ); ?></h3>
				<span class="bouncer-channel-card__pill bouncer-channel-card__pill--<?php echo esc_attr( $ch['pill_c'] ); ?>"><?php echo esc_html( $ch['pill'] ); ?></span>
				<p class="bouncer-channel-card__hint"><?php echo esc_html( $ch['hint'] ); ?></p>
				<?php if ( $ch['action_url'] && $ch['action_txt'] ) : ?>
				<a class="bouncer-channel-card__action" href="<?php echo esc_url( $ch['action_url'] ); ?>"><?php echo esc_html( $ch['action_txt'] ); ?></a>
				<?php endif; ?>
			</div>
			<?php endforeach; ?>
		</div>
		<?php
	}

	/**
	 * Dashboard tab body (shell is render_app).
	 */
	private function render_dashboard_inner(): void {
		$counts         = $this->bouncer->logger->get_severity_counts( 7 );
		$plugin_summary = $this->bouncer->logger->get_plugin_summary( 7 );
		$mode           = $this->bouncer->get_setting( 'mode', 'monitor' );

		?>
			<h2 class="screen-reader-text"><?php esc_html_e( 'Overview', 'bouncer' ); ?></h2>

			<?php $this->render_dashboard_at_a_glance( $counts ); ?>

			<div class="bouncer-mode-row">
				<span class="bouncer-mode-badge bouncer-mode-<?php echo esc_attr( 'enforce' === $mode ? 'enforce' : 'monitor' ); ?>">
					<?php
					if ( 'enforce' === $mode ) {
						esc_html_e( 'On duty at the door (Enforce)', 'bouncer' );
					} else {
						esc_html_e( 'Taking notes first (Monitor)', 'bouncer' );
					}
					?>
				</span>
			</div>

			<div class="bouncer-card-notice bouncer-enforce-summary">
				<p>
					<?php
					$fi_on = $this->bouncer->get_setting( 'file_integrity' );
					if ( 'enforce' === $mode && $fi_on ) {
						esc_html_e( 'Monitor is “see everything, block nothing.” Enforce can block sketchy outbound web calls that break a plugin’s cheat sheet, and—with file watching on—can park a plugin if its files change in a sketchy way. Database oddities get logged; queries themselves aren’t blocked.', 'bouncer' );
					} elseif ( 'enforce' === $mode && ! $fi_on ) {
						esc_html_e( 'You’re in Enforce, but file watching is off—so Bouncer won’t auto-pause plugins for surprise file edits until you turn that channel on in Settings. Outbound web rules still apply when HTTP watching is on.', 'bouncer' );
					} else {
						esc_html_e( 'Monitor watches and learns. Flip to Enforce when you want outbound web rules and (with file watching) stronger responses to tampering. Database issues are logged, not blocked.', 'bouncer' );
					}
					?>
				</p>
			</div>

			<?php $this->render_ai_modes_intro(); ?>

			<?php $this->render_installed_plugins_scan_panel(); ?>

			<?php $this->render_dashboard_metric_cards( $counts ); ?>

			<?php $this->render_dashboard_channel_grid(); ?>

			<?php if ( ! empty( $plugin_summary ) ) : ?>
			<div class="bouncer-plugin-summary">
				<h2><?php esc_html_e( 'Who’s been chatty (last 7 days)', 'bouncer' ); ?></h2>
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
									<?php esc_html_e( 'See the log →', 'bouncer' ); ?>
								</a>
								|
								<a href="<?php echo esc_url( bouncer_admin_url( 'manifests', array( 'plugin' => $plugin->plugin_slug ) ) ); ?>">
									<?php esc_html_e( 'Cheat sheet →', 'bouncer' ); ?>
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
					esc_html_e( 'Quick Look runs on your server every time. Deep Dive is on and your key is set, so scans can add Claude’s longer plain-English notes.', 'bouncer' );
				} elseif ( $ai_on && ! $deep_ok ) {
					esc_html_e( 'Quick Look still runs on your server. Deep Dive is toggled on, but there’s no Anthropic key yet—add one under Settings → Connectors (or ANTHROPIC_API_KEY) when you want the extra story.', 'bouncer' );
				} else {
					esc_html_e( 'Quick Look is always there on your server. Deep Dive is optional—flip it on under Bouncer → Settings when you want Claude’s take.', 'bouncer' );
				}
				?>
			</p>
			<div class="bouncer-ai-modes-grid">
				<div class="bouncer-ai-mode-card bouncer-ai-mode-quick">
					<span class="dashicons dashicons-search" aria-hidden="true"></span>
					<h3><?php esc_html_e( 'Quick Look', 'bouncer' ); ?></h3>
					<p><?php esc_html_e( 'Fast pass on your server: a score, a vibe check, and a few short bullets. No outside API.', 'bouncer' ); ?></p>
				</div>
				<div class="bouncer-ai-mode-card bouncer-ai-mode-deep">
					<span class="dashicons dashicons-welcome-learn-more" aria-hidden="true"></span>
					<h3><?php esc_html_e( 'Deep Dive (Claude)', 'bouncer' ); ?></h3>
					<p>
						<?php
						if ( $deep_ok ) {
							esc_html_e( 'Claude adds a longer read from a compact sketch of the code—not the raw files—under Anthropic’s terms.', 'bouncer' );
						} elseif ( $ai_on ) {
							esc_html_e( 'Waiting on an API key in Connectors or ANTHROPIC_API_KEY.', 'bouncer' );
						} else {
							esc_html_e( 'Optional: turn it on in Bouncer → Settings, then add your key in Connectors.', 'bouncer' );
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
			<h2><?php esc_html_e( 'Plugin cheat sheets', 'bouncer' ); ?></h2>
			<p class="description">
				<?php
				echo esc_html(
					sprintf(
						/* translators: 1: number of plugins with a stored manifest, 2: total installed plugins */
						__( 'You’ve got %2$d plugins installed; %1$d already have a Quick Look cheat sheet saved.', 'bouncer' ),
						$have,
						$n
					)
				);
				?>
			</p>
			<p>
				<a class="button button-primary" href="<?php echo esc_url( $url ); ?>"><?php esc_html_e( 'Open Manifests & scanning', 'bouncer' ); ?></a>
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
						esc_html_e( 'WordPress isn’t listing any plugins in this context—odd, but it happens on some setups.', 'bouncer' );
					} else {
						echo esc_html(
							sprintf(
								/* translators: 1: plugins with a manifest, 2: total installed */
								__( '%2$d plugins live here; %1$d already have a Quick Look cheat sheet. Hit Scan anytime to refresh or make a new one.', 'bouncer' ),
								$scanned,
								$n_inst
							)
						);
						if ( $deep_ok ) {
							echo ' ';
							esc_html_e( 'Deep Dive will tag along on each scan while your key is available.', 'bouncer' );
						} elseif ( $ai_on ) {
							echo ' ';
							esc_html_e( 'Deep Dive is on, but there’s no key yet—scans will still refresh Quick Look until you add one under Connectors.', 'bouncer' );
						} else {
							echo ' ';
							esc_html_e( 'Deep Dive is off in Settings—scans stick to Quick Look unless you enable it and add a key.', 'bouncer' );
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

			<div class="bouncer-manifests-table-wrap">
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
						<tr class="bouncer-risk-row--none"><td colspan="7"><?php esc_html_e( 'No installed plugins found.', 'bouncer' ); ?></td></tr>
					<?php else : ?>
						<?php foreach ( $installed as $slug => $info ) : ?>
							<?php
							$m        = $by_slug[ $slug ] ?? null;
							$risk_row = $m ? 'bouncer-risk-row--' . $this->risk_row_class_for_score( (int) $m->risk_score ) : 'bouncer-risk-row--none';
							?>
						<tr class="<?php echo esc_attr( $risk_row ); ?>">
							<td>
								<strong><?php echo esc_html( $info['name'] ); ?></strong>
								<div class="description"><?php echo esc_html( $slug ); ?></div>
							</td>
							<td>
								<?php
								if ( $info['active'] ) {
									echo '<span class="bouncer-status-active">&#9679; ' . esc_html__( 'Active', 'bouncer' ) . '</span>';
								} else {
									echo '<span class="bouncer-status-inactive">&#9679; ' . esc_html__( 'Resting', 'bouncer' ) . '</span>';
								}
								?>
							</td>
							<td><?php echo $m ? esc_html( $m->plugin_version ) : '—'; ?></td>
							<td>
								<?php
								if ( $m ) {
									$band = $this->risk_row_class_for_score( (int) $m->risk_score );
									echo '<div class="bouncer-at-a-glance-cell">';
									echo '<span class="bouncer-risk-dot bouncer-risk-dot--' . esc_attr( $band ) . '" aria-hidden="true"></span>';
									echo '<div class="bouncer-at-a-glance-cell__text">';
									echo wp_kses_post( $this->render_risk_badge( (int) $m->risk_score ) );
									echo '<div class="bouncer-quick-line">' . esc_html( wp_trim_words( Bouncer_AI_Experience::headline_for_score( (int) $m->risk_score ), 14, '…' ) ) . '</div>';
									echo '</div></div>';
								} else {
									echo '<div class="bouncer-at-a-glance-cell"><span class="bouncer-risk-dot" aria-hidden="true"></span><div class="bouncer-at-a-glance-cell__text"><em>' . esc_html__( 'Not scanned yet', 'bouncer' ) . '</em></div></div>';
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
			</div>
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
			<p><a href="<?php echo esc_url( bouncer_admin_url( 'manifests' ) ); ?>" class="button"><?php esc_html_e( '← Back to all cheat sheets', 'bouncer' ); ?></a></p>
			<div class="notice notice-error"><p><?php esc_html_e( 'That plugin name doesn’t look right.', 'bouncer' ); ?></p></div>
			<?php
			return;
		}

		if ( ! Bouncer_Installed_Plugins::is_installed_slug( $plugin_slug ) ) {
			?>
			<p><a href="<?php echo esc_url( bouncer_admin_url( 'manifests' ) ); ?>" class="button"><?php esc_html_e( '← Back to all cheat sheets', 'bouncer' ); ?></a></p>
			<div class="notice notice-error">
				<p>
					<?php
					echo esc_html(
						sprintf(
							/* translators: %s: plugin slug */
							__( 'Nothing installed uses “%s” right now. Pop back to Manifests and pick from the list.', 'bouncer' ),
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
				<a href="<?php echo esc_url( bouncer_admin_url( 'manifests' ) ); ?>" class="button"><?php esc_html_e( '← Back to all cheat sheets', 'bouncer' ); ?></a>
			</p>
			<h2>
				<?php
				/* translators: 1: plugin name, 2: slug */
				printf( esc_html__( 'Cheat sheet: %1$s (%2$s)', 'bouncer' ), esc_html( $info['name'] ), esc_html( $plugin_slug ) );
				?>
			</h2>

			<?php if ( ! $manifest ) : ?>
				<div class="notice notice-warning">
					<p><?php esc_html_e( 'This plugin is here, but we haven’t saved a Quick Look cheat sheet for it yet.', 'bouncer' ); ?></p>
				</div>
				<button type="button" class="button button-primary bouncer-rescan" data-plugin="<?php echo esc_attr( $plugin_slug ); ?>">
					<?php esc_html_e( 'Run the first scan', 'bouncer' ); ?>
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
								__( 'Bouncer vibe score: %1$d/100 — %2$s', 'bouncer' ),
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
					<summary><?php esc_html_e( 'Deep Dive — Claude’s full story (tap to open)', 'bouncer' ); ?></summary>
					<div class="bouncer-deep-dive-body">
						<?php echo esc_html( $manifest['ai_assessment'] ); ?>
					</div>
				</details>
				<?php else : ?>
				<p class="description bouncer-deep-dive-empty">
					<?php
					if ( ! $ai_on ) {
						esc_html_e( 'No Deep Dive write-up saved yet. Turn it on under Bouncer → Settings, add your Anthropic key, then scan again.', 'bouncer' );
					} elseif ( $ai_on && ! $deep_ok ) {
						esc_html_e( 'Deep Dive is on, but there’s no key handy—add one in Connectors (or ANTHROPIC_API_KEY), then scan again.', 'bouncer' );
					} else {
						esc_html_e( 'No Deep Dive story yet, even though your key is set—tap “Run Quick Look again” below to generate it.', 'bouncer' );
					}
					?>
				</p>
				<?php endif; ?>

				<h2><?php esc_html_e( 'Under the hood (for support & nerds)', 'bouncer' ); ?></h2>
				<pre class="bouncer-manifest-json"><?php echo esc_html( wp_json_encode( $manifest, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) ); ?></pre>

				<button type="button" class="button bouncer-rescan" data-plugin="<?php echo esc_attr( $plugin_slug ); ?>">
					<?php esc_html_e( 'Run Quick Look again', 'bouncer' ); ?>
				</button>
				<span class="description" style="margin-left:8px;">
					<?php
					if ( $deep_ok ) {
						esc_html_e( 'This run refreshes Quick Look and asks Claude for a new Deep Dive because your key is ready.', 'bouncer' );
					} elseif ( $ai_on ) {
						esc_html_e( 'This run refreshes Quick Look; Deep Dive waits until a key shows up.', 'bouncer' );
					} else {
						esc_html_e( 'This run refreshes Quick Look. Turn on Deep Dive in Settings if you want Claude too.', 'bouncer' );
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

				<div class="bouncer-settings-section">
				<h2><?php esc_html_e( 'Operating Mode', 'bouncer' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Mode', 'bouncer' ); ?></th>
						<td>
							<select name="bouncer_mode">
								<option value="monitor" <?php selected( get_option( 'bouncer_mode' ), 'monitor' ); ?>><?php esc_html_e( 'Monitor — watch and learn, don’t block yet', 'bouncer' ); ?></option>
								<option value="enforce" <?php selected( get_option( 'bouncer_mode' ), 'enforce' ); ?>><?php esc_html_e( 'Enforce — step in when something breaks the rules', 'bouncer' ); ?></option>
							</select>
							<p class="description"><?php esc_html_e( 'Start in Monitor so Bouncer learns what “normal” looks like before you turn on stronger responses.', 'bouncer' ); ?></p>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Sampling Rate', 'bouncer' ); ?></th>
						<td>
							<input type="number" name="bouncer_sampling_rate" min="0" max="100" value="<?php echo esc_attr( get_option( 'bouncer_sampling_rate', 100 ) ); ?>" /> %
							<p class="description"><?php esc_html_e( 'What share of visits get the full watch. Use 100% on staging; dial back in production if you need less overhead.', 'bouncer' ); ?></p>
						</td>
					</tr>
				</table>
				</div>

				<div class="bouncer-settings-section">
				<h2><?php esc_html_e( 'Monitoring Channels', 'bouncer' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Database Monitoring', 'bouncer' ); ?></th>
						<td><label><input type="checkbox" name="bouncer_db_monitoring" value="1" <?php checked( get_option( 'bouncer_db_monitoring' ) ); ?> /> <?php esc_html_e( 'Watch the database and say which plugin touched it', 'bouncer' ); ?></label></td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'HTTP Monitoring', 'bouncer' ); ?></th>
						<td><label><input type="checkbox" name="bouncer_http_monitoring" value="1" <?php checked( get_option( 'bouncer_http_monitoring' ) ); ?> /> <?php esc_html_e( 'Watch plugins calling out to the web', 'bouncer' ); ?></label></td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Hook Auditing', 'bouncer' ); ?></th>
						<td><label><input type="checkbox" name="bouncer_hook_auditing" value="1" <?php checked( get_option( 'bouncer_hook_auditing' ) ); ?> /> <?php esc_html_e( 'Notice unusual hook sign-ups', 'bouncer' ); ?></label></td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'File Integrity', 'bouncer' ); ?></th>
						<td><label><input type="checkbox" name="bouncer_file_integrity" value="1" <?php checked( get_option( 'bouncer_file_integrity' ) ); ?> /> <?php esc_html_e( 'Spot surprise edits to plugin files', 'bouncer' ); ?></label></td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'REST monitoring', 'bouncer' ); ?></th>
						<td><label><input type="checkbox" name="bouncer_rest_monitoring" value="1" <?php checked( get_option( 'bouncer_rest_monitoring', true ) ); ?> /> <?php esc_html_e( 'Log write-style REST tries from visitors who aren’t logged in', 'bouncer' ); ?></label></td>
					</tr>
				</table>
				</div>

				<div class="bouncer-settings-section">
				<h2><?php esc_html_e( 'Smarter summaries (optional)', 'bouncer' ); ?></h2>
				<p class="description"><?php esc_html_e( 'Quick Look always runs on your server. Flip on Deep Dive when you want Claude’s longer write-up and you’ve added a key.', 'bouncer' ); ?></p>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Deep Dive (Claude)', 'bouncer' ); ?></th>
						<td>
							<label><input type="checkbox" name="bouncer_ai_scanning" value="1" <?php checked( get_option( 'bouncer_ai_scanning' ) ); ?> /> <?php esc_html_e( 'Let Claude add a friendly long read after scans (when your key is set)', 'bouncer' ); ?></label>
							<p class="description">
								<?php
								echo wp_kses_post(
									sprintf(
										/* translators: 1: Anthropic terms URL, 2: privacy URL */
										__( 'Deep Dive sends a compact structural sketch—not your raw PHP—to Anthropic. Their <a href="%1$s" rel="noopener noreferrer" target="_blank">Commercial Terms</a> and <a href="%2$s" rel="noopener noreferrer" target="_blank">Privacy Policy</a> apply.', 'bouncer' ),
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
								'connector_env'      => __( 'Key from the server environment (ANTHROPIC_API_KEY)', 'bouncer' ),
								'connector_constant' => __( 'Key from a PHP constant (ANTHROPIC_API_KEY)', 'bouncer' ),
								'connector_db'       => __( 'Key saved under Settings → Connectors', 'bouncer' ),
								'none'               => __( 'No key yet — Deep Dive is napping', 'bouncer' ),
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
									wp_kses_post( __( 'Drop your Anthropic key in <a href="%s">Settings &rarr; Connectors</a>, or use ANTHROPIC_API_KEY in the environment / as a PHP constant.', 'bouncer' ) ),
									esc_url( admin_url( 'options-general.php?page=connectors' ) )
								);
								?>
							</p>
						</td>
					</tr>
				</table>
				</div>

				<div class="bouncer-settings-section">
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
							<label><input type="checkbox" name="bouncer_notify_on_critical" value="1" <?php checked( get_option( 'bouncer_notify_on_critical' ) ); ?> /> <?php esc_html_e( 'Serious flags', 'bouncer' ); ?></label><br>
							<label><input type="checkbox" name="bouncer_notify_on_emergency" value="1" <?php checked( get_option( 'bouncer_notify_on_emergency' ) ); ?> /> <?php esc_html_e( 'Big deals', 'bouncer' ); ?></label>
						</td>
					</tr>
					<tr>
						<th scope="row"><?php esc_html_e( 'Email digest', 'bouncer' ); ?></th>
						<td>
							<label><input type="checkbox" name="bouncer_digest_enabled" value="1" <?php checked( get_option( 'bouncer_digest_enabled' ) ); ?> /> <?php esc_html_e( 'Email a periodic “how we’re doing” summary to the address above', 'bouncer' ); ?></label>
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
							<p class="description"><?php esc_html_e( 'Optional. When set, requests include X-Bouncer-Signature so your endpoint can verify they’re really from Bouncer.', 'bouncer' ); ?></p>
							<label for="bouncer-webhook-min-sev"><?php esc_html_e( 'Only send webhooks from this level up', 'bouncer' ); ?></label>
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
				</div>

				<div class="bouncer-settings-section">
				<h2><?php esc_html_e( 'Data', 'bouncer' ); ?></h2>
				<table class="form-table">
					<tr>
						<th scope="row"><?php esc_html_e( 'Log Retention', 'bouncer' ); ?></th>
						<td>
							<input type="number" name="bouncer_log_retention_days" min="1" max="365" value="<?php echo esc_attr( get_option( 'bouncer_log_retention_days', 30 ) ); ?>" /> <?php esc_html_e( 'days', 'bouncer' ); ?>
						</td>
					</tr>
				</table>
				</div>

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
			echo '<span class="bouncer-badge bouncer-badge-unknown">' . esc_html__( 'No cheat sheet yet', 'bouncer' ) . '</span>';
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
						__( '<strong>Bouncer:</strong> Deep Dive is switched on, but there’s no Anthropic key yet—Quick Look still runs fine. Add one in <a href="%s">Settings → Connectors</a> (or ANTHROPIC_API_KEY in the environment / as a PHP constant).', 'bouncer' )
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
