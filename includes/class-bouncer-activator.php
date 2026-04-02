<?php
/**
 * Activation and deactivation logic.
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

class Bouncer_Activator {

	public static function activate(): void {
		require_once __DIR__ . '/class-bouncer-filesystem.php';

		$admin_role = get_role( 'administrator' );
		if ( $admin_role && defined( 'BOUNCER_CAP' ) ) {
			$admin_role->add_cap( BOUNCER_CAP );
		}

		self::create_tables();
		self::install_mu_plugin();
		self::install_db_dropin();
		self::create_data_directories();
		self::schedule_cron_events();

		update_option( 'bouncer_version', BOUNCER_VERSION );
		update_option( 'bouncer_activated_at', time() );

		$defaults = array(
			'mode'                => 'monitor',
			'db_monitoring'       => true,
			'http_monitoring'     => true,
			'hook_auditing'       => true,
			'file_integrity'      => true,
			'ai_scanning'         => false,
			'sampling_rate'       => 100,
			'log_retention_days'  => 30,
			'community_telemetry' => false,
			'notify_email'        => get_option( 'admin_email' ),
			'notify_on_warning'   => true,
			'notify_on_critical'  => true,
			'notify_on_emergency' => true,
			'rest_monitoring'     => true,
			'webhook_url'         => '',
			'webhook_secret'      => '',
			'webhook_min_severity'=> 'warning',
			'digest_enabled'      => false,
			'digest_frequency'    => 'daily',
		);

		foreach ( $defaults as $key => $value ) {
			if ( false === get_option( "bouncer_{$key}" ) ) {
				update_option( "bouncer_{$key}", $value );
			}
		}

		flush_rewrite_rules();

		require_once __DIR__ . '/class-bouncer-notifications.php';
		Bouncer_Notifications::sync_digest_schedule();
	}

	public static function deactivate(): void {
		require_once __DIR__ . '/class-bouncer-filesystem.php';
		self::remove_mu_plugin();
		self::remove_db_dropin();
		self::clear_cron_events();
	}

	private static function create_tables(): void {
		global $wpdb;

		try {
			$c   = $wpdb->get_charset_collate();
			$sql = array();

			$sql[] = "CREATE TABLE {$wpdb->prefix}bouncer_events (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			event_time datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			severity varchar(20) NOT NULL DEFAULT 'info',
			channel varchar(30) NOT NULL,
			plugin_slug varchar(200) NOT NULL DEFAULT '',
			event_type varchar(100) NOT NULL,
			message text NOT NULL,
			context longtext,
			request_uri varchar(2048) DEFAULT '',
			user_id bigint(20) unsigned DEFAULT 0,
			ip_address varchar(45) DEFAULT '',
			PRIMARY KEY (id),
			KEY idx_severity_time (severity, event_time),
			KEY idx_plugin_slug (plugin_slug),
			KEY idx_event_time (event_time),
			KEY idx_channel (channel)
		) {$c};";

			$sql[] = "CREATE TABLE {$wpdb->prefix}bouncer_manifests (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			plugin_slug varchar(200) NOT NULL,
			plugin_version varchar(50) NOT NULL DEFAULT '',
			manifest longtext NOT NULL,
			generated_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			generated_by varchar(20) NOT NULL DEFAULT 'static',
			risk_score int unsigned DEFAULT 0,
			ai_assessment text,
			PRIMARY KEY (id),
			UNIQUE KEY idx_plugin_version (plugin_slug, plugin_version)
		) {$c};";

			$sql[] = "CREATE TABLE {$wpdb->prefix}bouncer_checksums (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			plugin_slug varchar(200) NOT NULL,
			file_path varchar(500) NOT NULL,
			checksum_sha256 char(64) NOT NULL,
			file_size bigint(20) unsigned DEFAULT 0,
			recorded_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			UNIQUE KEY idx_plugin_file (plugin_slug, file_path(191)),
			KEY idx_plugin_slug (plugin_slug)
		) {$c};";

			$sql[] = "CREATE TABLE {$wpdb->prefix}bouncer_hook_baselines (
			id bigint(20) unsigned NOT NULL AUTO_INCREMENT,
			plugin_slug varchar(200) NOT NULL,
			hook_name varchar(200) NOT NULL,
			callback_signature varchar(500) NOT NULL,
			priority int NOT NULL DEFAULT 10,
			recorded_at datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
			PRIMARY KEY (id),
			KEY idx_plugin_slug (plugin_slug)
		) {$c};";

			require_once ABSPATH . 'wp-admin/includes/upgrade.php';
			foreach ( $sql as $q ) {
				$altered = dbDelta( $q );
				if ( is_array( $altered ) ) {
					foreach ( $altered as $line ) {
						if ( is_string( $line ) && preg_match( '/\b(error|failed|cannot)\b/i', $line ) ) {
							// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
							error_log( 'Bouncer dbDelta: ' . $line );
							update_option( 'bouncer_dbdelta_last_issue', wp_strip_all_tags( $line ), false );
						}
					}
				}
			}
		} catch ( \Throwable $e ) {
			update_option( 'bouncer_create_tables_error', wp_strip_all_tags( $e->getMessage() ), false );
			throw $e;
		}
	}

	private static function install_mu_plugin(): void {
		$mu_dir = WPMU_PLUGIN_DIR;
		if ( ! is_dir( $mu_dir ) ) {
			wp_mkdir_p( $mu_dir );
		}

		$mu_file   = $mu_dir . '/00-bouncer-loader.php';
		$basename  = plugin_basename( BOUNCER_PLUGIN_FILE );
		$dir       = dirname( $basename );
		$early_rel = ( '.' === $dir ) ? '' : $dir . '/includes/class-bouncer-early-monitor.php';

		$b_export     = var_export( $basename, true );
		$early_export = var_export( $early_rel, true );

		$content  = "<?php\n";
		$content .= "/**\n * Bouncer Early Loader (mu-plugin).\n *\n * Installed by Bouncer. Do not edit manually.\n *\n * @package Bouncer\n */\n\n";
		$content .= "defined( 'ABSPATH' ) || exit;\n\n";
		$content .= "\$bouncer_basename = {$b_export};\n";
		$content .= "\$bouncer_main = WP_PLUGIN_DIR . '/' . \$bouncer_basename;\n";
		$content .= "if ( ! file_exists( \$bouncer_main ) ) {\n\treturn;\n}\n\n";
		$content .= "if ( ! function_exists( 'is_plugin_active' ) ) {\n\trequire_once ABSPATH . 'wp-admin/includes/plugin.php';\n}\n";
		$content .= "if ( ! is_plugin_active( \$bouncer_basename ) ) {\n\treturn;\n}\n\n";
		$content .= "\$bouncer_early_rel = {$early_export};\n";
		$content .= "if ( \$bouncer_early_rel !== '' ) {\n";
		$content .= "\t\$early_loader = WP_PLUGIN_DIR . '/' . \$bouncer_early_rel;\n";
		$content .= "\tif ( file_exists( \$early_loader ) ) {\n";
		$content .= "\t\trequire_once \$early_loader;\n";
		$content .= "\t\tBouncer_Early_Monitor::init();\n";
		$content .= "\t}\n";
		$content .= "}\n";

		$written = Bouncer_Filesystem::put_contents( $mu_file, $content );
		if ( ! $written ) {
			update_option( 'bouncer_mu_install_failed', true );
		} else {
			delete_option( 'bouncer_mu_install_failed' );
		}
	}

	private static function install_db_dropin(): void {
		$dest   = WP_CONTENT_DIR . '/db.php';
		$source = BOUNCER_PLUGIN_DIR . 'db.php';

		if ( file_exists( $dest ) ) {
			$existing = Bouncer_Filesystem::get_contents( $dest );
			if ( false === $existing || '' === $existing ) {
				update_option( 'bouncer_db_dropin_conflict', true );
				return;
			}
			if ( false === strpos( $existing, '@package Bouncer' ) ) {
				update_option( 'bouncer_db_dropin_conflict', true );
				return;
			}
		}

		if ( file_exists( $source ) ) {
			$copied = Bouncer_Filesystem::copy( $source, $dest );
			if ( ! $copied ) {
				update_option( 'bouncer_db_copy_failed', true );
				return;
			}
			delete_option( 'bouncer_db_copy_failed' );
			update_option( 'bouncer_db_dropin_conflict', false );
			update_option( 'bouncer_db_dropin_installed', true );
		}
	}

	private static function create_data_directories(): void {
		$dirs = array(
			WP_CONTENT_DIR . '/bouncer',
			WP_CONTENT_DIR . '/bouncer/manifests',
		);

		foreach ( $dirs as $dir ) {
			if ( ! is_dir( $dir ) ) {
				wp_mkdir_p( $dir );
			}
			$htaccess = $dir . '/.htaccess';
			if ( ! file_exists( $htaccess ) ) {
				Bouncer_Filesystem::put_contents( $htaccess, "Deny from all\n" );
			}
			$index = $dir . '/index.php';
			if ( ! file_exists( $index ) ) {
				Bouncer_Filesystem::put_contents( $index, "<?php\n// Silence is golden.\n" );
			}
		}
	}

	private static function schedule_cron_events(): void {
		if ( ! wp_next_scheduled( 'bouncer_file_integrity_check' ) ) {
			wp_schedule_event( time(), 'hourly', 'bouncer_file_integrity_check' );
		}
		if ( ! wp_next_scheduled( 'bouncer_cleanup_old_events' ) ) {
			wp_schedule_event( time(), 'daily', 'bouncer_cleanup_old_events' );
		}
	}

	private static function remove_mu_plugin(): void {
		$f = WPMU_PLUGIN_DIR . '/00-bouncer-loader.php';
		if ( file_exists( $f ) ) {
			Bouncer_Filesystem::delete_file( $f );
		}
	}

	private static function remove_db_dropin(): void {
		$f = WP_CONTENT_DIR . '/db.php';
		if ( file_exists( $f ) ) {
			$content = Bouncer_Filesystem::get_contents( $f );
			if ( is_string( $content ) && false !== strpos( $content, '@package Bouncer' ) ) {
				Bouncer_Filesystem::delete_file( $f );
				delete_option( 'bouncer_db_dropin_installed' );
			}
		}
	}

	private static function clear_cron_events(): void {
		wp_clear_scheduled_hook( 'bouncer_file_integrity_check' );
		wp_clear_scheduled_hook( 'bouncer_cleanup_old_events' );
		wp_clear_scheduled_hook( 'bouncer_weekly_report' );
		wp_clear_scheduled_hook( 'bouncer_event_digest' );
	}
}
