<?php
/**
 * WP-CLI commands for Bouncer.
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

/**
 * @phpstan-ignore-next-line
 */
class Bouncer_CLI_Command extends WP_CLI_Command {

	/**
	 * Show protection mode, db drop-in, and recent event counts.
	 *
	 * ## OPTIONS
	 *
	 * [--format=<format>]
	 * : Render output as table, json, csv, or yaml.
	 * ---
	 * default: table
	 * options:
	 *   - table
	 *   - json
	 *   - csv
	 *   - yaml
	 * ---
	 */
	public function status( $args, $assoc_args ) {
		unset( $args );
		$bouncer = Bouncer::get_instance();
		$bouncer->logger->flush();
		$counts = $bouncer->logger->get_severity_counts( 1 );

		$rows = array(
			array(
				'key'   => 'mode',
				'value' => $bouncer->get_setting( 'mode', 'monitor' ),
			),
			array(
				'key'   => 'db_dropin_installed',
				'value' => get_option( 'bouncer_db_dropin_installed' ) ? 'yes' : 'no',
			),
			array(
				'key'   => 'db_dropin_conflict',
				'value' => get_option( 'bouncer_db_dropin_conflict' ) ? 'yes' : 'no',
			),
			array(
				'key'   => 'events_24h_info',
				'value' => (string) $counts['info'],
			),
			array(
				'key'   => 'events_24h_warning',
				'value' => (string) $counts['warning'],
			),
			array(
				'key'   => 'events_24h_critical',
				'value' => (string) $counts['critical'],
			),
			array(
				'key'   => 'events_24h_emergency',
				'value' => (string) $counts['emergency'],
			),
		);

		\WP_CLI\Utils\format_items( $assoc_args['format'] ?? 'table', $rows, array( 'key', 'value' ) );
	}

	/**
	 * List recent Bouncer events.
	 *
	 * ## OPTIONS
	 *
	 * [--limit=<n>]
	 * : Number of rows.
	 * ---
	 * default: 20
	 * ---
	 *
	 * [--severity=<level>]
	 * : Filter by severity.
	 *
	 * [--plugin=<slug>]
	 * : Filter by plugin slug.
	 *
	 * [--format=<format>]
	 * : table, json, csv, yaml, ids
	 */
	public function log( $args, $assoc_args ) {
		unset( $args );
		$limit = max( 1, min( 500, (int) ( $assoc_args['limit'] ?? 20 ) ) );
		$sev   = isset( $assoc_args['severity'] ) ? sanitize_text_field( $assoc_args['severity'] ) : '';
		$plug  = isset( $assoc_args['plugin'] ) ? sanitize_text_field( $assoc_args['plugin'] ) : '';

		$res = Bouncer::get_instance()->logger->get_events(
			array(
				'per_page' => $limit,
				'page'     => 1,
				'severity' => $sev ?: null,
				'plugin'   => $plug ?: null,
			)
		);

		$out = array();
		foreach ( $res['events'] as $e ) {
			$out[] = array(
				'id'          => $e->id,
				'time'        => $e->event_time,
				'severity'    => $e->severity,
				'channel'     => $e->channel,
				'plugin_slug' => $e->plugin_slug,
				'event_type'  => $e->event_type,
				'message'     => $e->message,
			);
		}

		\WP_CLI\Utils\format_items( $assoc_args['format'] ?? 'table', $out, array( 'id', 'time', 'severity', 'channel', 'plugin_slug', 'event_type', 'message' ) );
	}

	/**
	 * Show the stored manifest for a plugin (JSON).
	 *
	 * <slug>
	 * : Plugin directory slug.
	 *
	 * [--format=<format>]
	 * : json or yaml (table shows summary only).
	 */
	public function manifest( $args, $assoc_args ) {
		$slug = isset( $args[0] ) ? sanitize_text_field( $args[0] ) : '';
		if ( '' === $slug || ! preg_match( '/^[a-z0-9\-]+$/', $slug ) ) {
			\WP_CLI::error( 'Invalid or missing plugin slug.' );
		}

		$m = Bouncer::get_instance()->manifest->get_manifest( $slug );
		if ( null === $m ) {
			\WP_CLI::warning( 'No manifest found. Run a scan from wp-admin or extend this command later.' );
			return;
		}

		$fmt = $assoc_args['format'] ?? 'json';
		if ( 'json' === $fmt ) {
			\WP_CLI::line( wp_json_encode( $m, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) );
			return;
		}

		\WP_CLI\Utils\format_items(
			'table',
			array(
				array(
					'slug'        => $m['plugin'] ?? $slug,
					'version'     => $m['version'] ?? '',
					'risk_score'  => $m['risk_score'] ?? '',
					'generated_at'=> $m['generated_at'] ?? '',
				),
			),
			array( 'slug', 'version', 'risk_score', 'generated_at' )
		);
	}

	/**
	 * Export or import Bouncer options (bouncer_*).
	 *
	 * ## SUBCOMMANDS
	 *
	 * export
	 * : Write options to a JSON file.
	 *
	 * import
	 * : Read options from a JSON file.
	 *
	 * ## OPTIONS
	 *
	 * [--file=<path>]
	 * : Path to JSON file.
	 *
	 * [--dry-run=<bool>]
	 * : For import, default true (no writes). Set --dry-run=false to apply.
	 * ---
	 * default: true
	 * ---
	 */
	public function config( $args, $assoc_args ) {
		$sub = isset( $args[0] ) ? $args[0] : '';
		if ( ! in_array( $sub, array( 'export', 'import' ), true ) ) {
			\WP_CLI::error( 'Usage: wp bouncer config export|import --file=path.json' );
		}

		$file = isset( $assoc_args['file'] ) ? $assoc_args['file'] : '';
		if ( '' === $file ) {
			\WP_CLI::error( 'Missing --file=path' );
		}

		if ( 'export' === $sub ) {
			global $wpdb;
			// phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
			$rows = $wpdb->get_results( "SELECT option_name, option_value FROM {$wpdb->options} WHERE option_name LIKE 'bouncer\\_%'", ARRAY_A );
			$data = array();
			foreach ( $rows as $row ) {
				$data[ $row['option_name'] ] = maybe_unserialize( $row['option_value'] );
			}
			$written = file_put_contents( $file, wp_json_encode( $data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES ) );
			if ( false === $written ) {
				\WP_CLI::error( 'Could not write file.' );
			}
			\WP_CLI::success( sprintf( 'Exported %d options.', count( $data ) ) );
			return;
		}

		$dry_raw = $assoc_args['dry-run'] ?? 'true';
		$dry     = filter_var( $dry_raw, FILTER_VALIDATE_BOOLEAN );

		if ( ! is_readable( $file ) ) {
			\WP_CLI::error( 'File not readable.' );
		}
		$json = file_get_contents( $file );
		$data = json_decode( $json, true );
		if ( ! is_array( $data ) ) {
			\WP_CLI::error( 'Invalid JSON.' );
		}

		$n = 0;
		foreach ( $data as $name => $value ) {
			if ( ! is_string( $name ) || ! str_starts_with( $name, 'bouncer_' ) ) {
				continue;
			}
			++$n;
			if ( ! $dry ) {
				update_option( $name, $value );
			}
		}

		if ( $dry ) {
			\WP_CLI::success( sprintf( 'Dry run: would import %d options. Pass --dry-run=false to apply.', $n ) );
		} else {
			\WP_CLI::success( sprintf( 'Imported %d options.', $n ) );
		}
	}
}
