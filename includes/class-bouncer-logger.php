<?php
/**
 * Event logger for Bouncer.
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

/**
 * Structured event logging with write buffering and rate limiting.
 *
 * Buffers log writes and flushes in a single multi-row INSERT on shutdown,
 * reducing per-event DB overhead from O(n) queries to O(1).
 */
class Bouncer_Logger {

	const SEVERITY_INFO      = 'info';
	const SEVERITY_WARNING   = 'warning';
	const SEVERITY_CRITICAL  = 'critical';
	const SEVERITY_EMERGENCY = 'emergency';

	const CHANNEL_DATABASE  = 'database';
	const CHANNEL_HTTP      = 'http';
	const CHANNEL_HOOKS     = 'hooks';
	const CHANNEL_FILES     = 'files';
	const CHANNEL_AI        = 'ai';
	const CHANNEL_LIFECYCLE = 'lifecycle';
	const CHANNEL_REST      = 'rest';

	/** @var array<string, true> Valid severities for whitelist check. */
	private static array $valid_severities = array(
		'info'      => true,
		'warning'   => true,
		'critical'  => true,
		'emergency' => true,
	);

	/** @var array<string, true> Valid channels. */
	private static array $valid_channels = array(
		'database'  => true,
		'http'      => true,
		'hooks'     => true,
		'files'     => true,
		'ai'        => true,
		'lifecycle' => true,
		'rest'      => true,
	);

	/** @var array<int, array<string, mixed>> Write buffer. */
	private array $buffer = array();

	/** @var bool Recursion guard. */
	private bool $suppressed = false;

	/** @var bool Whether shutdown flush is registered. */
	private bool $shutdown_registered = false;

	/** @var int Maximum buffer size before forced flush. */
	private const BUFFER_MAX = 100;

	/**
	 * Log an event. Buffers the write for batch INSERT on shutdown.
	 *
	 * @param string               $severity    One of the SEVERITY_* constants.
	 * @param string               $channel     One of the CHANNEL_* constants.
	 * @param string               $plugin_slug Plugin identifier.
	 * @param string               $event_type  Machine-readable event type.
	 * @param string               $message     Human-readable message.
	 * @param array<string, mixed> $context     Additional structured data.
	 */
	public function log( string $severity, string $channel, string $plugin_slug, string $event_type, string $message, array $context = array() ): void {
		if ( $this->suppressed ) {
			return;
		}

		// Validate severity and channel against whitelist.
		if ( ! isset( self::$valid_severities[ $severity ] ) ) {
			$severity = self::SEVERITY_INFO;
		}
		if ( ! isset( self::$valid_channels[ $channel ] ) ) {
			$channel = self::CHANNEL_LIFECYCLE;
		}

		$this->buffer[] = array(
			'severity'    => $severity,
			'channel'     => $channel,
			'plugin_slug' => sanitize_text_field( $plugin_slug ),
			'event_type'  => sanitize_key( $event_type ),
			'message'     => sanitize_text_field( mb_substr( $message, 0, 1000 ) ),
			'context'     => ! empty( $context ) ? wp_json_encode( $context ) : '',
			'request_uri' => isset( $_SERVER['REQUEST_URI'] ) ? esc_url_raw( wp_unslash( $_SERVER['REQUEST_URI'] ) ) : '',
			'user_id'     => get_current_user_id(),
			'ip_address'  => self::get_client_ip(),
		);

		// Register shutdown handler once.
		if ( ! $this->shutdown_registered ) {
			$this->shutdown_registered = true;
			add_action( 'shutdown', array( $this, 'flush' ), 5 );
		}

		// Force flush if buffer is large (long-running process safety).
		if ( count( $this->buffer ) >= self::BUFFER_MAX ) {
			$this->flush();
		}

		// High-severity events still notify immediately.
		if ( in_array( $severity, array( self::SEVERITY_CRITICAL, self::SEVERITY_EMERGENCY ), true ) ) {
			$this->maybe_notify( $severity, $channel, $plugin_slug, $event_type, $message, $context );
		}
	}

	/**
	 * Flush the write buffer to the database in a single batch INSERT.
	 */
	public function flush(): void {
		if ( empty( $this->buffer ) || $this->suppressed ) {
			return;
		}

		$this->suppressed = true;
		global $wpdb;

		$saved = $this->buffer;

		$columns = '(severity, channel, plugin_slug, event_type, message, context, request_uri, user_id, ip_address)';
		$values  = array();
		$params  = array();

		foreach ( $this->buffer as $row ) {
			$values[] = '(%s, %s, %s, %s, %s, %s, %s, %d, %s)';
			$params[] = $row['severity'];
			$params[] = $row['channel'];
			$params[] = $row['plugin_slug'];
			$params[] = $row['event_type'];
			$params[] = $row['message'];
			$params[] = $row['context'];
			$params[] = $row['request_uri'];
			$params[] = $row['user_id'];
			$params[] = $row['ip_address'];
		}

		$sql = "INSERT INTO {$wpdb->prefix}bouncer_events {$columns} VALUES " . implode( ', ', $values );

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$wpdb->query( $wpdb->prepare( $sql, $params ) );

		if ( ! empty( $wpdb->last_error ) ) {
			$row_count = count( $saved );
			// phpcs:ignore WordPress.PHP.DevelopmentFunctions.error_log_error_log
			error_log(
				sprintf(
					'Bouncer logger flush failed (%d rows not persisted): %s',
					$row_count,
					$wpdb->last_error
				)
			);
			$this->buffer     = array();
			$this->suppressed = false;
			return;
		}

		foreach ( $saved as $row ) {
			/**
			 * Fires after a Bouncer event row is persisted (one hook per row).
			 *
			 * @param array<string, mixed> $row Buffered row prior to insert.
			 */
			do_action( 'bouncer_event_recorded', $row );
		}

		$this->buffer     = array();
		$this->suppressed = false;
	}

	/**
	 * Get events with filtering and pagination.
	 *
	 * @param array<string, mixed> $args Query arguments.
	 * @return array{events: array, total: int, page: int, per_page: int, pages: int}
	 */
	public function get_events( array $args = array() ): array {
		// Flush pending writes first so results are current.
		$this->flush();

		global $wpdb;

		$defaults = array(
			'severity' => null,
			'channel'  => null,
			'plugin'   => null,
			'per_page' => 50,
			'page'     => 1,
			'orderby'  => 'event_time',
			'order'    => 'DESC',
		);

		$args   = wp_parse_args( $args, $defaults );
		$where  = array();
		$values = array();

		if ( ! empty( $args['severity'] ) && isset( self::$valid_severities[ $args['severity'] ] ) ) {
			$where[]  = 'severity = %s';
			$values[] = $args['severity'];
		}

		if ( ! empty( $args['channel'] ) && isset( self::$valid_channels[ $args['channel'] ] ) ) {
			$where[]  = 'channel = %s';
			$values[] = $args['channel'];
		}

		if ( ! empty( $args['plugin'] ) ) {
			$where[]  = 'plugin_slug = %s';
			$values[] = sanitize_text_field( $args['plugin'] );
		}

		$where_sql = ! empty( $where ) ? 'WHERE ' . implode( ' AND ', $where ) : '';

		// Whitelist orderby to prevent SQL injection.
		$allowed_orderby = array( 'event_time', 'severity', 'plugin_slug', 'channel', 'id' );
		$orderby         = in_array( $args['orderby'], $allowed_orderby, true ) ? $args['orderby'] : 'event_time';
		$order           = 'ASC' === strtoupper( (string) $args['order'] ) ? 'ASC' : 'DESC';
		$per_page        = max( 1, min( 200, (int) $args['per_page'] ) );
		$page            = max( 1, (int) $args['page'] );
		$offset          = ( $page - 1 ) * $per_page;

		$filter_values = $values;

		// Count query.
		if ( ! empty( $filter_values ) ) {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			$total = (int) $wpdb->get_var(
				$wpdb->prepare(
					"SELECT COUNT(*) FROM {$wpdb->prefix}bouncer_events {$where_sql}",
					$filter_values
				)
			);
		} else {
			// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
			$total = (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$wpdb->prefix}bouncer_events {$where_sql}" );
		}

		// Results query — orderby/order are whitelisted strings, not user input.
		$paged_values = array_merge( $filter_values, array( $per_page, $offset ) );

		// phpcs:ignore WordPress.DB.PreparedSQL.NotPrepared
		$results = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT * FROM {$wpdb->prefix}bouncer_events {$where_sql} ORDER BY {$orderby} {$order} LIMIT %d OFFSET %d",
				$paged_values
			)
		);

		foreach ( $results as $row ) {
			if ( ! empty( $row->context ) ) {
				$row->context = json_decode( $row->context, true );
			}
		}

		return array(
			'events'   => $results ?: array(),
			'total'    => $total,
			'page'     => $page,
			'per_page' => $per_page,
			'pages'    => (int) ceil( $total / $per_page ),
		);
	}

	/**
	 * Get severity counts for the dashboard.
	 *
	 * Uses object cache when available for repeated calls within a request.
	 *
	 * @param int $days Look-back period.
	 * @return array<string, int>
	 */
	public function get_severity_counts( int $days = 7 ): array {
		$cache_key = 'bouncer_severity_counts_' . $days;
		$cached    = wp_cache_get( $cache_key, 'bouncer' );
		if ( false !== $cached ) {
			return $cached;
		}

		$this->flush();
		global $wpdb;

		$results = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT severity, COUNT(*) as count
				FROM {$wpdb->prefix}bouncer_events
				WHERE event_time >= DATE_SUB(NOW(), INTERVAL %d DAY)
				GROUP BY severity",
				$days
			)
		);

		$counts = array(
			'info'      => 0,
			'warning'   => 0,
			'critical'  => 0,
			'emergency' => 0,
		);
		foreach ( $results as $row ) {
			if ( isset( $counts[ $row->severity ] ) ) {
				$counts[ $row->severity ] = (int) $row->count;
			}
		}

		wp_cache_set( $cache_key, $counts, 'bouncer', 300 );
		return $counts;
	}

	/**
	 * Get per-plugin event summary.
	 *
	 * @param int $days Look-back period.
	 * @return array
	 */
	public function get_plugin_summary( int $days = 7 ): array {
		$this->flush();
		global $wpdb;

		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT plugin_slug,
					SUM(severity = 'warning') as warnings,
					SUM(severity = 'critical') as criticals,
					SUM(severity = 'emergency') as emergencies,
					COUNT(*) as total_events
				FROM {$wpdb->prefix}bouncer_events
				WHERE event_time >= DATE_SUB(NOW(), INTERVAL %d DAY)
					AND plugin_slug != ''
				GROUP BY plugin_slug
				ORDER BY emergencies DESC, criticals DESC, warnings DESC
				LIMIT 50",
				$days
			)
		) ?: array();
	}

	/**
	 * Clean up events older than retention period.
	 *
	 * Uses batched deletes to avoid long-running locks.
	 *
	 * @param int $days Retention period.
	 * @return int Total rows deleted.
	 */
	public function cleanup( int $days = 30 ): int {
		global $wpdb;

		$this->suppressed = true;
		$total_deleted    = 0;
		$batch_size       = 1000;

		do {
			$deleted        = (int) $wpdb->query(
				$wpdb->prepare(
					"DELETE FROM {$wpdb->prefix}bouncer_events WHERE event_time < DATE_SUB(NOW(), INTERVAL %d DAY) LIMIT %d",
					$days,
					$batch_size
				)
			);
			$total_deleted += $deleted;
		} while ( $deleted === $batch_size );

		$this->suppressed = false;
		return $total_deleted;
	}

	/**
	 * Send notification for high-severity events (rate-limited).
	 */
	private function maybe_notify( string $severity, string $channel, string $plugin_slug, string $event_type, string $message, array $context ): void {
		if ( ! get_option( "bouncer_notify_on_{$severity}", true ) ) {
			return;
		}

		// Rate limit: 1 email per plugin per severity per hour.
		$transient_key = 'bouncer_ntfy_' . md5( $plugin_slug . $severity );
		if ( get_transient( $transient_key ) ) {
			return;
		}
		set_transient( $transient_key, 1, HOUR_IN_SECONDS );

		$email   = get_option( 'bouncer_notify_email', get_option( 'admin_email' ) );
		$subject = sprintf(
			/* translators: 1: severity, 2: site name */
			__( '[Bouncer %1$s] Security event on %2$s', 'bouncer' ),
			strtoupper( $severity ),
			get_bloginfo( 'name' )
		);

		$body = sprintf(
			"Bouncer detected a %s security event.\n\nPlugin: %s\nChannel: %s\nEvent: %s\n\n%s\n\nDashboard: %s",
			$severity,
			$plugin_slug,
			$channel,
			$event_type,
			$message,
			bouncer_admin_url( 'events', array( 'plugin' => $plugin_slug ) )
		);

		wp_mail( $email, $subject, $body );
	}

	/**
	 * Get client IP with safety bounds.
	 *
	 * Note: X-Forwarded-For is only trusted if the server is behind
	 * a known reverse proxy. In direct-connection setups, REMOTE_ADDR
	 * is the authoritative source. We use XFF as a hint for logging only,
	 * never for access control decisions.
	 *
	 * @return string Validated IP or empty string.
	 */
	private static function get_client_ip(): string {
		// Prefer REMOTE_ADDR as it's set by the web server.
		$ip = '';
		if ( ! empty( $_SERVER['REMOTE_ADDR'] ) ) {
			$ip = sanitize_text_field( wp_unslash( $_SERVER['REMOTE_ADDR'] ) );
		}

		return filter_var( $ip, FILTER_VALIDATE_IP ) ? $ip : '';
	}
}
