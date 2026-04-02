<?php
/**
 * Bouncer Database Query Monitor (db.php drop-in).
 *
 * Intercepts all database queries and attributes them to originating plugins.
 * Extends wpdb with full backward compatibility.
 *
 * Installed/removed automatically by the Bouncer plugin. Do not edit.
 *
 * @package Bouncer
 * @version 1.0.5
 */

defined( 'ABSPATH' ) || exit;

if ( ! function_exists( 'bouncer_pending_violations_lock_acquire' ) && defined( 'WP_PLUGIN_DIR' ) ) {
	$__bouncer_lock_paths = glob( WP_PLUGIN_DIR . '/*/includes/bouncer-pending-violations-lock.php' ) ?: array();
	foreach ( $__bouncer_lock_paths as $__bouncer_lp ) {
		if ( is_readable( $__bouncer_lp ) ) {
			require_once $__bouncer_lp;
			break;
		}
	}
}

/**
 * Extended wpdb class with per-plugin query attribution and violation detection.
 *
 * Performance: attribution uses debug_backtrace only for write ops by default.
 * Cached path lookups avoid repeated string operations on every query.
 * Violations buffer in memory and flush on shutdown (no recursive DB calls).
 * Query log is capped to prevent unbounded memory growth.
 */
class Bouncer_DB extends wpdb {

	/** @var bool Whether monitoring is active for this request. */
	private bool $bouncer_active = false;

	/** @var bool Recursion guard for internal operations. */
	private bool $bouncer_internal = false;

	/** @var bool Whether the shutdown flush has been registered. */
	private bool $shutdown_registered = false;

	/** @var array<int, array<string, mixed>> Query log (capped). */
	private array $bouncer_query_log = array();

	/** @var array<string, array<string, mixed>> Cached manifests keyed by slug. */
	private array $bouncer_manifests = array();

	/** @var array<int, array<string, mixed>> Violations buffered for shutdown flush. */
	private array $bouncer_violations = array();

	/** @var array{plugin_dir: string, mu_dir: string, theme_dir: string}|null Cached paths. */
	private ?array $cached_paths = null;

	private const LOG_CAP              = 500;
	private const VIOLATION_CAP        = 50;
	private const TRACE_DEPTH          = 12;
	private const MAX_QUERY_LOG_LENGTH = 500;

	/** @var array<string, true> Sensitive tables — keyed for O(1) isset() lookup. */
	private static array $sensitive_tables = array(
		'users'    => true,
		'usermeta' => true,
		'options'  => true,
	);

	/** @var array<string, true> Write ops — keyed for O(1) lookup. */
	private static array $write_ops = array(
		'INSERT' => true,
		'UPDATE' => true,
		'DELETE' => true,
		'DDL'    => true,
	);

	/** @var array<string, true> Sources to skip — keyed for O(1) lookup. */
	private static array $skip_sources = array(
		'core'      => true,
		'bouncer'   => true,
		'unknown'   => true,
		'mu-plugin' => true,
	);

	/** @var string Combined regex for table extraction (FROM/INTO/UPDATE/JOIN). */
	private static string $table_regex = '/\b(?:FROM|INTO|UPDATE|JOIN)\s+`?(\w+)`?/i';

	/**
	 * Run a query and monitor it.
	 *
	 * @param string $query SQL query.
	 * @return int|bool
	 */
	public function query( $query ) {
		if ( ! $this->bouncer_active || $this->bouncer_internal ) {
			return parent::query( $query );
		}

		$operation = $this->classify_operation( $query );
		$is_write  = isset( self::$write_ops[ $operation ] );

		// Skip reads when no manifests loaded (common early-request case).
		if ( ! $is_write && empty( $this->bouncer_manifests ) ) {
			return parent::query( $query );
		}

		$attribution = $this->attribute_query();

		if ( isset( self::$skip_sources[ $attribution['source'] ] ) ) {
			return parent::query( $query );
		}

		$table       = $this->extract_table_name( $query );
		$table_short = $this->strip_table_prefix( $table );
		$plugin_slug = $attribution['source'];
		$violations  = array();

		// Manifest-based check.
		if ( '' !== $table && isset( $this->bouncer_manifests[ $plugin_slug ] ) ) {
			$violations = $this->check_manifest_violations(
				$is_write,
				$table,
				$table_short,
				$this->bouncer_manifests[ $plugin_slug ],
				$plugin_slug
			);
		}

		// Sensitive table write (always checked for plugin sources).
		if ( $is_write && 'plugin' === $attribution['type'] && isset( self::$sensitive_tables[ $table_short ] ) ) {
			$violations[] = array(
				'type'     => 'sensitive_table_write',
				'message'  => sprintf( 'Plugin "%s" is writing to sensitive table "%s".', $plugin_slug, $table ),
				'severity' => 'critical',
			);
		}

		if ( ! empty( $violations ) ) {
			$this->buffer_violations( $violations, $attribution, $query, $table, $operation );
		}

		// Capped query log — skip sanitization cost when log is full.
		if ( count( $this->bouncer_query_log ) < self::LOG_CAP ) {
			$this->bouncer_query_log[] = array(
				'source'     => $plugin_slug,
				'table'      => $table,
				'operation'  => $operation,
				'violations' => count( $violations ),
				'time'       => microtime( true ),
			);
		}

		return parent::query( $query );
	}

	/**
	 * Activate monitoring and register shutdown flush.
	 */
	public function bouncer_activate(): void {
		$this->bouncer_active = true;
		if ( ! $this->shutdown_registered ) {
			$this->shutdown_registered = true;
			register_shutdown_function( array( $this, 'flush_violations' ) );
		}
	}

	/** @return array<int, array<string, mixed>> */
	public function bouncer_get_log(): array {
		return $this->bouncer_query_log;
	}

	/** @return array<int, array<string, mixed>> */
	public function bouncer_get_violations(): array {
		return $this->bouncer_violations;
	}

	public function bouncer_load_manifest( string $plugin_slug, array $manifest ): void {
		$this->bouncer_manifests[ $plugin_slug ] = $manifest;
	}

	/**
	 * Flush buffered violations to wp_options on shutdown.
	 * Runs once at request end — avoids recursive DB calls in the hot path.
	 */
	public function flush_violations(): void {
		if ( empty( $this->bouncer_violations ) ) {
			return;
		}

		$this->bouncer_internal = true;

		$locked = false;
		if ( function_exists( 'bouncer_pending_violations_lock_acquire' ) ) {
			for ( $i = 0; $i < 15 && ! $locked; $i++ ) {
				$locked = bouncer_pending_violations_lock_acquire();
				if ( ! $locked ) {
					usleep( 5000 );
				}
			}
		}

		try {
			$pending = get_option( 'bouncer_pending_violations', array() );
			if ( ! is_array( $pending ) ) {
				$pending = array();
			}

			foreach ( $this->bouncer_violations as $v ) {
				if ( count( $pending ) >= 100 ) {
					break;
				}
				$pending[] = $v['record'];
			}

			update_option( 'bouncer_pending_violations', $pending, false );
		} finally {
			if ( $locked && function_exists( 'bouncer_pending_violations_lock_release' ) ) {
				bouncer_pending_violations_lock_release();
			}
			$this->bouncer_internal = false;
		}
	}

	/**
	 * Classify operation from first query keyword.
	 * Uses bitwise ASCII lowercase trick — no allocation.
	 */
	private function classify_operation( string $query ): string {
		$i   = 0;
		$len = strlen( $query );
		while ( $i < $len && ( ' ' === $query[ $i ] || "\t" === $query[ $i ] || "\n" === $query[ $i ] || "\r" === $query[ $i ] ) ) {
			++$i;
		}
		if ( $i >= $len ) {
			return 'OTHER';
		}

		$c1 = $query[ $i ] | "\x20";
		$c2 = ( $i + 1 < $len ) ? ( $query[ $i + 1 ] | "\x20" ) : '';

		return match ( $c1 ) {
			's'     => ( 'e' === $c2 ) ? 'SELECT' : 'OTHER',
			'i'     => 'INSERT',
			'u'     => 'UPDATE',
			'd'     => ( 'e' === $c2 ) ? 'DELETE' : ( ( 'r' === $c2 ) ? 'DDL' : 'OTHER' ),
			'c', 'a', 't' => 'DDL',
			default => 'OTHER',
		};
	}

	/**
	 * Attribute a query to its originating plugin via backtrace.
	 *
	 * @return array{source: string, file: string, type: string}
	 */
	private function attribute_query(): array {
		if ( null === $this->cached_paths ) {
			$this->cached_paths = array(
				'plugin_dir' => defined( 'WP_PLUGIN_DIR' ) ? WP_PLUGIN_DIR . '/' : WP_CONTENT_DIR . '/plugins/',
				'mu_dir'     => defined( 'WPMU_PLUGIN_DIR' ) ? WPMU_PLUGIN_DIR . '/' : WP_CONTENT_DIR . '/mu-plugins/',
				'theme_dir'  => function_exists( 'get_theme_root' ) ? get_theme_root() . '/' : WP_CONTENT_DIR . '/themes/',
			);
		}

		$trace      = debug_backtrace( DEBUG_BACKTRACE_IGNORE_ARGS, self::TRACE_DEPTH ); // phpcs:ignore WordPress.PHP.DevelopmentFunctions
		$plugin_dir = $this->cached_paths['plugin_dir'];
		$count      = count( $trace );

		for ( $i = 2; $i < $count; $i++ ) {
			$file = $trace[ $i ]['file'] ?? '';
			if ( '' === $file ) {
				continue;
			}

			// Skip wpdb and Bouncer internals.
			if ( false !== strpos( $file, 'class-wpdb.php' ) || false !== strpos( $file, '/bouncer/' ) || str_ends_with( $file, '/db.php' ) ) {
				continue;
			}

			// Plugin (most common).
			if ( str_starts_with( $file, $plugin_dir ) ) {
				$relative = substr( $file, strlen( $plugin_dir ) );
				$slash    = strpos( $relative, '/' );
				return array(
					'source' => ( false !== $slash ) ? substr( $relative, 0, $slash ) : $relative,
					'file'   => $relative,
					'type'   => 'plugin',
				);
			}

			if ( str_starts_with( $file, $this->cached_paths['mu_dir'] ) ) {
				return array(
					'source' => 'mu-plugin',
					'file'   => basename( $file ),
					'type'   => 'mu-plugin',
				);
			}

			if ( str_starts_with( $file, $this->cached_paths['theme_dir'] ) ) {
				$relative = substr( $file, strlen( $this->cached_paths['theme_dir'] ) );
				$slash    = strpos( $relative, '/' );
				return array(
					'source' => 'theme:' . ( ( false !== $slash ) ? substr( $relative, 0, $slash ) : $relative ),
					'file'   => $relative,
					'type'   => 'theme',
				);
			}

			if ( str_starts_with( $file, ABSPATH ) ) {
				return array(
					'source' => 'core',
					'file'   => substr( $file, strlen( ABSPATH ) ),
					'type'   => 'core',
				);
			}
		}

		return array(
			'source' => 'unknown',
			'file'   => '',
			'type'   => 'unknown',
		);
	}

	/**
	 * Extract primary table name. Single combined regex, DDL fallback.
	 */
	private function extract_table_name( string $query ): string {
		if ( preg_match( self::$table_regex, $query, $m ) ) {
			return $m[1];
		}
		if ( preg_match( '/\bTABLE\s+(?:IF\s+(?:NOT\s+)?EXISTS\s+)?`?(\w+)`?/i', $query, $m ) ) {
			return $m[1];
		}
		return '';
	}

	/**
	 * Strip table prefix using $this->prefix (not global $wpdb — that's us).
	 */
	private function strip_table_prefix( string $table ): string {
		if ( '' !== $this->prefix && str_starts_with( $table, $this->prefix ) ) {
			return substr( $table, strlen( $this->prefix ) );
		}
		return $table;
	}

	/**
	 * Check query against manifest.
	 *
	 * @return array<int, array<string, string>>
	 */
	private function check_manifest_violations(
		bool $is_write,
		string $table,
		string $table_short,
		array $manifest,
		string $plugin_slug
	): array {
		$violations = array();
		$db_caps    = $manifest['capabilities']['database'] ?? null;
		if ( null === $db_caps ) {
			return $violations;
		}

		$key     = $is_write ? 'write' : 'read';
		$allowed = $db_caps[ $key ] ?? array();

		if ( ! empty( $allowed ) && ! in_array( $table, $allowed, true ) && ! in_array( $table_short, $allowed, true ) ) {
			$violations[] = array(
				'type'     => $is_write ? 'unauthorized_table_write' : 'unauthorized_table_read',
				'message'  => sprintf(
					'Plugin "%s" %s table "%s" which is not in its manifest.',
					$plugin_slug,
					$is_write ? 'wrote to' : 'read from',
					$table
				),
				'severity' => $is_write ? 'warning' : 'info',
			);
		}

		return $violations;
	}

	/**
	 * Buffer violations in memory. Sanitizes query once here instead of per-log-entry.
	 */
	private function buffer_violations( array $violations, array $attribution, string $query, string $table, string $operation ): void {
		if ( count( $this->bouncer_violations ) >= self::VIOLATION_CAP ) {
			return;
		}

		$safe_query = $this->strip_query_values( $query );

		foreach ( $violations as $violation ) {
			if ( count( $this->bouncer_violations ) >= self::VIOLATION_CAP ) {
				break;
			}
			$this->bouncer_violations[] = array(
				'violation' => $violation,
				'record'    => array(
					'severity'    => $violation['severity'],
					'channel'     => 'database',
					'plugin_slug' => $attribution['source'],
					'event_type'  => $violation['type'],
					'message'     => $violation['message'],
					'context'     => array(
						'table'     => $table,
						'operation' => $operation,
						'file'      => $attribution['file'],
						'query'     => $safe_query,
					),
					'time'        => time(),
				),
			);
		}
	}

	/**
	 * Strip values from query for safe logging.
	 * Handles escaped quotes. Avoids mangling table names with digits.
	 */
	private function strip_query_values( string $query ): string {
		$s = str_replace( array( "\\'", '\\"' ), '', $query );
		$s = preg_replace( "/'[^']*'/", "'?'", $s );
		$s = preg_replace( '/"[^"]*"/', '"?"', $s );
		$s = preg_replace( '/(?<=[=<>!,(])\s*\d+(?:\.\d+)?/', ' ?', $s );

		if ( strlen( $s ) > self::MAX_QUERY_LOG_LENGTH ) {
			$s = substr( $s, 0, self::MAX_QUERY_LOG_LENGTH ) . '...';
		}
		return $s;
	}
}

// Replace global $wpdb with monitored version.
if ( ! defined( 'BOUNCER_DB_DROPIN_LOADED' ) ) {
	define( 'BOUNCER_DB_DROPIN_LOADED', true );

	// phpcs:ignore WordPress.WP.GlobalVariablesOverride.Prohibited
	$GLOBALS['wpdb'] = new Bouncer_DB( DB_USER, DB_PASSWORD, DB_NAME, DB_HOST );

	if ( ! empty( $GLOBALS['table_prefix'] ) ) {
		$GLOBALS['wpdb']->set_prefix( $GLOBALS['table_prefix'] );
	}
}
