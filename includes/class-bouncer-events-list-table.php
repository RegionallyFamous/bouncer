<?php
/**
 * Event log list table (wp-admin list table pattern).
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

if ( ! class_exists( 'WP_List_Table', false ) ) {
	require_once ABSPATH . 'wp-admin/includes/class-wp-list-table.php';
}

/**
 * Displays Bouncer security events using WP_List_Table.
 */
class Bouncer_Events_List_Table extends WP_List_Table {

	private Bouncer_Logger $logger;

	public function __construct( Bouncer_Logger $logger ) {
		parent::__construct(
			array(
				'singular' => 'event',
				'plural'   => 'events',
				'ajax'     => false,
			)
		);
		$this->logger = $logger;
	}

	/**
	 * @return array<string, string>
	 */
	public function get_columns() {
		return array(
			'event_time'  => __( 'Time', 'bouncer' ),
			'severity'    => __( 'Severity', 'bouncer' ),
			'channel'     => __( 'Channel', 'bouncer' ),
			'plugin_slug' => __( 'Plugin', 'bouncer' ),
			'event_type'  => __( 'Event', 'bouncer' ),
			'message'     => __( 'Message', 'bouncer' ),
		);
	}

	/**
	 * @return array<string, array{0: string, 1: bool}>
	 */
	protected function get_sortable_columns() {
		return array(
			'event_time' => array( 'event_time', true ),
			'severity'   => array( 'severity', false ),
		);
	}

	/**
	 * @param object $item Row object.
	 * @param string $column_name Column key.
	 * @return string
	 */
	protected function column_default( $item, $column_name ) {
		switch ( $column_name ) {
			case 'severity':
				return sprintf(
					'<span class="bouncer-badge bouncer-badge-%1$s">%2$s</span>',
					esc_attr( $item->severity ),
					esc_html( ucfirst( $item->severity ) )
				);
			case 'channel':
				return esc_html( $item->channel );
			case 'plugin_slug':
				return '<code>' . esc_html( $item->plugin_slug ) . '</code>';
			case 'event_type':
				return '<code>' . esc_html( $item->event_type ) . '</code>';
			case 'message':
				return esc_html( $item->message );
			default:
				return '';
		}
	}

	/**
	 * @param object $item Row.
	 * @return string
	 */
	protected function column_event_time( $item ) {
		return sprintf(
			'<span class="bouncer-event-time">%s</span>',
			esc_html( wp_date( 'M j, g:ia', strtotime( $item->event_time ) ) )
		);
	}

	/**
	 * @param string $which top|bottom.
	 */
	protected function extra_tablenav( $which ) {
		if ( 'top' !== $which ) {
			return;
		}

		$severity = isset( $_GET['severity'] ) ? sanitize_text_field( wp_unslash( $_GET['severity'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$plugin   = isset( $_GET['plugin'] ) ? sanitize_text_field( wp_unslash( $_GET['plugin'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		?>
		<div class="alignleft actions">
			<label class="screen-reader-text" for="bouncer-filter-severity"><?php esc_html_e( 'Filter by severity', 'bouncer' ); ?></label>
			<select name="severity" id="bouncer-filter-severity">
				<option value=""><?php esc_html_e( 'All severities', 'bouncer' ); ?></option>
				<option value="info" <?php selected( $severity, 'info' ); ?>><?php esc_html_e( 'Info', 'bouncer' ); ?></option>
				<option value="warning" <?php selected( $severity, 'warning' ); ?>><?php esc_html_e( 'Warning', 'bouncer' ); ?></option>
				<option value="critical" <?php selected( $severity, 'critical' ); ?>><?php esc_html_e( 'Critical', 'bouncer' ); ?></option>
				<option value="emergency" <?php selected( $severity, 'emergency' ); ?>><?php esc_html_e( 'Emergency', 'bouncer' ); ?></option>
			</select>
			<label class="screen-reader-text" for="bouncer-filter-plugin"><?php esc_html_e( 'Filter by plugin slug', 'bouncer' ); ?></label>
			<input type="search" id="bouncer-filter-plugin" name="plugin" value="<?php echo esc_attr( $plugin ); ?>" placeholder="<?php esc_attr_e( 'Plugin slug…', 'bouncer' ); ?>" />
			<?php submit_button( __( 'Filter', 'bouncer' ), '', 'filter_action', false ); ?>
		</div>
		<?php
	}

	/**
	 * @return string[]
	 */
	protected function get_table_classes() {
		return array( 'widefat', 'fixed', 'striped', 'bouncer-events-table', $this->_args['plural'] );
	}

	/**
	 * @return string
	 */
	protected function get_primary_column_name() {
		return 'message';
	}

	public function no_items() {
		esc_html_e( 'No events found.', 'bouncer' );
	}

	public function prepare_items(): void {
		$per_page = $this->get_items_per_page( 'bouncer_events_per_page', 50 );
		$paged    = $this->get_pagenum();

		$severity = isset( $_GET['severity'] ) ? sanitize_text_field( wp_unslash( $_GET['severity'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$plugin   = isset( $_GET['plugin'] ) ? sanitize_text_field( wp_unslash( $_GET['plugin'] ) ) : ''; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		$orderby = isset( $_GET['orderby'] ) ? sanitize_key( wp_unslash( $_GET['orderby'] ) ) : 'event_time'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended
		$order   = isset( $_GET['order'] ) ? strtoupper( sanitize_text_field( wp_unslash( $_GET['order'] ) ) ) : 'DESC'; // phpcs:ignore WordPress.Security.NonceVerification.Recommended

		$result = $this->logger->get_events(
			array(
				'severity' => $severity ?: null,
				'plugin'   => $plugin ?: null,
				'per_page' => $per_page,
				'page'     => $paged,
				'orderby'  => $orderby,
				'order'    => 'ASC' === $order ? 'ASC' : 'DESC',
			)
		);

		$this->items = $result['events'];

		$this->set_pagination_args(
			array(
				'total_items' => $result['total'],
				'per_page'    => $per_page,
				'total_pages' => max( 1, $result['pages'] ),
			)
		);
	}

	/**
	 * @param object $item Row.
	 * @return string
	 */
	protected function get_row_css_class( $item ) {
		return 'bouncer-event-' . sanitize_html_class( $item->severity, 'info' );
	}

	/**
	 * @param object $item Row.
	 */
	public function single_row( $item ) {
		echo '<tr class="' . esc_attr( $this->get_row_css_class( $item ) ) . '">';
		$this->single_row_columns( $item );
		echo '</tr>';
	}
}
