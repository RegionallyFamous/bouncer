<?php
/**
 * Site Health integration (tests + Site Health Info).
 *
 * @package Bouncer
 */

defined( 'ABSPATH' ) || exit;

/**
 * Registers Bouncer with WordPress Site Health.
 */
class Bouncer_Site_Health {

	public static function init(): void {
		add_filter( 'site_status_tests', array( __CLASS__, 'register_tests' ) );
		add_filter( 'debug_information', array( __CLASS__, 'debug_information' ) );
	}

	/**
	 * @param array<string, array<string, mixed>> $tests Site Health tests.
	 * @return array<string, array<string, mixed>>
	 */
	public static function register_tests( array $tests ): array {
		if ( ! isset( $tests['direct'] ) || ! is_array( $tests['direct'] ) ) {
			$tests['direct'] = array();
		}
		$tests['direct']['bouncer_db_monitoring']  = array(
			'label' => __( 'Bouncer database monitoring (db.php)', 'bouncer' ),
			'test'  => array( __CLASS__, 'test_db_monitoring' ),
		);
		$tests['direct']['bouncer_operating_mode'] = array(
			'label' => __( 'Bouncer operating mode', 'bouncer' ),
			'test'  => array( __CLASS__, 'test_operating_mode' ),
		);
		$tests['direct']['bouncer_brain'] = array(
			'label' => __( 'Bouncer Brain (optional on-server check)', 'bouncer' ),
			'test'  => array( __CLASS__, 'test_bouncer_brain' ),
		);
		return $tests;
	}

	/**
	 * @return array<string, mixed>
	 */
	public static function test_db_monitoring(): array {
		$installed = (bool) get_option( 'bouncer_db_dropin_installed', false );
		$conflict  = (bool) get_option( 'bouncer_db_dropin_conflict', false );
		$url       = bouncer_admin_url();

		if ( $conflict ) {
			return array(
				'label'       => __( 'Bouncer could not install the database monitor', 'bouncer' ),
				'status'      => 'recommended',
				'badge'       => array(
					'label' => __( 'Security', 'bouncer' ),
					'color' => 'orange',
				),
				'description' => '<p>' . esc_html__( 'Another db.php drop-in is present. Bouncer cannot attribute database queries to plugins until that conflict is resolved.', 'bouncer' ) . '</p>',
				'actions'     => sprintf(
					'<p><a href="%s">%s</a></p>',
					esc_url( $url ),
					esc_html__( 'Open Bouncer', 'bouncer' )
				),
				'test'        => 'bouncer_db_monitoring',
			);
		}

		if ( $installed && defined( 'BOUNCER_DB_DROPIN_LOADED' ) ) {
			return array(
				'label'       => __( 'Bouncer database monitoring is active', 'bouncer' ),
				'status'      => 'good',
				'badge'       => array(
					'label' => __( 'Security', 'bouncer' ),
					'color' => 'blue',
				),
				'description' => '<p>' . esc_html__( 'The db.php drop-in is loaded. Query attribution is available for this request.', 'bouncer' ) . '</p>',
				'actions'     => '',
				'test'        => 'bouncer_db_monitoring',
			);
		}

		if ( $installed ) {
			return array(
				'label'       => __( 'Bouncer db.php is installed', 'bouncer' ),
				'status'      => 'good',
				'badge'       => array(
					'label' => __( 'Security', 'bouncer' ),
					'color' => 'blue',
				),
				'description' => '<p>' . esc_html__( 'The drop-in is present. It loads on the next full bootstrap.', 'bouncer' ) . '</p>',
				'actions'     => '',
				'test'        => 'bouncer_db_monitoring',
			);
		}

		return array(
			'label'       => __( 'Bouncer database monitoring is not active', 'bouncer' ),
			'status'      => 'recommended',
			'badge'       => array(
				'label' => __( 'Security', 'bouncer' ),
				'color' => 'orange',
			),
			'description' => '<p>' . esc_html__( 'Without the db.php drop-in, Bouncer cannot monitor SQL at the database layer. Other monitoring channels may still work.', 'bouncer' ) . '</p>',
			'actions'     => sprintf(
				'<p><a href="%s">%s</a></p>',
				esc_url( $url ),
				esc_html__( 'Open Bouncer', 'bouncer' )
			),
			'test'        => 'bouncer_db_monitoring',
		);
	}

	/**
	 * @return array<string, mixed>
	 */
	public static function test_operating_mode(): array {
		$mode = get_option( 'bouncer_mode', 'monitor' );
		$url  = bouncer_admin_url( 'settings' );

		if ( 'enforce' === $mode ) {
			return array(
				'label'       => __( 'Bouncer is in Enforce mode', 'bouncer' ),
				'status'      => 'recommended',
				'badge'       => array(
					'label' => __( 'Security', 'bouncer' ),
					'color' => 'orange',
				),
				'description' => '<p>' . esc_html__( 'Policy violations may be blocked or plugins emergency-deactivated. Ensure you have validated behavior in Monitor mode first.', 'bouncer' ) . '</p>',
				'actions'     => sprintf(
					'<p><a href="%s">%s</a></p>',
					esc_url( $url ),
					esc_html__( 'Review Bouncer settings', 'bouncer' )
				),
				'test'        => 'bouncer_operating_mode',
			);
		}

		return array(
			'label'       => __( 'Bouncer is in Monitor mode', 'bouncer' ),
			'status'      => 'good',
			'badge'       => array(
				'label' => __( 'Security', 'bouncer' ),
				'color' => 'blue',
			),
			'description' => '<p>' . esc_html__( 'Bouncer is observing and logging without blocking. This is the recommended starting mode.', 'bouncer' ) . '</p>',
			'actions'     => sprintf(
				'<p><a href="%s">%s</a></p>',
				esc_url( $url ),
				esc_html__( 'Bouncer settings', 'bouncer' )
			),
			'test'        => 'bouncer_operating_mode',
		);
	}

	/**
	 * @return array<string, mixed>
	 */
	public static function test_bouncer_brain(): array {
		$url     = bouncer_admin_url( 'settings' );
		$enabled = (bool) get_option( 'bouncer_local_brain_enabled', false );

		if ( ! $enabled ) {
			return array(
				'label'       => __( 'Bouncer Brain is off (Quick Look still runs)', 'bouncer' ),
				'status'      => 'good',
				'badge'       => array(
					'label' => __( 'Security', 'bouncer' ),
					'color' => 'blue',
				),
				'description' => '<p>' . esc_html__( 'That’s fine — every plugin still gets an automatic Quick Look. Turn on Bouncer Brain in Settings when you want an optional on-server second opinion.', 'bouncer' ) . '</p>',
				'actions'     => sprintf(
					'<p><a href="%s">%s</a></p>',
					esc_url( $url ),
					esc_html__( 'Bouncer settings', 'bouncer' )
				),
				'test'        => 'bouncer_brain',
			);
		}

		if ( ! class_exists( 'Bouncer_AI_Experience' ) ) {
			return array(
				'label'       => __( 'Bouncer Brain status unavailable', 'bouncer' ),
				'status'      => 'recommended',
				'badge'       => array(
					'label' => __( 'Security', 'bouncer' ),
					'color' => 'orange',
				),
				'description' => '<p>' . esc_html__( 'We couldn’t load the helper that explains Brain status. Quick Look is unaffected.', 'bouncer' ) . '</p>',
				'actions'     => sprintf(
					'<p><a href="%s">%s</a></p>',
					esc_url( $url ),
					esc_html__( 'Bouncer settings', 'bouncer' )
				),
				'test'        => 'bouncer_brain',
			);
		}

		$panel = Bouncer_AI_Experience::local_brain_panel();
		if ( ! empty( $panel['ready'] ) ) {
			return array(
				'label'       => __( 'Bouncer Brain is ready on this host', 'bouncer' ),
				'status'      => 'good',
				'badge'       => array(
					'label' => __( 'Security', 'bouncer' ),
					'color' => 'blue',
				),
				'description' => '<p>' . esc_html( $panel['body'] ) . '</p>',
				'actions'     => sprintf(
					'<p><a href="%s">%s</a></p>',
					esc_url( $url ),
					esc_html__( 'Bouncer settings', 'bouncer' )
				),
				'test'        => 'bouncer_brain',
			);
		}

		$description = '<p>' . esc_html( $panel['body'] ) . '</p>';
		if ( '' !== $panel['hint'] ) {
			$description .= '<p>' . esc_html( $panel['hint'] ) . '</p>';
		}

		return array(
			'label'       => $panel['title'],
			'status'      => 'recommended',
			'badge'       => array(
				'label' => __( 'Security', 'bouncer' ),
				'color' => 'orange',
			),
			'description' => $description,
			'actions'     => sprintf(
				'<p><a href="%s">%s</a></p>',
				esc_url( $url ),
				esc_html__( 'Bouncer settings', 'bouncer' )
			),
			'test'        => 'bouncer_brain',
		);
	}

	/**
	 * @param array<string, array<string, mixed>> $info Debug info sections.
	 * @return array<string, array<string, mixed>>
	 */
	public static function debug_information( array $info ): array {
		$info['bouncer'] = array(
			'label'  => __( 'Bouncer', 'bouncer' ),
			'fields' => array(
				'version'       => array(
					'label' => __( 'Version', 'bouncer' ),
					'value' => BOUNCER_VERSION,
				),
				'mode'          => array(
					'label' => __( 'Operating mode', 'bouncer' ),
					'value' => get_option( 'bouncer_mode', 'monitor' ),
				),
				'db_dropin'     => array(
					'label' => __( 'db.php installed', 'bouncer' ),
					'value' => get_option( 'bouncer_db_dropin_installed', false ) ? __( 'Yes', 'bouncer' ) : __( 'No', 'bouncer' ),
				),
				'db_conflict'   => array(
					'label' => __( 'db.php conflict', 'bouncer' ),
					'value' => get_option( 'bouncer_db_dropin_conflict', false ) ? __( 'Yes', 'bouncer' ) : __( 'No', 'bouncer' ),
				),
				'dropin_loaded' => array(
					'label' => __( 'Bouncer DB class loaded this request', 'bouncer' ),
					'value' => defined( 'BOUNCER_DB_DROPIN_LOADED' ) && BOUNCER_DB_DROPIN_LOADED ? __( 'Yes', 'bouncer' ) : __( 'No', 'bouncer' ),
				),
				'local_brain_on' => array(
					'label' => __( 'Bouncer Brain enabled in settings', 'bouncer' ),
					'value' => get_option( 'bouncer_local_brain_enabled', false ) ? __( 'Yes', 'bouncer' ) : __( 'No', 'bouncer' ),
				),
				'local_brain_ready' => array(
					'label' => __( 'Bouncer Brain ready (FFI + model file)', 'bouncer' ),
					'value' => ( class_exists( 'Bouncer_AI_Experience' ) && Bouncer_AI_Experience::local_brain_panel()['ready'] ) ? __( 'Yes', 'bouncer' ) : __( 'No', 'bouncer' ),
				),
				'php_ffi'       => array(
					'label' => __( 'PHP FFI extension loaded', 'bouncer' ),
					'value' => extension_loaded( 'ffi' ) ? __( 'Yes', 'bouncer' ) : __( 'No', 'bouncer' ),
				),
			),
		);
		return $info;
	}
}
