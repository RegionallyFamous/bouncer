<?php
/**
 * Bouncer Uninstall Handler.
 *
 * Removes all Bouncer data when the plugin is deleted via the admin.
 *
 * @package Bouncer
 */

defined( 'WP_UNINSTALL_PLUGIN' ) || exit;

global $wpdb;

$bouncer_plugin_dir = __DIR__;
if ( is_readable( $bouncer_plugin_dir . '/includes/class-bouncer-filesystem.php' ) ) {
	require_once $bouncer_plugin_dir . '/includes/class-bouncer-filesystem.php';
}

// Remove custom tables.
$bouncer_tables = array(
	$wpdb->prefix . 'bouncer_events',
	$wpdb->prefix . 'bouncer_manifests',
	$wpdb->prefix . 'bouncer_checksums',
	$wpdb->prefix . 'bouncer_hook_baselines',
);

foreach ( $bouncer_tables as $bouncer_table ) {
	$wpdb->query( "DROP TABLE IF EXISTS {$bouncer_table}" ); // phpcs:ignore WordPress.DB.PreparedSQL.InterpolatedNotPrepared
}

// Remove options.
$wpdb->query( "DELETE FROM {$wpdb->options} WHERE option_name LIKE 'bouncer\_%'" );

// Remove mu-plugin.
$bouncer_mu_file = WPMU_PLUGIN_DIR . '/00-bouncer-loader.php';
if ( file_exists( $bouncer_mu_file ) && class_exists( 'Bouncer_Filesystem', false ) ) {
	Bouncer_Filesystem::delete_file( $bouncer_mu_file );
}

// Remove db.php if it's ours.
$bouncer_db_dropin = WP_CONTENT_DIR . '/db.php';
if ( file_exists( $bouncer_db_dropin ) && class_exists( 'Bouncer_Filesystem', false ) ) {
	$bouncer_db_content = Bouncer_Filesystem::get_contents( $bouncer_db_dropin );
	if ( is_string( $bouncer_db_content ) && false !== strpos( $bouncer_db_content, '@package Bouncer' ) ) {
		Bouncer_Filesystem::delete_file( $bouncer_db_dropin );
	}
}

// Remove data directory.
$bouncer_data_dir = WP_CONTENT_DIR . '/bouncer';
if ( is_dir( $bouncer_data_dir ) && class_exists( 'Bouncer_Filesystem', false ) ) {
	Bouncer_Filesystem::delete_tree( $bouncer_data_dir );
}

// Remove optional Brain helper directory under uploads (not part of the plugin zip).
if ( class_exists( 'Bouncer_Filesystem', false ) && function_exists( 'wp_upload_dir' ) ) {
	$bouncer_uploads = wp_upload_dir();
	if ( empty( $bouncer_uploads['error'] ) && ! empty( $bouncer_uploads['basedir'] ) ) {
		$bouncer_brain_parent = trailingslashit( $bouncer_uploads['basedir'] ) . 'bouncer';
		if ( is_dir( $bouncer_brain_parent ) ) {
			Bouncer_Filesystem::delete_tree( $bouncer_brain_parent );
		}
	}
}

// Clear cron events.
wp_clear_scheduled_hook( 'bouncer_file_integrity_check' );
wp_clear_scheduled_hook( 'bouncer_cleanup_old_events' );
wp_clear_scheduled_hook( 'bouncer_weekly_report' );

// Remove Bouncer-owned transients (stored in options table).
$bouncer_transient_like = array(
	'_transient_bouncer_%',
	'_transient_timeout_bouncer_%',
	'_site_transient_bouncer_%',
	'_site_transient_timeout_bouncer_%',
);
foreach ( $bouncer_transient_like as $bouncer_like ) {
	$wpdb->query( $wpdb->prepare( "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s", $bouncer_like ) );
}
