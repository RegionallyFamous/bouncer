/**
 * Bouncer Admin JavaScript
 *
 * @package Bouncer
 */

/* global jQuery, bouncerAdmin */

( function( $ ) {
	'use strict';

	/**
	 * Handle rescan button clicks.
	 */
	$( document ).on( 'click', '.bouncer-rescan', function( e ) {
		e.preventDefault();

		var $btn     = $( this );
		var plugin   = $btn.data( 'plugin' );
		var origText = $btn.text();

		$btn.text( bouncerAdmin.strings.scanning ).prop( 'disabled', true );

		$.ajax( {
			url: bouncerAdmin.ajaxUrl,
			method: 'POST',
			data: {
				action: 'bouncer_scan_plugin',
				nonce: bouncerAdmin.nonce,
				plugin: plugin
			},
			success: function( response ) {
				if ( response.success ) {
					$btn.text( bouncerAdmin.strings.complete );

					// Reload after a moment to show updated data.
					setTimeout( function() {
						window.location.reload();
					}, 1000 );
				} else {
					$btn.text( bouncerAdmin.strings.error );
					setTimeout( function() {
						$btn.text( origText ).prop( 'disabled', false );
					}, 2000 );
				}
			},
			error: function() {
				$btn.text( bouncerAdmin.strings.error );
				setTimeout( function() {
					$btn.text( origText ).prop( 'disabled', false );
				}, 2000 );
			}
		} );
	} );

	/**
	 * Handle generate manifest button clicks.
	 */
	$( document ).on( 'click', '.bouncer-generate-manifest', function( e ) {
		e.preventDefault();

		var $btn     = $( this );
		var plugin   = $btn.data( 'plugin' );

		$btn.text( bouncerAdmin.strings.scanning ).prop( 'disabled', true );

		$.ajax( {
			url: bouncerAdmin.ajaxUrl,
			method: 'POST',
			data: {
				action: 'bouncer_generate_manifest',
				nonce: bouncerAdmin.nonce,
				plugin: plugin
			},
			success: function( response ) {
				if ( response.success ) {
					window.location.reload();
				} else {
					$btn.text( bouncerAdmin.strings.error ).prop( 'disabled', false );
				}
			},
			error: function() {
				$btn.text( bouncerAdmin.strings.error ).prop( 'disabled', false );
			}
		} );
	} );

	/**
	 * Handle notice dismissals.
	 */
	$( document ).on( 'click', '.bouncer-dismiss-notice', function( e ) {
		e.preventDefault();

		var notice = $( this ).data( 'notice' );

		$.ajax( {
			url: bouncerAdmin.ajaxUrl,
			method: 'POST',
			data: {
				action: 'bouncer_dismiss_notice',
				nonce: bouncerAdmin.nonce,
				notice: notice
			}
		} );

		$( this ).closest( '.notice' ).fadeOut();
	} );

} )( jQuery );
