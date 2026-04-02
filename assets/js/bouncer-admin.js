/**
 * Bouncer Admin JavaScript.
 * @param {object} $ jQuery.
 */

(function ($) {
	'use strict';

	const S = () => (typeof bouncerAdmin !== 'undefined' && bouncerAdmin.strings) || {};

	function formatScanProgress(done, total) {
		const tpl = S().scanAllProgress || 'Scanned %1$d of %2$d…';
		return tpl.replace(/%1\$d/g, String(done)).replace(/%2\$d/g, String(total));
	}

	function formatContinueLeft(n) {
		const tpl = S().continueScanLeft || 'Continue scan (%d left)';
		return tpl.replace('%d', String(n));
	}

	function extractErrorMessage(response) {
		const d = response && response.data;
		if (d && typeof d === 'object' && d.message) {
			return d.message;
		}
		if (typeof d === 'string' && d) {
			return d;
		}
		return S().error || 'Error';
	}

	/**
	 * Handle rescan button clicks.
	 */
	$(document).on('click', '.bouncer-rescan', function (e) {
		e.preventDefault();

		const $btn = $(this);
		const plugin = $btn.data('plugin');
		const origText = $btn.text();

		$btn.text(S().scanning || '…').prop('disabled', true);

		$.ajax({
			url: bouncerAdmin.ajaxUrl,
			method: 'POST',
			data: {
				action: 'bouncer_scan_plugin',
				nonce: bouncerAdmin.nonce,
				plugin,
			},
			success(response) {
				if (response.success) {
					$btn.text(S().complete || 'OK');

					setTimeout(function () {
						window.location.reload();
					}, 1000);
				} else {
					$btn.text(extractErrorMessage(response));
					setTimeout(function () {
						$btn.text(origText).prop('disabled', false);
					}, 3000);
				}
			},
			error() {
				$btn.text(S().error || 'Error');
				setTimeout(function () {
					$btn.text(origText).prop('disabled', false);
				}, 2000);
			},
		});
	});

	/**
	 * Handle generate manifest button clicks (legacy / API).
	 */
	$(document).on('click', '.bouncer-generate-manifest', function (e) {
		e.preventDefault();

		const $btn = $(this);
		const plugin = $btn.data('plugin');
		const origText = $btn.text();

		$btn.text(S().scanning || '…').prop('disabled', true);

		$.ajax({
			url: bouncerAdmin.ajaxUrl,
			method: 'POST',
			data: {
				action: 'bouncer_generate_manifest',
				nonce: bouncerAdmin.nonce,
				plugin,
			},
			success(response) {
				if (response.success) {
					window.location.reload();
				} else {
					$btn.text(extractErrorMessage(response));
					setTimeout(function () {
						$btn.text(origText).prop('disabled', false);
					}, 3000);
				}
			},
			error() {
				$btn.text(S().error || 'Error').prop('disabled', false);
			},
		});
	});

	/**
	 * Scan all installed plugins in batches (one rate-limit slot per request).
	 */
	$(document).on('click', '.bouncer-scan-all-installed', function (e) {
		e.preventDefault();

		const $btn = $(this);
		const $status = $('.bouncer-scan-all-status');
		const origLabel =
			$btn.data('origLabel') || $btn.text();
		$btn.data('origLabel', origLabel);

		let queue = $btn.data('pendingSlugs');
		let doneSoFar = $btn.data('scanDoneSoFar');
		if (!Array.isArray(queue) || queue.length < 1) {
			queue = bouncerAdmin.installedPluginSlugs || [];
			doneSoFar = 0;
		}
		if (!Array.isArray(queue) || queue.length < 1) {
			$status.text(S().scanAllEmpty || '');
			return;
		}

		const totalAll = (bouncerAdmin.installedPluginSlugs || []).length;
		const total = totalAll > 0 ? totalAll : queue.length;
		const batchSize = Math.max(
			1,
			Math.min(20, parseInt(bouncerAdmin.scanBatchSize, 10) || 10)
		);

		$btn.prop('disabled', true);
		$status.text(S().scanAllRunning || '…');

		function finishOk() {
			$btn.removeData('pendingSlugs').removeData('scanDoneSoFar');
			$status.text(S().scanAllDone || '…');
			setTimeout(function () {
				window.location.reload();
			}, 800);
		}

		function runNext(remaining, done) {
			if (remaining.length < 1) {
				finishOk();
				return;
			}

			const chunk = remaining.slice(0, batchSize);
			const rest = remaining.slice(batchSize);

			$status.text(formatScanProgress(done, total));

			$.ajax({
				url: bouncerAdmin.ajaxUrl,
				method: 'POST',
				data: {
					action: 'bouncer_scan_batch',
					nonce: bouncerAdmin.nonce,
					slugs: JSON.stringify(chunk),
				},
				success(response) {
					if (response.success && response.data) {
						const processed = parseInt(response.data.processed, 10) || 0;
						const nextDone = done + processed;
						$btn.removeData('pendingSlugs').removeData('scanDoneSoFar');
						if (rest.length < 1) {
							finishOk();
						} else {
							runNext(rest, nextDone);
						}
					} else {
						const data = response && response.data;
						const code =
							data && typeof data === 'object' ? data.code : '';
						if (code === 'rate_limited') {
							const left = remaining.length;
							$btn
								.data('pendingSlugs', remaining)
								.data('scanDoneSoFar', done)
								.text(formatContinueLeft(left))
								.prop('disabled', false);
							$status.text(
								(data && data.message) ||
									S().rateLimited ||
									''
							);
						} else {
							$btn.text(origLabel).prop('disabled', false);
							$status.text(extractErrorMessage(response));
						}
					}
				},
				error() {
					$btn.text(origLabel).prop('disabled', false);
					$status.text(S().error || '');
				},
			});
		}

		runNext(queue, doneSoFar);
	});

	/**
	 * Handle notice dismissals.
	 */
	$(document).on('click', '.bouncer-dismiss-notice', function (e) {
		e.preventDefault();

		const notice = $(this).data('notice');

		$.ajax({
			url: bouncerAdmin.ajaxUrl,
			method: 'POST',
			data: {
				action: 'bouncer_dismiss_notice',
				nonce: bouncerAdmin.nonce,
				notice,
			},
		});

		$(this).closest('.notice').fadeOut();
	});
})(jQuery);
