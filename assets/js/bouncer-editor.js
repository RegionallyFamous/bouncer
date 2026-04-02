/**
 * Block editor: lightweight pre-publish reminder (Bouncer).
 *
 * @param {Object} wp WordPress editor globals (`window.wp`).
 */
(function (wp) {
	if (!wp || !wp.plugins || !wp.editPost || !wp.element) {
		return;
	}
	const el = wp.element.createElement;
	wp.plugins.registerPlugin('bouncer-prepublish', {
		render() {
			return el(
				wp.editPost.PluginPrePublishPanel,
				{
					title: 'Bouncer',
					initialOpen: false,
				},
				el(
					'p',
					{ className: 'bouncer-editor-panel-note' },
					'Server-side monitoring still applies when this post goes live. Use Bouncer under Tools for full behavioral status.'
				)
			);
		},
	});
})(window.wp);
