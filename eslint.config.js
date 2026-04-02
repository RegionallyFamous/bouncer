'use strict';

const eslint = require( '@eslint/js' );
const globals = require( 'globals' );
const jsdoc = require( 'eslint-plugin-jsdoc' );

module.exports = [
	{
		ignores: [ 'vendor/**', 'node_modules/**' ],
	},
	eslint.configs.recommended,
	jsdoc.configs[ 'flat/recommended-error' ],
	{
		files: [ 'assets/js/**/*.js' ],
		languageOptions: {
			ecmaVersion: 'latest',
			sourceType: 'script',
			globals: {
				...globals.browser,
				...globals.jquery,
				bouncerAdmin: 'readonly',
				wp: 'readonly',
			},
		},
	},
];
