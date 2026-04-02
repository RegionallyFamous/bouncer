=== Bouncer ===
Contributors: regionallyfamous
Tags: security, firewall, plugin-monitor, ai-security, behavior-monitoring
Requires at least: 7.0
Tested up to: 7.0
Requires PHP: 8.1
Stable tag: 1.0.5
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

A plugin behavior firewall for WordPress. Watches what your plugins actually do and uses AI to catch the ones that misbehave.

== Description ==

Bouncer monitors what your WordPress plugins actually do — not just what they say they'll do.

Every plugin you install gets full access to your database, your filesystem, and your network. A contact form plugin can read your user passwords. A carousel plugin can phone home to a server you've never heard of.

Bouncer watches four channels:

**Database Query Attribution** — Every database query is attributed to the plugin that made it. A gallery plugin writing to your users table? Bouncer flags it immediately.

**Outbound HTTP Monitoring** — Every outbound HTTP request is tracked and checked against per-plugin allowlists. Undeclared domains get flagged.

**Hook Registration Auditing** — Bouncer monitors which plugins register on sensitive WordPress hooks (authentication, user management, email) and detects anomalies.

**File Integrity Monitoring** — SHA-256 checksums are recorded for every plugin file. Any modification outside of an update process triggers an alert.

**AI-Powered Code Analysis** — When you install or update a plugin, Bouncer can send a structural fingerprint (not your source code) to Claude for intelligent analysis. The AI evaluates what the plugin does, whether that's normal for its type, and what changed since the last version.

= How It Works =

1. **Install Bouncer** — it sets up monitoring automatically.
2. **Plugin Manifests** — Bouncer generates a capability manifest for each plugin via static analysis, documenting every database table, outbound domain, hook, and dangerous API call.
3. **Runtime Monitoring** — On every request, Bouncer watches plugin behavior against these manifests.
4. **Alerts** — Violations trigger notifications based on severity (info, warning, critical, emergency).
5. **Enforcement** — In Enforce mode, Bouncer actively blocks manifest violations and can emergency-deactivate compromised plugins.

= AI Scanning =

With an Anthropic API key, Bouncer uses Claude to:

* Analyze plugin code behavior in plain English
* Detect obfuscated payloads and supply-chain compromises
* Compare version changes and flag suspicious additions
* Generate risk scores and human-readable security reports

Bouncer never sends your source code off-site. It sends structural fingerprints — function call graphs, hook registrations, API usage patterns — that cannot be reverse-engineered into source code.

= Third-party services (WordPress.org Guideline 6) =

**Anthropic (Claude API)** — When you enable AI scanning and configure an API key via **Settings → Connectors**, the `ANTHROPIC_API_KEY` environment variable, or the `ANTHROPIC_API_KEY` PHP constant (same priority WordPress uses for Connectors), Bouncer sends **only** structural fingerprints to Anthropic’s API for analysis. By enabling this feature you direct Bouncer to contact Anthropic on your behalf.

* Commercial Terms: https://www.anthropic.com/legal/commercial-terms
* Privacy Policy: https://www.anthropic.com/legal/privacy

= Monitor vs. Enforce =

**Monitor Mode** (recommended to start): Logs everything, blocks nothing. Run this for a week to learn your plugins' normal behavior.

**Enforce Mode**: Actively blocks manifest violations, including unauthorized database writes, undeclared outbound HTTP calls, and can emergency-deactivate plugins with file integrity violations.

== Installation ==

1. Upload the `bouncer` folder to `/wp-content/plugins/`.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Bouncer automatically installs its monitoring components (mu-plugin loader and database monitor).
4. Open **Tools → Bouncer**, then use the **Settings** tab to configure AI scanning and notification preferences.
5. Use the **Dashboard** tab (same screen) to see your security status, event log, and manifests.

= Requirements =

* WordPress 7.0 or later
* PHP 8.1 or later
* For AI scanning: An Anthropic API key in **Settings → Connectors** (or `ANTHROPIC_API_KEY` via environment/constant), from https://console.anthropic.com/, and acceptance of Anthropic’s terms (see “Third-party services” above).

== Frequently Asked Questions ==

= Will Bouncer slow down my site? =

Bouncer is designed to be invisible in production. Database query attribution adds approximately 0.1-0.3ms per query. HTTP monitoring and hook auditing add negligible overhead. File integrity checks run on WP-Cron, not on page loads. You can also reduce the sampling rate for high-traffic sites.

= What if another plugin already has a db.php? =

Bouncer detects existing db.php files and will not overwrite them. Database query attribution will be disabled, but all other monitoring channels work normally.

= Does Bouncer send my code to Anthropic? =

No. Bouncer sends structural fingerprints — function names, call patterns, hook registrations, API usage — not raw source code. AI scanning is off by default; turning it on and configuring a key in **Settings → Connectors** (or via environment/constant) means you choose to use Anthropic’s service under their Commercial Terms (https://www.anthropic.com/legal/commercial-terms) and Privacy Policy (https://www.anthropic.com/legal/privacy).

= Why did my webhook stop working after an update? =

Bouncer blocks outbound requests to link-local and private IP ranges (SSRF protection) for webhooks. Use a public hostname that resolves to a routable address, or ask a developer to use the `bouncer_webhook_skip_url_safety` filter in controlled environments.

= REST API scan throttling =

`POST /wp-json/bouncer/v1/scan/{slug}` is rate-limited per user (default: 12 per minute) to limit load and AI cost. Pass `run_ai: false` in the JSON body to refresh only the manifest without calling Claude.

= Can Bouncer break my site? =

In Monitor mode, Bouncer only observes and logs. It never blocks or modifies anything. In Enforce mode, it can block specific operations and deactivate plugins, but only for clear policy violations. Start in Monitor mode.

= Troubleshooting activation or “fatal error” messages =

* **WordPress version:** Bouncer requires **WordPress 7.0 or newer** (Connectors API). Older WordPress versions cannot activate or load the plugin.
* **PHP version:** Bouncer requires **PHP 8.1 or newer**. On older PHP, activation is blocked with an on-screen message instead of a parse error from the main plugin code.
* **Debug log:** Enable `WP_DEBUG` and `WP_DEBUG_LOG` in `wp-config.php`, try again, and read `wp-content/debug.log` for the exact error.
* **Database:** The MySQL user must be allowed to create tables. If creation fails, check the log and your host’s database permissions.
* **Filesystem:** Bouncer writes a small loader under `wp-content/mu-plugins/` and may copy `db.php` into `wp-content/`. Those directories must be writable by the web server, or installation continues with flags you can see in the dashboard.
* **Conflicts:** Another plugin’s `wp-content/db.php` is detected and left in place; query attribution stays off until that conflict is resolved.

== Changelog ==

= 1.0.5 =
* Manifests: **Scan all installed plugins** (batched AJAX, one rate-limit slot per batch) with resume after rate limit.
* Manifests list is built from **actually installed** plugins; REST scan/manifest routes and AJAX validate slugs against that registry (supports single-file plugins and broader slug characters).
* Admin copy on Dashboard, Manifests, and single-plugin views reflects **Deep Dive** setting, API key availability, and related state instead of static text.
* Single-plugin “first scan” uses the same path as rescan (Quick Look plus Deep Dive when available).

= 1.0.4 =
* Require **WordPress 7.0+**. Deep Dive keys use **Settings → Connectors** only (plus `ANTHROPIC_API_KEY` env/constant per core); removed the Bouncer settings fallback field.
* Fix: resolve the Anthropic key from the Connectors database option (`connectors_ai_anthropic_api_key`) even when connector metadata is incomplete, and refresh the AI scanner after `wp_connectors_init`.

= 1.0.3 =
* Remove Bouncer Brain, local model download, and related settings; optional AI analysis is **Deep Dive** (Anthropic Claude) only.

= 1.0.2 =
* Remove optional WPVulnerability.net / “Vulnerability database” integration (settings, dashboard, and API client).

= 1.0.1 =
* Fix: stop redirect loop on **Tools → Bouncer** (`ERR_TOO_MANY_REDIRECTS`). The legacy submenu redirect no longer treats `page=bouncer` as an old slug to rewrite.

= 1.0.0 =
* Initial public release.
* Database query attribution via optional `wp-content/db.php` drop-in; conflict detection when another drop-in is present.
* Outbound HTTP monitoring with per-plugin manifest allowlists; Monitor vs Enforce modes.
* Hook registration auditing (optional mu-loaded hook snapshots when auditing is enabled).
* File integrity monitoring with SHA-256 checksums and WordPress.org checksum verification.
* Per-plugin capability manifests, Quick Look and Deep Dive (Claude) UX; optional Anthropic analysis with Connectors API and fallbacks.
* REST unauthenticated write logging; email digests and HMAC-signed webhooks.
* SSRF-safe URL checks for webhooks.
* WP-CLI: `status`, `log`, `manifest`, `config export|import`.
* REST API for events, manifests, and scans (rate-limited; `run_ai` to skip Claude).
* Filesystem API for plugin-owned writes; PHPCS WordPress ruleset; Site Health and Abilities API integration when supported.
* Playground blueprint asset; block editor pre-publish stub.
* Buffered event logger with batch insert; performance sampling for discovery-mode HTTP logs.
