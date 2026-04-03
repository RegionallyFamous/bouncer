# Developing Bouncer

Bouncer is a WordPress plugin written in PHP 8.1+ with a small admin JavaScript surface. This document is for contributors and anyone running the plugin from source.

## Repository layout

| Path | Role |
|------|------|
| `bouncer.php` | Bootstrap, constants, autoloader, activation hooks |
| `includes/` | PHP classes (`Bouncer_*`), loaded by the autoloader |
| `db.php` | Template for the optional `wp-content/db.php` drop-in (copied on activation) |
| `assets/js/`, `assets/css/` | Admin UI |
| `dev-environment/wp-env.json` | Local WordPress via `@wordpress/env` |
| `readme.txt` | WordPress.org–style readme (also the source of truth for the stable tag) |

## Local WordPress (`wp-env`)

From the repository root:

```bash
cd dev-environment
npx @wordpress/env start
```

The environment loads this plugin from the parent directory and adds the [Plugin Check](https://wordpress.org/plugins/plugin-check/) plugin for pre-submission scans. Default URLs and credentials are printed when the environment starts.

Stop with `npx @wordpress/env stop`; destroy the Docker volumes with `npx @wordpress/env destroy`.

## PHP tooling

```bash
composer install
composer run lint    # syntax + PHPCS (WPCS) + PHPCompatibilityWP
composer run phpcs   # coding standards only
composer run phpcbf  # auto-fix where possible
```

PHP versions exercised in CI: 8.1, 8.2, 8.3, 8.4 (see `.github/workflows/ci.yml`).

## JavaScript tooling

Admin scripts are linted with ESLint:

```bash
npm ci
npm run lint:js
```

## Architecture (high level)

`Bouncer` (`includes/class-bouncer.php`) is the singleton orchestrator. On `plugins_loaded` it wires:

- **Logger** — buffered events, persisted to `{prefix}bouncer_events`
- **Manifest** — static analysis output per plugin slug, stored in `{prefix}bouncer_manifests`
- **HTTP monitor** — outbound requests vs manifest allowlists (optional enforce)
- **Hook auditor** — sensitive hook registrations vs manifest
- **File integrity** — checksum baselines and drift detection (cron-driven)
- **DB layer** — only active when the `db.php` drop-in is loaded as `Bouncer_DB`; attributes SQL to plugins
- **REST monitor** — logs unauthenticated REST writes (when enabled)
- **Notifications** — email digests and HMAC-signed webhooks
- **AI scanner** — optional Deep Dive via Anthropic when settings and key resolution allow

Activation (`Bouncer_Activator`) creates tables, installs the mu-plugin loader, attempts the `db.php` install, sets default `bouncer_*` options, and schedules cron hooks.

## Capability and admin URL

- Capability: `manage_bouncer` (admins receive it on activation; `manage_options` still implies it via `user_has_cap`).
- Admin screens live under **Tools → Bouncer** (`tools.php?page=bouncer`). Tabs include dashboard, events, manifests, and settings.

## WP-CLI

When WP-CLI is available:

| Command | Purpose |
|---------|---------|
| `wp bouncer status` | Mode, db drop-in flags, 24h event counts by severity |
| `wp bouncer log` | Recent events (`--limit`, `--severity`, `--plugin`, `--format`) |
| `wp bouncer manifest <slug>` | Dump stored manifest JSON for a plugin |
| `wp bouncer config export --file=out.json` | Export all `bouncer_*` options |
| `wp bouncer config import --file=in.json` | Import options (`--dry-run=false` to apply) |

## REST API

Namespace: `bouncer/v1`. All routes require a user who passes `bouncer_current_user_can_manage()`.

| Method | Route | Notes |
|--------|--------|--------|
| GET | `/wp-json/bouncer/v1/events` | Query params: `severity`, `channel`, `plugin`, `per_page`, `page` |
| GET | `/wp-json/bouncer/v1/manifest/{slug}` | 404 if plugin not installed or no manifest |
| POST | `/wp-json/bouncer/v1/scan/{slug}` | Regenerates manifest; optional AI. JSON body: `run_ai` (boolean, default true). Rate-limited per user (default 12/minute). |

## Filters (extension points)

| Filter | Use |
|--------|-----|
| `bouncer_should_monitor_request` | Force skip or include a request after sampling is applied |
| `bouncer_webhook_skip_url_safety` | Return true to skip SSRF-style URL checks for a webhook URL (controlled environments only) |
| `bouncer_rest_scan_max_per_minute` | Adjust POST `/scan/{slug}` throttle (default 12) |
| `bouncer_url_safety_reject_host` | Customize host rejection for URL safety |
| `bouncer_url_safety_allow_unresolvable_host` | Allow hosts that do not resolve (default false) |
| `bouncer_http_discovery_log_sample_denominator` | Tune discovery-mode HTTP log sampling |
| `bouncer_scan_batch_max_with_ai` / `bouncer_scan_batch_max_quick_only` | Admin “scan all” batch sizes |

`bouncer_initialized` fires with the main `Bouncer` instance after components register.

## Release notes

See [RELEASING.txt](../RELEASING.txt) in the repository root for versioning, zip layout, and WordPress.org steps.
