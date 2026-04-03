# Bouncer

> **Your plugins can do anything. Bouncer makes sure they don't.**

You probably don't think twice when you install a WordPress plugin, and you shouldn't have to. Here's what actually happens when you click **Activate**:

- That plugin gets access to **everything**: your customer list, passwords, files, and the whole site.
- It can send data to any server, change how people log in, or rewrite other plugins.

A simple contact form plugin has the same level of access as WordPress itself. That's not a worst-case scenario; it's how WordPress is designed, for every plugin, every time. Until now, nothing was watching what they do with that access.

## Contents

- [Requirements and installation](#requirements-and-installation)
- [How Bouncer fits in](#your-security-plugins-look-for-known-problems)
- [What it monitors](#bouncer-watches-what-your-plugins-actually-do)
- [Optional AI analysis](#ai-that-explains-what-your-plugins-do-in-plain-english)
- [Monitor vs enforce](#start-by-watching-act-when-youre-ready)
- [Privacy and third parties](#privacy-and-third-party-services)
- [Development](#development)
- [License and credits](#free-open-source-no-subscription-required)

## Requirements and installation

| Requirement | Version |
|-------------|---------|
| WordPress | **7.0+** (uses the Connectors API for optional AI keys) |
| PHP | **8.1+** |

**Install**

1. Copy the plugin folder to `wp-content/plugins/bouncer/` (or upload the release zip so the folder name is `bouncer`).
2. Activate **Bouncer** under **Plugins**.
3. Open **Tools → Bouncer**. On first run, Bouncer installs a small must-use loader under `wp-content/mu-plugins/` and, when possible, a `wp-content/db.php` drop-in for query attribution. If another plugin already owns `db.php`, Bouncer leaves it in place and database query attribution stays off until that conflict is resolved (see the FAQ in [readme.txt](readme.txt)).

**Configure**

- **Dashboard** — status, recent events, manifests.
- **Settings** — monitoring channels, sampling, notifications, optional **Deep Dive** (Anthropic) analysis, Monitor vs Enforce.

Site administrators get the `manage_bouncer` capability (mapped from `manage_options` so existing admins keep access).

For REST endpoints, WP-CLI, local development, and contributor workflows, see [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Your security plugins look for known problems

Wordfence, Sucuri, Patchstack, and similar tools are good at what they do: they match plugins and files against **known** threats (disclosed vulnerabilities, known malware, and the like).

**The gap:** what about problems nobody has named yet?

- In **2025**, researchers found **11,000+** new plugin security issues (**30+ per day**).
- **Nearly half** could be exploited **without a password**.

The hardest cases are **poisoned updates**: a trusted developer account is compromised, an update looks normal, and your stack still sees a "safe" plugin. There's no signature for that yet, only the window before the world catches up. That's often when damage happens.

## Bouncer watches what your plugins actually do

Bouncer doesn't start from a list of known badness. It watches behavior in real time and asks:

> *Is this plugin doing something it's not supposed to do?*

When you install a plugin, Bouncer builds a **profile of normal behavior**: what it reads and writes, which outside servers it talks to, and how it hooks into WordPress. On each request, it checks that reality still matches that profile.

**Examples of what gets caught**

- Access to your user list when it doesn't fit the profile
- Traffic to a server the plugin never used before
- File changes when there wasn't an update, with optional automatic shutdown of the plugin

You don't need to read stack traces. The dashboard is simple: **green** means normal, **yellow** means something unusual, **red** means look now.

## AI that explains what your plugins do (in plain English)

Optional: Bouncer can use AI when you install or update a plugin. Core protection does **not** depend on it.

It does **not** ship your source code off-site. It sends a **structural summary** (like a table of contents, not the book) and returns a report covering:

- What the plugin **actually** does (from code, not marketing copy)
- Whether that's **normal** for that kind of plugin
- What **changed** since the last version
- A **risk level** (low / medium / high)
- **Plain-English** notes on anything concerning

Think of it as a home inspection report: you don't need to be a plumber to understand what matters.

Keys are configured through **Settings → Connectors** (WordPress 7.0), or the same `ANTHROPIC_API_KEY` environment variable / PHP constant pattern WordPress uses elsewhere. See [Privacy and third-party services](#privacy-and-third-party-services) below.

## Cloudflare thinks WordPress is the problem. We disagree.

In **April 2026**, Cloudflare launched **EmDash**, a new platform framed as the answer to WordPress plugin security: if WordPress can't be fixed, start over.

Plugin security **is** in bad shape. Abandoning **~43% of the web** isn't the only answer.

**Bouncer** stays on the WordPress you already run: same site, same plugins, same content. EmDash asks for a greenfield with no plugin or theme ecosystem. You shouldn't have to start over to be safer.

## It works alongside the tools you already use

Bouncer is **not** a drop-in replacement for Wordfence or Patchstack. It's another layer.

| Layer | What it's for |
|--------|----------------|
| **Known malware** (e.g. Wordfence) | Bad files and signatures you already know about |
| **Known vulns** (e.g. Patchstack) | CVEs and disclosed issues for your versions |
| **Unknown behavior** (Bouncer) | Trusted plugins doing **new**, suspicious things |

On the same site you get **three** complementary angles, not one tool trying to do everything.

## Start by watching. Act when you're ready.

**Monitor Mode** (default): watch and log, block nothing. Run it for a week and see what your plugins actually do.

**Enforce Mode**: block suspicious activity and shut down compromised plugins automatically when you're ready and on your thresholds.

## Privacy and third-party services

**Optional AI (Anthropic Claude)** — Only when you enable AI scanning and provide a key. Bouncer sends **structural fingerprints** to Anthropic’s API, not raw plugin source. Enabling that feature means you direct Bouncer to contact Anthropic on your behalf.

- [Anthropic Commercial Terms](https://www.anthropic.com/legal/commercial-terms)
- [Anthropic Privacy Policy](https://www.anthropic.com/legal/privacy)

Core behavioral monitoring does not require a Bouncer-hosted cloud or a paid subscription to us.

## Development

- [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) — local environment (`wp-env`), PHP/JS linting, CI, architecture sketch, REST and WP-CLI reference, useful filters.
- [RELEASING.txt](RELEASING.txt) — version bumps, distributable zip, WordPress.org checklist.

Pull requests welcome; CI runs Composer lint (syntax, PHPCS, PHP compatibility) and ESLint on admin JavaScript.

## Free. Open source. No subscription required.

Built by **[Regionally Famous](https://regionallyfamous.com)**, a WordPress studio that ships and maintains real client sites. We needed behavioral visibility that didn't exist, so we built Bouncer.

Core protection needs **no** AI, **no** Bouncer-hosted cloud, and **no** monthly fee to us. AI is optional and **bring-your-own-key**; we don't monetize your analysis. The plugin is **free** and **open source** (GPL-2.0-or-later).

## The way we think about plugin security is changing

| Old model | New model |
|-----------|-----------|
| Trust reputation, scan for **known** threats, patch **after** incidents | Watch **every** plugin **continuously**, catch problems **before** they have a name |

**Bouncer is the new model** for the WordPress site you already have, without burning it down.
