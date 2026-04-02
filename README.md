# Bouncer

### The first plugin behavior firewall for WordPress.

---

Every plugin you install gets the keys to the kingdom.

Your database. Your filesystem. Your network. All of it. A contact form plugin can read your user passwords. A carousel plugin can phone home to a server you've never heard of. A SEO plugin can rewrite your authentication hooks.

This isn't a bug. It's how WordPress works. And nobody is watching.

---

## The security tools you have look backwards

Wordfence checks files against known malware signatures. Patchstack matches your plugin versions against a CVE database. Sucuri filters requests at the network edge.

They're all asking the same question: **"Is this a known threat?"**

That works — until it doesn't. When a plugin gets compromised through a supply chain attack (a stolen developer password, a hijacked update), there's no CVE yet. No signature. No WAF rule. The plugin just quietly starts doing things it never did before.

11,334 new plugin vulnerabilities were discovered in 2025. That's 31 per day. 43% require zero authentication. And supply chain attacks — where legitimate plugins get poisoned at the source — are the fastest-growing category.

The window between compromise and detection? That's where sites get owned.

---

## Bouncer asks a different question

**"Is this plugin doing something it shouldn't?"**

Instead of checking IDs at the door and hoping for the best, Bouncer watches the room all night.

It generates a behavioral contract for every plugin on your site — what database tables it touches, what domains it contacts, what hooks it registers, what dangerous functions it calls. Then it monitors every request against those contracts.

A gallery plugin suddenly writing to your users table? Not in the contract.

A slider plugin calling a domain in Eastern Europe that wasn't there last version? Not in the contract.

A caching plugin registering a callback on `wp_login` at priority zero? Not in the contract.

Bouncer catches the things that happen between the compromise and the CVE. The hours nobody else is watching.

---

## Cloudflare said WordPress plugin security is broken

They're right. In April 2026, Cloudflare launched EmDash — a whole new CMS built from scratch with V8 sandboxes that isolate every plugin in its own secure container. It's architecturally elegant. It's also useless to the 810 million websites already running WordPress.

Bouncer is the answer that doesn't require burning your site to the ground.

You can't sandbox PHP plugins. But you can watch them so closely that the moment they step out of line, you know. And with AI reading plugin code before it ever runs, you can catch most threats at the door.

**EmDash prevents misbehavior by architecture. Bouncer detects it by intelligence.**

One requires leaving WordPress. The other protects the WordPress you already have.

---

## AI that reads the code before it runs

When you install or update a plugin, Bouncer can analyze it with Claude before activation. Not pattern matching. Not signature checking. Actually reading the code structure and asking: does this plugin do what it says it does?

The AI generates a plain-English report. What the plugin does. Whether that's normal. What changed since the last version. What looks suspicious. A risk score a non-technical site owner can understand.

Your source code never leaves your server. Bouncer sends structural fingerprints only — function signatures, hook registrations, API patterns. Not your code. Not your files.

---

## This isn't a replacement for your security stack

Bouncer doesn't do what Wordfence does. It does what Wordfence can't.

Use them together. Wordfence catches known malware. Patchstack patches known vulnerabilities. Bouncer catches unknown behavioral changes in plugins you already trust.

Different question. Different layer. Same site.

---

## Start by watching. Enforce when you're ready.

Monitor Mode is the default. Bouncer observes, logs, and learns. It builds behavioral baselines for your plugins without blocking anything. Run it for a week. Look at the event log. See what your plugins actually do behind the scenes. You'll probably be surprised.

Enforce Mode is for when you're confident. Bouncer blocks outbound HTTP requests to undeclared domains and emergency-deactivates plugins with unauthorized file changes. You choose when. You choose the thresholds.

---

## Built by people who build WordPress sites

Bouncer is built by [Regionally Famous](https://regionallyfamous.com) — a WordPress studio that manages real client sites and needed a tool that didn't exist.

We weren't looking for another malware scanner. We wanted to know what our plugins were actually doing. When a trusted plugin pushed a suspicious update, we wanted to know before the security blogs did.

So we built it.

The core monitoring works without AI. Without a cloud service. Without a subscription. The AI features are opt-in and bring-your-own-key. The whole thing is GPL.

---

## The WordPress security conversation is changing

The old model: trust plugins by reputation, scan for known threats, patch after disclosure.

The new model: verify behavior continuously, detect anomalies in real-time, catch compromises before they have a name.

Bouncer is the new model. For the WordPress you already have.

---

<p align="center">
  <strong>Bouncer</strong> — a plugin behavior firewall for WordPress.<br/>
  Built with Claude. Maintained by <a href="https://regionallyfamous.com">Regionally Famous</a>.<br/><br/>
  <a href="https://wordpress.org/plugins/bouncer/">WordPress.org</a> · <a href="https://regionallyfamous.com/bouncer">Documentation</a> · <a href="https://github.com/RegionallyFamous/bouncer/issues">Report an Issue</a>
</p>
