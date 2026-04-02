# Bouncer

[![CI](https://github.com/nick/bouncer/actions/workflows/ci.yml/badge.svg)](https://github.com/nick/bouncer/actions/workflows/ci.yml)

Your plugins can do anything. Bouncer makes sure they don't.

You probably don't think twice when you install a WordPress plugin. You shouldn't have to. But here's what actually happens when you click **Activate**:

That plugin gets access to everything. Your customer list. Your passwords. Your files. Your entire site. It can send your data to any server in the world. It can change how people log in. It can rewrite other plugins.

A simple contact form plugin has the same level of access as WordPress itself.

That's not a worst-case scenario. That's how WordPress is designed. Every plugin, every time.

And until now, nothing was watching what they do with that access.

### Your security plugins look for known problems

The security tools you probably already use — Wordfence, Sucuri, Patchstack — are good at what they do. They check your plugins against a list of known threats. If your plugin version matches a known vulnerability, they warn you. If a file matches a known piece of malware, they flag it.

But what about threats nobody knows about yet?

In 2025, over 11,000 new plugin security issues were discovered. That's more than 30 per day. Almost half of them could be exploited by anyone — no password required.

The scariest ones are the attacks where a perfectly safe plugin gets a poisoned update. The plugin developer's account gets stolen, and a bad actor pushes an update that looks normal but quietly does something it shouldn't. There's no warning for that. No known signature. Your security tools see a trusted plugin updating normally.

The gap between when that happens and when someone figures it out? That's when damage gets done.

### Bouncer watches what your plugins actually do

Instead of checking a list of known threats, Bouncer watches your plugins in real time and asks a simple question:

**"Is this plugin doing something it's not supposed to do?"**

When you install a plugin, Bouncer creates a profile of its normal behavior — what parts of your site it reads and writes, what outside servers it talks to, and what parts of WordPress it interacts with.

Then, on every page load, Bouncer checks.

Did a plugin just try to access your user list for no reason? Bouncer catches that.

Did a plugin start sending data to a server it never contacted before? Bouncer catches that.

Did a plugin file change when there was no update? Bouncer catches that — and can shut the plugin down automatically.

You don't need to understand the technical details. Bouncer shows you a simple dashboard: green means everything is normal, yellow means something unusual happened, red means something needs your attention right now.

### AI that explains what your plugins do (in plain English)

This is optional — Bouncer works perfectly fine without it. But if you want a deeper look, Bouncer can use AI to analyze a plugin's code when you install or update it.

It won't send your actual code anywhere. It sends a summary — like a table of contents, not the book itself — and gets back a report that tells you:

- What the plugin actually does (not what the description says — what the code says)
- Whether that's normal for this type of plugin
- What changed since the last version
- A risk score: low, medium, or high
- A plain-English explanation of anything concerning

Think of it like getting a home inspection before you move in. You don't need to understand plumbing to read the report.

### Cloudflare thinks WordPress is the problem. We disagree.

In April 2026, Cloudflare launched an entirely new platform called EmDash — their answer to WordPress plugin security. Their argument: WordPress can't be fixed, so start over.

They're right that plugin security is broken. They're wrong that the answer is to abandon 43% of the entire internet.

Bouncer fixes the security problem without leaving WordPress.

EmDash asks you to move to a new platform with zero plugins, zero themes, and zero community. Bouncer works with the site you already have, the plugins you already use, and the content you've already built.

You shouldn't have to start over to be safe.

### It works alongside the tools you already use

Bouncer isn't a replacement for Wordfence or Patchstack. It's a different layer of protection.

Wordfence catches known malware. Patchstack warns you about known vulnerabilities. Bouncer catches the unknown stuff — when a trusted plugin starts doing something new and suspicious.

Known threats. Known vulnerabilities. Unknown behavior. Three layers. Same site.

### Start by watching. Act when you're ready.

Bouncer starts in Monitor Mode. It watches everything, logs everything, and blocks nothing. Run it for a week. Look at what your plugins have been doing behind the scenes. You might be surprised.

When you're comfortable, you can switch to Enforce Mode. Bouncer will actively block suspicious activity and shut down compromised plugins automatically.

You decide when. You decide the thresholds.

### Free. Open source. No subscription required.

Bouncer is built by [Regionally Famous](https://regionallyfamous.com), a WordPress studio that builds and manages real websites for real clients. We needed a tool that watched our plugins' behavior, and it didn't exist. So we built it.

The core protection works without AI, without a cloud service, and without paying anyone a monthly fee. The AI features are optional and use your own API key — we don't see your data, and we don't charge for the service.

The entire plugin is free and open source.

### The way we think about plugin security is changing

The old way: Trust plugins by reputation. Scan for known threats. Patch after something goes wrong.

The new way: Watch what every plugin does, all the time. Catch problems before they have a name.

Bouncer is the new way. For the WordPress site you already have. Without starting over.
