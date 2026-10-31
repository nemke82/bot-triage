---
name: bot-triage
description: Find and stop bots, crawlers and vulnerability scanners that overload a Linux web server. Use when a server has high load, slow or timing-out sites, maxed-out PHP workers, a traffic spike, or suspicious requests, on any stack (nginx, Apache, LiteSpeed/OpenLiteSpeed, Caddy; cPanel, Plesk, DirectAdmin or no panel; csf, Imunify360, ufw, firewalld, nftables or iptables; with or without Cloudflare). Reads access logs read-only, identifies the IPs, subnets, user agents and URL patterns responsible, then proposes blocks at the right layer for the user to approve.
---

# Bot triage

Diagnose what is loading a web server, then block it at the cheapest layer that
actually works, without locking out real visitors, search engines or integrations.

## Ground rules

- **Read-only until the user approves.** The scripts never change anything.
  Show the proposed blocks and wait for an explicit yes before running them.
- **Smallest effective block first.** Temporary bans (24h) before permanent ones;
  one IP before a subnet; a path pattern before a whole site.
- **Never block without checking** verified search engines (Googlebot, Bingbot,
  Applebot, YandexBot), payment-gateway callbacks, uptime monitors, the site's own
  integrations (ERP, feeds, webhooks) or the user's office IP. Ask when unsure.
- **Back up any config file before editing it**, validate the config, reload, then
  test that the site still works.
- **One change, then measure.** Re-run the triage after each block.

## Scripts

All scripts are in `scripts/`, need bash and standard GNU tools, and are read-only.
Run them as root (logs and firewall state usually need it).

| Script | Purpose |
|---|---|
| `detect-env.sh [-H]` | OS, control panel, web server in front, active firewall, where rules belong |
| `triage.sh [-m MIN] [-l LOG]...` | Markdown report: host load, top IPs/subnets/user agents/paths, attack signatures, hints |
| `ip-detail.sh [-m MIN] IP...` | One IP in depth: timeline, URLs, user agents, reverse DNS with search-engine verification, firewall status |
| `gen-blocks.sh -i IP -u UA -p PATH [-T auto]` | Prints (never applies) block rules for the detected firewall and web server, or any target |

Logs are auto-detected (cPanel domlogs, `/var/log/{apache2,httpd,nginx}`, LiteSpeed,
Plesk). Pass `-l FILE_OR_DIR` for anything else, or `-l -` to read stdin, e.g.
`docker logs web 2>&1 | bash scripts/triage.sh -l -`. The NCSA combined format and
Apache `vhost_combined` are supported. `BOT_TRIAGE_NOW="2026-01-31 14:05"` analyses
a past window.

## Workflow

### 1. Confirm the problem is web traffic

Run `bash scripts/triage.sh -m 15` and read **Host load** first.

- Load well above the core count with web workers (php-fpm, lsphp, httpd, nginx)
  on top: continue.
- Many processes in D state or high I/O wait: storage problem (disk, NFS, backup
  job), not bots. Stop here and say so.
- mysqld on top: usually still driven by web requests; continue, but mention it.
- High load with CPU mostly idle and a short run queue: a burst that is already
  over. Check again in a few minutes before blocking anything.

### 2. Read the report

Work through the tables and the **What this suggests** section. Classify the
traffic using `references/playbook.md` (single source, subnet, distributed pool,
scanner, brute force, crawler, facet crawl, PATH_INFO loop). The playbook says
which layer fits each case; `references/signatures.md` explains every signature
tag and its usual false positives.

### 3. Drill into suspects

`bash scripts/ip-detail.sh -m 60 IP [IP...]` for the top few. Check the reverse
DNS line: "forward-confirmed: genuine" means a real search engine, so do not
block it; slow it with robots.txt or the engine's webmaster tools instead.

### 4. Choose the layer

Run `bash scripts/detect-env.sh -H`, then pick the layer:

| Situation | Block at |
|---|---|
| Traffic arrives through Cloudflare or another CDN | The CDN WAF (origin firewall would block the CDN) |
| A few abusive IPs or one /24 | Firewall, temporary ban |
| Thousands of IPs, one request each | Pattern rule (path, query shape, user agent) at CDN or web server |
| Known bad user agent, many IPs | Web server or CDN user-agent rule |
| Probe paths (`.env`, `.git`, LFI) | Firewall for the IPs, plus an early 403 for the paths |
| Crawler that obeys robots.txt | robots.txt first, block only if ignored |

Details per firewall in `references/firewalls.md`, per web server in
`references/web-servers.md`, CDN rules in `references/cloudflare-waf.md`.

### 5. Generate, review, apply

```sh
bash scripts/gen-blocks.sh -i 203.0.113.7,198.51.100.0/24 -u ExampleBot -p /xmlrpc.php
```

`-T auto` (default) prints rules for this server's firewall and web server only;
`-T all` shows every format; `-C` adds Cloudflare rules and real-IP matching.
Show the output to the user, explain each rule in a sentence, and apply only what
they approve. Back up edited files with a dated suffix first.

### 6. Verify

- Re-run `triage.sh -m 5` after 2 to 5 minutes. Load lags: busy workers finish
  their current requests first, so a short rise right after blocking is normal.
- Test the real user paths still return 200: home page, login, search, cart and
  checkout, and any API, XHR or webhook endpoints. Use a fresh query string when a
  page cache is in front.
- If load does not drop, the block is at the wrong layer or the fingerprint is
  wrong. Go back to step 2.

### 7. Report

Summarise for the user: what the traffic was, what was blocked where, when the
temporary bans expire, how to undo each change, and what to watch for next time
(see the follow-ups in `references/playbook.md`).
