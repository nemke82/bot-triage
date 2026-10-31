# Bot triage playbook

How to read the triage report, which layer to block at, and the traps that waste
hours. Every lesson here comes from real incidents on production web servers.

## Traffic shapes

| Shape | How it looks in the report | Best response |
|---|---|---|
| **Single source** | One IP has 20%+ of requests | Temporary firewall ban on that IP |
| **Subnet** | Several IPs in one /24 in the top list, same user agent or same probes | Temporary ban on the /24; permanent if it returns daily |
| **Rotating pool** | Hundreds or thousands of IPs, 1 to 3 requests each, often residential ISPs, realistic browser user agents | Do not chase IPs. Block the shared pattern (path, query shape, user agent, missing referer) at the CDN or web server |
| **Cloud scanner fleet** | Many IPs from big cloud providers, bursts of 5 to 15 minutes, probe paths | Temporary bans for the loudest IPs plus an early 403 for the probe paths, server-wide |
| **Vulnerability scanner** | `probe` and `lfi-rce` signatures, mostly 404s | Ban the IP; early 403 for probe paths. If any probe got a 200, investigate the site for compromise |
| **WordPress brute force** | `xmlrpc` and `wp-login-post` signatures | Ban the sources; block xmlrpc.php if unused; rate-limit wp-login |
| **SEO / AI crawler** | `seo-crawler` or `ai-crawler`, steady rate, many distinct URLs | robots.txt Disallow or Crawl-delay; user-agent block if it ignores robots.txt |
| **Facet / filter crawl** | `multi-value-filter` or `3plus-params`, almost every URL unique | Challenge or block that query shape (see cloudflare-waf.md); exclude XHR/API/checkout |
| **Cart / wishlist bots** | `cart-action` | Block crawler user agents on those query parameters; robots.txt Disallow `/*add-to-cart=*` |
| **PATH_INFO loop** | `pathinfo-loop`: `/page.php/a/b/c` growing deeper | Fix the site: 301 `^([^.]*\.php)/` back to the .php URL |
| **Fake search engine** | `googlebot-claim-unverified`; ip-detail shows no Google PTR | Safe to block |

## Why bots hurt so much

- **Every 404 on a CMS is a full PHP render.** WordPress, Magento, Laravel and most
  frameworks route unknown URLs through the application. A scanner asking for
  5,000 paths that do not exist costs as much as 5,000 page views. An early 403 in
  the web server (before PHP) is far cheaper than letting the CMS answer 404.
- **Unique URLs never cache.** Filter permutations, random query strings and
  PATH_INFO loops bypass page caches and CDNs, so every hit is a cache miss.
- **Cart and session URLs create server-side state** (sessions, carts, database
  rows) on every request.

## Before you block

1. **Check it is still happening.** Look at the per-minute timeline in
   `ip-detail.sh`. A burst that ended five minutes ago does not need a permanent ban.
2. **Check for CDN or proxy addresses.** If the top IPs are Cloudflare (flagged in
   the report) or your own load balancer, a firewall ban blocks everyone behind it.
3. **Verify claimed search engines** with reverse + forward DNS (ip-detail.sh does
   this for Google, Bing, Apple and Yandex). Many AI-crawler operators publish
   their IP ranges in their documentation; check there before blocking a named bot.
4. **Check for integrations.** Requests with no user agent or a library user agent
   (curl, Go, Python, Java) are often payment callbacks, ERP sync, feeds or uptime
   checks. Ask the user.
5. **Check the window is right.** The report covers the last N minutes; widen it
   (`-m 60`) before concluding traffic is "normal".

## After you block

- **Load drops with a delay.** Workers finish their in-flight requests first; a
  brief rise right after blocking is normal. Judge after 2 to 5 minutes.
- **Test with fresh URLs.** Page caches (LiteSpeed Cache, Varnish, CDN) can serve
  cached pages before your new rules run, which makes a broken rule look fine.
- **Test the flows bots do not use:** login, cart, checkout, payment return URLs,
  REST/GraphQL APIs, admin AJAX. A challenge or block on these breaks the site
  silently, because XHR and API clients cannot solve a challenge.
- **Write down what expires when.** Temporary bans vanish; if the source returns
  daily, convert it to a permanent entry with a clear comment.

## Recurring traps

- **Firewall ban lists have limits.** csf keeps at most DENY_IP_LIMIT entries; when
  full, lfd drops the oldest, including "permanent" ones, unless the comment
  contains "do not delete". Ban lists can silently forget your blocks.
- **The same log file can be reachable through two paths** (cPanel keeps
  `domlogs/<file>` and `domlogs/<user>/<file>`). Counting both doubles every
  number. The scripts deduplicate by inode.
- **Comparing log timestamps as strings is wrong.** `15/Dec` sorts after `15/Jan`;
  string comparisons pull lines from other months into "the last hour". The
  scripts match exact minute stamps instead.
- **Bots follow relative links forever** on sites that accept PATH_INFO
  (`/page.php/anything`). Fix the site; blocking the crawler only hides it.
- **Hand-edited config can be locked.** Some admins set `chattr +i` on `.htaccess`
  to stop malware rewriting it. If an edit fails with "Operation not permitted",
  check `lsattr`, unlock, edit, and lock again.
- **Editing PHP files of a running site** can serve stale or half-written code from
  OPcache; prefer web-server rules over PHP changes during an incident.

## Follow-ups worth suggesting

- Server-wide early 403 for probe paths (see web-servers.md), so every future
  scanner costs nothing.
- Origin lock when behind a CDN: accept ports 80/443 only from the CDN's ranges, so
  attackers cannot bypass the WAF by hitting the origin IP.
- Rate limiting for login and search endpoints (nginx `limit_req`, Cloudflare rate
  limiting rules, LiteSpeed per-client throttling).
- fail2ban jails for patterns that recur (see firewalls.md).
- A robots.txt that disallows infinite spaces: filters, cart links, internal search.
