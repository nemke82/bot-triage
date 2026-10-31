# Signatures in the triage report

What each tag in "Attack and crawler signatures" matches, what it usually means,
and its common false positives.

| Tag | Matches | Usually | False positives |
|---|---|---|---|
| `probe` | `/.env`, `/.git`, `/.svn`, `.js.map`, `/@fs/`, `__vite`, `storage/framework`, `bootstrap/cache`, `phpinfo`, `/vendor/phpunit`, `/.aws`, `/.ssh`, `wp-config.php`, `.sql`, `.bak`, `.DS_Store`, wp-file-manager plugin | Vulnerability scanners looking for leaked secrets and dev servers | Sites that really serve source maps; developers' own tools |
| `lfi-rce` | `pagename=`, `pearcmd`, `../`, `%2e%2e`, `/etc/passwd`, `php://`, `allow_url_include`, `${jndi`, `union select` | Local file inclusion / remote code execution attempts | Almost none. Any 200 response deserves a closer look |
| `wp-login-post` | POST to `wp-login.php` | Password brute force | Real logins (a handful per user) |
| `xmlrpc` | any request to `xmlrpc.php` | Brute force via system.multicall, pingback abuse | Jetpack and some mobile/publishing apps |
| `wp-api-abuse` | `/wp-json/batch/v1`, `/wp-json/wp/v2/users`, `rest_route=` equivalents | User enumeration, batch-endpoint exploits (rogue admin creation) | The block editor and some plugins use the REST API, but rarely these routes from outside |
| `cart-action` | `add-to-cart=`, `add_to_wishlist=`, `remove_item=`, `add_to_compare=`, `wc-ajax=add_to_cart` | Crawlers following cart links (each creates a session) | Real shoppers; look at the user agent |
| `multi-value-filter` | query string containing a comma (raw or `%2C`) | Facet-permutation crawls | API queries (`fields=a,b`), analytics parameters |
| `3plus-params` | 3+ query parameters, ignoring `utm_*`, `fbclid`, `gclid`, `msclkid` | Facet-permutation crawls | Search pages, tracking links |
| `pathinfo-loop` | `/x.php/` followed by 2+ more path segments | Crawler stuck in a PATH_INFO loop | Apps that really use PATH_INFO routing (`index.php/route`) |
| `404-dynamic` | 404 on `.php`, extensionless or directory URLs | Scanners and broken crawlers; each one is a full CMS render | Broken internal links after a site change |
| `no-user-agent` | empty or `-` user agent | Scripts, scanners | Health checks, some payment callbacks |
| `script-client` | python-requests, Go-http-client, curl, wget, okhttp, scrapy, Java, node-fetch, axios, HeadlessChrome, zgrab, masscan, nuclei | Scrapers and scanners | Integrations, monitoring, the site's own cron |
| `seo-crawler` | Semrush, Ahrefs, MJ12, DotBot, BLEX, DataForSeo, SERanking, Serpstat, PetalBot, Barkrowler, MegaIndex and similar | Commercial SEO crawlers | The site owner's own SEO tool; ask before blocking |
| `ai-crawler` | GPTBot, ChatGPT-User, OAI-SearchBot, ClaudeBot, Claude-SearchBot, Claude-User, PerplexityBot, Bytespider, CCBot, Amazonbot, Meta-ExternalAgent and similar | AI training and AI search crawlers | Blocking AI search crawlers removes the site from those answers; ask the owner |
| `googlebot-claim-unverified` | user agent says Googlebot, IP outside 66.249.x.x | Often a fake Googlebot | Google also crawls from other ranges; verify with ip-detail.sh before blocking |

## Verifying good bots

Reverse DNS, then forward DNS of that name must return the same IP:

| Crawler | Reverse DNS ends with |
|---|---|
| Googlebot | `googlebot.com`, `google.com`, `googleusercontent.com` |
| Bingbot | `search.msn.com` |
| Applebot | `applebot.apple.com` |
| YandexBot | `yandex.com`, `yandex.ru`, `yandex.net` |

`scripts/ip-detail.sh` does this check. Many other crawler operators (including
most AI crawlers) publish their IP ranges as JSON in their documentation instead.

## robots.txt before blocks

Reputable crawlers honour robots.txt, usually within a day:

```
User-agent: ExampleSEOBot
Disallow: /

User-agent: *
Disallow: /*add-to-cart=
Disallow: /*?*filter
Crawl-delay: 5
```

`Crawl-delay` is ignored by Google but respected by many others. Block by user
agent only for crawlers that ignore robots.txt, or while the load is acute.
