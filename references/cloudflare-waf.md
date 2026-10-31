# Cloudflare WAF (and CDNs in general)

When a site is behind Cloudflare, block there: the bad traffic never reaches the
origin, and the origin firewall cannot see real client IPs anyway (it sees
Cloudflare's). The same reasoning applies to other CDNs with a WAF.

Rules live under Security > WAF > Custom rules. The Free plan allows a handful of
custom rules and lacks some operators, so plan rules to combine conditions.

## Actions

- **Block**: scanners, exploit attempts, abusive IPs.
- **Managed Challenge**: crawlers that might be humans (browser user agents from
  residential IPs). Real browsers usually pass invisibly; bots mostly do not.
  Watch the solve rate in Security > Events: around 1% solved means it is
  catching bots, not people.
- **Skip**: exempt trusted sources (your office, monitoring, integrations) from
  other rules.

## Expressions that work well

```
# IPs and subnets
(ip.src in {203.0.113.7 198.51.100.0/24})

# a user agent, case-insensitive
(lower(http.user_agent) contains "examplebot")

# probe paths
(http.request.uri.path contains "/.env" or http.request.uri.path contains "/.git" or ends_with(http.request.uri.path, ".js.map"))

# multi-value facet filters (comma, raw or encoded) on one host
(http.host eq "shop.example.com" and (http.request.uri.query contains "%2C" or http.request.uri.query contains ","))

# three or more query parameters on category paths (needs regex)
(starts_with(http.request.uri.path, "/category/") and http.request.uri.query matches "[^&]*&[^&]*&")

# no regex on your plan? use length as a proxy
(starts_with(http.request.uri.path, "/category/") and len(http.request.uri.query) > 60)
```

Add `and not cf.client.bot` to rules that might catch verified search engines.

## Exclusions you almost always need

A challenge cannot be solved by code: XHR, fetch, API clients, webhooks and
payment callbacks just fail. Facet and query-shape rules must exclude them, for
example for a shop:

```
and not starts_with(http.request.uri.path, "/checkout")
and not starts_with(http.request.uri.path, "/cart")
and not starts_with(http.request.uri.path, "/customer/")
and not starts_with(http.request.uri.path, "/api/")
and not starts_with(http.request.uri.path, "/rest/")
and not starts_with(http.request.uri.path, "/graphql")
and not starts_with(http.request.uri.path, "/wp-json/")
and not starts_with(http.request.uri.path, "/wp-admin/admin-ajax.php")
```

Commas also appear in legitimate API queries (`fields=a,b`, search criteria), which
is another reason to scope comma rules to the storefront paths that bots crawl.

## Regex pitfalls

- The `matches` operator (regex) is not available on every plan. Fall back to
  `contains`, `starts_with`, `ends_with` and `len()`.
- Cloudflare rejects regexes it considers expensive, sometimes with only a generic
  "unexpected error". A repeated group around a wildcard such as `(.*&){2,}` is a
  typical cause. Flatten it: `[^&]*&[^&]*&` matches the same thing and is accepted.

## Also useful

- **Rate limiting rules**: per-IP request caps on login, search, add-to-cart.
- **Bot Fight Mode / Super Bot Fight Mode**: broad, but can break integrations;
  test checkout and APIs after enabling.
- **Under Attack mode**: challenges everyone. A last resort during a flood; turn it
  off afterwards, since it also blocks APIs and webhooks.
- **Lock the origin**: allow ports 80/443 only from Cloudflare's published ranges
  (https://www.cloudflare.com/ips/), or use Cloudflare Tunnel, so attackers cannot
  bypass the WAF by connecting to the origin IP directly.
- **Real IPs in origin logs**: configure the web server to log `CF-Connecting-IP`
  (see web-servers.md); otherwise the triage report only shows Cloudflare addresses.
