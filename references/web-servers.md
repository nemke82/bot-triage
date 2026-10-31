# Web servers

Block in the server that receives the request first. If nginx proxies to Apache,
rules in Apache only run after nginx has already accepted and forwarded the
request; put them in nginx. `scripts/detect-env.sh` reports what is in front.

Web-server blocks can match user agents, paths and query strings, which a firewall
cannot. They still cost a request, so for floods from a few IPs the firewall is
cheaper.

## Real client IP behind a CDN or proxy

If a CDN or load balancer is in front, the server sees the proxy's address unless
it is told to trust a forwarded header. Configure this before writing IP rules,
and only trust the header from the proxy's own ranges (otherwise anyone can forge it).

- **nginx**: `set_real_ip_from <proxy range>;` for each range, plus
  `real_ip_header CF-Connecting-IP;` (Cloudflare) or `X-Forwarded-For`.
- **Apache**: `mod_remoteip` with `RemoteIPHeader CF-Connecting-IP` and
  `RemoteIPTrustedProxy <range>`. Change the log format to `%a` so logs show the
  visitor, not the proxy.
- **LiteSpeed**: Server > General > "Use Client IP in Header" (trusted IPs only).
- **Caddy**: `trusted_proxies` in the global `servers` options, then match with
  `client_ip` instead of `remote_ip`.

## nginx

Server-wide, in a file included inside `http { }` (e.g. `/etc/nginx/conf.d/`):

```nginx
deny 203.0.113.7;
deny 198.51.100.0/24;

map $http_user_agent $bad_ua {
    default 0;
    "~*(ExampleBot|AnotherBot)" 1;
}
```

Per site, inside `server { }`:

```nginx
if ($bad_ua) { return 403; }
location ~ ^/(xmlrpc\.php) { return 403; }
```

- A `location` with its own `allow`/`deny` overrides the `http`-level ones.
- Rate limiting is built in and very effective for login and search:
  `limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;` in `http`, then
  `limit_req zone=login burst=5 nodelay;` in the login location.
- Apply with `nginx -t && systemctl reload nginx`.

## Apache

`.htaccess` only works where `AllowOverride` allows it. Panels (cPanel, Plesk,
DirectAdmin) enable it; stock Debian/Ubuntu and RHEL Apache often have
`AllowOverride None`, so `.htaccess` is silently ignored. Use server config there
(gen-blocks `-T apache`).

`.htaccess` (needs mod_rewrite, place above the CMS rewrite block):

```apache
RewriteEngine On
RewriteCond %{REMOTE_ADDR} ^203\.0\.113\.7$ [OR]
RewriteCond %{REMOTE_ADDR} ^198\.51\.100\.
RewriteRule .* - [F,L]
RewriteCond %{HTTP_USER_AGENT} (ExampleBot|AnotherBot) [NC]
RewriteRule .* - [F,L]
```

Server config for all sites: gen-blocks prints a `SetEnvIf` + `Require not env`
block inside `<Location "/">` with `AuthMerging And`. AuthMerging And matters: a
plain `Require all granted` in a Location would override every directory's own
access rules (including protected admin folders).

Apply with `apachectl configtest && apachectl graceful`.

## LiteSpeed Enterprise and OpenLiteSpeed

LiteSpeed reads Apache `.htaccess` rewrite rules, with differences that break
rules copied from Apache guides:

- No `{n,m}` repetition in rewrite regexes; spell patterns out.
- No `[G]` flag; use `[R=410,L]` for "gone".
- To match an encoded dot in the raw request, write `[%]2e`, not `%2e` (the `%`
  is otherwise taken as a back-reference).
- **LiteSpeed Cache answers cached pages before rewrite rules run.** Test new rules
  with a fresh query string, or you will see cached 200s and think the rule failed.
- **OpenLiteSpeed** reads only rewrite rules from `.htaccess` (no `Require`, no
  `Deny from`) and picks up changes only after a graceful restart
  (`/usr/local/lsws/bin/lswsctrl restart`).
- LiteSpeed has per-client throttling built in (Server > Security > Per Client
  Throttling) and supports ModSecurity rules.

## Caddy

```caddy
@bad_ip remote_ip 203.0.113.7 198.51.100.0/24
respond @bad_ip 403
@bad_ua header_regexp User-Agent (?i)(ExampleBot|AnotherBot)
respond @bad_ua 403
@bad_path path /xmlrpc.php*
respond @bad_path 403
```

Each named matcher's conditions are ANDed, so use one matcher per kind of block.
Apply with `caddy validate --config /etc/caddy/Caddyfile && systemctl reload caddy`.

## Other front ends

- **Varnish**: block in VCL `vcl_recv` (`if (client.ip ~ bad_acl) { return (synth(403)); }`)
  or at the firewall; backend rules see Varnish's address.
- **HAProxy**: `http-request deny if { src -f /etc/haproxy/deny.lst }` or a user-agent ACL.
- **Traefik**: an `ipAllowList`/`ipWhiteList` middleware cannot deny, so block at the
  firewall or the CDN, or use a plugin.
- **Docker**: published ports bypass host firewalls like ufw; use the
  `DOCKER-USER` chain or block in the proxy container.

## Early 403 for probe paths (recommended permanent fix)

Scanners request paths that never exist on a normal site. Answering them in the
web server, before PHP, saves a full application render per request.

Paths worth refusing: `/.env`, `/.git`, `/.svn`, `*.js.map` (if you do not serve
source maps), `/@fs/`, `/__vite`, `/vendor/phpunit/`, `storage/framework/*.php`,
`bootstrap/cache/*.php`, direct `.php` requests under `/wp-includes/` (except the
TinyMCE folder the classic editor needs). Check that the site really does not use
a path before blocking it.

nginx:

```nginx
location ~* (^/\.(env|git|svn)|\.js\.map$|^/@fs/|^/__vite|/vendor/phpunit/) { return 403; }
```

ModSecurity (Apache or LiteSpeed; pick rule IDs that do not collide with yours):

```apache
SecRule REQUEST_URI "@rx (?:/\.env|/\.git|/\.svn|\.js\.map$|/@fs/|/__vite|/vendor/phpunit/|storage/framework/.*\.php|bootstrap/cache/.*\.php)" \
    "id:1990001,phase:1,deny,status:403,log,msg:'bot-triage probe path',t:urlDecodeUni,t:lowercase"
```

`t:urlDecodeUni,t:lowercase` makes encoded variants (`%2f%2egit`) match too.
