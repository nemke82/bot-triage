#!/usr/bin/env bash
# Self-contained tests for bot-triage. Builds synthetic logs (documentation IP
# ranges from RFC 5737 and example.* domains only), runs the scripts and checks
# the numbers. Usage: bash tests/run.sh
set -uo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
S=$ROOT/scripts
T=$(mktemp -d "${TMPDIR:-/tmp}/bot-triage-test.XXXXXX")
if [ -n "${KEEP:-}" ]; then echo "keeping test files in $T"; else trap 'rm -rf "$T"' EXIT; fi

NOW="2026-01-15 12:00"
export BOT_TRIAGE_NOW="$NOW"
base=$(date -d "$NOW" +%s)
ts() { LC_ALL=C date -d "@$((base - $1 * 60))" '+%d/%b/%Y:%H:%M:%S %z'; }   # minutes ago

pass=0 fail=0
ok()   { pass=$((pass + 1)); printf 'ok   %s\n' "$1"; }
bad()  { fail=$((fail + 1)); printf 'FAIL %s\n' "$1"; }
check() { # description, grep -E pattern, file
  if grep -qE -- "$2" "$3"; then ok "$1"; else bad "$1  (pattern: $2)"; fi
}

# ------------------------------------------------------------------ fixtures
mkdir -p "$T/domlogs/user1" "$T/apache2"
L=$T/domlogs/example.com-ssl_log
{
  for i in $(seq 1 400); do
    echo "203.0.113.7 - - [$(ts $((i % 10)))] \"POST /xmlrpc.php HTTP/1.1\" 200 412 \"-\" \"Mozilla/5.0 (compatible; ExampleBot)\""
  done
  probes=(/.env /.git/config /wp-config.php.bak /app.js.map /@fs/etc/passwd /vendor/phpunit/x.php)
  for i in $(seq 1 120); do
    echo "198.51.100.23 - - [$(ts $((i % 10)))] \"GET ${probes[i % 6]} HTTP/1.1\" 404 196 \"-\" \"Go-http-client/1.1\""
  done
  for i in $(seq 1 600); do
    if [ $((i % 2)) -eq 0 ]; then ip="192.0.2.$((i % 254 + 1))"; else ip="198.51.100.$((100 + (i / 2) % 150))"; fi
    echo "$ip - - [$(ts $((i % 10)))] \"GET /plants?color=12%2C$i&size=3 HTTP/1.1\" 200 51234 \"-\" \"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0\""
  done
  for i in $(seq 1 50); do
    echo "203.0.113.50 - - [$(ts $((i % 10)))] \"GET /page-$i HTTP/1.1\" 200 9000 \"-\" \"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)\""
  done
  for i in $(seq 1 30); do
    echo "198.51.100.5 - - [$(ts $((i % 10)))] \"GET / HTTP/1.1\" 200 30000 \"https://example.com/\" \"Mozilla/5.0 (X11; Linux x86_64) Firefox/140.0\""
  done
  for i in $(seq 1 25); do
    echo "203.0.113.60 - - [$(ts $((i % 10)))] \"GET /page.php/blog/blog/blog/$i HTTP/1.1\" 200 30000 \"-\" \"Mozilla/5.0 (compatible; MJ12bot/v1.4.8)\""
  done
  # same day and time, other month: must NOT be counted
  for i in $(seq 1 77); do
    echo "203.0.113.99 - - [15/Dec/2025:11:55:00 +0000] \"GET /old HTTP/1.1\" 200 1 \"-\" \"old\""
  done
} > "$L"
ln "$L" "$T/domlogs/user1/example.com-ssl_log"   # cPanel-style second path to the same file

for i in $(seq 1 80); do
  echo "172.70.1.2 - - [$(ts $((i % 10)))] \"GET /shop HTTP/1.1\" 200 4000 \"-\" \"Mozilla/5.0 Safari/605\""
done > "$T/domlogs/cf.example.net-ssl_log"

for i in $(seq 1 40); do
  echo "shop.example.org:443 192.0.2.77 - - [$(ts $((i % 10)))] \"GET /cart?add-to-cart=$i HTTP/1.1\" 302 0 \"-\" \"Mozilla/5.0 (compatible; SemrushBot/7)\""
done > "$T/apache2/other_vhosts_access.log"

# ------------------------------------------------------------------ triage
bash "$S/triage.sh" -m 15 -n 20 -l "$T/domlogs" -l "$T/apache2" > "$T/out.md" 2> "$T/err"
[ -s "$T/err" ] && { echo "--- stderr:"; cat "$T/err"; }
check "total excludes old-month lines and hardlinked duplicate" '^- Requests: 1345 ' "$T/out.md"
check "top IP 203.0.113.7 with 400 requests"         '^\| 400 \| [0-9.]+ \| 203\.0\.113\.7 \|' "$T/out.md"
check "xmlrpc signature counted once per request"    '^\| xmlrpc \| 400 \| 1 \|' "$T/out.md"
check "probe signature"                              '^\| probe \| 120 \| 1 \| 198\.51\.100\.23' "$T/out.md"
check "multi-value filter crawl"                     '^\| multi-value-filter \| 600 \|' "$T/out.md"
check "unverified Googlebot claim"                   '^\| googlebot-claim-unverified \| 50 \|' "$T/out.md"
check "PATH_INFO loop"                               '^\| pathinfo-loop \| 25 \|' "$T/out.md"
check "cart-action from vhost_combined log"          '^\| cart-action \| 40 \| 1 \| 192\.0\.2\.77' "$T/out.md"
check "vhost_combined site name"                     '^\| 40 \| shop\.example\.org \|' "$T/out.md"
check "Cloudflare address flagged"                   '172\.70\.1\.2 \|.*\| CLOUDFLARE \|' "$T/out.md"
check "distributed-traffic hint"                     'Distributed traffic' "$T/out.md"
check "scanner hint"                                 'Vulnerability scanners' "$T/out.md"
check "brute-force hint"                             'WordPress brute force' "$T/out.md"
if grep -q '203\.0\.113\.99' "$T/out.md"; then bad "old-month IP leaked into report"; else ok "old-month IP absent"; fi

# stdin input
bash "$S/triage.sh" -m 15 -l - < "$T/apache2/other_vhosts_access.log" > "$T/stdin.md" 2>&1
check "stdin input works" '^- Requests: 40 ' "$T/stdin.md"

# empty window
BOT_TRIAGE_NOW="2026-06-01 00:00" bash "$S/triage.sh" -m 5 -l "$T/apache2" > "$T/empty.md" 2>&1
check "empty window handled" 'No requests found' "$T/empty.md"

# ------------------------------------------------------------------ ip-detail
bash "$S/ip-detail.sh" -m 15 -l "$T/domlogs" 203.0.113.7 > "$T/ip.md" 2>&1
check "ip-detail request count" '^- Requests in window: 400$' "$T/ip.md"
check "ip-detail top URL"       '^\| 400 \| /xmlrpc\.php \|' "$T/ip.md"
if bash "$S/ip-detail.sh" 'x;id' > /dev/null 2>&1; then bad "ip-detail accepted a non-IP"; else ok "ip-detail rejects non-IP"; fi

# ------------------------------------------------------------------ gen-blocks
bash "$S/gen-blocks.sh" -T all -i 203.0.113.7 -i 198.51.100.0/24 -u SemrushBot -p /xmlrpc.php -c "test run" > "$T/blocks.md" 2>&1
check "csf temp deny"            '^csf -td 203\.0\.113\.7 86400 "test run"$' "$T/blocks.md"
check "csf perm deny keeps tag"  '^csf -d 198\.51\.100\.0/24 "do not delete - test run' "$T/blocks.md"
check "htaccess exact IP"        '^RewriteCond %\{REMOTE_ADDR\} \^203\\\.0\\\.113\\\.7\$ \[OR\]$' "$T/blocks.md"
check "htaccess /24 prefix"      '^RewriteCond %\{REMOTE_ADDR\} \^198\\\.51\\\.100\\\.$' "$T/blocks.md"
check "htaccess UA rule"         '^RewriteCond %\{HTTP_USER_AGENT\} \(SemrushBot\) \[NC\]$' "$T/blocks.md"
check "htaccess path rule"       '^RewriteRule \^\(xmlrpc\\\.php\) - \[F,L\]$' "$T/blocks.md"
check "nginx deny"               '^deny 198\.51\.100\.0/24;$' "$T/blocks.md"
check "cloudflare expression"    '^\(ip\.src in \{203\.0\.113\.7 198\.51\.100\.0/24\}\) or \(lower\(http\.user_agent\) contains "semrushbot"\) or \(starts_with\(http\.request\.uri\.path, "/xmlrpc\.php"\)\)$' "$T/blocks.md"
check "ufw rule"                 '^ufw insert 1 deny from 203\.0\.113\.7 comment "test run"$' "$T/blocks.md"
check "firewalld temporary"      "^firewall-cmd --add-rich-rule='rule family=\"ipv4\" source address=\"203\.0\.113\.7\" drop' --timeout=86400$" "$T/blocks.md"
check "nftables expiring set"    "^nft add element inet bot_triage deny4 '\{ 203\.0\.113\.7 timeout 86400s, 198\.51\.100\.0/24 timeout 86400s \}'$" "$T/blocks.md"
check "ipset rule"               '^ipset add bot-triage 198\.51\.100\.0/24 timeout 86400 -exist$' "$T/blocks.md"
check "imunify360 rule"          '^imunify360-agent ip-list local add --purpose drop 203\.0\.113\.7 ' "$T/blocks.md"
check "apache server config"     '^SetEnvIfNoCase User-Agent "\(SemrushBot\)" bot_triage_block$' "$T/blocks.md"
check "apache keeps other rules" '^    AuthMerging And$' "$T/blocks.md"
check "nginx UA map"             '^    "~\*\(SemrushBot\)" 1;$' "$T/blocks.md"
check "caddy matcher"            '^@bot_triage_ip remote_ip 203\.0\.113\.7 198\.51\.100\.0/24$' "$T/blocks.md"
check "caddy path matcher"       '^@bot_triage_path path /xmlrpc\.php\*$' "$T/blocks.md"
bash "$S/gen-blocks.sh" -C -T htaccess -i 203.0.113.7 > "$T/cf.md" 2>&1
check "behind-Cloudflare header" 'CF-Connecting-IP' "$T/cf.md"
bash "$S/gen-blocks.sh" -i 203.0.113.7 > "$T/auto.md" 2>&1
check "auto target detection runs" '^Detected: panel ' "$T/auto.md"
if bash "$S/gen-blocks.sh" -T bogus -i 203.0.113.7 > /dev/null 2>&1; then bad "gen-blocks accepted unknown target"; else ok "gen-blocks rejects unknown target"; fi
bash "$S/detect-env.sh" > "$T/env" 2>&1
check "detect-env prints WEB_TARGET" '^WEB_TARGET=' "$T/env"
# shellcheck disable=SC2016  # literal $(id) is the point of this test
for evil in '203.0.113.4;id' '203.0.113.4/33' '300.0.113.1' '$(id)'; do
  if bash "$S/gen-blocks.sh" -i "$evil" > /dev/null 2>&1; then bad "gen-blocks accepted IP '$evil'"; else ok "gen-blocks rejects IP '$evil'"; fi
done
if bash "$S/gen-blocks.sh" -u 'x"; rm -rf /' > /dev/null 2>&1; then bad "gen-blocks accepted unsafe UA"; else ok "gen-blocks rejects unsafe UA"; fi

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
