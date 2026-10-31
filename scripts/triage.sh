#!/usr/bin/env bash
# bot-triage: read-only snapshot of what is loading a web server right now.
# Prints a markdown report: host load, traffic volume, top IPs/subnets/user agents/paths,
# attack signatures, and plain-language hints on where to block. Changes nothing.
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$HERE/lib.sh"

MINUTES=15
TOP=15
MAXLINES=200000
LOGS=()

usage() {
  cat <<'EOF'
Usage: triage.sh [-m MINUTES] [-n TOP] [-L MAXLINES] [-l LOG_FILE_OR_DIR]...

  -m MINUTES   time window to analyse (default 15)
  -n TOP       rows per table (default 15)
  -L MAXLINES  lines read from the end of each log file (default 200000)
  -l PATH      access log file or directory; repeatable. Default: auto-detect
               (cPanel domlogs, /var/log/apache2, httpd, nginx, LiteSpeed, Plesk)

Environment:
  BOT_TRIAGE_NOW  analyse a past window, e.g. BOT_TRIAGE_NOW="2026-01-31 14:05"

Read-only. Run as root (or a user that can read the logs).
EOF
}

while getopts ':m:n:L:l:h' opt; do
  case $opt in
    m) MINUTES=$OPTARG ;;
    n) TOP=$OPTARG ;;
    L) MAXLINES=$OPTARG ;;
    l) LOGS+=("$OPTARG") ;;
    h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
for v in "$MINUTES" "$TOP" "$MAXLINES"; do
  case $v in ''|*[!0-9]*) bt_die "-m, -n and -L take positive whole numbers" ;; esac
done
[ "$MINUTES" -ge 1 ] && [ "$MINUTES" -le 1440 ] || bt_die "-m must be 1..1440"

WORK=$(mktemp -d "${TMPDIR:-/tmp}/bot-triage.XXXXXX") || bt_die "cannot create temp dir"
trap 'rm -rf "$WORK"' EXIT

bt_minute_keys "$MINUTES" > "$WORK/keys"
mapfile -t FILES < <(bt_find_logs "$MINUTES" "${LOGS[@]}")
[ ${#FILES[@]} -gt 0 ] || bt_die "no access logs written in the last $MINUTES min (use -l PATH)"
bt_normalize "$WORK/keys" "$MAXLINES" "${FILES[@]}" > "$WORK/req.tsv"
TOTAL=$(wc -l < "$WORK/req.tsv")

# ---------------------------------------------------------------- host snapshot
echo "# Bot triage report"
echo
echo "- Host: $(hostname 2>/dev/null || echo unknown)"
echo "- Window: last $MINUTES min ending $(date -d "${BOT_TRIAGE_NOW:-now}" '+%Y-%m-%d %H:%M %Z')"
echo "- Log files read: ${#FILES[@]}"
echo
echo "## Host load"
echo
if [ -z "${BOT_TRIAGE_NOW:-}" ]; then
  read -r l1 l5 l15 _ < /proc/loadavg
  cores=$(nproc 2>/dev/null || echo '?')
  echo "- Load average: $l1 / $l5 / $l15 on $cores cores"
  if command -v vmstat >/dev/null 2>&1; then
    # last line of a 1-second sample: r b ... us sy id wa
    vmstat 1 2 | tail -1 | awk '{printf "- Run queue %s, blocked on I/O %s, CPU idle %s%%, I/O wait %s%%\n", $1, $2, $15, $16}'
  fi
  # shellcheck disable=SC2009  # pgrep cannot select by process state
  dstate=$(ps -eo stat= 2>/dev/null | grep -c '^D' || true)
  echo "- Processes in D state (waiting on disk/network storage): $dstate"
  echo
  echo "Busiest processes (CPU %, user, command):"
  echo
  echo '```'
  ps -eo pcpu=,user=,comm= --sort=-pcpu 2>/dev/null | head -8
  echo '```'
  echo
  # shellcheck disable=SC2009  # counting several process names at once
  echo "Worker counts: $(ps -eo comm= 2>/dev/null | grep -E '^(lsphp|php-fpm|php-cgi|httpd|apache2|nginx|litespeed|lshttpd|mysqld|mariadbd)' | sort | uniq -c | awk '{printf "%s %s, ", $2, $1}' | sed 's/, $//')"
  echo
  bash "$HERE/detect-env.sh" -H | sed 's/^## /### /'
else
  echo "- Skipped (BOT_TRIAGE_NOW set: analysing a past window)."
fi
echo

if [ "$TOTAL" -eq 0 ]; then
  echo "No requests found in the window. Check the time window, the log paths (-l), or the log format (combined format expected)."
  exit 0
fi

# ---------------------------------------------------------------- classification
# Tags each request with zero or more signatures. Output: tag<TAB>ip<TAB>site
LC_ALL=C awk -F'\t' '
function lc(s) { return tolower(s) }
{
  ip = $2; method = $3; path = lc($4); query = lc($5); status = $6; ua = lc($7)
  full = path "?" query
  if (path ~ /\/\.env|\/\.git|\.js\.map$|\/@fs\/|__vite|storage\/framework|bootstrap\/cache|phpinfo|\/vendor\/phpunit|\/\.aws|\/\.ssh|wp-config\.php|\.sql$|\.bak$|\/\.svn|\.ds_store|\/wp-content\/plugins\/wp-file-manager/) print "probe\t" ip "\t" $1
  if (full ~ /pagename=|pearcmd|\.\.\/|%2e%2e|\/etc\/passwd|php:\/\/|allow_url_include|\$\{jndi|union(%20|\+)select/) print "lfi-rce\t" ip "\t" $1
  if (method == "POST" && path ~ /wp-login\.php$/) print "wp-login-post\t" ip "\t" $1
  if (path ~ /xmlrpc\.php$/) print "xmlrpc\t" ip "\t" $1
  if (path ~ /wp-json\/batch\/v1|wp-json\/wp\/v2\/users/ || query ~ /rest_route=%2fwp%2fv2%2fusers|rest_route=\/wp\/v2\/users|rest_route=\/batch|rest_route=%2fbatch/) print "wp-api-abuse\t" ip "\t" $1
  if (query ~ /add-to-cart=|add_to_cart=|add_to_wishlist=|remove_item=|add_to_compare=|wc-ajax=add_to_cart/) print "cart-action\t" ip "\t" $1
  if (query ~ /%2c|,/) print "multi-value-filter\t" ip "\t" $1
  if (query != "") {
    n = split(query, pp, "&"); real = 0
    for (i = 1; i <= n; i++) if (pp[i] !~ /^(utm_|fbclid|gclid|msclkid|_ga)/) real++
    if (real >= 3) print "3plus-params\t" ip "\t" $1
  }
  j = index(path, ".php/")
  if (j) { rest = substr(path, j + 5); if (gsub(/\//, "/", rest) >= 2) print "pathinfo-loop\t" ip "\t" $1 }
  if (status == "404" && path ~ /\.php$|\/$|^[^.]*$/) print "404-dynamic\t" ip "\t" $1
  if (ua == "-" || ua == "") print "no-user-agent\t" ip "\t" $1
  if (ua ~ /python-requests|python-urllib|aiohttp|go-http-client|^curl\/|^wget\/|libwww|okhttp|scrapy|apache-httpclient|^java\/|node-fetch|axios|headlesschrome|phantomjs|zgrab|masscan|nuclei/) print "script-client\t" ip "\t" $1
  if (ua ~ /semrush|ahrefs|mj12bot|dotbot|blexbot|dataforseo|seranking|serpstat|petalbot|barkrowler|megaindex|zoominfo|screaming frog|seokicks|linkpad|siteauditbot/) print "seo-crawler\t" ip "\t" $1
  if (ua ~ /gptbot|chatgpt-user|oai-searchbot|claudebot|claude-searchbot|claude-user|anthropic-ai|perplexitybot|perplexity-user|bytespider|ccbot|amazonbot|applebot-extended|meta-externalagent|facebookbot|youbot|diffbot|cohere-ai|timpibot|imagesiftbot/) print "ai-crawler\t" ip "\t" $1
  if (ua ~ /googlebot/ && ip !~ /^66\.249\./) print "googlebot-claim-unverified\t" ip "\t" $1
}' "$WORK/req.tsv" > "$WORK/tags.tsv"

# ---------------------------------------------------------------- summary metrics
LC_ALL=C awk -F'\t' -v cfr="$BT_CF_RANGES" -v minutes="$MINUTES" '
function ip2n(ip,  o) { if (split(ip, o, ".") != 4) return -1; return ((o[1] * 256 + o[2]) * 256 + o[3]) * 256 + o[4] }
function iscf(ip,  n, i) { n = ip2n(ip); if (n < 0) return 0; for (i = 1; i <= ncf; i++) if (n >= cfs[i] && n < cfe[i]) return 1; return 0 }
BEGIN { ncf = split(cfr, r, " "); for (i = 1; i <= ncf; i++) { split(r[i], c, "/"); cfs[i] = ip2n(c[1]); cfe[i] = cfs[i] + 2 ^ (32 - c[2]) } }
{ total++; ipc[$2]++; url[$4 "?" $5] = 1; if ($6 ~ /^5/) e5++; if ($6 ~ /^4/) e4++ }
END {
  for (ip in ipc) {
    nip++; if (ipc[ip] > top) { top = ipc[ip]; topip = ip }; if (iscf(ip)) cfreq += ipc[ip]
    if (ipc[ip] <= 3) { lightips++; lightreq += ipc[ip] }
  }
  for (u in url) nurl++
  printf "total %d\nrpm %.0f\nips %d\ntopip %s\ntopcount %d\ncfreq %d\nurls %d\ne4 %d\ne5 %d\nlightips %d\nlightreq %d\n", total, total / minutes, nip, topip, top, cfreq, nurl, e4, e5, lightips, lightreq
}' "$WORK/req.tsv" > "$WORK/summary"
declare -A S
while read -r k v; do S[$k]=$v; done < "$WORK/summary"
declare -A T
while read -r c t; do T[$t]=$c; done < <(cut -f1 "$WORK/tags.tsv" | sort | uniq -c)
pct() { awk -v a="$1" -v b="$2" 'BEGIN { if (b > 0) printf "%.0f", 100 * a / b; else print 0 }'; }

echo "## Traffic volume"
echo
echo "- Requests: ${S[total]} (about ${S[rpm]}/min), from ${S[ips]} distinct IPs"
echo "- Distinct URLs: ${S[urls]} ($(pct "${S[urls]}" "${S[total]}")% of requests; high means cache-busting crawl)"
echo "- 4xx: ${S[e4]:-0} ($(pct "${S[e4]:-0}" "${S[total]}")%), 5xx: ${S[e5]:-0} ($(pct "${S[e5]:-0}" "${S[total]}")%)"
echo
echo "### Requests per site"
echo
echo "| Requests | Site |"
echo "|---:|---|"
cut -f1 "$WORK/req.tsv" | sort | uniq -c | sort -rn | head -n "$TOP" | awk '{printf "| %s | %s |\n", $1, $2}'
echo

# ---------------------------------------------------------------- top IPs
echo "## Top client IPs"
echo
echo "| Requests | % | IP | Sites | Distinct paths | 4xx % | Flags | Most used user agent |"
echo "|---:|---:|---|---:|---:|---:|---|---|"
LC_ALL=C awk -F'\t' -v total="${S[total]}" -v cfr="$BT_CF_RANGES" '
function ip2n(ip,  o) { if (split(ip, o, ".") != 4) return -1; return ((o[1] * 256 + o[2]) * 256 + o[3]) * 256 + o[4] }
function iscf(ip,  n, i) { n = ip2n(ip); if (n < 0) return 0; for (i = 1; i <= ncf; i++) if (n >= cfs[i] && n < cfe[i]) return 1; return 0 }
BEGIN { ncf = split(cfr, r, " "); for (i = 1; i <= ncf; i++) { split(r[i], c, "/"); cfs[i] = ip2n(c[1]); cfe[i] = cfs[i] + 2 ^ (32 - c[2]) } }
{
  ip = $2; n[ip]++
  if (!((ip, $1) in seen)) { seen[ip, $1] = 1; sites[ip]++ }
  if (!((ip, $4) in pseen)) { pseen[ip, $4] = 1; paths[ip]++ }
  if ($6 ~ /^4/) e4[ip]++
  uac[ip, $7]++; if (uac[ip, $7] > best[ip]) { best[ip] = uac[ip, $7]; bua[ip] = $7 }
}
END {
  for (ip in n) {
    ua = bua[ip]; gsub(/\|/, "/", ua); if (length(ua) > 70) ua = substr(ua, 1, 67) "..."
    printf "%d\t| %d | %.1f | %s | %d | %d | %.0f | %s | %s |\n", n[ip], n[ip], 100 * n[ip] / total, ip, sites[ip], paths[ip], 100 * e4[ip] / n[ip], (iscf(ip) ? "CLOUDFLARE" : ""), ua
  }
}' "$WORK/req.tsv" | sort -t "$(printf '\t')" -k1,1rn | head -n "$TOP" | cut -f2-
echo

echo "## Top /24 subnets"
echo
echo "| Requests | Subnet | Distinct IPs |"
echo "|---:|---|---:|"
LC_ALL=C awk -F'\t' '$2 ~ /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/ {
  split($2, o, "."); s = o[1] "." o[2] "." o[3] ".0/24"; n[s]++
  if (!(($2) in seen)) { seen[$2] = 1; d[s]++ }
} END { for (s in n) printf "%d\t| %d | %s | %d |\n", n[s], n[s], s, d[s] }' "$WORK/req.tsv" \
  | sort -t "$(printf '\t')" -k1,1rn | head -n "$TOP" | cut -f2-
echo

echo "## Top user agents"
echo
echo "| Requests | Distinct IPs | User agent |"
echo "|---:|---:|---|"
LC_ALL=C awk -F'\t' '{ n[$7]++; if (!(($7, $2) in seen)) { seen[$7, $2] = 1; d[$7]++ } }
END { for (u in n) { ua = u; gsub(/\|/, "/", ua); if (length(ua) > 110) ua = substr(ua, 1, 107) "..."; printf "%d\t| %d | %d | %s |\n", n[u], n[u], d[u], ua } }' "$WORK/req.tsv" \
  | sort -t "$(printf '\t')" -k1,1rn | head -n "$TOP" | cut -f2-
echo

echo "## Top paths (query string removed)"
echo
echo "| Requests | Distinct IPs | With query % | Site | Path |"
echo "|---:|---:|---:|---|---|"
LC_ALL=C awk -F'\t' '{ k = $1 "\t" $4; n[k]++; if ($5 != "") q[k]++; if (!((k, $2) in seen)) { seen[k, $2] = 1; d[k]++ } }
END { for (k in n) { split(k, a, "\t"); p = a[2]; gsub(/\|/, "%7C", p); if (length(p) > 90) p = substr(p, 1, 87) "..."; printf "%d\t| %d | %d | %.0f | %s | %s |\n", n[k], n[k], d[k], 100 * q[k] / n[k], a[1], p } }' "$WORK/req.tsv" \
  | sort -t "$(printf '\t')" -k1,1rn | head -n "$TOP" | cut -f2-
echo

# ---------------------------------------------------------------- signatures
echo "## Attack and crawler signatures"
echo
if [ ! -s "$WORK/tags.tsv" ]; then
  echo "No known signature matched."
else
  echo "| Signature | Requests | Distinct IPs | Top IPs (requests) |"
  echo "|---|---:|---:|---|"
  cut -f1,2 "$WORK/tags.tsv" | sort | uniq -c | sort -k2,2 -k1,1rn | LC_ALL=C awk '
    { t = $2; tot[t] += $1; d[t]++; if (d[t] <= 3) top[t] = top[t] (top[t] == "" ? "" : ", ") $3 " (" $1 ")" }
    END { for (t in tot) printf "%d\t| %s | %d | %d | %s |\n", tot[t], t, tot[t], d[t], top[t] }' \
    | sort -t "$(printf '\t')" -k1,1rn | cut -f2-
fi
echo

# ---------------------------------------------------------------- hints
echo "## What this suggests"
echo
hints=0
hint() { echo "- $*"; hints=$((hints + 1)); }
total=${S[total]}
if [ "$(pct "${S[cfreq]:-0}" "$total")" -ge 50 ]; then
  hint "**Traffic arrives through Cloudflare.** The origin sees Cloudflare addresses, so csf/iptables/ufw blocks here would block Cloudflare itself. Block in the Cloudflare WAF, or match the real client in .htaccess via CF-Connecting-IP (only if the origin accepts web traffic from Cloudflare alone). See references/cloudflare-waf.md."
fi
if [ "$(pct "${S[topcount]}" "$total")" -ge 20 ]; then
  hint "**One IP dominates:** ${S[topip]} sent $(pct "${S[topcount]}" "$total")% of requests. Inspect it (scripts/ip-detail.sh ${S[topip]}) and, if abusive, add a temporary firewall deny (scripts/gen-blocks.sh)."
fi
if [ "${S[lightips]:-0}" -ge 200 ] && [ "$(pct "${S[lightreq]:-0}" "$total")" -ge 30 ]; then
  hint "**Distributed traffic:** ${S[lightips]} IPs sent only 1-3 requests each, together $(pct "${S[lightreq]}" "$total")% of all requests. That is a rotating residential/proxy pool: per-IP blocks will not keep up. Find the shared fingerprint (path, query shape, user agent, missing referer) and block that pattern at the web server or CDN instead."
fi
if [ "$(pct "${S[urls]}" "$total")" -ge 70 ] && [ "$total" -ge 300 ]; then
  hint "**Almost every URL is unique,** so nothing caches and each request is a full application render. Typical of filter/facet enumeration or cache-busting crawls."
fi
if [ "${T[probe]:-0}" -gt 0 ] || [ "${T[lfi-rce]:-0}" -gt 0 ]; then
  hint "**Vulnerability scanners** (${T[probe]:-0} probe + ${T[lfi-rce]:-0} LFI/RCE requests). On a CMS every 404 is a full PHP render, so scanners cost CPU even when they fail. Deny the IPs temporarily and consider an early 403 for probe paths (references/web-servers.md). Also check the targeted sites for compromise if any probe got a 200."
fi
if [ "${T[xmlrpc]:-0}" -ge 50 ] || [ "${T[wp-login-post]:-0}" -ge 50 ]; then
  hint "**WordPress brute force:** ${T[xmlrpc]:-0} xmlrpc.php + ${T[wp-login-post]:-0} wp-login POSTs. Block xmlrpc.php if the site does not use it (Jetpack and some apps do) and deny the sources."
fi
if [ "${T[wp-api-abuse]:-0}" -gt 0 ]; then
  hint "**WordPress REST abuse** (user enumeration or /batch/v1, ${T[wp-api-abuse]} requests). Batch-endpoint exploits have been used to create rogue admins: check the affected sites for unknown administrator accounts."
fi
if [ "${T[cart-action]:-0}" -ge 50 ]; then
  hint "**Bots hitting cart/wishlist links** (${T[cart-action]} requests). Each one creates a session and bypasses page cache. Block crawler user agents on those query parameters and add them to robots.txt Disallow."
fi
if [ "${T[multi-value-filter]:-0}" -ge 100 ] || [ "${T[3plus-params]:-0}" -ge 100 ]; then
  hint "**Faceted-navigation crawl** (${T[multi-value-filter]:-0} multi-value + ${T[3plus-params]:-0} 3+ parameter URLs). Real shoppers rarely stack many filters. Challenge or block that query shape, but exclude XHR/API/checkout paths (they cannot solve a challenge). See references/cloudflare-waf.md."
fi
if [ "${T[pathinfo-loop]:-0}" -ge 20 ]; then
  hint "**PATH_INFO loop** (${T[pathinfo-loop]} URLs like /page.php/a/b/c). The app serves the same page under endless URLs and crawlers follow relative links forever. Fix at the source with a 301 back to the .php URL."
fi
if [ "${T[seo-crawler]:-0}" -ge 100 ] || [ "${T[ai-crawler]:-0}" -ge 100 ]; then
  hint "**Heavy SEO/AI crawlers** (${T[seo-crawler]:-0} SEO + ${T[ai-crawler]:-0} AI-crawler requests). Most honour robots.txt (Disallow or Crawl-delay) within a day; block the user agent only if it ignores robots.txt or the load is acute."
fi
if [ "${T[googlebot-claim-unverified]:-0}" -gt 0 ]; then
  hint "**Requests claim to be Googlebot from non-Google ranges** (${T[googlebot-claim-unverified]}). Verify with reverse + forward DNS (scripts/ip-detail.sh does this) before treating them as Google; fake Googlebots are common and safe to block."
fi
if [ "${T[no-user-agent]:-0}" -ge 50 ] || [ "${T[script-client]:-0}" -ge 100 ]; then
  hint "**Scripted clients** (${T[no-user-agent]:-0} with no user agent, ${T[script-client]:-0} from HTTP libraries). Legitimate integrations (payment callbacks, ERP, uptime monitors) also look like this: confirm before blocking."
fi
[ "$hints" -eq 0 ] && echo "- Nothing stands out. If load is high, the cause may not be web traffic: check the database, cron jobs, backups and disk I/O."
echo
echo "_Read-only report. Nothing was changed._"
