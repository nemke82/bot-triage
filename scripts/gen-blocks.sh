#!/usr/bin/env bash
# bot-triage: PRINT block rules for review. This script never applies anything.
# It validates the inputs and prints firewall commands and web-server/CDN rules
# for the layers this server actually uses (-T auto, the default), or for the
# targets you name. A human, or the agent after approval, applies them.
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$HERE/lib.sh"

ALL_TARGETS="csf imunify360 ufw firewalld nftables iptables htaccess apache nginx caddy cloudflare"
IPS=()
UAS=()
PATHS=()
TTL=86400
COMMENT="bot-triage"
TARGETS=auto
BEHIND_CF=0

usage() {
  cat <<EOF
Usage: gen-blocks.sh [options]

  -i IP_OR_CIDR   IPv4 address or CIDR (/8../32) to block; repeatable or comma-separated
  -u UA_TOKEN     user-agent substring to block (e.g. SemrushBot); repeatable
  -p PATH_PREFIX  URL path prefix to block (e.g. /xmlrpc.php); repeatable or comma-separated
  -t SECONDS      length of temporary bans (default 86400 = 24h)
  -c COMMENT      comment stored with firewall entries (default "bot-triage")
  -T TARGETS      auto (default: detect this server), all, or a comma list of:
                  $ALL_TARGETS
  -C              traffic arrives through Cloudflare: add the Cloudflare rule and
                  match CF-Connecting-IP in web-server rules

Prints commands and snippets only. Review them, then apply the ones that fit.
EOF
}

split_add() { # array-name value
  local -n arr=$1
  local IFS=',' part
  for part in $2; do [ -n "$part" ] && arr+=("$part"); done
}

while getopts ':i:u:p:t:c:T:Ch' opt; do
  case $opt in
    i) split_add IPS "$OPTARG" ;;
    u) UAS+=("$OPTARG") ;;
    p) split_add PATHS "$OPTARG" ;;
    t) TTL=$OPTARG ;;
    c) COMMENT=$OPTARG ;;
    T) TARGETS=$OPTARG ;;
    C) BEHIND_CF=1 ;;
    h) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[ ${#IPS[@]} -gt 0 ] || [ ${#UAS[@]} -gt 0 ] || [ ${#PATHS[@]} -gt 0 ] || { usage >&2; exit 2; }
case $TTL in ''|*[!0-9]*) bt_die "-t takes seconds" ;; esac

# ---- validation: everything printed here may be pasted into a root shell
valid_ipv4() {
  local ip=$1 mask=32 octet
  if [[ $ip == */* ]]; then mask=${ip#*/}; ip=${ip%/*}; fi
  [[ $mask =~ ^[0-9]+$ ]] && [ "$mask" -ge 8 ] && [ "$mask" -le 32 ] || return 1
  [[ $ip =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for octet in "${BASH_REMATCH[@]:1}"; do [ "$((10#$octet))" -le 255 ] || return 1; done
}
for x in "${IPS[@]}"; do valid_ipv4 "$x" || bt_die "not an IPv4 address or CIDR (/8../32): $x"; done
for x in "${UAS[@]}"; do [[ $x =~ ^[A-Za-z0-9._/\ -]{3,60}$ ]] || bt_die "user-agent token must be 3-60 chars of letters, digits, space . _ / -: $x"; done
for x in "${PATHS[@]}"; do [[ $x =~ ^/[A-Za-z0-9._/~-]{0,120}$ ]] || bt_die "path prefix must start with / and use letters, digits . _ / ~ -: $x"; done
COMMENT=$(printf '%s' "$COMMENT" | tr -cd 'A-Za-z0-9 ._:/-' | cut -c1-80)

# ---- choose targets
DETECTED=""
if [ "$TARGETS" = auto ]; then
  env_out=$(bash "$HERE/detect-env.sh") || bt_die "detect-env.sh failed"
  FIREWALL=none WEB_TARGET=none WEB_FRONT=unknown PANEL=none
  # Read only the keys we need; accept plain word values, ignore everything else.
  while IFS='=' read -r key val; do
    [[ $val =~ ^[a-z0-9_-]+$ ]] || continue
    case $key in
      FIREWALL) FIREWALL=$val ;;
      WEB_TARGET) WEB_TARGET=$val ;;
      WEB_FRONT) WEB_FRONT=$val ;;
      PANEL) PANEL=$val ;;
    esac
  done <<< "$env_out"
  TARGETS=""
  [ "$FIREWALL" != none ] && TARGETS+="$FIREWALL"
  [ "$WEB_TARGET" != none ] && TARGETS+="${TARGETS:+,}$WEB_TARGET"
  [ "$BEHIND_CF" -eq 1 ] && TARGETS+="${TARGETS:+,}cloudflare"
  [ -n "$TARGETS" ] || TARGETS=all
  DETECTED="Detected: panel $PANEL, web server in front $WEB_FRONT, firewall $FIREWALL. Use -T all to see every option."
elif [ "$TARGETS" = all ]; then
  TARGETS=${ALL_TARGETS// /,}
fi
IFS=',' read -r -a TLIST <<< "$TARGETS"
for t in "${TLIST[@]}"; do
  case " $ALL_TARGETS " in *" $t "*) ;; *) bt_die "unknown target: $t (choose from: auto all $ALL_TARGETS)" ;; esac
done
want() { local t; for t in "${TLIST[@]}"; do [ "$t" = "$1" ] && return 0; done; return 1; }

# Inputs are already restricted to [A-Za-z0-9 ._/~-], so only "." can be a regex metachar,
# but escape the full set anyway in case validation is loosened later.
# shellcheck disable=SC2016  # literal regex characters, nothing to expand
regex_escape() { printf '%s' "$1" | sed 's#[.*^$()+?{}|]#\\&#g'; }
cidr_regex() { # CIDR -> REMOTE_ADDR regex, exact on octet boundaries, widened otherwise
  local ip=${1%/*} mask=32 o1 o2 o3 o4
  [[ $1 == */* ]] && mask=${1#*/}
  IFS=. read -r o1 o2 o3 o4 <<< "$ip"
  if [ "$mask" -ge 32 ]; then printf '^%s\\.%s\\.%s\\.%s$' "$o1" "$o2" "$o3" "$o4"
  elif [ "$mask" -ge 24 ]; then printf '^%s\\.%s\\.%s\\.' "$o1" "$o2" "$o3"
  elif [ "$mask" -ge 16 ]; then printf '^%s\\.%s\\.' "$o1" "$o2"
  else printf '^%s\\.' "$o1"; fi
}
ua_alt() { local x alt=""; for x in "${UAS[@]}"; do alt+="${alt:+|}$(regex_escape "$x")"; done; printf '%s' "$alt"; }
path_alt() { local x alt=""; for x in "${PATHS[@]}"; do alt+="${alt:+|}$(regex_escape "$x")"; done; printf '%s' "$alt"; }
fence() { echo; echo "\`\`\`$1"; }
endfence() { echo '```'; }

today=$(date +%Y-%m-%d)
hours=$(( (TTL + 3599) / 3600 ))
echo "# Proposed blocks ($today)"
echo
echo "Nothing has been applied. Review, then run only what fits this server."
[ -n "$DETECTED" ] && { echo; echo "$DETECTED"; }
if [ ${#IPS[@]} -eq 0 ]; then
  echo; echo "No IPs given, so no firewall rules: firewalls cannot match user agents or URL paths."
fi

# ================================================================ firewalls
if [ ${#IPS[@]} -gt 0 ]; then
  if want csf; then
    echo; echo "## csf (ConfigServer Firewall)"
    echo; echo "Temporary ban, expires by itself after ${hours}h (preferred for scanners and crawlers):"
    fence sh
    for x in "${IPS[@]}"; do printf 'csf -td %s %s "%s"\n' "$x" "$TTL" "$COMMENT"; done
    endfence
    echo; echo "Permanent deny for repeat offenders. Keep \"do not delete\" in the comment: when csf.deny reaches DENY_IP_LIMIT, lfd drops the oldest entries, permanent ones included, unless the comment says \"do not delete\"."
    fence sh
    for x in "${IPS[@]}"; do printf 'csf -d %s "do not delete - %s %s"\n' "$x" "$COMMENT" "$today"; done
    endfence
    echo; echo "Undo: \`csf -tr IP\` (temporary) or \`csf -dr IP\` (permanent)."
  fi
  if want imunify360; then
    echo; echo "## Imunify360"
    echo; echo "Imunify360 owns the firewall rules, so add blocks through its agent. Command names differ between versions: check \`imunify360-agent ip-list local add --help\` (newer) or \`imunify360-agent blacklist ip add --help\` (older)."
    fence sh
    for x in "${IPS[@]}"; do printf 'imunify360-agent ip-list local add --purpose drop %s --comment "%s"\n' "$x" "$COMMENT"; done
    endfence
    echo; echo "Undo: \`imunify360-agent ip-list local delete --purpose drop IP\`. These entries do not expire on their own."
  fi
  if want ufw; then
    echo; echo "## ufw (Ubuntu/Debian)"
    fence sh
    for x in "${IPS[@]}"; do printf 'ufw insert 1 deny from %s comment "%s"\n' "$x" "$COMMENT"; done
    endfence
    echo; echo "ufw has no expiring rules: note them and remove later with \`ufw delete deny from IP\`. Ports published by Docker bypass ufw (Docker writes its own iptables rules); block those in the DOCKER-USER chain instead."
  fi
  if want firewalld; then
    echo; echo "## firewalld (RHEL/Alma/Rocky/Fedora)"
    echo; echo "Temporary (runtime only, expires after ${hours}h):"
    fence sh
    for x in "${IPS[@]}"; do printf "firewall-cmd --add-rich-rule='rule family=\"ipv4\" source address=\"%s\" drop' --timeout=%s\n" "$x" "$TTL"; done
    endfence
    echo; echo "Permanent:"
    fence sh
    for x in "${IPS[@]}"; do printf "firewall-cmd --permanent --add-rich-rule='rule family=\"ipv4\" source address=\"%s\" drop'\n" "$x"; done
    echo "firewall-cmd --reload"
    endfence
  fi
  if want nftables; then
    echo; echo "## nftables"
    echo; echo "Uses its own table with a self-expiring set, so it does not touch existing tables. The first four lines are needed once."
    fence sh
    echo "nft add table inet bot_triage"
    echo "nft add set inet bot_triage deny4 '{ type ipv4_addr; flags interval, timeout; }'"
    echo "nft add chain inet bot_triage input '{ type filter hook input priority -10; policy accept; }'"
    echo "nft add rule inet bot_triage input ip saddr @deny4 drop"
    printf "nft add element inet bot_triage deny4 '{ %s }'\n" "$(for x in "${IPS[@]}"; do printf '%s timeout %ss, ' "$x" "$TTL"; done | sed 's/, $//')"
    endfence
    echo; echo "Inspect: \`nft list set inet bot_triage deny4\`. Remove all: \`nft delete table inet bot_triage\`. Not persistent across reboot unless added to /etc/nftables.conf."
  fi
  if want iptables; then
    echo; echo "## iptables + ipset (no firewall manager)"
    echo; echo "ipset entries expire by themselves. If ipset is not installed, use the plain rule below instead."
    fence sh
    echo "ipset create bot-triage hash:net timeout $TTL -exist"
    echo "iptables -C INPUT -m set --match-set bot-triage src -j DROP 2>/dev/null || iptables -I INPUT -m set --match-set bot-triage src -j DROP"
    for x in "${IPS[@]}"; do printf 'ipset add bot-triage %s timeout %s -exist\n' "$x" "$TTL"; done
    endfence
    echo; echo "Plain iptables (no expiry, lost on reboot unless saved):"
    fence sh
    for x in "${IPS[@]}"; do printf 'iptables -I INPUT -s %s -j DROP -m comment --comment "%s"\n' "$x" "$COMMENT"; done
    endfence
  fi
fi

# ================================================================ web servers
if want htaccess; then
  echo; echo "## .htaccess (Apache with AllowOverride, LiteSpeed, cPanel/Plesk/DirectAdmin sites)"
  echo; echo "Near the top of the site's .htaccess, above the CMS rewrite block. Back up the file first."
  echo "LiteSpeed: no {n,m} repetition and no [G] flag; match an encoded dot with [%]2e, not %2e; LiteSpeed Cache can answer cached pages before these rules run, so test with a fresh query string. OpenLiteSpeed only reads rewrite rules from .htaccess and needs a graceful restart to pick up changes."
  fence apache
  echo "# BEGIN bot-triage $today"
  echo "<IfModule mod_rewrite.c>"
  echo "RewriteEngine On"
  if [ ${#IPS[@]} -gt 0 ]; then
    var='%{REMOTE_ADDR}'; [ "$BEHIND_CF" -eq 1 ] && var='%{HTTP:CF-Connecting-IP}'
    n=${#IPS[@]}; i=0
    for x in "${IPS[@]}"; do
      i=$((i + 1)); flag=""; [ "$i" -lt "$n" ] && flag=" [OR]"
      printf 'RewriteCond %s %s%s\n' "$var" "$(cidr_regex "$x")" "$flag"
    done
    echo "RewriteRule .* - [F,L]"
  fi
  if [ ${#UAS[@]} -gt 0 ]; then
    printf 'RewriteCond %%{HTTP_USER_AGENT} (%s) [NC]\n' "$(ua_alt | sed 's/ /\\ /g')"
    echo "RewriteRule .* - [F,L]"
  fi
  if [ ${#PATHS[@]} -gt 0 ]; then
    alt=""; for x in "${PATHS[@]}"; do alt+="${alt:+|}$(regex_escape "${x#/}")"; done
    printf 'RewriteRule ^(%s) - [F,L]\n' "$alt"
  fi
  echo "</IfModule>"
  echo "# END bot-triage"
  endfence
  for x in "${IPS[@]}"; do
    m=32; [[ $x == */* ]] && m=${x#*/}
    case $m in 8|16|24|32) ;; *) echo; echo "Note: $x is not on an octet boundary; the pattern above widens it to the enclosing /$(( m >= 24 ? 24 : (m >= 16 ? 16 : 8) ))." ;; esac
  done
fi

if want apache; then
  echo; echo "## Apache server config (all sites; works where .htaccess is ignored)"
  echo; echo "Debian/Ubuntu: /etc/apache2/conf-available/bot-triage.conf, then \`a2enconf bot-triage\`. RHEL family: /etc/httpd/conf.d/bot-triage.conf. cPanel: WHM > Apache Configuration > Include Editor > Pre Main Include. Then \`apachectl configtest && apachectl graceful\`."
  fence apache
  echo "# BEGIN bot-triage $today"
  if [ ${#IPS[@]} -gt 0 ]; then
    hdr=Remote_Addr; [ "$BEHIND_CF" -eq 1 ] && hdr=CF-Connecting-IP
    for x in "${IPS[@]}"; do printf 'SetEnvIf %s "%s" bot_triage_block\n' "$hdr" "$(cidr_regex "$x")"; done
  fi
  [ ${#UAS[@]} -gt 0 ] && printf 'SetEnvIfNoCase User-Agent "(%s)" bot_triage_block\n' "$(ua_alt)"
  if [ ${#IPS[@]} -gt 0 ] || [ ${#UAS[@]} -gt 0 ]; then
    echo '<Location "/">'
    echo '    # AuthMerging And keeps every existing Require rule and adds this one on top'
    echo '    AuthMerging And'
    echo '    <RequireAll>'
    echo '        Require all granted'
    echo '        Require not env bot_triage_block'
    echo '    </RequireAll>'
    echo '</Location>'
  fi
  if [ ${#PATHS[@]} -gt 0 ]; then
    printf '<LocationMatch "^(%s)">\n    Require all denied\n</LocationMatch>\n' "$(path_alt)"
  fi
  echo "# END bot-triage"
  endfence
fi

if want nginx; then
  echo; echo "## nginx"
  if [ ${#IPS[@]} -gt 0 ] || [ ${#UAS[@]} -gt 0 ]; then
    echo; echo "Server-wide file, e.g. /etc/nginx/conf.d/bot-triage.conf (included inside http { }):"
    fence nginx
    echo "# BEGIN bot-triage $today"
    if [ ${#IPS[@]} -gt 0 ]; then
      [ "$BEHIND_CF" -eq 1 ] && echo "# Behind Cloudflare: configure real_ip_header CF-Connecting-IP + set_real_ip_from <Cloudflare ranges> first, or these match Cloudflare, not visitors."
      for x in "${IPS[@]}"; do printf 'deny %s;\n' "$x"; done
    fi
    if [ ${#UAS[@]} -gt 0 ]; then
      # shellcheck disable=SC2016  # nginx variables, printed literally
      printf 'map $http_user_agent $bot_triage_ua {\n    default 0;\n    "~*(%s)" 1;\n}\n' "$(ua_alt)"
    fi
    echo "# END bot-triage"
    endfence
    echo; echo "\`deny\` in http { } applies to every site unless a location has its own allow/deny. It still costs an nginx request; for floods, the firewall is cheaper."
  fi
  if [ ${#UAS[@]} -gt 0 ] || [ ${#PATHS[@]} -gt 0 ]; then
    echo; echo "Inside each affected server { } block:"
    fence nginx
    # shellcheck disable=SC2016  # nginx variable, printed literally
    [ ${#UAS[@]} -gt 0 ] && printf 'if ($bot_triage_ua) { return 403; }\n'
    [ ${#PATHS[@]} -gt 0 ] && printf 'location ~ ^(%s) { return 403; }\n' "$(path_alt)"
    endfence
  fi
  echo; echo "Apply: \`nginx -t && systemctl reload nginx\`."
fi

if want caddy; then
  echo; echo "## Caddy"
  echo; echo "Inside the site block in the Caddyfile, then \`caddy validate --config /etc/caddy/Caddyfile && systemctl reload caddy\`."
  fence caddy
  echo "# BEGIN bot-triage $today"
  if [ ${#IPS[@]} -gt 0 ]; then
    m=remote_ip; [ "$BEHIND_CF" -eq 1 ] && m=client_ip
    printf '@bot_triage_ip %s %s\nrespond @bot_triage_ip 403\n' "$m" "$(IFS=' '; echo "${IPS[*]}")"
  fi
  [ ${#UAS[@]} -gt 0 ] && printf '@bot_triage_ua header_regexp User-Agent (?i)(%s)\nrespond @bot_triage_ua 403\n' "$(ua_alt)"
  if [ ${#PATHS[@]} -gt 0 ]; then
    printf '@bot_triage_path path'; for x in "${PATHS[@]}"; do printf ' %s*' "$x"; done; printf '\nrespond @bot_triage_path 403\n'
  fi
  echo "# END bot-triage"
  endfence
  [ "$BEHIND_CF" -eq 1 ] && { echo; echo "client_ip needs trusted_proxies set to the Cloudflare ranges in the global servers options."; }
fi

if want cloudflare; then
  echo; echo "## Cloudflare WAF custom rule"
  echo; echo "Security > WAF > Custom rules. Block for scanners, Managed Challenge for crawlers that may be human. Never challenge XHR, API, webhook or checkout paths (they cannot solve a challenge): add exclusions like \`and not starts_with(http.request.uri.path, \"/api/\")\`. \`and not cf.client.bot\` spares verified search engines."
  parts=()
  [ ${#IPS[@]} -gt 0 ] && parts+=("(ip.src in {$(IFS=' '; echo "${IPS[*]}")})")
  for x in "${UAS[@]}"; do parts+=("(lower(http.user_agent) contains \"$(printf '%s' "$x" | tr '[:upper:]' '[:lower:]')\")"); done
  for x in "${PATHS[@]}"; do parts+=("(starts_with(http.request.uri.path, \"$x\"))"); done
  expr=""; for p in "${parts[@]}"; do expr+="${expr:+ or }$p"; done
  fence ""
  echo "$expr"
  endfence
fi
