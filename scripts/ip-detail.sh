#!/usr/bin/env bash
# bot-triage: read-only drill-down for one or more client IPs.
# Shows timeline, sites, status codes, top URLs, user agents and referers from the
# access logs, plus reverse DNS (with search-engine verification) and whether the IP
# is already listed in csf or the running firewall. Changes nothing.
set -uo pipefail

HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lib.sh
. "$HERE/lib.sh"

MINUTES=60
TOP=10
MAXLINES=200000
LOGS=()

usage() {
  cat <<'EOF'
Usage: ip-detail.sh [-m MINUTES] [-n TOP] [-L MAXLINES] [-l LOG]... IP [IP...]

  -m MINUTES   time window (default 60)
  -n TOP       rows per table (default 10)
  -L MAXLINES  lines read from the end of each log file (default 200000)
  -l PATH      access log file or directory; repeatable (default: auto-detect)

Read-only. Firewall lookups need root and are skipped otherwise.
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
shift $((OPTIND - 1))
[ $# -gt 0 ] || { usage >&2; exit 2; }
for v in "$MINUTES" "$TOP" "$MAXLINES"; do
  case $v in ''|*[!0-9]*) bt_die "-m, -n and -L take positive whole numbers" ;; esac
done
for ip in "$@"; do
  [[ $ip =~ ^[0-9a-fA-F:.]+$ ]] || bt_die "not an IP address: $ip"
done

WORK=$(mktemp -d "${TMPDIR:-/tmp}/bot-triage.XXXXXX") || bt_die "cannot create temp dir"
trap 'rm -rf "$WORK"' EXIT

bt_minute_keys "$MINUTES" > "$WORK/keys"
mapfile -t FILES < <(bt_find_logs "$MINUTES" "${LOGS[@]}")
[ ${#FILES[@]} -gt 0 ] || bt_die "no access logs written in the last $MINUTES min (use -l PATH)"
printf '%s\n' "$@" > "$WORK/ips"
bt_normalize "$WORK/keys" "$MAXLINES" "${FILES[@]}" \
  | LC_ALL=C awk -F'\t' -v f="$WORK/ips" 'BEGIN { while ((getline i < f) > 0) want[i] = 1 } ($2 in want)' > "$WORK/req.tsv"

# Reverse DNS, then forward-confirm it, for the crawlers people most often whitelist.
rdns() {
  local ip=$1 name fwd
  name=$(getent hosts "$ip" 2>/dev/null | awk '{print $2; exit}')
  [ -n "$name" ] || { echo "no PTR record"; return; }
  case $name in
    *.googlebot.com|*.google.com|*.googleusercontent.com|*.search.msn.com|*.applebot.apple.com|*.yandex.com|*.yandex.ru|*.yandex.net)
      fwd=$(getent ahosts "$name" 2>/dev/null | awk '{print $1}' | sort -u)
      if printf '%s\n' "$fwd" | grep -qxF "$ip"; then
        echo "$name (forward-confirmed: genuine)"
      else
        echo "$name (forward lookup does NOT return $ip: spoofed PTR)"
      fi ;;
    *) echo "$name" ;;
  esac
}

firewall_status() {
  local ip=$1 out=""
  if [ "$(id -u)" -ne 0 ]; then echo "not checked (needs root)"; return; fi
  if [ -r /etc/csf/csf.deny ] && grep -qE "^${ip//./\\.}([[:space:]#/]|$)" /etc/csf/csf.deny; then out+="csf.deny (permanent); "; fi
  if [ -r /etc/csf/csf.allow ] && grep -qE "^${ip//./\\.}([[:space:]#/]|$)" /etc/csf/csf.allow; then out+="csf.allow (whitelisted!); "; fi
  if [ -r /var/lib/csf/csf.tempban ] && grep -qF "|$ip|" /var/lib/csf/csf.tempban; then out+="csf temporary ban; "; fi
  if command -v iptables-save >/dev/null 2>&1 && iptables-save 2>/dev/null | grep -qF -- " $ip"; then out+="present in iptables rules; "; fi
  if command -v nft >/dev/null 2>&1 && nft list ruleset 2>/dev/null | grep -qwF -- "$ip"; then out+="present in nftables ruleset; "; fi
  echo "${out:-not blocked}"
}

table() { # header, then "count<TAB>value" lines on stdin
  echo "| Requests | $1 |"
  echo "|---:|---|"
  sort | uniq -c | sort -rn | head -n "$TOP" | LC_ALL=C awk '{c = $1; $1 = ""; sub(/^ /, ""); gsub(/\|/, "/"); if (length($0) > 120) $0 = substr($0, 1, 117) "..."; printf "| %s | %s |\n", c, $0}'
  echo
}

echo "# IP detail (last $MINUTES min)"
for ip in "$@"; do
  LC_ALL=C awk -F'\t' -v ip="$ip" '$2 == ip' "$WORK/req.tsv" > "$WORK/one.tsv"
  n=$(wc -l < "$WORK/one.tsv")
  echo
  echo "## $ip"
  echo
  echo "- Requests in window: $n"
  echo "- Reverse DNS: $(rdns "$ip")"
  echo "- Firewall: $(firewall_status "$ip")"
  echo
  [ "$n" -gt 0 ] || continue
  echo "### Requests per minute"
  echo
  echo '```'
  cut -f9 "$WORK/one.tsv" | sort | uniq -c | awk '
    { c[NR] = $1; t[NR] = $2; if ($1 > m) m = $1 }
    END { for (i = 1; i <= NR; i++) { w = int(50 * c[i] / m); if (w < 1) w = 1; b = ""; for (j = 0; j < w; j++) b = b "#"; printf "%s %6d %s\n", t[i], c[i], b } }'
  echo '```'
  echo
  cut -f1 "$WORK/one.tsv" | table "Site"
  cut -f3,6 "$WORK/one.tsv" | tr '\t' ' ' | table "Method and status"
  awk -F'\t' '{print $4 ($5 != "" ? "?" $5 : "")}' "$WORK/one.tsv" | table "URL"
  cut -f7 "$WORK/one.tsv" | table "User agent"
  cut -f8 "$WORK/one.tsv" | table "Referer"
done
echo "_Read-only. Nothing was changed._"
