#!/usr/bin/env bash
# Shared helpers for the bot-triage scripts. Sourced, never executed directly.
# Everything here is read-only: it finds and parses logs, it never changes the system.

bt_die() { printf 'bot-triage: %s\n' "$*" >&2; exit 1; }
bt_warn() { printf 'bot-triage: warning: %s\n' "$*" >&2; }

# Where access logs usually live, most specific first.
BT_LOG_ROOTS=(
  /usr/local/apache/domlogs   # cPanel/WHM (Apache or LiteSpeed)
  /var/log/apache2            # Debian/Ubuntu Apache
  /var/log/httpd              # RHEL/Alma/Rocky Apache
  /var/log/nginx
  /usr/local/lsws/logs        # LiteSpeed standalone / OpenLiteSpeed
  /var/www/vhosts/system      # Plesk: <domain>/logs/access_log
)

# bt_find_logs MINUTES [PATH...]
# Prints access-log files (one per line) written to within the window.
# Files reachable twice (cPanel keeps domlogs/<file> and domlogs/<user>/<file>)
# are printed once, deduplicated by device:inode, so hits are not double-counted.
bt_find_logs() {
  local minutes=$1; shift
  local roots=("$@") r
  [ ${#roots[@]} -eq 0 ] && roots=("${BT_LOG_ROOTS[@]}")
  for r in "${roots[@]}"; do
    if [ "$r" = - ]; then
      printf 'stdin\t-\n'; continue
    elif [ -f "$r" ]; then
      printf '%s\n' "$r"
    elif [ -d "$r" ]; then
      find "$r" -type f -mmin "-$((minutes + 2))" \
        \( -name '*log' -o -name '*.log' -o -name 'access*' \) \
        ! -name '*.gz' ! -name '*.bz2' ! -name '*.xz' ! -name '*.zst' \
        ! -name '*bytes_log' ! -name '*error*' ! -name '*.bkup' ! -name '*ftp*' \
        ! -name '*.offset' 2>/dev/null
    fi
  done | while IFS= read -r f; do
    case $f in
      stdin*) printf '%s\n' "$f" ;;
      *) printf '%s\t%s\n' "$(stat -Lc '%d:%i' -- "$f" 2>/dev/null)" "$f" ;;
    esac
  done | sort -u -t "$(printf '\t')" -k1,1 | cut -f2-
}

# bt_site_name FILE -> a short site label derived from the log path.
bt_site_name() {
  local f=$1 b
  case $f in
    -) printf 'stdin\n'; return ;;
    */vhosts/system/*/logs/*)
      b=${f#*/vhosts/system/}; printf '%s\n' "${b%%/*}"; return ;;
  esac
  b=${f##*/}
  b=${b%-ssl_log}; b=${b%_ssl_log}; b=${b%_log}; b=${b%.log}
  b=${b%-access}; b=${b%.access}; b=${b%_access}
  case $b in
    access|access_ssl|ssl_access|other_vhosts_access|'') b=${f%/*}; b=${b##*/} ;;
  esac
  printf '%s\n' "$b"
}

# bt_minute_keys MINUTES -> one "dd/Mon/YYYY:HH:MM" per line for the last N minutes.
# Matching exact minute keys avoids the classic bug of comparing log timestamps
# as strings, which lets lines from other months leak into the window.
# BOT_TRIAGE_NOW (any date(1) string) pins "now", for tests or past incidents.
bt_minute_keys() {
  local minutes=$1 base i
  base=$(date -d "${BOT_TRIAGE_NOW:-now}" +%s) || bt_die "bad BOT_TRIAGE_NOW value"
  for ((i = 0; i < minutes; i++)); do
    LC_ALL=C date -d "@$((base - i * 60))" '+%d/%b/%Y:%H:%M'
  done
}

# bt_normalize KEYFILE MAXLINES FILE...
# Reads access logs in the NCSA "combined" format used by default by Apache,
# nginx, LiteSpeed, Plesk and cPanel, plus Apache "vhost_combined"
# (host:port before the client IP, as in Debian's other_vhosts_access.log).
# A FILE of "-" reads stdin (e.g. `docker logs nginx 2>&1 | triage.sh -l -`).
# Prints tab-separated records:
#   site  ip  method  path  query  status  ua  referer  HH:MM
# Only lines whose timestamp minute is listed in KEYFILE are kept.
bt_normalize() {
  local keys=$1 maxlines=$2 f site; shift 2
  for f in "$@"; do
    site=$(bt_site_name "$f")
    tail -n "$maxlines" -- "$f" 2>/dev/null | LC_ALL=C awk -F'"' -v site="$site" -v keys="$keys" '
      BEGIN { while ((getline k < keys) > 0) want[k] = 1 }
      {
        p = index($1, "["); if (!p) next
        ts = substr($1, p + 1, 17)
        if (!(ts in want)) next
        split($1, a, " "); ip = a[1]; st = site
        if (ip ~ /:[0-9]+$/ && a[2] ~ /^[0-9a-fA-F.:]+$/ && a[2] != "-") { st = ip; sub(/:[0-9]+$/, "", st); ip = a[2] }
        n = split($2, r, " "); method = (n >= 1 ? r[1] : "-"); url = (n >= 2 ? r[2] : "-")
        q = index(url, "?"); path = url; query = ""
        if (q) { path = substr(url, 1, q - 1); query = substr(url, q + 1) }
        split($3, s, " "); status = s[1]
        ref = $4; ua = $6
        if (ua == "") ua = "-"
        gsub(/\t/, " ", path); gsub(/\t/, " ", query); gsub(/\t/, " ", ua); gsub(/\t/, " ", ref)
        printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", st, ip, method, path, query, status, ua, ref, substr(ts, 13, 5)
      }'
  done
}

# Cloudflare IPv4 ranges (https://www.cloudflare.com/ips-v4). If the origin logs
# show these as client IPs, firewall blocks on the origin would block Cloudflare.
# shellcheck disable=SC2034  # used by the scripts that source this file
BT_CF_RANGES="173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 104.24.0.0/14 172.64.0.0/13 131.0.72.0/22"
