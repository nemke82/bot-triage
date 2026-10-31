#!/usr/bin/env bash
# bot-triage: read-only detection of the server stack, so blocks go to the right layer.
# Detects OS, hosting control panel, web servers on :80/:443 (and which one is in
# front), firewall front-ends and Imunify360. Prints KEY=value lines by default,
# or a short markdown summary with -H. Changes nothing.
set -uo pipefail

HUMAN=0
case ${1:-} in
  -H) HUMAN=1 ;;
  -h|--help) echo "Usage: detect-env.sh [-H]   (-H: human-readable summary)"; exit 0 ;;
  '') ;;
  *) echo "Usage: detect-env.sh [-H]" >&2; exit 2 ;;
esac

have() { command -v "$1" >/dev/null 2>&1; }
active() { have systemctl && systemctl is-active --quiet "$1" 2>/dev/null; }
IS_ROOT=0; [ "$(id -u)" -eq 0 ] && IS_ROOT=1

# --- OS
OS=unknown
if [ -r /etc/os-release ]; then
  OS=$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-${NAME:-unknown}}")
fi

# --- control panel
PANEL=none
if [ -e /usr/local/cpanel/version ]; then PANEL=cpanel
elif [ -e /usr/local/psa/version ]; then PANEL=plesk
elif [ -d /usr/local/directadmin ]; then PANEL=directadmin
elif [ -d /usr/local/CyberCP ]; then PANEL=cyberpanel
elif [ -d /usr/local/hestia ]; then PANEL=hestiacp
elif [ -d /usr/local/vesta ]; then PANEL=vestacp
elif [ -d /opt/cloudpanel ] || [ -e /usr/local/bin/clpctl ]; then PANEL=cloudpanel
elif [ -d /usr/local/ispconfig ]; then PANEL=ispconfig
fi

# --- web servers: who listens on 80/443 (needs root to see process names)
norm() { # process name -> server family
  case $1 in
    nginx*|openresty*) echo nginx ;;
    httpd*|apache2*) echo apache ;;
    litespeed*|lshttpd*|openlitespeed*) echo litespeed ;;
    caddy*) echo caddy ;;
    traefik*) echo traefik ;;
    haproxy*) echo haproxy ;;
    varnishd*) echo varnish ;;
    envoy*) echo envoy ;;
    docker-proxy*) echo docker-proxy ;;
    *) echo "" ;;
  esac
}
FRONT=""; LISTEN443=""; LISTEN80=""
if have ss; then
  while read -r port procs; do
    name=$(printf '%s' "$procs" | grep -oE '"[^"]+"' | head -1 | tr -d '"')
    fam=$(norm "$name")
    [ -n "$fam" ] || continue
    case $port in
      443) case " $LISTEN443 " in *" $fam "*) ;; *) LISTEN443+="${LISTEN443:+ }$fam" ;; esac ;;
      80)  case " $LISTEN80 " in *" $fam "*) ;; *) LISTEN80+="${LISTEN80:+ }$fam" ;; esac ;;
    esac
  done < <(ss -ltnpH 2>/dev/null | awk '{n = split($4, a, ":"); print a[n], $6}' | grep -E '^(80|443) ')
fi
FRONT=${LISTEN443%% *}; [ -n "$FRONT" ] || FRONT=${LISTEN80%% *}
RUNNING=""
for p in nginx openresty httpd apache2 litespeed lshttpd openlitespeed caddy traefik haproxy varnishd; do
  if pgrep -x "$p" >/dev/null 2>&1; then
    fam=$(norm "$p"); case " $RUNNING " in *" $fam "*) ;; *) RUNNING+="${RUNNING:+ }$fam" ;; esac
  fi
done
[ -n "$FRONT" ] || FRONT=${RUNNING%% *}
[ -n "$FRONT" ] || FRONT=unknown
BACKENDS=""
for fam in $RUNNING; do [ "$fam" != "$FRONT" ] && BACKENDS+="${BACKENDS:+ }$fam"; done

# --- firewall front-ends, in the order blocks should go
FIREWALLS=""
addfw() { FIREWALLS+="${FIREWALLS:+ }$1"; }
if have imunify360-agent; then addfw imunify360; fi
if have csf && [ -e /etc/csf/csf.conf ]; then addfw csf; fi
if have ufw; then
  if [ "$IS_ROOT" -eq 1 ]; then ufw status 2>/dev/null | grep -q '^Status: active' && addfw ufw
  elif active ufw; then addfw ufw; fi
fi
if active firewalld; then addfw firewalld; fi
if have nft && [ "$IS_ROOT" -eq 1 ] && [ -n "$(nft list tables 2>/dev/null)" ]; then addfw nftables; fi
if have iptables; then addfw iptables; fi
FIREWALL=${FIREWALLS%% *}; [ -n "$FIREWALL" ] || FIREWALL=none
FAIL2BAN=no; active fail2ban && FAIL2BAN=yes
MODSEC=no
if [ -d /etc/apache2/conf.d/modsec ] || [ -d /etc/modsecurity ] || [ -e /etc/httpd/conf.d/mod_security.conf ] || [ -d /usr/local/lsws/conf/modsec ]; then MODSEC=yes; fi

# --- where web-server rules go
case $FRONT in
  nginx) WEB_TARGET=nginx ;;
  apache)
    if [ "$PANEL" = cpanel ] || [ "$PANEL" = plesk ] || [ "$PANEL" = directadmin ]; then WEB_TARGET=htaccess
    else WEB_TARGET=apache; fi ;;            # distro Apache often has AllowOverride None
  litespeed) WEB_TARGET=htaccess ;;
  caddy) WEB_TARGET=caddy ;;
  *) WEB_TARGET=none ;;
esac

if [ "$HUMAN" -eq 0 ]; then
  printf 'OS=%q\nPANEL=%s\nWEB_FRONT=%s\nWEB_BACKENDS=%q\nLISTEN_443=%q\nLISTEN_80=%q\nFIREWALL=%s\nFIREWALLS=%q\nFAIL2BAN=%s\nMODSECURITY=%s\nWEB_TARGET=%s\nIS_ROOT=%s\n' \
    "$OS" "$PANEL" "$FRONT" "$BACKENDS" "$LISTEN443" "$LISTEN80" "$FIREWALL" "$FIREWALLS" "$FAIL2BAN" "$MODSEC" "$WEB_TARGET" "$IS_ROOT"
  exit 0
fi

echo "## Server stack"
echo
echo "- OS: $OS"
echo "- Control panel: $PANEL"
echo "- Web server in front: $FRONT${BACKENDS:+ (also running: $BACKENDS)}"
echo "- Listening on 443: ${LISTEN443:-?}; on 80: ${LISTEN80:-?}"
echo "- Firewall to use: $FIREWALL${FIREWALLS:+ (available: $FIREWALLS)}"
echo "- fail2ban active: $FAIL2BAN; ModSecurity present: $MODSEC"
echo "- Web-server rules go to: $WEB_TARGET"
[ "$IS_ROOT" -eq 1 ] || echo "- Not root: listening processes and some firewalls could not be checked."
case $FRONT in
  nginx) [ -n "$BACKENDS" ] && echo "- nginx proxies to $BACKENDS: block in nginx (or the firewall); rules in the backend only run after nginx has already accepted the request." ;;
  varnish|haproxy|traefik|envoy|docker-proxy) echo "- $FRONT is in front: the backend logs may show the proxy's address. Block at the firewall or in $FRONT itself." ;;
esac
case $FIREWALL in
  imunify360) echo "- Imunify360 manages the firewall: add blocks through imunify360-agent, not raw iptables (it rewrites rules)." ;;
  csf) echo "- csf manages iptables: use csf commands, raw iptables rules are lost on csf restart." ;;
esac
