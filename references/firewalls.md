# Firewalls

Use the firewall manager the server already runs. Raw iptables rules added under a
manager (csf, Imunify360, firewalld, ufw) are usually wiped on its next restart.
`scripts/detect-env.sh` reports which one is active.

A firewall block is the cheapest block (the packet never reaches the web server),
but it only works on the real client IP. **Behind Cloudflare or another proxy, the
origin sees the proxy's address: do not firewall-block those.**

All generated rules are IPv4. For IPv6 sources, adapt by hand (`ip6tables`,
`ip6 saddr` in nftables, `family="ipv6"` in firewalld).

## csf (ConfigServer Firewall, common on cPanel/DirectAdmin)

```sh
csf -td 203.0.113.7 86400 "scanner"           # temporary, auto-expires
csf -d 198.51.100.0/24 "do not delete - scanner subnet 2026-01-31"   # permanent
csf -tr 203.0.113.7                            # remove temporary
csf -dr 198.51.100.0/24                        # remove permanent
csf -g 203.0.113.7                             # search all lists for an IP
```

- **DENY_IP_LIMIT** (csf.conf) caps csf.deny. When full, lfd evicts the oldest
  entries to make room for its own automatic blocks, permanent ones included.
  Entries whose comment contains `do not delete` are kept. Raise the limit
  carefully (each entry is an iptables rule unless LF_IPSET is enabled).
- **csf.allow and csf.ignore win.** A whitelisted IP cannot be blocked; check
  there if a ban "does not work".
- lfd blocks automatically too (login failures, port scans). `csf -t` lists the
  current temporary bans with reasons.

## Imunify360

Imunify360 owns the firewall rules when installed. Add blocks through its agent:

```sh
imunify360-agent ip-list local add --purpose drop 203.0.113.7 --comment "scanner"
imunify360-agent ip-list local delete --purpose drop 203.0.113.7
```

Older versions use `imunify360-agent blacklist ip add 203.0.113.7`. Check
`--help` on the server. Imunify360 also has its own WAF and may already be
greylisting the attacker (captcha); check its incident list before adding rules.

## ufw (Ubuntu, Debian)

```sh
ufw insert 1 deny from 203.0.113.7 comment "scanner"
ufw status numbered
ufw delete deny from 203.0.113.7
```

- `insert 1` matters: ufw evaluates rules in order, and an earlier `allow 80,443`
  would otherwise accept the traffic first.
- No expiring rules. Keep a note and remove them later.
- **Docker-published ports bypass ufw**: Docker inserts its own iptables rules
  before ufw's. Block container traffic in the `DOCKER-USER` chain:
  `iptables -I DOCKER-USER -s 203.0.113.7 -j DROP`.

## firewalld (RHEL, Alma, Rocky, Fedora)

```sh
firewall-cmd --add-rich-rule='rule family="ipv4" source address="203.0.113.7" drop' --timeout=86400
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="198.51.100.0/24" drop'
firewall-cmd --reload
firewall-cmd --list-rich-rules
```

Runtime rules with `--timeout` expire by themselves and do not survive a reload.
For many addresses, an ipset in the `drop` zone scales better:
`firewall-cmd --permanent --zone=drop --add-source=198.51.100.0/24`.

## nftables

gen-blocks.sh creates a separate table so it never edits your existing ruleset:

```sh
nft add table inet bot_triage
nft add set inet bot_triage deny4 '{ type ipv4_addr; flags interval, timeout; }'
nft add chain inet bot_triage input '{ type filter hook input priority -10; policy accept; }'
nft add rule inet bot_triage input ip saddr @deny4 drop
nft add element inet bot_triage deny4 '{ 203.0.113.7 timeout 86400s }'
```

Remove everything with `nft delete table inet bot_triage`. Add the table to
`/etc/nftables.conf` if it must survive a reboot.

## iptables (no manager)

Prefer ipset: one rule, any number of addresses, per-entry expiry.

```sh
ipset create bot-triage hash:net timeout 86400 -exist
iptables -I INPUT -m set --match-set bot-triage src -j DROP
ipset add bot-triage 203.0.113.7 timeout 86400 -exist
```

Plain rules (`iptables -I INPUT -s IP -j DROP`) work but do not expire and are
lost on reboot unless saved (`iptables-save`, netfilter-persistent, iptables-services).

## fail2ban: automate what keeps coming back

When the same pattern returns every few days, let fail2ban ban it automatically.
Example jail for WordPress xmlrpc/login floods on nginx (adapt `logpath`):

```ini
# /etc/fail2ban/filter.d/wp-flood.conf
[Definition]
failregex = ^<HOST> .* "POST /(xmlrpc|wp-login)\.php

# /etc/fail2ban/jail.d/wp-flood.conf
[wp-flood]
enabled  = true
port     = http,https
filter   = wp-flood
logpath  = /var/log/nginx/access.log
maxretry = 20
findtime = 120
bantime  = 86400
```

`fail2ban-client set wp-flood banip 203.0.113.7` bans by hand through the jail.
fail2ban uses whichever backend is configured (iptables, nftables, firewalld, ufw).
