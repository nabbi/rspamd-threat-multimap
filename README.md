# rspamd-threat-multimap

Score mail that points at known phishing and malware domains in
[rspamd](https://rspamd.com), from public threat feeds: one map and one
multimap rule per category.

- **What is checked:** every URL host in the message (text and HTML parts,
  `mailto:` addresses, URLs rspamd extracts from PDF and Office
  attachments; not images), the SMTP sender's domain, and the `From:` and
  `Reply-To:` domains.
- **How names match:** like a DNS wildcard. A listed `evil.example` matches
  `www.evil.example` and `a.b.evil.example`. A listed `x.host.example`
  matches only itself and names under it, never `host.example`. The public
  suffix (`com`, `co.uk`, or a hosting suffix such as `blogspot.com`) is
  never looked up.
- **What it fires:** `THREAT_PHISHING`, `THREAT_MALWARE` (and
  `THREAT_FRAUD` for the optional lower-risk feeds), one rule each, reading
  `phishing.map`, `malware.map` and `fraud.map`. The option names each
  matched domain. Each symbol counts once per message.
- **What it needs:** rspamd 3.12+ (`lua.local.d/selectors`); tested with
  4.2.3. Python 3.11+, standard library only.

It is the mail-server counterpart of DNS blocking with
[bind-adblock](https://github.com/nabbi/bind-adblock). Blocking these
names in the mail server's resolver (RPZ) makes Postfix reject mail with a
permanent error for any sender, client or HELO name a feed lists by
mistake, and holds the lists in the resolver. Scoring them in rspamd
weighs them against everything else rspamd knows about the message.

## Feeds

Narrowed to high-risk threats: names used for phishing and malware
delivery. Ad, tracker and general "malware" host lists are left out: on
mail, they list the marketing and bulk senders people subscribe to
(Constant Contact, HubSpot, ExactTarget, Amazon SES regions).

| Feed | Category | Names* | Source |
|---|---|---:|---|
| `phishing-filter` | phishing | 22,386 | [malware-filter](https://gitlab.com/malware-filter/phishing-filter): OpenPhish, PhishTank, IPThreat; every 12h |
| `cert-pl` | phishing | 126,628 | [CERT Polska](https://cert.pl/en/warning-list/) warning list |
| `urlhaus-online` | malware | 539 | [malware-filter](https://gitlab.com/malware-filter/urlhaus-filter): URLhaus hosts with malware online now; every 12h |
| `infoblox` | malware, phishing | 26,734 | [Infoblox threat intelligence](https://github.com/infobloxopen/threat-intelligence): malicious, clickfix, voltastealer, phishing (not "suspicious") |
| `blp-ransomware` | malware | 1,904 | [The Block List Project](https://github.com/blocklistproject/Lists) ransomware |
| `talos` | malware | 2,649 | [Cisco Talos IOCs](https://github.com/Cisco-Talos/IOCs): the hosts in the IOC lists of its blog posts, 2022 on |
| `hagezi-fake` (off) | fraud | ~17,500 | [HaGeZi](https://github.com/hagezi/dns-blocklists) fake shops and scams |
| `blp-scam` (off) | fraud | ~8,500 | The Block List Project scam |

\* 2026-11-03. Merged: 179,218 names. Feeds publish under their own
terms; check them for your use. This project downloads them; it does not
redistribute them.

The Talos feed is the repository's GitHub archive (one 2.4 MB tar.gz,
fetched again only when a report is added). Each blog post's `.txt` file
mixes hashes, IP addresses, URLs, domains and email addresses, usually
defanged (`evil[.]com`, `hxxp[://]`). The parser undoes that and keeps the
host names, bare or from URLs, and drops the rest: hashes, IPs and email
addresses, and file names (`auto.exe`) because their suffix is not a
top-level domain. A host named by several posts is listed once. Talos
also gives URLs of payloads on shared platforms (`bit.ly`, `discord.com`,
`drive.google.com`…); `protect` in the example config keeps those hosts
out. The STIX `.json` files beside the lists name fewer hosts and are not
read.

rspamd's own `phishing` module already checks full URLs against OpenPhish
and PhishTank; this adds their domains with wildcard matching, the other
feeds, and the sender domains.

## Install

```sh
# The updater
install -m 0755 rspamd_threat_multimap.py /usr/local/bin/rspamd-threat-multimap
install -d /etc/rspamd-threat-multimap
install -m 0644 config.example.toml /etc/rspamd-threat-multimap/config.toml
install -m 0644 allowlist.example.txt /etc/rspamd-threat-multimap/allowlist.txt
install -d -o rspamd -g rspamd /var/lib/rspamd/threat-multimap

# The first map, as the user that will refresh it
su -s /bin/sh rspamd -c '/usr/local/bin/rspamd-threat-multimap update'

# rspamd: the selector, the rule, the scores
install -D -m 0644 rspamd/lua.local.d/selectors/threat_domains.lua \
    /etc/rspamd/lua.local.d/selectors/threat_domains.lua
cat rspamd/local.d/multimap.conf >> /etc/rspamd/local.d/multimap.conf
cat rspamd/local.d/groups.conf   >> /etc/rspamd/local.d/groups.conf
rspamadm configtest && rc-service rspamd reload   # or systemctl reload rspamd

# Refresh every 4 hours
install -m 0644 cron/rspamd-threat-multimap /etc/cron.d/rspamd-threat-multimap
```

rspamd re-reads a map when its file changes. The updater replaces each map
atomically, and only when its list of names changed.

Each map holds one domain per line, with no value. rspamd (4.2.3 and
earlier) reads file maps in 1 MiB chunks. When a chunk ends after a line's
key, its parser loses the key and drops the line (it logs `empty or
invalid key found on line 0`). That costs a `key value` map over 1 MiB up
to one line per chunk. A line that is only a key is read again whole, so
nothing is lost. 0.1.0 wrote one `domain SYMBOL` map and lost 3 of its
176,819 names this way.

Put your own domains, and the ones you exchange mail with, in
`allowlist.txt`: a listed name and everything under it are never in the
map. `protect` in `config.toml` lists large shared platforms
(google.com, sharepoint.com, sendgrid.net…) that are never listed
themselves; their subdomains still can be (`phish.sharepoint.com`).

## Scores

In `rspamd/local.d/multimap.conf`:

- `THREAT_MALWARE` 8;
- `THREAT_PHISHING` 7, as rspamd's `PHISHED_OPENPHISH`;
- `THREAT_FRAUD` 4.

Each is `one_shot`, and `rspamd/local.d/groups.conf` caps the group at 12.
Tune them to your action thresholds. To score URL and sender hits apart,
copy a rule with `selector = "threat_domains('urls')"` or
`"threat_domains('senders')"`; each rule holds its own copy of its map.

## Upgrading from 0.1.0

`output` (one `threat.map`) is now `output_dir` (`<category>.map`), and
the single `THREAT_DOMAIN` rule is now a rule per category, scored in the
rule rather than in `groups.conf`. Replace both rspamd files, set
`output_dir`, run `update`, then delete `threat.map`.

## Memory

Measured with rspamd 4.2.3 on x86_64, 176,819 names in one map: **about
15 MB per rspamd process**: the main process and each worker hold their
own copy. A map per category holds the same names.
With a proxy (self-scan) and a controller, that is about 45 MB per host. The
same names as an RPZ zone in BIND take about 170 MB, because the zone also
needs a `*.name` record per name for wildcard matching.

## Operations

```sh
# What would match, from the cached feeds (no downloads); exit 2 on a hit
rspamd-threat-multimap lookup www.example.com
awk '{print $1}' names.txt | rspamd-threat-multimap lookup -

# Rebuild from the cache, e.g. after editing the allowlist
rspamd-threat-multimap update --offline
```

Checking a few months of your mail's client, HELO, sender and recipient
names with `lookup` before enabling the scores shows what a feed would
have hit.

Safeguards in `update`:

- **Failed downloads.** A feed that fails uses its last good copy for up
  to `max_cache_age_hours` (72), then drops out. The run exits 1, so cron
  mails you.
- **Feed outages.** If all the maps together would hold less than
  `min_ratio` (half) of what they hold now, none is written; `--force`
  overrides.
- **Conditional downloads.** Requests send `If-None-Match` and
  `If-Modified-Since`.
- **Invalid names are dropped.** IP addresses, single labels, and names
  whose last label is not a top-level domain (`.local`, `.test`, `.exe`;
  IANA's list is built in, `.onion` added, `.arpa` removed) never reach
  the map.
- **One run at a time.** A lock file stops runs from overlapping.

## Limits

- **URL count.** rspamd's `max_lua_urls` caps how many URLs a message
  hands to Lua.
- **Redirectors.** URLs that `url_redirector` resolves are seen only if
  they are known before the multimap rule runs.
- **Feed accuracy.** CERT Polska's list is long and aimed at Polish
  targets. A feed that lists a legitimate site affects scores until it is
  fixed upstream or allowlisted here.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

## License

MIT, see [LICENSE](LICENSE). The hosts-file parsing follows
[bind-adblock](https://github.com/Trellmor/bind-adblock) (MIT, Copyright (c)
2018 Daniel Triendl).
