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
| `unit42` | malware | 7,361 | [Unit 42 timely threat intel](https://github.com/PaloAltoNetworks/Unit42-timely-threat-intel): the defanged hosts in Palo Alto Networks' reports, 2020 on |
| `eset` | malware | 1,496 | [ESET Research IOCs](https://github.com/eset/malware-ioc): the defanged hosts in the AsciiDoc reports behind its WeLiveSecurity posts, 2016 on |
| `bitdefender` | malware | 5,003 | [Bitdefender Labs IOCs](https://github.com/bitdefender/malware-ioc): the domain and URL rows of its CSV tables (not those marked legitimate), and older campaign domain lists |
| `sophos` | malware | 6,600 | [Sophos X-Ops IOCs](https://github.com/sophoslabs/IoCs): the domain, URL and domain:port rows of its CSV tables, 2020 on |
| `zscaler` | malware | 12,564 | [Zscaler ThreatLabz IOCs](https://github.com/ThreatLabz/iocs): the defanged hosts in its lists; 10,600 are the typosquatting domains of one brand-impersonation report |
| `netskope` | malware | 2,143 | [Netskope Threat Labs IOCs](https://github.com/netskopeoss/NetskopeThreatLabsIOCs): the defanged hosts in its Markdown reports |
| `hagezi-fake` (off) | fraud | ~17,500 | [HaGeZi](https://github.com/hagezi/dns-blocklists) fake shops and scams |
| `blp-scam` (off) | fraud | ~8,500 | The Block List Project scam |

\* 2026-11-03. Merged: 214,093 names. Feeds publish under their own
terms; check them for your use. This project downloads them; it does not
redistribute them.

The vendor feeds (Talos, Unit 42, ESET, Bitdefender, Sophos, Zscaler,
Netskope) are each repository's GitHub archive: one tar.gz, 0.3 to 9 MB,
fetched again only when a report is added. A report mixes hashes, IP
addresses, URLs, domains and email addresses, usually defanged
(`evil[.]com`, `hxxps[:]//`), with prose, headings and tables. The
parser undoes the defanging and keeps the host names, bare or from URLs
(`name[.](xyz|com)` is both names), and drops the rest: hashes, IPs and
email addresses, and file names (`auto.exe`) because their suffix is not
a top-level domain. A host named by several reports is listed once. A
heading names no threat. A line, or a whole section, that the report
marks as legitimate or not malicious (the sites an infected host calls to
check its connectivity, the brand a page spoofs, a service the malware
abuses) is skipped.

Talos (`.txt` lists only; the STIX `.json` files beside them name fewer
hosts) often lists plain URLs, so every line counts. Unit 42 reports
(`.txt`, a few `.md`, one without an extension) defang every indicator
and leave the rest plain: the LinkedIn and X posts under REFERENCES, the
vendor blogs in NOTES, file names (`invoice.zip`: `.zip` is a top-level
domain) and the mail servers in quoted `Received:` headers. So in the
`unit42` format only a defanged line names a threat, which drops those
and keeps 7,361 of the 7,853 names a plain read would take.

ESET (`.adoc`: bullet lists, tables and URL blocks, beside hash lists,
MISP JSON and YARA), Zscaler (`.txt` lists per campaign, beside DNS,
WHOIS and password dumps) and Netskope (a Markdown README per campaign,
beside decrypted strings and scripts) are read the same way: only a
defanged line counts, so their blog and MITRE links, hosting providers
and file names are not. That costs ESET about 1,300 plain names, mostly
old DGA and dynamic-DNS hosts, and Zscaler about 1,450, mostly a DGA
list and `.onion` names. Sophos and Bitdefender publish CSV tables
instead (an indicator type, the value, a note): only the `domain`,
`url` and `domain_port` rows count, hashes, IPs, file names, commands
and wallet addresses do not, and a Bitdefender row whose `nature` is
`legitimate` (an abused benign host) is skipped. Zscaler is mostly the
10,600 typosquatting domains of one brand-impersonation report
(`phishing/typosquatting_brand_impersonation_domains.txt`): registered
look-alikes of brands, not all of them seen in attacks. They score as
malware here because a feed has one category; drop the feed, or copy it
with `category = "phishing"`, if that is too strong.

Both name payloads, phishing pages and C2 channels on services everyone
shares (`drive.google.com`, `github.com`, `discord.com`, `t.me`, `bit.ly`,
`mega.nz`, a tenant's `workers.dev`): the path is the indicator, the host
is not. The updater never lists those hosts: see `protect` below.

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
map.

Shared hosts are never listed exactly; their subdomains still can be
(`phish.sharepoint.com`, a tenant's `name.workers.dev`). The updater has
a built-in list (`SHARED_HOSTS`, about 270 names): file, paste and
link-shortening services and image hosts and archives (`drive.google.com`,
`pastebin.com`, `bit.ly`, `imgur.com`, `web.archive.org`),
code and package registries (`github.com`, `rubygems.org`), cloud storage
and web platforms (`s3.amazonaws.com`, `workers.dev`, `vercel.app`),
app stores and forums (`play.google.com`, `apps.apple.com`,
`www.reddit.com`), messaging (`discord.com`, `t.me`), the mail and
marketing senders a feed lists by mistake now and then (`gmail.com`,
`sendgrid.net`), the IP-check sites malware calls (`ipinfo.io`), and the
vendor update hosts an adversary-in-the-middle report lists as spoofed
(`updates.microsoft.com`, `get.adobe.com`). Also in it: the vendors and
projects whose own sites a report names as a tool's source
(`torproject.org`, `rdpguard.com`), and the news and government sites a
report names as compromised for a watering-hole attack
(`phnompenhpost.com`, `mfaic.gov.kh`): the site's own mail and links are
not the threat. Checked against the Tranco top million (2026-11-03). IOC lists name them as the
URL of a payload, a malicious app or a C2 channel; the host says nothing
about a message, and most mail links to one. `protect` in `config.toml` adds your own
(the example names `zoom.us`, `box.com`, `webex.com`).

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
