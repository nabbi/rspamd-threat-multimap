#!/usr/bin/env python3
"""rspamd-threat-multimap: build an rspamd multimap of high-risk threat domains.

Downloads public threat feeds (phishing and malware domains, the IOC lists
of Cisco Talos, Palo Alto Unit 42, ESET, Bitdefender, Sophos, Zscaler and
Netskope), validates and merges them into one map per category
(``<category>.map``, a domain per line), each read by one rspamd multimap
rule (rspamd/local.d/multimap.conf).
The selector in rspamd/lua.local.d/selectors/threat_domains.lua feeds those
rules every URL host in the message, with its parent domains, and the
sender domains.

Domain-only lines, not ``domain SYMBOL``: rspamd (4.2.3 and earlier) reads a
file map in 1 MiB chunks and drops a ``key value`` line when a chunk ends
after its key; a key alone is read again whole.

Python 3.11+, standard library only.

The hosts-file parsing follows nabbi/bind-adblock (Trellmor/bind-adblock,
MIT, Copyright (c) 2018 Daniel Triendl).
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import email.utils
import fcntl
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

VERSION = "0.5.4"
DEFAULT_CONFIG = "/etc/rspamd-threat-multimap/config.toml"
USER_AGENT = f"rspamd-threat-multimap/{VERSION} (+https://github.com/nabbi/rspamd-threat-multimap)"
MAX_BODY = 64 * 1024 * 1024
FORMATS = ("domain", "hosts", "infoblox", "talos", "unit42", "eset", "bitdefender", "sophos", "zscaler", "netskope")
MAX_MEMBER = 8 * 1024 * 1024  # one file inside an IOC archive

# Top-level domains: IANA's list, version 2026110300
# (https://data.iana.org/TLD/tlds-alpha-by-domain.txt, refresh now and then),
# plus 'onion' (RFC 7686), minus 'arpa' (in-addr/ip6, never a host). A name
# under any other suffix ('auto.exe', 'go.oo', 'host.local') is not a hostname.
_IANA_TLDS = """
aaa aarp abb abbott abbvie abc able abogado abudhabi ac academy accenture accountant accountants aco actor ad ads
adult ae aeg aero aetna af afl africa ag agakhan agency ai aig airbus airforce airtel akdn al alibaba alipay allfinanz
allstate ally alsace alstom am amazon americanexpress americanfamily amex amfam amica amsterdam analytics android
anquan anz ao aol apartments app apple aq aquarelle ar arab aramco archi army arpa art arte as asda asia associates at
athleta attorney au auction audi audible audio auspost author auto autos aw aws ax axa az azure ba baby baidu banamex
band bank bar barcelona barclaycard barclays barefoot bargains baseball basketball bauhaus bayern bb bbc bbt bbva bcg
bcn bd be beats beauty beer berlin best bestbuy bet bf bg bh bharti bi bible bid bike bing bingo bio biz bj black
blackfriday blockbuster blog bloomberg blue bm bms bmw bn bnpparibas bo boats boehringer bofa bom bond boo book
booking bosch bostik boston bot boutique box br bradesco bridgestone broadway broker brother brussels bs bt build
builders business buy buzz bv bw by bz bzh ca cab cafe cal call calvinklein cam camera camp canon capetown capital
capitalone car caravan cards care career careers cars casa case cash casino cat catering catholic cba cbn cbre cc cd
center ceo cern cf cfa cfd cg ch chanel channel charity chase chat cheap chintai christmas chrome church ci cipriani
circle cisco citadel citi citic city ck cl claims cleaning click clinic clinique clothing cloud club clubmed cm cn co
coach codes coffee college cologne com commbank community company compare computer comsec condos construction
consulting contact contractors cooking cool coop corsica country coupon coupons courses cpa cr credit creditcard
creditunion cricket crown crs cruise cruises cu cuisinella cv cw cx cy cymru cyou cz dad dance data date dating datsun
day dclk dds de deal dealer deals degree delivery dell deloitte delta democrat dental dentist desi design dev dhl
diamonds diet digital direct directory discount discover dish diy dj dk dm dnp do docs doctor dog domains dot download
drive dtv dubai dupont durban dvag dvr dz earth eat ec eco edeka edu education ee eg email emerck energy engineer
engineering enterprises epson equipment er ericsson erni es esq estate et eu eurovision eus events exchange expert
exposed express extraspace fage fail fairwinds faith family fan fans farm farmers fashion fast fedex feedback ferrari
ferrero fi fidelity fido film final finance financial fire firestone firmdale fish fishing fit fitness fj fk flickr
flights flir florist flowers fly fm fo foo food football ford forex forsale forum foundation fox fr free fresenius frl
frogans frontier ftr fujitsu fun fund furniture futbol fyi ga gal gallery gallo gallup game games gap garden gay gb
gbiz gd gdn ge gea gent genting george gf gg ggee gh gi gift gifts gives giving gl glass gle global globo gm gmail
gmbh gmo gmx gn godaddy gold goldpoint golf goodyear goog google gop got gov gp gq gr grainger graphics gratis green
gripe grocery group gs gt gu gucci guge guide guitars guru gw gy hair hamburg hangout haus hbo hdfc hdfcbank health
healthcare help here hermes hiphop hisamitsu hitachi hiv hk hkt hm hn hockey holdings holiday homedepot homegoods
homes homesense honda horse hospital host hosting hot hotels hotmail house how hr hsbc ht hu hughes hyatt hyundai ibm
icbc ice icu id ie ieee ifm ikano il im imamat imdb immo immobilien in inc industries infiniti info ing ink institute
insurance insure int international intuit investments io ipiranga iq ir irish is ismaili ist istanbul it itau itv
jaguar java jcb je jeep jetzt jewelry jio jll jm jmp jnj jo jobs joburg jot joy jp jpmorgan jprs juegos kaufen kddi ke
kerryhotels kerryproperties kfh kg kh ki kia kids kim kindle kitchen kiwi km kn koeln komatsu kosher kp kpmg kpn kr
krd kred kuokgroup kw ky kyoto kz la lacaixa lamborghini lamer land landrover lanxess lasalle lat latino latrobe law
lawyer lb lc lds lease leclerc lefrak legal lego lexus lgbt li lidl life lifeinsurance lifestyle lighting like lilly
limited limo lincoln link live living lk llc llp loan loans locker locus lol london lotte lotto love lpl lplfinancial
lr ls lt ltd ltda lu lundbeck luxe luxury lv ly ma madrid maif maison makeup man management mango map market marketing
markets marriott marshalls mattel mba mc mckinsey md me med media meet melbourne meme memorial men menu merck merckmsd
mg mh miami microsoft mil mini mint mit mitsubishi mk ml mlb mls mm mma mn mo mobi mobile moda moe moi mom monash
money monster mormon mortgage moscow moto motorcycles mov movie mp mq mr ms msd mt mtn mtr mu museum music mv mw mx my
mz na nab nagoya name navy nba nc ne nec net netbank netflix network neustar new news next nextdirect nexus nf nfl ng
ngo nhk ni nico nike nikon ninja nissan nissay nl no nokia norton now nowruz nowtv np nr nra nrw ntt nu nyc nz obi
observer office okinawa olayan olayangroup ollo om omega one ong onl online ooo open oracle orange org organic origins
osaka otsuka ott ovh pa page panasonic paris pars partners parts party pay pccw pe pet pf pfizer pg ph pharmacy phd
philips phone photo photography photos physio pics pictet pictures pid pin ping pink pioneer pizza pk pl place play
playstation plumbing plus pm pn pnc pohl poker politie porn post pr praxi press prime pro prod productions prof
progressive promo properties property protection pru prudential ps pt pub pw pwc py qa qpon quebec quest racing radio
re read realestate realtor realty recipes red redumbrella rehab reise reisen reit reliance ren rent rentals repair
report republican rest restaurant review reviews rexroth rich richardli ricoh ril rio rip ro rocks rodeo rogers room
rs rsvp ru rugby ruhr run rw rwe ryukyu sa saarland safe safety sakura sale salon samsclub samsung sandvik
sandvikcoromant sanofi sap sarl sas save saxo sb sbi sbs sc scb schaeffler schmidt scholarships school schule schwarz
science scot sd se search seat secure security seek select sener services seven sew sex sexy sfr sg sh shangrila sharp
shell shia shiksha shoes shop shopping shouji show si silk sina singles site sj sk ski skin sky skype sl sling sm
smart smile sn sncf so soccer social softbank software sohu solar solutions song sony soy spa space sport spot sr srl
ss st stada staples star statebank statefarm stc stcgroup stockholm storage store stream studio study style su sucks
supplies supply support surf surgery suzuki sv swatch swiss sx sy sydney systems sz tab taipei talk taobao target
tatamotors tatar tattoo tax taxi tc tci td tdk team tech technology tel temasek tennis teva tf tg th thd theater
theatre tiaa tickets tienda tips tires tirol tj tjmaxx tjx tk tkmaxx tl tm tmall tn to today tokyo tools top toray
toshiba total tours town toyota toys tr trade trading training travel travelers travelersinsurance trust trv tt tube
tui tunes tushu tv tvs tw tz ua ubank ubs ug uk unicom university uno uol ups us uy uz va vacations vana vanguard vc
ve vegas ventures verisign versicherung vet vg vi viajes video vig viking villas vin vip virgin visa vision viva vivo
vlaanderen vn vodka volvo vote voting voto voyage vu wales walmart walter wang wanggou watch watches weather
weatherchannel web webcam weber website wed wedding weibo weir wf whoswho wien wiki williamhill win windows wine
winners wme woodside work works world wow ws wtc wtf xbox xerox xihuan xin xn--11b4c3d xn--1ck2e1b xn--1qqw23a
xn--2scrj9c xn--30rr7y xn--3bst00m xn--3ds443g xn--3e0b707e xn--3hcrj9c xn--3pxu8k xn--42c2d9a xn--45br5cyl
xn--45brj9c xn--45q11c xn--4dbrk0ce xn--4gbrim xn--54b7fta0cc xn--55qw42g xn--55qx5d xn--5su34j936bgsg xn--5tzm5g
xn--6frz82g xn--6qq986b3xl xn--80adxhks xn--80ao21a xn--80aqecdr1a xn--80asehdb xn--80aswg xn--8y0a063a xn--90a3ac
xn--90ae xn--90ais xn--9dbq2a xn--9et52u xn--9krt00a xn--b4w605ferd xn--bck1b9a5dre4c xn--c1avg xn--c2br7g xn--cck2b3b
xn--cckwcxetd xn--cg4bki xn--clchc0ea0b2g2a9gcd xn--czr694b xn--czrs0t xn--czru2d xn--d1acj3b xn--d1alf xn--e1a4c
xn--eckvdtc9d xn--efvy88h xn--fct429k xn--fhbei xn--fiq228c5hs xn--fiq64b xn--fiqs8s xn--fiqz9s xn--fjq720a
xn--flw351e xn--fpcrj9c3d xn--fzc2c9e2c xn--fzys8d69uvgm xn--g2xx48c xn--gckr3f0f xn--gecrj9c xn--gk3at1e
xn--h2breg3eve xn--h2brj9c xn--h2brj9c8c xn--hxt814e xn--i1b6b1a6a2e xn--imr513n xn--io0a7i xn--j1aef xn--j1amh
xn--j6w193g xn--jlq480n2rg xn--jvr189m xn--kcrx77d1x4a xn--kprw13d xn--kpry57d xn--kput3i xn--l1acc xn--lgbbat1ad8j
xn--mgb9awbf xn--mgba3a3ejt xn--mgba3a4f16a xn--mgba7c0bbn0a xn--mgbaam7a8h xn--mgbab2bd xn--mgbah1a3hjkrd
xn--mgbai9azgqp6j xn--mgbayh7gpa xn--mgbbh1a xn--mgbbh1a71e xn--mgbc0a9azcg xn--mgbca7dzdo xn--mgbcpq6gpa1a
xn--mgberp4a5d4ar xn--mgbgu82a xn--mgbi4ecexp xn--mgbpl2fh xn--mgbt3dhd xn--mgbtx2b xn--mgbx4cd0ab xn--mix891f
xn--mk1bu44c xn--mxtq1m xn--ngbc5azd xn--ngbe9e0a xn--ngbrx xn--node xn--nqv7f xn--nqv7fs00ema xn--nyqy26a xn--o3cw4h
xn--ogbpf8fl xn--otu796d xn--p1acf xn--p1ai xn--pgbs0dh xn--pssy2u xn--q7ce6a xn--q9jyb4c xn--qcka1pmc xn--qxa6a
xn--qxam xn--rhqv96g xn--rovu88b xn--rvc1e0am3e xn--s9brj9c xn--ses554g xn--t60b56a xn--tckwe xn--tiq49xqyj xn--unup4y
xn--vermgensberater-ctb xn--vermgensberatung-pwb xn--vhquv xn--vuq861b xn--w4r85el8fhu5dnra xn--w4rs40l xn--wgbh1c
xn--wgbl6a xn--xhq521b xn--xkc2al3hye2a xn--xkc2dl3a5ee0h xn--y9a3aq xn--yfro4i67o xn--ygbi2ammx xn--zfr164b xxx xyz
yachts yahoo yamaxun yandex ye yodobashi yoga yokohama you youtube yt yun za zappos zara zero zip zm zone zuerich zw
"""
TLDS = (frozenset(_IANA_TLDS.split()) | {"onion"}) - {"arpa"}

# Hosts everyone shares, never listed exactly (their subdomains still can
# be: a tenant's name.workers.dev, bucket.s3.amazonaws.com). An IOC list
# names them as the URL of a payload, a phishing page or a C2 channel on a
# public service (drive.google.com, discord.com, t.me, bit.ly, workers.dev):
# the path is the indicator, the host is not, and most mail links to one.
# Then the mail and marketing platforms, which a feed lists by mistake
# now and then and whose listing would score most mail, and the sites a
# report names as what the attacker spoofs or as what an infected host
# calls to check its connectivity. `protect` in the config adds to this.
SHARED_HOSTS = frozenset("""
github.com www.github.com api.github.com gist.github.com objects.githubusercontent.com
raw.githubusercontent.com user-images.githubusercontent.com github.io gitlab.com gitlab.io
bitbucket.org www.npmjs.com registry.npmjs.org pypi.org files.pythonhosted.org rubygems.org
crates.io huggingface.co nodejs.org jsdelivr.net cdn.jsdelivr.net unpkg.com jspm.dev
google.com www.google.com drive.google.com docs.google.com sites.google.com script.google.com
forms.gle chromewebstore.google.com chrome.google.com feedproxy.google.com googleapis.com
play.google.com groups.google.com apps.apple.com
storage.googleapis.com firebasestorage.googleapis.com firebasestorage.google.com googleusercontent.com
appspot.com web.app firebaseapp.com firebaseio.com a.run.app run.app blogspot.com youtube.com
www.youtube.com youtu.be gmail.com
microsoft.com www.microsoft.com learn.microsoft.com msrc.microsoft.com blogs.microsoft.com
azure.microsoft.com login.microsoftonline.com onedrive.live.com 1drv.ms api.onedrive.com live.com
sway.cloud.microsoft sway.office.com updates.microsoft.com update.microsoft.com windowsupdate.com
download.microsoft.com get.adobe.com
office.com outlook.com sharepoint.com onmicrosoft.com windows.net blob.core.windows.net
web.core.windows.net azurefd.net azurewebsites.net azure.com cloudapp.azure.com
amazon.com amazonaws.com s3.amazonaws.com checkip.amazonaws.com cloudfront.net amazonses.com
apple.com icloud.com cloudflare.com workers.dev pages.dev r2.dev trycloudflare.com
dropbox.com www.dropbox.com dl.dropbox.com dl.dropboxusercontent.com
discord.com discordapp.com cdn.discordapp.com media.discordapp.net discord.gg
t.me api.telegram.org web.telegram.org telegra.ph graph.org
pastebin.com paste.ee rentry.co hastebin.com imgur.com ibb.co web.archive.org
bit.ly is.gd t.ly t.co tinyurl.com cutt.ly rebrand.ly psee.io href.li short.gy rb.gy shorturl.at
goo.gl ow.ly tiny.cc lnkd.in
transfer.sh temp.sh filebin.net catbox.moe files.catbox.moe anonfiles.com gofile.io pixeldrain.com
ufile.io wetransfer.com we.tl sendspace.com mediafire.com www.mediafire.com ucarecdn.com mega.nz mega.io
ipfs.io cf-ipfs.com cloudflare-ipfs.com dweb.link nftstorage.link w3s.link
vercel.app netlify.app surge.sh glitch.me replit.app repl.co herokuapp.com weebly.com weeblysite.com
wixsite.com godaddysites.com wordpress.com hostingersite.com 000webhostapp.com retool.com notion.com
notion.site lovable.app created.app b-cdn.net ngrok.io ngrok.app ngrok-free.app
duckdns.org dyna-ns.net no-ip.org ddns.net sytes.net serveftp.com hopto.org zapto.org myftp.org
docusign.net docusign.com constantcontact.com hubspotemail.net list-manage.com mailchimp.com
sendgrid.net exacttarget.com salesforce.com yahoo.com facebook.com www.facebook.com twitter.com
x.com linkedin.com www.linkedin.com instagram.com medium.com reddit.com www.reddit.com steamcommunity.com
chatgpt.com openai.com api.openai.com openrouter.ai getsession.org example.com example.net example.org
ip-api.com ipinfo.io ifconfig.me api.ipify.org ipify.org ipecho.net ident.me geoplugin.net
reallyfreegeoip.org icanhazip.com ipv4.icanhazip.com myexternalip.com curlmyip.net ip.sb
api.myip.com ipwho.is checkip.dyndns.org timeapi.io worldtimeapi.org
checkip.com bitly.com j.mp simp.ly shrinkearn.com webhook.site submit-form.com
od.lk filetransfer.io tmpfiles.org speedyshare.com xsph.ru webcindario.com gitcode.net
convertkit-mail2.com
torproject.org gsocket.io rdpguard.com k9webprotection.com mirotalk.net chrome-stats.com
jetbrains.cloud toptal.com solaredge.com deribit.com mcmod.cn
danviet.vn phnompenhpost.com cxotoday.com mfaic.gov.kh nepra.org.pk hgc.com.hk
""".split())

_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
# hosts-file line: an address, then the name (bind-adblock's REGEX_DOMAIN)
_HOSTS = re.compile(r"^\s*(?:(?:\d{1,3}\.){3}\d{1,3}|::1?|::)\s+(?P<domain>\S+)")
_COMMENT = re.compile(r"\s+#.*$")


class ConfigError(Exception):
    pass


# --------------------------------------------------------------------------
# Domains


def normalize(name: str) -> str | None:
    """Lower-case a list entry and check it is a usable DNS name.

    Returns None for anything rspamd could never see as a URL host or a
    sender domain: IP addresses, single labels, bad labels, and names whose
    last label is not a top-level domain (file names, reserved names).
    """
    name = name.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    if not name or len(name) > 253:
        return None
    labels = name.split(".")
    if len(labels) < 2:
        return None
    if not all(_LABEL.match(label) for label in labels):
        return None
    if labels[-1] not in TLDS:
        return None
    return name


def parents(name: str) -> list[str]:
    """The name and each parent with at least two labels, longest first.

    rspamd's selector stops at the registrable domain (eTLD+1); without the
    public suffix list this goes one step further (e.g. co.uk), which only
    matters if a feed lists a public suffix, and the protect list and the
    selector both keep that from matching.
    """
    labels = name.split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


# --------------------------------------------------------------------------
# Parsers: text -> {domain: category}


@dataclass
class ParseStats:
    lines: int = 0
    matched: int = 0  # distinct names
    invalid: int = 0
    skipped: int = 0  # comments, empty lines, rows of another type or class
    duplicates: int = 0  # a name listed again
    files: int = 0  # IOC archives: files read

    def add(self, out: dict[str, str], name: str, category: str) -> None:
        if name in out:
            self.duplicates += 1
        else:
            out[name] = category
            self.matched += 1

    def as_dict(self) -> dict:
        return self.__dict__.copy()


def _strip(line: str) -> str:
    line = line.strip()
    if not line or line[0] in "#!;":
        return ""
    return _COMMENT.sub("", line).strip()


def parse_domain(text: str, category: str, stats: ParseStats) -> dict[str, str]:
    """One name per line; '#', '!' and ';' start comments."""
    out = {}
    for raw in text.splitlines():
        stats.lines += 1
        line = _strip(raw)
        if not line:
            stats.skipped += 1
            continue
        name = normalize(line.split()[0])
        if name is None:
            stats.invalid += 1
            continue
        stats.add(out, name, category)
    return out


def parse_hosts(text: str, category: str, stats: ParseStats) -> dict[str, str]:
    """hosts-file format: '0.0.0.0 name' (the address is ignored)."""
    out = {}
    for raw in text.splitlines():
        stats.lines += 1
        line = _strip(raw)
        if not line:
            stats.skipped += 1
            continue
        m = _HOSTS.match(line)
        if not m:
            stats.invalid += 1
            continue
        name = normalize(m.group("domain"))
        if name is None:
            stats.invalid += 1
            continue
        stats.add(out, name, category)
    return out


def parse_infoblox(text: str, classes: dict[str, str], stats: ParseStats) -> dict[str, str]:
    """infobloxopen/threat-intelligence combined.csv.

    Columns: type,indicator,classification,detected_date. Only rows of
    type 'domain' whose classification is in `classes` are kept, under the
    category it maps to; the rest (e.g. 'suspicious') are skipped.
    """
    out = {}
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames or not {"type", "indicator", "classification"} <= set(reader.fieldnames):
        raise ValueError(f"not an Infoblox indicators CSV (header: {reader.fieldnames})")
    for row in reader:
        stats.lines += 1
        category = classes.get((row.get("classification") or "").strip().lower())
        if (row.get("type") or "").strip().lower() != "domain" or category is None:
            stats.skipped += 1
            continue
        name = normalize(row.get("indicator") or "")
        if name is None:
            stats.invalid += 1
            continue
        stats.add(out, name, category)
    return out


# IOC lists defang names: evil[.]com, evil(.)com, hxxp[://], hxxps[:]//
_DEFANG = [
    (re.compile(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[://\]|\(://\)"), "://"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[/\]"), "/"),
    (re.compile(r"\[at\]|\(at\)", re.I), "@"),
    (re.compile(r"\bhxxp", re.I), "http"),
]
_DEFANGED = re.compile("|".join(p.pattern for p, _ in _DEFANG), re.I)
# scheme://[user@]host[:port]... ; the host is up to the port or the path
_URL_HOST = re.compile(r"^[a-z][a-z0-9+.-]*://(?:[^/?#@\s]*@)?(?P<host>[^/?#:\s]+)", re.I)
_TLD_LIKE = re.compile(r"^(?:[a-z]{2,}|xn--[a-z0-9-]+)$", re.I)
# name.(xyz|com): one name under several suffixes
_ALTERNATION = re.compile(r"^(?P<stem>[^\s()|]+\.)\((?P<alts>[a-z0-9.-]+(?:\|[a-z0-9.-]+)+)\)$", re.I)
# A report's section heading ("REFERENCES:", "QAKBOT TRAFFIC TO LEGITIMATE
# DOMAINS:", AsciiDoc "== C&C servers", Markdown "## Domains") and the
# words that mark a line, a row or a whole section as naming sites that
# are not the threat
_HEADING = re.compile(r"^(?:[A-Z][A-Z0-9 ()/,:.'-]*:|=+ \S.*|#+ \S.*)\s*$")
_BENIGN = re.compile(r"legitimate|not (?:inherently )?malicious", re.I)
# The quoting around a name in a report: `name`, AsciiDoc `++name++`
_QUOTES = "\"'<>()[]{}`+"


def refang(text: str) -> str:
    for pat, rep in _DEFANG:
        text = pat.sub(rep, text)
    return text


def ioc_candidates(line: str) -> list[str]:
    """The hostname-looking tokens of an IOC line, defanging undone: bare
    names and the hosts of URLs (user info, port and path removed);
    name.(xyz|com) is both names. Email addresses, IP addresses and hashes
    are not candidates; a name whose last label is not a TLD (a file name)
    is, and fails normalize()."""
    out = []
    tokens = []
    for tok in re.split(r"[\s,;]+", refang(line)):
        m = _ALTERNATION.match(tok.strip(_QUOTES.replace("()", "")))
        if m:
            tokens += [m.group("stem") + alt for alt in m.group("alts").split("|")]
        else:
            tokens += tok.split("|")
    for tok in tokens:
        tok = tok.strip(_QUOTES)
        m = _URL_HOST.match(tok)
        if m:
            tok = m.group("host")
        elif "@" in tok:
            continue
        else:
            tok = tok.split("/", 1)[0].rsplit(":", 1)[0]
        labels = tok.rstrip(".").split(".")
        if len(labels) >= 2 and _TLD_LIKE.match(labels[-1]):
            out.append(tok)
    return out


# The IOC archives: which files of the GitHub archive are read (by
# extension; "" is a file without one), whether a name counts only on a
# defanged line, and whether .csv files are tables read by row (an indicator type
# column: only domain and URL rows count) instead of by line.
#   talos   Cisco-Talos/IOCs: a .txt list per blog post, beside STIX .json
#           files that name fewer hosts and .py/.yar tooling. Plain URL
#           lists are common, so every line counts.
#   unit42  PaloAltoNetworks/Unit42-timely-threat-intel: a report per
#           file (.txt, a few .md, one without an extension) of prose and
#           indicators. The indicators are defanged; the references
#           (linkedin.com, x.com, blog posts), file names (invoice.zip)
#           and mail servers in quoted headers are not, so only a
#           defanged line names a threat.
#   eset    eset/malware-ioc: an AsciiDoc README per campaign (bullet
#           lists, tables, URL blocks), beside hash lists, MISP JSON and
#           YARA. Indicators are defanged; the WeLiveSecurity and MITRE
#           links are not.
#   bitdefender  bitdefender/malware-ioc: a CSV per report (indicator_type,
#           [nature, hash_type,] data, ...; a `nature` of "legitimate" is
#           an abused benign host), and older campaign folders with
#           defanged domain lists in .txt.
#   sophos  sophoslabs/IoCs: a CSV per report (Indicator_type, Data,
#           Note), names plain or defanged, URLs often plain.
#   zscaler ThreatLabz/iocs: .txt lists per campaign (c2s.txt,
#           hashes.txt, ...), defanged, with "# comment" headings; the
#           DNS, WHOIS, password and decrypted-string dumps beside them
#           are plain, so only a defanged line names a threat.
#   netskope  netskopeoss/NetskopeThreatLabsIOCs: a Markdown README per
#           campaign (tables, code blocks), defanged; the blog and MITRE
#           links are not. The .txt files beside them are decrypted
#           strings and config lists, not read.
IOC_FORMATS = {
    "talos": {"suffixes": (".txt",), "defanged_only": False},
    "unit42": {"suffixes": (".txt", ".md", ""), "defanged_only": True},
    "eset": {"suffixes": (".adoc",), "defanged_only": True},
    "bitdefender": {"suffixes": (".csv", ".txt"), "defanged_only": True, "tables": True},
    "sophos": {"suffixes": (".csv",), "tables": True},
    "zscaler": {"suffixes": (".txt",), "defanged_only": True},
    "netskope": {"suffixes": (".md",), "defanged_only": True},
}
# CSV columns: the indicator's type, its value, its nature (Bitdefender:
# "malicious" or "legitimate"); the rest is notes. Only these types count.
_CSV_TYPE = ("indicator_type", "indicator", "type")
_CSV_DATA = ("data",)
_CSV_NATURE = ("nature",)
_CSV_HOST_TYPES = {"domain", "url", "url_path", "domain_port", "hostname", "fqdn"}


def _add_candidates(line: str, out: dict[str, str], category: str, stats: ParseStats) -> None:
    candidates = ioc_candidates(line)
    if not candidates:
        stats.skipped += 1
    for cand in candidates:
        name = normalize(cand)
        if name is None:
            stats.invalid += 1
        else:
            stats.add(out, name, category)


def _ioc_lines(text: str, out: dict[str, str], category: str, stats: ParseStats, defanged_only: bool) -> None:
    """A report: indicators between prose and headings. A heading names
    no threat; one saying legitimate or not malicious opens a section
    that is skipped whole, to the next heading."""
    benign_section = False
    for raw in text.splitlines():
        stats.lines += 1
        line = raw.strip()
        if _HEADING.match(line):
            benign_section = bool(_BENIGN.search(line))
            stats.skipped += 1
            continue
        if benign_section or _BENIGN.search(line) or (defanged_only and not _DEFANGED.search(line)):
            stats.skipped += 1
            continue
        _add_candidates(line, out, category, stats)


def _ioc_rows(text: str, out: dict[str, str], category: str, stats: ParseStats) -> None:
    """An IOC table: a header naming the indicator type and data columns
    (Sophos: Indicator_type, Data, Note; Bitdefender: indicator_type,
    nature, hash_type, data, ...), then a row per indicator. Only domain
    and URL rows count, and not one whose nature is legitimate or whose
    note says so. A file with another header is not an IOC table."""
    rows = csv.reader(io.StringIO(text.lstrip("\ufeff")))
    header = [h.strip().lower() for h in next(rows, [])]
    cols = {}
    for key, names in (("type", _CSV_TYPE), ("data", _CSV_DATA), ("nature", _CSV_NATURE)):
        cols[key] = next((i for i, h in enumerate(header) if h in names), None)
    if cols["type"] is None or cols["data"] is None:
        return
    for row in rows:
        stats.lines += 1
        if len(row) <= max(cols["type"], cols["data"]):
            stats.skipped += 1
            continue
        if row[cols["type"]].strip().lower() not in _CSV_HOST_TYPES:
            stats.skipped += 1
            continue
        if cols["nature"] is not None and len(row) > cols["nature"] and row[cols["nature"]].strip().lower() == "legitimate":
            stats.skipped += 1
            continue
        notes = " ".join(v for i, v in enumerate(row) if i != cols["data"])
        if _BENIGN.search(notes):
            stats.skipped += 1
            continue
        _add_candidates(row[cols["data"]], out, category, stats)


def parse_iocs(data: bytes, category: str, stats: ParseStats, suffixes: tuple[str, ...] = (".txt",),
               defanged_only: bool = False, tables: bool = False) -> dict[str, str]:
    """A GitHub archive (tar.gz) of IOC lists, one file per report: mixed
    hashes, IP addresses, URLs, domains and email addresses, usually
    defanged, between prose and headings. Keeps the host names, bare or
    from URLs, once each; the rest is skipped. A line, or a whole section
    under a heading, saying its sites are legitimate or not malicious is
    skipped too, as is every undefanged line when `defanged_only`. With
    `tables`, .csv files are IOC tables read by row (_ioc_rows)."""
    out: dict[str, str] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            for member in tar:
                suffix = os.path.splitext(member.name)[1].lower()
                if not member.isfile() or suffix not in suffixes:
                    continue
                if member.size > MAX_MEMBER:
                    raise ValueError(f"{member.name}: {member.size} bytes, larger than {MAX_MEMBER >> 20} MiB")
                stats.files += 1
                with tar.extractfile(member) as f:
                    text = f.read().decode("utf-8", errors="replace")
                if tables and suffix == ".csv":
                    _ioc_rows(text, out, category, stats)
                else:
                    _ioc_lines(text, out, category, stats, defanged_only)
    except (tarfile.TarError, OSError, EOFError) as e:
        raise ValueError(f"not a tar.gz archive: {e}") from None
    return out


def parse(feed: Feed, data: bytes) -> tuple[dict[str, str], ParseStats]:
    stats = ParseStats()
    if feed.format in IOC_FORMATS:
        return parse_iocs(data, feed.category, stats, **IOC_FORMATS[feed.format]), stats
    text = data.decode("utf-8", errors="replace")
    if feed.format == "domain":
        return parse_domain(text, feed.category, stats), stats
    if feed.format == "hosts":
        return parse_hosts(text, feed.category, stats), stats
    return parse_infoblox(text, feed.classes, stats), stats


# --------------------------------------------------------------------------
# Config


@dataclass
class Feed:
    name: str
    url: str
    format: str = "domain"
    category: str = ""
    classes: dict[str, str] = field(default_factory=dict)
    enabled: bool = True


@dataclass
class Config:
    output_dir: Path
    cache_dir: Path
    categories: dict[str, dict]  # name -> {symbol, rank}
    feeds: list[Feed]
    timeout: float = 30.0
    max_cache_age: float = 72 * 3600
    min_ratio: float = 0.5
    allowlist: set[str] = field(default_factory=set)
    protect: set[str] = field(default_factory=lambda: set(SHARED_HOSTS))  # plus the config's


def _read_names(path: Path) -> set[str]:
    names = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = _strip(raw)
        if line:
            name = normalize(line.split()[0])
            if name is None:
                raise ConfigError(f"{path}: not a domain: {line!r}")
            names.add(name)
    return names


def load_config(path: str | Path) -> Config:
    path = Path(path)
    try:
        with path.open("rb") as f:
            raw = tomllib.load(f)
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise ConfigError(f"{path}: {e}") from e

    def need(key):
        if key not in raw:
            raise ConfigError(f"{path}: '{key}' is required")
        return raw[key]

    if "output" in raw:
        raise ConfigError(f"{path}: 'output' (one map) is replaced by 'output_dir' (a map per category) in 0.2.0")
    categories = need("categories")
    for name, c in categories.items():
        if not re.match(r"^[a-z][a-z0-9_-]*$", name):
            raise ConfigError(f"{path}: category {name!r} must be lower-case [a-z0-9_-] (it names {name}.map)")
        if not isinstance(c, dict) or not re.match(r"^[A-Z][A-Z0-9_]*$", str(c.get("symbol", ""))):
            raise ConfigError(f"{path}: categories.{name}.symbol must be an upper-case rspamd symbol")
        c.setdefault("rank", 0)

    feeds = []
    seen = set()
    for f in need("feed"):
        feed = Feed(**{k: f[k] for k in ("name", "url", "format", "category", "classes", "enabled") if k in f})
        if feed.name in seen or not re.match(r"^[a-z0-9][a-z0-9_.-]*$", feed.name):
            raise ConfigError(f"{path}: feed name {feed.name!r} must be unique, lower-case [a-z0-9_.-]")
        seen.add(feed.name)
        if feed.format not in FORMATS:
            raise ConfigError(f"{path}: feed {feed.name}: format must be one of {', '.join(FORMATS)}")
        if feed.format == "infoblox":
            feed.classes = {k.lower(): v for k, v in feed.classes.items()}
            used = set(feed.classes.values())
        else:
            used = {feed.category}
        for c in used:
            if c not in categories:
                raise ConfigError(f"{path}: feed {feed.name}: unknown category {c!r}")
        if feed.enabled:
            feeds.append(feed)

    base = path.parent
    allowlist = set()
    if raw.get("allowlist"):
        allowlist = _read_names(base / raw["allowlist"])
    protect = set(SHARED_HOSTS)
    for p in raw.get("protect", []):
        name = normalize(p)
        if name is None:
            raise ConfigError(f"{path}: protect: not a domain: {p!r}")
        protect.add(name)

    return Config(
        output_dir=Path(need("output_dir")),
        cache_dir=Path(need("cache_dir")),
        categories=categories,
        feeds=feeds,
        timeout=float(raw.get("timeout", 30)),
        max_cache_age=float(raw.get("max_cache_age_hours", 72)) * 3600,
        min_ratio=float(raw.get("min_ratio", 0.5)),
        allowlist=allowlist,
        protect=protect,
    )


# --------------------------------------------------------------------------
# Fetching, with a per-feed cache (the last good copy)


class Log:
    def __init__(self, quiet: bool = False):
        self.quiet = quiet
        self.problems = 0

    def info(self, msg: str) -> None:
        if not self.quiet:
            print(msg, file=sys.stderr)

    def warning(self, msg: str) -> None:
        self.problems += 1
        print(f"warning: {msg}", file=sys.stderr)


def _cache_paths(cfg: Config, feed: Feed) -> tuple[Path, Path]:
    key = hashlib.sha256(feed.url.encode()).hexdigest()[:16]
    return cfg.cache_dir / f"{feed.name}.{key}.txt", cfg.cache_dir / f"{feed.name}.{key}.json"


def _write_atomic(path: Path, data: bytes, mode: int = 0o644) -> None:
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def fetch(cfg: Config, feed: Feed, log: Log, offline: bool = False) -> bytes | None:
    """The feed's body: downloaded, or the cached copy if not modified,
    unreachable (while younger than max_cache_age) or offline."""
    data_path, meta_path = _cache_paths(cfg, feed)
    meta = {}
    if meta_path.exists():
        with contextlib.suppress(ValueError, OSError):
            meta = json.loads(meta_path.read_text())

    def cached(reason: str) -> bytes | None:
        if not data_path.exists():
            log.warning(f"{feed.name}: {reason}, and no cached copy")
            return None
        age = time.time() - meta.get("fetched", data_path.stat().st_mtime)
        if not offline and age > cfg.max_cache_age:
            log.warning(f"{feed.name}: {reason}, cached copy too old ({age / 3600:.0f}h), feed dropped")
            return None
        if not offline:
            log.warning(f"{feed.name}: {reason}, using the cached copy ({age / 3600:.1f}h old)")
        return data_path.read_bytes()

    if offline:
        return cached("offline")

    req = urllib.request.Request(feed.url, headers={"User-Agent": USER_AGENT})
    if data_path.exists():
        if meta.get("etag"):
            req.add_header("If-None-Match", meta["etag"])
        if meta.get("last_modified"):
            req.add_header("If-Modified-Since", meta["last_modified"])
    try:
        with urllib.request.urlopen(req, timeout=cfg.timeout) as resp:
            body = resp.read(MAX_BODY + 1)
            if len(body) > MAX_BODY:
                return cached(f"larger than {MAX_BODY >> 20} MiB")
            headers = resp.headers
    except urllib.error.HTTPError as e:
        if e.code == 304:
            meta["fetched"] = time.time()
            _write_atomic(meta_path, json.dumps(meta).encode())
            log.info(f"{feed.name}: not modified")
            return data_path.read_bytes()
        return cached(f"HTTP {e.code}")
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        return cached(f"download failed ({getattr(e, 'reason', e)})")

    _write_atomic(data_path, body)
    meta = {
        "url": feed.url,
        "fetched": time.time(),
        "etag": headers.get("ETag"),
        "last_modified": headers.get("Last-Modified") or email.utils.formatdate(usegmt=True),
    }
    _write_atomic(meta_path, json.dumps(meta).encode())
    log.info(f"{feed.name}: downloaded {len(body)} bytes")
    return body


# --------------------------------------------------------------------------
# Merging and the map


@dataclass
class Result:
    entries: dict[str, str]  # domain -> category
    sources: dict[str, list[str]]  # domain -> feed names
    stats: dict[str, dict]
    dropped_allow: int = 0
    dropped_protect: int = 0


def is_allowed(name: str, allowlist: set[str]) -> bool:
    return any(p in allowlist for p in parents(name))


def merge(cfg: Config, parsed: list[tuple[Feed, dict[str, str]]], keep_sources: bool = False) -> Result:
    """Every feed's names in one map. A name in several categories gets
    the highest-ranked one. Allowlisted names (and everything under them)
    and protected names (exactly) are dropped."""
    rank = {k: v["rank"] for k, v in cfg.categories.items()}
    entries: dict[str, str] = {}
    sources: dict[str, list[str]] = {}
    res = Result(entries, sources, {})
    for feed, names in parsed:
        for name, category in names.items():
            if name in cfg.protect:
                res.dropped_protect += 1
                continue
            if cfg.allowlist and is_allowed(name, cfg.allowlist):
                res.dropped_allow += 1
                continue
            old = entries.get(name)
            if old is None or rank[category] > rank[old]:
                entries[name] = category
            if keep_sources:
                sources.setdefault(name, []).append(feed.name)
    return res


def map_path(cfg: Config, category: str) -> Path:
    return cfg.output_dir / f"{category}.map"


def render(cfg: Config, res: Result) -> dict[str, tuple[str, str]]:
    """{category: (header, body)} of each category's map; every category
    gets a file, empty or not, so its rspamd rule always has one. The body
    alone decides whether a file changed, so a run with nothing new leaves
    rspamd's maps alone."""
    names: dict[str, list[str]] = {cat: [] for cat in cfg.categories}
    for name, cat in res.entries.items():
        names[cat].append(name)
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    feeds = [f"# feed {n}: {s.get('matched', 0)} names, {s.get('invalid', 0)} invalid"
             for n, s in res.stats.items()]
    out = {}
    for cat, lst in names.items():
        header = [
            f"# rspamd-threat-multimap {VERSION}: generated {stamp}",
            f"# category {cat} ({cfg.categories[cat]['symbol']})",
            f"# entries: {len(lst)}",
            f"# all categories: {len(res.entries)}",
            *feeds,
        ]
        if res.dropped_allow or res.dropped_protect:
            header.append(f"# dropped: {res.dropped_allow} allowlisted, {res.dropped_protect} protected")
        out[cat] = ("\n".join(header) + "\n", "".join(f"{n}\n" for n in sorted(lst)))
    return out


def _previous(path: Path) -> tuple[int | None, str | None]:
    """(entries, body) of a current map, if there is one."""
    if not path.exists():
        return None, None
    count, body = None, []
    with path.open(encoding="utf-8") as f:
        for line in f:
            if line.startswith("#"):
                m = re.match(r"^# entries: (\d+)$", line.strip())
                if m:
                    count = int(m.group(1))
            else:
                body.append(line)
    return count, "".join(body)


def collect(cfg: Config, log: Log, offline: bool = False, keep_sources: bool = False) -> Result:
    parsed = []
    stats = {}
    for feed in cfg.feeds:
        data = fetch(cfg, feed, log, offline=offline)
        if data is None:
            stats[feed.name] = {"error": True}
            continue
        try:
            names, s = parse(feed, data)
        except ValueError as e:
            log.warning(f"{feed.name}: {e}")
            stats[feed.name] = {"error": True}
            continue
        if s.matched == 0:
            log.warning(f"{feed.name}: no names parsed ({s.lines} lines)")
        extra = (f", {s.duplicates} listed again" if s.duplicates else "") + (f", {s.files} files" if s.files else "")
        log.info(f"{feed.name}: {s.matched} names, {s.invalid} invalid, {s.skipped} skipped{extra}")
        stats[feed.name] = s.as_dict()
        parsed.append((feed, names))
    res = merge(cfg, parsed, keep_sources=keep_sources)
    res.stats = stats
    return res


@contextlib.contextmanager
def _lock(cfg: Config):
    cfg.cache_dir.mkdir(parents=True, exist_ok=True)
    with (cfg.cache_dir / ".lock").open("w") as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise ConfigError("another update is running") from None
        yield


def cmd_update(cfg: Config, args, log: Log) -> int:
    with _lock(cfg):
        res = collect(cfg, log, offline=args.offline)
        maps = render(cfg, res)
        prev = {cat: _previous(map_path(cfg, cat)) for cat in maps}
        counts = [c for c, _ in prev.values() if c is not None]
        prev_total = sum(counts) if counts else None
        total = len(res.entries)
        if not args.force and prev_total and total < prev_total * cfg.min_ratio:
            log.warning(f"{total} entries is under {cfg.min_ratio:.0%} of the current {prev_total}; maps not replaced (--force)")
            return 1
        if total == 0:
            log.warning("no entries; maps not replaced")
            return 1
        cfg.output_dir.mkdir(parents=True, exist_ok=True)
        for cat, (header, body) in maps.items():
            path = map_path(cfg, cat)
            count = body.count("\n")
            prev_count, prev_body = prev[cat]
            if body == prev_body and not args.force:
                log.info(f"{path}: unchanged ({count} entries)")
            else:
                _write_atomic(path, (header + body).encode())
                log.info(f"{path}: {count} entries (was {prev_count if prev_count is not None else 'none'})")
    return 1 if log.problems else 0


def cmd_lookup(cfg: Config, args, log: Log) -> int:
    """Which of the given names (or their parents) the cached feeds list,
    as rspamd would match them. Uses only the cache: no downloads."""
    names = args.names
    if names == ["-"]:
        names = [line.split()[0] for line in sys.stdin if line.strip()]
    res = collect(cfg, Log(quiet=True), offline=True, keep_sources=True)
    hits = 0
    for raw in names:
        name = normalize(raw)
        if name is None:
            continue
        for p in parents(name):
            if p in res.entries:
                hits += 1
                cat = res.entries[p]
                print(f"{name}\t{p}\t{cfg.categories[cat]['symbol']}\t{','.join(res.sources[p])}")
                break
        else:
            if args.all:
                print(f"{name}\t-\t-\t-")
    return 0 if hits == 0 or args.all else 2


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="rspamd-threat-multimap", description=__doc__.split("\n\n")[0])
    ap.add_argument("-c", "--config", default=os.environ.get("RSPAMD_THREAT_MULTIMAP_CONFIG", DEFAULT_CONFIG))
    ap.add_argument("-q", "--quiet", action="store_true", help="only warnings and errors (for cron)")
    ap.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)
    up = sub.add_parser("update", help="download the feeds and write the map")
    up.add_argument("--force", action="store_true", help="write even if unchanged or much smaller")
    up.add_argument("--offline", action="store_true", help="build from the cached feeds only")
    lk = sub.add_parser("lookup", help="which names the cached feeds would match (exit 2 on a hit)")
    lk.add_argument("--all", action="store_true", help="print misses too")
    lk.add_argument("names", nargs="+", help="domains or host names; '-' reads them from stdin")
    args = ap.parse_args(argv)

    log = Log(quiet=args.quiet)
    try:
        cfg = load_config(args.config)
        if args.cmd == "update":
            return cmd_update(cfg, args, log)
        return cmd_lookup(cfg, args, log)
    except ConfigError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
