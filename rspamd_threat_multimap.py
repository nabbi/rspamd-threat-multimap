#!/usr/bin/env python3
"""rspamd-threat-multimap: build an rspamd multimap of high-risk threat domains.

Downloads public threat feeds (phishing and malware domains), validates
and merges them into one hash map of ``domain SYMBOL`` lines that a single
rspamd multimap rule reads (rspamd/local.d/multimap.conf). The selector in
rspamd/lua.local.d/selectors/threat_domains.lua feeds that rule every URL
host in the message, with its parent domains, and the sender domains.

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
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

VERSION = "0.1.0"
DEFAULT_CONFIG = "/etc/rspamd-threat-multimap/config.toml"
USER_AGENT = f"rspamd-threat-multimap/{VERSION} (+https://github.com/nabbi/rspamd-threat-multimap)"
MAX_BODY = 64 * 1024 * 1024
FORMATS = ("domain", "hosts", "infoblox")

# Names that are never real hosts on the internet (RFC 6761, in-addr/ip6.arpa)
RESERVED_TLDS = {"arpa", "example", "invalid", "local", "localhost", "test"}

_LABEL = re.compile(r"^(?!-)[a-z0-9_-]{1,63}(?<!-)$")
_TLD = re.compile(r"^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$")
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
    sender domain: IP addresses, single labels, reserved TLDs, bad labels.
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
    tld = labels[-1]
    if not _TLD.match(tld) or tld in RESERVED_TLDS:
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
    matched: int = 0
    invalid: int = 0
    skipped: int = 0  # comments, empty lines, rows of another type or class

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
        out[name] = category
        stats.matched += 1
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
        out[name] = category
        stats.matched += 1
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
        out[name] = category
        stats.matched += 1
    return out


def parse(feed: "Feed", text: str) -> tuple[dict[str, str], ParseStats]:
    stats = ParseStats()
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
    output: Path
    cache_dir: Path
    categories: dict[str, dict]  # name -> {symbol, rank}
    feeds: list[Feed]
    timeout: float = 30.0
    max_cache_age: float = 72 * 3600
    min_ratio: float = 0.5
    allowlist: set[str] = field(default_factory=set)
    protect: set[str] = field(default_factory=set)


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

    categories = need("categories")
    for name, c in categories.items():
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
    protect = set()
    for p in raw.get("protect", []):
        name = normalize(p)
        if name is None:
            raise ConfigError(f"{path}: protect: not a domain: {p!r}")
        protect.add(name)

    return Config(
        output=Path(need("output")),
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

    def warn(self, msg: str) -> None:
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


def fetch(cfg: Config, feed: Feed, log: Log, offline: bool = False) -> str | None:
    """The feed's text: downloaded, or the cached copy if not modified,
    unreachable (while younger than max_cache_age) or offline."""
    data_path, meta_path = _cache_paths(cfg, feed)
    meta = {}
    if meta_path.exists():
        with contextlib.suppress(ValueError, OSError):
            meta = json.loads(meta_path.read_text())

    def cached(reason: str) -> str | None:
        if not data_path.exists():
            log.warn(f"{feed.name}: {reason}, and no cached copy")
            return None
        age = time.time() - meta.get("fetched", data_path.stat().st_mtime)
        if not offline and age > cfg.max_cache_age:
            log.warn(f"{feed.name}: {reason}, cached copy too old ({age / 3600:.0f}h), feed dropped")
            return None
        if not offline:
            log.warn(f"{feed.name}: {reason}, using the cached copy ({age / 3600:.1f}h old)")
        return data_path.read_text(encoding="utf-8", errors="replace")

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
            return data_path.read_text(encoding="utf-8", errors="replace")
        return cached(f"HTTP {e.code}")
    except (urllib.error.URLError, OSError, TimeoutError) as e:
        return cached(f"download failed ({getattr(e, 'reason', e)})")

    text = body.decode("utf-8", errors="replace")
    _write_atomic(data_path, body)
    meta = {
        "url": feed.url,
        "fetched": time.time(),
        "etag": headers.get("ETag"),
        "last_modified": headers.get("Last-Modified") or email.utils.formatdate(usegmt=True),
    }
    _write_atomic(meta_path, json.dumps(meta).encode())
    log.info(f"{feed.name}: downloaded {len(body)} bytes")
    return text


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


def render(cfg: Config, res: Result) -> tuple[str, str]:
    """(header, body) of the map file. The body alone decides whether the
    file changed, so a run with nothing new leaves rspamd's map alone."""
    body = "".join(f"{name} {cfg.categories[cat]['symbol']}\n" for name, cat in sorted(res.entries.items()))
    counts = {}
    for cat in res.entries.values():
        counts[cat] = counts.get(cat, 0) + 1
    header = [
        f"# rspamd-threat-multimap {VERSION}: generated {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}",
        f"# entries: {len(res.entries)}",
    ]
    for cat in sorted(counts):
        header.append(f"# category {cat} ({cfg.categories[cat]['symbol']}): {counts[cat]}")
    for name, s in res.stats.items():
        header.append(f"# feed {name}: {s.get('matched', 0)} names, {s.get('invalid', 0)} invalid")
    if res.dropped_allow or res.dropped_protect:
        header.append(f"# dropped: {res.dropped_allow} allowlisted, {res.dropped_protect} protected")
    return "\n".join(header) + "\n", body


def _previous(path: Path) -> tuple[int | None, str | None]:
    """(entries, body) of the current map, if there is one."""
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
        text = fetch(cfg, feed, log, offline=offline)
        if text is None:
            stats[feed.name] = {"error": True}
            continue
        try:
            names, s = parse(feed, text)
        except ValueError as e:
            log.warn(f"{feed.name}: {e}")
            stats[feed.name] = {"error": True}
            continue
        if s.matched == 0:
            log.warn(f"{feed.name}: no names parsed ({s.lines} lines)")
        log.info(f"{feed.name}: {s.matched} names, {s.invalid} invalid, {s.skipped} skipped")
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
        header, body = render(cfg, res)
        prev_count, prev_body = _previous(cfg.output)
        total = len(res.entries)
        if not args.force and prev_count and total < prev_count * cfg.min_ratio:
            log.warn(f"{total} entries is under {cfg.min_ratio:.0%} of the current {prev_count}; map not replaced (--force)")
            return 1
        if total == 0:
            log.warn("no entries; map not replaced")
            return 1
        if body == prev_body and not args.force:
            log.info(f"{cfg.output}: unchanged ({total} entries)")
        else:
            cfg.output.parent.mkdir(parents=True, exist_ok=True)
            _write_atomic(cfg.output, (header + body).encode())
            log.info(f"{cfg.output}: {total} entries (was {prev_count if prev_count is not None else 'none'})")
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
