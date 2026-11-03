import io
import json
import os
import sys
import tarfile
import tempfile
import time
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import rspamd_threat_multimap as m

CONFIG = """
output_dir = "{d}/out"
cache_dir = "{d}/cache"
min_ratio = 0.5
allowlist = "allow.txt"
protect = ["google.com"]

[categories]
malware  = {{ symbol = "THREAT_MALWARE",  rank = 3 }}
phishing = {{ symbol = "THREAT_PHISHING", rank = 2 }}

[[feed]]
name = "phish"
url = "https://feeds.invalid/phish.txt"
format = "domain"
category = "phishing"

[[feed]]
name = "hosts"
url = "https://feeds.invalid/hosts.txt"
format = "hosts"
category = "phishing"

[[feed]]
name = "ibx"
url = "https://feeds.invalid/ibx.csv"
format = "infoblox"
classes = {{ malicious = "malware", phishing = "phishing" }}

[[feed]]
name = "talos"
url = "https://feeds.invalid/iocs.tar.gz"
format = "talos"
category = "malware"

[[feed]]
name = "off"
url = "https://feeds.invalid/off.txt"
category = "malware"
enabled = false
"""

TALOS_FILES = {
    "IOCs-main/2026/04/report.txt": (
        "d41d8cd98f00b204e9800998ecf8427e\r\n"
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\r\n"
        "144[.]172[.]102[.]88\r\n"
        "c2(.)talos-evil(.)com\r\n"
        "hxxps[://]www[.]talos-evil[.]com[:]8443/x/y.php\r\n"
        "http://user:pw@shared.example.net/path, hxxp://10.0.0.1/drop.exe\r\n"
        "attacker[at]talos-evil.com\r\n"
        "auto.exe\r\n"
        "IOCs:\r\n"
    ),
    "IOCs-main/2025/01/other.txt": "c2.talos-evil.com\nupdate.go\n",
    "IOCs-main/2025/01/other.json": '{"objects": [{"type": "indicator", "pattern": "[domain-name:value = \'json-only.com\']"}]}',
    "IOCs-main/2024/10/server/server.py": "HOST = 'py-only.com'\n",
    "IOCs-main/README.md": "see https://blog.talosintelligence.com/\n",
}


def talos_tarball(files=TALOS_FILES):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


FEEDS = {
    "https://feeds.invalid/phish.txt": "# header\nevil.example.com\nBAD.Example.org.  # inline\n\n"
    "shared.example.net\ngoogle.com\nmine.example.edu\nsub.mine.example.edu\n",
    "https://feeds.invalid/hosts.txt": "0.0.0.0 hosted.example.com\n127.0.0.1 localhost\n0.0.0.0 0.0.0.0\nnot a hosts line\n",
    "https://feeds.invalid/ibx.csv": "type,indicator,classification,detected_date\n"
    "domain,shared.example.net,malicious,2026-01-01\n"
    "domain,phish.example.io,phishing,2026-01-01\n"
    "domain,meh.example.io,suspicious,2026-01-01\n"
    "domain,1.0.0.127.in-addr.arpa,malicious,2026-01-01\n"
    "ip,192.0.2.1,malicious,2026-01-01\n",
    "https://feeds.invalid/iocs.tar.gz": talos_tarball(),
}


class FakeResp(io.BytesIO):
    def __init__(self, body, headers=None):
        super().__init__(body)
        self.headers = headers or {}

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


def fake_urlopen(feeds, calls=None):
    def urlopen(req, timeout=None):
        if calls is not None:
            calls.append(req)
        body = feeds[req.full_url]
        if isinstance(body, Exception):
            raise body
        if isinstance(body, str):
            body = body.encode()
        return FakeResp(body, {"ETag": '"v1"'})

    return urlopen


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        (self.d / "allow.txt").write_text("# ours\nmine.example.edu\n")
        self.cfg_path = self.d / "config.toml"
        self.cfg_path.write_text(CONFIG.format(d=self.d))

    def tearDown(self):
        self.tmp.cleanup()

    def run_main(self, *argv, feeds=FEEDS, calls=None):
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(m.urllib.request, "urlopen", fake_urlopen(feeds, calls)), \
                redirect_stdout(out), mock.patch.object(sys, "stderr", err):
            rc = m.main(["-c", str(self.cfg_path), *argv])
        return rc, out.getvalue(), err.getvalue()

    def map_lines(self):
        """Every category map's names as 'name SYMBOL', sorted, and the
        files' text."""
        symbols = {"malware": "THREAT_MALWARE", "phishing": "THREAT_PHISHING"}
        lines, text = [], ""
        for cat, sym in symbols.items():
            t = (self.d / f"out/{cat}.map").read_text()
            text += t
            lines += [f"{n} {sym}" for n in t.splitlines() if not n.startswith("#")]
        return sorted(lines), text


class TestNormalize(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(m.normalize("WWW.Example.COM."), "www.example.com")
        self.assertEqual(m.normalize("*.evil.com"), "evil.com")
        self.assertEqual(m.normalize("xn--80ak6aa92e.com"), "xn--80ak6aa92e.com")
        self.assertEqual(m.normalize("a_b.example.com"), "a_b.example.com")
        self.assertEqual(m.normalize("abc.onion"), "abc.onion")

    def test_invalid(self):
        for bad in ["", "com", "192.0.2.1", "1.2.3.4.in-addr.arpa", "-a.example.com",
                    "a-.example.com", "host.local", "a..b.com", "x" * 64 + ".com",
                    "example.c0m", "ex ample.com", "localhost", "host.example", "host.test"]:
            self.assertIsNone(m.normalize(bad), bad)

    def test_tld_must_be_real(self):
        # file names and made-up suffixes are not hosts; .zip and .sh are TLDs
        for bad in ["auto.exe", "index.php", "ca.pem", "go.oo", "update.google.hta", "a.xn--nope"]:
            self.assertIsNone(m.normalize(bad), bad)
        for ok in ["x.zip", "x.sh", "x.xn--p1ai", "x.co.uk", "x.top"]:
            self.assertEqual(m.normalize(ok), ok)
        self.assertGreater(len(m.TLDS), 1400)
        self.assertNotIn("arpa", m.TLDS)

    def test_parents(self):
        self.assertEqual(m.parents("a.b.example.com"), ["a.b.example.com", "b.example.com", "example.com"])
        self.assertEqual(m.parents("example.com"), ["example.com"])


class TestParsers(unittest.TestCase):
    def test_domain(self):
        s = m.ParseStats()
        out = m.parse_domain("# c\n! c\n\nevil.com\nevil.com extra\nbad_\n192.0.2.1\n", "phishing", s)
        self.assertEqual(out, {"evil.com": "phishing"})
        self.assertEqual((s.matched, s.invalid, s.skipped, s.duplicates), (1, 2, 3, 1))

    def test_hosts(self):
        s = m.ParseStats()
        out = m.parse_hosts("0.0.0.0 a.com\n127.0.0.1 b.com # x\n:: c.com\nd.com\n0.0.0.0 localhost\n", "malware", s)
        self.assertEqual(set(out), {"a.com", "b.com", "c.com"})
        self.assertEqual(s.invalid, 2)

    def test_infoblox(self):
        s = m.ParseStats()
        out = m.parse_infoblox(FEEDS["https://feeds.invalid/ibx.csv"], {"malicious": "malware", "phishing": "phishing"}, s)
        self.assertEqual(out, {"shared.example.net": "malware", "phish.example.io": "phishing"})
        self.assertEqual((s.matched, s.invalid, s.skipped), (2, 1, 2))

    def test_infoblox_bad_header(self):
        with self.assertRaises(ValueError):
            m.parse_infoblox("a,b\n1,2\n", {}, m.ParseStats())

    def test_refang(self):
        self.assertEqual(m.refang("hxxps[://]www[.]a(.)b[dot]com[:]80[/]x"), "https://www.a.b.com:80/x")
        self.assertEqual(m.refang("HXXP://a{.}b (dot) c, x[at]y"), "http://a.b . c, x@y")

    def test_talos_candidates(self):
        line = "hxxps[://]www[.]evil(.)com[:]8443/x/y.php, foo[at]bar.com 1.2.3.4|443 " \
               "d41d8cd98f00b204e9800998ecf8427e evil2.com/path 'q.top' <rand>.c.ru auto.exe [::1]"
        self.assertEqual(m.talos_candidates(line), ["www.evil.com", "evil2.com", "q.top", "rand>.c.ru", "auto.exe"])
        self.assertEqual(m.talos_candidates("IOCs:"), [])
        self.assertEqual(m.talos_candidates(""), [])

    def test_talos(self):
        s = m.ParseStats()
        out = m.parse_talos(talos_tarball(), "malware", s)
        # only *.txt files: the .json and .py names are not read
        self.assertEqual(out, {
            "c2.talos-evil.com": "malware",
            "www.talos-evil.com": "malware",
            "shared.example.net": "malware",
        })
        # files, lines; c2.talos-evil.com twice; auto.exe and update.go
        # are file names; no candidates on the hash, IP, email, label lines
        self.assertEqual(s.files, 2)
        self.assertEqual(s.lines, 11)
        self.assertEqual((s.matched, s.duplicates, s.invalid, s.skipped), (3, 1, 2, 5))

    def test_talos_not_an_archive(self):
        with self.assertRaises(ValueError):
            m.parse_talos(b"evil.com\n", "malware", m.ParseStats())
        with self.assertRaises(ValueError):
            m.parse_talos(b"", "malware", m.ParseStats())
        whole = talos_tarball()
        with self.assertRaises(ValueError):
            m.parse_talos(whole[: len(whole) // 2], "malware", m.ParseStats())

    def test_talos_member_too_large(self):
        big = {"IOCs-main/x.txt": "a.com\n" * (m.MAX_MEMBER // 6 + 1)}
        with self.assertRaises(ValueError):
            m.parse_talos(talos_tarball(big), "malware", m.ParseStats())


class TestConfig(Base):
    def test_load(self):
        cfg = m.load_config(self.cfg_path)
        self.assertEqual([f.name for f in cfg.feeds], ["phish", "hosts", "ibx", "talos"])
        self.assertEqual(cfg.allowlist, {"mine.example.edu"})
        self.assertEqual(cfg.protect, {"google.com"})

    def test_unknown_category(self):
        self.cfg_path.write_text(CONFIG.format(d=self.d).replace('category = "phishing"', 'category = "nope"', 1))
        with self.assertRaises(m.ConfigError):
            m.load_config(self.cfg_path)

    def test_bad_symbol(self):
        self.cfg_path.write_text(CONFIG.format(d=self.d).replace('"THREAT_MALWARE"', '"threat malware"'))
        with self.assertRaises(m.ConfigError):
            m.load_config(self.cfg_path)

    def test_example_config_loads(self):
        repo = Path(__file__).resolve().parent.parent
        tmp = self.d / "example"
        tmp.mkdir()
        (tmp / "config.toml").write_text((repo / "config.example.toml").read_text())
        (tmp / "allowlist.txt").write_text((repo / "allowlist.example.txt").read_text())
        cfg = m.load_config(tmp / "config.toml")
        self.assertTrue(all(f.enabled for f in cfg.feeds))
        self.assertEqual(len(cfg.feeds), 6)
        self.assertEqual([f.format for f in cfg.feeds if f.format == "talos"], ["talos"])


class TestUpdate(Base):
    def test_map(self):
        rc, _, err = self.run_main("update")
        self.assertEqual(rc, 0, err)
        lines, text = self.map_lines()
        self.assertEqual(lines, [
            "bad.example.org THREAT_PHISHING",
            "c2.talos-evil.com THREAT_MALWARE",
            "evil.example.com THREAT_PHISHING",
            "hosted.example.com THREAT_PHISHING",
            "phish.example.io THREAT_PHISHING",
            # phishing in one feed, malware in another: the higher rank wins
            "shared.example.net THREAT_MALWARE",
            "www.talos-evil.com THREAT_MALWARE",
        ])
        self.assertIn("# all categories: 7", text)
        self.assertIn("# entries: 4", (self.d / "out/phishing.map").read_text())
        self.assertIn("# feed talos: 3 names, 2 invalid", text)
        self.assertIn("talos: 3 names, 2 invalid, 5 skipped, 1 listed again, 2 files", err)
        self.assertIn("# dropped: 2 allowlisted, 1 protected", text)
        self.assertEqual(os.stat(self.d / "out/phishing.map").st_mode & 0o777, 0o644)

    def test_unchanged_is_not_rewritten(self):
        self.run_main("update")
        before = (self.d / "out/phishing.map").stat().st_mtime_ns
        time.sleep(0.01)
        rc, _, err = self.run_main("update")
        self.assertEqual(rc, 0)
        self.assertIn("unchanged", err)
        self.assertEqual((self.d / "out/phishing.map").stat().st_mtime_ns, before)

    def test_conditional_request(self):
        self.run_main("update")
        calls = []
        self.run_main("update", calls=calls)
        self.assertTrue(all(r.get_header("If-none-match") == '"v1"' for r in calls))

    def test_not_modified_uses_cache(self):
        self.run_main("update")
        err304 = m.urllib.error.HTTPError("u", 304, "Not Modified", {}, None)
        feeds = {k: err304 for k in FEEDS}
        rc, _, err = self.run_main("update", feeds=feeds)
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(self.map_lines()[0]), 7)

    def test_failed_feed_uses_cache_and_warns(self):
        self.run_main("update")
        feeds = dict(FEEDS)
        feeds["https://feeds.invalid/phish.txt"] = m.urllib.error.URLError("down")
        rc, _, err = self.run_main("-q", "update", feeds=feeds)
        self.assertEqual(rc, 1)
        self.assertIn("using the cached copy", err)
        self.assertEqual(len(self.map_lines()[0]), 7)

    def test_stale_cache_dropped(self):
        self.run_main("update")
        cfg = m.load_config(self.cfg_path)
        _, meta = m._cache_paths(cfg, cfg.feeds[0])
        meta.write_text(json.dumps({"fetched": time.time() - 100 * 3600}))
        feeds = dict(FEEDS)
        feeds["https://feeds.invalid/phish.txt"] = m.urllib.error.URLError("down")
        rc, _, err = self.run_main("update", "--force", feeds=feeds)
        self.assertEqual(rc, 1)
        self.assertIn("too old", err)
        self.assertNotIn("evil.example.com THREAT_PHISHING", self.map_lines()[0])

    def test_shrink_guard(self):
        self.run_main("update")
        feeds = {k: "" for k in FEEDS}
        feeds["https://feeds.invalid/ibx.csv"] = "type,indicator,classification\n"
        feeds["https://feeds.invalid/iocs.tar.gz"] = talos_tarball({})
        feeds["https://feeds.invalid/phish.txt"] = "evil.example.com\n"
        rc, _, err = self.run_main("update", feeds=feeds)
        self.assertEqual(rc, 1)
        self.assertIn("maps not replaced", err)
        self.assertEqual(len(self.map_lines()[0]), 7)
        rc, _, _ = self.run_main("update", "--force", feeds=feeds)
        self.assertEqual(self.map_lines()[0], ["evil.example.com THREAT_PHISHING"])

    def test_offline(self):
        self.run_main("update")
        for cat in ("malware", "phishing"):
            (self.d / f"out/{cat}.map").unlink()
        rc, _, err = self.run_main("update", "--offline", feeds={})
        self.assertEqual(rc, 0, err)
        self.assertEqual(len(self.map_lines()[0]), 7)


class TestMapFormat(Base):
    def test_domain_only_lines(self):
        # rspamd drops a 'key value' line split across its 1 MiB read
        # chunks; a key alone is read again whole
        self.run_main("update")
        for cat in ("malware", "phishing"):
            body = [ln for ln in (self.d / f"out/{cat}.map").read_text().splitlines() if not ln.startswith("#")]
            self.assertTrue(body)
            self.assertTrue(all(" " not in ln and "\t" not in ln for ln in body), body)

    def test_empty_category_gets_a_file(self):
        self.cfg_path.write_text(CONFIG.format(d=self.d).replace(
            'phishing = {{ symbol = "THREAT_PHISHING", rank = 2 }}'.replace("{{", "{").replace("}}", "}"),
            'phishing = { symbol = "THREAT_PHISHING", rank = 2 }\nfraud = { symbol = "THREAT_FRAUD", rank = 1 }'))
        rc, _, err = self.run_main("update")
        self.assertEqual(rc, 0, err)
        text = (self.d / "out/fraud.map").read_text()
        self.assertIn("# entries: 0", text)
        self.assertEqual([ln for ln in text.splitlines() if not ln.startswith("#")], [])

    def test_only_changed_maps_rewritten(self):
        self.run_main("update")
        before = {c: (self.d / f"out/{c}.map").stat().st_mtime_ns for c in ("malware", "phishing")}
        time.sleep(0.01)
        feeds = dict(FEEDS)
        feeds["https://feeds.invalid/phish.txt"] += "new.example.com\n"
        rc, _, err = self.run_main("update", feeds=feeds)
        self.assertEqual(rc, 0, err)
        self.assertEqual((self.d / "out/malware.map").stat().st_mtime_ns, before["malware"])
        self.assertNotEqual((self.d / "out/phishing.map").stat().st_mtime_ns, before["phishing"])

    def test_old_output_key_rejected(self):
        self.cfg_path.write_text(CONFIG.format(d=self.d).replace("output_dir = ", "output = "))
        with self.assertRaises(m.ConfigError):
            m.load_config(self.cfg_path)

    def test_bad_category_name(self):
        self.cfg_path.write_text(CONFIG.format(d=self.d).replace("malware  =", "Mal/ware =").replace(
            '"malware"', '"Mal/ware"'))
        with self.assertRaises(m.ConfigError):
            m.load_config(self.cfg_path)


class TestLookup(Base):
    def test_lookup(self):
        self.run_main("update")
        rc, out, _ = self.run_main("lookup", "www.Evil.Example.com", "shared.example.net", "clean.example.com")
        self.assertEqual(rc, 2)
        self.assertEqual(out.splitlines(), [
            "www.evil.example.com\tevil.example.com\tTHREAT_PHISHING\tphish",
            "shared.example.net\tshared.example.net\tTHREAT_MALWARE\tphish,ibx,talos",
        ])

    def test_lookup_miss(self):
        self.run_main("update")
        rc, out, _ = self.run_main("lookup", "example.com", "sub.mine.example.edu")
        self.assertEqual((rc, out), (0, ""))


if __name__ == "__main__":
    unittest.main()
