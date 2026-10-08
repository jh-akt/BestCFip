"""Offline source-format contracts and last-good retention regressions."""
import contextlib
import io
import json
import tempfile
import unittest
import urllib.request
from pathlib import Path
import collects

RANGES4 = b"""103.21.244.0/22
103.22.200.0/22
103.31.4.0/22
104.16.0.0/13
104.24.0.0/14
108.162.192.0/18
131.0.72.0/22
141.101.64.0/18
162.158.0.0/15
172.64.0.0/13
173.245.48.0/20
188.114.96.0/20
190.93.240.0/20
197.234.240.0/22
198.41.128.0/17
"""
RANGES6 = b"""2400:cb00::/32
2606:4700::/32
2803:f800::/32
2405:b500::/32
2405:8100::/32
2a06:98c0::/29
2c0f:f248::/32
"""
TABLE = """<table><tr><th>线路名称</th><th>优选地址</th><th>网络带宽</th><th>峰值速度</th><th>往返延迟</th><th>数据中心</th><th>更新时间</th></tr>
<tr><td>联通</td><td>104.24.213.11</td><td>5 MB</td><td>644 kB/s</td><td>234 毫秒</td><td>LAX</td><td>2026-10-08 19:05:51</td></tr>
<tr><td>电信</td><td>104.24.213.11</td><td>5 MB</td><td>644 kB/s</td><td>225 毫秒</td><td>FRA</td><td>2026-10-08 19:05:51</td></tr></table>""".encode()


def fetcher(sources=None):
    payloads = {collects.RANGE_URLS[4]: RANGES4, collects.RANGE_URLS[6]: RANGES6}
    payloads.update({url: (sources or {}).get(name) for name, url in collects.SOURCES})

    def fetch(url):
        if payloads.get(url) is None:
            raise TimeoutError("fixture source unavailable")
        return payloads[url]
    return fetch


def run(output, sources, now="2026-10-08T12:00:00+00:00"):
    with contextlib.redirect_stdout(io.StringIO()):
        return collects.collect(output, fetcher(sources), now)


class CollectorTests(unittest.TestCase):
    def test_explicit_ports_and_non_public_addresses(self):
        values = collects.addresses("104.17.1.1:8443 104.17.1.2:443 10.0.0.1 127.0.0.1 [2606:4700::1234]:443 [2606:4700::4321]:8443")
        self.assertEqual(values, ["104.17.1.2", "2606:4700::1234"])

    def test_https_downgrade_rejected_before_network_redirect(self):
        handler = collects.HTTPSRedirects()
        request = urllib.request.Request("https://example.com/source")
        with self.assertRaisesRegex(ValueError, "before redirect"):
            handler.redirect_request(request, None, 302, "Found", {}, "http://example.com/source")

    def test_same_address_distinct_carrier_and_colo_are_preserved(self):
        rows = collects.parse_source("WeTest", TABLE)
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["metadata"]["carrier"] for row in rows}, {"联通", "电信"})
        self.assertEqual({row["metadata"]["colo"] for row in rows}, {"LAX", "FRA"})
        self.assertEqual({row["metadata"]["rtt_ms"] for row in rows}, {234, 225})
        self.assertTrue(all(row["metadata"]["observed_at_timezone"] == "unspecified" for row in rows))

    def test_json_hierarchy_and_source_timestamp(self):
        body = json.dumps({"Cf": {"result": {"dianxin": ["104.17.1.1", "8.217.206.24"], "liantong": ["104.17.1.1"]}, "update_time": 1731396002}}).encode()
        rows = collects.parse_source("FaaS", body)
        cf = [row for row in rows if row["ip"] == "104.17.1.1"]
        self.assertEqual({row["metadata"]["carrier"] for row in cf}, {"电信", "联通"})
        self.assertEqual(cf[0]["metadata"]["observed_at"], "1731396002")

    def test_no_script_execution_or_ip_extraction_from_scripts(self):
        self.assertEqual(collects.parse_source("ZXW", b'<html><script>fetch("104.17.1.1")</script><p>loading</p></html>'), [])

    def test_json_address_keys(self):
        rows = collects.parse_source("IPDB", b'{"104.17.1.1:443":{"colo":"HKG"},"[2606:4700::1234]:443":{"colo":"SIN"}}')
        self.assertEqual({row["ip"] for row in rows}, {"104.17.1.1", "2606:4700::1234"})
        self.assertEqual({row["metadata"]["colo"] for row in rows}, {"HKG", "SIN"})

    def test_json_records_with_separate_non_443_port_are_rejected(self):
        rows = collects.parse_source("VPS", b'[{"ip":"104.17.1.1","port":8443},{"ip":"104.17.1.2","port":443}]')
        self.assertEqual([row["ip"] for row in rows], ["104.17.1.2"])

    def test_json_wrapped_html_source(self):
        rows = collects.parse_source("WeTest", json.dumps(TABLE.decode()).encode())
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["metadata"]["colo"] for row in rows}, {"LAX", "FRA"})

    def test_data_row_using_th_is_not_a_column_header(self):
        table = TABLE.replace('<td>联通</td>'.encode(), '<th>联通</th>'.encode()).replace('<td>电信</td>'.encode(), '<th>电信</th>'.encode())
        rows = collects.parse_source("Uouin", table)
        self.assertEqual(len(rows), 2)
        self.assertEqual({row["metadata"]["carrier"] for row in rows}, {"联通", "电信"})

    def test_colo_lookup_placeholder_is_not_a_colo_measurement(self):
        value = collects.metadata({"Colo": "查询"})
        self.assertNotIn("colo", value)
        self.assertEqual(value["colo_raw"], "查询")
        self.assertEqual(value["source_fields"]["Colo"], "查询")

    def test_bracketed_ipv6_text_is_not_json(self):
        rows = collects.parse_source("CMLiussv6", b"[2606:4700::1234]:443#CM\n[2a06:98c1::1234]:443#CM\n")
        self.assertEqual({row["ip"] for row in rows}, {"2606:4700::1234", "2a06:98c1::1234"})
        self.assertTrue(all(row["format"] == "text-list" for row in rows))

    def test_actual_field_names_preserve_measurement_and_creation_time_separately(self):
        result = collects.metadata({"平均延迟": "67.92", "测速时间": "2026-10-08 16:49:04", "createdTime": "2026-09-30 01:30:01"}, ("data", "CM", "3"))
        self.assertEqual(result["rtt"], "67.92")
        self.assertEqual(result["carrier"], "移动")
        self.assertEqual(result["observed_at"], "2026-10-08 16:49:04")
        self.assertEqual(result["source_record_created_at"], "2026-09-30 01:30:01")

    def test_merge_sources_filter_ranges_and_match_output(self):
        with tempfile.TemporaryDirectory() as folder:
            catalog = run(folder, {"WeTest": TABLE, "IPDB": b'[{"ip":"104.24.213.11","colo":"HKG"},{"ip":"8.217.206.24"}]'})
            self.assertEqual(catalog["counts"]["ipv4"], 1)
            self.assertEqual(len(catalog["candidates"][0]["observations"]), 3)
            self.assertFalse(catalog["candidates"][0]["anycast_per_address_verified"])
            self.assertEqual(catalog["candidates"][0]["colos"], ["FRA", "HKG", "LAX"])
            self.assertEqual((Path(folder) / "ipv4.txt").read_text(), "104.24.213.11:443#colo=FRA,HKG,LAX\n")
            self.assertEqual(catalog, json.loads((Path(folder) / "candidates.json").read_text()))
            rejected = next(row for row in catalog["sources"] if row["source"] == "IPDB")
            self.assertEqual(rejected["outside_official_ranges"], 1)

    def test_complete_source_failure_preserves_all_previous_files(self):
        with tempfile.TemporaryDirectory() as folder:
            run(folder, {"WeTest": TABLE})
            paths = list(Path(folder).iterdir())
            before = {path.name: path.read_bytes() for path in paths}
            with self.assertRaisesRegex(ValueError, "previous outputs preserved"):
                run(folder, {})
            self.assertEqual(before, {path.name: path.read_bytes() for path in Path(folder).iterdir()})

    def test_official_range_failure_never_overwrites_output(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "ipv4.txt"
            file.write_text("previous exact bytes\n")
            with self.assertRaises(ValueError):
                collects.collect(folder, lambda url: b"0.0.0.0/0\n")
            self.assertEqual(file.read_text(), "previous exact bytes\n")

    def test_failed_source_retains_its_observations_with_original_time(self):
        with tempfile.TemporaryDirectory() as folder:
            run(folder, {"WeTest": TABLE, "IPDB": b'[{"ip":"104.17.1.2","colo":"HKG"}]'})
            second = run(folder, {"WeTest": TABLE}, "2026-10-08T16:00:00+00:00")
            candidate = next(row for row in second["candidates"] if row["ip"] == "104.17.1.2")
            observation = candidate["observations"][0]
            self.assertTrue(observation["retained"])
            self.assertEqual(observation["fetched_at"], "2026-10-08T12:00:00+00:00")
            self.assertEqual(candidate["colos"], ["HKG"])
            self.assertIn("104.17.1.2:443#colo=HKG\n", (Path(folder) / "ipv4.txt").read_text())

    def test_source_success_replaces_old_data(self):
        with tempfile.TemporaryDirectory() as folder:
            run(folder, {"IPDB": b'["104.17.1.1"]'})
            second = run(folder, {"IPDB": b'["104.17.1.2"]'})
            self.assertEqual([row["ip"] for row in second["candidates"]], ["104.17.1.2"])

    def test_retired_source_is_neither_fetched_nor_retained(self):
        with tempfile.TemporaryDirectory() as folder:
            first = run(folder, {"WeTest": TABLE})
            old = {"source": "Uouin", "fetched_at": "2024-04-09T00:00:00+00:00",
                   "metadata": {"observed_at": "2024/04/09 01:32:04", "colo": "SIN"}, "retained": False}
            first["candidates"][0]["observations"].append(old)
            first["candidates"].append({"ip": "104.17.1.77", "observations": [old]})
            (Path(folder) / "candidates.json").write_text(json.dumps(first))
            fetched = []
            fixture = fetcher({"WeTest": TABLE})

            def fetch(url):
                fetched.append(url)
                return fixture(url)

            with contextlib.redirect_stdout(io.StringIO()):
                second = collects.collect(folder, fetch)
            self.assertNotIn("https://api.uouin.com/cloudflare.html", fetched)
            self.assertNotIn("Uouin", {row["source"] for row in second["sources"]})
            self.assertEqual([row["ip"] for row in second["candidates"]], ["104.24.213.11"])
            self.assertEqual(second["candidates"][0]["colos"], ["FRA", "LAX"])
            self.assertTrue(all(row["source"] != "Uouin" for row in second["candidates"][0]["observations"]))

    def test_missing_fresh_family_preserves_legacy_family(self):
        with tempfile.TemporaryDirectory() as folder:
            (Path(folder) / "ipv6.txt").write_text("ipv6.list.updated.at#old\n[2606:4700::1234]:443#legacy\n")
            catalog = run(folder, {"WeTest": TABLE})
            ipv6 = next(row for row in catalog["candidates"] if row["family"] == 6)
            self.assertEqual(ipv6["observations"][0]["source"], "legacy-import")
            self.assertTrue(ipv6["observations"][0]["retained"])
            self.assertEqual(ipv6["colos"], [])
            self.assertEqual((Path(folder) / "ipv6.txt").read_text(), "[2606:4700::1234]:443#colo=unknown\n")

    def test_unsupported_previous_catalog_is_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            file = Path(folder) / "candidates.json"
            file.write_text('{"schema_version":99,"candidates":[]}')
            with self.assertRaisesRegex(ValueError, "previous catalog schema invalid"):
                run(folder, {"WeTest": TABLE})
            self.assertEqual(file.read_text(), '{"schema_version":99,"candidates":[]}')


if __name__ == "__main__":
    unittest.main()
