#!/usr/bin/env python3
"""Collect published CF candidates and provenance; never probe candidate IPs."""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import sys
import tempfile
import time
import urllib.request
from urllib.parse import urlsplit
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path

SOURCES = (
    ("Uouin", "https://api.uouin.com/cloudflare.html"),
    ("ZXW", "https://ip.164746.xyz"),
    ("IPDB", "https://ipdb.api.030101.xyz/?type=bestcf"),
    ("WeTestV6", "https://www.wetest.vip/page/cloudflare/address_v6.html"),
    ("IPDBv6", "https://ipdb.api.030101.xyz/?type=bestcfv6"),
    ("CFYes", "https://cf.090227.xyz/CloudFlareYes"),
    ("HaoGG", "https://ip.haogege.xyz"),
    ("VPS", "https://vps789.com/openApi/cfIpApi"),
    ("WeTest", "https://www.wetest.vip/page/cloudflare/address_v4.html"),
    ("CMLiuss", "https://addressesapi.090227.xyz/ct"),
    ("CMLiussv6", "https://addressesapi.090227.xyz/cmcc-ipv6"),
    ("FaaS", "https://raw.githubusercontent.com/xingpingcn/enhanced-FaaS-in-China/refs/heads/main/Cf.json"),
)
RANGE_URLS = {
    4: "https://www.cloudflare.com/ips-v4/",
    6: "https://www.cloudflare.com/ips-v6/",
}
ANYCAST_DOC = "https://developers.cloudflare.com/fundamentals/concepts/cloudflare-ip-addresses/"
MAX_BODY = 2 * 1024 * 1024
MAX_ROWS = 10000
MAX_CANDIDATES = 20000
SCHEMA_VERSION = 1
TOKEN = re.compile(
    r"(?<![\w:.])(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?(?![\w:.])"
    r"|\[[0-9a-fA-F:.]+\](?::\d{1,5})?"
    r"|(?<![\w:.])[0-9a-fA-F]*:[0-9a-fA-F:.]+(?![\w:.])"
)
DEFAULT_COLUMNS = {
    "WeTest": ["carrier", "address", "bandwidth", "speed", "rtt", "colo", "observed_at"],
    "WeTestV6": ["carrier", "address", "bandwidth", "speed", "rtt", "colo", "observed_at"],
    "Uouin": ["index", "carrier", "address", "loss", "rtt", "speed", "bandwidth", "colo", "observed_at"],
}
ALIASES = {
    "carrier": {"carrier", "line", "isp", "线路", "线路名称", "运营商", "网络运营商"},
    "colo": {"colo", "datacenter", "数据中心", "机房", "节点", "node"},
    "rtt": {"rtt", "rttms", "latency", "latencyms", "delay", "delayms", "ping", "pingms", "延迟", "平均延迟", "往返延迟"},
    "loss": {"loss", "lossrate", "packetloss", "丢包", "丢包率"},
    "speed": {"speed", "下载速度", "速度", "峰值速度"},
    "bandwidth": {"bandwidth", "带宽", "网络带宽"},
    "observed_at": {"observedat", "updatetime", "updatedat", "timestamp", "time", "date", "更新时间", "时间", "测试时间", "测速时间"},
    "source_record_created_at": {"createdat", "createdtime", "创建时间"},
    "anycast_claim": {"anycast", "isanycast", "routingtype", "routetype"},
}
CARRIERS = {"dianxin": "电信", "ct": "电信", "liantong": "联通", "cu": "联通", "yidong": "移动", "cm": "移动", "cmcc": "移动"}


def utc_now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def compact(value):
    return " ".join(str(value).split())[:240]


def key_name(value):
    return re.sub(r"[\W_]", "", str(value).lower())


def addresses(text):
    """Return unambiguous IP/443 values. Reject explicit non-443 ports."""
    result = []
    for match in TOKEN.finditer(str(text)):
        token = match.group(0)
        port = 443
        if token.startswith("["):
            closing = token.index("]")
            host = token[1:closing]
            if token[closing + 1:]:
                port = int(token[closing + 2:])
        elif token.count(":") == 1 and "." in token:
            host, raw_port = token.rsplit(":", 1)
            port = int(raw_port)
        else:
            host = token
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            continue
        if port == 443 and ip.is_global:
            result.append(str(ip))
    return sorted(set(result), key=lambda item: (ipaddress.ip_address(item).version, int(ipaddress.ip_address(item))))


def metadata(fields, context=()):
    scalars = {compact(k): compact(v) for k, v in fields.items()
               if isinstance(v, (str, int, float, bool)) and len(str(k)) < 120}
    result = {"source_fields": scalars}
    for target, aliases in ALIASES.items():
        for name, value in scalars.items():
            if key_name(name) in aliases:
                result[target] = value
                break
    if "carrier" not in result:
        for part in reversed(context):
            if str(part).lower() in CARRIERS:
                result["carrier"] = CARRIERS[str(part).lower()]
                break
    if "rtt" in result:
        number = re.fullmatch(r"([\d.]+)\s*(ms|毫秒)", result["rtt"], re.I)
        if number:
            result["rtt_ms"] = float(number[1])
    if "loss" in result:
        number = re.fullmatch(r"([\d.]+)\s*%", result["loss"])
        if number:
            result["loss_percent"] = float(number[1])
    # Source time is kept verbatim: HTML tables usually do not specify a timezone.
    result["observed_at_timezone"] = "unspecified" if "observed_at" in result else None
    if re.fullmatch(r"\d{10}", result.get("observed_at", "")):
        epoch = int(result["observed_at"])
        if 946684800 <= epoch <= 4102444800:
            result["observed_at_utc"] = datetime.fromtimestamp(epoch, timezone.utc).isoformat()
            result["observed_at_timezone"] = "UTC"
    if context:
        result["source_context"] = "/".join(map(str, context))[:240]
    return result


class Tables(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.rows, self.blocks = [], []
        self.row, self.cells, self.cell = None, None, None
        self.header = False
        self.block, self.block_tag = None, None
        self.ignored = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self.ignored += 1
        if tag == "tr":
            self.row, self.header = [], False
        if tag in ("td", "th") and self.row is not None:
            self.cell = []
            self.header = self.header or tag == "th"
        if tag in ("pre", "li") and self.block is None:
            self.block, self.block_tag = [], tag

    def handle_data(self, data):
        if self.ignored:
            return
        if self.cell is not None:
            self.cell.append(data)
        if self.block is not None:
            self.block.append(data)

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.ignored = max(0, self.ignored - 1)
        if tag in ("td", "th") and self.row is not None and self.cell is not None:
            self.row.append(compact(" ".join(self.cell)))
            self.cell = None
        if tag == "tr" and self.row is not None:
            self.rows.append((self.row, self.header))
            self.row = None
        if tag == self.block_tag and self.block is not None:
            self.blocks.append(" ".join(self.block))
            self.block, self.block_tag = None, None


def parse_source(source, body):
    """Parse JSON records, table rows, or published text data without JavaScript."""
    text = body.decode("utf-8-sig", errors="replace")
    rows = []

    def add(ips, fields, kind, context=()):
        for ip in ips:
            rows.append({"ip": ip, "metadata": metadata(fields, context), "format": kind})
            if len(rows) > MAX_ROWS:
                raise ValueError("source record limit exceeded")

    stripped = text.lstrip()
    bracket_address_list = bool(re.match(r"^\[[0-9a-fA-F:.]+\](?::\d+)?(?:\s|#|$)", stripped))
    if stripped.startswith("{") or (stripped.startswith("[") and not bracket_address_list):
        payload = json.loads(text)

        def walk(value, context=(), inherited=None):
            if len(context) > 20:
                raise ValueError("JSON nesting limit exceeded")
            inherited = inherited or {}
            if isinstance(value, dict):
                fields = {**inherited, **{str(k): v for k, v in value.items()
                          if isinstance(v, (str, int, float, bool))}}
                for key, child in value.items():
                    key_ips = addresses(key)
                    if key_ips and TOKEN.fullmatch(str(key).strip()):
                        add(key_ips, fields, "json-record", context + (key,))
                    if isinstance(child, (dict, list)):
                        walk(child, context + (key,), fields)
                    elif isinstance(child, str):
                        ips = addresses(child)
                        # Scalar API records must contain address data, not arbitrary prose.
                        if ips and "://" not in child and (len(child.split()) <= 3 or key_name(key) in {"ip", "address", "addr", "ipv4", "ipv6"}):
                            add(ips, fields, "json-record", context + (key,))
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    walk(child, context + (str(index),), inherited)
            elif isinstance(value, str):
                add(addresses(value), inherited, "json-list", context)

        walk(payload)
    elif re.search(r"<(?:html|table|tr|pre|li|!doctype)\b", text, re.I):
        parser = Tables()
        parser.feed(text)
        headers = DEFAULT_COLUMNS.get(source, [])
        for cells, header in parser.rows:
            ips = [ip for cell in cells for ip in addresses(cell)]
            if header or (not ips and cells and any(key_name(cell) in {"ip", "address", "优选地址", "优选ip"} for cell in cells)):
                headers = cells
                continue
            if ips:
                fields = {(headers[i] if i < len(headers) else f"column_{i + 1}"): value for i, value in enumerate(cells)}
                add(ips, fields, "html-table")
        if not rows:
            for block in parser.blocks:
                add(addresses(block), {}, "html-published-list")
    else:
        for line in text.splitlines():
            if line.strip() and not line.lstrip().startswith(("#", "//")):
                add(addresses(line), {"list_label": line.split("#", 1)[1]} if "#" in line else {}, "text-list")
    # Preserve distinct carrier/colo measurements of the same address.
    unique = {json.dumps(row, sort_keys=True, ensure_ascii=False): row for row in rows}
    return list(unique.values())


class HTTPSRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        if urlsplit(newurl).scheme.lower() != "https":
            raise ValueError("HTTPS downgrade rejected before redirect")
        return super().redirect_request(request, response, code, message, headers, newurl)


def fetch_http(url):
    if not url.startswith("https://"):
        raise ValueError("HTTPS sources required")
    request = urllib.request.Request(url, headers={"User-Agent": "BestCFip-provenance-collector/1.0", "Accept": "application/json,text/html,text/plain"})
    started = time.monotonic()
    opener = urllib.request.build_opener(HTTPSRedirects())
    with opener.open(request, timeout=20) as response:
        if not response.url.startswith("https://"):
            raise ValueError("HTTPS downgrade rejected")
        chunks, size = [], 0
        while True:
            chunk = response.read(65536)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_BODY or time.monotonic() - started > 45:
                raise ValueError("source response budget exceeded")
        return b"".join(chunks)


def official_ranges(fetcher):
    ranges, evidence = [], []
    for family, url in RANGE_URLS.items():
        raw = fetcher(url)
        current = [ipaddress.ip_network(line.strip()) for line in raw.decode("ascii").splitlines() if line.strip()]
        if len(current) < (10 if family == 4 else 5) or any(net.version != family or not net.network_address.is_global for net in current):
            raise ValueError("invalid official address ranges")
        ranges.extend(current)
        evidence.append({"family": family, "url": url, "sha256": hashlib.sha256(raw).hexdigest(), "prefixes": [str(net) for net in current]})
    return ranges, evidence


def matching_prefix(ip, ranges):
    address = ipaddress.ip_address(ip)
    if not address.is_global:
        return None
    for network in ranges:
        if address.version == network.version and address in network:
            return str(network)
    return None


def previous_observations(output):
    catalog = output / "candidates.json"
    if catalog.exists():
        data = json.loads(catalog.read_text(encoding="utf-8"))
        if data.get("schema_version") != SCHEMA_VERSION or not isinstance(data.get("candidates"), list):
            raise ValueError("previous catalog schema invalid; preserve outputs")
        return [(row["ip"], observation) for row in data["candidates"] for observation in row["observations"]]
    imported = []
    for family in (4, 6):
        path = output / f"ipv{family}.txt"
        if path.exists():
            for ip in addresses(path.read_text(encoding="utf-8")):
                if ipaddress.ip_address(ip).version == family:
                    imported.append((ip, {"source": "legacy-import", "url": None, "fetched_at": None,
                                         "format": "previous-ip-list", "metadata": {}, "retained": True}))
    return imported


def render_text(candidates, family):
    return "".join(f"[{row['ip']}]:443\n" if family == 6 else f"{row['ip']}:443\n"
                   for row in candidates if row["family"] == family)


def publish(output, files):
    """Stage and validate all bytes first. Failed collection never calls this."""
    staged = []
    try:
        for name, text in files.items():
            fd, filename = tempfile.mkstemp(prefix=f".{name}.", dir=output)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(filename, 0o644)
            staged.append((filename, output / name))
        for filename, path in staged:
            os.replace(filename, path)
    finally:
        for filename, _ in staged:
            if os.path.exists(filename):
                os.unlink(filename)


def collect(output, fetcher=fetch_http, now=None):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    now = now or utc_now()
    ranges, range_evidence = official_ranges(fetcher)
    previous = previous_observations(output)
    fresh, statuses, successful_sources = [], [], set()
    for source, url in SOURCES:
        status = {"source": source, "url": url, "attempted_at": now, "ok": False, "parsed": 0, "accepted": 0, "outside_official_ranges": 0}
        try:
            raw = fetcher(url)
            status.update(response_bytes=len(raw), body_sha256=hashlib.sha256(raw).hexdigest())
            if re.search(rb"<(?:html|table|!doctype)\b", raw, re.I):
                title = re.search(rb"<title[^>]*>(.*?)</title>", raw, re.I | re.S)
                status["html_title"] = compact(title[1].decode("utf-8", errors="replace")) if title else None
                status["html_table_count"] = len(re.findall(rb"<table\b", raw, re.I))
                status["html_row_count"] = len(re.findall(rb"<tr\b", raw, re.I))
            rows = parse_source(source, raw)
            if not rows:
                raise ValueError("no supported published address records")
            status.update(ok=True, parsed=len(rows), body_sha256=hashlib.sha256(raw).hexdigest())
            successful_sources.add(source)
            for row in rows:
                if not matching_prefix(row["ip"], ranges):
                    status["outside_official_ranges"] += 1
                    continue
                fresh.append((row["ip"], {"source": source, "url": url, "fetched_at": now,
                                           "format": row["format"], "metadata": row["metadata"], "retained": False}))
                status["accepted"] += 1
        except Exception as error:
            status["error"] = type(error).__name__ + ": " + compact(error)
        statuses.append(status)
        print(json.dumps({key: status[key] for key in ("source", "ok", "parsed", "accepted", "outside_official_ranges")}), flush=True)
    if not fresh:
        raise ValueError("no fresh candidate in official ranges; previous outputs preserved")
    fresh_families = {ipaddress.ip_address(ip).version for ip, _ in fresh}
    retained = []
    for ip, observation in previous:
        if not matching_prefix(ip, ranges):
            continue
        source = observation.get("source")
        if source == "legacy-import":
            keep = ipaddress.ip_address(ip).version not in fresh_families
        else:
            keep = source not in successful_sources and source in {name for name, _ in SOURCES}
        if keep:
            retained.append((ip, {**observation, "retained": True}))
    combined = {}
    for ip, observation in fresh + retained:
        combined.setdefault(ip, {})[json.dumps(observation, sort_keys=True, ensure_ascii=False)] = observation
    if len(combined) > MAX_CANDIDATES:
        raise ValueError("candidate limit exceeded; previous outputs preserved")
    candidates = []
    for ip in sorted(combined, key=lambda item: (ipaddress.ip_address(item).version, int(ipaddress.ip_address(item)))):
        candidates.append({"ip": ip, "port": 443, "family": ipaddress.ip_address(ip).version,
                           "cf_official_prefix": matching_prefix(ip, ranges),
                           "network_class": "cloudflare_published_proxy_range", "anycast_per_address_verified": False,
                           "observations": sorted(combined[ip].values(), key=lambda value: json.dumps(value, sort_keys=True, ensure_ascii=False))})
    catalog = {"schema_version": SCHEMA_VERSION, "generated_at": now, "candidate_probing": False,
               "anycast_documentation": ANYCAST_DOC,
               "evidence_limit": "Official range membership and published source observations; not per-address Anycast verification or local reachability.",
               "range_sources": range_evidence, "sources": statuses, "candidates": candidates,
               "counts": {"ipv4": sum(row["family"] == 4 for row in candidates), "ipv6": sum(row["family"] == 6 for row in candidates),
                          "fresh_observations": len(fresh), "retained_observations": len(retained),
                          "source_success": sum(status["ok"] for status in statuses), "source_total": len(SOURCES)}}
    files = {"ipv4.txt": render_text(candidates, 4), "ipv6.txt": render_text(candidates, 6),
             "candidates.json": json.dumps(catalog, ensure_ascii=False, indent=2, sort_keys=True) + "\n"}
    if json.loads(files["candidates.json"])["counts"] != catalog["counts"]:
        raise ValueError("output validation failed")
    for family in (4, 6):
        actual = set(addresses(files[f"ipv{family}.txt"]))
        expected = {row["ip"] for row in candidates if row["family"] == family}
        if actual != expected:
            raise ValueError("text and catalog disagree")
    publish(output, files)
    return catalog


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", default=".")
    args = parser.parse_args()
    try:
        catalog = collect(args.output_dir)
    except Exception as error:
        print("COLLECTION_FAILED: " + type(error).__name__ + ": " + compact(error), file=sys.stderr)
        return 1
    print(json.dumps({"published": True, "generated_at": catalog["generated_at"], **catalog["counts"]}), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
