#!/usr/bin/env python3
"""ipscout - enrich a list of IP addresses with reverse DNS, ownership/geolocation
and (optionally) VirusTotal reputation.

Standard library only: no pip install needed.
"""

from __future__ import annotations

import argparse
import csv
import http.client
import ipaddress
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor

__version__ = "0.1.0"

USER_AGENT = f"ipscout/{__version__}"
IPINFO_URL = "https://ipinfo.io/{ip}/json"
VT_URL = "https://www.virustotal.com/api/v3/ip_addresses/{ip}"
VT_GUI_URL = "https://www.virustotal.com/gui/ip-address/{ip}"
MAX_RESPONSE_BYTES = 1_000_000
CSV_FORMULA_CHARS = ("=", "+", "-", "@", "\t", "\r")

FIELDS = [
    "ip", "scope", "rdns", "country", "region", "city", "asn", "org",
    "vt_verdict", "vt_malicious", "vt_suspicious", "vt_harmless",
    "vt_undetected", "vt_reputation", "vt_link", "error",
]


class RateLimited(Exception):
    """Raised when an API answers HTTP 429. Carries no URL, so tokens can't leak."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects: urllib would otherwise forward our API-key header to
    whatever host the redirect points at."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(NoRedirect)


def clean(value):
    """Drop control characters (e.g. ANSI escapes) from text that came from
    DNS or an API, so it can't mess with the terminal or files."""
    return "".join(ch for ch in str(value or "") if ch.isprintable())


# --------------------------------------------------------------------------- input

def load_ips(lines):
    """Parse IPs from an iterable of lines.

    Blank lines and '#' comments are ignored, duplicates are dropped (first one
    wins, order kept). Returns (ips, invalid) where invalid is a list of
    (line_number, text) tuples.
    """
    seen, ips, invalid = set(), [], []
    for lineno, line in enumerate(lines, 1):
        entry = line.split("#", 1)[0].strip()
        if not entry:
            continue
        try:
            ip = ipaddress.ip_address(entry)
        except ValueError:
            invalid.append((lineno, entry))
            continue
        if ip not in seen:
            seen.add(ip)
            ips.append(ip)
    return ips, invalid


# ----------------------------------------------------------------------- lookups

def http_get_json(url, headers=None, timeout=15):
    """GET a URL and decode JSON. Returns (status_code, data_or_None)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with _opener.open(req, timeout=timeout) as resp:
            body = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ValueError("response too large")
            data = json.loads(body)
            return resp.status, data if isinstance(data, dict) else None
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise RateLimited() from None
        return e.code, None


def reverse_dns(ip):
    try:
        return clean(socket.gethostbyaddr(str(ip))[0])
    except (socket.herror, socket.gaierror, OSError):
        return ""


def parse_org(org):
    """Split ipinfo's 'AS15169 Google LLC' into ('AS15169', 'Google LLC')."""
    if org and org.startswith("AS") and " " in org:
        asn, name = org.split(" ", 1)
        return asn, name
    return "", org or ""


def ipinfo_lookup(ip, token=None):
    url = IPINFO_URL.format(ip=ip)
    if token:
        url += "?" + urllib.parse.urlencode({"token": token})
    status, data = http_get_json(url)
    if status != 200 or not data:
        return {"error": f"ipinfo: unexpected response (HTTP {status})"}
    asn, org = parse_org(clean(data.get("org")))
    return {
        "country": clean(data.get("country")),
        "region": clean(data.get("region")),
        "city": clean(data.get("city")),
        "asn": asn,
        "org": org,
    }


def vt_verdict(stats):
    if not stats:
        return ""
    if stats.get("malicious", 0) > 0:
        return "MALICIOUS"
    if stats.get("suspicious", 0) > 0:
        return "SUSPICIOUS"
    return "clean"


def virustotal_lookup(ip, api_key):
    status, data = http_get_json(VT_URL.format(ip=ip), headers={"x-apikey": api_key})
    if status == 401:
        raise SystemExit("VirusTotal rejected the API key (HTTP 401).")
    if status == 404:
        return {"vt_verdict": "not found"}
    if status != 200 or not data:
        return {"error": f"VirusTotal: unexpected response (HTTP {status})"}
    attrs = (data.get("data") or {}).get("attributes") or {}
    stats = {k: v for k, v in (attrs.get("last_analysis_stats") or {}).items()
             if isinstance(v, int)}
    return {
        "vt_verdict": vt_verdict(stats),
        "vt_malicious": stats.get("malicious", 0),
        "vt_suspicious": stats.get("suspicious", 0),
        "vt_harmless": stats.get("harmless", 0),
        "vt_undetected": stats.get("undetected", 0),
        "vt_reputation": attrs.get("reputation", 0) if isinstance(attrs.get("reputation"), int) else 0,
        "vt_link": VT_GUI_URL.format(ip=ip),
    }


def with_retry(func, *args, wait=60, log=print):
    """Call func, waiting and retrying once if the API rate-limits us.
    Network and parsing errors become an 'error' field instead of a crash."""
    for attempt in (1, 2):
        try:
            return func(*args)
        except RateLimited:
            if attempt == 2:
                return {"error": "rate limited"}
            log(f"  rate limited, waiting {wait}s...")
            time.sleep(wait)
        except urllib.error.URLError as e:
            return {"error": f"network error: {clean(e.reason)}"}
        except (OSError, http.client.HTTPException, ValueError) as e:
            return {"error": f"{type(e).__name__}: {clean(e)}"}


def enrich(ip, ipinfo_token=None, log=print):
    """Reverse DNS + ownership for one IP. Private/reserved IPs get no external lookup."""
    row = {"ip": str(ip), "scope": "public" if ip.is_global else "private/reserved"}
    row["rdns"] = reverse_dns(ip)
    if ip.is_global:
        row.update(with_retry(ipinfo_lookup, ip, ipinfo_token, log=log))
    return row


# ------------------------------------------------------------------------ output

def merge_error(row, extra):
    """Merge a lookup result into a row without overwriting an earlier error."""
    err = extra.pop("error", None)
    row.update(extra)
    if err:
        row["error"] = "; ".join(filter(None, [row.get("error", ""), err]))


def vt_summary(row):
    """Short VirusTotal cell for the console, e.g. 'MALICIOUS (5 mal, 1 sus)'."""
    if "vt_malicious" in row:
        return f"{row['vt_verdict']} ({row['vt_malicious']} mal, {row['vt_suspicious']} sus)"
    return row.get("vt_verdict") or ("-" if row["scope"] == "public" else "")


def print_table(rows, show_vt, out=sys.stdout):
    cols = [("IP", "ip", 39), ("CC", "country", 2), ("ASN", "asn", 9),
            ("Organisation", "org", 30), ("Reverse DNS", "rdns", 40)]
    if show_vt:
        cols.append(("VirusTotal", "vt", 28))
    display = []
    for r in rows:
        d = dict(r, vt=vt_summary(r))
        if r["scope"] != "public":
            d["org"] = "(private/reserved)"
        display.append(d)
    widths = [min(w, max([len(h)] + [len(str(d.get(k, ""))) for d in display]))
              for h, k, w in cols]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*[h for h, _, _ in cols]), file=out)
    print(fmt.format(*["-" * w for w in widths]), file=out)
    for d in display:
        print(fmt.format(*[str(d.get(k, ""))[:w] for (_, k, _), w in zip(cols, widths)]), file=out)


def csv_safe(value):
    """Stop spreadsheet apps treating attacker-controlled text (e.g. a PTR record
    of '=HYPERLINK(...)') as a formula, by prefixing it with a quote."""
    if isinstance(value, str) and value.startswith(CSV_FORMULA_CHARS):
        return "'" + value
    return value


def write_csv(rows, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows({k: csv_safe(v) for k, v in r.items()} for r in rows)


def write_json(rows, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump([{k: r.get(k, "") for k in FIELDS} for r in rows], f, indent=2)


# -------------------------------------------------------------------------- main

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Look up reverse DNS, country and owner for a list of IPs, "
                    "with optional VirusTotal reputation.",
        epilog="API keys are read from the VT_API_KEY and IPINFO_TOKEN environment "
               "variables. Prefer these over command-line flags so keys don't end up "
               "in your shell history.",
    )
    p.add_argument("file", help="text file with one IP per line ('-' for stdin)")
    p.add_argument("--csv", metavar="PATH", help="also write results to CSV")
    p.add_argument("--json", metavar="PATH", help="also write results to JSON")
    p.add_argument("--vt", action="store_true",
                   help="run VirusTotal reputation lookups (needs VT_API_KEY)")
    p.add_argument("--vt-delay", type=float, default=15.0, metavar="SECONDS",
                   help="pause between VirusTotal calls (default 15, the free tier's 4/min; "
                        "use 0 for a premium key)")
    p.add_argument("--workers", type=int, default=8,
                   help="parallel reverse DNS / ipinfo lookups (default 8)")
    p.add_argument("-q", "--quiet", action="store_true", help="no progress messages")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    log = (lambda *a, **k: None) if args.quiet else (lambda *a, **k: print(*a, file=sys.stderr, **k))

    vt_key = os.environ.get("VT_API_KEY", "").strip()
    if args.vt and not vt_key:
        sys.exit("--vt needs a VirusTotal API key in the VT_API_KEY environment variable.")
    if args.vt and (not vt_key.isprintable() or any(ch.isspace() for ch in vt_key)):
        # http.client would echo the bad value (the key) in its error message
        sys.exit("VT_API_KEY contains spaces or control characters; check how it was set.")
    ipinfo_token = os.environ.get("IPINFO_TOKEN", "").strip() or None

    try:
        if args.file == "-":
            ips, invalid = load_ips(sys.stdin)
        else:
            with open(args.file, encoding="utf-8") as f:
                ips, invalid = load_ips(f)
    except OSError as e:
        sys.exit(f"Cannot read {args.file}: {e.strerror}")

    for lineno, text in invalid:
        log(f"warning: line {lineno}: not an IP address: {text!r}")
    if not ips:
        sys.exit("No valid IP addresses found.")

    log(f"Looking up {len(ips)} IP(s)...")
    with ThreadPoolExecutor(max_workers=max(1, args.workers)) as pool:
        rows = list(pool.map(lambda ip: enrich(ip, ipinfo_token, log), ips))

    if args.vt:
        public = [(ip, row) for ip, row in zip(ips, rows) if ip.is_global]
        if public and args.vt_delay:
            log(f"VirusTotal: {len(public)} lookup(s), ~{int(len(public) * args.vt_delay)}s "
                f"at {args.vt_delay:g}s apart (free tier)...")
        for i, (ip, row) in enumerate(public):
            if i and args.vt_delay:
                time.sleep(args.vt_delay)
            log(f"  [{i + 1}/{len(public)}] {ip}")
            merge_error(row, with_retry(virustotal_lookup, ip, vt_key, log=log))

    print_table(rows, show_vt=args.vt)
    if args.csv:
        write_csv(rows, args.csv)
        log(f"CSV written to {args.csv}")
    if args.json:
        write_json(rows, args.json)
        log(f"JSON written to {args.json}")

    errors = [r for r in rows if r.get("error")]
    for r in errors:
        log(f"error: {r['ip']}: {r['error']}")
    return 1 if errors else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
