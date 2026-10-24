"""Subdomain discovery: certificate transparency, passive APIs, DNS brute force."""
import random
import re
import string
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

import requests

from . import USER_AGENT
from .dnsutil import query_ips


def _get(url: str, timeout: float, retries: int = 2):
    """GET with a few retries - crt.sh in particular is often flaky."""
    for attempt in range(retries + 1):
        try:
            r = requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
            if r.status_code == 200:
                return r
        except requests.RequestException:
            pass
        time.sleep(1.5 * (attempt + 1))
    return None


# --------------------------------------------------------------------------- #
# Passive sources
# --------------------------------------------------------------------------- #
def source_crtsh(domain: str, timeout: float):
    """Certificate Transparency via crt.sh. Returns (names, cert_records)."""
    r = _get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=max(timeout, 30))
    if r is None:
        return set(), []
    try:
        data = r.json()
    except ValueError:
        return set(), []
    names, certs, seen = set(), [], set()
    for row in data:
        for n in str(row.get("name_value", "")).splitlines():
            names.add(n)
        cid = row.get("id")
        if cid in seen:
            continue
        seen.add(cid)
        certs.append({
            "id": cid,
            "issuer": row.get("issuer_name", ""),
            "common_name": row.get("common_name", ""),
            "not_before": row.get("not_before"),
            "not_after": row.get("not_after"),
        })
    return names, certs


def source_certspotter(domain: str, timeout: float):
    """Second CT source (free tier, rate limited)."""
    url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
           "&include_subdomains=true&expand=dns_names")
    r = _get(url, timeout=timeout, retries=1)
    names = set()
    if r is None:
        return names, []
    try:
        for row in r.json():
            names.update(row.get("dns_names", []))
    except (ValueError, AttributeError):
        pass
    return names, []


def source_hackertarget(domain: str, timeout: float):
    r = _get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=timeout, retries=1)
    names = set()
    if r is None or "error" in r.text[:50].lower() or "API count exceeded" in r.text:
        return names, []
    for line in r.text.splitlines():
        host = line.split(",")[0].strip()
        if host:
            names.add(host)
    return names, []


def source_anubis(domain: str, timeout: float):
    r = _get(f"https://jldc.me/anubis/subdomains/{domain}", timeout=timeout, retries=1)
    names = set()
    if r is None:
        return names, []
    try:
        names.update(r.json())
    except (ValueError, TypeError):
        pass
    return names, []


PASSIVE_SOURCES = {
    "crt.sh": source_crtsh,
    "certspotter": source_certspotter,
    "hackertarget": source_hackertarget,
    "anubis": source_anubis,
}


def clean_name(name: str, domain: str):
    """Normalise a hostname and keep it only if it belongs to the target domain."""
    n = name.strip().lower().lstrip("*.").rstrip(".")
    if not n or " " in n or "@" in n or "/" in n:
        return None
    if n == domain or n.endswith("." + domain):
        return n
    return None


def passive_enum(domain: str, timeout: float, log):
    """Query all passive sources in parallel. Returns (found, certs)."""
    found, certs = {}, []

    def run(item):
        label, fn = item
        try:
            return label, fn(domain, timeout)
        except Exception as exc:  # a broken source must never kill the run
            log.debug(f"{label} failed: {exc}")
            return label, (set(), [])

    with ThreadPoolExecutor(max_workers=len(PASSIVE_SOURCES)) as ex:
        for label, (names, cert_rows) in ex.map(run, PASSIVE_SOURCES.items()):
            kept = 0
            for raw in names:
                n = clean_name(raw, domain)
                if n:
                    found.setdefault(n, set()).add(label)
                    kept += 1
            if cert_rows:
                certs.extend(cert_rows)
            log.info(f"  {label:<13} -> {len(set(clean_name(x, domain) for x in names) - {None})} names")
    return found, certs


def summarize_certs(certs: list) -> dict:
    """Aggregate certificate-transparency records into report-friendly stats."""
    if not certs:
        return {"total": 0}
    issuers = Counter()
    for c in certs:
        m = re.search(r"O=([^,]+)", c.get("issuer", "")) or re.search(r"CN=([^,]+)", c.get("issuer", ""))
        issuers[m.group(1).strip() if m else "unknown"] += 1
    starts = sorted(c["not_before"] for c in certs if c.get("not_before"))
    return {
        "total": len(certs),
        "wildcards": sum(1 for c in certs if str(c.get("common_name", "")).startswith("*")),
        "issuers": issuers.most_common(8),
        "first_seen": starts[0][:10] if starts else None,
        "last_seen": starts[-1][:10] if starts else None,
    }


# --------------------------------------------------------------------------- #
# Active: DNS brute force
# --------------------------------------------------------------------------- #
def detect_wildcard(domain: str, resolver) -> set:
    """If random labels resolve, the zone has wildcard DNS - brute force must filter it."""
    ips = set()
    for _ in range(2):
        label = "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
        ips.update(query_ips(resolver, f"{label}.{domain}"))
    return ips


def load_wordlist(path: str) -> list:
    with open(path, encoding="utf-8", errors="ignore") as fh:
        words = [w.strip().lower() for w in fh if w.strip() and not w.startswith("#")]
    return list(dict.fromkeys(words))


def brute_force(domain: str, words: list, resolver, threads: int, wildcard_ips: set):
    found = {}

    def check(word):
        name = f"{word}.{domain}"
        ips = query_ips(resolver, name)
        if not ips:
            return None
        if wildcard_ips and set(ips) <= wildcard_ips:
            return None
        return name

    with ThreadPoolExecutor(max_workers=threads) as ex:
        for name in ex.map(check, words):
            if name:
                found.setdefault(name, set()).add("bruteforce")
    return found
