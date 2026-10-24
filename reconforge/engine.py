"""The recon pipeline: WHOIS -> DNS -> subdomains -> resolve -> probe -> analyse -> report."""
import json
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from pathlib import Path

from . import __version__
from .analysis import build_findings
from .dnsinfo import collect_records, email_security, try_zone_transfer
from .dnsutil import make_resolver, resolve_host
from .fingerprint import probe_host
from .report import render_html
from .subdomains import (brute_force, clean_name, detect_wildcard, load_wordlist,
                         passive_enum, summarize_certs)
from .whoisinfo import lookup as whois_lookup


def _merge(hosts: dict, found: dict):
    for name, sources in found.items():
        hosts.setdefault(name, {"name": name, "sources": set()})["sources"].update(sources)


def run_recon(domain: str, opt, log) -> dict:
    started = datetime.now()
    t0 = time.time()
    passive = opt.passive
    res = {
        "meta": {"domain": domain, "mode": "passive" if passive else "full",
                 "started": started.strftime("%Y-%m-%d %H:%M:%S"), "version": __version__},
        "whois": {}, "dns": {}, "email_security": {}, "axfr": [], "certificates": {},
        "wildcard_ips": [], "subdomains": [], "findings": [],
    }
    resolver = make_resolver(opt.resolvers, timeout=opt.timeout / 2)
    hosts = {domain: {"name": domain, "sources": {"target"}}}

    # 1 - WHOIS
    log.step("1/6  WHOIS")
    res["whois"] = whois_lookup(domain, timeout=opt.timeout)
    w = res["whois"]
    if w.get("error"):
        log.warn(w["error"])
    else:
        log.ok(f"registrar={w.get('registrar', '?')}  expires={w.get('expires', '?')}")

    # 2 - DNS
    log.step("2/6  DNS records & email security")
    res["dns"] = collect_records(domain, resolver)
    res["email_security"] = email_security(domain, res["dns"], resolver)
    log.ok(", ".join(f"{k}:{len(v)}" for k, v in res["dns"].items()) or "no records")
    if not passive:
        res["axfr"] = try_zone_transfer(domain, res["dns"].get("NS", []), resolver, opt.timeout)
        for z in res["axfr"]:
            if z["vulnerable"]:
                log.warn(f"ZONE TRANSFER ALLOWED on {z['ns']} ({len(z['names'])} names)")
                _merge(hosts, {n: {"axfr"} for n in (clean_name(x, domain) for x in z["names"]) if n})

    # 3 - passive enumeration
    log.step("3/6  Subdomain enumeration (certificate transparency + passive sources)")
    found, certs = passive_enum(domain, opt.timeout, log)
    _merge(hosts, found)
    res["certificates"] = summarize_certs(certs)
    log.ok(f"{len(found)} unique names from passive sources")

    # 4 - brute force
    if not passive and not opt.no_brute:
        log.step("4/6  DNS brute force")
        words = load_wordlist(opt.wordlist)
        wildcard = detect_wildcard(domain, resolver)
        res["wildcard_ips"] = sorted(wildcard)
        if wildcard:
            log.warn(f"wildcard DNS detected ({', '.join(sorted(wildcard))}) - filtering")
        brute = brute_force(domain, words, resolver, opt.threads, wildcard)
        _merge(hosts, brute)
        log.ok(f"{len(brute)} names from {len(words)} words")
    else:
        log.step("4/6  DNS brute force (skipped)")

    # 5 - resolve everything
    log.step(f"5/6  Resolving {len(hosts)} hosts")
    with ThreadPoolExecutor(max_workers=opt.threads) as ex:
        for name, info in zip(list(hosts), ex.map(lambda n: resolve_host(resolver, n), list(hosts))):
            hosts[name].update(info)
    live = [h for h in hosts.values() if h["resolves"]]
    log.ok(f"{len(live)} resolve to an IP")

    # 6 - HTTP / TLS probing
    if not passive and not opt.no_http:
        targets = sorted(live, key=lambda h: (h["name"] != domain, h["name"]))[: opt.max_hosts]
        log.step(f"6/6  Probing {len(targets)} hosts (HTTP, TLS, fingerprinting)")
        workers = min(opt.threads, 20)
        with ThreadPoolExecutor(max_workers=workers) as ex:
            for h, data in zip(targets, ex.map(lambda t: probe_host(t["name"], opt.timeout), targets)):
                h["http"], h["tls"] = data, data.pop("tls", None)
                if not data.get("error"):
                    log.debug(f"{h['name']} -> {data['status']} "
                              f"{', '.join(t['name'] for t in data['tech'])}")
        # names that only appear in live TLS certificates
        extra = {}
        for h in targets:
            for san in (h.get("tls") or {}).get("sans", []):
                n = clean_name(san, domain)
                if n and n not in hosts:
                    extra.setdefault(n, set()).add("tls-san")
        if extra:
            _merge(hosts, extra)
            for n in extra:
                hosts[n].update(resolve_host(resolver, n))
            log.ok(f"{len(extra)} extra names from live TLS certificates")
    else:
        log.step("6/6  HTTP probing (skipped)")

    # finalise
    for h in hosts.values():
        h["sources"] = sorted(h["sources"])
        h.setdefault("http", None)
        h.setdefault("tls", None)
    res["subdomains"] = sorted(hosts.values(), key=lambda h: (h["name"] != domain, h["name"]))
    res["findings"] = build_findings(res)
    res["meta"]["duration_s"] = round(time.time() - t0, 1)
    return res


def write_outputs(res: dict, out_root: str, formats: list) -> Path:
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out = Path(out_root) / f"{res['meta']['domain']}_{stamp}"
    out.mkdir(parents=True, exist_ok=True)
    if "json" in formats:
        (out / "results.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    if "html" in formats:
        (out / "report.html").write_text(render_html(res), encoding="utf-8")
    subs = [h["name"] for h in res["subdomains"]]
    live = [h["name"] for h in res["subdomains"] if h.get("resolves")]
    (out / "subdomains.txt").write_text("\n".join(subs) + "\n", encoding="utf-8")
    (out / "live_hosts.txt").write_text("\n".join(live) + "\n", encoding="utf-8")
    return out
