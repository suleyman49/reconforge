"""DNS record collection, SPF/DMARC analysis and AXFR (zone transfer) testing."""
import re

import dns.exception
import dns.query

from .dnsutil import query, query_ips

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"]


def _fmt(rtype: str, rdata) -> str:
    if rtype == "TXT":
        return "".join(s.decode("utf-8", "replace") for s in rdata.strings)
    if rtype == "MX":
        return f"{rdata.preference} {rdata.exchange.to_text().rstrip('.')}"
    if rtype == "NS":
        return rdata.target.to_text().rstrip(".")
    return rdata.to_text()


def collect_records(domain: str, resolver) -> dict:
    records = {}
    for rtype in RECORD_TYPES:
        ans = query(resolver, domain, rtype)
        if ans is not None and ans.rrset is not None:
            records[rtype] = [_fmt(rtype, r) for r in ans]
    return records


def email_security(domain: str, records: dict, resolver) -> dict:
    """Inspect SPF and DMARC - classic spoofing/phishing exposure checks."""
    txts = records.get("TXT", [])
    spf = next((t for t in txts if t.lower().startswith("v=spf1")), None)
    spf_all = None
    if spf:
        m = re.search(r"([+\-~?]?)all\b", spf, re.I)
        spf_all = (m.group(1) or "+") + "all" if m else None

    dmarc = dmarc_policy = None
    ans = query(resolver, f"_dmarc.{domain}", "TXT")
    if ans is not None and ans.rrset is not None:
        for r in ans:
            text = _fmt("TXT", r)
            if text.lower().startswith("v=dmarc1"):
                dmarc = text
                m = re.search(r"\bp=(\w+)", text, re.I)
                dmarc_policy = m.group(1).lower() if m else None
    return {
        "has_mx": bool(records.get("MX")),
        "spf": spf,
        "spf_all": spf_all,
        "dmarc": dmarc,
        "dmarc_policy": dmarc_policy,
    }


def try_zone_transfer(domain: str, nameservers: list, resolver, timeout: float = 8.0) -> list:
    """Attempt AXFR against each authoritative NS. A success is a serious misconfiguration."""
    results = []
    for ns in nameservers:
        info = {"ns": ns, "vulnerable": False, "names": []}
        ips = query_ips(resolver, ns)
        if ips:
            try:
                names = set()
                for msg in dns.query.xfr(ips[0], domain, lifetime=timeout, timeout=timeout):
                    for rrset in msg.answer:
                        names.add(rrset.name.to_text().rstrip(".").lower())
                if names:
                    info["vulnerable"] = True
                    info["names"] = sorted(names)
            except Exception:
                pass  # refused / timed out = the secure outcome
        results.append(info)
    return results
