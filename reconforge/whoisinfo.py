"""WHOIS lookup implemented with plain sockets (follows IANA / registrar referrals)."""
import re
import socket
from datetime import datetime, timezone

FIELD_MAP = {
    "registrar": ["registrar", "sponsoring registrar"],
    "created": ["creation date", "created", "registered on", "registration time", "domain registration date"],
    "expires": ["registry expiry date", "registrar registration expiration date", "expiry date",
                "expires", "paid-till", "expiration date", "expires on"],
    "updated": ["updated date", "last updated", "last modified", "last update"],
    "org": ["registrant organization", "registrant org", "org", "organization"],
    "country": ["registrant country", "country"],
    "dnssec": ["dnssec"],
}
LIST_FIELDS = {
    "status": ["domain status", "status"],
    "nameservers": ["name server", "nserver"],
}
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")


def raw_whois(server: str, query: str, timeout: float = 10.0) -> str:
    with socket.create_connection((server, 43), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall((query + "\r\n").encode())
        chunks = []
        while True:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", "replace")


def _referral(text: str):
    for key in ("refer", "whois", "registrar whois server"):
        m = re.search(rf"^\s*{key}:\s*(\S+)", text, re.I | re.M)
        if m:
            host = m.group(1).strip().lower()
            host = re.sub(r"^(https?://|whois://)", "", host).strip("/")
            if "." in host:
                return host
    return None


def parse_date(value: str):
    if not value:
        return None
    value = value.strip()
    m = re.search(r"(\d{4})-(\d{2})-(\d{2})", value)
    if m:
        return datetime(int(m.group(1)), int(m.group(2)), int(m.group(3)), tzinfo=timezone.utc)
    for fmt in ("%d-%b-%Y", "%d.%m.%Y", "%Y.%m.%d", "%Y/%m/%d", "%d/%m/%Y"):
        try:
            return datetime.strptime(value.split()[0], fmt).replace(tzinfo=timezone.utc)
        except (ValueError, IndexError):
            continue
    return None


def parse_whois(text: str) -> dict:
    """Extract the interesting fields from free-form WHOIS text."""
    fields, lists = {}, {k: [] for k in LIST_FIELDS}
    for line in text.splitlines():
        if ":" not in line or line.lstrip().startswith(("%", "#", ">>>")):
            continue
        key, _, value = line.partition(":")
        key, value = key.strip().lower(), value.strip()
        if not value:
            continue
        for name, aliases in FIELD_MAP.items():
            if key in aliases and name not in fields:
                fields[name] = value
        for name, aliases in LIST_FIELDS.items():
            if key in aliases:
                # "clientTransferProhibited https://icann.org/..." -> keep the first token
                item = value.split()[0].lower() if name == "nameservers" else value.split()[0]
                if item not in lists[name]:
                    lists[name].append(item)
    out = dict(fields)
    out.update(lists)
    out["emails"] = sorted({e.lower() for e in EMAIL_RE.findall(text)
                            if not e.lower().startswith(("abuse@", "noc@"))})[:5]
    exp = parse_date(fields.get("expires", ""))
    out["days_to_expiry"] = (exp - datetime.now(timezone.utc)).days if exp else None
    created = parse_date(fields.get("created", ""))
    out["age_days"] = (datetime.now(timezone.utc) - created).days if created else None
    return out


def lookup(domain: str, timeout: float = 10.0) -> dict:
    """Follow IANA -> registry -> registrar and return parsed data plus raw text."""
    result = {"server": None, "raw": "", "error": None}
    try:
        iana = raw_whois("whois.iana.org", domain, timeout)
        server = _referral(iana)
        if not server:
            result["error"] = "No WHOIS server found for this TLD"
            return result
        text = raw_whois(server, domain, timeout)
        result["server"] = server
        for _ in range(2):  # thin registries point to the registrar's own server
            nxt = _referral(text)
            if not nxt or nxt == server:
                break
            try:
                text2 = raw_whois(nxt, domain, timeout)
            except OSError:
                break
            if len(text2) > 100:
                text, server = text2, nxt
                result["server"] = server
            else:
                break
        result["raw"] = text
        result.update(parse_whois(text))
    except OSError as exc:
        result["error"] = f"WHOIS lookup failed: {exc}"
    return result
