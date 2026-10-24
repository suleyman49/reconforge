"""Thin wrappers around dnspython so the rest of the code stays simple."""
import dns.exception
import dns.resolver

DEFAULT_NAMESERVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


def make_resolver(nameservers=None, timeout: float = 4.0) -> dns.resolver.Resolver:
    resolver = dns.resolver.Resolver(configure=True)
    if nameservers:
        resolver.nameservers = list(nameservers)
    elif not resolver.nameservers:
        resolver.nameservers = list(DEFAULT_NAMESERVERS)
    resolver.timeout = timeout
    resolver.lifetime = timeout * 2
    return resolver


def query(resolver, name: str, rtype: str):
    """Return the dnspython Answer, or None on any DNS failure."""
    try:
        return resolver.resolve(name, rtype, raise_on_no_answer=False)
    except dns.exception.DNSException:
        return None
    except Exception:  # malformed names, socket errors, etc.
        return None


def query_ips(resolver, name: str) -> list:
    """A + AAAA lookups (CNAME chains are followed automatically)."""
    ips = []
    for rtype in ("A", "AAAA"):
        ans = query(resolver, name, rtype)
        if ans is not None and ans.rrset is not None:
            ips.extend(r.to_text() for r in ans)
    return ips


def resolve_host(resolver, name: str) -> dict:
    """Return {'ips': [...], 'cnames': [...], 'resolves': bool} for a hostname."""
    out = {"ips": query_ips(resolver, name), "cnames": [], "resolves": False}
    ans = query(resolver, name, "CNAME")
    if ans is not None and ans.rrset is not None:
        out["cnames"] = [r.target.to_text().rstrip(".") for r in ans]
    out["resolves"] = bool(out["ips"])
    return out
