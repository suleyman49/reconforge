"""Turn raw recon data into prioritized findings."""
import re
from collections import Counter

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}

# CNAME targets that are commonly exploitable when the target resource is gone.
TAKEOVER_SERVICES = {
    "github.io": "GitHub Pages", "herokuapp.com": "Heroku", "herokudns.com": "Heroku",
    "s3.amazonaws.com": "AWS S3", "azurewebsites.net": "Azure App Service",
    "cloudapp.net": "Azure Cloud Services", "trafficmanager.net": "Azure Traffic Manager",
    "blob.core.windows.net": "Azure Blob Storage", "ghost.io": "Ghost", "surge.sh": "Surge",
    "bitbucket.io": "Bitbucket", "zendesk.com": "Zendesk", "readme.io": "Readme",
    "myshopify.com": "Shopify", "statuspage.io": "Statuspage", "netlify.app": "Netlify",
    "pantheonsite.io": "Pantheon", "unbouncepages.com": "Unbounce", "fly.dev": "Fly.io",
}

SENSITIVE_TOKENS = {
    "admin", "dev", "staging", "stage", "test", "uat", "qa", "internal", "intranet", "vpn",
    "jenkins", "git", "gitlab", "jira", "backup", "old", "beta", "sandbox", "phpmyadmin",
    "grafana", "kibana", "sso", "db", "sql", "ftp", "debug", "demo", "preprod", "stg",
}


def _add(findings, severity, title, detail, target=None):
    findings.append({"severity": severity, "title": title, "detail": detail, "target": target})


def build_findings(res: dict) -> list:
    f = []
    domain = res["meta"]["domain"]

    # ---- WHOIS
    days = res.get("whois", {}).get("days_to_expiry")
    if days is not None:
        if days < 0:
            _add(f, "high", "Domain registration has expired", f"{domain} expired {-days} days ago.", domain)
        elif days < 30:
            _add(f, "high", "Domain expires very soon", f"Registration expires in {days} days.", domain)
        elif days < 90:
            _add(f, "medium", "Domain expires within 90 days", f"Registration expires in {days} days.", domain)

    # ---- DNS / email security
    dns_rec = res.get("dns", {})
    mail = res.get("email_security", {})
    if mail.get("has_mx") or not dns_rec.get("MX"):
        if not mail.get("spf"):
            _add(f, "medium", "No SPF record", "Anyone can forge email from this domain more easily.", domain)
        elif mail.get("spf_all") == "+all":
            _add(f, "high", "SPF allows any sender (+all)", "The SPF record authorises the entire internet.", domain)
        elif mail.get("spf_all") in ("?all", None):
            _add(f, "low", "Weak SPF policy", f"SPF ends with '{mail.get('spf_all')}' (no enforcement).", domain)
        if not mail.get("dmarc"):
            _add(f, "medium", "No DMARC record", "Spoofed email is not instructed to be rejected or quarantined.", domain)
        elif mail.get("dmarc_policy") == "none":
            _add(f, "low", "DMARC in monitor-only mode", "p=none reports abuse but does not block it.", domain)
    if not dns_rec.get("CAA"):
        _add(f, "info", "No CAA record", "Any certificate authority may issue certificates for this domain.", domain)

    for z in res.get("axfr", []):
        if z.get("vulnerable"):
            _add(f, "high", "DNS zone transfer allowed (AXFR)",
                 f"Nameserver {z['ns']} returned {len(z['names'])} names to an unauthenticated request.", z["ns"])

    if res.get("wildcard_ips"):
        _add(f, "info", "Wildcard DNS detected",
             "Random labels resolve; brute-force results were filtered to avoid false positives.", domain)

    # ---- Hosts
    hosts = res.get("subdomains", [])
    header_gaps, http_only, version_leaks = Counter(), [], []
    for h in hosts:
        name = h["name"]

        # dangling CNAME / takeover candidates
        if h.get("cnames") and not h.get("resolves"):
            target = h["cnames"][0]
            svc = next((v for k, v in TAKEOVER_SERVICES.items() if target.endswith(k)), None)
            if svc:
                _add(f, "high", "Possible subdomain takeover",
                     f"{name} -> {target} ({svc}) does not resolve. Claim or remove the record.", name)
            else:
                _add(f, "medium", "Dangling CNAME", f"{name} points to {target}, which does not resolve.", name)

        # interesting names
        prefix = name[: -len(domain)].rstrip(".")
        if set(re.split(r"[.\-_]", prefix)) & SENSITIVE_TOKENS:
            _add(f, "info", "Potentially sensitive hostname",
                 "Name suggests a dev/admin/internal system - verify it should be internet-facing.", name)

        http = h.get("http")
        if http and not http.get("error"):
            if http["scheme"] == "http" and not http.get("https_available"):
                http_only.append(name)
            if http.get("server") and re.search(r"\d+\.\d+", http["server"]):
                version_leaks.append(f"{name} ({http['server']})")
            for m in http["security_headers"]["missing"]:
                header_gaps[m] += 1

        tls = h.get("tls")
        if tls:
            if tls.get("valid") is False:
                _add(f, "medium", "Invalid TLS certificate", tls.get("error", "Verification failed."), name)
            elif tls.get("expires_in_days") is not None:
                d = tls["expires_in_days"]
                if d < 0:
                    _add(f, "high", "TLS certificate expired", f"Expired {-d} days ago.", name)
                elif d < 14:
                    _add(f, "medium", "TLS certificate expires soon", f"Expires in {d} days.", name)

    if http_only:
        _add(f, "medium", "Hosts served over plain HTTP only",
             ", ".join(http_only[:10]) + (" ..." if len(http_only) > 10 else ""))
    if version_leaks:
        _add(f, "low", "Server version disclosure",
             "; ".join(version_leaks[:8]) + (" ..." if len(version_leaks) > 8 else ""))
    probed = sum(1 for h in hosts if h.get("http") and not h["http"].get("error"))
    for header, count in header_gaps.most_common():
        if count >= max(2, probed // 2):
            _add(f, "low", f"Missing security header: {header}",
                 f"Absent on {count} of {probed} web hosts.")

    return sorted(f, key=lambda x: SEVERITY_ORDER[x["severity"]])
