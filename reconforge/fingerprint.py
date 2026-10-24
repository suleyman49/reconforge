"""HTTP probing, technology fingerprinting, security-header grading and TLS inspection."""
import re
import socket
import ssl
import time

import requests
import urllib3

from . import USER_AGENT

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

MAX_BODY = 300_000

SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

# Each signature: name, category and any of headers / cookies / html patterns.
# A capture group, when present, is used as the version.
SIGNATURES = [
    # --- CMS / platforms
    {"name": "WordPress", "cat": "CMS", "html": [r"/wp-content/", r"/wp-includes/"],
     "meta": r"WordPress\s*([\d.]+)?"},
    {"name": "Drupal", "cat": "CMS", "headers": {"x-generator": r"Drupal\s*([\d.]+)?"},
     "html": [r"Drupal\.settings", r"/sites/default/files/"], "meta": r"Drupal\s*([\d.]+)?"},
    {"name": "Joomla", "cat": "CMS", "html": [r"/media/jui/", r"/components/com_"], "meta": r"Joomla!?\s*([\d.]+)?"},
    {"name": "Shopify", "cat": "E-commerce", "headers": {"x-shopid": r""}, "html": [r"cdn\.shopify\.com"]},
    {"name": "Magento", "cat": "E-commerce", "cookies": [r"^frontend$"], "html": [r"/static/frontend/Magento", r"Mage\.Cookies"]},
    {"name": "Wix", "cat": "CMS", "headers": {"x-wix-request-id": r""}, "html": [r"static\.wixstatic\.com"]},
    {"name": "Squarespace", "cat": "CMS", "html": [r"static1\.squarespace\.com", r"Squarespace"]},
    {"name": "Ghost", "cat": "CMS", "meta": r"Ghost\s*([\d.]+)?"},
    {"name": "Webflow", "cat": "CMS", "html": [r"assets\.website-files\.com", r"data-wf-site"]},
    # --- Web servers
    {"name": "nginx", "cat": "Web server", "headers": {"server": r"nginx/?([\d.]+)?"}},
    {"name": "Apache", "cat": "Web server", "headers": {"server": r"Apache/?([\d.]+)?"}},
    {"name": "Microsoft IIS", "cat": "Web server", "headers": {"server": r"Microsoft-IIS/?([\d.]+)?"}},
    {"name": "LiteSpeed", "cat": "Web server", "headers": {"server": r"LiteSpeed"}},
    {"name": "Caddy", "cat": "Web server", "headers": {"server": r"Caddy"}},
    {"name": "OpenResty", "cat": "Web server", "headers": {"server": r"openresty/?([\d.]+)?"}},
    # --- Languages / frameworks
    {"name": "PHP", "cat": "Language", "headers": {"x-powered-by": r"PHP/?([\d.]+)?"}, "cookies": [r"^PHPSESSID$"]},
    {"name": "ASP.NET", "cat": "Framework", "headers": {"x-aspnet-version": r"([\d.]+)", "x-powered-by": r"ASP\.NET"},
     "cookies": [r"^ASP\.NET_SessionId$"]},
    {"name": "Express", "cat": "Framework", "headers": {"x-powered-by": r"Express"}},
    {"name": "Django", "cat": "Framework", "cookies": [r"^csrftoken$"], "html": [r"csrfmiddlewaretoken"]},
    {"name": "Laravel", "cat": "Framework", "cookies": [r"^laravel_session$", r"^XSRF-TOKEN$"]},
    {"name": "Ruby on Rails", "cat": "Framework", "cookies": [r"^_[a-z0-9_]+_session$"], "html": [r"csrf-param.{0,40}authenticity_token"]},
    {"name": "Next.js", "cat": "Framework", "headers": {"x-powered-by": r"Next\.js\s*([\d.]+)?"}, "html": [r"/_next/static/"]},
    {"name": "Nuxt.js", "cat": "Framework", "html": [r"/_nuxt/", r"window\.__NUXT__"]},
    {"name": "React", "cat": "JS library", "html": [r"data-reactroot", r"react(?:\.production)?(?:\.min)?\.js", r"__REACT_DEVTOOLS"]},
    {"name": "Angular", "cat": "JS framework", "html": [r"ng-version=\"([\d.]+)\"", r"<app-root"]},
    {"name": "Vue.js", "cat": "JS framework", "html": [r"vue(?:\.runtime)?(?:\.min)?\.js", r"data-v-[0-9a-f]{6,8}"]},
    {"name": "jQuery", "cat": "JS library", "html": [r"jquery[-.]?([\d]+\.[\d.]+)?(?:\.min)?\.js"]},
    {"name": "Bootstrap", "cat": "UI", "html": [r"bootstrap(?:[-.]|@)?([\d]+\.[\d.]+)?(?:\.min)?\.(?:css|js)"]},
    # --- CDN / WAF / hosting
    {"name": "Cloudflare", "cat": "CDN/WAF", "headers": {"server": r"cloudflare", "cf-ray": r""}},
    {"name": "Akamai", "cat": "CDN/WAF", "headers": {"server": r"AkamaiGHost", "x-akamai-transformed": r""}},
    {"name": "Fastly", "cat": "CDN/WAF", "headers": {"x-served-by": r"cache-", "x-fastly-request-id": r""}},
    {"name": "Amazon CloudFront", "cat": "CDN/WAF", "headers": {"x-amz-cf-id": r"", "via": r"CloudFront"}},
    {"name": "Sucuri", "cat": "CDN/WAF", "headers": {"x-sucuri-id": r"", "server": r"Sucuri"}},
    {"name": "Imperva", "cat": "CDN/WAF", "headers": {"x-iinfo": r""}, "cookies": [r"^incap_ses_", r"^visid_incap_"]},
    {"name": "AWS ELB", "cat": "Hosting", "cookies": [r"^AWSALB(?:CORS)?$", r"^AWSELB$"]},
    {"name": "Vercel", "cat": "Hosting", "headers": {"server": r"Vercel", "x-vercel-id": r""}},
    {"name": "Netlify", "cat": "Hosting", "headers": {"server": r"Netlify", "x-nf-request-id": r""}},
    {"name": "GitHub Pages", "cat": "Hosting", "headers": {"server": r"GitHub\.com"}},
    # --- Analytics
    {"name": "Google Analytics", "cat": "Analytics", "html": [r"google-analytics\.com/(?:analytics|ga)\.js", r"gtag\('config'"]},
    {"name": "Google Tag Manager", "cat": "Analytics", "html": [r"googletagmanager\.com/gtm\.js"]},
]

_META_GEN_1 = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I)
_META_GEN_2 = re.compile(r'<meta[^>]+content=["\']([^"\']+)["\'][^>]+name=["\']generator["\']', re.I)
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)


def _clean_version(v):
    if not v:
        return None
    v = re.sub(r"[^\w.\-]", "", v)
    return v or None


def detect_technologies(headers: dict, cookie_names: list, html: str) -> list:
    """Match response headers, cookies and HTML against the signature list."""
    headers = {k.lower(): str(v) for k, v in headers.items()}
    html = html or ""
    generators = _META_GEN_1.findall(html) + _META_GEN_2.findall(html)
    found = {}

    for sig in SIGNATURES:
        evidence, version = None, None

        for hname, rx in sig.get("headers", {}).items():
            value = headers.get(hname)
            if value is None:
                continue
            m = re.search(rx, value, re.I)
            if m:
                evidence = f"header {hname}"
                if m.groups():
                    version = version or _clean_version(m.group(1))

        for rx in sig.get("cookies", []):
            if any(re.search(rx, c) for c in cookie_names):
                evidence = evidence or "cookie"

        for rx in sig.get("html", []):
            m = re.search(rx, html, re.I)
            if m:
                evidence = evidence or "html"
                if m.groups():
                    version = version or _clean_version(m.group(1))

        if sig.get("meta"):
            for gen in generators:
                m = re.search(sig["meta"], gen, re.I)
                if m:
                    evidence = evidence or "meta generator"
                    if m.groups():
                        version = version or _clean_version(m.group(1))

        if evidence:
            found[sig["name"]] = {"name": sig["name"], "category": sig["cat"],
                                  "version": version, "evidence": evidence}
    return sorted(found.values(), key=lambda t: (t["category"], t["name"]))


def grade_security_headers(headers: dict, scheme: str) -> dict:
    headers = {k.lower(): v for k, v in headers.items()}
    present, missing = [], []
    for h in SECURITY_HEADERS:
        ok = h in headers
        if h == "x-frame-options" and "frame-ancestors" in headers.get("content-security-policy", ""):
            ok = True
        if h == "strict-transport-security" and scheme != "https":
            continue  # HSTS is meaningless over plain HTTP
        (present if ok else missing).append(h)
    total = len(present) + len(missing)
    ratio = len(present) / total if total else 0
    grade = "A" if ratio >= 0.99 else "B" if ratio >= 0.8 else "C" if ratio >= 0.6 else "D" if ratio >= 0.4 else "F"
    return {"present": present, "missing": missing, "grade": grade}


def tls_info(host: str, port: int = 443, timeout: float = 6.0):
    """Inspect the live certificate. Returns None if nothing listens on 443."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert, proto = tls.getpeercert(), tls.version()
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        expires = ssl.cert_time_to_seconds(cert["notAfter"])
        return {
            "valid": True,
            "issuer": issuer.get("organizationName") or issuer.get("commonName"),
            "not_after": cert["notAfter"],
            "expires_in_days": int((expires - time.time()) // 86400),
            "sans": [v.lower() for k, v in cert.get("subjectAltName", ()) if k == "DNS"],
            "protocol": proto,
        }
    except ssl.SSLCertVerificationError as exc:
        return {"valid": False, "error": getattr(exc, "verify_message", str(exc)), "sans": []}
    except (OSError, ssl.SSLError):
        return None


def _title(html: str):
    m = _TITLE.search(html or "")
    return re.sub(r"\s+", " ", m.group(1)).strip()[:100] if m else None


def probe(host: str, timeout: float = 8.0) -> dict:
    """Fetch the host over HTTPS (then HTTP) and fingerprint what answers."""
    result = {"error": None}
    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        try:
            r = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=timeout,
                             verify=False, allow_redirects=True, stream=True)
            body = r.raw.read(MAX_BODY, decode_content=True) or b""
            html = body.decode(r.encoding or "utf-8", "replace")
            cookies = list(r.cookies.keys())
            for hist in r.history:
                cookies.extend(hist.cookies.keys())
            headers = dict(r.headers)
            final_scheme = r.url.split(":", 1)[0]
            result = {
                "error": None,
                "url": url,
                "final_url": r.url,
                "scheme": final_scheme,
                "status": r.status_code,
                "title": _title(html),
                "server": headers.get("Server"),
                "tech": detect_technologies(headers, cookies, html),
                "security_headers": grade_security_headers(headers, final_scheme),
                "https_available": scheme == "https",
            }
            r.close()
            return result
        except requests.RequestException as exc:
            result["error"] = type(exc).__name__
    return result


def probe_host(host: str, timeout: float = 8.0) -> dict:
    """HTTP probe + TLS inspection for one host."""
    data = probe(host, timeout)
    data["tls"] = tls_info(host, timeout=min(timeout, 6.0))
    return data
