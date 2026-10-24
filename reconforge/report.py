"""Self-contained HTML report (no external assets) with search and dark mode."""
from collections import Counter
from html import escape as e

CSS = """
:root{--bg:#f5f6fa;--card:#fff;--text:#1d2433;--muted:#667085;--line:#e4e7ee;--accent:#4f46e5;
--high:#dc2626;--medium:#ea580c;--low:#ca8a04;--info:#2563eb;--ok:#16a34a}
@media(prefers-color-scheme:dark){:root{--bg:#0f1320;--card:#181d2e;--text:#e6e9f2;--muted:#8d97b0;--line:#2a3148;--accent:#818cf8}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:1180px;margin:0 auto;padding:28px 20px 60px}
header h1{margin:0;font-size:26px}header p{margin:4px 0 0;color:var(--muted)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:22px 0}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.card b{display:block;font-size:26px}.card span{color:var(--muted);font-size:13px}
section{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px;margin:16px 0}
h2{margin:0 0 12px;font-size:18px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.scroll{overflow-x:auto}.mono{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:13px;word-break:break-all}
.badge{display:inline-block;padding:1px 9px;border-radius:99px;font-size:12px;font-weight:600;color:#fff}
.high{background:var(--high)}.medium{background:var(--medium)}.low{background:var(--low)}.info{background:var(--info)}
.chip{display:inline-block;background:color-mix(in srgb,var(--accent) 14%,transparent);color:var(--accent);
padding:0 8px;border-radius:6px;font-size:12px;margin:1px 3px 1px 0}
.grade{font-weight:700;border-radius:6px;padding:0 7px;color:#fff}
.gA,.gB{background:var(--ok)}.gC{background:var(--low)}.gD{background:var(--medium)}.gF{background:var(--high)}
.muted{color:var(--muted)}.kv td:first-child{width:200px;color:var(--muted)}
input#q{width:100%;padding:9px 12px;margin-bottom:10px;border:1px solid var(--line);border-radius:8px;
background:var(--bg);color:var(--text);font-size:14px}
footer{margin-top:30px;color:var(--muted);font-size:12px;text-align:center}
"""

JS = """
document.getElementById('q').addEventListener('input',function(){
 var t=this.value.toLowerCase();
 document.querySelectorAll('#hosts tbody tr').forEach(function(r){
  r.style.display=r.textContent.toLowerCase().indexOf(t)>-1?'':'none';});});
"""


def _kv(rows):
    body = "".join(f"<tr><td>{e(str(k))}</td><td class='mono'>{v}</td></tr>" for k, v in rows if v)
    return f"<table class='kv'>{body}</table>" if body else "<p class='muted'>No data.</p>"


def _findings(findings):
    if not findings:
        return "<p class='muted'>No findings.</p>"
    rows = "".join(
        f"<tr><td><span class='badge {x['severity']}'>{x['severity'].upper()}</span></td>"
        f"<td><b>{e(x['title'])}</b><br><span class='muted'>{e(x['detail'])}</span></td>"
        f"<td class='mono'>{e(x.get('target') or '')}</td></tr>" for x in findings)
    return f"<div class='scroll'><table><tr><th>Severity</th><th>Finding</th><th>Target</th></tr>{rows}</table></div>"


def _hosts_table(hosts):
    rows = []
    for h in hosts:
        http = h.get("http") or {}
        techs = "".join(
            f"<span class='chip'>{e(t['name'])}{(' ' + e(t['version'])) if t.get('version') else ''}</span>"
            for t in http.get("tech", []))
        grade = (http.get("security_headers") or {}).get("grade")
        missing = ", ".join((http.get("security_headers") or {}).get("missing", []))
        gcell = f"<span class='grade g{grade}' title='Missing: {e(missing)}'>{grade}</span>" if grade else ""
        status = http.get("status", "")
        if not status and h.get("resolves") and http.get("error"):
            status = "<span class='muted'>no web</span>"
        ips = "<br>".join(e(i) for i in h.get("ips", [])[:3]) or (
            f"<span class='muted'>CNAME {e(h['cnames'][0])}</span>" if h.get("cnames") else "")
        rows.append(
            f"<tr><td class='mono'>{e(h['name'])}</td><td class='mono'>{ips}</td><td>{status}</td>"
            f"<td>{e(http.get('title') or '')}</td><td>{techs}</td><td>{gcell}</td>"
            f"<td class='muted'>{e(', '.join(h['sources']))}</td></tr>")
    return ("<input id='q' placeholder='Filter hosts, IPs, technologies...'>"
            "<div class='scroll'><table id='hosts'><thead><tr><th>Host</th><th>IP / CNAME</th><th>HTTP</th>"
            "<th>Title</th><th>Technologies</th><th>Headers</th><th>Sources</th></tr></thead>"
            f"<tbody>{''.join(rows)}</tbody></table></div>")


def render_html(res: dict) -> str:
    m, w = res["meta"], res.get("whois", {})
    subs = res.get("subdomains", [])
    live = [s for s in subs if s.get("resolves")]
    web = [s for s in subs if s.get("http") and not s["http"].get("error")]
    sev = Counter(x["severity"] for x in res.get("findings", []))
    tech_counter = Counter(t["name"] for s in web for t in s["http"].get("tech", []))

    cards = [
        (len(subs), "Subdomains found"), (len(live), "Resolving"), (len(web), "Web hosts"),
        (sev.get("high", 0), "High findings"), (sev.get("medium", 0), "Medium findings"),
        (len(tech_counter), "Technologies"),
    ]
    cards_html = "".join(f"<div class='card'><b>{n}</b><span>{e(label)}</span></div>" for n, label in cards)

    whois_html = (f"<p class='muted'>{e(w['error'])}</p>" if w.get("error") else _kv([
        ("Registrar", e(w.get("registrar", ""))), ("Organisation", e(w.get("org", ""))),
        ("Created", e(w.get("created", ""))), ("Expires", e(w.get("expires", ""))
         + (f" ({w['days_to_expiry']} days)" if w.get("days_to_expiry") is not None else "")),
        ("Updated", e(w.get("updated", ""))), ("Name servers", e(", ".join(w.get("nameservers", [])))),
        ("Status", e(", ".join(w.get("status", [])[:4]))), ("DNSSEC", e(w.get("dnssec", ""))),
        ("Contact emails", e(", ".join(w.get("emails", [])))), ("WHOIS server", e(w.get("server") or "")),
    ]))

    dns_rows = "".join(
        f"<tr><td><b>{e(t)}</b></td><td class='mono'>{'<br>'.join(e(v) for v in vals)}</td></tr>"
        for t, vals in res.get("dns", {}).items()) or "<tr><td class='muted'>No records.</td></tr>"

    mail = res.get("email_security", {})
    mail_html = _kv([
        ("SPF", e(mail.get("spf") or "missing")), ("DMARC", e(mail.get("dmarc") or "missing")),
        ("DMARC policy", e(mail.get("dmarc_policy") or "")),
    ])

    axfr = res.get("axfr", [])
    axfr_html = "".join(
        f"<tr><td class='mono'>{e(z['ns'])}</td><td>"
        + ("<span class='badge high'>VULNERABLE</span>" if z["vulnerable"] else "<span class='muted'>refused</span>")
        + "</td></tr>" for z in axfr) or "<tr><td class='muted'>Not tested (passive mode).</td></tr>"

    ct = res.get("certificates", {})
    ct_html = _kv([
        ("Certificates logged", str(ct.get("total", 0))), ("Wildcard certs", str(ct.get("wildcards", ""))),
        ("First seen", e(ct.get("first_seen") or "")), ("Latest issued", e(ct.get("last_seen") or "")),
        ("Top issuers", e(", ".join(f"{n} ({c})" for n, c in ct.get("issuers", [])))),
    ]) if ct.get("total") else "<p class='muted'>No certificate transparency data retrieved.</p>"

    tech_html = "".join(f"<span class='chip'>{e(n)} &times; {c}</span>"
                        for n, c in tech_counter.most_common()) or "<p class='muted'>No technologies detected.</p>"

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReconForge - {e(m['domain'])}</title><style>{CSS}</style></head><body><div class="wrap">
<header><h1>Recon report: {e(m['domain'])}</h1>
<p>Mode: {e(m['mode'])} &middot; Generated {e(m['started'])} &middot; Duration {m['duration_s']}s &middot; ReconForge {e(m['version'])}</p></header>
<div class="cards">{cards_html}</div>
<section><h2>Findings</h2>{_findings(res.get('findings', []))}</section>
<section><h2>Subdomains &amp; web hosts</h2>{_hosts_table(subs)}</section>
<section><h2>Technology summary</h2>{tech_html}</section>
<section><h2>WHOIS</h2>{whois_html}</section>
<section><h2>DNS records</h2><table class="kv">{dns_rows}</table></section>
<section><h2>Email security</h2>{mail_html}</section>
<section><h2>Zone transfer (AXFR)</h2><table class="kv">{axfr_html}</table></section>
<section><h2>Certificate transparency</h2>{ct_html}</section>
<footer>Generated by ReconForge. Use only against systems you own or are explicitly authorised to test.</footer>
</div><script>{JS}</script></body></html>"""
