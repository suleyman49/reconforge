# ReconForge

An automated **recon & OSINT pipeline in pure Python**. Give it a domain and it produces a single
HTML report (plus JSON) covering:

| Stage | What it does |
|---|---|
| WHOIS | Registrar, dates, name servers, expiry countdown (raw socket client, no extra dependency) |
| DNS | A, AAAA, MX, NS, TXT, SOA, CAA records; SPF and DMARC analysis; AXFR zone-transfer test |
| Subdomains | Certificate Transparency (crt.sh, CertSpotter) + HackerTarget + Anubis + DNS brute force with wildcard filtering |
| Certificates | CT statistics (issuers, wildcard certs, first/last issuance) and live TLS inspection |
| Fingerprinting | ~45 signatures (CMS, servers, frameworks, CDN/WAF, analytics) with version extraction, security-header grading |
| Analysis | Prioritised findings: dangling CNAMEs / takeover candidates, weak SPF/DMARC, expiring certs/domains, HTTP-only hosts, sensitive hostnames |

> **Legal / ethical use:** only run the full mode against domains you own or have written permission to test.
> `--passive` mode never contacts the target's web servers, but you should still respect local law and terms of service.

## Install

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```
Requires Python 3.9+.

## Usage

```bash
# Passive only: WHOIS, DNS, CT logs and public sources. No brute force, no HTTP probing, no AXFR.
python -m reconforge example.com --passive

# Full scan of a domain you own (asks for confirmation unless --yes is given)
python -m reconforge example.com

# Faster / custom
python -m reconforge example.com --threads 60 --wordlist big.txt --yes
python -m reconforge example.com --no-brute          # skip brute force only
python -m reconforge example.com --resolvers 1.1.1.1,9.9.9.9 -v
```

Open `output/<domain>_<timestamp>/report.html` in a browser.

### Output files
```
output/example.com_20260101_120000/
  report.html      interactive report (search box, dark mode, severity badges)
  results.json     full machine-readable data
  subdomains.txt   every discovered name
  live_hosts.txt   names that resolve (feed these into other tools)
```

### Options
| Flag | Meaning |
|---|---|
| `--passive` | No direct probing of the target's hosts |
| `--no-brute` / `--no-http` | Skip a stage |
| `-w, --wordlist` | Brute-force wordlist (one word per line) |
| `-t, --threads` | Concurrency (default 30) |
| `--timeout` | Network timeout in seconds (default 8) |
| `--max-hosts` | Cap on hosts that get HTTP-probed (default 150) |
| `--resolvers` | Comma-separated DNS servers |
| `--format html,json` | Choose report formats |
| `-y, --yes` | Confirm authorisation non-interactively |
| `-v / -q` | Verbose / quiet |

## Project layout
```
reconforge/
  cli.py          argument parsing and consent prompt
  engine.py       pipeline orchestration and output writing
  subdomains.py   CT logs, passive APIs, brute force, wildcard detection
  dnsinfo.py      records, SPF/DMARC, AXFR
  dnsutil.py      dnspython helpers
  whoisinfo.py    WHOIS client + parser
  fingerprint.py  HTTP/TLS probing, signatures, header grading
  analysis.py     findings engine
  report.py       HTML report
  wordlist.txt    bundled subdomain wordlist
tests/            offline unit tests
```

## Documentation
* [Architecture and data flow](docs/ARCHITECTURE.md)
* [Module reference and finding rules](docs/MODULES.md)
* [Testing](docs/TESTING.md)

## Run the tests
```bash
python -m unittest discover -s tests -v
```

## Extending it
* **New technology signature:** add a dict to `SIGNATURES` in `fingerprint.py`.
* **New passive source:** write `source_x(domain, timeout) -> (names, certs)` and register it in `PASSIVE_SOURCES`.
* **New finding rule:** add a check in `build_findings()` in `analysis.py`.

## Limitations
* Pass the **registrable apex domain** (`example.com`, not `www.example.com`).
* Passive APIs are free tiers and may rate-limit or time out; the pipeline simply continues without them.
* Fingerprinting is signature-based, so it can miss custom stacks and may be fooled by deliberate header changes.
* It does not do port scanning or vulnerability exploitation: it is a reconnaissance tool.
## Team & Responsibilities

| # | Member | GitHub | Responsibility | Files |
|---|--------|--------|----------------|-------|
| 1 | Solan Rabira | [@SOLMANRAW](https://github.com/SOLMANRAW) | DNS | `dnsinfo.py`, `dnsutil.py` |
| 2 | Lakumenza Wasu | [@angelwassu8-crypto](https://github.com/angelwassu8-crypto) | WHOIS | `whoisinfo.py` |
| 3 | Suleyman Denbel | [@suleyman49 ](https://github.com/suleyman49 ) | Subdomain Enumeration | `subdomains.py`, `wordlist.txt` |
| 4 | Farson Yusuf | [@far-son](https://github.com/far-son) | Fingerprinting & Analysis | `fingerprint.py`, `analysis.py` |
| 5 | Sunamawit Endale | [@Sunendale](https://github.com/Sunendale) | Engine, CLI & Reports  | `engine.py`, `cli.py`, `report.py`, `tests/` |

## Demo
The demo video is in [`demo/reconforge_demo.mp4`](demo/reconforge_demo.mp4).
