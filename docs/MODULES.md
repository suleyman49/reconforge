# ReconForge – Module reference

Each section lists the module, its owner role, and the functions other modules rely on.

## DNS – `dnsinfo.py`, `dnsutil.py`
| Function | Purpose |
|---|---|
| `dnsutil.make_resolver(nameservers, timeout)` | Builds a dnspython resolver (default 1.1.1.1, 8.8.8.8, 9.9.9.9). |
| `dnsutil.query(resolver, name, rtype)` | Safe query: returns `None` instead of raising on NXDOMAIN/timeout. |
| `dnsutil.query_ips(resolver, name)` | A and AAAA addresses of a name. |
| `dnsutil.resolve_host(resolver, name)` | Returns `resolves`, IPs and CNAME chain for one host. |
| `dnsinfo.collect_records(domain, resolver)` | A, AAAA, MX, NS, TXT, SOA, CAA. |
| `dnsinfo.email_security(domain, records, resolver)` | Finds the SPF record and its `all` qualifier, and the `_dmarc` record and its policy. |
| `dnsinfo.try_zone_transfer(domain, nameservers, resolver, timeout)` | Attempts AXFR against each name server (full mode only). |

## WHOIS – `whoisinfo.py`
| Function | Purpose |
|---|---|
| `raw_whois(server, query, timeout)` | Plain TCP/43 query. |
| `parse_whois(text)` | Maps registry field names (`FIELD_MAP`) to a normalised dict. |
| `parse_date(value)` | Handles the date formats used by different registries. |
| `lookup(domain, timeout)` | Queries the registry, follows the referral to the registrar, returns the parsed dict plus days until expiry. |

## Subdomain enumeration – `subdomains.py`, `wordlist.txt`
| Function | Purpose |
|---|---|
| `source_crtsh / source_certspotter / source_hackertarget / source_anubis` | One passive source each, registered in `PASSIVE_SOURCES`. |
| `passive_enum(domain, timeout, log)` | Runs all sources, returns `(names, certs)`. |
| `clean_name(name, domain)` | Lower-cases, strips `*.`, rejects names outside the target domain. |
| `summarize_certs(certs)` | Issuers, wildcard certificates, first/last issuance. |
| `detect_wildcard(domain, resolver)` | Resolves random labels to find wildcard DNS. |
| `load_wordlist(path)` / `brute_force(...)` | Threaded dictionary brute force, filtered by wildcard IPs. |

## Fingerprinting & analysis – `fingerprint.py`, `analysis.py`
| Function | Purpose |
|---|---|
| `probe_host(host, timeout)` | HTTP(S) request plus TLS inspection for one host. |
| `detect_technologies(headers, cookie_names, html)` | Matches about 45 `SIGNATURES` (CMS, servers, frameworks, CDN/WAF, analytics) and extracts versions. |
| `grade_security_headers(headers, scheme)` | Grade A–F from the presence of security headers (HSTS ignored on plain HTTP). |
| `tls_info(host, port, timeout)` | Certificate issuer, expiry, SANs. |
| `analysis.build_findings(res)` | Turns the whole result dictionary into findings. |

### Finding rules in `analysis.build_findings`
| Severity | Rule |
|---|---|
| High | Domain expired or expires in < 30 days; SPF `+all`; AXFR allowed; dangling CNAME to a known takeover service |
| Medium | Domain expires in < 90 days; no SPF; no DMARC; dangling CNAME to other targets |
| Low | SPF `?all` or missing `all`; DMARC `p=none` |
| Info | No CAA record; wildcard DNS; potentially sensitive hostname (`SENSITIVE_TOKENS`) |
| Host-level | HTTP-only hosts, server banners that expose a version |

## Engine, CLI & reports – `engine.py`, `cli.py`, `report.py`
| Function | Purpose |
|---|---|
| `cli.build_parser()` / `cli.main()` | Arguments, validation (domain, wordlist, formats), consent prompt, exit codes (0 ok, 1 declined, 2 bad input, 130 interrupted). |
| `engine.run_recon(domain, opt, log)` | Runs the six stages and returns the result dictionary. |
| `engine.write_outputs(res, out_root, formats)` | Writes `report.html`, `results.json`, `subdomains.txt`, `live_hosts.txt` into `output/<domain>_<timestamp>/`. |
| `report.render_html(res)` | Self-contained HTML report with search box, dark mode and severity badges. |

## Shared – `utils.py`, `__init__.py`
`normalize_domain`, `is_valid_domain`, the colored `Log` class, `__version__` and the `USER_AGENT` string.
