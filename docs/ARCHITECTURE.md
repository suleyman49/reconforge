# ReconForge – Architecture

ReconForge is a pipeline: the CLI parses arguments, the engine runs six stages in order,
and every stage adds its results to one shared dictionary (`res`) that is finally turned
into an HTML report, a JSON file and two text lists.

```
cli.py  ->  engine.run_recon()  ->  engine.write_outputs()
               |
               |-- 1  WHOIS            whoisinfo.lookup()
               |-- 2  DNS + email sec  dnsinfo.collect_records / email_security / try_zone_transfer
               |-- 3  Passive subdomains   subdomains.passive_enum  (crt.sh, CertSpotter, HackerTarget, Anubis)
               |-- 4  DNS brute force      subdomains.detect_wildcard + brute_force
               |-- 5  Resolve all hosts    dnsutil.resolve_host (thread pool)
               |-- 6  HTTP/TLS probing     fingerprint.probe_host (thread pool)
               '-- findings                analysis.build_findings(res)
```

## Data flow

All stages write into the result dictionary created in `engine.run_recon()`:

| Key | Filled by | Content |
|---|---|---|
| `meta` | engine | domain, mode (`passive`/`full`), start time, version, duration |
| `whois` | `whoisinfo` | registrar, dates, name servers, days until expiry, or `error` |
| `dns` | `dnsinfo` | records per type (A, AAAA, MX, NS, TXT, SOA, CAA) |
| `email_security` | `dnsinfo` | `has_mx`, `spf`, `spf_all`, `dmarc`, `dmarc_policy` |
| `axfr` | `dnsinfo` | one entry per name server: `vulnerable` flag and leaked `names` |
| `certificates` | `subdomains` | certificate-transparency statistics |
| `wildcard_ips` | `subdomains` | IPs returned for random names (used to filter brute-force noise) |
| `subdomains` | engine | list of hosts: name, sources, IPs, CNAMEs, `resolves`, `http`, `tls` |
| `findings` | `analysis` | prioritised issues (high / medium / low / info) |

Hosts are merged by name in a dict, and each host remembers every `source` that found it
(`target`, `axfr`, `crt.sh`, `brute`, `tls-san`, ...).

## Modes

| Mode | What runs |
|---|---|
| `--passive` | WHOIS, DNS records, certificate transparency and public sources, resolving. **No** brute force, AXFR or HTTP probing. |
| full (default) | Everything. Asks for confirmation ("Do you own or have written permission...") unless `-y`. |
| `--no-brute`, `--no-http` | Skip just that stage. |

## Concurrency

Stages 4, 5 and 6 use `ThreadPoolExecutor`. `--threads` controls brute force and resolving;
HTTP probing is capped at 20 workers to stay polite. `--max-hosts` limits how many hosts get probed.

## Design decisions

* **Raw-socket WHOIS client** – no extra dependency; follows registry referrals to the registrar.
* **Wildcard filtering** – random labels are resolved first, and brute-force hits that match the
  wildcard IPs are discarded to avoid thousands of false positives.
* **Failure tolerance** – public APIs are free tiers; a source that times out is skipped and the
  pipeline continues.
* **Escaped reports** – everything coming from the network is HTML-escaped in `report.py`
  (covered by `test_report_escapes_html`).
