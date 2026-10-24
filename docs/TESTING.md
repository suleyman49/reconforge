# ReconForge – Testing

The tests are offline unit tests, so they need no network and no target.

```bash
python -m unittest discover -s tests -v
```

| Test class | What it checks |
|---|---|
| `TestUtils` | Domain normalisation (URLs, case, ports) and validation |
| `TestWhois` | Parsing of a sample WHOIS response |
| `TestSubdomains` | `clean_name` rules and certificate summary |
| `TestFingerprint` | Technology detection, no false positives, security-header grading |
| `TestAnalysisAndReport` | Findings produced from a sample result, and HTML escaping in the report |

Result at the time of writing: 10 tests, all passing.

## Manual test (use only on a domain you own or may test)
```bash
python -m reconforge yourdomain.com --passive        # safe, passive only
python -m reconforge yourdomain.com --yes            # full scan
```
Open `output/<domain>_<timestamp>/report.html` and check that WHOIS, DNS, subdomains and
findings sections are filled. `examples/sample_report.html` shows what a finished report looks like.
