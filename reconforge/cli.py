"""Command line interface for ReconForge."""
import argparse
import os
import sys

from . import __version__
from .engine import run_recon, write_outputs
from .utils import Log, is_valid_domain, normalize_domain

BANNER = r"""
  ____                      _____
 |  _ \ ___  ___ ___  _ __ |  ___|__  _ __ __ _  ___
 | |_) / _ \/ __/ _ \| '_ \| |_ / _ \| '__/ _` |/ _ \
 |  _ <  __/ (_| (_) | | | |  _| (_) | | | (_| |  __/
 |_| \_\___|\___\___/|_| |_|_|  \___/|_|  \__, |\___|
                                          |___/   v{v}
 Recon & OSINT pipeline - authorized testing only
"""

DEFAULT_WORDLIST = os.path.join(os.path.dirname(__file__), "wordlist.txt")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="reconforge",
        description="Automated recon: WHOIS, DNS, subdomains, certificate transparency, "
                    "technology fingerprinting -> HTML/JSON report.",
        epilog="Examples:\n  python -m reconforge example.com --passive\n"
               "  python -m reconforge example.com --threads 50 --yes\n",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("domain", help="target apex domain, e.g. example.com")
    p.add_argument("--passive", action="store_true",
                   help="never touch the target's web servers; no brute force, AXFR or HTTP probing")
    p.add_argument("--no-brute", action="store_true", help="skip DNS brute force")
    p.add_argument("--no-http", action="store_true", help="skip HTTP/TLS probing and fingerprinting")
    p.add_argument("-w", "--wordlist", default=DEFAULT_WORDLIST, help="brute-force wordlist (default: bundled)")
    p.add_argument("-t", "--threads", type=int, default=30, help="concurrent workers (default 30)")
    p.add_argument("--timeout", type=float, default=8.0, help="network timeout in seconds (default 8)")
    p.add_argument("--max-hosts", type=int, default=150, help="max hosts to HTTP-probe (default 150)")
    p.add_argument("--resolvers", type=lambda s: [x.strip() for x in s.split(",") if x.strip()],
                   default=None, help="comma-separated DNS resolvers (default: system / 1.1.1.1,8.8.8.8)")
    p.add_argument("-o", "--output", default="output", help="output directory (default ./output)")
    p.add_argument("--format", default="html,json", help="report formats: html,json (default both)")
    p.add_argument("-y", "--yes", action="store_true", help="confirm you are authorised; skip the prompt")
    p.add_argument("-v", "--verbose", action="store_true")
    p.add_argument("-q", "--quiet", action="store_true")
    p.add_argument("--version", action="version", version=f"ReconForge {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    log = Log(verbose=args.verbose, quiet=args.quiet)

    domain = normalize_domain(args.domain)
    if not is_valid_domain(domain):
        log.err(f"'{args.domain}' is not a valid domain name")
        return 2
    if not args.passive and not os.path.isfile(args.wordlist) and not args.no_brute:
        log.err(f"wordlist not found: {args.wordlist}")
        return 2
    formats = [f.strip().lower() for f in args.format.split(",") if f.strip()]
    if not set(formats) <= {"html", "json"}:
        log.err("--format accepts only: html, json")
        return 2

    if not args.quiet:
        print(BANNER.format(v=__version__))
    if not args.yes and not args.passive:
        answer = input(f"Do you own or have written permission to test {domain}? [y/N] ").strip().lower()
        if answer not in ("y", "yes"):
            log.err("Aborted. Run with --passive for third-party-friendly lookups only.")
            return 1

    try:
        res = run_recon(domain, args, log)
    except KeyboardInterrupt:
        log.err("Interrupted by user")
        return 130

    out = write_outputs(res, args.output, formats)
    sev = {}
    for f in res["findings"]:
        sev[f["severity"]] = sev.get(f["severity"], 0) + 1
    log.ok(f"Done in {res['meta']['duration_s']}s - {len(res['subdomains'])} hosts, "
           f"findings: " + (", ".join(f"{v} {k}" for k, v in sev.items()) or "none"))
    log.ok(f"Report: {out / 'report.html' if 'html' in formats else out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
