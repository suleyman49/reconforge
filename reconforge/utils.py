"""Shared helpers: console logging and domain validation."""
import os
import re
import sys
from urllib.parse import urlparse

DOMAIN_RE = re.compile(
    r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$"
)


def normalize_domain(raw: str) -> str:
    """Turn 'https://Example.com/path' into 'example.com'."""
    raw = (raw or "").strip().lower()
    if "://" in raw:
        raw = urlparse(raw).netloc or raw
    raw = raw.split("/")[0].split(":")[0].rstrip(".")
    try:
        raw = raw.encode("idna").decode("ascii")
    except UnicodeError:
        pass
    return raw


def is_valid_domain(domain: str) -> bool:
    return bool(DOMAIN_RE.match(domain or ""))


class Log:
    """Tiny colored console logger."""

    COLORS = {
        "info": "\033[36m",
        "ok": "\033[32m",
        "warn": "\033[33m",
        "err": "\033[31m",
        "step": "\033[1;35m",
        "dim": "\033[90m",
    }
    SYMBOLS = {"info": "[*]", "ok": "[+]", "warn": "[!]", "err": "[-]", "step": "[>]", "dim": "   "}

    def __init__(self, verbose: bool = False, quiet: bool = False):
        self.verbose = verbose
        self.quiet = quiet
        self.color = sys.stdout.isatty() and (os.name != "nt" or "WT_SESSION" in os.environ)

    def _emit(self, kind: str, msg: str):
        if self.quiet and kind != "err":
            return
        line = f"{self.SYMBOLS[kind]} {msg}"
        if self.color:
            line = f"{self.COLORS[kind]}{line}\033[0m"
        print(line, file=sys.stderr if kind == "err" else sys.stdout, flush=True)

    def info(self, msg): self._emit("info", msg)
    def ok(self, msg): self._emit("ok", msg)
    def warn(self, msg): self._emit("warn", msg)
    def err(self, msg): self._emit("err", msg)
    def step(self, msg): self._emit("step", msg)

    def debug(self, msg):
        if self.verbose:
            self._emit("dim", msg)
