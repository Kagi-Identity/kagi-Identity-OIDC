#!/usr/bin/env python3
"""Static regression checks for the hosted RP demo."""
from pathlib import Path
import re
import sys

ROOT = Path("examples/rp-demo")
INDEX = ROOT / "index.html"
CALLBACK = ROOT / "callback.html"

def fail(message: str) -> int:
    print(f"ERROR: {message}", file=sys.stderr)
    return 1

def main() -> int:
    for path in (INDEX, CALLBACK):
        if not path.is_file():
            return fail(f"missing required file: {path}")

    index = INDEX.read_text(encoding="utf-8")
    callback = CALLBACK.read_text(encoding="utf-8")

    required_index = (
        'lang="ja"',
        "https://kagi-gakusei-bot.vercel.app",
        "/healthz",
        "/.well-known/openid-configuration",
        "/jwks.json",
        "code_challenge_method",
        "sessionStorage",
        "noopener noreferrer",
    )
    missing = [value for value in required_index if value not in index]
    if missing:
        return fail("index.html is missing required integration markers: " + ", ".join(missing))

    required_callback = (
        "/token",
        "/userinfo",
        "state mismatch",
        "nonce",
        "code_verifier",
        "signature_validation",
        "NOT PERFORMED IN THIS BROWSER DEMO",
    )
    missing = [value for value in required_callback if value not in callback]
    if missing:
        return fail("callback.html is missing required validation markers: " + ", ".join(missing))

    if "localStorage" in index + callback:
        return fail("demo must not persist credentials in localStorage")
    if re.search(r"client_secret|CLIENT_SECRET", index + callback, re.I):
        return fail("public browser demo must not contain a client secret")
    if re.search(r"<script[^>]+src=", index, re.I):
        return fail("index should remain self-contained so the deployment cannot silently omit its script")
    if re.search(r"<script[^>]+src=", callback, re.I):
        return fail("callback should remain self-contained so the deployment cannot silently omit its script")

    print("RP demo checks passed: files, endpoint diagnostics, PKCE, state/nonce checks, and no persistent browser credentials.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
