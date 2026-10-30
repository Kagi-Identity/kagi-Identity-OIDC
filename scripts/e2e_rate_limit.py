#!/usr/bin/env python3
"""Exercise the shared fixed-window limiter against an isolated local server."""
import os
import sys
import requests

BASE = os.environ.get("KAGI_BASE", "http://127.0.0.1:8080").rstrip("/")

def main() -> int:
    session = requests.Session()
    statuses = []
    last_response = None
    for _ in range(61):
        last_response = session.get(BASE + "/login", timeout=5, allow_redirects=False)
        statuses.append(last_response.status_code)

    if statuses[-1] != 429:
        print(f"expected request 61 to be rate-limited; got {statuses[-1]}", file=sys.stderr)
        return 1
    if statuses.count(429) != 1:
        print(f"expected exactly one 429 in 61 requests; got {statuses.count(429)}", file=sys.stderr)
        return 1
    if not last_response.headers.get("Retry-After", "").isdigit():
        print("429 response did not include a numeric Retry-After header", file=sys.stderr)
        return 1

    print("shared rate-limit smoke test passed (61st request rejected with Retry-After).")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
