#!/usr/bin/env python3
"""Exercise the shared fixed-window limiter against an isolated local server."""
import os
import sys
import requests

BASE = os.environ.get("KAGI_BASE", "http://127.0.0.1:8080").rstrip("/")

def main() -> int:
    session = requests.Session()
    statuses = []
    for _ in range(61):
        response = session.get(BASE + "/login", timeout=5, allow_redirects=False)
        statuses.append(response.status_code)

    if statuses[-1] != 429:
        print(f"expected request 61 to be rate-limited; got {statuses[-1]}", file=sys.stderr)
        return 1
    if statuses.count(429) != 1:
        print(f"expected exactly one 429 in 61 requests; got {statuses.count(429)}", file=sys.stderr)
        return 1

    retry = statuses[-1]
    print("shared rate-limit smoke test passed (61st request rejected).")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
