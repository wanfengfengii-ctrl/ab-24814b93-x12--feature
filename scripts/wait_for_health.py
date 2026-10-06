"""Poll GET /health until the API is ready.

Usage: python3 wait_for_health.py [BASE_URL]
Exits 0 once a 200 response is received, 1 on timeout.
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.request
from urllib.error import URLError

DEFAULT_TIMEOUT_S = 60


def wait(base_url: str, timeout_s: float = DEFAULT_TIMEOUT_S) -> bool:
    deadline = time.monotonic() + timeout_s
    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        try:
            with urllib.request.urlopen(
                f"{base_url}/health", timeout=2
            ) as response:
                if response.status == 200:
                    payload = json.loads(response.read().decode("ascii"))
                    if payload.get("status") == "ok":
                        print(f"API is healthy after {attempt} attempt(s)")
                        return True
        except (URLError, OSError, ValueError):
            pass
        time.sleep(1)
    print(f"API at {base_url} did not become healthy within {timeout_s}s")
    return False


def main() -> int:
    base_url = (
        sys.argv[1]
        if len(sys.argv) > 1
        else os.environ.get("BASE_URL", "http://localhost:8080")
    ).rstrip("/")
    return 0 if wait(base_url) else 1


if __name__ == "__main__":
    sys.exit(main())
