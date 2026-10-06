"""One-shot verification entrypoint for the ``verify`` compose service.

Steps, in order:

1. wait for the API health endpoint,
2. run the unit test suite (``unittest``),
3. run the application build check (``compileall``),
4. run HTTP smoke tests covering valid and damaged envelopes.

The process exits non-zero if any step fails; the exit code uses distinct
bits so logs (and CI) can tell which step failed:

* bit 0 (1): health wait timed out
* bit 1 (2): unit tests failed
* bit 2 (4): build check failed
* bit 3 (8): HTTP smoke tests failed
"""

from __future__ import annotations

import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.wait_for_health import wait  # noqa: E402

BASE_URL = os.environ.get("BASE_URL", "http://api:8080")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def run_step(name: str, cmd: list[str]) -> bool:
    print()
    print("=" * 70)
    print(f"STEP: {name}")
    print(f"$ {' '.join(cmd)}")
    print("-" * 70)
    completed = subprocess.run(cmd, cwd=ROOT)
    ok = completed.returncode == 0
    print(f"-> {name}: {'OK' if ok else 'FAILED'} (exit {completed.returncode})")
    return ok


def main() -> int:
    result = 0

    print(f"STEP: waiting for API health at {BASE_URL}")
    healthy = wait(BASE_URL, timeout_s=float(os.environ.get("HEALTH_TIMEOUT", "60")))
    result |= 0 if healthy else 1

    tests_ok = run_step(
        "unit tests", [sys.executable, "-m", "unittest", "discover", "-s", "tests"]
    )
    result |= 0 if tests_ok else 2

    build_ok = run_step(
        "application build check (byte-compile)",
        [sys.executable, "-m", "compileall", "-q", "app", "scripts"],
    )
    result |= 0 if build_ok else 4

    smoke_ok = run_step(
        "HTTP smoke tests",
        [sys.executable, os.path.join("scripts", "smoke_http.py"), BASE_URL],
    )
    result |= 0 if smoke_ok else 8

    print()
    print("=" * 70)
    if result == 0:
        print("VERIFICATION PASSED: all steps succeeded")
    else:
        labels = []
        if result & 1:
            labels.append("health")
        if result & 2:
            labels.append("unit-tests")
        if result & 4:
            labels.append("build-check")
        if result & 8:
            labels.append("http-smoke")
        print(f"VERIFICATION FAILED: {', '.join(labels)} (exit code {result})")
    return result


if __name__ == "__main__":
    sys.exit(main())
