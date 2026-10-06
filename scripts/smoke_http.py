"""HTTP smoke tests for POST /api/x12/audit.

Exercises the running API with both a valid envelope and a series of
damaged envelopes, asserting on HTTP status, stable error codes and the
first locatable segment index.  Also covers the optional
``?detail=transactions`` evidence mode (exact byte intervals and
per-transaction SHA-256 digests), default-mode response compatibility,
custom delimiters and request-error handling for the query parameter.
Exits non-zero if any assertion fails.

Usage: python3 smoke_http.py [BASE_URL]
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import urllib.error
import urllib.request

BASE_URL = (
    sys.argv[1]
    if len(sys.argv) > 1
    else os.environ.get("BASE_URL", "http://localhost:8080")
).rstrip("/")

ENDPOINT = f"{BASE_URL}/api/x12/audit"
MAX_BYTES = 2 * 1024 * 1024  # 2 MiB

failures: list[str] = []


def isa(
    control: str = "000000001",
    element: str = "*",
    component: str = ":",
    terminator: str = "~",
) -> str:
    fields = [
        "00",
        " " * 10,
        "00",
        " " * 10,
        "ZZ",
        "SENDER".ljust(15),
        "ZZ",
        "PARTNER".ljust(15),
        " " * 6,
        " " * 4,
        "U",
        "00501",
        control.rjust(9),
        "0",
        "P",
        component,
    ]
    return "ISA" + element + element.join(fields) + terminator


GS = "GS*PO*SENDER*PARTNER*20240101*1200*1*X*005010~"
IEA = "IEA*1*000000001~"


def post(
    raw: bytes,
    content_type: str = "application/octet-stream",
    query: str | None = None,
):
    url = ENDPOINT if query is None else f"{ENDPOINT}?{query}"
    req = urllib.request.Request(
        url,
        data=raw,
        headers={"Content-Type": content_type},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, json.loads(response.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def check(name: str, condition: bool, detail: str = "") -> None:
    if condition:
        print(f"  PASS  {name}")
    else:
        print(f"  FAIL  {name} {detail}")
        failures.append(name)


def scenario_valid():
    print("scenario: valid multi-group interchange (default mode)")
    body = (
        isa()
        + "GS*PO*S*R*D*T*1*X*V~"
        + "ST*850*100~BEG*00~REF*A:B~SE*4*100~"
        + "GE*1*1~"
        + "GS*PO*S*R*D*T*2*X*V~"
        + "ST*850*200~SE*2*200~"
        + "ST*850*201~SE*2*201~"
        + "GE*2*2~"
        + "IEA*2*000000001~"
    ).encode("ascii")
    status, payload = post(body)
    check("http 200", status == 200, f"got {status} {payload}")
    check(
        "control number",
        payload.get("interchange_control_number") == "000000001",
        str(payload),
    )
    check("group count", payload.get("group_count") == 2, str(payload))
    check("transaction count", payload.get("transaction_count") == 3, str(payload))
    check(
        "sha256 of raw body",
        payload.get("sha256") == hashlib.sha256(body).hexdigest(),
        str(payload),
    )
    # Default mode must not leak the detail field.
    check(
        "no transactions field in default mode",
        "transactions" not in payload,
        str(payload),
    )
    return body


def _assert_evidence(name, body, entries):
    """Validate the detail-mode response against expected transactions.

    ``entries`` is a list of (gs06, st01, st02, expected_slice) tuples in
    functional-group/document order.
    """
    status, payload = post(body, query="detail=transactions")
    check(f"{name}: http 200", status == 200, f"got {status} {payload}")
    txns = payload.get("transactions")
    check(
        f"{name}: transaction list length",
        isinstance(txns, list) and len(txns) == len(entries),
        str(payload),
    )
    if not isinstance(txns, list):
        return
    required = {
        "gs06",
        "st01",
        "st02",
        "segment_start",
        "segment_end",
        "byte_start",
        "byte_end",
        "sha256",
    }
    for index, (txn, (gs06, st01, st02, expected)) in enumerate(zip(txns, entries)):
        prefix = f"{name}: txn[{index}]"
        check(f"{prefix} field set", required <= set(txn), str(txn))
        check(f"{prefix} gs06", txn.get("gs06") == gs06, str(txn))
        check(f"{prefix} st01", txn.get("st01") == st01, str(txn))
        check(f"{prefix} st02", txn.get("st02") == st02, str(txn))
        start, end = txn.get("byte_start"), txn.get("byte_end")
        valid_span = (
            isinstance(start, int)
            and isinstance(end, int)
            and 0 <= start < end <= len(body)
        )
        check(f"{prefix} byte bounds", valid_span, str(txn))
        if not valid_span:
            continue
        evidence = body[start:end]
        check(
            f"{prefix} slice starts at ST tag",
            evidence[:2] == b"ST",
            repr(evidence),
        )
        check(
            f"{prefix} exact raw slice",
            evidence == expected,
            f"{evidence!r} != {expected!r}",
        )
        check(
            f"{prefix} lowercase sha256 of slice",
            txn.get("sha256") == hashlib.sha256(evidence).hexdigest(),
            str(txn),
        )
        check(
            f"{prefix} segment interval",
            isinstance(txn.get("segment_start"), int)
            and isinstance(txn.get("segment_end"), int)
            and 1 <= txn["segment_start"] <= txn["segment_end"],
            str(txn),
        )


def scenario_detail():
    print("scenario: detail=transactions evidence list")
    body = (
        isa()
        + "GS*PO*S*R*D*T*1*X*V~"
        + "ST*850*100~BEG*00~REF*A:B~SE*4*100~"
        + "GE*1*1~"
        + "GS*PO*S*R*D*T*2*X*V~"
        + "ST*810*200~SE*2*200~"
        + "ST*997*201~SE*2*201~"
        + "GE*2*2~"
        + "IEA*2*000000001~"
    ).encode("ascii")
    _assert_evidence(
        "detail",
        body,
        [
            ("1", "850", "100", b"ST*850*100~BEG*00~REF*A:B~SE*4*100~"),
            ("2", "810", "200", b"ST*810*200~SE*2*200~"),
            ("2", "997", "201", b"ST*997*201~SE*2*201~"),
        ],
    )
    # The summary fields remain present and unchanged in detail mode.
    status, payload = post(body, query="detail=transactions")
    check("detail keeps group count", payload.get("group_count") == 2, str(payload))
    check(
        "detail keeps transaction count",
        payload.get("transaction_count") == 3,
        str(payload),
    )
    check(
        "detail keeps whole-body sha256",
        payload.get("sha256") == hashlib.sha256(body).hexdigest(),
        str(payload),
    )


def scenario_detail_custom_delimiters():
    print("scenario: detail mode with custom delimiters and whitespace")
    body = (
        isa(element="|", component="^", terminator="\n")
        + "GS|PO|S|R|20240101|1200|55|X|005010\n"
        + "  ST|850|100\n"
        + "BEG|00|NE|PO-1\n"
        + " SE|3|100\n"
        + "GE|1|55\n"
        + "IEA|1|000000001\n"
    ).encode("ascii")
    _assert_evidence(
        "custom-delims",
        body,
        [("55", "850", "100", b"ST|850|100\nBEG|00|NE|PO-1\n SE|3|100\n")],
    )

    # CR terminator and a non-standard element separator.
    cr_body = (
        isa(element="@", component=":", terminator="\r")
        + "GS@PO@S@R@D@T@9@X@V\r"
        + "ST@850@7\rSE@2@7\r"
        + "GE@1@9\r"
        + "IEA@1@000000001\r"
    ).encode("ascii")
    _assert_evidence(
        "cr-terminator",
        cr_body,
        [("9", "850", "7", b"ST@850@7\rSE@2@7\r")],
    )


def scenario_detail_errors():
    print("scenario: invalid detail query parameter")
    body = (isa() + GS + "ST*850*100~SE*2*100~GE*1*1~" + IEA).encode("ascii")
    for bad_query in ("detail=full", "detail=", "detail=transactions&detail=full"):
        status, payload = post(body, query=bad_query)
        check(
            f"400 for '{bad_query}'",
            status == 400,
            f"got {status} {payload}",
        )
        check(
            f"error code for '{bad_query}'",
            payload.get("error", {}).get("code") == "INVALID_QUERY_PARAMETER",
            str(payload),
        )

    print("scenario: envelope error with detail=transactions has no partial list")
    damaged = (
        isa()
        + GS
        + "ST*850*100~BEG*00~SE*2*100~"  # count mismatch, earliest error
        + "ST*850*200~SE*2*200~"
        + "GE*9*1~"
        + "IEA*9*000000001~"
    ).encode("ascii")
    status, payload = post(damaged, query="detail=transactions")
    check("still 422", status == 422, f"got {status} {payload}")
    error = payload.get("error", {})
    check(
        "first locatable inner error wins",
        error.get("code") == "SEGMENT_COUNT_MISMATCH"
        and error.get("segment") == 5,
        str(payload),
    )
    check(
        "no partial transaction list on error",
        "transactions" not in payload,
        str(payload),
    )

    print("scenario: transport error keeps its semantics with detail param")
    status, payload = post(b"", query="detail=transactions")
    check("empty body still 400", status == 400, f"got {status} {payload}")
    check(
        "empty body error code",
        payload.get("error", {}).get("code") == "EMPTY_MESSAGE",
        str(payload),
    )


def expect_envelope_error(name, body: bytes, status_code: int, code: str, segment: int):
    print(f"scenario: {name}")
    status, payload = post(body)
    error = payload.get("error", {})
    check("http status", status == status_code, f"got {status} {payload}")
    check("error code", error.get("code") == code, str(payload))
    check("segment index", error.get("segment") == segment, str(payload))
    check("message present", bool(error.get("message")), str(payload))


def scenario_damaged():
    expect_envelope_error(
        "truncated final segment (no terminator)",
        (isa() + GS + "ST*850*100~SE*2*100~GE*1*1~IEA*1*000000001").encode(),
        422,
        "MISSING_TERMINATOR",
        6,
    )

    # Inner SE error plus deliberately wrong GE and IEA summaries: the
    # innermost, earliest error must not be masked.
    expect_envelope_error(
        "SE count wrong while GE/IEA summaries also wrong",
        (
            isa()
            + GS
            + "ST*850*100~BEG*00~SE*2*100~"   # actual span is 3
            + "GE*9*1~"
            + "IEA*9*000000001~"
        ).encode("ascii"),
        422,
        "SEGMENT_COUNT_MISMATCH",
        5,
    )

    expect_envelope_error(
        "SE control number mismatch",
        (isa() + GS + "ST*850*100~SE*2*999~GE*1*1~" + IEA).encode("ascii"),
        422,
        "CONTROL_NUMBER_MISMATCH",
        4,
    )

    expect_envelope_error(
        "GE transaction count mismatch",
        (
            isa()
            + GS
            + "ST*850*100~SE*2*100~"
            + "ST*850*200~SE*2*200~"
            + "GE*1*1~" + IEA
        ).encode("ascii"),
        422,
        "GE_COUNT_MISMATCH",
        7,
    )

    expect_envelope_error(
        "IEA group count mismatch",
        (isa() + GS + "ST*850*100~SE*2*100~GE*1*1~IEA*2*000000001~").encode(),
        422,
        "IEA_COUNT_MISMATCH",
        6,
    )

    expect_envelope_error(
        "IEA control number mismatch",
        (isa() + GS + "ST*850*100~SE*2*100~GE*1*1~IEA*1*000000999~").encode(),
        422,
        "CONTROL_NUMBER_MISMATCH",
        6,
    )

    expect_envelope_error(
        "interleaved levels (GE before SE)",
        (isa() + GS + "ST*850*100~GE*1*1~" + IEA).encode("ascii"),
        422,
        "NESTING_VIOLATION",
        4,
    )

    expect_envelope_error(
        "trailing data after IEA",
        (isa() + GS + "ST*850*100~SE*2*100~GE*1*1~" + IEA + "ZZZ*1~").encode(),
        422,
        "TRAILING_DATA",
        7,
    )

    expect_envelope_error(
        "second ISA in one message",
        (isa() + isa()).encode("ascii"),
        422,
        "MULTIPLE_INTERCHANGES",
        2,
    )


def scenario_transport():
    print("scenario: wrong content type")
    status, payload = post(b"whatever", "text/plain")
    check("http 415", status == 415, f"got {status} {payload}")
    check(
        "error code",
        payload.get("error", {}).get("code") == "UNSUPPORTED_MEDIA_TYPE",
        str(payload),
    )

    print("scenario: empty body")
    status, payload = post(b"")
    check("http 400", status == 400, f"got {status} {payload}")
    check(
        "error code",
        payload.get("error", {}).get("code") == "EMPTY_MESSAGE",
        str(payload),
    )

    print("scenario: body over 2 MiB")
    status, payload = post(b"x" * (MAX_BYTES + 1))
    check("http 413", status == 413, f"got {status} {payload}")
    check(
        "error code",
        payload.get("error", {}).get("code") == "MESSAGE_TOO_LARGE",
        str(payload),
    )

    print("scenario: health endpoint")
    with urllib.request.urlopen(f"{BASE_URL}/health", timeout=5) as response:
        check("health 200", response.status == 200)


def main() -> int:
    print(f"Smoke testing X12 audit API at {ENDPOINT}")
    scenario_valid()
    scenario_detail()
    scenario_detail_custom_delimiters()
    scenario_detail_errors()
    scenario_damaged()
    scenario_transport()
    print()
    if failures:
        print(f"{len(failures)} smoke check(s) FAILED: {', '.join(failures)}")
        return 1
    print("All HTTP smoke checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
