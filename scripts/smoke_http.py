"""HTTP smoke tests for POST /api/x12/audit.

Exercises the running API with both a valid envelope and a series of
damaged envelopes, asserting on HTTP status, stable error codes and the
first locatable segment index.  Exits non-zero if any assertion fails.

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


def isa(control: str = "000000001") -> str:
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
        ":",
    ]
    return "ISA*" + "*".join(fields) + "~"


GS = "GS*PO*SENDER*PARTNER*20240101*1200*1*X*005010~"
IEA = "IEA*1*000000001~"


def post(
    raw: bytes,
    content_type: str = "application/octet-stream",
    query: str = "",
):
    url = ENDPOINT + (f"?{query}" if query else "")
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
    print("scenario: valid multi-group interchange")
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


def isa_custom(
    control: str = "000000001",
    element: str = "|",
    component: str = "^",
    terminator: str = "\n",
) -> str:
    """Build a fixed-width, 106-byte ISA with arbitrary delimiters."""
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


def scenario_default_mode_compatibility():
    print("scenario: default mode keeps the original response shape")
    body = (
        isa()
        + GS
        + "ST*850*100~SE*2*100~"
        + "GE*1*1~"
        + IEA
    ).encode("ascii")
    status, payload = post(body)
    check("http 200", status == 200, f"got {status} {payload}")
    check(
        "default response has no transactions field",
        "transactions" not in payload,
        str(payload),
    )
    check(
        "default summary fields unchanged",
        set(payload)
        == {
            "interchange_control_number",
            "group_count",
            "transaction_count",
            "sha256",
        },
        str(payload),
    )


def scenario_detail_transactions():
    print("scenario: detail=transactions with custom delimiters")
    # Custom element '|', component '^', terminator LF.  Two groups so the
    # ordering (group then position) and GS06 association can be checked.
    isa_c = isa_custom()
    body = (
        isa_c
        + "GS|PO|S|R|D|T|1|X|V\n"
        + "ST|850|100\nBEG|00\nSE|3|100\n"
        + "ST|820|101\nSE|2|101\n"
        + "GE|2|1\n"
        + "GS|PO|S|R|D|T|2|X|V\n"
        + "ST|997|200\nSE|2|200\n"
        + "GE|1|2\n"
        + "IEA|2|000000001\n"
    ).encode("ascii")
    status, payload = post(body, query="detail=transactions")
    check("http 200", status == 200, f"got {status} {payload}")
    check("transaction count", payload.get("transaction_count") == 3, str(payload))

    transactions = payload.get("transactions")
    check("transactions present", isinstance(transactions, list), str(payload))
    expected = [
        # gs06, st01, st02, segment_range
        ("1", "850", "100", (3, 5)),
        ("1", "820", "101", (6, 7)),
        ("2", "997", "200", (10, 11)),
    ]
    check("three entries in order", transactions is not None
          and len(transactions) == 3, str(payload))
    if transactions and len(transactions) == 3:
        for entry, (gs06, st01, st02, seg_range) in zip(transactions, expected):
            check(
                f"gs06/st01/st02 {st02}",
                (entry.get("gs06"), entry.get("st01"), entry.get("st02"))
                == (gs06, st01, st02),
                str(entry),
            )
            check(
                f"segment_range {st02}",
                tuple(entry.get("segment_range", [])) == seg_range,
                str(entry),
            )
            byte_range = entry.get("byte_range", [])
            check(
                f"byte_range is half-open {st02}",
                len(byte_range) == 2 and byte_range[1] > byte_range[0],
                str(entry),
            )
            start, end = byte_range
            slice_ = body[start:end]
            check(
                f"slice starts at ST tag {st02}",
                slice_.startswith(f"ST|{st01}|{st02}\n".encode()),
                repr(slice_),
            )
            check(
                f"slice ends with SE terminator {st02}",
                slice_.endswith(
                    f"SE|{seg_range[1] - seg_range[0] + 1}|{st02}\n".encode()
                ),
                repr(slice_),
            )
            check(
                f"sha256 matches raw slice {st02}",
                entry.get("sha256") == hashlib.sha256(slice_).hexdigest(),
                str(entry),
            )
            check(
                f"lowercase hex sha256 {st02}",
                isinstance(entry.get("sha256"), str)
                and entry["sha256"] == entry["sha256"].lower()
                and len(entry["sha256"]) == 64,
                str(entry),
            )

    print("scenario: envelope error with detail=transactions has no list")
    bad = (
        isa_c
        + "GS|PO|S|R|D|T|1|X|V\n"
        + "ST|850|100\nBEG|00\nSE|2|100\n"   # count actually 3
        + "GE|9|1\nIEA|9|000000001\n"
    ).encode("ascii")
    status, payload = post(bad, query="detail=transactions")
    check("http 422", status == 422, f"got {status} {payload}")
    error = payload.get("error", {})
    check(
        "first inner error preserved",
        error.get("code") == "SEGMENT_COUNT_MISMATCH"
        and error.get("segment") == 5,
        str(payload),
    )
    check(
        "no partial transaction list on error",
        "transactions" not in payload,
        str(payload),
    )


def scenario_detail_parameter_validation():
    print("scenario: unsupported detail values are rejected as request errors")
    body = (
        isa()
        + GS
        + "ST*850*100~SE*2*100~GE*1*1~"
        + IEA
    ).encode("ascii")
    for value in ("summary", "TRANSACTIONS", "foo", ""):
        status, payload = post(body, query=f"detail={value}")
        check(
            f"http 400 for detail={value!r}",
            status == 400,
            f"got {status} {payload}",
        )
        check(
            f"error code for detail={value!r}",
            payload.get("error", {}).get("code") == "INVALID_DETAIL_PARAMETER",
            str(payload),
        )
    # Unrelated query parameters keep being tolerated only via absence of
    # detail; detail appearing twice with a bad value must still 400.
    status, payload = post(body, query="detail=transactions&detail=other")
    check(
        "repeated detail with bad value -> 400",
        status == 400 and payload.get("error", {}).get("code")
        == "INVALID_DETAIL_PARAMETER",
        f"got {status} {payload}",
    )
    status, payload = post(body, query="detail=transactions&detail=transactions")
    check(
        "repeated detail=transactions still works",
        status == 200 and isinstance(payload.get("transactions"), list),
        f"got {status} {payload}",
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
    scenario_default_mode_compatibility()
    scenario_detail_transactions()
    scenario_detail_parameter_validation()
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
