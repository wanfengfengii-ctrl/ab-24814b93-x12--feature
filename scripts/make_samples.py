"""Generate a sample valid X12 interchange at samples/sample.edi."""

from __future__ import annotations

import os


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
        "260106",          # ISA09 date YYMMDD
        "1200",            # ISA10 time HHMM
        "U",
        "00501",
        control.rjust(9),
        "0",
        "P",
        ":",
    ]
    return "ISA*" + "*".join(fields) + "~"


def main() -> None:
    message = (
        isa()
        + "GS*PO*SENDER*PARTNER*20260106*1200*1*X*005010~"
        + "ST*850*0001~"
        + "BEG*00*NE*PO-0001**20260106~"
        + "REF*IA:ACME:42~"
        + "SE*4*0001~"
        + "GE*1*1~"
        + "IEA*1*000000001~"
    )
    out_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "samples")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "sample.edi")
    with open(path, "w", encoding="ascii", newline="") as handle:
        handle.write(message)
    print(f"wrote {path} ({len(message)} bytes)")


if __name__ == "__main__":
    main()
