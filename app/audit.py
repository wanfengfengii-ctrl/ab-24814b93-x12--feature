"""X12 interchange envelope auditing.

The auditor validates only the envelope structure (ISA/IEA, GS/GE, ST/SE):

* exactly one ISA/IEA interchange,
* 1..64 GS/GE functional groups,
* 1..500 ST/SE transaction sets per group,
* segments never interleave across the three envelope levels,
* paired control numbers match,
* SE segment counts, GE transaction counts and IEA group counts agree.

Delimiters are taken from the fixed-length ISA segment:

* element separator    = byte 4   (ISA byte offset 3),
* component separator  = byte 105 (ISA byte offset 104),
* segment terminator   = byte 106 (ISA byte offset 105).

Every error is reported at the first segment where it is locatable.  Because
segments are processed strictly in document order, an inner envelope error
(SE/GE level) is always raised before any later outer summary (IEA level)
could mask it.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

MAX_MESSAGE_BYTES = 2 * 1024 * 1024  # 2 MiB

MAX_GROUPS = 64
MAX_TRANSACTIONS_PER_GROUP = 500

# Fixed element widths inside the 105-byte ISA payload (tag included).
ISA_FIELD_WIDTHS = (3, 2, 10, 2, 10, 2, 15, 2, 15, 6, 4, 1, 5, 9, 1, 1, 1)


class EnvelopeError(Exception):
    """Raised on the first envelope/framing violation.

    ``code`` is a stable, machine-readable error code and ``segment`` is the
    1-based segment index where the problem is locatable (1 for errors in
    the ISA header itself).
    """

    def __init__(self, code: str, message: str, segment: int = 1):
        super().__init__(message)
        self.code = code
        self.segment = segment


@dataclass(frozen=True)
class AuditResult:
    interchange_control_number: str
    group_count: int
    transaction_count: int
    sha256: str


@dataclass
class _Transaction:
    st_index: int
    control_number: bytes


@dataclass
class _Group:
    gs_index: int
    control_number: bytes
    transactions: list[_Transaction]


def _is_printable_punctuation(value: int) -> bool:
    if not 0x21 <= value <= 0x7E:
        return False
    ch = chr(value)
    return not (ch.isalnum() or ch == " ")


def audit(raw: bytes) -> AuditResult:
    """Audit a raw X12 message and return its envelope summary."""

    if len(raw) == 0:
        raise EnvelopeError("EMPTY_MESSAGE", "request body is empty", 1)
    if len(raw) > MAX_MESSAGE_BYTES:
        raise EnvelopeError(
            "MESSAGE_TOO_LARGE",
            f"message exceeds {MAX_MESSAGE_BYTES} bytes",
            1,
        )
    try:
        raw.decode("ascii")
    except UnicodeDecodeError:
        raise EnvelopeError("NON_ASCII", "message is not pure ASCII", 1) from None

    if len(raw) < 106:
        raise EnvelopeError(
            "ISA_TOO_SHORT",
            "ISA segment must be at least 106 bytes including terminator",
            1,
        )
    if raw[0:3] != b"ISA":
        raise EnvelopeError(
            "MISSING_ISA", "message must begin with an ISA segment", 1
        )

    element_sep = raw[3]
    component_sep = raw[104]
    segment_terminator = raw[105]

    if not _is_printable_punctuation(element_sep):
        raise EnvelopeError(
            "BAD_DELIMITER", "invalid ISA element separator", 1
        )
    if not _is_printable_punctuation(component_sep):
        raise EnvelopeError(
            "BAD_DELIMITER", "invalid ISA component separator", 1
        )
    # The terminator may additionally be CR or LF in line-oriented feeds.
    if not (
        _is_printable_punctuation(segment_terminator)
        or segment_terminator in (0x0D, 0x0A)
    ):
        raise EnvelopeError(
            "BAD_DELIMITER", "invalid ISA segment terminator", 1
        )
    if len({element_sep, component_sep, segment_terminator}) != 3:
        raise EnvelopeError(
            "BAD_DELIMITER",
            "element separator, component separator and segment terminator "
            "must be distinct",
            1,
        )

    element_sep_byte = bytes([element_sep])
    terminator_byte = bytes([segment_terminator])

    isa_core = raw[0:105]
    isa_parts = isa_core.split(element_sep_byte)
    if len(isa_parts) != len(ISA_FIELD_WIDTHS) or any(
        len(part) != width
        for part, width in zip(isa_parts, ISA_FIELD_WIDTHS)
    ):
        raise EnvelopeError(
            "ISA_MALFORMED",
            "ISA segment does not match its fixed-length element layout",
            1,
        )
    interchange_control = isa_parts[13].decode("ascii").strip()

    raw_tokens = raw.split(terminator_byte)
    if raw_tokens[0] != isa_core:
        # Only possible if the terminator byte occurs inside the ISA header,
        # which the fixed-width validation above normally catches first.
        raise EnvelopeError("ISA_MALFORMED", "malformed ISA segment", 1)

    # A trailing terminator is mandatory; its absence usually means the
    # message was truncated.  CRLF/LF line endings after the final
    # terminator are tolerated.
    if raw_tokens[-1].strip(b" \t\r\n") != b"":
        raise EnvelopeError(
            "MISSING_TERMINATOR",
            "final segment is missing its segment terminator; the message "
            "may be truncated",
            len(raw_tokens),
        )

    groups: list[_Group] = []
    current_group: _Group | None = None
    current_txn: _Transaction | None = None
    closed = False
    last_segment_index = max(len(raw_tokens) - 1, 1)

    def tag_of(token: bytes) -> bytes:
        return token.split(element_sep_byte, 1)[0].strip()

    for position, raw_token in enumerate(raw_tokens[1:], start=2):
        token = raw_token.strip(b" \t\r\n")

        # A final empty token is produced by the trailing segment terminator
        # (optionally followed by line breaks).  Any other blank token is an
        # empty segment.
        if not token:
            if position == len(raw_tokens):
                continue
            raise EnvelopeError(
                "EMPTY_SEGMENT", "empty segment encountered", position
            )

        tag = tag_of(token)
        parts = token.split(element_sep_byte)

        if tag == b"ISA":
            raise EnvelopeError(
                "MULTIPLE_INTERCHANGES",
                "a second ISA segment was found; exactly one interchange is "
                "allowed per message",
                position,
            )

        if closed:
            raise EnvelopeError(
                "TRAILING_DATA",
                "data found after the IEA segment",
                position,
            )

        if tag == b"GS":
            if current_txn is not None:
                raise EnvelopeError(
                    "NESTING_VIOLATION",
                    "GS encountered before the open ST/SE transaction was "
                    "closed",
                    position,
                )
            if current_group is not None:
                raise EnvelopeError(
                    "NESTING_VIOLATION",
                    "GS encountered before the previous GS/GE group was "
                    "closed",
                    position,
                )
            if len(groups) >= MAX_GROUPS:
                raise EnvelopeError(
                    "GROUP_LIMIT_EXCEEDED",
                    f"an interchange may contain at most {MAX_GROUPS} groups",
                    position,
                )
            if len(parts) < 9:
                raise EnvelopeError(
                    "GS_MALFORMED",
                    "GS segment must contain eight elements",
                    position,
                )
            current_group = _Group(
                gs_index=position,
                control_number=parts[6],
                transactions=[],
            )
            groups.append(current_group)

        elif tag == b"ST":
            if current_group is None:
                raise EnvelopeError(
                    "NESTING_VIOLATION",
                    "ST encountered outside of a GS/GE group",
                    position,
                )
            if current_txn is not None:
                raise EnvelopeError(
                    "NESTING_VIOLATION",
                    "ST encountered before the previous ST/SE transaction "
                    "was closed",
                    position,
                )
            if len(current_group.transactions) >= MAX_TRANSACTIONS_PER_GROUP:
                raise EnvelopeError(
                    "TRANSACTION_LIMIT_EXCEEDED",
                    "a group may contain at most "
                    f"{MAX_TRANSACTIONS_PER_GROUP} transactions",
                    position,
                )
            if len(parts) < 3:
                raise EnvelopeError(
                    "ST_MALFORMED",
                    "ST segment must contain a control number (ST02)",
                    position,
                )
            current_txn = _Transaction(
                st_index=position,
                control_number=parts[2],
            )

        elif tag == b"SE":
            if current_group is None:
                raise EnvelopeError(
                    "NESTING_VIOLATION",
                    "SE encountered without a matching GS group",
                    position,
                )
            if current_txn is None:
                raise EnvelopeError(
                    "NESTING_VIOLATION",
                    "SE encountered without a matching ST",
                    position,
                )
            if len(parts) < 3:
                raise EnvelopeError(
                    "SE_MALFORMED",
                    "SE segment must contain SE01 (segment count) and SE02 "
                    "(control number)",
                    position,
                )
            declared_count_raw = parts[1].decode("ascii")
            if not declared_count_raw.isdigit() or int(declared_count_raw) < 2:
                raise EnvelopeError(
                    "SE_MALFORMED",
                    "SE01 segment count must be an integer of at least 2",
                    position,
                )
            declared_count = int(declared_count_raw)
            actual_count = position - current_txn.st_index + 1
            if declared_count != actual_count:
                raise EnvelopeError(
                    "SEGMENT_COUNT_MISMATCH",
                    f"SE01 declares {declared_count} segments but the "
                    f"ST..SE envelope spans {actual_count}",
                    position,
                )
            if parts[2] != current_txn.control_number:
                raise EnvelopeError(
                    "CONTROL_NUMBER_MISMATCH",
                    "SE02 control number does not match ST02",
                    position,
                )
            current_group.transactions.append(current_txn)
            current_txn = None

        elif tag == b"GE":
            if current_group is None:
                raise EnvelopeError(
                    "NESTING_VIOLATION",
                    "GE encountered without a matching GS",
                    position,
                )
            if current_txn is not None:
                raise EnvelopeError(
                    "NESTING_VIOLATION",
                    "GE encountered before the open ST/SE transaction was "
                    "closed with SE",
                    position,
                )
            if len(parts) < 3:
                raise EnvelopeError(
                    "GE_MALFORMED",
                    "GE segment must contain GE01 (transaction count) and "
                    "GE02 (control number)",
                    position,
                )
            txn_count = len(current_group.transactions)
            if txn_count == 0:
                raise EnvelopeError(
                    "ZERO_TRANSACTIONS",
                    "group contains no ST/SE transaction sets",
                    position,
                )
            declared_raw = parts[1].decode("ascii")
            if not declared_raw.isdigit():
                raise EnvelopeError(
                    "GE_MALFORMED",
                    "GE01 transaction count must be an integer",
                    position,
                )
            if int(declared_raw) != txn_count:
                raise EnvelopeError(
                    "GE_COUNT_MISMATCH",
                    f"GE01 declares {declared_raw} transactions but the "
                    f"group contains {txn_count}",
                    position,
                )
            if parts[2] != current_group.control_number:
                raise EnvelopeError(
                    "CONTROL_NUMBER_MISMATCH",
                    "GE02 control number does not match GS06",
                    position,
                )
            current_group = None

        elif tag == b"IEA":
            if current_txn is not None:
                raise EnvelopeError(
                    "NESTING_VIOLATION",
                    "IEA encountered before the open ST/SE transaction was "
                    "closed with SE",
                    position,
                )
            if current_group is not None:
                raise EnvelopeError(
                    "NESTING_VIOLATION",
                    "IEA encountered before the open GS/GE group was closed "
                    "with GE",
                    position,
                )
            if len(parts) < 3:
                raise EnvelopeError(
                    "IEA_MALFORMED",
                    "IEA segment must contain IEA01 (group count) and IEA02 "
                    "(control number)",
                    position,
                )
            if not groups:
                raise EnvelopeError(
                    "ZERO_GROUPS",
                    "interchange contains no GS/GE functional groups",
                    position,
                )
            declared_raw = parts[1].decode("ascii")
            if not declared_raw.isdigit():
                raise EnvelopeError(
                    "IEA_MALFORMED",
                    "IEA01 group count must be an integer",
                    position,
                )
            if int(declared_raw) != len(groups):
                raise EnvelopeError(
                    "IEA_COUNT_MISMATCH",
                    f"IEA01 declares {declared_raw} groups but the "
                    f"interchange contains {len(groups)}",
                    position,
                )
            # ISA13 is a fixed 9-character, space-padded field; IEA02 is
            # variable width, so compare the trimmed values.
            if parts[2].decode("ascii").strip() != interchange_control:
                raise EnvelopeError(
                    "CONTROL_NUMBER_MISMATCH",
                    "IEA02 control number does not match ISA13",
                    position,
                )
            closed = True

        else:
            # Any other segment is payload, which is only legal inside an
            # open transaction set.
            if current_txn is None:
                raise EnvelopeError(
                    "UNEXPECTED_SEGMENT",
                    f"segment {tag.decode('ascii', 'replace')!r} is not "
                    "allowed outside an ST/SE transaction",
                    position,
                )

    if not closed:
        if current_txn is not None:
            raise EnvelopeError(
                "MISSING_SE",
                "transaction set was never closed with an SE segment",
                current_txn.st_index,
            )
        if current_group is not None:
            raise EnvelopeError(
                "MISSING_GE",
                "functional group was never closed with a GE segment",
                current_group.gs_index,
            )
        raise EnvelopeError(
            "MISSING_IEA",
            "interchange was never closed with an IEA segment",
            last_segment_index,
        )

    transaction_count = sum(len(group.transactions) for group in groups)
    return AuditResult(
        interchange_control_number=interchange_control,
        group_count=len(groups),
        transaction_count=transaction_count,
        sha256=hashlib.sha256(raw).hexdigest(),
    )
