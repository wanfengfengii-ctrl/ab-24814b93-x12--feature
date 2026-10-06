"""Unit tests for the X12 envelope auditor."""

from __future__ import annotations

import hashlib
import unittest

from app.audit import (
    MAX_GROUPS,
    MAX_MESSAGE_BYTES,
    MAX_TRANSACTIONS_PER_GROUP,
    EnvelopeError,
    audit,
)

ELEMENT = "*"
COMPONENT = ":"
TERMINATOR = "~"


def isa(
    control: str = "000000001",
    element: str = ELEMENT,
    component: str = COMPONENT,
    terminator: str = TERMINATOR,
) -> str:
    """Build a fixed-width, 106-byte ISA segment (with terminator)."""
    fields = [
        "00",               # ISA01 authorization information qualifier
        " " * 10,           # ISA02 authorization information
        "00",               # ISA03 security information qualifier
        " " * 10,           # ISA04 security information
        "ZZ",               # ISA05 sender qualifier
        "SENDER".ljust(15),  # ISA06 sender id
        "ZZ",               # ISA07 receiver qualifier
        "PARTNER".ljust(15),  # ISA08 receiver id
        " " * 6,            # ISA09 interchange date
        " " * 4,            # ISA10 interchange time
        "U",                # ISA11 repetition/usage indicator
        "00501",            # ISA12 control version number
        control.rjust(9),  # ISA13 interchange control number
        "0",                # ISA14 acknowledgment requested
        "P",                # ISA15 usage indicator
        component,          # ISA16 component element separator
    ]
    return "ISA" + element + element.join(fields) + terminator


def build_message(
    groups: list[list[int]] | None = None,
    *,
    control: str = "000000001",
    element: str = ELEMENT,
    component: str = COMPONENT,
    terminator: str = TERMINATOR,
) -> bytes:
    """Build a well-formed message.

    ``groups`` is a list whose entries are lists of per-transaction extra
    payload segment counts (0 means bare ST/SE).
    """
    if groups is None:
        groups = [[0]]
    segs = [isa(control, element, component, terminator)]
    for g_index, txns in enumerate(groups):
        segs.append(
            f"GS{element}PO{element}SENDER{element}RECEIVER{element}20240101"
            f"{element}1200{element}{g_index + 1}{element}X{element}005010"
            + terminator
        )
        for t_index, extra in enumerate(txns):
            t_ctrl = f"{g_index + 1}{t_index + 1:03d}"
            count = 2 + extra
            segs.append(f"ST{element}850{element}{t_ctrl}" + terminator)
            for i in range(extra):
                segs.append(f"BEG{i:02d}{element}00" + terminator)
            segs.append(f"SE{element}{count}{element}{t_ctrl}" + terminator)
        segs.append(f"GE{element}{len(txns)}{element}{g_index + 1}" + terminator)
    segs.append(
        f"IEA{element}{len(groups)}{element}{control.rjust(9)}"
        + terminator
    )
    return "".join(segs).encode("ascii")


class ValidMessageTests(unittest.TestCase):
    def test_minimal_message(self):
        raw = build_message([[0]])
        result = audit(raw)
        self.assertEqual(result.interchange_control_number, "000000001")
        self.assertEqual(result.group_count, 1)
        self.assertEqual(result.transaction_count, 1)
        self.assertEqual(result.sha256, hashlib.sha256(raw).hexdigest())

    def test_multiple_groups_and_transactions(self):
        raw = build_message([[0, 2, 1], [3], [0, 0]])
        result = audit(raw)
        self.assertEqual(result.group_count, 3)
        self.assertEqual(result.transaction_count, 6)

    def test_payload_segments_counted(self):
        raw = build_message([[4]])
        result = audit(raw)
        self.assertEqual(result.transaction_count, 1)
        self.assertEqual(result.group_count, 1)

    def test_custom_delimiters(self):
        raw = build_message(
            [[1]], element="|", component="^", terminator="\n"
        )
        result = audit(raw)
        self.assertEqual(result.transaction_count, 1)
        self.assertEqual(result.sha256, hashlib.sha256(raw).hexdigest())

    def test_trailing_line_break_accepted(self):
        raw = build_message([[0]]) + b"\r\n"
        result = audit(raw)
        self.assertEqual(result.group_count, 1)

    def test_component_separator_used_in_payload(self):
        raw = (
            isa()
            + "GS*PO*S*R*20240101*1200*1*X*005010~"
            + "ST*850*100~"
            + "REF*AB:CD:EF~"
            + "SE*3*100~"
            + "GE*1*1~"
            + "IEA*1*000000001~"
        ).encode("ascii")
        result = audit(raw)
        self.assertEqual(result.transaction_count, 1)

    def test_isa_control_number_space_padding(self):
        raw = build_message([[0]], control="ABC")
        result = audit(raw)
        self.assertEqual(result.interchange_control_number, "ABC")

    def test_max_limits_accepted(self):
        groups = [[0] * MAX_TRANSACTIONS_PER_GROUP for _ in range(MAX_GROUPS)]
        raw = build_message(groups)
        result = audit(raw)
        self.assertEqual(result.group_count, MAX_GROUPS)
        self.assertEqual(
            result.transaction_count,
            MAX_GROUPS * MAX_TRANSACTIONS_PER_GROUP,
        )


class FramingTests(unittest.TestCase):
    def test_empty(self):
        with self.assertRaises(EnvelopeError) as ctx:
            audit(b"")
        self.assertEqual(ctx.exception.code, "EMPTY_MESSAGE")
        self.assertEqual(ctx.exception.segment, 1)

    def test_non_ascii(self):
        with self.assertRaises(EnvelopeError) as ctx:
            audit(b"ISA*00          *\x80")
        self.assertEqual(ctx.exception.code, "NON_ASCII")

    def test_too_large(self):
        with self.assertRaises(EnvelopeError) as ctx:
            audit(b"x" * (MAX_MESSAGE_BYTES + 1))
        self.assertEqual(ctx.exception.code, "MESSAGE_TOO_LARGE")

    def test_too_short(self):
        with self.assertRaises(EnvelopeError) as ctx:
            audit(b"ISA*00")
        self.assertEqual(ctx.exception.code, "ISA_TOO_SHORT")

    def test_not_starting_with_isa(self):
        with self.assertRaises(EnvelopeError) as ctx:
            audit(b"GS*PO~" + b"x" * 100)
        self.assertEqual(ctx.exception.code, "MISSING_ISA")

    def test_bad_delimiter_letter(self):
        raw = bytearray(isa().replace("*", "A", 1).encode("ascii"))
        with self.assertRaises(EnvelopeError) as ctx:
            audit(bytes(raw))
        self.assertEqual(ctx.exception.code, "BAD_DELIMITER")

    def test_duplicate_delimiters(self):
        raw = bytearray(isa().encode("ascii"))
        raw[104] = ord("*")  # component separator == element separator
        with self.assertRaises(EnvelopeError) as ctx:
            audit(bytes(raw))
        self.assertEqual(ctx.exception.code, "BAD_DELIMITER")

    def test_isa_wrong_field_widths(self):
        # Corrupt the fixed-width layout (ISA01 loses a byte that ISA02
        # gains) while keeping bytes 104/105 valid.
        raw = isa().encode("ascii")
        raw = raw.replace(
            b"ISA*00" + b"*" + b" " * 10 + b"*00",
            b"ISA*0" + b"*" + b" " * 11 + b"*00",
            1,
        )
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "ISA_MALFORMED")

    def test_missing_final_terminator(self):
        raw = build_message([[0]])
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw[:-1])
        self.assertEqual(ctx.exception.code, "MISSING_TERMINATOR")

    def test_empty_segment(self):
        raw = isa().encode() + b"~" + b"GS*PO~"
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "EMPTY_SEGMENT")
        self.assertEqual(ctx.exception.segment, 2)

    def test_trailing_data_after_iea(self):
        raw = build_message([[0]]) + b"ZZZ*1~"
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "TRAILING_DATA")
        # ISA=1, GS=2, ST=3, SE=4, GE=5, IEA=6, ZZZ=7
        self.assertEqual(ctx.exception.segment, 7)

    def test_second_isa(self):
        raw = isa().encode() + isa().encode()
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "MULTIPLE_INTERCHANGES")
        self.assertEqual(ctx.exception.segment, 2)


class NestingTests(unittest.TestCase):
    def test_st_without_gs(self):
        raw = isa().encode() + "ST*850*1~SE*2*1~IEA*0*1~".encode()
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "NESTING_VIOLATION")
        self.assertEqual(ctx.exception.segment, 2)

    def test_se_without_st(self):
        raw = isa().encode() + "GS*PO*S*R*D*T*1*X*V~SE*2*9~GE*1*1~IEA*1*1~".encode()
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "NESTING_VIOLATION")
        self.assertEqual(ctx.exception.segment, 3)

    def test_ge_without_gs(self):
        raw = isa().encode() + "GE*1*1~IEA*0*1~".encode()
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "NESTING_VIOLATION")
        self.assertEqual(ctx.exception.segment, 2)

    def test_gs_inside_open_group(self):
        raw = (
            isa()
            + "GS*PO*S*R*D*T*1*X*V~"
            + "GS*PO*S*R*D*T*2*X*V~"
            + "GE*0*2~GE*0*1~IEA*2*1~"
        ).encode()
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "NESTING_VIOLATION")
        self.assertEqual(ctx.exception.segment, 3)

    def test_iea_while_group_open(self):
        raw = isa().encode() + "GS*PO*S*R*D*T*1*X*V~IEA*1*1~".encode()
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "NESTING_VIOLATION")
        self.assertEqual(ctx.exception.segment, 3)

    def test_iea_while_transaction_open(self):
        raw = (
            isa()
            + "GS*PO*S*R*D*T*1*X*V~ST*850*7~IEA*1*1~"
        ).encode()
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "NESTING_VIOLATION")
        self.assertEqual(ctx.exception.segment, 4)

    def test_payload_outside_transaction(self):
        raw = isa().encode() + "GS*PO*S*R*D*T*1*X*V~FOO*1~GE*1*1~IEA*1*1~".encode()
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "UNEXPECTED_SEGMENT")
        self.assertEqual(ctx.exception.segment, 3)

    def test_missing_se(self):
        raw = isa().encode() + "GS*PO*S*R*D*T*1*X*V~ST*850*7~GE*1*1~IEA*1*1~".encode()
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        # GE while transaction open is reported first, at the GE segment.
        self.assertEqual(ctx.exception.code, "NESTING_VIOLATION")
        self.assertEqual(ctx.exception.segment, 4)

    def test_truncated_without_iea(self):
        raw = isa().encode() + "GS*PO*S*R*D*T*1*X*V~ST*850*7~SE*2*7~GE*1*1~".encode()
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "MISSING_IEA")

    def test_truncated_within_open_group(self):
        raw = isa().encode() + "GS*PO*S*R*D*T*1*X*V~ST*850*7~SE*2*7~".encode()
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "MISSING_GE")
        self.assertEqual(ctx.exception.segment, 2)

    def test_truncated_within_open_transaction(self):
        raw = isa().encode() + "GS*PO*S*R*D*T*1*X*V~ST*850*7~BEG*00~".encode()
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "MISSING_SE")
        self.assertEqual(ctx.exception.segment, 3)

    def test_zero_groups(self):
        raw = isa().encode() + "IEA*0*000000001~".encode()
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "ZERO_GROUPS")
        self.assertEqual(ctx.exception.segment, 2)

    def test_zero_transactions(self):
        raw = (
            isa() + "GS*PO*S*R*D*T*1*X*V~GE*0*1~IEA*1*000000001~"
        ).encode()
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "ZERO_TRANSACTIONS")
        self.assertEqual(ctx.exception.segment, 3)

    def test_payload_directly_after_isa(self):
        raw = (isa() + "FOO*1~IEA*0*1~").encode()
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "UNEXPECTED_SEGMENT")
        self.assertEqual(ctx.exception.segment, 2)

    def test_duplicate_se(self):
        raw = (
            isa()
            + "GS*PO*S*R*D*T*1*X*V~"
            + "ST*850*100~SE*2*100~SE*2*100~"
            + "GE*1*1~IEA*1*000000001~"
        ).encode()
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "NESTING_VIOLATION")
        self.assertEqual(ctx.exception.segment, 5)

    def test_st_without_control_number(self):
        raw = (
            isa() + "GS*PO*S*R*D*T*1*X*V~ST*850~GE*0*1~IEA*1*1~"
        ).encode()
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "ST_MALFORMED")
        self.assertEqual(ctx.exception.segment, 3)

    def test_non_numeric_se_count(self):
        raw = (
            isa() + "GS*PO*S*R*D*T*1*X*V~ST*850*1~SE*X*1~GE*1*1~IEA*1*1~"
        ).encode()
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "SE_MALFORMED")
        self.assertEqual(ctx.exception.segment, 4)


class CountAndControlTests(unittest.TestCase):
    def _valid(self) -> bytes:
        return (
            isa()
            + "GS*PO*S*R*20240101*1200*1*X*005010~"
            + "ST*850*100~BEG*00~SE*3*100~"
            + "ST*850*200~SE*2*200~"
            + "GE*2*1~"
            + "IEA*1*000000001~"
        ).encode("ascii")

    def test_valid_baseline(self):
        result = audit(self._valid())
        self.assertEqual(result.group_count, 1)
        self.assertEqual(result.transaction_count, 2)

    def test_se_count_too_low_reports_inner_error_first(self):
        # Both the inner SE count and an outer IEA count are wrong; the
        # inner error must win and be located at the SE segment.
        raw = (
            isa()
            + "GS*PO*S*R*20240101*1200*1*X*005010~"
            + "ST*850*100~BEG*00~SE*2*100~"   # actual count is 3
            + "ST*850*200~SE*2*200~"
            + "GE*9*1~"                         # also wrong
            + "IEA*9*000000001~"               # also wrong
        ).encode("ascii")
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "SEGMENT_COUNT_MISMATCH")
        self.assertEqual(ctx.exception.segment, 5)

    def test_se_control_mismatch(self):
        raw = (
            isa()
            + "GS*PO*S*R*D*T*1*X*V~"
            + "ST*850*100~SE*2*999~"
            + "GE*1*1~IEA*1*000000001~"
        ).encode("ascii")
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "CONTROL_NUMBER_MISMATCH")
        self.assertEqual(ctx.exception.segment, 4)

    def test_ge_control_mismatch(self):
        raw = (
            isa()
            + "GS*PO*S*R*D*T*1*X*V~"
            + "ST*850*100~SE*2*100~"
            + "GE*1*9~IEA*1*000000001~"
        ).encode("ascii")
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "CONTROL_NUMBER_MISMATCH")
        self.assertEqual(ctx.exception.segment, 5)

    def test_iea_control_mismatch(self):
        raw = (
            isa()
            + "GS*PO*S*R*D*T*1*X*V~"
            + "ST*850*100~SE*2*100~"
            + "GE*1*1~IEA*1*000000999~"
        ).encode("ascii")
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "CONTROL_NUMBER_MISMATCH")
        self.assertEqual(ctx.exception.segment, 6)

    def test_ge_count_mismatch(self):
        raw = (
            isa()
            + "GS*PO*S*R*D*T*1*X*V~"
            + "ST*850*100~SE*2*100~"
            + "ST*850*200~SE*2*200~"
            + "GE*1*1~IEA*1*000000001~"
        ).encode("ascii")
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "GE_COUNT_MISMATCH")
        self.assertEqual(ctx.exception.segment, 7)

    def test_iea_count_mismatch(self):
        raw = (
            isa()
            + "GS*PO*S*R*D*T*1*X*V~"
            + "ST*850*100~SE*2*100~"
            + "GE*1*1~IEA*2*000000001~"
        ).encode("ascii")
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "IEA_COUNT_MISMATCH")
        self.assertEqual(ctx.exception.segment, 6)

    def test_ge_error_reported_before_iea_summary(self):
        # Wrong GE count and a matching-but-also-wrong IEA count: the GE
        # error (inner) surfaces first even though IEA agrees with it.
        raw = (
            isa()
            + "GS*PO*S*R*D*T*1*X*V~"
            + "ST*850*100~SE*2*100~"
            + "GE*2*1~"                          # actual 1, claims 2
            + "IEA*1*000000001~"
        ).encode("ascii")
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "GE_COUNT_MISMATCH")
        self.assertEqual(ctx.exception.segment, 5)

    def test_group_limit_exceeded(self):
        groups = [[0]] * (MAX_GROUPS + 1)
        raw = build_message(groups)
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "GROUP_LIMIT_EXCEEDED")

    def test_transaction_limit_exceeded(self):
        groups = [[0] * (MAX_TRANSACTIONS_PER_GROUP + 1)]
        raw = build_message(groups)
        with self.assertRaises(EnvelopeError) as ctx:
            audit(raw)
        self.assertEqual(ctx.exception.code, "TRANSACTION_LIMIT_EXCEEDED")


if __name__ == "__main__":
    unittest.main()
