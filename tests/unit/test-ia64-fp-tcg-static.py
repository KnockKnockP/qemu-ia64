#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Structural gate for the first IA-64 full-TCG floating-compute tranche.

This is deliberately stricter than a string inventory test.  Floating-point
instructions have three architectural properties which the old raw-slot
executor obscured:

* ordinary FR reads use the issue-group entry image;
* FP faults are pre-result while FP traps are post-result;
* paired operations make one atomic two-lane decision.

The companion :mod:`ia64_fp_tcg_spec` records the owner for all 67 live
instructions.  This gate admits 35 helper-free direct rows and 32 focused
helper rows.  ``IA64_OP_FMOV`` remains in the enum only as a decoder-dead alias
because Intel defines no such instruction.
"""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path
import sys


sys.path.insert(0, str(Path(__file__).resolve().parent))
from ia64_fp_tcg_spec import (  # noqa: E402
    FMOV_CATCHALL_FORM_PAIRS,
    FMOV_ILLEGAL_FORM_PAIRS,
    FMOV_MISDECODED_LIVE_ALIAS_PAIRS,
    FP_DEAD_OPCODE_NAMES,
    FP_DIRECT_OPCODE_NAMES,
    FP_EXACT_DIRECT_OPCODE_NAMES,
    FP_HELPER_OPCODE_NAMES,
    FP_IGNORED_FIELDS,
    FP_LIVE_OPCODES,
    FP_LIVE_OPCODE_NAMES,
    FP_OPCODES,
    FP_OPCODE_NAMES,
)


ARCHITECTURAL_RESET_FPSR = 0x0009804C0270033F


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def function_body(text: str, name: str) -> str:
    """Return a C function from its name through its matching closing brace."""
    match = re.search(r"\b" + re.escape(name) + r"\s*\([^;]*?\)\s*\{", text,
                      re.DOTALL)
    if match is None:
        raise SystemExit("floating-TCG function missing: " + name)
    opening = text.find("{", match.start())
    depth = 0
    for index in range(opening, len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[match.start():index + 1]
    raise SystemExit("unterminated floating-TCG function: " + name)


def trait_rows(root: Path) -> dict[str, list[str]]:
    text = (root / "target/ia64/opcode-traits.def").read_text(
        encoding="utf-8"
    )
    return {
        fields[0]: fields
        for body in re.findall(r"IA64_OPCODE\((.*?)\)", text, re.DOTALL)
        if len(fields := [part.strip() for part in body.split(",")]) == 8
    }


def ledger_rows(root: Path) -> dict[str, dict[str, str]]:
    with (root / "docs/devel/ia64-opcode-ledger.csv").open(
        encoding="utf-8", newline=""
    ) as source:
        return {row["opcode"]: row for row in csv.DictReader(source)}


def check_inventory_and_traits(root: Path) -> None:
    ledger = ledger_rows(root)
    ledger_fp = {
        opcode for opcode, row in ledger.items()
        if row["family"] == "floating-compute"
    }
    require(
        ledger_fp == FP_OPCODE_NAMES,
        "floating inventory drift: missing={}, extra={}".format(
            sorted(FP_OPCODE_NAMES - ledger_fp),
            sorted(ledger_fp - FP_OPCODE_NAMES),
        ),
    )
    for opcode in FP_LIVE_OPCODE_NAMES:
        require(ledger[opcode]["closure"] == "closed",
                opcode + ": live FP row is not closed")
    require(
        ledger["IA64_OP_FMOV"]["closure"] == "alias-canonicalized",
        "dead FMOV alias is not canonicalized",
    )

    rows = trait_rows(root)
    for op in FP_LIVE_OPCODES:
        row = rows.get(op.opcode)
        require(row is not None, "missing floating trait row: " + op.opcode)
        require(row[1] == "FP_COMPUTE", op.opcode + ": wrong family")
        if op.opcode in FP_DIRECT_OPCODE_NAMES:
            require(
                row[2:8] == [
                    "DIRECT_TCG", "NONE", "FULL_TCG",
                    "NONE", "NO_OS", "TYPED",
                ],
                op.opcode + ": exact/direct tranche ownership drift",
            )
        else:
            require(op.opcode in FP_HELPER_OPCODE_NAMES,
                    op.opcode + ": live FP owner is unclassified")
            require(
                row[2:8] == [
                    "FOCUSED_HELPER", "DATA_PLANE", "DATA_PLANE",
                    "NONE", "NO_OS", "TYPED",
                ],
                op.opcode + ": focused-helper ownership drift",
            )

    # The enum row is kept stable as a decoder-dead canonical alias.  Decoder
    # and runtime checks below require that no architected encoding produce it.
    dead = rows.get("IA64_OP_FMOV")
    require(dead == [
        "IA64_OP_FMOV", "FP_COMPUTE", "CANONICAL_ALIAS", "NONE",
        "DECODE", "NONE", "NONE", "DEAD_ALIAS",
    ], "FMOV final trait drift: {}".format(dead))


def check_decoder(root: Path) -> None:
    decode = (root / "target/ia64/decode.c").read_text(encoding="utf-8")

    require("opcode = IA64_OP_FMOV" not in decode,
            "reserved F-unit space still decodes as FMOV")
    require("ia64_base_insn(IA64_OP_FMOV" not in decode,
            "decoder still directly produces FMOV")
    nop_call = decode.find("if (ia64_is_f_nop(raw))")
    f_block = decode.rfind("if (unit == IA64_INSN_UNIT_F)", 0, nop_call)
    first_live = min(position for opcode in FP_LIVE_OPCODE_NAMES
                     if (position := decode.find(opcode, nop_call)) >= 0)
    require(f_block >= 0 and f_block < nop_call < first_live,
            "F-unit nop recognition no longer precedes generic F decoding")

    # White-space fields in Intel's diagrams are ignored, not fixed zero.
    # Executable decoder tests vary each field; this structural gate prevents
    # resurrection of the specific centralized zero gate which once rejected
    # valid F9/F11 aliases.
    require("ia64_f9_fixed_bits_are_zero" not in decode,
            "decoder rejects architecturally ignored F9/F11 fields")

    # Keep the exact independent collision inventory alive even though the
    # runtime test samples only representative illegal encodings.
    require(len(FMOV_ILLEGAL_FORM_PAIRS) == 136,
            "former FMOV illegal-form inventory drift")
    require(len(FMOV_MISDECODED_LIVE_ALIAS_PAIRS) == 12,
            "former FMOV live-alias inventory drift")
    require(len(FMOV_CATCHALL_FORM_PAIRS) == 148,
            "obsolete FMOV total collision inventory drift")
    require(set(FP_IGNORED_FIELDS) == {
        "F3", "F5", "F7", "F8", "F9", "F10", "F11", "F12", "F13",
        "F14", "M18", "M19",
    }, "FP ignored-field format inventory drift")


def check_fr_transaction(root: Path) -> None:
    cpu_h = (root / "target/ia64/cpu.h").read_text(encoding="utf-8")
    machine = (root / "target/ia64/machine.c").read_text(encoding="utf-8")
    translate = (root / "target/ia64/translate.c").read_text(encoding="utf-8")
    insn = (root / "target/ia64/insn.c").read_text(encoding="utf-8")

    group = function_like_struct(
        cpu_h, "typedef struct IA64IssueGroupState",
        "} IA64IssueGroupState;"
    )
    require("saved_fr[IA64_FR_COUNT]" in group or "saved_fr[128]" in group,
            "FP source transaction lacks saved_fr[128]")
    require("saved_fr_mask[2]" in group,
            "FP source transaction lacks saved_fr_mask[2]")
    for token in (
        "VMSTATE_STRUCT_ARRAY(issue_group.saved_fr",
        "VMSTATE_UINT64_ARRAY(issue_group.saved_fr_mask",
    ):
        require(token in machine, "FP overlay migration lacks " + token)
    for token in (
        "ia64_tr_group_prepare_fr",
        "ia64_tr_group_load_ordinary_fr",
        "ia64_tr_group_stage_fr",
        "issue_group.saved_fr_mask",
    ):
        require(token in translate, "typed FP transaction lacks " + token)
    for token in (
        "ia64_read_fr_ordinary",
        "ia64_write_fr_parts",
        "issue_group.saved_fr_mask",
    ):
        require(token in insn, "focused FP helper overlay lacks " + token)


def function_like_struct(text: str, begin: str, end: str) -> str:
    try:
        start = text.index(begin)
        finish = text.index(end, start) + len(end)
    except ValueError as exc:
        raise SystemExit("floating-TCG structural marker missing: " + begin) from exc
    return text[start:finish]


def check_typed_emitter(root: Path) -> None:
    translate = (root / "target/ia64/translate.c").read_text(encoding="utf-8")

    require("IA64TrFpDescriptor" in translate,
            "typed FP descriptor type is missing")
    require("ia64_tr_decoded_fp_compute" in translate,
            "typed FP descriptor lookup is missing")

    descriptor_start = translate.find(
        "static const IA64TrFpDescriptor ia64_tr_fp_table")
    descriptor_end = translate.find(
        "#undef IA64_TR_FP_DIRECT_ROW", descriptor_start)
    require(descriptor_start >= 0 and descriptor_end > descriptor_start,
            "exact/direct FP descriptor table is malformed")
    descriptors = translate[descriptor_start:descriptor_end]
    positions = []
    for opcode in FP_LIVE_OPCODE_NAMES:
        matches = list(re.finditer(r"\b" + re.escape(opcode) + r"\b",
                                   descriptors))
        count = len(matches)
        require(count == 1,
                "live FP descriptor must contain {} once (got {})".format(
                    opcode, count
                ))
        positions.append((matches[0].start(), opcode))
    require("IA64_OP_FMOV" not in descriptors,
            "dead FMOV alias has a descriptor")
    positions.sort()
    for index, (start, opcode) in enumerate(positions):
        finish = positions[index + 1][0] if index + 1 < len(positions) \
            else len(descriptors)
        row = descriptors[start:finish]
        owner = "IA64_TR_FP_DIRECT_ROW" if opcode in FP_DIRECT_OPCODE_NAMES \
            else "IA64_TR_FP_FOCUSED_ROW"
        require(owner in row[:300],
                "FP descriptor has the wrong owner: " + opcode)

    emitter = function_body(translate, "ia64_tr_emit_decoded_fp_compute")
    require("IA64_OP_FMOV" not in emitter,
            "dead FMOV alias has a runtime lowering")
    for forbidden in (
        "insn->raw", "fast_fp_slot", "exec_predecoded_slot",
        "ia64_exec_", "ia64_decode_",
    ):
        require(forbidden not in emitter,
                "typed FP emitter uses raw/generic path: " + forbidden)
    for token in (
        "ia64_tr_emit_decoded_predicate_guard",
        "ia64_tr_group_prepare_fr",
        "ia64_tr_group_load_ordinary_fr",
        "ia64_tr_group_stage_fr",
        "ia64_tr_finish_predicate_guard",
        "ia64_tr_emit_decoded_disabled_fp_check",
        "ia64_tr_decoded_fp_compute",
        "ia64_tr_fp_accumulate_natval",
        "ia64_tr_finish_faulting_slot",
    ):
        require(token in emitter, "typed FP emitter lacks " + token)
    require("gen_helper_fp_compute" not in emitter,
            "exact/direct FP emitter calls a focused helper")
    direct_runtime = emitter + "\n" + "\n".join(
        function_body(translate, name)
        for name in (
            "ia64_tr_emit_decoded_fp_direct_special",
            "ia64_tr_emit_decoded_fclass",
            "ia64_tr_emit_decoded_getf_exact",
            "ia64_tr_emit_decoded_setf_exact",
            "ia64_tr_emit_decoded_fsetc",
            "ia64_tr_emit_decoded_fclrf",
            "ia64_tr_emit_decoded_fchkf_split",
        )
    )
    require("IA64_OP_FMOV" not in direct_runtime,
            "dead FMOV alias has a direct runtime lowering")
    for opcode in FP_DIRECT_OPCODE_NAMES:
        require(re.search(r"\b" + re.escape(opcode) + r"\b", direct_runtime)
                is not None,
                "direct FP runtime omits " + opcode)
    for opcode in FP_HELPER_OPCODE_NAMES:
        require(re.search(r"\b" + re.escape(opcode) + r"\b", direct_runtime)
                is None,
                "focused FP opcode leaked into direct runtime: " + opcode)

    focused = function_body(translate, "ia64_tr_emit_decoded_fp_focused")
    require("gen_helper_fp_compute" in focused,
            "focused FP emitter does not call its decoded helper")
    require("insn->raw" not in focused,
            "focused FP emitter passes or consumes a raw slot")

    guard = emitter.find("ia64_tr_emit_decoded_predicate_guard")
    legality = emitter.find("insn->r1 < 2")
    disabled = emitter.find("ia64_tr_emit_decoded_disabled_fp_check")
    require(guard >= 0 and legality > guard and disabled > legality,
            "direct FP order is not predicate -> f0/f1 legality -> disabled")

    fclass = function_body(translate, "ia64_tr_emit_decoded_fclass")
    require(fclass.find("insn->p1 == insn->p2") >= 0 and
            fclass.find("ia64_tr_emit_decoded_disabled_fp_regs") >
            fclass.find("ia64_tr_emit_decoded_predicate_guard"),
            "fclass legality/predication/disabled ordering drift")
    getf = function_body(translate, "ia64_tr_emit_decoded_getf_exact")
    require(getf.find("ia64_tr_emit_application_target_check") >= 0 and
            getf.find("ia64_tr_emit_decoded_disabled_fp_regs") >
            getf.find("ia64_tr_emit_application_target_check"),
            "getf target and disabled-check ordering drift")
    setf = function_body(translate, "ia64_tr_emit_decoded_setf_exact")
    require(setf.find("target < 2") >= 0 and
            setf.find("ia64_tr_emit_decoded_disabled_fp_regs") >
            setf.find("target < 2"),
            "setf legality and disabled-check ordering drift")
    for name in ("ia64_tr_emit_decoded_fsetc",
                 "ia64_tr_emit_decoded_fclrf",
                 "ia64_tr_emit_decoded_fchkf_split"):
        body = function_body(translate, name)
        require("ia64_tr_group_load_ordinary_ar" in body,
                name + ": FPSR does not use the issue-group entry image")


def check_focused_transactions(root: Path) -> None:
    data_plane = (root / "target/ia64/data-plane.c").read_text(
        encoding="utf-8"
    )

    for token in (
        "ia64_fp_transaction_begin",
        "ia64_fp_transaction_finish",
        "ia64_fp_transaction_commit",
        "ia64_fp_raise",
        "IA64_EXCEPTION_FP_FAULT",
        "IA64_EXCEPTION_FP_TRAP",
        "float_flag_invalid",
        "float_flag_divbyzero",
        "float_flag_overflow",
        "float_flag_underflow",
        "float_flag_inexact",
    ):
        require(token in data_plane,
                "focused FP transaction lacks " + token)

    finish = function_body(data_plane, "ia64_fp_transaction_finish")
    fault = finish.find("IA64_EXCEPTION_FP_FAULT")
    commit = finish.find("ia64_fp_transaction_commit")
    trap = finish.find("IA64_EXCEPTION_FP_TRAP")
    require(fault >= 0 and commit > fault and trap > commit,
            "FP transaction does not encode fault-before-result/trap-after-result")
    fault_arm = finish[max(0, fault - 80):commit]
    raise_fp = function_body(data_plane, "ia64_fp_raise")
    require("ia64_fp_raise" in fault_arm and
            "cpu_loop_exit" in raise_fp and "G_NORETURN" in data_plane,
            "FP fault arm can fall through and commit a result")
    for token in ("bool paired", "hi_soft", "lo_soft"):
        require(token in data_plane,
                "paired FP helper lacks two-lane staging: " + token)
    require(finish.count("ia64_fp_transaction_commit") == 1,
            "paired FP helper does not use one atomic transaction commit")

    match = re.search(
        r"\bHELPER\(fp_compute\)\s*\(([^)]*)\)", data_plane, re.DOTALL,
    )
    require(match is not None,
            "focused FP helper implementation missing: fp_compute")
    signature = match.group(1)
    require(not re.search(r"\braw\b", signature),
            "focused FP helper implementation receives raw slot")
    require(re.search(r"\bopcode\b", signature) is not None,
            "focused FP helper does not receive decoded opcode")
    body = function_body(data_plane, "HELPER(fp_compute)")
    require(body.count("ia64_fp_transaction_finish") == 1,
            "focused FP helper bypasses the required transaction finalizer")
    finish_call = body.find("ia64_fp_transaction_finish")
    require(re.search(r"(?m)^\s*return\b", body[:finish_call]) is None,
            "focused FP helper has a pre-finalizer return path")
    for opcode in FP_HELPER_OPCODE_NAMES:
        require(opcode in body,
                "focused FP helper dispatch omits " + opcode)
    for opcode in FP_DIRECT_OPCODE_NAMES:
        require(opcode not in body,
                "direct FP opcode leaked into focused helper: " + opcode)
    for forbidden in ("ia64_exec_", "exec_predecoded_slot", "ia64_decode_"):
        require(forbidden not in body,
                "focused FP helper calls generic executor: " + forbidden)


def check_exceptions_and_reset(root: Path) -> None:
    cpu_h = (root / "target/ia64/cpu.h").read_text(encoding="utf-8")
    exception = (root / "target/ia64/exception.c").read_text(encoding="utf-8")
    insn = (root / "target/ia64/insn.c").read_text(encoding="utf-8")

    for token in ("IA64_EXCEPTION_FP_FAULT", "IA64_EXCEPTION_FP_TRAP"):
        require(token in cpu_h, "exception enum lacks " + token)
        require(token in exception, "exception delivery lacks " + token)
    for vector in ("0x5c00", "0x5d00"):
        require(vector in exception, "FP exception vector missing: " + vector)
    fpsr_tokens = {
        f"0x{ARCHITECTURAL_RESET_FPSR:016x}",
        f"0x{ARCHITECTURAL_RESET_FPSR:016X}",
        "IA64_FPSR_RESET_VALUE",
    }
    require(any(token in insn or token in cpu_h for token in fpsr_tokens),
            "reset does not install architectural FPSR 0x{:016x}".format(
                ARCHITECTURAL_RESET_FPSR
            ))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    args = parser.parse_args()
    root = args.source_root.resolve()

    require(len(FP_OPCODES) == 68, "floating inventory is not 68 rows")
    require(len(FP_LIVE_OPCODE_NAMES) == 67,
            "floating live inventory is not 67 rows")
    require(FP_DEAD_OPCODE_NAMES == {"IA64_OP_FMOV"},
            "floating dead-alias inventory drift")
    require(len(FP_DIRECT_OPCODE_NAMES) == 35,
            "floating direct inventory is not 35 rows")
    require(len(FP_EXACT_DIRECT_OPCODE_NAMES) == 35,
            "floating exact/direct tranche is not 35 rows")
    require(len(FP_HELPER_OPCODE_NAMES) == 32,
            "floating helper inventory is not 32 rows")
    check_inventory_and_traits(root)
    check_decoder(root)
    check_fr_transaction(root)
    check_typed_emitter(root)
    check_focused_transactions(root)
    check_exceptions_and_reset(root)
    print("IA-64 floating-compute gate passed: "
          "35 exact/direct and 32 focused admitted, 1 dead alias")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
