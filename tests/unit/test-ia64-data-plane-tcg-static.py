#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Self-check the independent 63-row IA-64 data-plane rewrite map.

This preparation gate does not require the shared translator to have landed.
``--audit-open`` additionally proves that the map's live rows are closed by
the data-plane owner and its reserved encodings are decoder-dead.
"""

from __future__ import annotations

import argparse
from collections import Counter
import csv
from pathlib import Path
import re
import sys
from typing import Optional, Sequence


sys.path.insert(0, str(Path(__file__).resolve().parent))
from ia64_data_plane_tcg_spec import (  # noqa: E402
    ALIAS_ENCODINGS,
    DATA_PLANE_OPCODE_SPECS,
    DATA_PLANE_OPCODES,
    FAMILY_COUNTS,
    FP_STORE_X6,
    PRIMARY_ENCODINGS,
    SPEC_BY_OPCODE,
    WIDTH_CODE,
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def field(raw: int, low: int, width: int) -> int:
    return (raw >> low) & ((1 << width) - 1)


def _integer_opcode(x6a: int) -> Optional[str]:
    table = {}
    for base, stem in (
        (0x00, ""), (0x04, "S"), (0x08, "A"), (0x0c, "SA"),
        (0x10, ""), (0x14, ""), (0x18, "FILL"),
        (0x20, "C_CLR"), (0x24, "C_NC"), (0x28, "C_CLR"),
        (0x30, "ST"), (0x34, "STREL"), (0x38, "STSPILL"),
    ):
        for width, code in WIDTH_CODE.items():
            if stem.startswith("ST"):
                suffix = stem.removeprefix("ST")
                name = "IA64_OP_ST{}{}".format(width, suffix)
            else:
                name = "IA64_OP_LD{}{}".format(width, stem)
            table[base + code] = name
    return table.get(x6a)


def _fp_load_opcode(x6a: int, pair: bool) -> Optional[str]:
    if not (x6a <= 0x0f or 0x20 <= x6a <= 0x27):
        return "IA64_OP_LDF_FILL" if not pair and x6a == 0x1b else None
    low = x6a & 3
    if pair:
        return {1: "IA64_OP_LDFP8", 2: "IA64_OP_LDFPS",
                3: "IA64_OP_LDFPD"}.get(low)
    return {0: "IA64_OP_LDFE", 1: "IA64_OP_LDF8",
            2: "IA64_OP_LDFS", 3: "IA64_OP_LDFD"}[low]


def normalize_probe(raw: int) -> Optional[str]:
    """Independent port of the decoder decisions exercised by this map."""
    op = field(raw, 37, 4)
    x6a = field(raw, 30, 6)

    if op == 1 and field(raw, 33, 3) in (1, 3):
        return "IA64_OP_CHK_S"
    if op == 0 and field(raw, 33, 3) >= 4:
        return ("IA64_OP_CHK_A" if field(raw, 33, 3) in (4, 6)
                else "IA64_OP_CHK_A_CLR")
    if op == 0 and field(raw, 33, 1) == 0 and field(raw, 34, 2) == 0:
        x6 = field(raw, 27, 6)
        if field(raw, 36, 1) == 0:
            if x6 == 0x10:
                return "IA64_OP_INVALA"
            if x6 in (0x12, 0x13):
                return "IA64_OP_INVALAT"
        if x6 == 0x20:
            return "IA64_OP_FWB"
    if op == 1 and field(raw, 33, 3) == 0 and field(raw, 27, 6) == 0x30:
        return "IA64_OP_FC"

    if op == 4:
        if (field(raw, 36, 1) == 0 and field(raw, 27, 1) == 1
                and x6a in (0x28, 0x2c)):
            return "IA64_OP_LD16"
        x6 = field(raw, 27, 6)
        if (field(raw, 36, 1) == 0 and field(raw, 33, 3) == 6
                and (x6 & ~0x26) == 0x01):
            return "IA64_OP_ST16"
        if (field(raw, 36, 1) == 0 and field(raw, 27, 1) == 1
                and x6a in (0x20, 0x24)):
            return "IA64_OP_CMP8XCHG16"
        if (field(raw, 36, 1) == 0 and field(raw, 27, 1) == 1
                and field(raw, 33, 3) == 0):
            size = field(raw, 30, 1) | (field(raw, 31, 1) << 1)
            return "IA64_OP_CMPXCHG{}".format((1, 2, 4, 8)[size])
        if (field(raw, 36, 1) == 0 and field(raw, 27, 1) == 1
                and field(raw, 32, 1) == 0 and field(raw, 33, 3) == 1):
            size = field(raw, 30, 1) | (field(raw, 31, 1) << 1)
            return "IA64_OP_XCHG{}".format((1, 2, 4, 8)[size])
        if (field(raw, 36, 1) == 0 and field(raw, 27, 2) == 1
                and x6a <= 3):
            return "IA64_OP_LD{}S".format((1, 2, 4, 8)[x6a])
        if (field(raw, 36, 1) == 0 and field(raw, 27, 2) == 3
                and x6a <= 3):
            stem = "C_NC" if field(raw, 29, 1) else "C_CLR"
            return "IA64_OP_LD{}{}".format((1, 2, 4, 8)[x6a], stem)
        if field(raw, 36, 1) == 0 and field(raw, 27, 1) == 1:
            if x6a in (0x12, 0x16):
                return "IA64_OP_FETCHADD4"
            if x6a in (0x13, 0x17):
                return "IA64_OP_FETCHADD8"
        decoded = _integer_opcode(x6a)
        if decoded is not None:
            return decoded

    if op == 2 and field(raw, 36, 1) == 0 and field(raw, 12, 1) == 0:
        xm, hint = field(raw, 29, 2), field(raw, 27, 2)
        table = {
            (0, 0): "IA64_OP_XCHG1", (0, 1): "IA64_OP_XCHG2",
            (1, 0): "IA64_OP_XCHG4", (1, 1): "IA64_OP_XCHG8",
            (2, 0): "IA64_OP_CMPXCHG1", (2, 1): "IA64_OP_CMPXCHG2",
            (3, 0): "IA64_OP_CMPXCHG4", (3, 1): "IA64_OP_CMPXCHG8",
        }
        return table.get((xm, hint))
    if op == 3 and field(raw, 36, 1) == 0 and field(raw, 27, 1) == 0:
        return {0: "IA64_OP_FETCHADD4", 1: "IA64_OP_FETCHADD8"}.get(
            field(raw, 29, 2)
        )

    if op in (6, 7):
        if 0x2c <= x6a <= 0x2f:
            return "IA64_OP_LFETCH_FAULT" if x6a >= 0x2e else "IA64_OP_LFETCH"
        if op == 6 and field(raw, 27, 1) == 1:
            return _fp_load_opcode(x6a, True)
        load = _fp_load_opcode(x6a, False)
        if load is not None:
            return load
        for opcode, code in FP_STORE_X6.items():
            if x6a == code:
                return opcode
    return None


def check_inventory(root: Path, audit_open: bool) -> None:
    require(len(DATA_PLANE_OPCODES) == 63, "data-plane inventory is not 63 rows")
    require(len(set(DATA_PLANE_OPCODES)) == 63, "data-plane inventory duplicates")
    require(Counter(row.family for row in DATA_PLANE_OPCODE_SPECS) == FAMILY_COUNTS,
            "data-plane family counts drifted")

    ledger = root / "docs/devel/ia64-opcode-ledger.csv"
    require(ledger.is_file(), "missing opcode ledger: " + str(ledger))
    with ledger.open(encoding="utf-8", newline="") as source:
        rows = {row["opcode"]: row for row in csv.DictReader(source)}
    for spec in DATA_PLANE_OPCODE_SPECS:
        require(spec.opcode in rows, "spec row absent from ledger: " + spec.opcode)
        require(rows[spec.opcode]["family"] == spec.family,
                spec.opcode + ": ledger family mismatch")
    if audit_open:
        reserved = {
            spec.opcode for spec in DATA_PLANE_OPCODE_SPECS
            if spec.isa_status == "decoder-reserved-width"
        }
        for opcode in DATA_PLANE_OPCODES:
            row = rows[opcode]
            if opcode in reserved:
                require(row["decoder_status"] == "decoder-dead-alias" and
                        row["closure"] == "alias-canonicalized" and
                        row["lowering_owner"] == "canonical-alias",
                        opcode + ": reserved row is not decoder-dead")
            else:
                require(row["decoder_status"] == "live" and
                        row["closure"] == "closed" and
                        row["typed_admission"] == "full" and
                        row["test_owner"] == "data-plane",
                        opcode + ": live row is not data-plane closed")


def check_semantics() -> None:
    allowed_lowering = {"direct-tcg", "focused-helper",
                        "direct-tcg+focused-helper"}
    allowed_alignment = {"none", "ordinary-psr.ac", "strict-natural",
                         "strict-8-byte", "strict-16-byte",
                         "ordinary-psr.ac;reference-16-byte-span-for-e/fill",
                         "ordinary-psr.ac;reference-16-byte-span-for-e/spill"}
    for row in DATA_PLANE_OPCODE_SPECS:
        require(row.lowering in allowed_lowering,
                row.opcode + ": unbounded lowering owner")
        require(row.alignment in allowed_alignment,
                row.opcode + ": unknown alignment policy")
        require(row.helper_class not in {"exec-bundle", "exec-slot", "raw"},
                row.opcode + ": generic helper escaped into spec")
        require(row.runtime_group,
                row.opcode + ": lacks a runtime ownership group")

    reserved = {
        row.opcode for row in DATA_PLANE_OPCODE_SPECS
        if row.isa_status == "decoder-reserved-width"
    }
    require(reserved == {
        "IA64_OP_LD1FILL", "IA64_OP_LD2FILL", "IA64_OP_LD4FILL",
        "IA64_OP_ST1SPILL", "IA64_OP_ST2SPILL", "IA64_OP_ST4SPILL",
    }, "reserved-width alias inventory drifted")
    require(SPEC_BY_OPCODE["IA64_OP_LD16"].semantic.endswith("ar.csd"),
            "LD16 must target AR.CSD, not a second GR")
    require(SPEC_BY_OPCODE["IA64_OP_ST16"].lowering == "direct-tcg",
            "ST16 must use one direct qemu_st_i128 transaction")
    for opcode in ("IA64_OP_LDFE", "IA64_OP_STFE"):
        row = SPEC_BY_OPCODE[opcode]
        require(row.width == 10 and "16-byte-span" in row.alignment,
                opcode + " lost its boundary-16/payload-10 contract")
    require(all(offset + 10 <= 0x1000
                for offset in range(0, 0x1000, 16)),
            "an aligned extended payload unexpectedly crosses a 4-KiB page")
    require(SPEC_BY_OPCODE["IA64_OP_CMP8XCHG16"].alignment == "strict-8-byte",
            "cmp8xchg16 must align the selected qword, not the 16-byte base")
    require(SPEC_BY_OPCODE["IA64_OP_LFETCH"].nat.startswith("suppress"),
            "nonfaulting lfetch must suppress base-NaT faults")


def check_encodings() -> None:
    require(set(PRIMARY_ENCODINGS) == set(DATA_PLANE_OPCODES),
            "primary encoder coverage differs from 63-row map")
    require(len(set(PRIMARY_ENCODINGS.values())) == 63,
            "primary encodings unexpectedly collide")
    for opcode, raw in PRIMARY_ENCODINGS.items():
        require(0 <= raw < (1 << 41), opcode + ": slot exceeds 41 bits")
        require(field(raw, 0, 6) == 0,
                opcode + ": primary encoding unexpectedly predicated")
        require(normalize_probe(raw) == opcode,
                "{} primary normalized as {} (raw 0x{:x})".format(
                    opcode, normalize_probe(raw), raw))
    names = [alias.name for alias in ALIAS_ENCODINGS]
    require(len(names) == len(set(names)), "duplicate alias names")
    alias_opcodes = {alias.opcode for alias in ALIAS_ENCODINGS}
    require({"IA64_OP_FC", "IA64_OP_INVALAT", "IA64_OP_CHK_S",
             "IA64_OP_LFETCH", "IA64_OP_LFETCH_FAULT"} <= alias_opcodes,
            "multi-form cache/check/hint aliases are incomplete")
    for alias in ALIAS_ENCODINGS:
        normalized = normalize_probe(alias.raw)
        if alias.status == "shadowed-by-cmpxchg":
            width = SPEC_BY_OPCODE[alias.opcode].width
            require(normalized == "IA64_OP_CMPXCHG{}".format(width),
                    "{} shadowing changed to {}".format(alias.name,
                                                         normalized))
        else:
            require(normalized == alias.opcode,
                    "{} normalized as {} rather than {}".format(
                        alias.name, normalized, alias.opcode))


def check_sources(root: Path) -> None:
    """Prove the 63-row inventory is wired to typed production lowerings."""
    translate = (root / "target/ia64/translate.c").read_text(encoding="utf-8")
    decode = (root / "target/ia64/decode.c").read_text(encoding="utf-8")
    traits = (root / "target/ia64/opcode-traits.def").read_text(
        encoding="utf-8"
    )
    helper = (root / "target/ia64/helper.h").read_text(encoding="utf-8")
    data_plane = (root / "target/ia64/data-plane.c").read_text(
        encoding="utf-8"
    )
    arch_helper = (root / "target/ia64/arch-helpers.c").read_text(
        encoding="utf-8"
    )
    memory = (root / "target/ia64/mem.c").read_text(encoding="utf-8")

    def lowering(start: str, end: str) -> str:
        begin = translate.index(start)
        finish = translate.index(end, begin + len(start))
        return translate[begin:finish]

    def require_debug_before_alignment(body: str, count: int,
                                       label: str) -> None:
        debug = [match.start() for match in re.finditer(
            r"ia64_tr_emit_decoded_data_debug_pre_access\(", body
        )]
        alignment = [match.start() for match in re.finditer(
            r"ia64_tr_emit_decoded_(?:memory_alignment(?:_span)?_check|"
            r"strict_alignment_check)\(", body
        )]
        require(len(debug) == count and len(alignment) == count,
                "{}: expected {} debug/alignment pairs, got {}/{}".format(
                    label, count, len(debug), len(alignment)))
        require(all(debug_pos < alignment_pos
                    for debug_pos, alignment_pos in zip(debug, alignment)),
                label + ": Data Debug must precede Unaligned")

    data_debug_guard = lowering(
        "static void ia64_tr_emit_decoded_data_debug_pre_access",
        "static void ia64_tr_emit_decoded_store_alat_invalidate",
    )
    for token in (
        "if ((ctx->base.tb->flags & IA64_TB_FLAG_DATA_DEBUG_ACTIVE) == 0)",
        "ctx->base.tb->flags & IA64_TB_FLAG_DATA_DEBUG_ACTIVE",
        "return;",
        "gen_helper_data_debug_pre_access(",
    ):
        require(token in data_debug_guard,
                "typed Data Debug fast guard lost " + token)
    require(data_debug_guard.index("return;") <
            data_debug_guard.index("gen_helper_data_debug_pre_access"),
            "inactive Data Debug TBs must emit no helper")
    require("ia64_tr_debug_fast_guard_enabled" not in translate and
            "VIBTANIUM_TCG_DEBUG_FAST_GUARD" not in translate,
            "typed Data Debug production shape retains an escape hatch")

    reserved = {
        spec.opcode for spec in DATA_PLANE_OPCODE_SPECS
        if spec.isa_status == "decoder-reserved-width"
    }
    live = set(DATA_PLANE_OPCODES) - reserved

    trait_rows = {}
    for body in re.findall(r"IA64_OPCODE\((.*?)\)", traits, re.S):
        fields = [field.strip() for field in body.split(",")]
        if len(fields) == 8:
            trait_rows[fields[0]] = fields
    for opcode in live:
        require(opcode in trait_rows, opcode + ": missing trait row")
        row = trait_rows[opcode]
        require(row[4] == "DATA_PLANE" and row[7] == "TYPED",
                opcode + ": trait row is not fully data-plane typed")
    for opcode in reserved:
        require(opcode in trait_rows, opcode + ": missing reserved trait row")
        row = trait_rows[opcode]
        require(row[2:] == ["CANONICAL_ALIAS", "NONE", "DECODE",
                            "NONE", "NONE", "DEAD_ALIAS"],
                opcode + ": reserved trait row is not decoder-dead")
        require(opcode not in decode,
                opcode + ": reserved opcode remains decoder-reachable")

    table_start = translate.index("ia64_tr_data_plane_table[IA64_OP_COUNT]")
    table_end = translate.index("#undef IA64_TR_DP", table_start)
    table = translate[table_start:table_end]
    table_rows = set(re.findall(
        r"\[(IA64_OP_[A-Z0-9_]+)\]\s*=\s*IA64_TR_DP", table
    ))
    require(table_rows == live,
            "typed descriptor table differs from 57 live rows: "
            "missing={}, extra={}".format(sorted(live - table_rows),
                                           sorted(table_rows - live)))

    dispatch_start = translate.index(
        "static void ia64_tr_emit_decoded_instruction(")
    dispatch_end = translate.index("static bool ia64_tr_emit_decoded_rse_spine(",
                                   dispatch_start)
    dispatch = translate[dispatch_start:dispatch_end]
    require(dispatch.index("ia64_tr_decoded_data_plane(insn->opcode)") <
            dispatch.index("ia64_tr_prime_decoded_instruction_state"),
            "data-plane descriptor dispatch no longer precedes generic lowering")
    require("gen_helper_exec_bundle" not in dispatch and
            "gen_helper_exec_slot" not in dispatch,
            "data-plane dispatch escaped through a generic/raw helper")
    for kind in (
        "INTEGER_LOAD", "INTEGER_SPILL", "WIDE_LOAD", "WIDE_STORE",
        "XCHG", "CMPXCHG", "CMP8XCHG16", "FETCHADD", "FP_LOAD",
        "FP_LOAD_PAIR", "FP_STORE", "FWB", "FC", "INVALA", "INVALAT",
        "LFETCH",
    ):
        require("case IA64_TR_DATA_PLANE_" + kind in dispatch,
                "missing typed dispatch kind " + kind)
    require("ia64_tr_emit_decoded_checked_branch_split" in translate and
            "IA64_TR_DATA_PLANE_CHK_S" in translate and
            "IA64_TR_DATA_PLANE_CHK_A" in translate,
            "checked-load opcodes lost their typed CFG lowering")

    priority_lowerings = (
        ("static void ia64_tr_emit_decoded_ordinary_integer_memory(",
         "static void ia64_tr_emit_decoded_strict_alignment_check(",
         1, "ordinary scalar memory"),
        ("static void ia64_tr_emit_decoded_data_plane_integer_load(",
         "static void ia64_tr_emit_decoded_data_plane_integer_spill(",
         1, "data-plane integer load"),
        ("static void ia64_tr_emit_decoded_data_plane_integer_spill(",
         "static void ia64_tr_emit_decoded_data_plane_atomic(",
         1, "integer spill"),
        ("static void ia64_tr_emit_decoded_data_plane_atomic(",
         "static void ia64_tr_emit_decoded_data_plane_wide(",
         1, "semaphore atomic"),
        ("static void ia64_tr_emit_decoded_data_plane_wide(",
         "static void ia64_tr_emit_decoded_data_plane_cmp8xchg16(",
         2, "LD16/ST16"),
        ("static void ia64_tr_emit_decoded_data_plane_cmp8xchg16(",
         "static void ia64_tr_emit_decoded_data_plane_cache_control(",
         1, "cmp8xchg16"),
        ("static void ia64_tr_emit_decoded_data_plane_fp_load(",
         "static void ia64_tr_emit_decoded_data_plane_fp_store(",
         1, "floating load"),
        ("static void ia64_tr_emit_decoded_data_plane_fp_store(",
         "static void ia64_tr_emit_decoded_pr_move(",
         1, "floating store"),
    )
    for start, end, count, label in priority_lowerings:
        require_debug_before_alignment(lowering(start, end), count, label)

    unaligned_fault = lowering(
        "static void ia64_tr_emit_decoded_unaligned_data_reference(",
        "static void ia64_tr_emit_decoded_memory_nat_check(",
    )
    exact_ip = unaligned_fault.index(
        "tcg_gen_movi_i64(cpu_ip, insn->address)")
    preprobe = unaligned_fault.index(
        "gen_helper_data_unaligned_pre_access", exact_ip)
    deliver = unaligned_fault.index(
        "gen_helper_raise_unaligned_data_reference", preprobe)
    require(exact_ip < preprobe < deliver,
            "unaligned fault arm must bind exact IP, translation-probe, then raise")
    require("compact\n     * memory publication" in unaligned_fault,
            "unaligned fault arm lost its dominating compact safepoint")
    require("ia64_tr_group_publish_prefix_for_noreturn_fault" not in
            unaligned_fault,
            "unaligned fault arm must not republish the committed prefix")
    require("tcg_constant_i32(payload_size)" in unaligned_fault and
            "ia64_tr_data_mmu_index(ctx)" in unaligned_fault,
            "unaligned preprobe lost its full datum span or MMU index")
    require("DEF_HELPER_5(data_unaligned_pre_access" in helper,
            "unaligned translation-priority helper is not generated")
    preprobe_helper = data_plane[data_plane.index(
        "void HELPER(data_unaligned_pre_access)") :
        data_plane.index("uint32_t HELPER(data_plane_integer_load_prepare)")]
    require(preprobe_helper.count("ia64_data_probe_range") == 2 and
            "MMU_DATA_LOAD" in preprobe_helper and
            "MMU_DATA_STORE" in preprobe_helper and
            "IA64_EXCEPTION_ACCESS_SEMAPHORE" in preprobe_helper,
            "unaligned preprobe does not cover read/write/semaphore rights")
    require("cpu_ld" not in preprobe_helper and
            "cpu_st" not in preprobe_helper and
            "qemu_ld" not in preprobe_helper and
            "qemu_st" not in preprobe_helper,
            "unaligned preprobe must not issue RAM/MMIO accesses")

    fp_load = lowering(
        "static void ia64_tr_emit_decoded_data_plane_fp_load(",
        "static void ia64_tr_emit_decoded_data_plane_fp_store(",
    )
    fp_store = lowering(
        "static void ia64_tr_emit_decoded_data_plane_fp_store(",
        "static void ia64_tr_emit_decoded_pr_move(",
    )
    for body, access in ((fp_load, "READ"), (fp_store, "WRITE")):
        require("uint8_t debug_span = payload == 10 ? 16 : payload;" in body,
                "extended FP lost its 16-byte breakpoint datum span")
        require("ctx, base, debug_span, IA64_DEBUG_ACCESS_" + access in body,
                "extended FP debug lookup does not use debug_span")
        require("ctx, insn, base, alignment, payload" in body,
                "extended FP alignment lost its ten-byte payload span")
        require("ctx, base, payload, IA64_DEBUG_ACCESS_" + access not in body,
                "extended FP still uses its ten-byte payload for DBR matching")

    speculative_action = memory[
        memory.index("static bool "
                     "ia64_control_speculative_data_debug_deferred("):
        memory.index("bool ia64_control_speculative_load_defer(")
    ]
    for token in (
        "IA64_DCR_DD_BIT",
        "(psr & IA64_PSR_IC_BIT) == 0",
        "(psr & IA64_PSR_IT_BIT) != 0",
        "ia64_current_itlb_exception_deferral(env)",
        "ia64_data_debug_match",
        "IA64_CONTROL_SPECULATIVE_LOAD_DATA_DEBUG",
    ):
        require(token in speculative_action,
                "control-speculative DBR policy lost " + token)
    integer_prepare = data_plane[
        data_plane.index("uint32_t HELPER(data_plane_integer_load_prepare)("):
        data_plane.index("uint32_t HELPER(data_plane_integer_load_prepare_nat)(")
    ]
    fp_prepare = data_plane[
        data_plane.index("uint32_t HELPER(data_plane_fp_load_prepare)("):
        data_plane.index("void HELPER(data_plane_fp_load_complete)(")
    ]
    for body, label in ((integer_prepare, "integer ld.s/ld.sa"),
                        (fp_prepare, "floating ld.s/ld.sa")):
        require("ia64_control_speculative_load_action" in body and
                "IA64_CONTROL_SPECULATIVE_LOAD_DATA_DEBUG" in body and
                "IA64_EXCEPTION_DATA_DEBUG" in body,
                label + ": nondeferred DBR action is not delivered")
    data_plane_raise = arch_helper[
        arch_helper.index("G_NORETURN void ia64_raise_data_plane_exception("):
        arch_helper.index(
            "G_NORETURN void HELPER(raise_unaligned_data_reference)(")
    ]
    require("kind == IA64_EXCEPTION_DATA_DEBUG" in data_plane_raise,
            "typed data-plane exception exit rejects Data Debug")

    fc_begin = data_plane.index("void HELPER(data_plane_fc)(")
    lfetch_fault_begin = data_plane.index(
        "void HELPER(data_plane_lfetch_fault)(", fc_begin)
    fc_helper = data_plane[fc_begin:lfetch_fault_begin]
    lfetch_fault_helper = data_plane[lfetch_fault_begin:]
    require("ia64_data_debug_match" not in fc_helper,
            "FC must remain excluded from Data Debug matching")
    probe = lfetch_fault_helper.index(
        "ia64_data_plane_probe_non_access_read(")
    debug_match = lfetch_fault_helper.index("ia64_data_debug_match(")
    debug_raise = lfetch_fault_helper.index("IA64_EXCEPTION_DATA_DEBUG")
    require(probe < debug_match < debug_raise,
            "lfetch.fault must check translation before its DBR")
    require("address, 1, IA64_DEBUG_ACCESS_READ" in lfetch_fault_helper and
            "IA64_EXCEPTION_ACCESS_LFETCH_FAULT_READ_NON_ACCESS" in
            lfetch_fault_helper,
            "lfetch.fault DBR lost its one-byte read/non-access identity")
    lfetch_lowering = lowering(
        "static void ia64_tr_emit_decoded_data_plane_lfetch(",
        "static void ia64_tr_emit_decoded_pr_move(",
    )
    require(lfetch_lowering.count(
                "gen_helper_data_plane_lfetch_fault") == 1 and
            lfetch_lowering.index("if (faulting) {") <
            lfetch_lowering.index("gen_helper_data_plane_lfetch_fault"),
            "ordinary lfetch must remain excluded from the fault/DBR helper")

    wide_start = translate.index(
        "static void ia64_tr_emit_decoded_data_plane_wide(")
    wide_end = translate.index(
        "static void ia64_tr_emit_decoded_data_plane_cmp8xchg16(", wide_start)
    wide = translate[wide_start:wide_end]
    require("tcg_gen_qemu_ld_i128" in wide and
            "tcg_gen_qemu_st_i128" in wide and
            "gen_helper_data_plane_wb_only_probe" in wide,
            "wide lowering lost its single-copy/WB-only contract")
    require("tcg_gen_atomic" not in wide and
            not re.search(r"gen_helper_[a-z0-9_]*xchg", wide),
            "ST16 must remain a write-only store, never an xchg")
    wide_store = wide[wide.index(
        "    } else {\n        TCGv_i64 low = ia64_tr_scratch_i64(ctx);\n"
        "        TCGv_i64 low_nat") :]
    require(wide_store.count("tcg_gen_qemu_st_i128") == 1 and
            "tcg_gen_qemu_ld" not in wide_store and
            "tcg_gen_atomic" not in wide_store,
            "ST16 must issue exactly one write and no guest read/RMW")

    for token in (
        "data_plane_fp_extended_preflight", "data_plane_wb_only_probe",
        "probe_access", "translator_io_start(&ctx->base)",
        "ia64_tr_decoded_bundle_requires_io_boundary",
    ):
        require(token in helper + data_plane + translate,
                "production source lost " + token)

    memory_decoder_start = decode.index(
        "static IA64Opcode ia64_memory_opcode_from_x6a(")
    memory_decoder_end = decode.index(
        "static bool ia64_memory_x6a_is_acquire_load", memory_decoder_start)
    memory_decoder = decode[memory_decoder_start:memory_decoder_end]
    require("case 0x1b:" in memory_decoder and
            "return IA64_OP_LD8FILL" in memory_decoder and
            "case 0x3b:" in memory_decoder and
            "return IA64_OP_ST8SPILL" in memory_decoder,
            "architectural ld8.fill/st8.spill decoder entries drifted")
    for code in ("0x18", "0x19", "0x1a", "0x38", "0x39", "0x3a"):
        require("case " + code + ":" not in memory_decoder,
                "reserved fill/spill width remains decoder-reachable: " + code)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path,
        default=Path(__file__).resolve().parents[2],
        help="qemu-ia64 source root",
    )
    parser.add_argument(
        "--audit-open", action="store_true",
        help="require live rows closed and reserved rows decoder-dead",
    )
    args = parser.parse_args(argv)
    root = args.root.resolve()

    check_inventory(root, args.audit_open)
    check_semantics()
    check_encodings()
    check_sources(root)

    print("data-plane TCG spec: 63 rows, 8 families, {} aliases"
          .format(len(ALIAS_ENCODINGS)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
