#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Structural gate for the direct-TCG IA-64 packed-integer tranche."""

from __future__ import annotations

import argparse
import csv
import re
from pathlib import Path


PACKED_OPCODES = (
    "IA64_OP_PADD1", "IA64_OP_PADD2", "IA64_OP_PADD4",
    "IA64_OP_PSUB1", "IA64_OP_PSUB2", "IA64_OP_PSUB4",
    "IA64_OP_PSHLADD2", "IA64_OP_PSHRADD2",
    "IA64_OP_PAVG1", "IA64_OP_PAVG2",
    "IA64_OP_PAVGSUB1", "IA64_OP_PAVGSUB2",
    "IA64_OP_PCMP1_EQ", "IA64_OP_PCMP1_GT",
    "IA64_OP_PCMP2_EQ", "IA64_OP_PCMP2_GT",
    "IA64_OP_PCMP4_EQ", "IA64_OP_PCMP4_GT",
    "IA64_OP_PMAX1_U", "IA64_OP_PMAX2",
    "IA64_OP_PMIN1_U", "IA64_OP_PMIN2",
    "IA64_OP_PMPY2_L", "IA64_OP_PMPY2_R",
    "IA64_OP_PMPYSH2", "IA64_OP_PMPYSH2_U",
    "IA64_OP_PSHL2", "IA64_OP_PSHL4",
    "IA64_OP_PSHR2", "IA64_OP_PSHR2_U",
    "IA64_OP_PSHR4", "IA64_OP_PSHR4_U",
    "IA64_OP_PSAD1", "IA64_OP_MUX1", "IA64_OP_MUX2",
    "IA64_OP_MIX1_L", "IA64_OP_MIX1_R",
    "IA64_OP_MIX2_L", "IA64_OP_MIX2_R",
    "IA64_OP_MIX4_L", "IA64_OP_MIX4_R",
    "IA64_OP_PACK2_SSS", "IA64_OP_PACK2_USS", "IA64_OP_PACK4_SSS",
    "IA64_OP_UNPACK1_H", "IA64_OP_UNPACK1_L",
    "IA64_OP_UNPACK2_H", "IA64_OP_UNPACK2_L",
    "IA64_OP_UNPACK4_H", "IA64_OP_UNPACK4_L",
    "IA64_OP_CZX1_L", "IA64_OP_CZX1_R",
    "IA64_OP_CZX2_L", "IA64_OP_CZX2_R",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def section(text: str, begin: str, end: str) -> str:
    try:
        start = text.index(begin)
        finish = text.index(end, start + len(begin))
    except ValueError as exc:
        raise SystemExit(
            "packed-TCG structural marker missing: {} / {}".format(
                begin, end
            )
        ) from exc
    return text[start:finish]


def check_traits(root: Path) -> None:
    traits = (root / "target/ia64/opcode-traits.def").read_text(
        encoding="utf-8"
    )
    rows = {
        fields[0]: fields
        for body in re.findall(r"IA64_OPCODE\((.*?)\)", traits, re.DOTALL)
        if len(fields := [item.strip() for item in body.split(",")]) == 8
    }
    for opcode in PACKED_OPCODES:
        require(opcode in rows, "missing packed trait row: " + opcode)
        require(
            rows[opcode] == [
                opcode, "PACKED_INTEGER", "DIRECT_TCG", "NONE",
                "FULL_TCG", "NONE", "NO_OS", "TYPED",
            ],
            "packed trait row is not closed/direct/helper-free: {}: {}".format(
                opcode, rows[opcode]
            ),
        )

    with (root / "docs/devel/ia64-opcode-ledger.csv").open(
        encoding="utf-8", newline=""
    ) as source:
        ledger = {row["opcode"]: row for row in csv.DictReader(source)}
    for opcode in PACKED_OPCODES:
        row = ledger.get(opcode)
        require(row is not None, "missing packed ledger row: " + opcode)
        require(row["family"] == "packed-integer", opcode + ": wrong family")
        require(row["lowering_owner"] == "direct-tcg", opcode + ": owner")
        require(row["focused_helper_whitelist"] == "none", opcode + ": helper")
        require(row["typed_admission"] == "full", opcode + ": admission")
        require(row["closure"] == "closed", opcode + ": closure")
        require(row["reference_tcg"] == "yes", opcode + ": reference")


def check_translate(root: Path) -> None:
    text = (root / "target/ia64/translate.c").read_text(encoding="utf-8")
    table = section(
        text,
        "ia64_tr_packed_table[IA64_OP_COUNT]",
        "#undef IA64_TR_PACKED",
    )
    present = [
        opcode
        for opcode in re.findall(r"\[(IA64_OP_[A-Z0-9_]+)\]\s*=", table)
        if opcode != "IA64_OP_COUNT"
    ]
    require(len(present) == len(set(present)), "duplicate packed descriptor row")
    require(
        set(present) == set(PACKED_OPCODES),
        "packed descriptor coverage drift: missing={}, extra={}".format(
            sorted(set(PACKED_OPCODES) - set(present)),
            sorted(set(present) - set(PACKED_OPCODES)),
        ),
    )

    shape = section(
        text,
        "static bool ia64_tr_decoded_is_supported_packed",
        "static bool ia64_tr_decoded_opcode_supported",
    )
    for token in (
        "insn->slot_span == 1",
        "IA64_INSN_UNIT_M",
        "IA64_INSN_UNIT_I",
        "insn->imm",
        "descriptor->source_count",
        "descriptor->form",
    ):
        require(token in shape, "packed normalized-shape check lacks " + token)

    sources = section(
        text,
        "static unsigned ia64_tr_decoded_sources",
        "static bool ia64_tr_decoded_instruction_supported",
    )
    require(
        "ia64_tr_decoded_packed" in sources,
        "ordinary source planning does not use the packed descriptor",
    )

    emitter = section(
        text,
        "static void ia64_tr_packed_extract_lane",
        "static void ia64_tr_system_validate",
    )
    for forbidden in (
        "gen_helper_", "helper_exec", "ia64_exec_", "exec_predecoded_slot"
    ):
        require(forbidden not in emitter,
                "packed direct lowering calls forbidden path: " + forbidden)
    for token in (
        "ia64_tr_group_prepare_gr",
        "ia64_tr_emit_decoded_predicate_guard",
        "ia64_tr_group_load_ordinary_gr_pair",
        "ia64_tr_nat_or",
        "ia64_tr_group_ordinary_gr_nat_state",
        "tcg_gen_or_i64(combined, result_nat, source_nat[i])",
        "g_assert(result_nat != NULL)",
        "ia64_tr_group_stage_gr",
        "ia64_tr_group_stage_gr_known",
        "ia64_tr_finish_predicate_guard",
        "tcg_gen_extract_i64",
        "tcg_gen_deposit_i64",
        "tcg_gen_mul_i64",
        "tcg_gen_movcond_i64",
    ):
        require(token in emitter, "packed direct lowering lacks " + token)

    dispatch = section(
        text,
        "static void ia64_tr_emit_decoded_instruction",
        "static void ia64_tr_clear_restart_ri",
    )
    require(
        "ia64_tr_emit_decoded_packed(ctx, insn);" in dispatch,
        "typed instruction dispatcher does not select packed direct TCG",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    args = parser.parse_args()
    root = args.source_root.resolve()

    require(len(PACKED_OPCODES) == 54, "packed opcode inventory is not 54 rows")
    require(len(set(PACKED_OPCODES)) == 54, "packed opcode inventory duplicates")
    check_traits(root)
    check_translate(root)
    print("IA-64 packed direct-TCG gate passed: 54/54 helper-free rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
