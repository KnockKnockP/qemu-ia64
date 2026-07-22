#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Structural gate for the 57-row IA-64 system/control TCG tranche."""

from __future__ import annotations

import argparse
import csv
import re
import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parent))
from ia64_system_tcg_spec import (  # noqa: E402
    ENCODING_VARIANTS,
    PRECLOSED_SYSTEM_PREREQUISITES,
    SPEC_BY_OPCODE,
    SYSTEM_OPCODE_SPECS,
    SYSTEM_OPCODES,
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
            "system-TCG structural marker missing: {!r} / {!r}".format(
                begin, end
            )
        ) from exc
    return text[start:finish]


def parse_traits(root: Path) -> dict[str, list[str]]:
    text = (root / "target/ia64/opcode-traits.def").read_text(
        encoding="utf-8"
    )
    return {
        fields[0]: fields
        for body in re.findall(r"IA64_OPCODE\((.*?)\)", text, re.DOTALL)
        if len(fields := [item.strip() for item in body.split(",")]) == 8
    }


def parse_system_descriptors(table: str) -> dict[str, list[str]]:
    descriptors: dict[str, list[str]] = {}
    marker = re.compile(
        r"\[(IA64_OP_[A-Z0-9_]+)\]\s*=\s*IA64_TR_SYSTEM\("
    )
    for match in marker.finditer(table):
        depth = 1
        field_start = match.end()
        fields: list[str] = []
        index = field_start
        while index < len(table) and depth:
            char = table[index]
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    fields.append(table[field_start:index])
                    break
            elif char == "," and depth == 1:
                fields.append(table[field_start:index])
                field_start = index + 1
            index += 1
        require(depth == 0, "unterminated descriptor for " + match.group(1))
        normalized = [re.sub(r"\s+", " ", field).strip()
                      for field in fields]
        require(len(normalized) == 13,
                "{} descriptor has {} fields, not 13".format(
                    match.group(1), len(normalized)))
        require(match.group(1) not in descriptors,
                "duplicate system descriptor row: " + match.group(1))
        descriptors[match.group(1)] = normalized
    return descriptors


def expected_operand_descriptor(opcode: str) -> tuple[str, str, str, str]:
    """Independent normalized shape and architectural register footprint."""
    dest_index_r3 = {
        "IA64_OP_TPA", "IA64_OP_TAK", "IA64_OP_THASH", "IA64_OP_TTAG",
        "IA64_OP_MOV_PKRGR_INDEXED", "IA64_OP_MOV_IBRGR_INDEXED",
        "IA64_OP_MOV_DBRGR_INDEXED", "IA64_OP_MOV_PMCGR_INDEXED",
        "IA64_OP_MOV_PMDGR_INDEXED", "IA64_OP_MOV_CPUID_INDEXED",
        "IA64_OP_MOV_DAHRGR_INDEXED", "IA64_OP_MOV_MSRGR",
    }
    src_index_r3 = {
        "IA64_OP_ITR_D", "IA64_OP_ITR_I", "IA64_OP_PTR_D",
        "IA64_OP_PTR_I", "IA64_OP_PTC_L", "IA64_OP_PTC_G",
        "IA64_OP_PTC_GA", "IA64_OP_MOV_GRRR",
        "IA64_OP_MOV_GRPKR_INDEXED", "IA64_OP_MOV_GRIBR_INDEXED",
        "IA64_OP_MOV_GRDBR_INDEXED", "IA64_OP_MOV_GRPMC_INDEXED",
        "IA64_OP_MOV_GRPMD_INDEXED", "IA64_OP_MOV_GRMSR",
    }
    dest_r1 = {
        "IA64_OP_MOV_PSRGR", "IA64_OP_MOV_UMGR",
        "IA64_OP_MOV_CURRENT_IP",
    }
    src_r1 = {"IA64_OP_MOV_GRPSR", "IA64_OP_MOV_GRUM"}
    mask = {"IA64_OP_SSM", "IA64_OP_RSM", "IA64_OP_RUM",
            "IA64_OP_SUM_UM"}

    if opcode == "IA64_OP_BREAK":
        return ("BREAK", "IA64_TR_SYSTEM_GR_NONE",
                "IA64_TR_SYSTEM_GR_NONE", "IA64_TR_SYSTEM_BR_NONE")
    if opcode == "IA64_OP_BR_IA":
        return ("BRANCH", "IA64_TR_SYSTEM_GR_NONE",
                "IA64_TR_SYSTEM_GR_NONE", "IA64_TR_SYSTEM_BR_B2")
    if opcode == "IA64_OP_BRP":
        return ("BRANCH", "IA64_TR_SYSTEM_GR_NONE",
                "IA64_TR_SYSTEM_GR_NONE", "IA64_TR_SYSTEM_BR_NONE")
    if opcode == "IA64_OP_MOV_IMMAR":
        return ("AR_IMMEDIATE", "IA64_TR_SYSTEM_GR_NONE",
                "IA64_TR_SYSTEM_GR_NONE", "IA64_TR_SYSTEM_BR_NONE")
    if opcode == "IA64_OP_MOV_CRGR":
        return ("DEST_R1_INDEX_R2", "IA64_TR_SYSTEM_GR_NONE",
                "IA64_TR_SYSTEM_GR_R1", "IA64_TR_SYSTEM_BR_NONE")
    if opcode == "IA64_OP_MOV_GRCR":
        return ("SRC_R1_INDEX_R2", "IA64_TR_SYSTEM_GR_R1",
                "IA64_TR_SYSTEM_GR_NONE", "IA64_TR_SYSTEM_BR_NONE")
    if opcode == "IA64_OP_MOV_RRGR":
        return ("DEST_R1_INDEX_R2", "IA64_TR_SYSTEM_GR_R2",
                "IA64_TR_SYSTEM_GR_R1", "IA64_TR_SYSTEM_BR_NONE")
    if opcode in dest_index_r3:
        return ("DEST_R1_INDEX_R3", "IA64_TR_SYSTEM_GR_R3",
                "IA64_TR_SYSTEM_GR_R1", "IA64_TR_SYSTEM_BR_NONE")
    if opcode in src_index_r3:
        return ("SRC_R2_INDEX_R3",
                "IA64_TR_SYSTEM_GR_R2 | IA64_TR_SYSTEM_GR_R3",
                "IA64_TR_SYSTEM_GR_NONE", "IA64_TR_SYSTEM_BR_NONE")
    if opcode in {"IA64_OP_PROBE_R", "IA64_OP_PROBE_W"}:
        return ("PROBE",
                "IA64_TR_SYSTEM_GR_R2 | IA64_TR_SYSTEM_GR_R3",
                "IA64_TR_SYSTEM_GR_R1", "IA64_TR_SYSTEM_BR_NONE")
    if opcode == "IA64_OP_PROBE_RW":
        return ("PROBE", "IA64_TR_SYSTEM_GR_R3",
                "IA64_TR_SYSTEM_GR_NONE", "IA64_TR_SYSTEM_BR_NONE")
    if opcode == "IA64_OP_PTC_E":
        return ("INDEX_R3", "IA64_TR_SYSTEM_GR_R3",
                "IA64_TR_SYSTEM_GR_NONE", "IA64_TR_SYSTEM_BR_NONE")
    if opcode in {"IA64_OP_ITC_D", "IA64_OP_ITC_I"}:
        return ("SRC_R2", "IA64_TR_SYSTEM_GR_R2",
                "IA64_TR_SYSTEM_GR_NONE", "IA64_TR_SYSTEM_BR_NONE")
    if opcode in dest_r1:
        return ("DEST_R1", "IA64_TR_SYSTEM_GR_NONE",
                "IA64_TR_SYSTEM_GR_R1", "IA64_TR_SYSTEM_BR_NONE")
    if opcode in src_r1:
        return ("SRC_R1", "IA64_TR_SYSTEM_GR_R1",
                "IA64_TR_SYSTEM_GR_NONE", "IA64_TR_SYSTEM_BR_NONE")
    if opcode in mask:
        return ("MASK", "IA64_TR_SYSTEM_GR_NONE",
                "IA64_TR_SYSTEM_GR_NONE", "IA64_TR_SYSTEM_BR_NONE")
    none = {
        "IA64_OP_SYNC_I", "IA64_OP_SRLZ", "IA64_OP_SRLZ_D",
        "IA64_OP_MF", "IA64_OP_MF_A", "IA64_OP_BSW0",
        "IA64_OP_BSW1", "IA64_OP_EPC", "IA64_OP_VMSW",
    }
    require(opcode in none, opcode + ": missing operand descriptor contract")
    return ("NONE", "IA64_TR_SYSTEM_GR_NONE",
            "IA64_TR_SYSTEM_GR_NONE", "IA64_TR_SYSTEM_BR_NONE")


def check_inventory(root: Path) -> None:
    require(len(SYSTEM_OPCODES) == 57, "system inventory is not 57 rows")
    require(len(set(SYSTEM_OPCODES)) == 57, "system inventory duplicates")

    with (root / "docs/devel/ia64-opcode-ledger.csv").open(
        encoding="utf-8", newline=""
    ) as source:
        rows = {row["opcode"]: row for row in csv.DictReader(source)}

    selected = {
        opcode for opcode, row in rows.items()
        if row["family"] in {
            "system-register-move", "mmu", "state-control",
            "move-cr-to-gr", "move-gr-to-cr", "move-gr-to-ar",
        } or opcode in {"IA64_OP_BREAK", "IA64_OP_BR_IA", "IA64_OP_BRP"}
    }
    # Dead aliases are deliberately not owned by this tranche.
    selected = {
        opcode for opcode in selected
        if rows[opcode]["decoder_status"] == "live"
    }
    selected -= set(PRECLOSED_SYSTEM_PREREQUISITES)
    require(
        selected == set(SYSTEM_OPCODES),
        "57-row ledger ownership drift: missing={}, extra={}".format(
            sorted(set(SYSTEM_OPCODES) - selected),
            sorted(selected - set(SYSTEM_OPCODES)),
        ),
    )
    for spec in SYSTEM_OPCODE_SPECS:
        row = rows[spec.opcode]
        require(row["family"] == spec.family,
                spec.opcode + ": family differs from independent spec")
        require(row["lowering_owner"] in {"direct-tcg", "focused-helper"},
                spec.opcode + ": still owned by the legacy oracle")
        require(row["test_owner"] == "full-tcg",
                spec.opcode + ": no full-TCG test owner")
        require(row["typed_admission"] == "full",
                spec.opcode + ": typed admission is not full")
        require(row["closure"] == "closed",
                spec.opcode + ": family row is not verified")
        require(row["system_evidence"] == "no-os",
                spec.opcode + ": no no-OS system evidence")

    for opcode in PRECLOSED_SYSTEM_PREREQUISITES:
        require(opcode in rows and rows[opcode]["decoder_status"] == "live",
                opcode + ": missing preclosed live prerequisite")
        require(rows[opcode]["lowering_owner"] == "focused-helper" and
                rows[opcode]["focused_helper_whitelist"] == "system-plane" and
                rows[opcode]["test_owner"] == "full-tcg" and
                rows[opcode]["typed_admission"] == "full" and
                rows[opcode]["system_evidence"] == "no-os" and
                rows[opcode]["closure"] == "closed",
                opcode + ": preclosed prerequisite regressed")


def check_traits(root: Path) -> None:
    traits = parse_traits(root)
    family_names = {
        "SYSTEM_MOVE": "system-register-move",
    }
    for opcode in PRECLOSED_SYSTEM_PREREQUISITES:
        require(opcode in traits, "missing prerequisite trait: " + opcode)
        fields = traits[opcode]
        require(fields[2] == "FOCUSED_HELPER" and
                fields[3] == "SYSTEM_PLANE" and
                fields[4] == "FULL_TCG" and fields[6] == "NO_OS" and
                fields[7] == "TYPED",
                opcode + ": preclosed prerequisite trait regressed")
    for spec in SYSTEM_OPCODE_SPECS:
        require(spec.opcode in traits, "missing trait: " + spec.opcode)
        fields = traits[spec.opcode]
        trait_family = family_names.get(
            fields[1], fields[1].replace("_", "-").lower()
        )
        require(trait_family == spec.family,
                spec.opcode + ": trait family mismatch: " + repr(fields))
        require(fields[2] in {"DIRECT_TCG", "FOCUSED_HELPER"},
                spec.opcode + ": legacy trait owner: " + fields[2])
        if spec.owner == "direct":
            require(fields[2] == "DIRECT_TCG",
                    spec.opcode + ": helper-free row is not direct TCG")
            require(fields[3] == "NONE",
                    spec.opcode + ": helper-free row has a whitelist")
        elif fields[2] == "FOCUSED_HELPER":
            require(fields[3] != "NONE",
                    spec.opcode + ": focused row lacks a bounded helper class")
        require(fields[4] == "FULL_TCG",
                spec.opcode + ": trait lacks full-TCG tests")
        require(fields[6] == "NO_OS",
                spec.opcode + ": trait lacks no-OS evidence")
        require(fields[7] == "TYPED",
                spec.opcode + ": trait lifecycle is not typed")


def check_translate(root: Path) -> None:
    text = (root / "target/ia64/translate.c").read_text(encoding="utf-8")
    table = section(
        text,
        "ia64_tr_system_table[IA64_OP_COUNT]",
        "#undef IA64_TR_SYSTEM",
    )
    descriptors = parse_system_descriptors(table)
    require(
        set(descriptors) == set(SYSTEM_OPCODES),
        "system descriptor coverage drift: missing={}, extra={}".format(
            sorted(set(SYSTEM_OPCODES) - set(descriptors)),
            sorted(set(descriptors) - set(SYSTEM_OPCODES)),
        ),
    )

    privilege = {
        "none": "NONE", "always": "ALWAYS", "register": "REGISTER",
        "pmd": "PMD", "feature": "FEATURE",
    }
    nat = {
        "none": "NONE", "value": "VALUE", "index": "INDEX",
        "value,index": "VALUE_INDEX", "address": "ADDRESS",
        "address,size": "ADDRESS_SIZE",
        "address,level": "ADDRESS_LEVEL",
        "propagate-address": "PROPAGATE_ADDRESS",
    }
    tb_end = {
        "continue": "CONTINUE", "bundle": "BUNDLE",
        "slot": "NEXT_SLOT", "control": "CONTROL",
        "no-return": "NORETURN",
        "conditional-bundle": "CONDITIONAL_BUNDLE",
    }
    lowering = {
        "direct": "DIRECT", "serialize": "DIRECT",
        "exception": "EXCEPTION", "control": "CONTROL",
        "mmu": "MMU", "focused": "STATE",
    }
    for spec in SYSTEM_OPCODE_SPECS:
        fields = descriptors[spec.opcode]
        expected_shape, expected_src_gr, expected_dst_gr, expected_src_br = \
            expected_operand_descriptor(spec.opcode)
        expected_units = ({"M", "I", "F", "B", "X"}
                          if spec.opcode == "IA64_OP_BREAK" else
                          ({"M", "I"}
                           if spec.opcode == "IA64_OP_MOV_IMMAR" else
                           {spec.unit}))
        actual_units = set(re.findall(r"SYSTEM_UNIT\(([MIFBXL])\)",
                                      fields[3]))
        expected_spans = ({"1", "2"}
                          if spec.opcode == "IA64_OP_BREAK" else {"1"})
        actual_spans = set(re.findall(r"SYSTEM_SPAN_([12])", fields[4]))
        require(fields[0] == spec.opcode.removeprefix("IA64_OP_"),
                spec.opcode + ": descriptor kind drift")
        require(fields[1] == expected_shape,
                spec.opcode + ": normalized operand shape drift")
        require(fields[5] == expected_src_gr,
                spec.opcode + ": source-GR footprint drift")
        require(fields[6] == expected_dst_gr,
                spec.opcode + ": destination-GR footprint drift")
        require(fields[7] == expected_src_br,
                spec.opcode + ": source-BR footprint drift")
        expected_lowering = ("DIRECT"
                             if spec.opcode == "IA64_OP_MOV_PSRGR" else
                             lowering[spec.owner])
        require(fields[2] == expected_lowering,
                spec.opcode + ": descriptor lowering drift")
        require(actual_units == expected_units,
                spec.opcode + ": descriptor unit mask drift")
        require(actual_spans == expected_spans,
                spec.opcode + ": descriptor span mask drift")
        require(fields[8] == str(spec.predicable).lower(),
                spec.opcode + ": descriptor predication drift")
        require(fields[9] == privilege[spec.privilege],
                spec.opcode + ": descriptor privilege drift")
        require(fields[10] == nat[spec.nat],
                spec.opcode + ": descriptor NaT policy drift")
        require(fields[11] == tb_end[spec.tb_end],
                spec.opcode + ": descriptor TB-end drift")
        require(fields[12] == str(spec.must_end_group).lower(),
                spec.opcode + ": descriptor group-end drift")

    admission = section(
        text,
        "static bool ia64_tr_decoded_is_supported_system",
        "static bool ia64_tr_decoded_opcode_supported",
    )
    for token in (
        # BREAK.X is a normalized two-slot MLX instruction; admission must
        # inspect the span through the descriptor instead of hard-coding one.
        "insn->slot_span",
        "descriptor->unit_mask",
        "descriptor->span_mask",
        "descriptor->status_mask",
        "descriptor->shape",
        "insn->status",
        "insn->reserved_field",
    ):
        require(token in admission,
                "system normalized-shape admission lacks " + token)

    emitter = section(
        text,
        "static void ia64_tr_emit_decoded_system",
        "static void ia64_tr_emit_decoded_instruction",
    )
    forbidden = (
        "gen_helper_exec_bundle", "gen_helper_exec_slot",
        "helper_exec_bundle", "helper_exec_slot", "exec_predecoded_slot",
        "ia64_exec_bundle_impl",
    )
    for token in forbidden:
        require(token not in emitter,
                "system lowering reaches a generic execution path: " + token)

    predicate = emitter.find("ia64_tr_emit_decoded_predicate_guard")
    validation_candidates = [
        pos for marker in (
            "ia64_tr_system_validate", "raise_privileged",
            "raise_register_nat", "raise_reserved",
        ) if (pos := emitter.find(marker)) >= 0
    ]
    require(predicate >= 0, "system emitter lacks a predicate guard")
    require(validation_candidates,
            "system emitter lacks architectural validation/fault paths")
    require(predicate < min(validation_candidates),
            "system legality/privilege/NaT checks precede predication")

    for token in (
        "ia64_tr_group_prepare_gr",
        "ia64_tr_system_load_gr",
        "ia64_tr_group_stage_gr",
        "ia64_tr_publish_fault_state",
        "tcg_gen_mb",
    ):
        require(token in emitter, "system emitter lacks " + token)

    preflight = emitter.find("gen_helper_system_preflight")
    operand_load = emitter.find("ia64_tr_system_load_gr")
    require(0 <= preflight < operand_load,
            "system preflight no longer precedes operand/NaT consumption")

    dispatch = section(
        text,
        "static void ia64_tr_emit_decoded_instruction",
        "static void ia64_tr_clear_restart_ri",
    )
    require("ia64_tr_emit_decoded_system(ctx, insn);" in dispatch,
            "typed dispatcher does not select the system plane")

    # Instruction-side translation changes and serialization must resume at
    # the exact next physical slot, not merely carry a descriptor/comment.
    driver = section(
        text,
        "static bool ia64_tr_try_decoded_bundle",
        "static void ia64_tr_emit_main_loop_exit",
    )
    require("system->tb_end == IA64_TR_SYSTEM_TB_NEXT_SLOT" in driver,
            "bundle driver does not dispatch NEXT_SLOT descriptors")
    require(re.search(
        r"ia64_tr_emit_system_main_loop_exit\(\s*ctx,\s*pc,\s*"
        r"slot \+ insn->slot_span\s*\)", driver, re.DOTALL) is not None,
        "NEXT_SLOT path does not publish the exact physical continuation")


def check_translation_insert_ic_legality(root: Path) -> None:
    """Lock down the architected IC -> CPL -> NaT/field fault order."""
    text = (root / "target/ia64/system-plane.c").read_text(encoding="utf-8")
    predicate = section(
        text,
        "static bool ia64_system_translation_insert_requires_ic_clear",
        "static void ia64_system_validate_privilege",
    )
    cases = set(re.findall(r"case (IA64_OP_[A-Z0-9_]+):", predicate))
    require(cases == {
        "IA64_OP_ITC_D", "IA64_OP_ITC_I",
        "IA64_OP_ITR_D", "IA64_OP_ITR_I",
    }, "PSR.ic translation-insert legality inventory drift")
    require("return true;" in predicate and
            re.search(r"default:\s*return false;", predicate) is not None,
            "translation-insert IC predicate lacks a closed true/false split")

    preflight = section(
        text,
        "void HELPER(system_preflight)",
        "void HELPER(application_register_preflight)",
    )
    ic_gate = re.search(
        r"if\s*\(ia64_system_translation_insert_requires_ic_clear\(opcode\)"
        r"\s*&&\s*\(env->psr\s*&\s*IA64_PSR_IC_BIT\)\s*!=\s*0\s*\)"
        r"\s*\{\s*ia64_system_raise_illegal\(env\);\s*\}",
        preflight,
        re.DOTALL,
    )
    require(ic_gate is not None,
            "ITC/ITR IC=1 no longer raises Illegal Operation")
    privilege = preflight.find("ia64_system_validate_privilege")
    require(privilege >= 0 and ic_gate.start() < privilege,
            "ITC/ITR PSR.ic legality no longer precedes CPL")
    require(preflight.find("ia64_system_insert_translation") < 0,
            "IC-clear preflight unexpectedly performs an insertion")

    dispatch = section(
        text,
        "uint64_t HELPER(system_plane)",
        "default:",
    )
    for opcode in sorted(cases):
        require("case " + opcode + ":" in dispatch,
                opcode + " IC=0 success path is no longer dispatched")
    require("ia64_system_insert_translation(env, opcode, arg0, arg1);" in
            dispatch,
            "IC=0 translation inserts no longer reach the shared inserter")


def check_vhpt_backing_debug_abort(root: Path) -> None:
    memory = (root / "target/ia64/mem.c").read_text(encoding="utf-8")
    begin = memory.index("static IA64VHPTWalkStatus ia64_try_vhpt_walk_common(")
    end = memory.index("IA64VHPTWalkStatus ia64_try_vhpt_walk(", begin)
    walker = memory[begin:end]

    translate = walker.index("ia64_translate_address_common(")
    debug = walker.index("ia64_data_debug_match_at_cpl(")
    read = walker.index("ia64_read_vhpt_u64(")
    install = walker.index("ia64_install_translation(")
    require(translate < debug < read < install,
            "VHPT backing DBR abort lost translation-before-debug-before-read "
            "ordering")
    debug_arm = walker[debug:read]
    for token in ("env, iha, 8", "IA64_DEBUG_ACCESS_READ, 0",
                  "return IA64_VHPT_WALK_MISS;"):
        require(token in debug_arm,
                "VHPT backing DBR abort lost " + token)


def check_vhpt_advertised_default(root: Path) -> None:
    cpu = (root / "target/ia64/cpu.c").read_text(encoding="utf-8")
    memory = (root / "target/ia64/mem.c").read_text(encoding="utf-8")
    header = (root / "target/ia64/mem.h").read_text(encoding="utf-8")
    firmware = (root / "hw/ia64/firmware.c").read_text(encoding="utf-8")

    require("const uint64_t hardware_walker = 1;" in firmware,
            "PAL_VM_SUMMARY no longer advertises the VHPT walker")
    require("VIBTANIUM_VHPT_WALK" not in cpu + memory + header,
            "advertised VHPT walking still depends on a private host knob")
    miss_path = section(
        cpu,
        "if (!translated &&",
        "if (result.status == IA64_TRANSLATE_OK &&",
    )
    require("ia64_try_rse_vhpt_walk(" in miss_path and
            "ia64_try_vhpt_walk(" in miss_path,
            "TLB misses no longer reach the advertised VHPT walker")


def check_application_register_plane(root: Path) -> None:
    """Lock target legality and legality/NaT/value/privilege ordering."""
    translate = (root / "target/ia64/translate.c").read_text(encoding="utf-8")
    data_plane = (root / "target/ia64/data-plane.c").read_text(
        encoding="utf-8"
    )
    system = (root / "target/ia64/system-plane.c").read_text(encoding="utf-8")
    insn = (root / "target/ia64/insn.c").read_text(encoding="utf-8")
    ar_legality = section(
        system,
        "static void ia64_system_validate_ar_legality(",
        "static void ia64_system_validate_ar_privilege(",
    )
    require("write && reg == IA64_AR_BSP" in ar_legality and
            "reg == IA64_AR_BSPSTORE || reg == IA64_AR_RNAT" in ar_legality and
            "env->rse.rsc & IA64_RSC_MODE_MASK" in ar_legality,
            "RSE application-register read-only/mode legality drifted")

    write_resources = section(
        translate,
        "static void ia64_tr_plan_ar_write_resources(",
        "static void ia64_tr_plan_gr_source(",
    )
    for token in ("IA64_AR_BSPSTORE", "IA64_AR_BSP", "IA64_AR_RNAT"):
        require(token in write_resources,
                "BSPSTORE typed side-effect footprint lost " + token)
    lowering = section(
        translate,
        "static void ia64_tr_emit_decoded_application_move(",
        "static unsigned ia64_tr_decoded_bitfield_pos(",
    )
    read_arm = lowering[lowering.index(
        "if (insn->opcode == IA64_OP_MOV_ARGR)"):
        lowering.index("        uint64_t expected[2]")]
    require(read_arm.index("ia64_tr_emit_decoded_predicate_guard") <
            read_arm.index("ia64_tr_emit_application_target_check") <
            read_arm.index("ia64_tr_emit_application_legality") <
            read_arm.index("ia64_tr_emit_application_privilege") <
            read_arm.index("gen_helper_application_register_read"),
            "MOV_ARGR target/selector/read fault order drifted")
    require("insn->r2 != IA64_AR_ITC && insn->qp == 0" in read_arm,
            "qualified MOV_ARGR helper result can escape its predicate arm")
    target_check = section(
        translate,
        "static void ia64_tr_emit_application_target_check(",
        "static void ia64_tr_emit_application_write_value_check(",
    )
    require("insn->r1 == 0" in target_check and
            "insn->r1 < IA64_STATIC_GR_COUNT" in target_check and
            "offsetof(CPUIA64State, cfm)" in target_check and
            "ia64_tr_emit_decoded_illegal_operation" in target_check,
            "MOV_ARGR no longer rejects r0/out-of-frame targets")

    write_arm = lowering[lowering.index(
        "    {\n        IA64TrArEffect *pfs_write"):]
    pfs_prepare = write_arm.index("ia64_tr_group_prepare_pfs_write")
    predicate_guard = write_arm.index(
        "ia64_tr_emit_decoded_predicate_guard", pfs_prepare)
    legality = write_arm.index(
        "ia64_tr_emit_application_legality(ctx, insn, true)")
    source = write_arm.index("ia64_tr_group_load_ordinary_gr_pair", legality)
    nat = write_arm.index("ia64_tr_emit_decoded_register_nat_check", source)
    value = write_arm.index("ia64_tr_emit_application_write_value_check", nat)
    pfs_write = write_arm.index("ia64_tr_group_write_pfs", value)
    privilege = write_arm.index(
        "ia64_tr_emit_application_privilege(ctx, insn, true)", value)
    committed_write = write_arm.index(
        "gen_helper_application_register_write_committed", privilege)
    require(pfs_prepare < predicate_guard < legality < source < nat <
            value < pfs_write and
            legality < source < nat < value < privilege < committed_write,
            "MOV_GRAR legality/NaT/value/privilege/write ordering drifted")
    for token in (
            "ia64_tr_application_write_contract",
            "ia64_tr_apply_application_write_post",
            "ia64_tr_finish_faulting_slot",
    ):
        require(token in write_arm,
                "MOV_GRAR exact helper contract lost " + token)
    require("instruction->forward_pfs ==" in write_arm and
            "instruction->must_pfs ==" in write_arm,
            "MOV_GRAR PFS overlay assertions disappeared")
    require("ia64_tr_plan_ar_write_resources(expected, insn->r2)" in
            write_arm and
            "instruction->dest_ar[0] == expected[0]" in write_arm and
            "instruction->dest_ar[1] == expected[1]" in write_arm,
            "MOV_GRAR no longer asserts the complete AR side-effect set")

    planner = section(
        translate,
        "static void ia64_tr_rewrite_plan_append(",
        "static void ia64_tr_rewrite_plan_append_bundle(",
    )
    require("system->kind == IA64_TR_SYSTEM_MOV_IMMAR" in planner and
            planner.count("ia64_tr_plan_ar_write_resources("
                          "plan->dest_ar, insn->r2)") == 2 and
            "plan->forward_pfs = true" in planner and
            "plan->must_pfs = insn->qp == 0" in planner,
            "MOV_GRAR/MOV_IMMAR AR transaction planning drifted")
    system_lowering = section(
        translate,
        "static void ia64_tr_emit_decoded_system(",
        "static void ia64_tr_emit_decoded_instruction(",
    )
    pfs_special = system_lowering[system_lowering.index(
        "descriptor->kind == IA64_TR_SYSTEM_MOV_IMMAR &&"):
        system_lowering.index("if (descriptor->kind == IA64_TR_SYSTEM_MF")]
    require(pfs_special.index("ia64_tr_group_prepare_pfs_write") <
            pfs_special.index("ia64_tr_emit_decoded_predicate_guard") <
            pfs_special.index("ia64_tr_emit_application_write_value_check") <
            pfs_special.index("ia64_tr_group_write_pfs"),
            "MOV_IMMAR PFS preparation/predicate/value ordering drifted")

    pfs_prepare_helper = section(
        translate,
        "static IA64TrArEffect *ia64_tr_group_prepare_pfs_write(",
        "static void ia64_tr_group_write_pfs(",
    )
    require("ia64_tr_ssa_ensure_branch_pfs_forwarded" in
            pfs_prepare_helper and
            "ia64_tr_group_prepare_ordered_ar_effect" in pfs_prepare_helper,
            "qualified PFS writes no longer define both SSA predecessors")

    writer = section(
        system,
        "void HELPER(application_register_write)(",
        "uint64_t HELPER(system_plane)(",
    )
    require(writer.index("ia64_system_validate_ar_write_value") <
            writer.index("ia64_system_validate_ar_privilege") <
            writer.index("ia64_system_preserve_ar_write_sources") <
            writer.index("ia64_write_application_register"),
            "AR writer no longer orders reserved value before privilege")
    rsc_fields = section(
        system,
        "static bool ia64_system_reserved_rsc(",
        "static bool ia64_system_reserved_fpsr(",
    )
    for token in ("UINT64_C(0x1f)", "UINT64_C(0x3fff)",
                  "IA64_RSC_LOADRS_SHIFT", "value & ~implemented"):
        require(token in rsc_fields,
                "RSC reserved-field contract lost " + token)
    fpsr_fields = section(
        system,
        "static bool ia64_system_reserved_fpsr(",
        "static bool ia64_system_reserved_cr_value(",
    )
    for token in ("value >> 58", "value >> 12", "value >> 47",
                  "value >> 34", "value >> 21", "value >> 8"):
        require(token in fpsr_fields,
                "FPSR reserved-field contract lost " + token)
    pfs_fields = section(
        system,
        "static bool ia64_system_reserved_pfs(",
        "static bool ia64_system_reserved_rsc(",
    )
    for token in ("sof > IA64_RSE_PHYS_STACKED_REGS", "sol > sof",
                  "sor > sof", "rrb_gr >= sor", "rrb_fr >= 96",
                  "rrb_pr >= 48", "UINT64_C(0x3fff) << 38",
                  "UINT64_C(0xf) << 58"):
        require(token in pfs_fields,
                "PFS reserved-field contract lost " + token)
    ar_writer = section(
        insn,
        "void ia64_write_application_register(",
        "static const char *ia64_cr_trace_name(",
    )
    for token in ("value & ~7ULL", "ia64_rse_write_rnat(env, value)",
                  "env->nat.unat = value", "value & UINT64_C(0x3f)"):
        require(token in ar_writer,
                "named AR ignored/preserve contract lost " + token)
    atomic = section(
        translate,
        "static void ia64_tr_emit_decoded_data_plane_atomic(",
        "static void ia64_tr_emit_decoded_data_plane_wide(",
    )
    require(
        atomic.index("ia64_tr_group_load_ordinary_ar(") <
        atomic.index("IA64_AR_CCV") <
        atomic.index("gen_helper_data_plane_cmpxchg(") <
        atomic.index("ia64_tr_group_stage_gr_known("),
        "cmpxchg no longer consumes CCV before publishing the old value",
    )
    cmpxchg = section(
        data_plane,
        "uint64_t HELPER(data_plane_cmpxchg)(",
        "static MemOpIdx ia64_data_plane_wide_oi(",
    )
    for token in (
        "(compare & mask) == compare",
        "ia64_data_plane_load_scalar(env, address, width, big_endian)",
        "cpu_atomic_cmpxchgb_mmu",
        "cpu_atomic_cmpxchgw_le_mmu",
        "cpu_atomic_cmpxchgl_le_mmu",
        "cpu_atomic_cmpxchgq_le_mmu",
        "if (old == compare)",
    ):
        require(token in cmpxchg,
                "CCV/cmpxchg width contract lost " + token)
    fill = section(
        translate,
        "static void ia64_tr_emit_decoded_data_plane_integer_load(",
        "static void ia64_tr_emit_decoded_data_plane_integer_spill(",
    )
    for token in (
        "descriptor->memory_class == 6",
        "ia64_tr_group_load_ordinary_ar(ctx, unat, IA64_AR_UNAT)",
        "tcg_gen_shri_i64(bitpos, base, 3)",
        "tcg_gen_andi_i64(bitpos, bitpos, 0x3f)",
        "tcg_gen_shr_i64(result_nat, unat, bitpos)",
    ):
        require(token in fill, "ld8.fill UNAT selector contract lost " + token)
    spill = section(
        translate,
        "static void ia64_tr_emit_decoded_data_plane_integer_spill(",
        "static void ia64_tr_emit_decoded_data_plane_atomic(",
    )
    for token in (
        "ia64_tr_group_prepare_ordered_ar_effect(",
        "ia64_tr_group_load_ordered_ar_effect(ctx, unat, IA64_AR_UNAT)",
        "tcg_gen_shri_i64(bitpos, base, 3)",
        "tcg_gen_andi_i64(bitpos, bitpos, 0x3f)",
        "tcg_gen_movcond_i64(TCG_COND_NE, next, value_nat",
        "ia64_tr_group_stage_ordered_ar_effect(ctx, unat_write, next)",
    ):
        require(token in spill,
                "st8.spill ordered UNAT selector contract lost " + token)
    preserve = section(
        system,
        "static void ia64_system_preserve_ar_write_sources(",
        "void HELPER(application_register_write)(",
    )
    for token in ("selector == IA64_AR_BSPSTORE", "IA64_AR_BSP",
                  "IA64_AR_RNAT"):
        require(token in preserve,
                "BSPSTORE source-visibility closure lost " + token)
    io_boundary = section(
        translate,
        "static bool ia64_tr_decoded_bundle_requires_io_boundary(",
        "static bool ia64_tr_preflight_decoded_bundle(",
    )
    for token in ("IA64_OP_MOV_ARGR", "IA64_OP_MOV_GRAR",
                  "IA64_OP_MOV_IMMAR", "IA64_AR_ITC",
                  "IA64_OP_MOV_GRCR", "IA64_CR_ITM", "IA64_CR_ITV"):
        require(token in io_boundary,
                "timer-register I/O boundary lost " + token)


def check_variant_matrix() -> None:
    require(set(ENCODING_VARIANTS) == {
        "IA64_OP_BREAK", "IA64_OP_MOV_IMMAR", "IA64_OP_PROBE_R",
        "IA64_OP_PROBE_W", "IA64_OP_PROBE_RW", "IA64_OP_VMSW",
        "IA64_OP_BRP",
    }, "system normalized-form variant inventory drift")
    require(sum(len(rows) for rows in ENCODING_VARIANTS.values()) == 19,
            "system normalized-form variant count drift")


def check_control_register_partition(root: Path) -> None:
    cpu = (root / "target/ia64/cpu.h").read_text(encoding="utf-8")
    decode = (root / "target/ia64/decode.c").read_text(encoding="utf-8")
    system = (root / "target/ia64/system-plane.c").read_text(
        encoding="utf-8"
    )
    for token in ("IA64_CR_IIB0 = 26", "IA64_CR_IIB1 = 27"):
        require(token in cpu, "control-register endpoint lost " + token)
    reserved = section(
        decode,
        "static bool ia64_reserved_cr(uint8_t cr)",
        "bool ia64_instruction_has_illegal_register(",
    )
    compact = re.sub(r"\s+", " ", reserved)
    for token in (
        "cr >= 3 && cr <= 7",
        "cr >= 9 && cr <= 15",
        "cr == 18",
        "cr >= 28 && cr <= 63",
        "cr >= 75 && cr <= 79",
        "cr >= 82",
    ):
        require(token in compact, "CR reserved partition lost " + token)
    require("cr >= 26 && cr <= 63" not in compact and
            "cr >= 10 && cr <= 15" not in compact,
            "CR9 or IIB0/IIB1 reverted to the former wrong partition")
    require(system.count(
        "reg >= IA64_CR_IPSR && reg <= IA64_CR_IIB1"
    ) == 2, "CR interruption-access range no longer reaches IIB1")
    reserved_values = section(
        system,
        "static bool ia64_system_reserved_cr_value",
        "static uint64_t ia64_system_normalize_cr_value",
    )
    for token in (
        "case IA64_CR_DCR:", "case IA64_CR_PTA:",
        "case IA64_CR_IPSR:", "case IA64_CR_ISR:",
        "case IA64_CR_IFS:", "case IA64_CR_LID:",
        "case IA64_CR_IVR:", "case IA64_CR_TPR:",
        "case IA64_CR_ITV:", "case IA64_CR_PMV:",
        "case IA64_CR_CMCV:", "case IA64_CR_LRR0:",
        "case IA64_CR_LRR1:", "ps < 15", "delivery_mode == 1",
        "delivery_mode == 3", "delivery_mode == 6",
    ):
        require(token in reserved_values,
                "named CR reserved-field contract lost " + token)
    normalized_values = section(
        system,
        "static uint64_t ia64_system_normalize_cr_value",
        "static uint64_t ia64_system_validate_cr_access",
    )
    for token in (
        "case IA64_CR_IVA:", "~UINT64_C(0x7fff)",
        "case IA64_CR_IHA:", "~UINT64_C(3)",
        "case IA64_CR_LID:", "UINT64_C(0x00000000ffff0000)",
        "case IA64_CR_TPR:", "UINT64_C(0x100f0)",
        "case IA64_CR_EOI:", "return 0;",
        "case IA64_CR_ITV:", "case IA64_CR_PMV:",
        "case IA64_CR_CMCV:", "UINT64_C(0x100ff)",
        "case IA64_CR_LRR0:", "case IA64_CR_LRR1:",
        "UINT64_C(0x1a7ff)",
    ):
        require(token in normalized_values,
                "named CR ignored-field contract lost " + token)
    validator = section(
        system,
        "static uint64_t ia64_system_validate_cr_access",
        "static void ia64_system_validate_cr_legality",
    )
    require(validator.index("ia64_system_reserved_cr_value") <
            validator.index("ia64_system_normalize_cr_value"),
            "reserved CR fields must fault before ignored fields normalize")


def check_performance_monitor_contract(root: Path) -> None:
    cpu = (root / "target/ia64/cpu.h").read_text(encoding="utf-8")
    pmu = (root / "target/ia64/pmu.c").read_text(encoding="utf-8")
    system = (root / "target/ia64/system-plane.c").read_text(
        encoding="utf-8"
    )
    firmware = (root / "hw/ia64/firmware.c").read_text(encoding="utf-8")
    for token in (
        "#define IA64_PMU_GENERIC_FIRST 4",
        "#define IA64_PMU_GENERIC_COUNT 4",
        "#define IA64_PMU_COUNTER_WIDTH 60",
    ):
        require(token in cpu, "PMU product profile lost " + token)
    for token in (
        "#define IA64_PMC0_WRITABLE_MASK UINT64_C(0x00000000000000f1)",
        "#define IA64_GENERIC_PMC_WRITABLE_MASK UINT64_C(0x000000000000ff7f)",
        "bool ia64_pmu_pmc_implemented(unsigned index)",
        "bool ia64_pmu_pmd_implemented(unsigned index)",
        "return index < IA64_PMU_GENERIC_FIRST + IA64_PMU_GENERIC_COUNT;",
        "index >= IA64_PMU_GENERIC_FIRST &&",
    ):
        require(token in pmu, "PMU product contract lost " + token)
    for token in (
        "env->pmc[index] = value & ia64_pmu_pmc_writable_mask(index);",
        "env->pmd[index] = value & ia64_pmu_pmd_writable_mask(index);",
    ):
        require(token in system, "PMU selector contract lost " + token)
    pal = section(
        firmware,
        "static IA64FirmwareResult pal_performance_monitor_info(",
        "static IA64FirmwareResult dispatch_pal(",
    )
    for token in (
        "uint8_t masks[128] = { 0 }",
        "buffer == 0 || (buffer & 7) != 0",
        "ia64_pmu_pmc_implemented(index)",
        "ia64_pmu_pmd_implemented(index)",
        "masks[0x20 + index / 8]",
        "firmware_guest_write_bytes(env, buffer, masks, sizeof(masks))",
        "IA64_PMU_GENERIC_COUNT",
        "IA64_PMU_COUNTER_WIDTH << 8",
    ):
        require(token in pal, "PAL PMU discovery contract lost " + token)
    require("masks[0x40" not in pal and "masks[0x60" not in pal,
            "PAL must not advertise unimplemented PMU event counting")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    args = parser.parse_args()
    root = args.source_root.resolve()

    check_variant_matrix()
    check_control_register_partition(root)
    check_performance_monitor_contract(root)
    check_inventory(root)
    check_traits(root)
    check_translate(root)
    check_translation_insert_ic_legality(root)
    check_vhpt_backing_debug_abort(root)
    check_vhpt_advertised_default(root)
    check_application_register_plane(root)
    print("IA-64 system/control direct-TCG gate passed: 57/57 rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
