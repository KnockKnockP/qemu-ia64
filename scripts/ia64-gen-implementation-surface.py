#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate the implementation-derived IA-64 conformance surface foundation.

The output is deliberately not a normative catalogue.  It records what the
current source and selected build expose, together with provenance and honest
coverage limits for the foundation checkpoint.
"""

from __future__ import annotations

import argparse
from collections import Counter
import csv
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import time
from types import ModuleType
from typing import Any, Sequence


SCHEMA = "vibtanium.ia64.implementation-surface"
SCHEMA_VERSION = 2
MACHINE = "vibtanium"
MACHINE_TYPE = "vibtanium-machine"
QMP_TIMEOUT = 10.0

REGISTER_BANKS = (
    ("gr", "IA64_GR_COUNT", "gr", "instruction-register-field",
     "target/ia64/translate.c",
     "static IA64TrGrWrite *ia64_tr_group_prepare_gr("),
    ("fr", "IA64_FR_COUNT", "fr", "instruction-register-field",
     "target/ia64/translate.c",
     "static void ia64_tr_group_prepare_fr("),
    ("pr", "IA64_PR_COUNT", "pr", "predicate-register-field",
     "target/ia64/translate.c",
     "static IA64TrPrWrite *ia64_tr_group_prepare_pr("),
    ("br", "IA64_BR_COUNT", "br", "branch-register-field",
     "target/ia64/translate.c",
     "static IA64TrBrWrite *ia64_tr_group_prepare_br("),
    ("ar", "IA64_AR_COUNT", "ar", "application-register-selector",
     "target/ia64/system-plane.c",
     "uint64_t HELPER(application_register_read)("),
    ("cr", "IA64_CR_COUNT", "cr", "control-register-selector",
     "target/ia64/insn.c", "uint64_t ia64_read_control_register("),
    ("rr", "IA64_RR_COUNT", "rr", "virtual-region-selector",
     "target/ia64/system-plane.c", "case IA64_OP_MOV_RRGR:"),
    ("pkr", "IA64_PKR_COUNT", "pkr", "indexed-register-selector",
     "target/ia64/system-plane.c", "case IA64_OP_MOV_PKRGR_INDEXED:"),
    ("dbr", "IA64_DBR_COUNT", "dbr", "indexed-register-selector",
     "target/ia64/system-plane.c", "case IA64_OP_MOV_DBRGR_INDEXED:"),
    ("ibr", "IA64_IBR_COUNT", "ibr", "indexed-register-selector",
     "target/ia64/system-plane.c", "case IA64_OP_MOV_IBRGR_INDEXED:"),
    ("cpuid", "IA64_CPUID_COUNT", "cpuid", "indexed-register-selector",
     "target/ia64/system-plane.c", "case IA64_OP_MOV_CPUID_INDEXED:"),
    ("dahr", "IA64_DAHR_COUNT", "dahr", "indexed-register-selector",
     "target/ia64/system-plane.c", "case IA64_OP_MOV_DAHRGR_INDEXED:"),
    ("msr", "IA64_MSR_COUNT", "msr", "model-specific-selector",
     "target/ia64/system-plane.c", "case IA64_OP_MOV_MSRGR:"),
    ("itr", "IA64_ITR_COUNT", "itr", "translation-register-slot",
     "target/ia64/system-plane.c", "env->itr[slot] = translation;"),
    ("dtr", "IA64_DTR_COUNT", "dtr", "translation-register-slot",
     "target/ia64/system-plane.c", "env->dtr[slot] = translation;"),
    ("pmc", "IA64_PMC_COUNT", "pmc", "indexed-register-selector",
     "target/ia64/system-plane.c", "case IA64_OP_MOV_PMCGR_INDEXED:"),
    ("pmd", "IA64_PMD_COUNT", "pmd", "indexed-register-selector",
     "target/ia64/system-plane.c", "case IA64_OP_MOV_PMDGR_INDEXED:"),
)
SCALAR_REGISTERS = (
    ("ip", "instruction-pointer-state", "target/ia64/system-plane.c",
     "case IA64_OP_MOV_CURRENT_IP:"),
    ("psr", "processor-status-state", "target/ia64/system-plane.c",
     "case IA64_OP_MOV_PSRGR:"),
    ("cfm", "current-frame-state", "target/ia64/insn.c",
     "void ia64_assign_cfm("),
)
BUILD_FEATURES = (
    "CONFIG_TCG",
    "CONFIG_PLUGIN",
    "CONFIG_VIBTANIUM",
    "CONFIG_VIBTANIUM_BIT",
    "CONFIG_IA64_OBSERVABILITY",
)


class SurfaceError(RuntimeError):
    pass


ARCHITECTURAL_SURFACES = (
    (
        "cpu.mmu.translation-install",
        "cpu.mmu",
        "ITR/DTR/ITC/DTC construction and same-stream overlap handling",
        "target/ia64/mem.c",
        "bool ia64_install_translation(",
    ),
    (
        "cpu.mmu.translation-lookup",
        "cpu.mmu",
        "fully associative ITR/DTR and dynamic translation lookup",
        "target/ia64/mem.c",
        "static const IA64TranslationEntry *ia64_lookup_translation(",
    ),
    (
        "cpu.mmu.translation-register-purge",
        "cpu.mmu",
        "PTR same-stream translation-register and cache purge",
        "target/ia64/mem.c",
        "void ia64_purge_translation_register(",
    ),
    (
        "cpu.alat.reset",
        "cpu.speculation",
        "ALAT persistent and transient reset state",
        "target/ia64/insn.c",
        "void ia64_cpu_reset_synthetic_itanium2(CPUIA64State *env)",
    ),
    (
        "cpu.alat.vmstate",
        "cpu.speculation",
        "ALAT migration persistence and incoming-state validation",
        "target/ia64/machine.c",
        "static const VMStateDescription vmstate_alat =",
    ),
    (
        "platform.reset.vibtanium",
        "platform.reset",
        "Vibtanium machine reset dispatch and CPU/device restart",
        "hw/ia64/vibtanium.c",
        "static void vibtanium_reset(MachineState *machine, ResetType type)",
    ),
    (
        "platform.firmware.pal-debug-info",
        "platform.firmware",
        "PAL debug-register pair discovery and argument validation",
        "hw/ia64/firmware.c",
        "static IA64FirmwareResult pal_debug_info(",
    ),
    (
        "platform.firmware.pal-perf-mon-info",
        "platform.firmware",
        "PAL performance-monitor metadata and implementation masks",
        "hw/ia64/firmware.c",
        "static IA64FirmwareResult pal_performance_monitor_info(",
    ),
    (
        "platform.firmware.pal-vm-summary",
        "platform.firmware",
        "PAL virtual-memory profile and register maximum indices",
        "hw/ia64/firmware.c",
        "static IA64FirmwareResult pal_vm_summary(",
    ),
    (
        "platform.firmware.pal-vm-page-size",
        "platform.firmware",
        "PAL insertable and purgeable virtual-memory page-size profile",
        "hw/ia64/firmware.c",
        "static IA64FirmwareResult pal_vm_page_size(",
    ),
    (
        "cpu.bundle.format",
        "cpu.bundle",
        "128-bit bundle field extraction",
        "target/ia64/bundle.c",
        "decoded->slot[0] = (lo >> 5) & IA64_SLOT_MASK",
    ),
    (
        "cpu.bundle.template-map",
        "cpu.bundle",
        "defined template unit and stop map",
        "target/ia64/bundle.c",
        "ia64_template_table[32]",
    ),
    (
        "cpu.bundle.template-equivalence", "cpu.bundle",
        "complete defined-template execution equivalence",
        "target/ia64/bundle.c", "ia64_template_table[32]",
    ),
    (
        "cpu.bundle.long-immediate", "cpu.bundle",
        "logical L+X immediate construction",
        "target/ia64/translate.c", "IA64_OP_MOVL",
    ),
    (
        "cpu.bundle.legality", "cpu.bundle",
        "reserved-template and invalid MLX restart handling",
        "target/ia64/translate.c", "ia64_tr_emit_invalid_mlx_restart",
    ),
    (
        "cpu.bundle.field-semantics", "cpu.bundle",
        "ignored and reserved instruction-field behavior",
        "target/ia64/translate.c", "ia64_tr_emit_decoded_illegal_operation",
    ),
    (
        "cpu.bundle.ip-ri", "cpu.bundle",
        "IP and RI transition publication",
        "target/ia64/translate.c", "ia64_tr_publish_fault_state",
    ),
    (
        "cpu.bundle.ri-resume", "cpu.bundle",
        "architectural RI entry and suffix resume",
        "target/ia64/translate.c", "ia64_tcg_tb_flags_ri",
    ),
    (
        "cpu.bundle.boundaries", "cpu.bundle",
        "translation-block and page-boundary equivalence",
        "target/ia64/translate.c", "ia64_tr_preflight_rewrite_region",
    ),
    (
        "cpu.sequencing.sequential-order",
        "cpu.sequencing",
        "bundle and slot execution order",
        "target/ia64/translate.c",
        "ia64_tr_try_decoded_bundle",
    ),
    (
        "cpu.issue-group.stop-visibility",
        "cpu.issue-group",
        "architectural stop visibility",
        "target/ia64/translate.c",
        "decoded.ends_at_group_boundary",
    ),
    (
        "cpu.issue-group.entry-register",
        "cpu.issue-group",
        "instruction-group entry register image",
        "target/ia64/translate.c",
        "ia64_tr_store_source_visibility_state",
    ),
    (
        "cpu.issue-group.fault-commitment",
        "cpu.issue-group",
        "precise committed prefix publication",
        "target/ia64/translate.c",
        "ia64_tr_group_publish_prefix_for_noreturn_fault",
    ),
    (
        "cpu.integer.arithmetic", "cpu.integer",
        "scalar add, subtract, immediate, carry/borrow, and shifted-add forms",
        "target/ia64/translate.c", "case IA64_OP_ADD_ONE:",
    ),
    (
        "cpu.integer.logical", "cpu.integer",
        "scalar logical, complement, immediate, and constant construction",
        "target/ia64/translate.c", "case IA64_OP_ANDCM_IMM:",
    ),
    (
        "cpu.integer.multiply-gr", "cpu.integer",
        "GR-based 32-bit multiply and shifted-high multiply",
        "target/ia64/translate.c", "case IA64_OP_MPYSHL4:",
    ),
    (
        "cpu.integer.multiply-xma", "cpu.integer",
        "FR-based integer multiply-add low and high forms",
        "target/ia64/translate.c", "case IA64_OP_XMA_HU:",
    ),
    (
        "cpu.integer.bitfield-shift", "cpu.integer",
        "scalar variable shifts, funnel shift, extract, deposit, and extension",
        "target/ia64/translate.c", "case IA64_OP_SHRP_IMM:",
    ),
    (
        "cpu.integer.character-bit", "cpu.integer",
        "population, leading-zero, mux, and zero-index character operations",
        "target/ia64/translate.c", "tcg_gen_ctpop_i64",
    ),
    (
        "cpu.integer.legality", "cpu.integer",
        "scalar predication, NaT, alias, slot, reserved-field, and fault behavior",
        "target/ia64/translate.c", "ia64_tr_emit_decoded_illegal_operation",
    ),
    (
        "cpu.integer.generated-domain", "cpu.integer",
        "complete current scalar domain and ordinary source/NaT selection",
        "target/ia64/translate.c", "source_count = ia64_tr_decoded_sources",
    ),
    (
        "cpu.memory.code-invalidation",
        "cpu.memory",
        "translated-code invalidation after an architectural store",
        "target/ia64/translate.c",
        "tcg_gen_qemu_st_i64",
    ),
    (
        "cpu.memory.ram-tb-equivalence",
        "cpu.memory",
        "ordinary RAM architectural TB-boundary equivalence",
        "target/ia64/translate.c",
        "tcg_gen_qemu_ld_i64",
    ),
    (
        "cpu.memory.update-safepoint",
        "cpu.memory",
        "memory base-update safepoint",
        "target/ia64/translate.c",
        "memory_safepoint_valid",
    ),
    (
        "cpu.memory.fault-commitment",
        "cpu.memory",
        "faulting memory operation commitment",
        "target/ia64/translate.c",
        "ia64_tr_group_publish_prefix_for_noreturn_fault",
    ),
    (
        "cpu.memory.mmio-exactly-once",
        "cpu.memory",
        "MMIO retry without architectural replay",
        "target/ia64/translate.c",
        "memory_restart_complex",
    ),
    (
        "cpu.packed.lane-widths", "cpu.packed",
        "packed 8-bit, 16-bit, and 32-bit lane execution",
        "target/ia64/translate.c", "ia64_tr_packed_extract_lane",
    ),
    (
        "cpu.packed.saturation", "cpu.packed",
        "packed signed and unsigned saturation",
        "target/ia64/translate.c", "ia64_tr_packed_saturate_signed",
    ),
    (
        "cpu.packed.comparisons", "cpu.packed",
        "packed equality and signed greater-than comparisons",
        "target/ia64/translate.c", "IA64_TR_PACKED_CMP_EQ",
    ),
    (
        "cpu.packed.arrangement", "cpu.packed",
        "packed mix, mux, pack, unpack, average, sum, and SAD forms",
        "target/ia64/translate.c", "ia64_tr_packed_mux1_lane",
    ),
    (
        "cpu.packed.shifts", "cpu.packed",
        "packed fixed and variable shift boundaries",
        "target/ia64/translate.c", "IA64_TR_PACKED_SHR_U",
    ),
    (
        "cpu.packed.legality", "cpu.packed",
        "packed predication, alias, NaT, reserved-field, and slot admission",
        "target/ia64/translate.c", "ia64_tr_decoded_is_supported_packed",
    ),
    (
        "cpu.predicate.compare-relations", "cpu.predicate",
        "signed, unsigned, and equality predicate comparisons",
        "target/ia64/translate.c", "ia64_tr_compare_cond",
    ),
    (
        "cpu.predicate.update-completers", "cpu.predicate",
        "normal, unconditional, and parallel predicate updates",
        "target/ia64/translate.c", "ia64_tr_emit_decoded_integer_compare",
    ),
    (
        "cpu.predicate.alias", "cpu.predicate",
        "paired predicate target alias semantics",
        "target/ia64/translate.c", "ia64_tr_write_pr_bool",
    ),
    (
        "cpu.predicate.nat", "cpu.predicate",
        "NaT integer comparison semantics",
        "target/ia64/translate.c", "ia64_tr_emit_decoded_integer_compare",
    ),
    (
        "cpu.predicate.group-producers", "cpu.predicate",
        "same-group predicate producer and consumer visibility",
        "target/ia64/translate.c",
        "ia64_tr_group_update_branch_forward_predicate",
    ),
    (
        "cpu.predicate.rotation", "cpu.predicate",
        "rotating predicate register transfer and rename semantics",
        "target/ia64/translate.c", "ia64_tr_emit_decoded_pr_move",
    ),
    (
        "cpu.predicate.tests", "cpu.predicate",
        "test-bit, test-NaT, and test-feature predicate production",
        "target/ia64/translate.c", "ia64_tr_emit_decoded_predicate_test",
    ),
    (
        "cpu.register.rotation.gr", "cpu.register",
        "general-register rotating-region rename semantics",
        "target/ia64/insn.c", "env->rse.rrb_gr =",
    ),
    (
        "cpu.register.rotation.fr", "cpu.register",
        "floating-register rotating-region rename semantics",
        "target/ia64/insn.c", "env->rse.rrb_fr =",
    ),
    (
        "cpu.register.rotation.pr", "cpu.register",
        "predicate-register rotating-region rename semantics",
        "target/ia64/insn.c", "env->rse.rrb_pr =",
    ),
    (
        "cpu.register.gr.bank-switch", "cpu.register",
        "interruption, RFI, and explicit GR16-GR31 bank selection",
        "target/ia64/exception.c", "ia64_psr_for_interruption_delivery",
    ),
    (
        "cpu.branch.forms", "cpu.branch",
        "direct, indirect, long, conditional, and loop branch forms",
        "target/ia64/translate.c", "ia64_tr_emit_decoded_branch_split",
    ),
    (
        "cpu.branch.outcomes", "cpu.branch",
        "taken, not-taken, and first-taken branch outcomes",
        "target/ia64/translate.c", "ia64_tr_emit_decoded_branch_cfg_exits",
    ),
    (
        "cpu.branch.displacement", "cpu.branch",
        "signed IP-relative and long branch target construction",
        "target/ia64/translate.c", "ia64_tr_emit_typed_direct_branch_exit",
    ),
    (
        "cpu.branch.register-target", "cpu.branch",
        "branch-register target selection and alignment",
        "target/ia64/translate.c", "ia64_tr_emit_typed_indirect_branch_exit",
    ),
    (
        "cpu.branch.loop-state", "cpu.branch",
        "loop count, epilog count, and rotating-register transitions",
        "target/ia64/translate.c", "ia64_tr_emit_decoded_loop_branch_split",
    ),
    (
        "cpu.branch.traps", "cpu.branch",
        "taken-branch and lower-privilege trap delivery",
        "target/ia64/translate.c", "gen_helper_raise_taken_branch_trap",
    ),
    (
        "cpu.branch.boundaries", "cpu.branch",
        "branch execution across slot, page, helper, and TB boundaries",
        "target/ia64/translate.c",
        "ia64_tr_split_state_cache_at_typed_branch",
    ),
)


def relative(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return "@build/" + path.name


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SurfaceError(f"cannot load generator module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def generated_opcode_rows(root: Path) -> list[dict[str, str]]:
    script = root / "scripts/ia64-gen-opcode-ledger.py"
    generator = load_module(script, "_ia64_opcode_ledger_generator")
    enum_path = root / "target/ia64/decode.h"
    traits_path = root / "target/ia64/opcode-traits.def"
    families_path = root / "target/ia64/opcode-families.def"
    names = generator.opcode_enum(enum_path)
    traits = generator.opcode_rows(traits_path)
    families = generator.family_rows(families_path)
    generator.verify_sources(
        names,
        traits,
        families,
        root / "target/ia64/decode.c",
        root / "target/ia64/translate.c",
    )
    text = generator.make_ledger(names, traits, families)
    rows = list(csv.DictReader(io.StringIO(text)))
    if len(rows) != len(names):
        raise SurfaceError("generated opcode ledger row count drifted")
    return rows


def parse_integer_defines(text: str) -> dict[str, int]:
    return {
        name: int(value, 0)
        for name, value in re.findall(
            r"^#define\s+(IA64_[A-Z0-9_]+)\s+(0x[0-9a-fA-F]+|[0-9]+)\s*$",
            text,
            re.MULTILINE,
        )
    }


def parse_named_registers(text: str) -> dict[tuple[str, int], str]:
    result: dict[tuple[str, int], str] = {}
    for bank, enum_name, prefix in (
        ("ar", "IA64ApplicationRegister", "IA64_AR_"),
        ("cr", "IA64ControlRegister", "IA64_CR_"),
    ):
        match = re.search(
            rf"enum\s+{enum_name}\s*\{{(.*?)\}};", text, re.DOTALL
        )
        if match is None:
            raise SurfaceError(f"missing {enum_name} declaration")
        for name, value in re.findall(
            rf"\b({prefix}[A-Z0-9_]+)\s*=\s*(0x[0-9a-fA-F]+|[0-9]+)",
            match.group(1),
        ):
            result[(bank, int(value, 0))] = name
    return result


def require_source_anchor(root: Path, path_text: str, anchor: str) -> None:
    path = root / path_text
    if anchor not in path.read_text(encoding="utf-8"):
        raise SurfaceError(
            f"register reachability anchor disappeared: {path_text}: "
            f"{anchor}"
        )


def register_rows(root: Path) -> list[dict[str, Any]]:
    cpu_h = root / "target/ia64/cpu.h"
    text = cpu_h.read_text(encoding="utf-8")
    defines = parse_integer_defines(text)
    aliases = parse_named_registers(text)
    pmu_first = defines["IA64_PMU_GENERIC_FIRST"]
    pmu_count = defines["IA64_PMU_GENERIC_COUNT"]
    rows: list[dict[str, Any]] = []
    for (bank, count_name, storage, access_class,
         access_path, access_anchor) in REGISTER_BANKS:
        if count_name not in defines:
            raise SurfaceError(f"missing register count {count_name}")
        count = defines[count_name]
        if not re.search(
            rf"\b(?:uint64_t|IA64FloatReg)\s+{storage}\s*"
            rf"(?:\[{re.escape(count_name)}\]|;)",
            text,
        ):
            raise SurfaceError(f"register storage {storage!r} is not declared")
        require_source_anchor(root, access_path, access_anchor)
        for index in range(count):
            status = "live"
            field_behavior = "not-yet-classified"
            if bank == "pmc":
                implemented = index < pmu_first + pmu_count
                status = "live" if implemented else "known-unimplemented"
                field_behavior = (
                    "architected-minimum-pmu" if implemented else
                    "unimplemented-zero-read-ignore-write"
                )
            elif bank == "pmd":
                implemented = pmu_first <= index < pmu_first + pmu_count
                status = "live" if implemented else "known-unimplemented"
                field_behavior = (
                    "architected-minimum-generic-counter" if implemented else
                    "unimplemented-zero-read-ignore-write"
                )
            attributes: dict[str, Any] = {
                "bank": bank,
                "index": index,
                "count_constant": count_name,
                "storage": storage,
                "guest_reachability": "guest-selectable",
                "access_class": access_class,
                "coverage_group": f"cpu.register.{bank}.all-indices",
                "selector_domain": {
                    "first": 0,
                    "last": count - 1,
                    "cardinality": count,
                },
                "field_behavior": field_behavior,
            }
            if (bank, index) in aliases:
                attributes["named_alias"] = aliases[(bank, index)]
            rows.append({
                "id": f"cpu.register.{bank}.{index}",
                "kind": "cpu.register",
                "name": f"{bank}{index}",
                "status": status,
                "attributes": attributes,
                "provenance": [
                    {
                        "path": relative(cpu_h, root),
                        "anchor": count_name,
                    },
                    {"path": access_path, "anchor": access_anchor},
                ],
            })
    for name, access_class, access_path, access_anchor in SCALAR_REGISTERS:
        if re.search(rf"\buint64_t\s+{name}\s*;", text) is None:
            raise SurfaceError(f"missing scalar architectural storage {name}")
        require_source_anchor(root, access_path, access_anchor)
        rows.append({
            "id": f"cpu.register.scalar.{name}",
            "kind": "cpu.register",
            "name": name,
            "status": "live",
            "attributes": {
                "bank": "scalar",
                "guest_reachability": "architectural-state",
                "access_class": access_class,
                "coverage_group": f"cpu.register.scalar.{name}",
                "field_behavior": "not-yet-classified",
            },
            "provenance": [
                {
                    "path": relative(cpu_h, root),
                    "anchor": f"uint64_t {name}",
                },
                {"path": access_path, "anchor": access_anchor},
            ],
        })
    return rows


def architectural_surface_rows(root: Path) -> list[dict[str, Any]]:
    """Inventory explicitly catalogued architectural surfaces.

    These rows remain implementation-derived: every row is admitted only when
    its named source anchor exists.  Normative meaning stays in the separate
    catalogue and is never inferred from these source names.
    """
    rows = []
    for identifier, kind, name, path_text, anchor in ARCHITECTURAL_SURFACES:
        path = root / path_text
        source = path.read_text(encoding="utf-8")
        if anchor not in source:
            raise SurfaceError(
                f"architectural surface anchor disappeared: {path_text}: "
                f"{anchor}"
            )
        rows.append({
            "id": identifier,
            "kind": kind,
            "name": name,
            "status": "live",
            "attributes": {
                "classification": "catalogued-architectural-surface",
                "guest_reachability": "reachable",
            },
            "provenance": [{"path": path_text, "anchor": anchor}],
        })
    return rows


def opcode_surface_rows(root: Path) -> list[dict[str, Any]]:
    provenance = [
        {"path": "target/ia64/decode.h", "anchor": "IA64Opcode"},
        {"path": "target/ia64/opcode-traits.def", "anchor": "IA64_OPCODE"},
        {
            "path": "target/ia64/opcode-families.def",
            "anchor": "IA64_OPCODE_FAMILY",
        },
    ]
    result = []
    for ledger in generated_opcode_rows(root):
        attributes: dict[str, Any] = dict(ledger)
        attributes["ordinal"] = int(attributes["ordinal"])
        result.append({
            "id": f"cpu.opcode.{ledger['opcode'].lower()}",
            "kind": "cpu.opcode",
            "name": ledger["opcode"],
            "status": ledger["decoder_status"],
            "attributes": attributes,
            "provenance": provenance,
        })
    return result


def config_features(
    build_dir: Path, root: Path
) -> tuple[dict[str, bool], list[str]]:
    candidates = (
        build_dir / "config-host.h",
        build_dir / "ia64-softmmu-config-target.h",
        build_dir / "ia64-softmmu-config-devices.h",
    )
    texts: list[tuple[Path, str]] = []
    for path in candidates:
        if not path.is_file():
            raise SurfaceError(f"missing configured build input: {path}")
        texts.append((path, path.read_text(encoding="utf-8")))
    features: dict[str, bool] = {}
    sources: list[str] = []
    for name in BUILD_FEATURES:
        states: list[bool] = []
        for path, text in texts:
            if re.search(rf"^#define\s+{re.escape(name)}(?:\s+1)?\s*$", text,
                         re.MULTILINE):
                states.append(True)
                sources.append(relative(path, root))
            elif re.search(rf"^#undef\s+{re.escape(name)}\s*$", text,
                           re.MULTILINE):
                states.append(False)
                sources.append(relative(path, root))
        if not states:
            features[name] = False
        elif any(state != states[0] for state in states):
            raise SurfaceError(f"conflicting configured values for {name}")
        else:
            features[name] = states[0]
    return features, sorted(set(sources))


def free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def child_environment(binary: Path) -> dict[str, str]:
    environment = os.environ.copy()
    runtime = str(binary.parent)
    environment["PATH"] = runtime + os.pathsep + environment.get("PATH", "")
    return environment


class QMPClient:
    def __init__(self, stream: socket.socket):
        self.stream = stream
        self.reader = stream.makefile("rb")
        self.next_id = 1

    def read(self) -> dict[str, Any]:
        line = self.reader.readline()
        if not line:
            raise SurfaceError("QMP connection closed unexpectedly")
        return json.loads(line.decode("utf-8"))

    def execute(self, command: str,
                arguments: dict[str, Any] | None = None) -> Any:
        identifier = self.next_id
        self.next_id += 1
        request: dict[str, Any] = {"execute": command, "id": identifier}
        if arguments is not None:
            request["arguments"] = arguments
        self.stream.sendall(json.dumps(request).encode("utf-8") + b"\n")
        while True:
            response = self.read()
            if response.get("id") != identifier:
                continue
            if "error" in response:
                raise SurfaceError(
                    f"QMP {command} failed: "
                    f"{response['error'].get('desc', response['error'])}"
                )
            return response.get("return")

    def close(self) -> None:
        self.reader.close()
        self.stream.close()


def connect_qmp(process: subprocess.Popen[str], port: int) -> socket.socket:
    deadline = time.monotonic() + QMP_TIMEOUT
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout else ""
            raise SurfaceError(
                f"QEMU exited before QMP became available: {output.strip()}"
            )
        try:
            stream = socket.create_connection(("127.0.0.1", port), timeout=0.2)
            stream.settimeout(QMP_TIMEOUT)
            return stream
        except OSError as exc:
            last_error = exc
            time.sleep(0.025)
    raise SurfaceError(f"timed out connecting to QMP: {last_error}")


def runtime_machine_surface(binary: Path,
                            property_names: Sequence[str]) -> tuple[
                                dict[str, Any], dict[str, dict[str, Any]],
                                dict[str, Any]]:
    port = free_tcp_port()
    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    command = [
        str(binary), "-S", "-display", "none", "-serial", "none",
        "-monitor", "none", "-machine",
        f"{MACHINE},efi-boot-manager=off", "-qmp",
        f"tcp:127.0.0.1:{port},server=on,wait=off",
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=child_environment(binary),
        creationflags=creationflags,
    )
    stream: socket.socket | None = None
    client: QMPClient | None = None
    try:
        stream = connect_qmp(process, port)
        client = QMPClient(stream)
        greeting = client.read()
        if "QMP" not in greeting:
            raise SurfaceError("QMP greeting is malformed")
        client.execute("qmp_capabilities")
        machines = client.execute("query-machines")
        machine = next(
            (entry for entry in machines if entry.get("name") == MACHINE), None
        )
        if machine is None:
            raise SurfaceError("built emulator does not expose vibtanium")
        properties = client.execute(
            "qom-list-properties", {"typename": MACHINE_TYPE}
        )
        metadata = {entry["name"]: entry for entry in properties}
        missing = sorted(set(property_names) - set(metadata))
        if missing:
            raise SurfaceError(
                "built machine lacks source-declared properties: "
                + ", ".join(missing)
            )
        defaults = {}
        for name in property_names:
            if name == "efi-boot-manager":
                continue
            defaults[name] = client.execute(
                "qom-get", {"path": "/machine", "property": name}
            )
        client.execute("quit")
        version = greeting["QMP"]["version"]
        return machine, metadata, {"defaults": defaults, "version": version}
    finally:
        if client is not None:
            try:
                client.close()
            except OSError:
                pass
        elif stream is not None:
            stream.close()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


def source_qom_properties(source: str) -> dict[str, str]:
    result = {
        name: kind
        for kind, name in re.findall(
            r"object_class_property_add_(bool|str)\s*\(oc,\s*\"([^\"]+)\"",
            source,
        )
    }
    all_names = set(re.findall(
        r"object_class_property_add(?:_[a-z0-9_]+)?\s*"
        r"\(oc,\s*\"([^\"]+)\"",
        source,
    ))
    unsupported = sorted(all_names - set(result))
    if unsupported:
        raise SurfaceError(
            "unclassified Vibtanium QOM property constructors: "
            + ", ".join(unsupported)
        )
    if not result:
        raise SurfaceError("no Vibtanium-owned QOM properties were found")
    return result


def source_machine_defaults(source: str, internal: str) -> dict[str, Any]:
    def string_assignment(field: str) -> str:
        match = re.search(rf"mc->{field}\s*=\s*\"([^\"]+)\"", source)
        if match is None:
            raise SurfaceError(f"missing MachineClass assignment {field}")
        return match.group(1)

    def integer_assignment(field: str) -> int:
        match = re.search(rf"mc->{field}\s*=\s*([0-9]+)\s*;", source)
        if match is None:
            raise SurfaceError(f"missing MachineClass assignment {field}")
        return int(match.group(1))

    ram = re.search(r"mc->default_ram_size\s*=\s*([0-9]+)\s*\*\s*GiB", source)
    policy = re.search(
        r'#define\s+VIBTANIUM_EFI_BOOT_MANAGER_DEFAULT\s+"([^"]+)"',
        internal,
    )
    if ram is None or policy is None:
        raise SurfaceError("missing Vibtanium RAM or boot-manager default")
    return {
        "max_cpus": integer_assignment("max_cpus"),
        "default_ram_size": int(ram.group(1)) * 1024 ** 3,
        "default_ram_id": string_assignment("default_ram_id"),
        "default_nic": string_assignment("default_nic"),
        "default_display": string_assignment("default_display"),
        "efi_boot_manager": policy.group(1),
    }


def platform_rows(
    root: Path, binary: Path
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    source_path = root / "hw/ia64/vibtanium.c"
    internal_path = root / "hw/ia64/vibtanium-internal.h"
    source = source_path.read_text(encoding="utf-8")
    internal = internal_path.read_text(encoding="utf-8")
    property_kinds = source_qom_properties(source)
    source_defaults = source_machine_defaults(source, internal)
    machine, metadata, runtime = runtime_machine_surface(
        binary, sorted(property_kinds)
    )
    defaults = runtime["defaults"]
    defaults["efi-boot-manager"] = source_defaults["efi_boot_manager"]
    rows: list[dict[str, Any]] = [{
        "id": "platform.machine.vibtanium",
        "kind": "platform.machine",
        "name": MACHINE,
        "status": "runtime-exposed",
        "attributes": {
            "runtime": machine,
            "source_defaults": {
                key: value for key, value in source_defaults.items()
                if key != "efi_boot_manager"
            },
        },
        "provenance": [{
            "path": relative(source_path, root),
            "anchor": "vibtanium_machine_class_init",
        }],
    }]
    for name in sorted(property_kinds):
        item = metadata[name]
        attributes = {
            "type": item.get("type"),
            "description": item.get("description"),
            "default": defaults[name],
            "default_origin": (
                "source-constant" if name == "efi-boot-manager"
                else "runtime-qom-get"
            ),
            "source_property_kind": property_kinds[name],
        }
        rows.append({
            "id": f"platform.qom.machine.vibtanium.{name}",
            "kind": "platform.qom-property",
            "name": name,
            "status": "runtime-exposed",
            "attributes": attributes,
            "provenance": [{
                "path": relative(source_path, root),
                "anchor": (
                    f"object_class_property_add_{property_kinds[name]}"
                    f'(oc, "{name}"'
                ),
            }],
        })
    return rows, runtime["version"]


def build_surface(root: Path, build_dir: Path, binary: Path) -> dict[str, Any]:
    if not binary.is_file():
        raise SurfaceError(f"IA-64 emulator not found: {binary}")
    features, feature_sources = config_features(build_dir, root)
    rows = opcode_surface_rows(root)
    rows.extend(register_rows(root))
    rows.extend(architectural_surface_rows(root))
    platform, version = platform_rows(root, binary)
    rows.extend(platform)
    rows.sort(key=lambda row: row["id"])
    identifiers = [row["id"] for row in rows]
    if len(set(identifiers)) != len(identifiers):
        raise SurfaceError("implementation-surface row IDs are not unique")
    counts = Counter(row["kind"] for row in rows)
    return {
        "schema": SCHEMA,
        "schema_version": SCHEMA_VERSION,
        "implementation_derived": True,
        "normative_oracle": False,
        "profiles": ["vibtanium-strict-up", "vibtanium-default-up"],
        "coverage": {
            "included": [
                {
                    "domain": "cpu.opcode",
                    "completeness": "current-ledger-complete",
                },
                {
                    "domain": "cpu.register",
                    "completeness": "guest-selectable-index-complete",
                },
                {
                    "domain": "cpu.bundle",
                    "completeness": "catalogued-domain-closure",
                },
                {
                    "domain": "cpu.issue-group",
                    "completeness": "first-architectural-tranche",
                },
                {
                    "domain": "cpu.integer",
                    "completeness": "catalogued-semantic-tranche",
                },
                {
                    "domain": "cpu.sequencing",
                    "completeness": "first-architectural-tranche",
                },
                {
                    "domain": "cpu.memory",
                    "completeness": "catalogued-boundary-tranche",
                },
                {
                    "domain": "cpu.packed",
                    "completeness": "catalogued-semantic-tranche",
                },
                {
                    "domain": "cpu.predicate",
                    "completeness": "catalogued-semantic-tranche",
                },
                {
                    "domain": "cpu.branch",
                    "completeness": "catalogued-semantic-tranche",
                },
                {"domain": "platform.machine", "completeness": "foundation"},
                {
                    "domain": "platform.qom-property",
                    "completeness": "vibtanium-owned-complete",
                },
            ],
            "pending": [
                "opcode encoding masks, completers, units, and legal slots",
                "register access, masks, and reserved behavior",
                "CPUID values and feature declarations",
                "interruptions, MMU facilities, PAL, SAL, and EFI services",
                "ACPI tables, PCI functions, MMIO, sparse I/O, and inherited devices",
                "reset, power, VMState, observability modes, and compatibility hooks",
            ],
        },
        "build": {
            "target": "ia64-softmmu",
            "machine": MACHINE,
            "qemu_version": version,
            "features": features,
            "feature_provenance": feature_sources,
        },
        "summary": {
            "rows": len(rows),
            "by_kind": dict(sorted(counts.items())),
        },
        "rows": rows,
    }


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path,
        default=Path(__file__).resolve().parents[1],
        help="QEMU source root",
    )
    parser.add_argument(
        "--build-dir", type=Path, required=True,
        help="configured IA-64 QEMU build directory",
    )
    parser.add_argument(
        "--binary", type=Path,
        help="qemu-system-ia64 binary (defaults inside --build-dir)",
    )
    parser.add_argument("--output", type=Path, help="write JSON to this path")
    parser.add_argument(
        "--check", action="store_true",
        help="validate the inventory without emitting JSON",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    build_dir = args.build_dir.resolve()
    binary = (args.binary.resolve() if args.binary else
              build_dir / ("qemu-system-ia64.exe" if os.name == "nt"
                           else "qemu-system-ia64"))
    if args.check and args.output:
        raise SurfaceError("--check and --output are mutually exclusive")
    surface = build_surface(root, build_dir, binary)
    if args.check:
        counts = surface["summary"]["by_kind"]
        print(
            "IA-64 implementation surface verified: "
            f"{surface['summary']['rows']} rows; "
            + ", ".join(f"{kind}={count}" for kind, count in counts.items())
        )
        return 0
    encoded = json.dumps(surface, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding="utf-8")
    else:
        sys.stdout.write(encoded)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, SurfaceError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
