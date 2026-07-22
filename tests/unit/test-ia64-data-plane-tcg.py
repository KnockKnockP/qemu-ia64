#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""No-OS runtime gate for the remaining 63 IA-64 data-plane rows.

The two admission programs execute every primary encoding and every live
normalizing alias under a false predicate, which exercises decode, typed
admission, predicate placement, and direct-TCG trace rejection without
creating incidental memory faults.  Active literal-golden programs then cover
atomics, speculative spill/fill and 16-byte AR.CSD traffic, floating memory,
ALAT check loads, cache controls, and line-prefetch base updates.

Run without ``--qemu`` (or with ``--self-check``) to validate the independent
program inventory while the shared translator is being rewritten.
"""

from __future__ import annotations

import argparse
import dataclasses
import importlib.util
import json
from pathlib import Path
import sys
from typing import Callable, Dict, List, Optional, Sequence, Tuple


def _load_harness():
    path = Path(__file__).with_name("test-ia64-full-tcg.py")
    spec = importlib.util.spec_from_file_location(
        "_ia64_full_tcg_data_plane_harness", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load IA-64 full-TCG runtime harness")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


H = _load_harness()
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ia64_data_plane_tcg_spec import (  # noqa: E402
    ALIAS_ENCODINGS,
    DATA_PLANE_OPCODES,
    SPEC_BY_OPCODE,
    atomic,
    cache_control,
    chk_a,
    chk_s,
    floating_load,
    floating_store,
    integer_load,
    integer_spill,
    ld16,
    lfetch,
    primary_encoding,
    st16,
)


IA64_PSR_ED = 1 << 43
IA64_PSR_DFL = 1 << 18
IA64_PSR_AC = 1 << 3
IA64_PSR_PK = 1 << 15
IA64_PSR_DB = 1 << 24
IA64_PSR_IT = 1 << 36
IA64_ISR_NA = 1 << 35
IA64_ISR_SP = 1 << 36
IA64_ISR_ED = 1 << 43
IA64_ISR_CODE_DATA_NAT_PAGE_CONSUMPTION = 0x20
IA64_DISABLED_FP_VECTOR = 0x5500
IA64_VHPT_TRANSLATION_VECTOR = 0x0000
IA64_DATA_TLB_VECTOR = 0x0800
IA64_DATA_KEY_MISS_VECTOR = 0x1C00
IA64_DATA_ACCESS_BIT_VECTOR = 0x2800
IA64_PAGE_FAULT_VECTOR = 0x5000
IA64_KEY_PERMISSION_VECTOR = 0x5100
IA64_DATA_ACCESS_RIGHTS_VECTOR = 0x5300
IA64_DATA_NAT_PAGE_VECTOR = 0x5600
IA64_DATA_DEBUG_VECTOR = 0x5900
IA64_UNSUPPORTED_DATA_REFERENCE_VECTOR = 0x5B00
IA64_UNALIGNED_DATA_REFERENCE_VECTOR = 0x5A00
IA64_ILLEGAL_OPERATION_VECTOR = 0x5400
IA64_CR_DCR = 0
IA64_CR_PTA = 8
IA64_DCR_DM = 1 << 8
IA64_DCR_DP = 1 << 9
IA64_DCR_DK = 1 << 10
IA64_DCR_DX = 1 << 11
IA64_DCR_DR = 1 << 12
IA64_DCR_DA = 1 << 13
IA64_DCR_DD = 1 << 14

INTEGER_SPECULATIVE_NATPAGE_IMPLEMENTATION_ROWS = (
    "cpu.opcode.ia64_op_chk_a",
    "cpu.opcode.ia64_op_chk_s",
    "cpu.opcode.ia64_op_ld1s",
    "cpu.opcode.ia64_op_ld1sa",
    "cpu.opcode.ia64_op_ld2s",
    "cpu.opcode.ia64_op_ld2sa",
    "cpu.opcode.ia64_op_ld4s",
    "cpu.opcode.ia64_op_ld4sa",
    "cpu.opcode.ia64_op_ld8s",
    "cpu.opcode.ia64_op_ld8sa",
)

INTEGER_SPECULATIVE_LOAD_IMPLEMENTATION_ROWS = tuple(
    row for row in INTEGER_SPECULATIVE_NATPAGE_IMPLEMENTATION_ROWS
    if "_ld" in row
)

INTEGER_SPECULATION_SUCCESS_IMPLEMENTATION_ROWS = tuple(sorted((
    "cpu.opcode.ia64_op_chk_a",
    "cpu.opcode.ia64_op_chk_s",
    *("cpu.opcode.ia64_op_ld{}{}".format(width, suffix)
      for width in (1, 2, 4, 8)
      for suffix in ("a", "c_clr", "c_nc", "s", "sa")),
)))


def validate_contract(root: Path) -> str:
    path = root / "tests/ia64-conformance/speculation-semantic-tranche.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    if (document.get("schema") !=
            "vibtanium.ia64.speculation-semantic-tranche" or
            document.get("schema_version") != 1):
        raise AssertionError("speculation tranche schema/version drift")
    cases = document.get("cases")
    if not isinstance(cases, list) or len(cases) != 9:
        raise AssertionError("speculation tranche must contain nine atomic cases")
    by_row = {case.get("normative_row"): case for case in cases}
    if set(by_row) != {
            "ALT-001-INTEGER-ALWAYS-DEFER-PSR-IC",
            "ALT-001-INTEGER-NATPAGE-DEFERRAL",
            "ALT-001-INTEGER-SOFTWARE-DEFER-PSR-ED",
            "ALT-002-INTEGER-NO-RECOVERY-FAULTS",
            "ALT-002-INTEGER-NO-RECOVERY-PROTECTION",
            "ALT-002-INTEGER-NO-RECOVERY-VHPT",
            "ALT-001-INTEGER-RECOVERY-DCR-DM",
            "ALT-001-INTEGER-RECOVERY-DCR-PROTECTION-DEBUG",
            "ALT-003-INTEGER-NONFAULTING-SPECULATION-ATTRIBUTES"}:
        raise AssertionError("speculation tranche normative rows drifted")
    deferred = by_row["ALT-001-INTEGER-NATPAGE-DEFERRAL"]
    if deferred.get("implementation_rows") != list(
            INTEGER_SPECULATIVE_NATPAGE_IMPLEMENTATION_ROWS):
        raise AssertionError("NaTPage implementation rows drifted")
    if deferred.get("execution", {}).get("probes") != [
            "integer_speculative_nat_page_defer_case"]:
        raise AssertionError("NaTPage execution probe drifted")
    always_defer = by_row["ALT-001-INTEGER-ALWAYS-DEFER-PSR-IC"]
    if always_defer.get("implementation_rows") != list(
            INTEGER_SPECULATIVE_NATPAGE_IMPLEMENTATION_ROWS):
        raise AssertionError("PSR.ic=0 implementation rows drifted")
    if always_defer.get("execution", {}).get("probes") != [
            "integer_speculative_always_defer_case"]:
        raise AssertionError("PSR.ic=0 execution probe drifted")
    software_defer = by_row["ALT-001-INTEGER-SOFTWARE-DEFER-PSR-ED"]
    if software_defer.get("implementation_rows") != list(
            INTEGER_SPECULATIVE_NATPAGE_IMPLEMENTATION_ROWS):
        raise AssertionError("PSR.ed implementation rows drifted")
    if software_defer.get("execution", {}).get("probes") != [
            "integer_speculative_software_defer_case"]:
        raise AssertionError("PSR.ed execution probe drifted")
    success = by_row[
        "ALT-003-INTEGER-NONFAULTING-SPECULATION-ATTRIBUTES"]
    if success.get("implementation_rows") != list(
            INTEGER_SPECULATION_SUCCESS_IMPLEMENTATION_ROWS):
        raise AssertionError("successful speculation implementation rows drifted")
    if success.get("execution", {}).get("probes") != [
            "successful_integer_speculative_load_case",
            "successful_integer_check_load_case"]:
        raise AssertionError("successful speculation execution probes drifted")
    immediate = by_row["ALT-002-INTEGER-NO-RECOVERY-FAULTS"]
    if immediate.get("implementation_rows") != list(
            INTEGER_SPECULATIVE_LOAD_IMPLEMENTATION_ROWS):
        raise AssertionError("no-recovery implementation rows drifted")
    if immediate.get("execution", {}).get("probes") != [
            "integer_speculative_translation_miss_case",
            "integer_speculative_unaligned_case"]:
        raise AssertionError("no-recovery execution probes drifted")
    protection = by_row["ALT-002-INTEGER-NO-RECOVERY-PROTECTION"]
    if protection.get("implementation_rows") != list(
            INTEGER_SPECULATIVE_LOAD_IMPLEMENTATION_ROWS):
        raise AssertionError("protection implementation rows drifted")
    if protection.get("execution", {}).get("probes") != [
            "integer_speculative_protection_fault_case",
            "integer_speculative_data_debug_case"]:
        raise AssertionError("protection execution probes drifted")
    vhpt = by_row["ALT-002-INTEGER-NO-RECOVERY-VHPT"]
    if vhpt.get("implementation_rows") != list(
            INTEGER_SPECULATIVE_LOAD_IMPLEMENTATION_ROWS):
        raise AssertionError("VHPT implementation rows drifted")
    if vhpt.get("execution", {}).get("probes") != [
            "integer_speculative_vhpt_fault_case"]:
        raise AssertionError("VHPT execution probes drifted")
    recovery = by_row["ALT-001-INTEGER-RECOVERY-DCR-DM"]
    if recovery.get("implementation_rows") != list(
            INTEGER_SPECULATIVE_LOAD_IMPLEMENTATION_ROWS):
        raise AssertionError("DCR.dm implementation rows drifted")
    if recovery.get("execution", {}).get("probes") != [
            "integer_speculative_dm_recovery_case"]:
        raise AssertionError("DCR.dm execution probes drifted")
    recovery_other = by_row[
        "ALT-001-INTEGER-RECOVERY-DCR-PROTECTION-DEBUG"]
    if recovery_other.get("implementation_rows") != list(
            INTEGER_SPECULATIVE_LOAD_IMPLEMENTATION_ROWS):
        raise AssertionError("DCR protection/debug implementation rows drifted")
    if recovery_other.get("execution", {}).get("probes") != [
            "integer_speculative_dcr_recovery_case"]:
        raise AssertionError("DCR protection/debug execution probes drifted")
    if any(case.get("oracle", {}).get("independence") != "independent"
           for case in cases):
        raise AssertionError("speculation tranche oracle is not independent")
    variants = set(deferred.get("applicable_variants", []))
    always_defer_variants = set(always_defer.get("applicable_variants", []))
    software_defer_variants = set(
        software_defer.get("applicable_variants", []))
    success_variants = set(success.get("applicable_variants", []))
    immediate_variants = set(immediate.get("applicable_variants", []))
    protection_variants = set(protection.get("applicable_variants", []))
    vhpt_variants = set(vhpt.get("applicable_variants", []))
    recovery_variants = set(recovery.get("applicable_variants", []))
    recovery_other_variants = set(
        recovery_other.get("applicable_variants", []))
    for width in (1, 2, 4, 8):
        if "ld{}.s".format(width) not in variants or \
                "ld{}.sa".format(width) not in variants:
            raise AssertionError(
                "NaTPage row misses width {} variants".format(width)
            )
        if "ld{}.s".format(width) not in always_defer_variants or \
                "ld{}.sa".format(width) not in always_defer_variants:
            raise AssertionError(
                "PSR.ic=0 row misses width {} variants".format(width)
            )
        if "ld{}.s".format(width) not in software_defer_variants or \
                "ld{}.sa".format(width) not in software_defer_variants:
            raise AssertionError(
                "PSR.ed row misses width {} variants".format(width)
            )
        for suffix in ("s", "a", "sa", "c.clr", "c.clr.acq", "c.nc"):
            if "ld{}.{}".format(width, suffix) not in success_variants:
                raise AssertionError(
                    "successful speculation row misses ld{}.{}".format(
                        width, suffix)
                )
        if "ld{}.s".format(width) not in immediate_variants or \
                "ld{}.sa".format(width) not in immediate_variants:
            raise AssertionError(
                "no-recovery row misses width {} variants".format(width)
            )
        if "ld{}.s".format(width) not in protection_variants or \
                "ld{}.sa".format(width) not in protection_variants:
            raise AssertionError(
                "protection row misses width {} variants".format(width)
            )
        if "ld{}.s".format(width) not in vhpt_variants or \
                "ld{}.sa".format(width) not in vhpt_variants:
            raise AssertionError(
                "VHPT row misses width {} variants".format(width)
            )
        if "ld{}.s".format(width) not in recovery_variants or \
                "ld{}.sa".format(width) not in recovery_variants:
            raise AssertionError(
                "DCR.dm row misses width {} variants".format(width)
            )
        if "ld{}.s".format(width) not in recovery_other_variants or \
                "ld{}.sa".format(width) not in recovery_other_variants:
            raise AssertionError(
                "DCR protection/debug row misses width {} variants".format(
                    width)
            )
    return ("nine exact ALT rows cover non-faulting speculation attributes, "
            "PSR.ed software deferral, PSR.ic=0 always-defer, deferred "
            "NaTPage, and no-recovery "
            "translation, alignment, protection, debug, VHPT-translation, "
            "Data-TLB, and the complete recovery-model DCR deferral-bit "
            "behavior for every applicable integer width")


def _movl_bundle(address: int, reg: int, value: int) -> object:
    """Encode X2 ``movl r1=imm64`` without borrowing a system-test oracle."""
    value &= (1 << 64) - 1
    l_slot = (value >> 22) & H.SLOT_MASK
    x_slot = (
        H.bitfield(reg, 6, 7)
        | H.bitfield(value & 0x7f, 13, 7)
        | H.bitfield((value >> 21) & 1, 21, 1)
        | H.bitfield((value >> 16) & 0x1f, 22, 5)
        | H.bitfield((value >> 7) & 0x1ff, 27, 9)
        | H.bitfield((value >> 63) & 1, 36, 1)
        | H.bitfield(6, 37, 4)
    )
    return H.Bundle(address, 0x05, H.nop_m(), l_slot, x_slot)


def _checked_field(source: int, target: int) -> int:
    displacement = target - (source & ~0xf)
    if displacement & 0xf:
        raise ValueError("checked-branch target must be bundle aligned")
    scaled = displacement // 16
    if not -(1 << 20) <= scaled < (1 << 20):
        raise ValueError("checked-branch displacement exceeds signed imm21")
    return scaled & ((1 << 21) - 1)


def _chk_s_branch(source: int, target: int, *, reg: int,
                  fp: bool = False, qp: int = 0) -> int:
    field = _checked_field(source, target)
    return (
        chk_s(reg=reg, fp=fp, qp=qp)
        | H.bitfield(field & 0x7f, 6, 7)
        | H.bitfield((field >> 7) & 0x1fff, 20, 13)
        | H.bitfield((field >> 20) & 1, 36, 1)
    )


def _chk_a_branch(source: int, target: int, *, reg: int,
                  fp: bool = False, clear: bool = False,
                  qp: int = 0) -> int:
    field = _checked_field(source, target)
    return (
        chk_a(reg=reg, fp=fp, clear=clear, qp=qp)
        | H.bitfield(field & 0xfffff, 13, 20)
        | H.bitfield((field >> 20) & 1, 36, 1)
    )


def _m_system(x6: int, *, r1: int = 0, r2: int = 0,
              r3: int = 0, qp: int = 0) -> int:
    return (
        H.op(1) | H.bitfield(x6, 27, 6) | H.bitfield(r3, 20, 7)
        | H.bitfield(r2, 13, 7) | H.bitfield(r1, 6, 7)
        | H.bitfield(qp, 0, 6)
    )


def ordinary_load(width: int, r1: int, r3: int, *, qp: int = 0) -> int:
    code = {1: 0, 2: 1, 4: 2, 8: 3}[width]
    return (H.op(4) | H.bitfield(code, 30, 6) | H.bitfield(r3, 20, 7)
            | H.bitfield(r1, 6, 7) | qp)


def _append_i(bundles: List[object], address: int,
              instructions: Sequence[int]) -> int:
    for index in range(0, len(instructions), 2):
        slot2 = (instructions[index + 1]
                 if index + 1 < len(instructions) else H.nop_i())
        bundles.append(H.Bundle(address, 0x03, H.nop_m(),
                                instructions[index], slot2))
        address += 0x10
    return address


def _append_m(bundles: List[object], address: int, raw: int,
              traced: List[int], *, trace: bool = True) -> int:
    bundles.append(H.Bundle(address, 0x01, raw, H.nop_i(), H.nop_i()))
    if trace:
        traced.append(address)
    return address + 0x10


def _finish(name: str, bundles: List[object], address: int,
            data: Sequence[object] = ()) -> object:
    bundles.append(H.spin_bundle(address))
    return H.Program(name=name, bundles=tuple(bundles), terminal_ip=address,
                     data=tuple(data))


def _mapped_pte(physical: int, memory_attribute: int, *,
                access_rights: int = 3) -> int:
    """Present, accessed, dirty, PL0 4-KiB DTC translation image."""
    return (physical | 1 | ((memory_attribute & 7) << 2) |
            (1 << 5) | (1 << 6) | ((access_rights & 7) << 9))


def _append_dtc_install(bundles: List[object], address: int, *,
                        pte_reg: int = 2, virtual_reg: int = 7,
                        itir_reg: int = 4,
                        itir: int = 12 << 2,
                        enable_translation: bool = True) -> int:
    bundles.append(_movl_bundle(address, itir_reg, itir))
    address += 0x10
    for raw in (
        H.mov_grcr(H.IA64_CR_IFA, virtual_reg),
        H.mov_grcr(H.IA64_CR_ITIR, itir_reg),
    ):
        bundles.append(H.Bundle(address, 0x01, raw,
                                H.nop_i(), H.nop_i()))
        address += 0x10
    # ITC.D must end its instruction group.  M_MI places a stop directly
    # after slot 0 while retaining the one-bundle-per-step fixture layout.
    bundles.append(H.Bundle(
        address, 0x0B, _m_system(0x2e, r2=pte_reg),
        H.nop_m(), H.nop_i(),
    ))
    address += 0x10
    controls = [H.srlz_d()]
    if enable_translation:
        controls.extend((
            H.ssm(H.IA64_PSR_IC | H.IA64_PSR_DT),
            H.srlz_i(),
        ))
    for raw in controls:
        bundles.append(H.Bundle(address, 0x01, raw,
                                H.nop_i(), H.nop_i()))
        address += 0x10
    return address


def _append_itc_install(bundles: List[object], address: int, *,
                        pte_reg: int, virtual_reg: int,
                        itir_reg: int = 4,
                        itir: int = 12 << 2) -> int:
    """Install one test-owned instruction translation while PSR.it is clear."""
    bundles.append(_movl_bundle(address, itir_reg, itir))
    address += 0x10
    for raw in (
        H.mov_grcr(H.IA64_CR_IFA, virtual_reg),
        H.mov_grcr(H.IA64_CR_ITIR, itir_reg),
    ):
        bundles.append(H.Bundle(address, 0x01, raw,
                                H.nop_i(), H.nop_i()))
        address += 0x10
    bundles.append(H.Bundle(
        address, 0x0B, _m_system(0x2F, r2=pte_reg),
        H.nop_m(), H.nop_i(),
    ))
    address += 0x10
    bundles.extend((
        H.Bundle(address, 0x01, H.srlz_d(), H.nop_i(), H.nop_i()),
        H.Bundle(address + 0x10, 0x01,
                 H.srlz_i(), H.nop_i(), H.nop_i()),
    ))
    return address + 0x20


def _marker_bundle(address: int, reg: int, value: int,
                   target: int) -> object:
    return H.Bundle(address, 0x11, H.nop_m(), H.adds(reg, value, 0),
                    H.br_cond(address, target))


@dataclasses.dataclass(frozen=True)
class RuntimeCase:
    name: str
    program: object
    trace_ips: Tuple[int, ...]
    verify: Callable[[object], str]
    opcode_coverage: Tuple[str, ...]
    preserve_fault_slot: bool = False


def _no_exception(snapshot, label: str) -> None:
    H._require(not snapshot.exception_pending,
               label + " unexpectedly raised " + snapshot.exception_kind)


def _verify_admission(snapshot) -> str:
    _no_exception(snapshot, "predicated-off admission matrix")
    return "all encodings nullified after typed decode/admission"


def primary_admission_case() -> RuntimeCase:
    bundles: List[object] = []
    traced: List[int] = []
    address = 0x10
    for opcode in DATA_PLANE_OPCODES:
        address = _append_m(
            bundles, address, primary_encoding(opcode, qp=1), traced,
            trace=(SPEC_BY_OPCODE[opcode].isa_status !=
                   "decoder-reserved-width"),
        )
    return RuntimeCase(
        "57-live-row primary decode/admission",
        _finish("data-plane primary admission", bundles, address),
        tuple(traced), _verify_admission, tuple(DATA_PLANE_OPCODES),
    )


def alias_admission_case() -> RuntimeCase:
    live = tuple(alias for alias in ALIAS_ENCODINGS
                 if alias.status != "shadowed-by-cmpxchg")
    bundles: List[object] = []
    traced: List[int] = []
    address = 0x10
    for alias in live:
        raw = (alias.raw & ~0x3f) | 1
        address = _append_m(bundles, address, raw, traced)
    coverage = tuple(dict.fromkeys(alias.opcode for alias in live))
    return RuntimeCase(
        "live decoder aliases and completers",
        _finish("data-plane live aliases", bundles, address),
        tuple(traced), _verify_admission, coverage,
    )


def atomic_case() -> RuntimeCase:
    bundles: List[object] = []
    traced: List[int] = []
    address = _append_i(
        bundles, 0x10,
        (H.adds(10, 0x1800, 0), H.adds(11, 9, 0),
         H.adds(14, 0x1808, 0), H.adds(15, 0x1810, 0)),
    )
    address = _append_m(
        bundles, address,
        atomic("IA64_OP_XCHG8", r1=20, r2=11, r3=10), traced,
    )
    address = _append_m(
        bundles, address,
        atomic("IA64_OP_FETCHADD8", r1=21, r3=10, inc_index=3), traced,
    )
    address = _append_m(bundles, address, H.ld8(12, 14), traced, trace=False)
    address = _append_m(bundles, address, H.ld8(13, 15), traced, trace=False)
    address = _append_m(
        bundles, address, H.mov_m_grar(32, 12), traced, trace=False
    )
    address = _append_m(
        bundles, address,
        atomic("IA64_OP_CMPXCHG8", r1=22, r2=13, r3=10), traced,
    )
    address = _append_m(bundles, address, H.ld8(23, 10), traced, trace=False)
    program = _finish(
        "xchg/fetchadd/cmpxchg literal semantics", bundles, address,
        (H.DataWord(0x1800, 5, 8), H.DataWord(0x1808, 10, 8),
         H.DataWord(0x1810, 100, 8)),
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, "atomic matrix")
        H._require(
            (snapshot.gr[20], snapshot.gr[21], snapshot.gr[22],
             snapshot.gr[23]) == (5, 9, 10, 100),
            "atomic old values/final memory were {}, {}, {}, {}".format(
                snapshot.gr[20], snapshot.gr[21], snapshot.gr[22],
                snapshot.gr[23]),
        )
        H._require((snapshot.nat_low & sum(1 << reg for reg in range(20, 24))) == 0,
                   "atomic results did not clear NaT")
        return "xchg8 returned 5, fetchadd8 returned 9, cmpxchg8 returned 10 and stored 100"

    return RuntimeCase(
        "active atomic semantics", program, tuple(traced), verify,
        ("IA64_OP_XCHG8", "IA64_OP_FETCHADD8", "IA64_OP_CMPXCHG8"),
    )


def wide_spill_case() -> RuntimeCase:
    low = 0x1122334455667788
    high = 0x99AABBCCDDEEFF00
    bundles: List[object] = []
    traced: List[int] = []
    address = _append_i(
        bundles, 0x10,
        (H.adds(11, 0x1800, 0), H.adds(12, 0x1820, 0),
         H.adds(13, 0x1828, 0), H.adds(15, 0x1810, 0),
         H.adds(16, 0x1840, 0)),
    )
    address = _append_m(bundles, address, H.ld8(10, 15), traced, trace=False)
    address = _append_m(
        bundles, address, integer_load(8, "s", r1=20, r3=10), traced
    )
    address = _append_m(
        bundles, address, integer_spill(8, r2=20, r3=16), traced
    )
    address = _append_m(
        bundles, address, integer_load(8, "fill", r1=21, r3=16), traced
    )
    address = _append_m(bundles, address, ld16(r1=22, r3=11), traced)
    address = _append_m(
        bundles, address, H.mov_m_argr(23, 25), traced, trace=False
    )
    address = _append_m(bundles, address, st16(r2=22, r3=12), traced)
    address = _append_m(bundles, address, H.ld8(24, 12), traced, trace=False)
    address = _append_m(bundles, address, H.ld8(25, 13), traced, trace=False)
    program = _finish(
        "speculative spill/fill and AR.CSD wide memory", bundles, address,
        (H.DataWord(0x1800, low, 8), H.DataWord(0x1808, high, 8),
         H.DataWord(0x1810, 0x40000000, 8),
         H.DataWord(0x1820, 0, 8), H.DataWord(0x1828, 0, 8),
         H.DataWord(0x1840, 0, 8)),
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, "wide/spill matrix")
        H._require(snapshot.gr[22] == low and snapshot.gr[23] == high,
                   "ld16 did not place low address in GR and high address in AR.CSD")
        H._require(snapshot.gr[24] == low and snapshot.gr[25] == high,
                   "st16 did not write GR/AR.CSD pair")
        H._require((snapshot.nat_low & ((1 << 20) | (1 << 21))) ==
                   ((1 << 20) | (1 << 21)),
                   "speculative NaT did not survive st8.spill/ld8.fill")
        H._require(snapshot.unat & (1 << 8),
                   "st8.spill did not copy source NaT to UNAT[8]")
        return "ld8.s deferred, spill/fill copied UNAT[8], and ld16/st16 round-tripped GR+AR.CSD"

    return RuntimeCase(
        "active speculative/wide/spill semantics", program, tuple(traced), verify,
        ("IA64_OP_LD8S", "IA64_OP_ST8SPILL", "IA64_OP_LD8FILL",
         "IA64_OP_LD16", "IA64_OP_ST16"),
    )


def ordered_unat_spill_case() -> RuntimeCase:
    """Two same-group spills must form one ordered UNAT effect chain."""
    payload = 0x1122334455667788
    initial_unat = (1 << 0) | (1 << 9)
    program = H.Program(
        name="same-group ordered st8.spill UNAT effects",
        bundles=(
            H.Bundle(0x10, 0x01, H.nop_m(), H.adds(8, initial_unat, 0),
                     H.adds(9, 0x1800, 0)),
            H.Bundle(0x20, 0x01, H.mov_m_grar(36, 8), H.nop_i(), H.nop_i()),
            # UNAT[0] makes r20 NaT while r21 remains a normal value.
            H.Bundle(0x30, 0x01, H.ld8_fill(20, 9), H.nop_i(), H.nop_i()),
            H.Bundle(0x40, 0x03, H.nop_m(), H.adds(10, 0x1840, 0),
                     H.adds(11, 0x1848, 0)),
            H.Bundle(0x50, 0x01, H.nop_m(), H.adds(21, 0x55, 0), H.nop_i()),
            # MMI has no internal stop.  Spill one sets UNAT[8]; spill two
            # consumes that live image and clears the initially-poisoned bit 9.
            H.Bundle(0x60, 0x09,
                     integer_spill(8, r2=20, r3=10),
                     integer_spill(8, r2=21, r3=11), H.nop_i()),
            # Read the completed image back through architectural fill behavior.
            H.Bundle(0x70, 0x09, integer_load(8, "fill", r1=22, r3=10),
                     integer_load(8, "fill", r1=23, r3=11), H.nop_i()),
            H.spin_bundle(0x80),
        ),
        terminal_ip=0x80,
        data=(H.DataWord(0x1800, payload, 8),
              H.DataWord(0x1840, 0, 8), H.DataWord(0x1848, 0, 8)),
    )

    def verify(snapshot) -> str:
        expected_unat = (1 << 0) | (1 << 8)

        _no_exception(snapshot, "ordered UNAT spill chain")
        H._require(snapshot.unat == expected_unat,
                   "same-group spills lost or reordered a UNAT effect: "
                   "expected 0x{:x}, got 0x{:x}".format(
                       expected_unat, snapshot.unat))
        H._require(snapshot.gr[22] == payload and snapshot.gr[23] == 0x55,
                   "same-group spill payloads did not round-trip through fill")
        H._require((snapshot.nat_low & ((1 << 22) | (1 << 23))) == (1 << 22),
                   "fill did not recover set UNAT[8] and clear UNAT[9]")
        return ("two no-stop st8.spill instructions preserved the first UNAT "
                "update, cleared the second bit, and filled both NaTs exactly")

    return RuntimeCase(
        "same-group ordered UNAT spill effects", program, (0x60, 0x70), verify,
        ("IA64_OP_ST8SPILL", "IA64_OP_LD8FILL"),
    )


def floating_case() -> RuntimeCase:
    single = 0x3FC00000
    double = 0x4002000000000000
    significand = 0x8877665544332211
    external = 0xC123
    spill_sign_exponent = 0x30123
    pair = 0x402000003F800000
    source_addresses = (0x1800, 0x1808, 0x1810, 0x1818, 0x1820, 0x1830)
    output_addresses = (0x1860, 0x1868, 0x1870, 0x1878, 0x1880, 0x1890)
    bundles: List[object] = []
    traced: List[int] = []
    address = _append_i(
        bundles, 0x10,
        tuple(H.adds(reg, value, 0) for reg, value in
              zip(range(10, 22), source_addresses + output_addresses)),
    )
    for load_op, store_op, f1, src_gr, dst_gr in (
        ("IA64_OP_LDFS", "IA64_OP_STFS", 20, 10, 16),
        ("IA64_OP_LDFD", "IA64_OP_STFD", 21, 11, 17),
        ("IA64_OP_LDF8", "IA64_OP_STF8", 22, 12, 18),
    ):
        address = _append_m(
            bundles, address, floating_load(load_op, f1=f1, r3=src_gr), traced
        )
        address = _append_m(
            bundles, address, floating_store(store_op, f2=f1, r3=dst_gr), traced
        )
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDFPS", f1=24, f2=25, r3=13), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STFS", f2=24, r3=19), traced,
    )
    # The second pair element follows the first output word.
    address = _append_i(bundles, address, (H.adds(22, 0x187c, 0),))
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STFS", f2=25, r3=22), traced,
    )
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDFE", f1=26, r3=14), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STFE", f2=26, r3=20), traced,
    )
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDF_FILL", f1=27, r3=15), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STF_SPILL", f2=27, r3=21), traced,
    )
    for width, target, base in (
        (4, 23, 16), (8, 24, 17), (8, 25, 18), (8, 26, 19),
        (8, 27, 20), (8, 28, 21),
    ):
        address = _append_m(
            bundles, address, ordinary_load(width, target, base), traced,
            trace=False,
        )
    address = _append_i(
        bundles, address,
        (H.adds(8, 0x1888, 0), H.adds(9, 0x1898, 0)),
    )
    address = _append_m(
        bundles, address, ordinary_load(2, 29, 8), traced, trace=False,
    )
    address = _append_m(
        bundles, address, ordinary_load(8, 30, 9), traced, trace=False,
    )
    data = (
        H.DataWord(0x1800, single, 4), H.DataWord(0x1808, double, 8),
        H.DataWord(0x1810, significand, 8), H.DataWord(0x1818, pair, 8),
        H.DataWord(0x1820, significand, 8),
        H.DataWord(0x1828, external, 2),
        H.DataWord(0x1830, significand, 8),
        H.DataWord(0x1838, spill_sign_exponent, 8),
        H.DataWord(0x1860, 0, 4), H.DataWord(0x1868, 0, 8),
        H.DataWord(0x1870, 0, 8), H.DataWord(0x1878, 0, 8),
        H.DataWord(0x1880, 0, 8), H.DataWord(0x1888, 0, 8),
        H.DataWord(0x1890, 0, 8), H.DataWord(0x1898, 0, 8),
    )
    program = _finish("floating load/store literal round trips",
                      bundles, address, data)

    def verify(snapshot) -> str:
        _no_exception(snapshot, "floating memory matrix")
        expected = (single, double, significand, pair,
                    significand, significand, external,
                    spill_sign_exponent)
        actual = tuple(snapshot.gr[reg] for reg in range(23, 31))
        H._require(actual == expected,
                   "floating memory round trips were {} not {}".format(
                       tuple(hex(value) for value in actual),
                       tuple(hex(value) for value in expected)))
        return ("single/double/significand/pair plus nonzero extended and "
                "spill payloads round-tripped literal LE bytes")

    return RuntimeCase(
        "active floating memory semantics", program, tuple(traced), verify,
        ("IA64_OP_LDFS", "IA64_OP_STFS", "IA64_OP_LDFD", "IA64_OP_STFD",
         "IA64_OP_LDF8", "IA64_OP_STF8", "IA64_OP_LDFPS",
         "IA64_OP_LDFE", "IA64_OP_STFE", "IA64_OP_LDF_FILL",
         "IA64_OP_STF_SPILL"),
    )


def floating_zero_encoding_case() -> RuntimeCase:
    """Keep architectural zero distinct from unsupported pseudo-infinity."""
    addresses = (
        0x1800, 0x1820, 0x1840, 0x1848,
        0x1880, 0x1888, 0x18A0, 0x18A8, 0x18C0, 0x18C8,
    )
    bundles: List[object] = []
    traced: List[int] = []
    address = _append_i(
        bundles, 0x10,
        tuple(H.adds(reg, value, 0)
              for reg, value in zip(range(10, 20), addresses)),
    )

    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDF_FILL", f1=20, r3=10), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STF_SPILL", f2=20, r3=14), traced,
    )
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDF_FILL", f1=21, r3=11), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STF_SPILL", f2=21, r3=16), traced,
    )
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDFS", f1=22, r3=12), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STFS", f2=22, r3=18), traced,
    )
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDFD", f1=23, r3=13), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STFD", f2=23, r3=19), traced,
    )

    for base, target, width in (
        (14, 20, 8), (15, 21, 8),
        (16, 22, 8), (17, 23, 8),
        (18, 24, 4), (19, 25, 8),
    ):
        address = _append_m(
            bundles, address, ordinary_load(width, target, base), traced,
            trace=False,
        )

    program = _finish(
        "floating architectural zero and pseudo-infinity encodings",
        bundles, address,
        (
            # Exact register-format +0 spill image.
            H.DataWord(0x1800, 0, 8), H.DataWord(0x1808, 0, 8),
            # Same significand, but special exponent: unsupported
            # pseudo-infinity and therefore not a zero alias.
            H.DataWord(0x1820, 0, 8), H.DataWord(0x1828, 0x1FFFF, 8),
            H.DataWord(0x1840, 0x80000000, 4),
            H.DataWord(0x1848, 0, 8),
            H.DataWord(0x1880, 0, 8), H.DataWord(0x1888, 0, 8),
            H.DataWord(0x18A0, 0, 8), H.DataWord(0x18A8, 0, 8),
            H.DataWord(0x18C0, 0, 4), H.DataWord(0x18C8, 0, 8),
        ),
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, "floating zero encoding matrix")
        expected = (0, 0, 0, 0x1FFFF, 0x80000000, 0)
        actual = tuple(snapshot.gr[reg] for reg in range(20, 26))
        H._require(actual == expected,
                   "zero/pseudo-infinity images were {} not {}".format(
                       tuple(hex(value) for value in actual),
                       tuple(hex(value) for value in expected)))
        return ("spill/fill preserved exp=0 zero and exp=0x1ffff "
                "pseudo-infinity separately; -0 single and +0 double "
                "round-tripped")

    return RuntimeCase(
        "floating zero/pseudo-infinity encoding semantics",
        program, tuple(traced), verify,
        ("IA64_OP_LDF_FILL", "IA64_OP_STF_SPILL",
         "IA64_OP_LDFS", "IA64_OP_STFS",
         "IA64_OP_LDFD", "IA64_OP_STFD"),
    )


def floating_big_endian_case() -> RuntimeCase:
    mantissa = 0x8877665544332211
    external = 0xC123
    spill_sign_exponent = 0x30123
    # DataWord values are little-endian byte images.  These literals encode
    # the architected BE layouts, not helper-internal numeric round trips.
    ext_prefix_image = 0x33445566778823C1
    spill_prefix_image = 0x2301030000000000
    mantissa_be_image = 0x1122334455667788
    bundles: List[object] = []
    traced: List[int] = []
    address = _append_i(
        bundles, 0x10,
        (H.adds(10, 0x1800, 0), H.adds(11, 0x1820, 0),
         H.adds(12, 0x1840, 0), H.adds(13, 0x1860, 0)),
    )
    bundles.append(H.Bundle(address, 0x01, H.ssm(1 << 1),
                            H.nop_i(), H.nop_i()))
    address += 0x10
    bundles.append(H.Bundle(address, 0x01, H.srlz_d(),
                            H.nop_i(), H.nop_i()))
    address += 0x10
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDFE", f1=20, r3=10), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STFE", f2=20, r3=12), traced,
    )
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDF_FILL", f1=21, r3=11), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STF_SPILL", f2=21, r3=13), traced,
    )
    bundles.append(H.Bundle(address, 0x01, H.rsm(1 << 1),
                            H.nop_i(), H.nop_i()))
    address += 0x10
    bundles.append(H.Bundle(address, 0x01, H.srlz_d(),
                            H.nop_i(), H.nop_i()))
    address += 0x10
    address = _append_i(
        bundles, address,
        (H.adds(14, 0x1840, 0), H.adds(15, 0x1848, 0),
         H.adds(16, 0x1860, 0), H.adds(17, 0x1868, 0)),
    )
    for width, target, base in (
        (8, 23, 14), (2, 24, 15), (8, 25, 16), (8, 26, 17),
    ):
        address = _append_m(
            bundles, address, ordinary_load(width, target, base), traced,
            trace=False,
        )
    program = _finish(
        "nonzero big-endian extended and spill literal layouts",
        bundles, address,
        (H.DataWord(0x1800, 0x23C1, 2),
         H.DataWord(0x1802, mantissa_be_image, 8),
         H.DataWord(0x1820, spill_prefix_image, 8),
         H.DataWord(0x1828, mantissa_be_image, 8),
         H.DataWord(0x1840, 0, 8), H.DataWord(0x1848, 0, 8),
         H.DataWord(0x1860, 0, 8), H.DataWord(0x1868, 0, 8)),
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, "big-endian floating memory matrix")
        expected = (ext_prefix_image, 0x1122,
                    spill_prefix_image, mantissa_be_image)
        actual = tuple(snapshot.gr[reg] for reg in range(23, 27))
        H._require(actual == expected,
                   "BE extended/spill byte images were {} not {}".format(
                       tuple(hex(value) for value in actual),
                       tuple(hex(value) for value in expected)))
        H._require((snapshot.psr & (1 << 1)) == 0,
                   "BE floating test did not restore PSR.be")
        return ("LDFE/STFE and LDF.FILL/STF.SPILL reproduced exact nonzero "
                "big-endian byte layouts")

    return RuntimeCase(
        "nonzero big-endian extended/spill semantics", program,
        tuple(traced), verify,
        ("IA64_OP_LDFE", "IA64_OP_STFE", "IA64_OP_LDF_FILL",
         "IA64_OP_STF_SPILL"),
    )


def big_endian_wide_pair_case() -> RuntimeCase:
    wide_low = 0x0123456789ABCDEF
    wide_high = 0xFEDCBA9876543210
    wide_low_image = 0xEFCDAB8967452301
    wide_high_image = 0x1032547698BADCFE
    pair_image = 0x000020400000803F
    bundles: List[object] = []
    traced: List[int] = []
    address = _append_i(
        bundles, 0x10,
        (H.adds(10, 0x1800, 0), H.adds(11, 0x1820, 0),
         H.adds(12, 0x1840, 0), H.adds(13, 0x1860, 0),
         H.adds(14, 0x1864, 0)),
    )
    bundles.append(H.Bundle(address, 0x01, H.ssm(1 << 1),
                            H.nop_i(), H.nop_i()))
    address += 0x10
    bundles.append(H.Bundle(address, 0x01, H.srlz_d(),
                            H.nop_i(), H.nop_i()))
    address += 0x10
    address = _append_m(bundles, address, ld16(r1=20, r3=10), traced)
    address = _append_m(
        bundles, address, H.mov_m_argr(21, 25), traced, trace=False
    )
    address = _append_m(bundles, address, st16(r2=20, r3=11), traced)
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDFPS", f1=24, f2=25, r3=12), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STFS", f2=24, r3=13), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STFS", f2=25, r3=14), traced,
    )
    bundles.append(H.Bundle(address, 0x01, H.rsm(1 << 1),
                            H.nop_i(), H.nop_i()))
    address += 0x10
    bundles.append(H.Bundle(address, 0x01, H.srlz_d(),
                            H.nop_i(), H.nop_i()))
    address += 0x10
    address = _append_m(
        bundles, address, ordinary_load(8, 22, 11), traced, trace=False,
    )
    address = _append_i(bundles, address, (H.adds(15, 0x1828, 0),))
    address = _append_m(
        bundles, address, ordinary_load(8, 23, 15), traced, trace=False,
    )
    address = _append_m(
        bundles, address, ordinary_load(8, 26, 13), traced, trace=False,
    )
    program = _finish(
        "big-endian wide and FP-pair address ordering", bundles, address,
        (H.DataWord(0x1800, wide_low_image, 8),
         H.DataWord(0x1808, wide_high_image, 8),
         H.DataWord(0x1820, 0, 8), H.DataWord(0x1828, 0, 8),
         H.DataWord(0x1840, pair_image, 8),
         H.DataWord(0x1860, 0, 8)),
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, "big-endian wide/pair matrix")
        H._require((snapshot.gr[20], snapshot.gr[21]) ==
                   (wide_low, wide_high),
                   "BE ld16 assigned the wrong GR/AR.CSD address halves")
        H._require((snapshot.gr[22], snapshot.gr[23]) ==
                   (wide_low_image, wide_high_image),
                   "BE st16 did not reproduce the two literal byte images")
        H._require(snapshot.gr[26] == pair_image,
                   "BE LDFPS/STFS reversed its low/high-address elements")
        H._require((snapshot.psr & (1 << 1)) == 0,
                   "BE wide/pair test did not restore PSR.be")
        return ("BE LD16/ST16 preserved low-address GR plus high-address "
                "AR.CSD, and LDFPS preserved pair element order")

    return RuntimeCase(
        "big-endian wide and FP-pair semantics", program, tuple(traced),
        verify,
        ("IA64_OP_LD16", "IA64_OP_ST16", "IA64_OP_LDFPS",
         "IA64_OP_STFS"),
    )


def _rotated_fr_setup(target: int, rrb_fr: int) -> List[object]:
    ifs = (1 << 63) | ((rrb_fr & 0x7f) << 25)
    return [
        _movl_bundle(0x10, 2, H.IA64_PSR_IC),
        _movl_bundle(0x20, 3, target),
        _movl_bundle(0x30, 4, ifs),
        H.Bundle(0x40, 0x01, H.mov_grcr(H.IA64_CR_IPSR, 2),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x50, 0x01, H.mov_grcr(H.IA64_CR_IIP, 3),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x60, 0x01, H.mov_grcr(H.IA64_CR_IFS, 4),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x70, 0x11, H.nop_m(), H.nop_i(), H.rfi()),
    ]


def rotated_fp_pair_legal_case() -> RuntimeCase:
    pair = 0x402000003F800000
    target = 0x80
    bundles = _rotated_fr_setup(target, rrb_fr=1)
    traced: List[int] = []
    address = _append_i(
        bundles, target,
        (H.adds(10, 0x1800, 0), H.adds(11, 0x1820, 0),
         H.adds(12, 0x1824, 0)),
    )
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDFPS", f1=20, f2=32, r3=10), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STFS", f2=20, r3=11), traced,
    )
    address = _append_m(
        bundles, address,
        floating_store("IA64_OP_STFS", f2=32, r3=12), traced,
    )
    address = _append_m(
        bundles, address, ordinary_load(8, 20, 11), traced, trace=False,
    )
    program = _finish(
        "physical FP-pair legality after FR rotation", bundles, address,
        (H.DataWord(0x1800, pair, 8), H.DataWord(0x1820, 0, 8)),
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, "rotated legal FP pair")
        H._require(((snapshot.cfm >> 25) & 0x7f) == 1,
                   "RFI did not establish rrb_fr=1")
        H._require(snapshot.gr[20] == pair,
                   "logical f20/f32 did not load/store as a legal physical "
                   "even/odd pair")
        return ("rrb_fr=1 mapped logical f20/f32 to physical f20/f33, "
                "making the logically same-parity pair legal")

    return RuntimeCase(
        "rotated physical FP-pair legal semantics", program, tuple(traced),
        verify, ("IA64_OP_LDFPS", "IA64_OP_STFS"),
    )


def rotated_fp_pair_illegal_case() -> RuntimeCase:
    target = 0x80
    bundles = _rotated_fr_setup(target, rrb_fr=1)
    traced: List[int] = []
    address = _append_i(bundles, target, (H.adds(10, 0x1800, 0),))
    fault_ip = address
    fault_raw = floating_load(
        "IA64_OP_LDFPS", f1=20, f2=33, r3=10
    )
    address = _append_m(bundles, address, fault_raw, traced)
    bundles.append(H._exception_vector_spin(IA64_ILLEGAL_OPERATION_VECTOR))
    program = H.Program(
        name="physical FP-pair illegality after FR rotation",
        bundles=tuple(bundles), terminal_ip=IA64_ILLEGAL_OPERATION_VECTOR,
        data=(H.DataWord(0x1800, 0x402000003F800000, 8),),
    )

    def verify(snapshot) -> str:
        H._require(
            snapshot.ip == IA64_ILLEGAL_OPERATION_VECTOR and
            snapshot.exception_pending and
            snapshot.exception_kind == "illegal-operation" and
            snapshot.exception_vector == IA64_ILLEGAL_OPERATION_VECTOR and
            snapshot.exception_source == fault_ip and
            snapshot.exception_address == fault_ip and
            snapshot.cr_iip == fault_ip and snapshot.cr_isr == 0,
            "rotated logical f20/f33 pair did not raise precise Illegal",
        )
        H._require(snapshot.slot_valid and snapshot.slot_ip == fault_ip and
                   snapshot.slot_ri == 0 and
                   snapshot.slot_type == H.IA64_SLOT_TYPE_M and
                   snapshot.slot_raw == (fault_raw & H.SLOT_MASK),
                   "rotated illegal FP pair lost its exact M-slot image")
        return ("rrb_fr=1 mapped logical f20/f33 to physical f20/f34, "
                "making the logically opposite-parity pair Illegal")

    return RuntimeCase(
        "rotated physical FP-pair Illegal", program, tuple(traced), verify,
        ("IA64_OP_LDFPS",), True,
    )


def alat_cache_hint_case() -> RuntimeCase:
    bundles: List[object] = []
    traced: List[int] = []
    address = _append_i(
        bundles, 0x10,
        (H.adds(10, 0x1800, 0), H.adds(11, 8, 0),
         H.adds(12, 0x1800, 0), H.adds(13, 0x1820, 0),
         H.adds(21, 0x222, 0)),
    )
    address = _append_m(
        bundles, address, lfetch(r2=11, r3=10, update="reg"), traced
    )
    address = _append_m(
        bundles, address,
        lfetch(fault=True, r3=12, update="imm", imm=8), traced,
    )
    address = _append_m(
        bundles, address, integer_load(8, "a", r1=20, r3=13), traced
    )
    address = _append_m(bundles, address, H.st8(21, 13), traced, trace=False)
    address = _append_m(
        bundles, address, integer_load(8, "c.nc", r1=20, r3=13), traced
    )
    address = _append_m(
        bundles, address, integer_load(8, "c.clr", r1=20, r3=13), traced
    )
    for raw in (
        cache_control("IA64_OP_FWB"),
        cache_control("IA64_OP_FC", reg=10),
        cache_control("IA64_OP_INVALAT", reg=20),
        cache_control("IA64_OP_INVALA"),
    ):
        address = _append_m(bundles, address, raw, traced)
    program = _finish(
        "ALAT check loads, cache control, and lfetch updates", bundles,
        address, (H.DataWord(0x1800, 0, 8), H.DataWord(0x1820, 0x111, 8)),
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, "ALAT/cache/hint matrix")
        H._require(snapshot.gr[10] == 0x1808 and snapshot.gr[12] == 0x1808,
                   "lfetch register/immediate updates did not run after hint")
        H._require(snapshot.gr[20] == 0x222,
                   "c.nc miss/c.clr hit did not reload then preserve target")
        return "lfetch updates reached 0x1808; store collision forced c.nc reload; c.clr hit preserved 0x222"

    return RuntimeCase(
        "active ALAT/cache/hint semantics", program, tuple(traced), verify,
        ("IA64_OP_LFETCH", "IA64_OP_LFETCH_FAULT", "IA64_OP_LD8A",
         "IA64_OP_LD8C_NC", "IA64_OP_LD8C_CLR", "IA64_OP_FWB",
         "IA64_OP_FC", "IA64_OP_INVALAT", "IA64_OP_INVALA"),
    )


def integer_advanced_nat_page_case() -> RuntimeCase:
    virtual = 0x8000
    physical = 0x2000
    bundles: List[object] = [
        _movl_bundle(0x10, 2, _mapped_pte(physical, 7)),
        _movl_bundle(0x20, 7, virtual),
        _movl_bundle(0x30, 6, physical),
    ]
    traced: List[int] = []
    address = _append_m(
        bundles, 0x40,
        integer_load(8, "a", r1=21, r3=6), traced,
    )
    address = _append_dtc_install(bundles, address)
    fault_ip = address
    fault_raw = integer_load(
        8, "a", r1=21, r3=7, update="imm", imm=8,
    )
    address = _append_m(bundles, address, fault_raw, traced)
    H._require(address == fault_ip + 0x10,
               "integer .a NaTPage fault address drifted")
    bundles.extend((
        H.Bundle(
            IA64_DATA_NAT_PAGE_VECTOR, 0x01,
            _chk_a_branch(IA64_DATA_NAT_PAGE_VECTOR,
                          IA64_DATA_NAT_PAGE_VECTOR + 0x20, reg=21),
            H.nop_i(), H.nop_i(),
        ),
        _marker_bundle(IA64_DATA_NAT_PAGE_VECTOR + 0x10, 30, 1,
                       IA64_DATA_NAT_PAGE_VECTOR + 0x30),
        _marker_bundle(IA64_DATA_NAT_PAGE_VECTOR + 0x20, 30, 0xBAD,
                       IA64_DATA_NAT_PAGE_VECTOR + 0x30),
        H.spin_bundle(IA64_DATA_NAT_PAGE_VECTOR + 0x30),
    ))
    traced.append(IA64_DATA_NAT_PAGE_VECTOR)
    program = H.Program(
        name="LD8.A NaTPage fault retains destination, update, and ALAT",
        bundles=tuple(bundles),
        terminal_ip=IA64_DATA_NAT_PAGE_VECTOR + 0x30,
        data=(H.DataWord(physical, 0x55, 8),),
    )

    def verify(snapshot) -> str:
        H._require(
            snapshot.exception_pending and
            snapshot.exception_kind == "data-nat-page-consumption" and
            snapshot.exception_vector == IA64_DATA_NAT_PAGE_VECTOR and
            snapshot.exception_source == fault_ip and
            snapshot.exception_address == virtual and
            snapshot.cr_iip == fault_ip and snapshot.cr_ifa == virtual and
            snapshot.cr_isr == H.IA64_ISR_R |
                               IA64_ISR_CODE_DATA_NAT_PAGE_CONSUMPTION,
            "LD8.A did not publish an exact ordinary-read Data-NaT fault",
        )
        H._require(snapshot.gr[7] == virtual and snapshot.gr[21] == 0x55 and
                   not (snapshot.nat_low & (1 << 21)),
                   "LD8.A NaTPage fault changed its base/destination/NaT")
        H._require(snapshot.gr[30] == 1,
                   "LD8.A NaTPage fault invalidated the prior ALAT entry")
        return ("LD8.A raised ordinary-read Data NaT Page with no base, "
                "destination, NaT, or ALAT mutation")

    return RuntimeCase(
        "LD8.A exact NaTPage fault and ALAT retention", program,
        tuple(traced), verify, ("IA64_OP_LD8A", "IA64_OP_CHK_A"),
    )


def fp_advanced_nat_page_case() -> RuntimeCase:
    virtual = 0x8000
    physical = 0x2000
    bundles: List[object] = [
        _movl_bundle(0x10, 2, _mapped_pte(physical, 7)),
        _movl_bundle(0x20, 7, virtual),
        _movl_bundle(0x30, 6, physical),
    ]
    traced: List[int] = []
    address = _append_m(
        bundles, 0x40,
        floating_load("IA64_OP_LDFE", attr="a", f1=20, r3=6), traced,
    )
    address = _append_dtc_install(bundles, address)
    fault_ip = address
    fault_raw = floating_load(
        "IA64_OP_LDFE", attr="a", f1=20, r3=7,
        update="imm", imm=8,
    )
    address = _append_m(bundles, address, fault_raw, traced)
    bundles.extend((
        H.Bundle(
            IA64_DATA_NAT_PAGE_VECTOR, 0x01,
            _chk_a_branch(IA64_DATA_NAT_PAGE_VECTOR,
                          IA64_DATA_NAT_PAGE_VECTOR + 0x20,
                          reg=20, fp=True),
            H.nop_i(), H.nop_i(),
        ),
        _marker_bundle(IA64_DATA_NAT_PAGE_VECTOR + 0x10, 30, 1,
                       IA64_DATA_NAT_PAGE_VECTOR + 0x30),
        _marker_bundle(IA64_DATA_NAT_PAGE_VECTOR + 0x20, 30, 0xBAD,
                       IA64_DATA_NAT_PAGE_VECTOR + 0x30),
        H.spin_bundle(IA64_DATA_NAT_PAGE_VECTOR + 0x30),
    ))
    traced.append(IA64_DATA_NAT_PAGE_VECTOR)
    program = H.Program(
        name="LDFE.A NaTPage fault retains base, FR, and ALAT",
        bundles=tuple(bundles),
        terminal_ip=IA64_DATA_NAT_PAGE_VECTOR + 0x30,
        data=(H.DataWord(physical, 0x8877665544332211, 8),
              H.DataWord(physical + 8, 0xC123, 2)),
    )

    def verify(snapshot) -> str:
        H._require(
            snapshot.exception_pending and
            snapshot.exception_kind == "data-nat-page-consumption" and
            snapshot.exception_vector == IA64_DATA_NAT_PAGE_VECTOR and
            snapshot.exception_source == fault_ip and
            snapshot.exception_address == virtual and
            snapshot.cr_iip == fault_ip and snapshot.cr_ifa == virtual and
            snapshot.cr_isr == H.IA64_ISR_R |
                               IA64_ISR_CODE_DATA_NAT_PAGE_CONSUMPTION,
            "LDFE.A did not publish an exact ordinary-read Data-NaT fault",
        )
        H._require(snapshot.gr[7] == virtual,
                   "LDFE.A NaTPage fault retired its base update")
        H._require(snapshot.gr[30] == 1,
                   "LDFE.A NaTPage fault invalidated the prior FR ALAT entry")
        return ("LDFE.A raised ordinary-read Data NaT Page and retained its "
                "base plus prior FR ALAT entry")

    return RuntimeCase(
        "LDFE.A exact NaTPage fault and FR ALAT retention", program,
        tuple(traced), verify, ("IA64_OP_LDFE", "IA64_OP_CHK_A"),
    )


def fp_advanced_unsupported_case(memory_attribute: int) -> RuntimeCase:
    if memory_attribute not in (4, 5, 6):
        raise ValueError("LDFE.A unsupported case requires MA4/5/6")
    virtual = 0x8000
    physical = 0x2000
    bundles: List[object] = [
        _movl_bundle(0x10, 2,
                     _mapped_pte(physical, memory_attribute)),
        _movl_bundle(0x20, 7, virtual),
    ]
    address = _append_dtc_install(bundles, 0x30)
    fault_ip = address
    fault_raw = floating_load(
        "IA64_OP_LDFE", attr="a", f1=20, r3=7,
        update="imm", imm=8,
    )
    traced: List[int] = []
    _append_m(bundles, address, fault_raw, traced)
    bundles.append(H._exception_vector_spin(
        IA64_UNSUPPORTED_DATA_REFERENCE_VECTOR
    ))
    program = H.Program(
        name="LDFE.A MA{} unsupported reference".format(memory_attribute),
        bundles=tuple(bundles),
        terminal_ip=IA64_UNSUPPORTED_DATA_REFERENCE_VECTOR,
        data=(H.DataWord(physical, 0x8877665544332211, 8),
              H.DataWord(physical + 8, 0xC123, 2)),
    )

    def verify(snapshot) -> str:
        H._require(
            snapshot.exception_pending and
            snapshot.exception_kind == "unsupported-data-reference" and
            snapshot.exception_vector ==
                IA64_UNSUPPORTED_DATA_REFERENCE_VECTOR and
            snapshot.exception_source == fault_ip and
            snapshot.exception_address == virtual and
            snapshot.cr_iip == fault_ip and snapshot.cr_ifa == virtual and
            snapshot.cr_isr == H.IA64_ISR_R,
            "LDFE.A MA{} did not raise exact Unsupported".format(
                memory_attribute),
        )
        H._require(snapshot.gr[7] == virtual,
                   "LDFE.A Unsupported retired its update")
        H._require(snapshot.slot_valid and snapshot.slot_ip == fault_ip and
                   snapshot.slot_ri == 0 and
                   snapshot.slot_type == H.IA64_SLOT_TYPE_M and
                   snapshot.slot_raw == (fault_raw & H.SLOT_MASK),
                   "LDFE.A Unsupported lost exact fault-slot publication")
        return "LDFE.A MA{} raised WB-only Unsupported".format(
            memory_attribute)

    return RuntimeCase(
        "LDFE.A MA{} WB-only Unsupported".format(memory_attribute),
        program, tuple(traced), verify, ("IA64_OP_LDFE",), True,
    )


def integer_speculative_nat_page_defer_case(width: int) -> RuntimeCase:
    if width not in (1, 2, 4, 8):
        raise ValueError("integer speculative width must be 1, 2, 4, or 8")
    virtual = 0x8000
    physical = 0x2000
    old_s = 0x1111000000000000 | width
    old_sa = 0x2222000000000000 | width
    bundles: List[object] = [
        _movl_bundle(0x10, 2, _mapped_pte(physical, 7)),
        _movl_bundle(0x20, 7, virtual),
        _movl_bundle(0x30, 8, virtual),
        _movl_bundle(0x40, 20, old_s),
        _movl_bundle(0x50, 21, old_sa),
    ]
    traced: List[int] = []
    address = _append_dtc_install(bundles, 0x60)
    address = _append_m(
        bundles, address,
        integer_load(width, "s", r1=20, r3=7,
                     update="imm", imm=width), traced,
    )
    address = _append_m(
        bundles, address,
        integer_load(width, "sa", r1=21, r3=8,
                     update="imm", imm=2 * width), traced,
    )
    first_check = address
    second_check = first_check + 0x40
    terminal = second_check + 0x40
    bundles.extend((
        H.Bundle(first_check, 0x01,
                 _chk_s_branch(first_check, first_check + 0x20, reg=20),
                 H.nop_i(), H.nop_i()),
        _marker_bundle(first_check + 0x10, 30, 0xBAD, terminal),
        _marker_bundle(first_check + 0x20, 30, 1, second_check),
        H.Bundle(second_check, 0x01,
                 _chk_a_branch(second_check, second_check + 0x20, reg=21),
                 H.nop_i(), H.nop_i()),
        _marker_bundle(second_check + 0x10, 31, 0xBAD, terminal),
        _marker_bundle(second_check + 0x20, 31, 2, terminal),
        H.spin_bundle(terminal),
    ))
    traced.extend((first_check, second_check))
    program = H.Program(
        name="LD{}.S/SA NaTPage deferral and checked recovery".format(width),
        bundles=tuple(bundles), terminal_ip=terminal,
        data=(H.DataWord(physical, 0x8877665544332211, 8),),
    )

    def verify(snapshot) -> str:
        label = "LD{}.S/SA NaTPage deferral".format(width)
        _no_exception(snapshot, label)
        H._require(snapshot.gr[7] == virtual + width and
                   snapshot.gr[8] == virtual + 2 * width,
                   label + " did not retire exact base updates")
        H._require((snapshot.nat_low & ((1 << 20) | (1 << 21))) ==
                   ((1 << 20) | (1 << 21)),
                   label + " did not set both destination NaTs")
        H._require((snapshot.gr[30], snapshot.gr[31]) == (1, 2),
                   label + " missed CHK.S or absent-entry CHK.A recovery")
        return (
            "LD{0}.S/SA deferred NaTPage, retired updates, set NaTs, and "
            "took CHK.S plus CHK.A recovery; NaT payloads are unconstrained"
            .format(
                width
            )
        )

    return RuntimeCase(
        "LD{}.S/SA NaTPage deferral and recovery".format(width),
        program, tuple(traced), verify,
        ("IA64_OP_LD{}S".format(width),
         "IA64_OP_LD{}SA".format(width),
         "IA64_OP_CHK_S", "IA64_OP_CHK_A"),
    )


def _require_speculative_immediate_fault(
        snapshot, *, label: str, fault_ip: int, fault_raw: int,
        address: int, kind: str, vector: int, old_target: int,
        expected_isr: Optional[int] = None) -> None:
    if expected_isr is None:
        expected_isr = H.IA64_ISR_R | IA64_ISR_SP
    H._require(
        snapshot.ip == vector and snapshot.exception_pending and
        snapshot.exception_kind == kind and
        snapshot.exception_vector == vector,
        "{} did not reach vector 0x{:x}".format(label, vector),
    )
    H._require(
        snapshot.exception_source == fault_ip and
        snapshot.exception_address == address and
        snapshot.cr_iip == fault_ip and snapshot.cr_ifa == address and
        snapshot.cr_isr == expected_isr,
        "{} expected source/address/IIP/IFA/ISR "
        "0x{:x}/0x{:x}/0x{:x}/0x{:x}/0x{:x}, got "
        "0x{:x}/0x{:x}/0x{:x}/0x{:x}/0x{:x}".format(
            label, fault_ip, address, fault_ip, address, expected_isr,
            snapshot.exception_source, snapshot.exception_address,
            snapshot.cr_iip, snapshot.cr_ifa, snapshot.cr_isr,
        ),
    )
    H._require(
        snapshot.slot_valid and snapshot.slot_ip == fault_ip and
        snapshot.slot_ri == 0 and
        snapshot.slot_type == H.IA64_SLOT_TYPE_M and
        snapshot.slot_raw == (fault_raw & H.SLOT_MASK),
        label + " lost exact fault-slot publication",
    )
    H._require(
        snapshot.gr[7] == address and snapshot.gr[20] == old_target and
        not (snapshot.nat_low & (1 << 20)),
        label + " retired its base update or destination state",
    )


def integer_speculative_translation_miss_case(
        width: int, memory_class: str) -> RuntimeCase:
    if width not in (1, 2, 4, 8) or memory_class not in ("s", "sa"):
        raise ValueError("translation-miss case requires ld1/2/4/8.s or .sa")
    virtual = 0x8000
    old_target = 0x5100000000000000 | (width << 4) | (memory_class == "sa")
    bundles: List[object] = list(H._interruption_collection_setup())
    bundles.extend((
        _movl_bundle(0x30, 7, virtual),
        _movl_bundle(0x40, 20, old_target),
        H.Bundle(0x50, 0x01, H.ssm(H.IA64_PSR_DT),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x60, 0x01, H.srlz_d(), H.nop_i(), H.nop_i()),
    ))
    fault_ip = 0x70
    fault_raw = integer_load(
        width, memory_class, r1=20, r3=7,
        update="imm", imm=width,
    )
    _append_m(bundles, fault_ip, fault_raw, [], trace=False)
    bundles.append(H._exception_vector_spin(H.IA64_ALTERNATE_DATA_TLB_VECTOR))
    program = H.Program(
        name="LD{}.{} no-recovery translated miss".format(
            width, memory_class.upper()),
        bundles=tuple(bundles),
        terminal_ip=H.IA64_ALTERNATE_DATA_TLB_VECTOR,
    )

    def verify(snapshot) -> str:
        label = "LD{}.{} translated miss".format(width, memory_class.upper())
        _require_speculative_immediate_fault(
            snapshot, label=label, fault_ip=fault_ip, fault_raw=fault_raw,
            address=virtual, kind="alternate-data-tlb-miss",
            vector=H.IA64_ALTERNATE_DATA_TLB_VECTOR,
            old_target=old_target,
        )
        return (label + " raised exact R|SP Alternate Data TLB and "
                "suppressed destination/update retirement")

    return RuntimeCase(
        "LD{}.{} immediate translated miss".format(
            width, memory_class.upper()),
        program, (fault_ip,), verify,
        ("IA64_OP_LD{}{}".format(width, memory_class.upper()),), True,
    )


def integer_speculative_unaligned_case(
        width: int, memory_class: str, *, deferred_nat_page: bool) -> RuntimeCase:
    if width not in (2, 4, 8) or memory_class not in ("s", "sa"):
        raise ValueError("unaligned case requires ld2/4/8.s or .sa")
    physical = 0x2000
    address = 0x8001 if deferred_nat_page else physical + 1
    old_target = 0x5200000000000000 | (width << 4) | (memory_class == "sa")
    if deferred_nat_page:
        bundles = [
            _movl_bundle(0x10, 2, _mapped_pte(physical, 7)),
            _movl_bundle(0x20, 7, address),
            _movl_bundle(0x30, 20, old_target),
        ]
        next_ip = _append_dtc_install(bundles, 0x40)
    else:
        bundles = list(H._interruption_collection_setup())
        bundles.extend((
            _movl_bundle(0x30, 7, address),
            _movl_bundle(0x40, 20, old_target),
        ))
        next_ip = 0x50
    bundles.extend((
        H.Bundle(next_ip, 0x01, H.ssm(IA64_PSR_AC),
                 H.nop_i(), H.nop_i()),
        H.Bundle(next_ip + 0x10, 0x01, H.srlz_d(),
                 H.nop_i(), H.nop_i()),
    ))
    fault_ip = next_ip + 0x20
    fault_raw = integer_load(
        width, memory_class, r1=20, r3=7,
        update="imm", imm=width,
    )
    _append_m(bundles, fault_ip, fault_raw, [], trace=False)
    bundles.append(H._exception_vector_spin(
        IA64_UNALIGNED_DATA_REFERENCE_VECTOR
    ))
    condition = "deferred NaTPage plus " if deferred_nat_page else ""
    program = H.Program(
        name="LD{}.{} no-recovery {}unaligned reference".format(
            width, memory_class.upper(), condition),
        bundles=tuple(bundles),
        terminal_ip=IA64_UNALIGNED_DATA_REFERENCE_VECTOR,
        data=(H.DataWord(physical, 0x8877665544332211, 8),),
    )

    def verify(snapshot) -> str:
        label = "LD{}.{} {}unaligned".format(
            width, memory_class.upper(), condition)
        _require_speculative_immediate_fault(
            snapshot, label=label, fault_ip=fault_ip, fault_raw=fault_raw,
            address=address, kind="unaligned-data-reference",
            vector=IA64_UNALIGNED_DATA_REFERENCE_VECTOR,
            old_target=old_target,
        )
        H._require(snapshot.cr_ipsr & IA64_PSR_AC,
                   label + " did not collect active PSR.ac")
        if deferred_nat_page:
            H._require(snapshot.cr_ipsr & H.IA64_PSR_DT,
                       label + " did not collect active PSR.dt")
        return (label + " raised exact R|SP Unaligned Data Reference and "
                "suppressed destination/update retirement")

    return RuntimeCase(
        "LD{}.{} immediate {}Unaligned".format(
            width, memory_class.upper(), condition),
        program, (fault_ip,), verify,
        ("IA64_OP_LD{}{}".format(width, memory_class.upper()),), True,
    )


def _append_indexed_system_write(
        bundles: List[object], address: int, *, x6: int,
        index: int, value: int) -> int:
    bundles.extend((
        _movl_bundle(address, 8, index),
        _movl_bundle(address + 0x10, 9, value),
        H.Bundle(address + 0x20, 0x01, _m_system(x6, r2=9, r3=8),
                 H.nop_i(), H.nop_i()),
        H.Bundle(address + 0x30, 0x01, H.srlz_d(),
                 H.nop_i(), H.nop_i()),
    ))
    return address + 0x40


def _append_rfi_state(
        bundles: List[object], address: int, psr: int) -> int:
    resume = address + 0x50
    bundles.extend((
        _movl_bundle(address, 5, psr),
        _movl_bundle(address + 0x10, 6, resume),
        H.Bundle(address + 0x20, 0x01,
                 H.mov_grcr(H.IA64_CR_IPSR, 5), H.nop_i(), H.nop_i()),
        H.Bundle(address + 0x30, 0x01,
                 H.mov_grcr(H.IA64_CR_IIP, 6), H.nop_i(), H.nop_i()),
        H.Bundle(address + 0x40, 0x11,
                 H.nop_m(), H.nop_i(), H.rfi()),
    ))
    return resume


def _append_short_vhpt_configuration(
        bundles: List[object], address: int) -> int:
    """Enable a test-owned 32-KiB short-format VHPT for region zero."""
    rr = 1 | (12 << 2)
    pta = 1 | (15 << 2)
    address = _append_indexed_system_write(
        bundles, address, x6=0x00, index=0, value=rr,
    )
    bundles.extend((
        _movl_bundle(address, 9, pta),
        H.Bundle(address + 0x10, 0x01,
                 H.mov_grcr(IA64_CR_PTA, 9), H.nop_i(), H.nop_i()),
        H.Bundle(address + 0x20, 0x01,
                 H.srlz_d(), H.nop_i(), H.nop_i()),
    ))
    return address + 0x30


def _short_vhpt_iha(address: int) -> int:
    """Apply Intel's short-format hash for PTA.size=15 and RR.ps=12."""
    mask = (1 << 15) - 1
    vhpt_offset = ((address & 0x0007FFFFFFFFFFFF) >> 12) << 3
    return vhpt_offset & mask


def integer_speculative_vhpt_fault_case(
        width: int, memory_class: str, condition: str) -> RuntimeCase:
    if width not in (1, 2, 4, 8) or memory_class not in ("s", "sa"):
        raise ValueError("VHPT case requires ld1/2/4/8.s or .sa")
    if condition not in ("invalid-entry", "missing-backing"):
        raise ValueError("unknown VHPT condition " + condition)

    virtual = 0x8000
    iha = _short_vhpt_iha(virtual)
    old_target = (0x5500000000000000 | (width << 4) |
                  int(memory_class == "sa"))
    entry = 0x10000
    bundles: List[object] = [
        _movl_bundle(entry, 7, virtual),
        _movl_bundle(entry + 0x10, 20, old_target),
    ]
    address = entry + 0x20
    data: Tuple[object, ...] = ()
    if condition == "invalid-entry":
        # Map the walker backing page but supply an architecturally invalid
        # short-format leaf.  The walker must finish and select Data TLB.
        bundles.extend((
            _movl_bundle(address, 2, _mapped_pte(0, 0)),
            _movl_bundle(address + 0x10, 8, 0),
        ))
        address = _append_dtc_install(
            bundles, address + 0x20, virtual_reg=8,
            enable_translation=False,
        )
        data = (H.DataWord(iha, 0x3, 8),)
        kind = "data-tlb-miss"
        vector = IA64_DATA_TLB_VECTOR
    else:
        # With no DTC entry for IHA, the walker's own lookup must select the
        # non-recursive VHPT Translation vector.
        kind = "vhpt-translation"
        vector = IA64_VHPT_TRANSLATION_VECTOR

    address = _append_short_vhpt_configuration(bundles, address)
    psr = H.IA64_PSR_IC | H.IA64_PSR_DT
    fault_ip = _append_rfi_state(bundles, address, psr)
    fault_raw = integer_load(
        width, memory_class, r1=20, r3=7,
        update="imm", imm=width,
    )
    _append_m(bundles, fault_ip, fault_raw, [], trace=False)
    bundles.append(H._exception_vector_spin(vector))
    label = "LD{}.{} {}".format(
        width, memory_class.upper(), condition)
    program = H.Program(
        name=label + " no-recovery VHPT selection",
        bundles=tuple(bundles), terminal_ip=vector,
        data=data, entry=entry,
    )

    def verify(snapshot) -> str:
        _require_speculative_immediate_fault(
            snapshot, label=label, fault_ip=fault_ip, fault_raw=fault_raw,
            address=virtual, kind=kind, vector=vector,
            old_target=old_target,
        )
        H._require(
            snapshot.cr_iha == iha and snapshot.cr_itir == 12 << 2,
            "{} expected IHA/ITIR 0x{:x}/0x{:x}, got 0x{:x}/0x{:x}"
            .format(
                label, iha, 12 << 2, snapshot.cr_iha, snapshot.cr_itir,
            ),
        )
        H._require((snapshot.cr_ipsr & psr) == psr and
                   not (snapshot.cr_ipsr & IA64_PSR_IT),
                   label + " did not collect the no-recovery PSR model")
        return (label + " selected exact {} vector with original IFA, "
                "short-format IHA/ITIR, R|SP ISR, and no load/update "
                "retirement".format(kind))

    return RuntimeCase(
        label + " immediate " + kind, program, (fault_ip,), verify,
        ("IA64_OP_LD{}{}".format(width, memory_class.upper()),), True,
    )


def integer_speculative_dm_recovery_case(
        width: int, memory_class: str, fault_class: str,
        control: str) -> RuntimeCase:
    if width not in (1, 2, 4, 8) or memory_class not in ("s", "sa"):
        raise ValueError("DCR.dm case requires ld1/2/4/8.s or .sa")
    if fault_class not in ("alternate", "invalid-entry", "missing-backing"):
        raise ValueError("unknown DCR.dm fault class " + fault_class)
    if control not in ("defer", "dm-clear", "ed-clear"):
        raise ValueError("unknown DCR.dm control " + control)

    virtual = 0x8000
    iha = _short_vhpt_iha(virtual)
    code_page = 0x10000
    itlb_ed = control != "ed-clear"
    dm = control != "dm-clear"
    deferred = itlb_ed and dm
    dcr = IA64_DCR_DM if dm else 0
    old_target = (0x5600000000000000 | (width << 4) |
                  int(memory_class == "sa"))
    bundles: List[object] = [
        _movl_bundle(code_page, 7, virtual),
        _movl_bundle(code_page + 0x10, 20, old_target),
    ]
    address = code_page + 0x20
    data: Tuple[object, ...] = ()

    if fault_class == "invalid-entry":
        bundles.extend((
            _movl_bundle(address, 2, _mapped_pte(0, 0)),
            _movl_bundle(address + 0x10, 8, 0),
        ))
        address = _append_dtc_install(
            bundles, address + 0x20, virtual_reg=8,
            enable_translation=False,
        )
        data = (H.DataWord(iha, 0x3, 8),)
        kind = "data-tlb-miss"
        vector = IA64_DATA_TLB_VECTOR
    elif fault_class == "missing-backing":
        kind = "vhpt-translation"
        vector = IA64_VHPT_TRANSLATION_VECTOR
    else:
        kind = "alternate-data-tlb-miss"
        vector = H.IA64_ALTERNATE_DATA_TLB_VECTOR

    if fault_class == "alternate":
        address = _append_indexed_system_write(
            bundles, address, x6=0x00, index=0, value=12 << 2,
        )
    else:
        address = _append_short_vhpt_configuration(bundles, address)

    handler_page = vector & ~0xFFF
    bundles.extend((
        _movl_bundle(address, 2, _mapped_pte(handler_page, 0)),
        _movl_bundle(address + 0x10, 11, handler_page),
    ))
    address = _append_itc_install(
        bundles, address + 0x20, pte_reg=2, virtual_reg=11,
    )

    code_pte = _mapped_pte(code_page, 0)
    if itlb_ed:
        code_pte |= 1 << 52
    bundles.extend((
        _movl_bundle(address, 2, code_pte),
        _movl_bundle(address + 0x10, 10, code_page),
    ))
    address = _append_itc_install(
        bundles, address + 0x20, pte_reg=2, virtual_reg=10,
    )
    bundles.extend((
        _movl_bundle(address, 9, dcr),
        H.Bundle(address + 0x10, 0x01,
                 H.mov_grcr(IA64_CR_DCR, 9), H.nop_i(), H.nop_i()),
        H.Bundle(address + 0x20, 0x01,
                 H.srlz_d(), H.nop_i(), H.nop_i()),
    ))
    address += 0x30
    psr = H.IA64_PSR_IC | H.IA64_PSR_DT | IA64_PSR_IT
    fault_ip = _append_rfi_state(bundles, address, psr)
    fault_raw = integer_load(
        width, memory_class, r1=20, r3=7,
        update="imm", imm=width,
    )
    _append_m(bundles, fault_ip, fault_raw, [], trace=False)
    label = "LD{}.{} DCR.dm {} {}".format(
        width, memory_class.upper(), fault_class, control)

    if deferred:
        check_ip = fault_ip + 0x10
        recovery = check_ip + 0x20
        terminal = check_ip + 0x50
        check_raw = (_chk_s_branch(check_ip, recovery, reg=20)
                     if memory_class == "s" else
                     _chk_a_branch(check_ip, recovery, reg=20))
        bundles.extend((
            H.Bundle(check_ip, 0x01, check_raw, H.nop_i(), H.nop_i()),
            _marker_bundle(check_ip + 0x10, 30, 0xBAD, terminal),
            H.Bundle(recovery, 0x01,
                     H.mov_crgr(31, IA64_CR_DCR), H.nop_i(), H.nop_i()),
            _marker_bundle(recovery + 0x10, 30, 1, terminal),
            H.spin_bundle(terminal),
        ))
        trace_ips = (fault_ip, check_ip)
    else:
        bundles.append(H._exception_vector_spin(vector))
        terminal = vector
        trace_ips = (fault_ip,)

    program = H.Program(
        name=label, bundles=tuple(bundles), terminal_ip=terminal,
        data=data, entry=code_page,
    )

    def verify(snapshot) -> str:
        if deferred:
            _no_exception(snapshot, label)
            H._require(snapshot.ip == terminal,
                       label + " did not reach recovery terminal")
            H._require(snapshot.gr[7] == virtual + width and
                       (snapshot.nat_low & (1 << 20)) != 0,
                       label + " did not retire update plus destination NaT")
            H._require(snapshot.gr[30] == 1 and snapshot.gr[31] == IA64_DCR_DM,
                       label + " missed checked recovery or active DCR.dm")
            H._require((snapshot.psr & psr) == psr,
                       label + " lost active recovery-model controls")
            return (label + " deferred to destination NaT, retired the exact "
                    "base update, and took checked recovery")

        expected_isr = H.IA64_ISR_R | IA64_ISR_SP
        if itlb_ed:
            expected_isr |= IA64_ISR_ED
        _require_speculative_immediate_fault(
            snapshot, label=label, fault_ip=fault_ip, fault_raw=fault_raw,
            address=virtual, kind=kind, vector=vector,
            old_target=old_target, expected_isr=expected_isr,
        )
        H._require((snapshot.cr_ipsr & psr) == psr,
                   label + " lost active translated-code controls")
        if fault_class != "alternate":
            H._require(snapshot.cr_iha == iha and
                       snapshot.cr_itir == 12 << 2,
                       label + " lost exact short-format IHA/ITIR")
        return (label + " raised exact {} with ISR.ed={} and no load/update "
                "retirement".format(kind, int(itlb_ed)))

    opcodes = ["IA64_OP_LD{}{}".format(width, memory_class.upper())]
    if deferred:
        opcodes.append("IA64_OP_CHK_S" if memory_class == "s" else
                       "IA64_OP_CHK_A")
    return RuntimeCase(
        label, program, trace_ips, verify, tuple(opcodes), not deferred,
    )


def integer_speculative_dcr_recovery_case(
        width: int, memory_class: str, condition: str,
        control: str) -> RuntimeCase:
    if width not in (1, 2, 4, 8) or memory_class not in ("s", "sa"):
        raise ValueError("DCR case requires ld1/2/4/8.s or .sa")
    conditions = {
        "page-not-present": (
            IA64_DCR_DP, "page-fault", IA64_PAGE_FAULT_VECTOR),
        "key-miss": (
            IA64_DCR_DK, "data-key-miss", IA64_DATA_KEY_MISS_VECTOR),
        "key-permission": (
            IA64_DCR_DX, "key-permission", IA64_KEY_PERMISSION_VECTOR),
        "access-rights": (
            IA64_DCR_DR, "data-access-rights",
            IA64_DATA_ACCESS_RIGHTS_VECTOR),
        "access-bit": (
            IA64_DCR_DA, "data-access-bit", IA64_DATA_ACCESS_BIT_VECTOR),
        "data-debug": (
            IA64_DCR_DD, "data-debug", IA64_DATA_DEBUG_VECTOR),
    }
    if condition not in conditions:
        raise ValueError("unknown DCR condition " + condition)
    if control not in ("defer", "dcr-clear", "ed-clear"):
        raise ValueError("unknown DCR control " + control)

    dcr_bit, kind, vector = conditions[condition]
    virtual = 0x8000
    physical = 0x2000
    code_page = 0x10000
    key = 0x123
    itir = 12 << 2
    pte = _mapped_pte(physical, 0)
    psr = H.IA64_PSR_IC | H.IA64_PSR_DT | IA64_PSR_IT
    pkrs: Tuple[Tuple[int, int], ...] = ()
    if condition == "page-not-present":
        pte = physical
    elif condition == "key-miss":
        itir |= key << 8
        psr |= IA64_PSR_PK
        pkrs = ((0, 1),)
    elif condition == "key-permission":
        itir |= key << 8
        psr |= IA64_PSR_PK
        pkrs = ((0, 1), (1, (key << 8) | 1 | (1 << 2)))
    elif condition == "access-rights":
        psr |= 3 << 32
    elif condition == "access-bit":
        pte &= ~(1 << 5)
    else:
        psr |= IA64_PSR_DB

    itlb_ed = control != "ed-clear"
    dcr_enabled = control != "dcr-clear"
    deferred = itlb_ed and dcr_enabled
    dcr = dcr_bit if dcr_enabled else 0
    old_target = (0x5700000000000000 | (width << 4) |
                  int(memory_class == "sa"))
    bundles: List[object] = [
        _movl_bundle(code_page, 2, pte),
        _movl_bundle(code_page + 0x10, 7, virtual),
        _movl_bundle(code_page + 0x20, 20, old_target),
    ]
    address = _append_dtc_install(
        bundles, code_page + 0x30, itir=itir,
        enable_translation=False,
    )
    for index, value in pkrs:
        address = _append_indexed_system_write(
            bundles, address, x6=0x03, index=index, value=value,
        )
    if condition == "data-debug":
        debug_control = ((1 << 63) | (1 << 56) |
                         0x00FFFFFFFFFFFFFF)
        address = _append_indexed_system_write(
            bundles, address, x6=0x01, index=0, value=virtual,
        )
        address = _append_indexed_system_write(
            bundles, address, x6=0x01, index=1, value=debug_control,
        )

    handler_page = vector & ~0xFFF
    bundles.extend((
        _movl_bundle(address, 2, _mapped_pte(handler_page, 0)),
        _movl_bundle(address + 0x10, 11, handler_page),
    ))
    address = _append_itc_install(
        bundles, address + 0x20, pte_reg=2, virtual_reg=11,
    )
    code_pte = _mapped_pte(code_page, 0)
    if condition == "access-rights":
        code_pte |= 3 << 7
    if itlb_ed:
        code_pte |= 1 << 52
    bundles.extend((
        _movl_bundle(address, 2, code_pte),
        _movl_bundle(address + 0x10, 10, code_page),
    ))
    address = _append_itc_install(
        bundles, address + 0x20, pte_reg=2, virtual_reg=10,
    )
    bundles.extend((
        _movl_bundle(address, 9, dcr),
        H.Bundle(address + 0x10, 0x01,
                 H.mov_grcr(IA64_CR_DCR, 9), H.nop_i(), H.nop_i()),
        H.Bundle(address + 0x20, 0x01,
                 H.srlz_d(), H.nop_i(), H.nop_i()),
        H.Bundle(address + 0x30, 0x01,
                 H.mov_crgr(31, IA64_CR_DCR), H.nop_i(), H.nop_i()),
    ))
    fault_ip = _append_rfi_state(bundles, address + 0x40, psr)
    fault_raw = integer_load(
        width, memory_class, r1=20, r3=7,
        update="imm", imm=width,
    )
    _append_m(bundles, fault_ip, fault_raw, [], trace=False)
    label = "LD{}.{} DCR {} {}".format(
        width, memory_class.upper(), condition, control)

    if deferred:
        check_ip = fault_ip + 0x10
        recovery = check_ip + 0x20
        terminal = check_ip + 0x50
        check_raw = (_chk_s_branch(check_ip, recovery, reg=20)
                     if memory_class == "s" else
                     _chk_a_branch(check_ip, recovery, reg=20))
        bundles.extend((
            H.Bundle(check_ip, 0x01, check_raw, H.nop_i(), H.nop_i()),
            _marker_bundle(check_ip + 0x10, 30, 0xBAD, terminal),
            H.Bundle(recovery, 0x01,
                     H.nop_m(), H.nop_i(), H.nop_i()),
            _marker_bundle(recovery + 0x10, 30, 1, terminal),
            H.spin_bundle(terminal),
        ))
        trace_ips = (fault_ip, check_ip)
    else:
        bundles.append(H._exception_vector_spin(vector))
        terminal = vector
        trace_ips = (fault_ip,)

    program = H.Program(
        name=label, bundles=tuple(bundles), terminal_ip=terminal,
        data=(H.DataWord(physical, 0x8877665544332211, 8),),
        entry=code_page,
    )

    def verify(snapshot) -> str:
        if deferred:
            _no_exception(snapshot, label)
            H._require(snapshot.ip == terminal,
                       label + " did not reach recovery terminal")
            H._require(snapshot.gr[7] == virtual + width and
                       (snapshot.nat_low & (1 << 20)) != 0,
                       label + " did not retire update plus destination NaT")
            H._require(snapshot.gr[30] == 1 and
                       snapshot.gr[31] == dcr_bit,
                       label + " missed checked recovery or exact DCR bit")
            H._require((snapshot.psr & psr) == psr,
                       label + " lost active recovery-model controls")
            return (label + " deferred to destination NaT, retired the exact "
                    "base update, and took checked recovery")

        expected_isr = H.IA64_ISR_R | IA64_ISR_SP
        if itlb_ed:
            expected_isr |= IA64_ISR_ED
        _require_speculative_immediate_fault(
            snapshot, label=label, fault_ip=fault_ip, fault_raw=fault_raw,
            address=virtual, kind=kind, vector=vector,
            old_target=old_target, expected_isr=expected_isr,
        )
        H._require((snapshot.cr_ipsr & psr) == psr,
                   label + " lost active translated-code controls")
        return (label + " raised exact {} with ISR.ed={} and no load/update "
                "retirement".format(kind, int(itlb_ed)))

    opcodes = ["IA64_OP_LD{}{}".format(width, memory_class.upper())]
    if deferred:
        opcodes.append("IA64_OP_CHK_S" if memory_class == "s" else
                       "IA64_OP_CHK_A")
    return RuntimeCase(
        label, program, trace_ips, verify, tuple(opcodes), not deferred,
    )


def integer_speculative_always_defer_case(
        width: int, memory_class: str, condition: str) -> RuntimeCase:
    """Exercise the complete integer PSR.ic=0 Table 5-4 fault set."""
    if width not in (1, 2, 4, 8) or memory_class not in ("s", "sa"):
        raise ValueError("PSR.ic=0 case requires ld1/2/4/8.s or .sa")
    conditions = {
        "alternate": (
            "alternate-data-tlb-miss", H.IA64_ALTERNATE_DATA_TLB_VECTOR),
        "invalid-entry": ("data-tlb-miss", IA64_DATA_TLB_VECTOR),
        "missing-backing": (
            "vhpt-translation", IA64_VHPT_TRANSLATION_VECTOR),
        "page-not-present": ("page-fault", IA64_PAGE_FAULT_VECTOR),
        "key-miss": ("data-key-miss", IA64_DATA_KEY_MISS_VECTOR),
        "key-permission": ("key-permission", IA64_KEY_PERMISSION_VECTOR),
        "access-rights": (
            "data-access-rights", IA64_DATA_ACCESS_RIGHTS_VECTOR),
        "access-bit": ("data-access-bit", IA64_DATA_ACCESS_BIT_VECTOR),
        "data-debug": ("data-debug", IA64_DATA_DEBUG_VECTOR),
        "unaligned": (
            "unaligned-data-reference", IA64_UNALIGNED_DATA_REFERENCE_VECTOR),
    }
    if condition not in conditions:
        raise ValueError("unknown PSR.ic=0 condition " + condition)
    if condition == "unaligned" and width == 1:
        raise ValueError("ld1 cannot form a naturally unaligned reference")

    kind, vector = conditions[condition]
    virtual = 0x8000
    physical = 0x2000
    code_page = 0x10000
    translated = condition != "unaligned"
    load_address = virtual if translated else physical + 1
    key = 0x123
    itir = 12 << 2
    pte = _mapped_pte(physical, 0)
    psr = H.IA64_PSR_DT if translated else IA64_PSR_AC
    pkrs: Tuple[Tuple[int, int], ...] = ()
    if condition == "page-not-present":
        pte = physical
    elif condition == "key-miss":
        itir |= key << 8
        psr |= IA64_PSR_PK
        pkrs = ((0, 1),)
    elif condition == "key-permission":
        itir |= key << 8
        psr |= IA64_PSR_PK
        pkrs = ((0, 1), (1, (key << 8) | 1 | (1 << 2)))
    elif condition == "access-rights":
        psr |= 3 << 32
    elif condition == "access-bit":
        pte &= ~(1 << 5)
    elif condition == "data-debug":
        psr |= IA64_PSR_DB

    old_target = (0x5800000000000000 | (width << 4) |
                  int(memory_class == "sa"))
    bundles: List[object] = [
        _movl_bundle(code_page, 7, load_address),
        _movl_bundle(code_page + 0x10, 20, old_target),
    ]
    address = code_page + 0x20
    data: List[object] = [
        H.DataWord(physical, 0x8877665544332211, 8),
    ]

    if condition == "alternate":
        # RR.ve=0 makes a missing DTC entry select Alternate Data TLB.
        address = _append_indexed_system_write(
            bundles, address, x6=0x00, index=0, value=12 << 2,
        )
    elif condition in ("invalid-entry", "missing-backing"):
        if condition == "invalid-entry":
            # The walker backing page is mapped, but its short-format leaf is
            # invalid, so the ultimate condition is Data TLB rather than VHPT.
            bundles.extend((
                _movl_bundle(address, 2, _mapped_pte(0, 0)),
                _movl_bundle(address + 0x10, 8, 0),
            ))
            address = _append_dtc_install(
                bundles, address + 0x20, virtual_reg=8,
                enable_translation=False,
            )
            data.append(H.DataWord(_short_vhpt_iha(virtual), 0x3, 8))
        address = _append_short_vhpt_configuration(bundles, address)
    elif condition != "unaligned":
        bundles.append(_movl_bundle(address, 2, pte))
        address = _append_dtc_install(
            bundles, address + 0x10, itir=itir, enable_translation=False,
        )
        for index, value in pkrs:
            address = _append_indexed_system_write(
                bundles, address, x6=0x03, index=index, value=value,
            )
        if condition == "data-debug":
            debug_control = ((1 << 63) | (1 << 56) |
                             0x00FFFFFFFFFFFFFF)
            address = _append_indexed_system_write(
                bundles, address, x6=0x01, index=0, value=virtual,
            )
            address = _append_indexed_system_write(
                bundles, address, x6=0x01, index=1, value=debug_control,
            )

    # DCR is explicitly zero.  Reading it back before a possible CPL3 RFI
    # keeps the recovery path completely unprivileged.
    bundles.extend((
        _movl_bundle(address, 9, 0),
        H.Bundle(address + 0x10, 0x01,
                 H.mov_grcr(IA64_CR_DCR, 9), H.nop_i(), H.nop_i()),
        H.Bundle(address + 0x20, 0x01,
                 H.srlz_d(), H.nop_i(), H.nop_i()),
        H.Bundle(address + 0x30, 0x01,
                 H.mov_crgr(31, IA64_CR_DCR), H.nop_i(), H.nop_i()),
    ))
    fault_ip = _append_rfi_state(bundles, address + 0x40, psr)
    fault_raw = integer_load(
        width, memory_class, r1=20, r3=7,
        update="imm", imm=width,
    )
    _append_m(bundles, fault_ip, fault_raw, [], trace=False)
    check_ip = fault_ip + 0x10
    recovery = check_ip + 0x20
    terminal = check_ip + 0x50
    check_raw = (_chk_s_branch(check_ip, recovery, reg=20)
                 if memory_class == "s" else
                 _chk_a_branch(check_ip, recovery, reg=20))
    bundles.extend((
        H.Bundle(check_ip, 0x01, check_raw, H.nop_i(), H.nop_i()),
        _marker_bundle(check_ip + 0x10, 30, 0xBAD, terminal),
        H.Bundle(recovery, 0x01, H.nop_m(), H.nop_i(), H.nop_i()),
        _marker_bundle(recovery + 0x10, 30, 1, terminal),
        H.spin_bundle(terminal),
        # If the load interrupts instead of deferring, the exact expected
        # vector is still a stable diagnostic terminal for the fixture.
        H._exception_vector_spin(vector),
    ))
    label = "LD{}.{} PSR.ic=0 {}".format(
        width, memory_class.upper(), condition)
    program = H.Program(
        name=label, bundles=tuple(bundles), terminal_ip=terminal,
        data=tuple(data), entry=code_page,
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, label)
        H._require(snapshot.ip == terminal,
                   label + " did not reach checked-recovery terminal")
        H._require(snapshot.gr[7] == load_address + width and
                   (snapshot.nat_low & (1 << 20)) != 0,
                   label + " did not retire update plus destination NaT")
        H._require(snapshot.gr[30] == 1 and snapshot.gr[31] == 0,
                   label + " missed checked recovery or exact zero DCR")
        H._require(not (snapshot.psr & H.IA64_PSR_IC) and
                   (snapshot.psr & psr) == psr,
                   label + " lost the PSR.ic=0 always-defer controls")
        return (label + " deferred without interruption, retired the exact "
                "base update, and took checked recovery for " + kind)

    return RuntimeCase(
        label, program, (fault_ip, check_ip), verify,
        ("IA64_OP_LD{}{}".format(width, memory_class.upper()),
         "IA64_OP_CHK_S" if memory_class == "s" else "IA64_OP_CHK_A"),
    )


def integer_speculative_software_defer_case(
        width: int, memory_class: str, condition: str) -> RuntimeCase:
    """Exercise PSR.ed on every applicable integer Table 5-4 condition."""
    if width not in (1, 2, 4, 8) or memory_class not in ("s", "sa"):
        raise ValueError("PSR.ed case requires ld1/2/4/8.s or .sa")
    conditions = {
        "success": (True, None),
        "base-nat": (False, H.IA64_REGISTER_NAT_CONSUMPTION_VECTOR),
        "unimplemented": (False, IA64_ILLEGAL_OPERATION_VECTOR),
        "alternate": (True, H.IA64_ALTERNATE_DATA_TLB_VECTOR),
        "invalid-entry": (True, IA64_DATA_TLB_VECTOR),
        "missing-backing": (True, IA64_VHPT_TRANSLATION_VECTOR),
        "page-not-present": (True, IA64_PAGE_FAULT_VECTOR),
        "nat-page": (True, IA64_DATA_NAT_PAGE_VECTOR),
        "key-miss": (True, IA64_DATA_KEY_MISS_VECTOR),
        "key-permission": (True, IA64_KEY_PERMISSION_VECTOR),
        "access-rights": (True, IA64_DATA_ACCESS_RIGHTS_VECTOR),
        "access-bit": (True, IA64_DATA_ACCESS_BIT_VECTOR),
        "data-debug": (True, IA64_DATA_DEBUG_VECTOR),
        "unaligned": (False, IA64_UNALIGNED_DATA_REFERENCE_VECTOR),
    }
    if condition not in conditions:
        raise ValueError("unknown PSR.ed condition " + condition)
    if condition == "unaligned" and width == 1:
        raise ValueError("ld1 cannot form a naturally unaligned reference")

    translated, diagnostic_vector = conditions[condition]
    virtual = 0x8000
    safe_virtual = 0x9000
    physical = 0x2000
    safe_physical = 0x3000
    if condition == "unimplemented":
        load_address = 1 << 50
    elif condition == "unaligned":
        load_address = physical + 1
    else:
        load_address = virtual if translated else physical
    # The fixture executes the post-ED control load through a translated WB
    # page.  Physical-mode data is LIMITED speculation and would itself defer.
    safe_address = safe_virtual
    code_page = 0x10000
    key = 0x123
    itir = 12 << 2
    pte = _mapped_pte(physical, 0)
    safe_pte = _mapped_pte(safe_physical, 0)
    psr = H.IA64_PSR_IC | IA64_PSR_ED
    if translated:
        psr |= H.IA64_PSR_DT
    pkrs: Tuple[Tuple[int, int], ...] = ()
    if condition == "page-not-present":
        pte = physical
    elif condition == "nat-page":
        pte = _mapped_pte(physical, 7)
    elif condition == "key-miss":
        itir |= key << 8
        psr |= IA64_PSR_PK
        pkrs = ((0, 1),)
    elif condition == "key-permission":
        itir |= key << 8
        psr |= IA64_PSR_PK
        pkrs = ((0, 1), (1, (key << 8) | 1 | (1 << 2)))
    elif condition == "access-rights":
        psr |= 3 << 32
        safe_pte |= 3 << 7
    elif condition == "access-bit":
        pte &= ~(1 << 5)
    elif condition == "data-debug":
        psr |= IA64_PSR_DB
    elif condition == "unaligned":
        psr |= IA64_PSR_AC

    old_target = (0x5900000000000000 | (width << 4) |
                  int(memory_class == "sa"))
    old_safe_target = (0x5A00000000000000 | (width << 4) |
                       int(memory_class == "sa"))
    data: List[object] = [
        H.DataWord(physical, 0x8877665544332211, 8),
        H.DataWord(safe_physical, 0x1122334455667788, 8),
    ]
    bundles: List[object] = []
    address = code_page
    if condition == "base-nat":
        # LD8.FILL imports UNAT[0] into r7 while retaining a test-owned base.
        bundles.extend((
            H.Bundle(address, 0x03, H.nop_m(), H.adds(1, 1, 0),
                     H.adds(2, 0x1000, 0)),
            H.Bundle(address + 0x10, 0x01,
                     H.mov_m_grar(36, 1), H.nop_i(), H.nop_i()),
            H.Bundle(address + 0x20, 0x01,
                     H.ld8_fill(7, 2), H.nop_i(), H.nop_i()),
        ))
        data.append(H.DataWord(0x1000, load_address, 8))
        address += 0x30
    else:
        bundles.append(_movl_bundle(address, 7, load_address))
        address += 0x10
    bundles.extend((
        _movl_bundle(address, 8, safe_address),
        _movl_bundle(address + 0x10, 20, old_target),
        _movl_bundle(address + 0x20, 21, old_safe_target),
    ))
    address += 0x30

    if condition == "alternate":
        address = _append_indexed_system_write(
            bundles, address, x6=0x00, index=0, value=12 << 2,
        )
    elif condition in ("invalid-entry", "missing-backing"):
        if condition == "invalid-entry":
            bundles.extend((
                _movl_bundle(address, 2, _mapped_pte(0, 0)),
                _movl_bundle(address + 0x10, 9, 0),
            ))
            address = _append_dtc_install(
                bundles, address + 0x20, virtual_reg=9,
                enable_translation=False,
            )
            data.append(H.DataWord(_short_vhpt_iha(virtual), 0x3, 8))
        address = _append_short_vhpt_configuration(bundles, address)
    elif translated:
        bundles.append(_movl_bundle(address, 2, pte))
        address = _append_dtc_install(
            bundles, address + 0x10, itir=itir,
            enable_translation=False,
        )

    # Indexed RR/PKR/DBR setup uses r8 as its architectural index operand.
    # Restore the test-owned safe VA both before installing its DTC entry and
    # after the final indexed write so the control load cannot accidentally
    # exercise a scratch address.
    bundles.extend((
        _movl_bundle(address, 8, safe_address),
        _movl_bundle(address + 0x10, 2, safe_pte),
    ))
    address = _append_dtc_install(
        bundles, address + 0x20, virtual_reg=8,
        enable_translation=False,
    )
    for index, value in pkrs:
        address = _append_indexed_system_write(
            bundles, address, x6=0x03, index=index, value=value,
        )
    if condition == "data-debug":
        debug_control = ((1 << 63) | (1 << 56) |
                         0x00FFFFFFFFFFFFFF)
        address = _append_indexed_system_write(
            bundles, address, x6=0x01, index=0, value=virtual,
        )
        address = _append_indexed_system_write(
            bundles, address, x6=0x01, index=1, value=debug_control,
        )

    bundles.append(_movl_bundle(address, 8, safe_address))
    address += 0x10

    if condition == "success" and memory_class == "sa":
        # Establish the exact address/target ALAT entry which forced .sa must
        # purge even though it performs no memory reference.
        bundles.extend((
            H.Bundle(address, 0x01,
                     H.ssm(H.IA64_PSR_DT), H.nop_i(), H.nop_i()),
            H.Bundle(address + 0x10, 0x01,
                     H.srlz_d(), H.nop_i(), H.nop_i()),
            H.Bundle(address + 0x20, 0x01,
                     integer_load(width, "a", r1=20, r3=7),
                     H.nop_i(), H.nop_i()),
            H.Bundle(address + 0x30, 0x01,
                     H.rsm(H.IA64_PSR_DT), H.nop_i(), H.nop_i()),
            H.Bundle(address + 0x40, 0x01,
                     H.srlz_d(), H.nop_i(), H.nop_i()),
        ))
        address += 0x50

    bundles.extend((
        _movl_bundle(address, 9, 0),
        H.Bundle(address + 0x10, 0x01,
                 H.mov_grcr(IA64_CR_DCR, 9), H.nop_i(), H.nop_i()),
        H.Bundle(address + 0x20, 0x01,
                 H.srlz_d(), H.nop_i(), H.nop_i()),
        H.Bundle(address + 0x30, 0x01,
                 H.mov_crgr(31, IA64_CR_DCR), H.nop_i(), H.nop_i()),
    ))
    forced_ip = _append_rfi_state(bundles, address + 0x40, psr)
    forced_raw = integer_load(
        width, memory_class, r1=20, r3=7,
        update="imm", imm=width,
    )
    _append_m(bundles, forced_ip, forced_raw, [], trace=False)
    check_ip = forced_ip + 0x10
    recovery = check_ip + 0x20
    check_raw = (_chk_s_branch(check_ip, recovery, reg=20)
                 if memory_class == "s" else
                 _chk_a_branch(check_ip, recovery, reg=20))
    safe_raw = integer_load(width, memory_class, r1=21, r3=8)
    recovery_bundles: List[object] = []
    if translated:
        safe_ip = recovery
    else:
        recovery_bundles.extend((
            H.Bundle(recovery, 0x01,
                     H.ssm(H.IA64_PSR_DT), H.nop_i(), H.nop_i()),
            H.Bundle(recovery + 0x10, 0x01,
                     H.srlz_d(), H.nop_i(), H.nop_i()),
        ))
        safe_ip = recovery + 0x20
    terminal = safe_ip + 0x30
    recovery_bundles.extend((
        H.Bundle(safe_ip, 0x01, safe_raw, H.nop_i(), H.nop_i()),
        _marker_bundle(safe_ip + 0x10, 30, 1, terminal),
        H.spin_bundle(terminal),
    ))
    bundles.extend((
        H.Bundle(check_ip, 0x01, check_raw, H.nop_i(), H.nop_i()),
        _marker_bundle(check_ip + 0x10, 30, 0xBAD, terminal),
        *recovery_bundles,
    ))
    if diagnostic_vector is not None:
        bundles.append(H._exception_vector_spin(diagnostic_vector))
    label = "LD{}.{} PSR.ed {}".format(
        width, memory_class.upper(), condition)
    program = H.Program(
        name=label, bundles=tuple(bundles), terminal_ip=terminal,
        data=tuple(data), entry=code_page,
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, label)
        H._require(snapshot.ip == terminal and snapshot.gr[30] == 1,
                   label + " did not reach checked-recovery terminal")
        H._require(snapshot.gr[7] == load_address + width and
                   (snapshot.nat_low & (1 << 20)) != 0,
                   label + " did not retire update plus destination NaT")
        H._require(bool(snapshot.nat_low & (1 << 7)) ==
                   (condition == "base-nat"),
                   label + " did not preserve the exact base NaT state")
        safe_mask = ((1 << (width * 8)) - 1
                     if width != 8 else (1 << 64) - 1)
        H._require(snapshot.gr[21] ==
                   (0x1122334455667788 & safe_mask) and
                   not (snapshot.nat_low & (1 << 21)),
                   label + " did not consume PSR.ed before the safe load")
        expected_psr = ((psr & ~IA64_PSR_ED) |
                        (0 if translated else H.IA64_PSR_DT))
        H._require((snapshot.psr & IA64_PSR_ED) == 0 and
                   (snapshot.psr & expected_psr) == expected_psr and
                   snapshot.gr[31] == 0,
                   label + " lost one-shot PSR.ed or exact zero DCR state")
        return (label + " forced NaT without interruption or data access, "
                "retired the update, took checked recovery, cleared ED, and "
                "executed the following safe load normally")

    return RuntimeCase(
        label, program, (forced_ip, check_ip, safe_ip), verify,
        ("IA64_OP_LD{}{}".format(width, memory_class.upper()),
         "IA64_OP_CHK_S" if memory_class == "s" else "IA64_OP_CHK_A"),
    )


def _successful_speculation_fixture(
        width: int, attribute: str) -> Tuple[int, int, int, List[object]]:
    """Return address, physical backing, next IP, and class-specific setup."""
    if width not in (1, 2, 4, 8):
        raise ValueError("successful speculation requires ld1/2/4/8")
    if attribute not in ("speculative", "limited", "non-speculative"):
        raise ValueError("unknown speculation attribute " + attribute)
    virtual = 0x8000
    physical = 0x2000
    entry = 0x10000
    load_address = physical if attribute == "limited" else virtual
    bundles: List[object] = [
        _movl_bundle(entry, 7, load_address),
        _movl_bundle(entry + 0x10, 8, load_address),
        _movl_bundle(entry + 0x20, 20, 0x6A00000000000000 | width),
        _movl_bundle(entry + 0x30, 22, 0x6B00000000000000 | width),
    ]
    address = entry + 0x40
    if attribute == "limited":
        bundles.extend((
            H.Bundle(address, 0x01, H.ssm(H.IA64_PSR_IC),
                     H.nop_i(), H.nop_i()),
            H.Bundle(address + 0x10, 0x01, H.srlz_i(),
                     H.nop_i(), H.nop_i()),
        ))
        address += 0x20
    else:
        memory_attribute = 0 if attribute == "speculative" else 4
        bundles.append(_movl_bundle(
            address, 2, _mapped_pte(physical, memory_attribute)))
        address = _append_dtc_install(bundles, address + 0x10)
    return load_address, physical, address, bundles


def successful_integer_speculative_load_case(
        width: int, memory_class: str, attribute: str) -> RuntimeCase:
    """Exercise every Table 4-14 integer result across speculation classes."""
    if memory_class not in ("s", "a", "sa"):
        raise ValueError("successful load case requires .s, .a, or .sa")
    load_address, physical, load_ip, bundles = \
        _successful_speculation_fixture(width, attribute)
    load_raw = integer_load(
        width, memory_class, r1=20, r3=7,
        update="imm", imm=width,
    )
    bundles.append(H.Bundle(
        load_ip, 0x01, load_raw, H.nop_i(), H.nop_i()))
    check_ip = load_ip + 0x10
    recovery = check_ip + 0x20
    check_raw = (_chk_s_branch(check_ip, recovery, reg=20)
                 if memory_class == "s" else
                 _chk_a_branch(check_ip, recovery, reg=20))
    terminal = check_ip + 0x40
    bundles.extend((
        H.Bundle(check_ip, 0x01, check_raw, H.nop_i(), H.nop_i()),
        _marker_bundle(check_ip + 0x10, 30, 1, terminal),
        _marker_bundle(recovery, 30, 2, terminal),
        H.spin_bundle(terminal),
    ))
    label = "LD{}.{} {} result".format(
        width, memory_class.upper(), attribute)
    program = H.Program(
        name=label, bundles=tuple(bundles), terminal_ip=terminal,
        data=(H.DataWord(physical, 0x8877665544332211, 8),),
        entry=0x10000,
    )

    returns_value = (attribute == "speculative" or
                     (attribute == "limited" and memory_class == "a"))
    returns_zero = attribute == "non-speculative" and memory_class == "a"
    fails_control = (memory_class in ("s", "sa") and
                     attribute != "speculative")

    def verify(snapshot) -> str:
        _no_exception(snapshot, label)
        H._require(snapshot.ip == terminal and
                   snapshot.gr[7] == load_address + width,
                   label + " did not reach terminal with the exact update")
        mask = ((1 << (width * 8)) - 1
                if width != 8 else (1 << 64) - 1)
        if returns_value:
            H._require(snapshot.gr[20] ==
                       (0x8877665544332211 & mask) and
                       not (snapshot.nat_low & (1 << 20)),
                       label + " did not return the exact memory value")
        elif returns_zero:
            H._require(snapshot.gr[20] == 0 and
                       not (snapshot.nat_low & (1 << 20)),
                       label + " did not return advanced-load failure zero")
        else:
            H._require(snapshot.nat_low & (1 << 20),
                       label + " did not return a deferred NaT token")
        if memory_class == "s":
            expected_marker = 2 if fails_control else 1
            H._require(snapshot.gr[30] == expected_marker,
                       label + " CHK.S selected the wrong edge")
        elif fails_control or returns_zero:
            H._require(snapshot.gr[30] == 2,
                       label + " unexpectedly exposed an ALAT entry")
        else:
            H._require(snapshot.gr[30] in (1, 2),
                       label + " produced an impossible CHK.A edge")
        expected_psr = H.IA64_PSR_IC
        if attribute != "limited":
            expected_psr |= H.IA64_PSR_DT
        H._require((snapshot.psr & expected_psr) == expected_psr,
                   label + " lost its class-selecting PSR controls")
        return (label + " matched Table 4-14 value/NaT/update semantics; "
                "CHK.A accepted the architecture-permitted hit or miss")

    opcode = "IA64_OP_LD{}{}".format(width, memory_class.upper())
    return RuntimeCase(
        label, program, (load_ip, check_ip), verify,
        (opcode, "IA64_OP_CHK_S" if memory_class == "s" else
         "IA64_OP_CHK_A"),
    )


def successful_integer_check_load_case(
        width: int, check_class: str, attribute: str,
        initial_entry: str) -> RuntimeCase:
    """Exercise exact-match and clean-miss Table 4-17 check-load behavior."""
    if check_class not in ("c.clr", "c.clr.acq", "c.nc"):
        raise ValueError("unknown integer check-load class " + check_class)
    if initial_entry not in ("hit", "miss"):
        raise ValueError("check-load initial entry must be hit or miss")
    if attribute == "non-speculative" and initial_entry == "hit":
        raise ValueError("non-speculative ALAT-hit behavior is undefined")
    load_address, physical, address, bundles = \
        _successful_speculation_fixture(width, attribute)
    traced: List[int] = []
    if initial_entry == "hit":
        advanced_ip = address
        address = _append_m(
            bundles, address,
            integer_load(width, "a", r1=20, r3=7), traced,
        )
        bundles.append(H.Bundle(
            address, 0x03, H.nop_m(), H.adds(22, 0, 20), H.nop_i()))
        address += 0x10
    else:
        advanced_ip = None
    check_ip = address
    address = _append_m(
        bundles, address,
        integer_load(
            width, check_class, r1=20, r3=8,
            update="imm", imm=width,
        ), traced,
    )
    branch_ip = address
    recovery = branch_ip + 0x20
    terminal = branch_ip + 0x40
    bundles.extend((
        H.Bundle(branch_ip, 0x01,
                 _chk_a_branch(branch_ip, recovery, reg=20),
                 H.nop_i(), H.nop_i()),
        _marker_bundle(branch_ip + 0x10, 30, 1, terminal),
        _marker_bundle(recovery, 30, 2, terminal),
        H.spin_bundle(terminal),
    ))
    traced.append(branch_ip)
    label = "LD{}.{} {} {}".format(
        width, check_class.upper(), attribute, initial_entry)
    program = H.Program(
        name=label, bundles=tuple(bundles), terminal_ip=terminal,
        data=(H.DataWord(physical, 0x8877665544332211, 8),),
        entry=0x10000,
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, label)
        mask = ((1 << (width * 8)) - 1
                if width != 8 else (1 << 64) - 1)
        expected = 0x8877665544332211 & mask
        H._require(snapshot.ip == terminal and
                   snapshot.gr[20] == expected and
                   not (snapshot.nat_low & (1 << 20)) and
                   snapshot.gr[8] == load_address + width,
                   label + " lost exact value, NaT, update, or terminal")
        if initial_entry == "hit":
            H._require(snapshot.gr[22] == expected,
                       label + " did not establish the exact advanced value")
        guaranteed_absent = (
            initial_entry == "miss" and
            (check_class != "c.nc" or attribute == "non-speculative")
        )
        if guaranteed_absent:
            H._require(snapshot.gr[30] == 2,
                       label + " allocated a forbidden ALAT entry")
        else:
            H._require(snapshot.gr[30] in (1, 2),
                       label + " produced an impossible CHK.A edge")
        return (label + " returned the exact value and update; its following "
                "CHK.A matched mandatory absence or permitted ALAT optionality")

    opcodes = ["IA64_OP_LD{}C_{}".format(
        width, "NC" if check_class == "c.nc" else "CLR"),
        "IA64_OP_CHK_A"]
    if advanced_ip is not None:
        opcodes.insert(0, "IA64_OP_LD{}A".format(width))
    return RuntimeCase(
        label, program, tuple(traced), verify, tuple(opcodes),
    )


def integer_speculative_protection_fault_case(
        width: int, memory_class: str, condition: str) -> RuntimeCase:
    if width not in (1, 2, 4, 8) or memory_class not in ("s", "sa"):
        raise ValueError("protection case requires ld1/2/4/8.s or .sa")
    virtual = 0x8000
    physical = 0x2000
    normal_pte = _mapped_pte(physical, 0)
    key = 0x123
    itir = 12 << 2
    psr = H.IA64_PSR_IC | H.IA64_PSR_DT
    pkrs: Tuple[Tuple[int, int], ...] = ()
    if condition == "page-not-present":
        pte = physical
        kind = "page-fault"
        vector = IA64_PAGE_FAULT_VECTOR
    elif condition == "key-miss":
        pte = normal_pte
        itir |= key << 8
        psr |= IA64_PSR_PK
        pkrs = ((0, 1),)
        kind = "data-key-miss"
        vector = IA64_DATA_KEY_MISS_VECTOR
    elif condition == "key-permission":
        pte = normal_pte
        itir |= key << 8
        psr |= IA64_PSR_PK
        valid_key = (key << 8) | 1
        pkrs = ((0, 1), (1, valid_key | (1 << 2)))
        kind = "key-permission"
        vector = IA64_KEY_PERMISSION_VECTOR
    elif condition == "access-rights":
        pte = normal_pte
        psr |= 3 << 32
        kind = "data-access-rights"
        vector = IA64_DATA_ACCESS_RIGHTS_VECTOR
    elif condition == "access-bit":
        pte = normal_pte & ~(1 << 5)
        kind = "data-access-bit"
        vector = IA64_DATA_ACCESS_BIT_VECTOR
    else:
        raise ValueError("unknown protection condition " + condition)

    old_target = (0x5300000000000000 | (width << 4) |
                  int(memory_class == "sa"))
    bundles: List[object] = [
        _movl_bundle(0x10, 2, pte),
        _movl_bundle(0x20, 7, virtual),
        _movl_bundle(0x30, 20, old_target),
    ]
    next_ip = _append_dtc_install(
        bundles, 0x40, itir=itir, enable_translation=False)
    for index, value in pkrs:
        next_ip = _append_indexed_system_write(
            bundles, next_ip, x6=0x03, index=index, value=value,
        )
    fault_ip = _append_rfi_state(bundles, next_ip, psr)
    fault_raw = integer_load(
        width, memory_class, r1=20, r3=7,
        update="imm", imm=width,
    )
    _append_m(bundles, fault_ip, fault_raw, [], trace=False)
    bundles.append(H._exception_vector_spin(vector))
    label = "LD{}.{} {}".format(
        width, memory_class.upper(), condition)
    program = H.Program(
        name=label + " no-recovery fault",
        bundles=tuple(bundles), terminal_ip=vector,
        data=(H.DataWord(physical, 0x8877665544332211, 8),),
    )

    def verify(snapshot) -> str:
        _require_speculative_immediate_fault(
            snapshot, label=label, fault_ip=fault_ip, fault_raw=fault_raw,
            address=virtual, kind=kind, vector=vector,
            old_target=old_target,
        )
        H._require((snapshot.cr_ipsr & psr) == psr,
                   label + " did not collect its exact active PSR controls")
        return (label + " raised exact R|SP immediate fault and suppressed "
                "destination/update retirement")

    return RuntimeCase(
        label + " immediate fault", program, (fault_ip,), verify,
        ("IA64_OP_LD{}{}".format(width, memory_class.upper()),), True,
    )


def integer_speculative_data_debug_case(
        width: int, memory_class: str, condition: str) -> RuntimeCase:
    if width not in (1, 2, 4, 8) or memory_class not in ("s", "sa"):
        raise ValueError("Data Debug case requires ld1/2/4/8.s or .sa")
    if condition == "unaligned" and width == 1:
        raise ValueError("one-byte load cannot be unaligned")
    if condition not in ("aligned", "unaligned", "deferred-nat-page"):
        raise ValueError("unknown Data Debug condition " + condition)
    physical = 0x4000
    translated = condition == "deferred-nat-page"
    address = 0x8000 if translated else physical
    if condition == "unaligned":
        address += 1
    old_target = (0x5400000000000000 | (width << 4) |
                  int(memory_class == "sa"))
    if translated:
        bundles: List[object] = [
            _movl_bundle(0x10, 2, _mapped_pte(physical, 7)),
            _movl_bundle(0x20, 7, address),
            _movl_bundle(0x30, 20, old_target),
        ]
        next_ip = _append_dtc_install(
            bundles, 0x40, enable_translation=False)
    else:
        bundles = [
            _movl_bundle(0x10, 7, address),
            _movl_bundle(0x20, 20, old_target),
        ]
        next_ip = 0x30
    debug_control = ((1 << 63) | (1 << 56) |
                     0x00FFFFFFFFFFFFFF)
    next_ip = _append_indexed_system_write(
        bundles, next_ip, x6=0x01, index=0, value=address,
    )
    next_ip = _append_indexed_system_write(
        bundles, next_ip, x6=0x01, index=1, value=debug_control,
    )
    psr = H.IA64_PSR_IC | IA64_PSR_DB
    if translated:
        psr |= H.IA64_PSR_DT
    if condition == "unaligned":
        psr |= IA64_PSR_AC
    fault_ip = _append_rfi_state(bundles, next_ip, psr)
    fault_raw = integer_load(
        width, memory_class, r1=20, r3=7,
        update="imm", imm=width,
    )
    _append_m(bundles, fault_ip, fault_raw, [], trace=False)
    bundles.append(H._exception_vector_spin(IA64_DATA_DEBUG_VECTOR))
    label = "LD{}.{} Data Debug ({})".format(
        width, memory_class.upper(), condition)
    program = H.Program(
        name=label + " no-recovery fault",
        bundles=tuple(bundles), terminal_ip=IA64_DATA_DEBUG_VECTOR,
        data=(H.DataWord(physical, 0x8877665544332211, 8),),
    )

    def verify(snapshot) -> str:
        _require_speculative_immediate_fault(
            snapshot, label=label, fault_ip=fault_ip, fault_raw=fault_raw,
            address=address, kind="data-debug",
            vector=IA64_DATA_DEBUG_VECTOR, old_target=old_target,
        )
        H._require((snapshot.cr_ipsr & psr) == psr,
                   label + " did not collect its exact active PSR controls")
        return (label + " raised exact R|SP before access/update retirement")

    return RuntimeCase(
        label + " immediate fault", program, (fault_ip,), verify,
        ("IA64_OP_LD{}{}".format(width, memory_class.upper()),), True,
    )


def fp_speculative_nat_page_defer_case() -> RuntimeCase:
    virtual = 0x8000
    physical = 0x2000
    bundles: List[object] = [
        _movl_bundle(0x10, 2, _mapped_pte(physical, 7)),
        _movl_bundle(0x20, 7, virtual),
        _movl_bundle(0x30, 8, virtual),
    ]
    traced: List[int] = []
    address = _append_dtc_install(bundles, 0x40)
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDFE", attr="s", f1=20, r3=7,
                      update="imm", imm=8), traced,
    )
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDFE", attr="sa", f1=21, r3=8,
                      update="imm", imm=16), traced,
    )
    first_check = address
    second_check = first_check + 0x40
    terminal = second_check + 0x40
    bundles.extend((
        H.Bundle(first_check, 0x01,
                 _chk_s_branch(first_check, first_check + 0x20,
                               reg=20, fp=True),
                 H.nop_i(), H.nop_i()),
        _marker_bundle(first_check + 0x10, 30, 0xBAD, terminal),
        _marker_bundle(first_check + 0x20, 30, 1, second_check),
        H.Bundle(second_check, 0x01,
                 _chk_s_branch(second_check, second_check + 0x20,
                               reg=21, fp=True),
                 H.nop_i(), H.nop_i()),
        _marker_bundle(second_check + 0x10, 31, 0xBAD, terminal),
        _marker_bundle(second_check + 0x20, 31, 2, terminal),
        H.spin_bundle(terminal),
    ))
    traced.extend((first_check, second_check))
    program = H.Program(
        name="LDFE.S/SA NaTPage NatVal deferral and updates",
        bundles=tuple(bundles), terminal_ip=terminal,
        data=(H.DataWord(physical, 0x8877665544332211, 8),
              H.DataWord(physical + 8, 0xC123, 2)),
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, "FP NaTPage speculative deferral")
        H._require(snapshot.gr[7] == virtual + 8 and
                   snapshot.gr[8] == virtual + 16,
                   "LDFE.S/SA deferral did not retire base updates")
        H._require((snapshot.gr[30], snapshot.gr[31]) == (1, 2),
                   "CHK.S did not observe both deferred FP NatVals")
        return ("LDFE.S and LDFE.SA deferred NaTPage to NatVal and retired "
                "their immediate updates")

    return RuntimeCase(
        "LDFE.S/SA NaTPage NatVal deferral", program, tuple(traced), verify,
        ("IA64_OP_LDFE", "IA64_OP_CHK_S"),
    )


def reserved_width_illegal_case(opcode: str) -> RuntimeCase:
    reserved = {
        "IA64_OP_LD1FILL", "IA64_OP_LD2FILL", "IA64_OP_LD4FILL",
        "IA64_OP_ST1SPILL", "IA64_OP_ST2SPILL", "IA64_OP_ST4SPILL",
    }
    if opcode not in reserved:
        raise ValueError("not a decoder-reserved fill/spill width")
    fault_ip = 0x30
    fault_raw = primary_encoding(opcode, qp=0)
    bundles: List[object] = [
        *H._interruption_collection_setup(),
        H.Bundle(fault_ip, 0x01, fault_raw, H.nop_i(), H.nop_i()),
        H._exception_vector_spin(IA64_ILLEGAL_OPERATION_VECTOR),
    ]
    program = H.Program(
        name=opcode + " true-predicate precise Illegal Operation",
        bundles=tuple(bundles), terminal_ip=IA64_ILLEGAL_OPERATION_VECTOR,
    )

    def verify(snapshot) -> str:
        H._require(
            snapshot.ip == IA64_ILLEGAL_OPERATION_VECTOR and
            snapshot.exception_pending and
            snapshot.exception_kind == "illegal-operation" and
            snapshot.exception_vector == IA64_ILLEGAL_OPERATION_VECTOR and
            snapshot.exception_source == fault_ip and
            snapshot.exception_address == fault_ip and
            snapshot.cr_iip == fault_ip and snapshot.cr_isr == 0,
            opcode + " did not raise a precise collected Illegal Operation",
        )
        H._require(snapshot.slot_valid and snapshot.slot_ip == fault_ip and
                   snapshot.slot_ri == 0 and
                   snapshot.slot_type == H.IA64_SLOT_TYPE_M and
                   snapshot.slot_raw == (fault_raw & H.SLOT_MASK),
                   opcode + " lost its exact reserved M-slot image")
        H._require(snapshot.unat == 0 and snapshot.nat_low == 0 and
                   snapshot.gr[20] == 0,
                   opcode + " changed memory-side architectural state")
        return opcode + " true predicate raised exact Illegal Operation"

    return RuntimeCase(
        opcode.removeprefix("IA64_OP_").lower() +
        " true-predicate reserved Illegal", program, (), verify,
        (opcode,), True,
    )


def _require_nonaccess_fault(snapshot, *, fault_ip: int, fault_raw: int,
                             address: int, kind: str, vector: int,
                             base_code: int, subcode: int) -> None:
    expected_isr = H.IA64_ISR_R | IA64_ISR_NA | base_code | subcode
    H._require(
        snapshot.ip == vector and snapshot.exception_pending and
        snapshot.exception_kind == kind and
        snapshot.exception_vector == vector,
        "{} did not reach vector 0x{:x}".format(kind, vector),
    )
    H._require(
        snapshot.exception_source == fault_ip and
        snapshot.exception_address == address and
        snapshot.cr_ifa == address,
        "{} published source/address/IFA 0x{:x}/0x{:x}/0x{:x}, expected "
        "0x{:x}/0x{:x}".format(
            kind, snapshot.exception_source, snapshot.exception_address,
            snapshot.cr_ifa, fault_ip, address),
    )
    H._require(
        snapshot.cr_isr == expected_isr and snapshot.cr_iip == fault_ip,
        "{} expected ISR/IIP 0x{:x}/0x{:x}, got 0x{:x}/0x{:x}".format(
            kind, expected_isr, fault_ip, snapshot.cr_isr,
            snapshot.cr_iip),
    )
    H._require(
        snapshot.slot_valid and snapshot.slot_ip == fault_ip and
        snapshot.slot_ri == 0 and
        snapshot.slot_type == H.IA64_SLOT_TYPE_M and
        snapshot.slot_raw == (fault_raw & H.SLOT_MASK),
        kind + " lost exact M-slot publication",
    )


def lfetch_nat_fault_case() -> RuntimeCase:
    bundles: List[object] = list(H._interruption_collection_setup())
    traced: List[int] = []
    address = _append_i(
        bundles, 0x30,
        (H.adds(1, 1, 0), H.adds(2, 0x1000, 0)),
    )
    address = _append_m(
        bundles, address, H.mov_m_grar(36, 1), traced, trace=False
    )
    address = _append_m(
        bundles, address, H.ld8_fill(10, 2), traced, trace=False
    )
    fault_ip = address
    fault_raw = lfetch(fault=True, r3=10, update="imm", imm=8)
    address = _append_m(bundles, address, fault_raw, traced)
    bundles.append(H._exception_vector_spin(
        H.IA64_REGISTER_NAT_CONSUMPTION_VECTOR
    ))
    program = H.Program(
        name="lfetch.fault exact address-NaT interruption",
        bundles=tuple(bundles),
        terminal_ip=H.IA64_REGISTER_NAT_CONSUMPTION_VECTOR,
        data=(H.DataWord(0x1000, 0x8000, 8),),
    )

    def verify(snapshot) -> str:
        _require_nonaccess_fault(
            snapshot, fault_ip=fault_ip, fault_raw=fault_raw,
            address=fault_ip, kind="register-nat-consumption",
            vector=H.IA64_REGISTER_NAT_CONSUMPTION_VECTOR,
            base_code=H.IA64_ISR_CODE_REGISTER_NAT_CONSUMPTION,
            subcode=4,
        )
        H._require(snapshot.gr[10] == 0x8000 and
                   (snapshot.nat_low & (1 << 10)),
                   "faulting lfetch consumed or updated its NaT base")
        return "base NaT raised exact R|NA Register-NaT code 0x14 before update"

    return RuntimeCase(
        "lfetch.fault exact base-NaT ISR", program, tuple(traced), verify,
        ("IA64_OP_LFETCH_FAULT",), True,
    )


def lfetch_translation_fault_case() -> RuntimeCase:
    bundles: List[object] = list(H._interruption_collection_setup())
    traced: List[int] = []
    bundles.append(_movl_bundle(0x30, 10, 0x8000))
    bundles.append(H.Bundle(0x40, 0x01, H.ssm(H.IA64_PSR_DT),
                            H.nop_i(), H.nop_i()))
    bundles.append(H.Bundle(0x50, 0x01, H.srlz_i(),
                            H.nop_i(), H.nop_i()))
    fault_ip = 0x60
    fault_raw = lfetch(fault=True, r3=10, update="imm", imm=8)
    _append_m(bundles, fault_ip, fault_raw, traced)
    bundles.append(H._exception_vector_spin(
        H.IA64_ALTERNATE_DATA_TLB_VECTOR
    ))
    program = H.Program(
        name="lfetch.fault exact translated-miss interruption",
        bundles=tuple(bundles),
        terminal_ip=H.IA64_ALTERNATE_DATA_TLB_VECTOR,
    )

    def verify(snapshot) -> str:
        _require_nonaccess_fault(
            snapshot, fault_ip=fault_ip, fault_raw=fault_raw,
            address=0x8000, kind="alternate-data-tlb-miss",
            vector=H.IA64_ALTERNATE_DATA_TLB_VECTOR,
            base_code=0, subcode=4,
        )
        H._require(snapshot.gr[10] == 0x8000 and
                   not (snapshot.nat_low & (1 << 10)),
                   "translated lfetch fault retired its immediate update")
        return "translated miss raised exact R|NA code 4 and suppressed update"

    return RuntimeCase(
        "lfetch.fault exact translated-miss ISR", program, tuple(traced),
        verify, ("IA64_OP_LFETCH_FAULT",), True,
    )


def nat_page_fault_case(opcode: str) -> RuntimeCase:
    if opcode not in ("IA64_OP_FC", "IA64_OP_LFETCH_FAULT"):
        raise ValueError("NaTPage case requires fc or lfetch.fault")
    virtual = 0x8000
    physical = 0x2000
    # P=1, ma=7, A=1, D=1, pl=0, ar=3 on a 4 KiB translation.
    pte = physical | 0x67d
    subcode = 1 if opcode == "IA64_OP_FC" else 4
    fault_raw = (
        cache_control(opcode, reg=7) if opcode == "IA64_OP_FC" else
        lfetch(fault=True, r3=7, update="imm", imm=8)
    )
    bundles: List[object] = [
        _movl_bundle(0x10, 2, pte),
        _movl_bundle(0x20, 7, virtual),
        H.Bundle(0x30, 0x03, H.nop_m(), H.adds(4, 12 << 2, 0),
                 H.nop_i()),
        H.Bundle(0x40, 0x01, H.mov_grcr(H.IA64_CR_IFA, 7),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x50, 0x01, H.mov_grcr(H.IA64_CR_ITIR, 4),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x60, 0x0B, _m_system(0x2e, r2=2),
                 H.nop_m(), H.nop_i()),
        H.Bundle(0x70, 0x01, H.srlz_d(), H.nop_i(), H.nop_i()),
        H.Bundle(0x80, 0x01, H.ssm(H.IA64_PSR_IC | H.IA64_PSR_DT),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x90, 0x01, H.srlz_i(), H.nop_i(), H.nop_i()),
        H.Bundle(0xA0, 0x01, fault_raw, H.nop_i(), H.nop_i()),
        H._exception_vector_spin(H.IA64_REGISTER_NAT_CONSUMPTION_VECTOR),
    ]
    program = H.Program(
        name=opcode + " exact NaTPage interruption",
        bundles=tuple(bundles),
        terminal_ip=H.IA64_REGISTER_NAT_CONSUMPTION_VECTOR,
        data=(H.DataWord(physical, 0xfeedfacecafebeef, 8),),
    )

    def verify(snapshot) -> str:
        _require_nonaccess_fault(
            snapshot, fault_ip=0xA0, fault_raw=fault_raw,
            address=virtual, kind="data-nat-page-consumption",
            vector=H.IA64_REGISTER_NAT_CONSUMPTION_VECTOR,
            base_code=IA64_ISR_CODE_DATA_NAT_PAGE_CONSUMPTION,
            subcode=subcode,
        )
        H._require(snapshot.gr[7] == virtual,
                   opcode + " NaTPage fault retired an address update")
        return ("NaTPage mapping raised exact R|NA data-NaT code 0x{:x} "
                "without a guest read".format(0x20 | subcode))

    label = "fc" if opcode == "IA64_OP_FC" else "lfetch.fault"
    return RuntimeCase(
        label + " exact NaTPage ISR", program, (0xA0,), verify,
        (opcode,), True,
    )


def lfetch_ed_update_case() -> RuntimeCase:
    restored_psr = IA64_PSR_ED | H.IA64_PSR_DT | H.IA64_PSR_IC
    target = 0xD0
    bundles: List[object] = [
        _movl_bundle(0x10, 2, restored_psr),
        _movl_bundle(0x20, 3, target),
        H.Bundle(0x30, 0x01, H.mov_grcr(H.IA64_CR_IPSR, 2),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x40, 0x01, H.mov_grcr(H.IA64_CR_IIP, 3),
                 H.nop_i(), H.nop_i()),
    ]
    traced: List[int] = []
    address = _append_i(
        bundles, 0x50,
        (H.adds(1, 14, 0), H.adds(4, 0x1000, 0),
         H.adds(5, 0x1008, 0), H.adds(6, 0x1010, 0)),
    )
    bundles.append(H.Bundle(
        address, 0x03, H.mov_m_grar(36, 1),
        H.adds(7, 0x1018, 0), H.nop_i(),
    ))
    address += 0x10
    address = _append_m(bundles, address, H.ld8(10, 4), traced, trace=False)
    address = _append_m(
        bundles, address, H.ld8_fill(11, 5), traced, trace=False
    )
    address = _append_m(
        bundles, address, H.ld8_fill(12, 6), traced, trace=False
    )
    address = _append_m(
        bundles, address, H.ld8_fill(13, 7), traced, trace=False
    )
    H._require(address == 0xC0, "lfetch ED setup address drifted")
    bundles.append(H.Bundle(address, 0x11, H.nop_m(), H.nop_i(), H.rfi()))
    address += 0x10
    H._require(address == target, "lfetch ED RFI target drifted")
    address = _append_m(
        bundles, address,
        lfetch(fault=True, r2=11, r3=10, update="reg"), traced,
    )
    address = _append_m(
        bundles, address,
        lfetch(r3=12, update="imm", imm=8), traced,
    )
    fault_ip = address
    fault_raw = lfetch(fault=True, r3=13)
    address = _append_m(bundles, address, fault_raw, traced)
    bundles.append(H._exception_vector_spin(
        H.IA64_REGISTER_NAT_CONSUMPTION_VECTOR
    ))
    program = H.Program(
        name=("lfetch.fault PSR.ed is one-shot while hint updates still "
              "retire"),
        bundles=tuple(bundles),
        terminal_ip=H.IA64_REGISTER_NAT_CONSUMPTION_VECTOR,
        data=(H.DataWord(0x1000, 0x8000, 8),
              H.DataWord(0x1008, 8, 8),
              H.DataWord(0x1010, 0x9000, 8),
              H.DataWord(0x1018, 0xA000, 8)),
    )

    def verify(snapshot) -> str:
        _require_nonaccess_fault(
            snapshot, fault_ip=fault_ip, fault_raw=fault_raw,
            address=fault_ip, kind="register-nat-consumption",
            vector=H.IA64_REGISTER_NAT_CONSUMPTION_VECTOR,
            base_code=H.IA64_ISR_CODE_REGISTER_NAT_CONSUMPTION,
            subcode=4,
        )
        H._require(snapshot.gr[10] == 0x8008 and
                   snapshot.gr[12] == 0x9008,
                   "lfetch updates produced 0x{:x}/0x{:x}".format(
                       snapshot.gr[10], snapshot.gr[12]))
        expected_nat = ((1 << 10) | (1 << 11) | (1 << 12) |
                        (1 << 13))
        H._require((snapshot.nat_low & expected_nat) == expected_nat,
                   "register/immediate lfetch updates lost OR/preserved NaT")
        H._require((snapshot.cr_ipsr & IA64_PSR_ED) == 0,
                   "successful lfetch.fault failed to clear one-shot PSR.ed")
        return ("PSR.ed suppressed one translated miss then cleared; register "
                "update ORed NaT, nonfaulting immediate update preserved NaT, "
                "and the next lfetch.fault consumed its base NaT")

    return RuntimeCase(
        "lfetch.fault one-shot PSR.ed and update retirement", program,
        tuple(traced), verify,
        ("IA64_OP_LFETCH", "IA64_OP_LFETCH_FAULT"), True,
    )


def fc_ed_translation_fault_case() -> RuntimeCase:
    restored_psr = IA64_PSR_ED | H.IA64_PSR_DT | H.IA64_PSR_IC
    target = 0x70
    fault_raw = cache_control("IA64_OP_FC", reg=10)
    bundles: List[object] = [
        _movl_bundle(0x10, 2, restored_psr),
        _movl_bundle(0x20, 3, target),
        _movl_bundle(0x30, 10, 0x8000),
        H.Bundle(0x40, 0x01, H.mov_grcr(H.IA64_CR_IPSR, 2),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x50, 0x01, H.mov_grcr(H.IA64_CR_IIP, 3),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x60, 0x11, H.nop_m(), H.nop_i(), H.rfi()),
        H.Bundle(target, 0x01, fault_raw, H.nop_i(), H.nop_i()),
        H._exception_vector_spin(H.IA64_ALTERNATE_DATA_TLB_VECTOR),
    ]
    program = H.Program(
        name="fc ignores PSR.ed and raises exact translated miss",
        bundles=tuple(bundles),
        terminal_ip=H.IA64_ALTERNATE_DATA_TLB_VECTOR,
    )

    def verify(snapshot) -> str:
        _require_nonaccess_fault(
            snapshot, fault_ip=target, fault_raw=fault_raw,
            address=0x8000, kind="alternate-data-tlb-miss",
            vector=H.IA64_ALTERNATE_DATA_TLB_VECTOR,
            base_code=0, subcode=1,
        )
        H._require(snapshot.cr_ipsr & IA64_PSR_ED,
                   "fc translated miss did not collect the active PSR.ed")
        return "fc ignored PSR.ed and raised exact R|NA translated-miss code 1"

    return RuntimeCase(
        "fc PSR.ed-independent translated miss", program, (target,), verify,
        ("IA64_OP_FC",), True,
    )


def fc_nonaccess_accessed_case() -> RuntimeCase:
    virtual = 0x8000
    physical = 0x2000
    # P=1, ma=0, A=0, D=0, pl=0, ar=7.  FC must not inspect A.
    pte = physical | 1 | (7 << 9)
    fault_raw = cache_control("IA64_OP_FC", reg=7)
    bundles: List[object] = [
        _movl_bundle(0x30, 2, pte),
        _movl_bundle(0x40, 7, virtual),
        H.Bundle(0x50, 0x03, H.nop_m(), H.adds(4, 12 << 2, 0),
                 H.nop_i()),
        H.Bundle(0x60, 0x01, H.mov_grcr(H.IA64_CR_IFA, 7),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x70, 0x01, H.mov_grcr(H.IA64_CR_ITIR, 4),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x80, 0x0B, _m_system(0x2e, r2=2),
                 H.nop_m(), H.nop_i()),
        H.Bundle(0x90, 0x01, H.srlz_d(), H.nop_i(), H.nop_i()),
        H.Bundle(0xA0, 0x01, H.ssm(H.IA64_PSR_DT),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0xB0, 0x01, H.srlz_i(), H.nop_i(), H.nop_i()),
        H.Bundle(0xC0, 0x01, fault_raw, H.nop_i(), H.nop_i()),
        H.spin_bundle(0xD0),
    ]
    program = H.Program(
        name="fc skips the translation accessed bit", bundles=tuple(bundles),
        terminal_ip=0xD0, entry=0x30,
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, "fc A-bit non-access lookup")
        H._require(snapshot.gr[7] == virtual,
                   "fc non-access lookup modified its source")
        return "fc completed through a present read mapping with A=0"

    return RuntimeCase(
        "fc non-access A-bit bypass", program, (0xC0,), verify,
        ("IA64_OP_FC",),
    )


def fc_nonaccess_rights_case() -> RuntimeCase:
    virtual = 0x8000
    physical = 0x2000
    target = 0xF0
    restored_psr = H.IA64_PSR_IC | H.IA64_PSR_DT | (3 << 32)
    # P=1, ma=0, A=1, D=0, pl=0, ar=0: CPL3 cannot read it.
    pte = physical | 1 | (1 << 5)
    fault_raw = cache_control("IA64_OP_FC", reg=7)
    bundles: List[object] = [
        _movl_bundle(0x30, 2, pte),
        _movl_bundle(0x40, 7, virtual),
        _movl_bundle(0x50, 5, restored_psr),
        _movl_bundle(0x60, 6, target),
        H.Bundle(0x70, 0x03, H.nop_m(), H.adds(4, 12 << 2, 0),
                 H.nop_i()),
        H.Bundle(0x80, 0x01, H.mov_grcr(H.IA64_CR_IFA, 7),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x90, 0x01, H.mov_grcr(H.IA64_CR_ITIR, 4),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0xA0, 0x0B, _m_system(0x2e, r2=2),
                 H.nop_m(), H.nop_i()),
        H.Bundle(0xB0, 0x01, H.srlz_d(), H.nop_i(), H.nop_i()),
        H.Bundle(0xC0, 0x01, H.mov_grcr(H.IA64_CR_IPSR, 5),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0xD0, 0x01, H.mov_grcr(H.IA64_CR_IIP, 6),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0xE0, 0x11, H.nop_m(), H.nop_i(), H.rfi()),
        H.Bundle(target, 0x01, fault_raw, H.nop_i(), H.nop_i()),
        H._exception_vector_spin(IA64_DATA_ACCESS_RIGHTS_VECTOR),
    ]
    program = H.Program(
        name="fc non-access lookup enforces read AR above CPL0",
        bundles=tuple(bundles), terminal_ip=IA64_DATA_ACCESS_RIGHTS_VECTOR,
        entry=0x30,
    )

    def verify(snapshot) -> str:
        _require_nonaccess_fault(
            snapshot, fault_ip=target, fault_raw=fault_raw,
            address=virtual, kind="data-access-rights",
            vector=IA64_DATA_ACCESS_RIGHTS_VECTOR,
            base_code=0, subcode=1,
        )
        H._require(((snapshot.cr_ipsr >> 32) & 3) == 3,
                   "fc access-rights fault did not collect CPL3")
        return "fc skipped A/key state but enforced read AR at CPL3"

    return RuntimeCase(
        "fc non-access CPL3 read-rights check", program, (target,), verify,
        ("IA64_OP_FC",), True,
    )


def checked_branch_gr_case() -> RuntimeCase:
    def marker(address: int, reg: int, value: int, target: int) -> object:
        return H.Bundle(
            address, 0x11, H.nop_m(), H.adds(reg, value, 0),
            H.br_cond(address, target),
        )

    bundles: List[object] = []
    traced: List[int] = []
    address = _append_i(
        bundles, 0x10,
        (H.adds(1, 1, 0), H.adds(2, 0x1000, 0)),
    )
    bundles.append(H.Bundle(
        address, 0x03, H.mov_m_grar(36, 1),
        H.adds(13, 0x1800, 0), H.nop_i(),
    ))
    address += 0x10
    address = _append_m(
        bundles, address, H.ld8_fill(10, 2), traced, trace=False
    )
    H._require(address == 0x40, "checked-branch setup address drifted")

    bundles.append(H.Bundle(
        0x40, 0x01, _chk_s_branch(0x40, 0x60, reg=10),
        H.nop_i(), H.nop_i(),
    ))
    traced.append(0x40)
    bundles.extend((
        marker(0x50, 20, 0x51, 0x80),
        marker(0x60, 20, 1, 0x80),
    ))

    _append_m(
        bundles, 0x80, integer_load(8, "a", r1=21, r3=13), traced
    )
    bundles.append(H.Bundle(
        0x90, 0x01, _chk_a_branch(0x90, 0xB0, reg=21),
        H.adds(25, 5, 0), H.nop_i(),
    ))
    traced.append(0x90)
    bundles.extend((
        marker(0xA0, 22, 2, 0xD0),
        marker(0xB0, 22, 0x52, 0x140),
    ))

    bundles.append(H.Bundle(
        0xD0, 0x01,
        _chk_a_branch(0xD0, 0xF0, reg=21, clear=True),
        H.nop_i(), H.nop_i(),
    ))
    traced.append(0xD0)
    bundles.extend((
        marker(0xE0, 23, 3, 0x110),
        marker(0xF0, 23, 0x53, 0x140),
    ))

    bundles.append(H.Bundle(
        0x110, 0x01, _chk_a_branch(0x110, 0x130, reg=21),
        H.nop_i(), H.nop_i(),
    ))
    traced.append(0x110)
    bundles.extend((
        marker(0x120, 24, 0x54, 0x140),
        marker(0x130, 24, 4, 0x140),
        H.spin_bundle(0x140),
    ))
    program = H.Program(
        name="checked GR recovery branches and CHK.A clear lifecycle",
        bundles=tuple(bundles), terminal_ip=0x140,
        data=(H.DataWord(0x1000, 0x777, 8),
              H.DataWord(0x1800, 0x1122334455667788, 8)),
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, "checked GR branches")
        H._require(snapshot.gr[20] == 1,
                   "CHK.S did not take recovery on a GR NaT")
        H._require(snapshot.gr[21] == 0x1122334455667788,
                   "advanced load did not seed the checked ALAT entry")
        H._require((snapshot.gr[22], snapshot.gr[23], snapshot.gr[24]) ==
                   (2, 3, 4),
                   "CHK.A hit/CHK.A.CLR hit/post-clear miss markers were {}"
                   .format(snapshot.gr[22:25]))
        H._require(snapshot.gr[25] == 5,
                   "p0 CHK.A hit skipped its later in-bundle false edge")
        H._require(snapshot.nat_low & (1 << 10),
                   "CHK.S consumed the tested GR NaT")
        return ("CHK.S branched on GR NaT; CHK.A retained a hit, CHK.A.CLR "
                "cleared it, and the following typed GR check branched")

    return RuntimeCase(
        "checked GR branch and ALAT clear semantics", program, tuple(traced),
        verify, ("IA64_OP_CHK_S", "IA64_OP_CHK_A",
                 "IA64_OP_CHK_A_CLR"),
    )


def checked_branch_fr_case() -> RuntimeCase:
    def marker(address: int, reg: int, value: int, target: int) -> object:
        return H.Bundle(
            address, 0x11, H.nop_m(), H.adds(reg, value, 0),
            H.br_cond(address, target),
        )

    bundles: List[object] = []
    traced: List[int] = []
    address = _append_i(
        bundles, 0x10,
        (H.adds(10, 0x1800, 0), H.adds(11, 0x1820, 0)),
    )
    address = _append_m(
        bundles, address,
        floating_load("IA64_OP_LDF_FILL", f1=20, r3=10), traced,
    )
    H._require(address == 0x30, "checked FR setup address drifted")
    bundles.append(H.Bundle(
        0x30, 0x01, _chk_s_branch(0x30, 0x50, reg=20, fp=True),
        H.nop_i(), H.nop_i(),
    ))
    traced.append(0x30)
    bundles.extend((
        marker(0x40, 20, 0x61, 0x70),
        marker(0x50, 20, 1, 0x70),
    ))

    _append_m(
        bundles, 0x70,
        floating_load("IA64_OP_LDFS", f1=21, r3=11, attr="a"), traced,
    )
    bundles.append(H.Bundle(
        0x80, 0x01, _chk_a_branch(0x80, 0xA0, reg=21, fp=True),
        H.nop_i(), H.nop_i(),
    ))
    traced.append(0x80)
    bundles.extend((
        marker(0x90, 22, 2, 0xC0),
        marker(0xA0, 22, 0x62, 0x130),
    ))

    bundles.append(H.Bundle(
        0xC0, 0x01,
        _chk_a_branch(0xC0, 0xE0, reg=21, fp=True, clear=True),
        H.nop_i(), H.nop_i(),
    ))
    traced.append(0xC0)
    bundles.extend((
        marker(0xD0, 23, 3, 0x100),
        marker(0xE0, 23, 0x63, 0x130),
    ))

    bundles.append(H.Bundle(
        0x100, 0x01, _chk_a_branch(0x100, 0x120, reg=21, fp=True),
        H.nop_i(), H.nop_i(),
    ))
    traced.append(0x100)
    bundles.extend((
        marker(0x110, 24, 0x64, 0x130),
        marker(0x120, 24, 4, 0x130),
        H.spin_bundle(0x130),
    ))
    program = H.Program(
        name="checked FR NatVal and typed ALAT clear lifecycle",
        bundles=tuple(bundles), terminal_ip=0x130,
        data=(H.DataWord(0x1800, 0, 8),
              H.DataWord(0x1808, 0x1fffe, 8),
              H.DataWord(0x1820, 0x3fc00000, 4)),
    )

    def verify(snapshot) -> str:
        _no_exception(snapshot, "checked FR branches")
        H._require((snapshot.gr[20], snapshot.gr[22], snapshot.gr[23],
                    snapshot.gr[24]) == (1, 2, 3, 4),
                   "FR NatVal/hit/clear/miss markers were {}".format(
                       (snapshot.gr[20], snapshot.gr[22], snapshot.gr[23],
                        snapshot.gr[24])))
        return ("CHK.S branched on FR NatVal; typed FR CHK.A retained, "
                "cleared, then missed the advanced-load entry")

    return RuntimeCase(
        "checked FR branch and ALAT clear semantics", program, tuple(traced),
        verify, ("IA64_OP_CHK_S", "IA64_OP_CHK_A",
                 "IA64_OP_CHK_A_CLR"),
    )


def checked_branch_disabled_fr_case() -> RuntimeCase:
    fault_ip = 0x50
    fault_raw = _chk_s_branch(fault_ip, 0x60, reg=20, fp=True)
    bundles: List[object] = [
        *H._interruption_collection_setup(),
        H.Bundle(0x30, 0x01, H.ssm(IA64_PSR_DFL),
                 H.nop_i(), H.nop_i()),
        H.Bundle(0x40, 0x01, H.srlz_i(), H.nop_i(), H.nop_i()),
        H.Bundle(fault_ip, 0x01, fault_raw, H.nop_i(), H.nop_i()),
        H._exception_vector_spin(IA64_DISABLED_FP_VECTOR),
    ]
    program = H.Program(
        name="CHK.S FR disabled-partition interruption",
        bundles=tuple(bundles), terminal_ip=IA64_DISABLED_FP_VECTOR,
    )

    def verify(snapshot) -> str:
        H._require(
            snapshot.ip == IA64_DISABLED_FP_VECTOR and
            snapshot.exception_pending and
            snapshot.exception_kind == "disabled-fp-register-low" and
            snapshot.exception_vector == IA64_DISABLED_FP_VECTOR,
            "CHK.S f20 did not raise Disabled FP Register low",
        )
        H._require(
            snapshot.exception_source == fault_ip and
            snapshot.exception_address == fault_ip and
            snapshot.cr_iip == fault_ip and
            snapshot.slot_valid and snapshot.slot_ip == fault_ip and
            snapshot.slot_ri == 0 and
            snapshot.slot_type == H.IA64_SLOT_TYPE_M and
            snapshot.slot_raw == (fault_raw & H.SLOT_MASK),
            "CHK.S disabled-FR fault lost exact source/slot state",
        )
        return "CHK.S f20 raised a precise Disabled FP Register low interruption"

    return RuntimeCase(
        "checked FR disabled-partition fault", program, (fault_ip,), verify,
        ("IA64_OP_CHK_S",), True,
    )


def runtime_cases() -> Tuple[RuntimeCase, ...]:
    return (
        primary_admission_case(), alias_admission_case(), atomic_case(),
        wide_spill_case(), ordered_unat_spill_case(), floating_case(),
        floating_zero_encoding_case(),
        floating_big_endian_case(),
        big_endian_wide_pair_case(),
        rotated_fp_pair_legal_case(), rotated_fp_pair_illegal_case(),
        alat_cache_hint_case(),
        integer_advanced_nat_page_case(), fp_advanced_nat_page_case(),
        *(fp_advanced_unsupported_case(ma) for ma in (4, 5, 6)),
        *(integer_speculative_nat_page_defer_case(width)
          for width in (1, 2, 4, 8)),
        *(integer_speculative_translation_miss_case(width, memory_class)
          for width in (1, 2, 4, 8) for memory_class in ("s", "sa")),
        *(integer_speculative_unaligned_case(
              width, memory_class, deferred_nat_page=deferred_nat_page)
          for deferred_nat_page in (False, True)
          for width in (2, 4, 8) for memory_class in ("s", "sa")),
        *(integer_speculative_protection_fault_case(
              width, memory_class, condition)
          for condition in (
              "page-not-present", "key-miss", "key-permission",
              "access-rights", "access-bit",
          )
          for width in (1, 2, 4, 8) for memory_class in ("s", "sa")),
        *(integer_speculative_data_debug_case(
              width, memory_class, condition)
          for condition in ("aligned", "unaligned", "deferred-nat-page")
          for width in (1, 2, 4, 8) if condition != "unaligned" or width != 1
          for memory_class in ("s", "sa")),
        *(integer_speculative_vhpt_fault_case(
              width, memory_class, condition)
          for condition in ("invalid-entry", "missing-backing")
          for width in (1, 2, 4, 8) for memory_class in ("s", "sa")),
        *(integer_speculative_dm_recovery_case(
              width, memory_class, fault_class, control)
          for fault_class in ("alternate", "invalid-entry", "missing-backing")
          for control in ("defer", "dm-clear", "ed-clear")
          for width in (1, 2, 4, 8) for memory_class in ("s", "sa")),
        *(integer_speculative_dcr_recovery_case(
              width, memory_class, condition, control)
          for condition in (
              "page-not-present", "key-miss", "key-permission",
              "access-rights", "access-bit", "data-debug",
          )
          for control in ("defer", "dcr-clear", "ed-clear")
          for width in (1, 2, 4, 8) for memory_class in ("s", "sa")),
        *(integer_speculative_always_defer_case(
              width, memory_class, condition)
          for condition in (
              "alternate", "invalid-entry", "missing-backing",
              "page-not-present", "key-miss", "key-permission",
              "access-rights", "access-bit", "data-debug", "unaligned",
          )
          for width in (1, 2, 4, 8)
          if condition != "unaligned" or width != 1
          for memory_class in ("s", "sa")),
        *(integer_speculative_software_defer_case(
              width, memory_class, condition)
          for condition in (
              "success", "base-nat", "unimplemented", "alternate",
              "invalid-entry", "missing-backing", "page-not-present",
              "nat-page", "key-miss", "key-permission", "access-rights",
              "access-bit", "data-debug", "unaligned",
          )
          for width in (1, 2, 4, 8)
          if condition != "unaligned" or width != 1
          for memory_class in ("s", "sa")),
        *(successful_integer_speculative_load_case(
              width, memory_class, attribute)
          for attribute in ("speculative", "limited", "non-speculative")
          for width in (1, 2, 4, 8)
          for memory_class in ("s", "a", "sa")),
        *(successful_integer_check_load_case(
              width, check_class, attribute, initial_entry)
          for attribute in ("speculative", "limited", "non-speculative")
          for width in (1, 2, 4, 8)
          for check_class in ("c.clr", "c.clr.acq", "c.nc")
          for initial_entry in ("hit", "miss")
          if not (attribute == "non-speculative" and
                  initial_entry == "hit")),
        fp_speculative_nat_page_defer_case(),
        *(reserved_width_illegal_case(opcode) for opcode in (
            "IA64_OP_LD1FILL", "IA64_OP_LD2FILL", "IA64_OP_LD4FILL",
            "IA64_OP_ST1SPILL", "IA64_OP_ST2SPILL",
            "IA64_OP_ST4SPILL",
        )),
        lfetch_nat_fault_case(), lfetch_translation_fault_case(),
        nat_page_fault_case("IA64_OP_FC"),
        nat_page_fault_case("IA64_OP_LFETCH_FAULT"),
        lfetch_ed_update_case(), fc_ed_translation_fault_case(),
        fc_nonaccess_accessed_case(), fc_nonaccess_rights_case(),
        checked_branch_gr_case(),
        checked_branch_fr_case(), checked_branch_disabled_fr_case(),
    )


def self_check(cases: Sequence[RuntimeCase]) -> str:
    contract = validate_contract(Path(__file__).resolve().parents[2])
    primary = cases[0]
    H._require(len(primary.program.bundles) - 1 == 63,
               "primary admission inventory is not 63 bundles")
    H._require(len(primary.trace_ips) == 57,
               "primary admission trace is not 57 decoder-live rows")
    H._require(set(primary.opcode_coverage) == set(DATA_PLANE_OPCODES),
               "primary admission coverage drifted")
    live_aliases = [alias for alias in ALIAS_ENCODINGS
                    if alias.status != "shadowed-by-cmpxchg"]
    H._require(len(cases[1].trace_ips) == len(live_aliases),
               "live-alias program length drifted")
    for case in cases:
        addresses = [bundle.address for bundle in case.program.bundles]
        H._require(len(addresses) == len(set(addresses)),
                   case.name + ": duplicate bundle address")
        H._require(case.program.terminal_ip in addresses,
                   case.name + ": terminal bundle missing")
        H._require(set(case.trace_ips) < set(addresses),
                   case.name + ": trace set must exclude terminal bundle")
        for bundle in case.program.bundles:
            for raw in (bundle.slot0, bundle.slot1, bundle.slot2):
                H._require(0 <= raw < (1 << 41),
                           case.name + ": instruction exceeds 41 bits")
    shadowed = [alias for alias in ALIAS_ENCODINGS
                if alias.status == "shadowed-by-cmpxchg"]
    H._require(len(shadowed) == 12,
               "expected 12 split-load branches shadowed by cmpxchg")
    reserved = [opcode for opcode in DATA_PLANE_OPCODES
                if SPEC_BY_OPCODE[opcode].isa_status ==
                "decoder-reserved-width"]
    H._require(len(reserved) == 6,
               "expected six decoder-reserved spill/fill widths")
    return ("{}; {} programs; 63 primary bundles (57 decoder-live); {} live "
            "alias/completer bundles; 12 shadowed split-load encodings; "
            "6 reserved-width rows"
            .format(contract, len(cases), len(live_aliases)))


def run_case(qemu: Path, case: RuntimeCase) -> str:
    snapshot = H.run_program(
        qemu, case.program,
        preserve_fault_slot=case.preserve_fault_slot,
        typed_direct_trace_ips=case.trace_ips,
        one_bundle_per_tb=True,
    )
    return case.verify(snapshot)


def _print_failure(exc: Exception) -> None:
    for line in str(exc).splitlines() or [repr(exc)]:
        print("# " + line)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--qemu", type=Path,
                        help="path to rewritten qemu-system-ia64")
    parser.add_argument("--self-check", action="store_true",
                        help="construct and validate programs without QEMU")
    args = parser.parse_args(argv)
    cases = runtime_cases()
    detail = self_check(cases)
    if args.self_check or args.qemu is None:
        print("data-plane runtime self-check: " + detail)
        return 0

    qemu = args.qemu.expanduser().resolve()
    print("TAP version 13")
    print("1..{}".format(len(cases)))
    if not qemu.is_file():
        for index, case in enumerate(cases, start=1):
            print("not ok {} - {}".format(index, case.name))
        print("# QEMU executable does not exist: {}".format(qemu))
        return 1
    failures = 0
    for index, case in enumerate(cases, start=1):
        try:
            result = run_case(qemu, case)
            print("ok {} - {}".format(index, case.name))
            print("# " + result)
        except Exception as exc:
            failures += 1
            print("not ok {} - {}".format(index, case.name))
            _print_failure(exc)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
