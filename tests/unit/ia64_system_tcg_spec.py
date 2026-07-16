#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared generated specification for the IA-64 system/control TCG tranche.

This is deliberately independent of the target implementation.  The static and
no-OS runtime gates import the same inventory so adding a typed lowering without
adding an architectural test (or vice versa) cannot silently change coverage.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple


def bitfield(value: int, low: int, width: int) -> int:
    return (value & ((1 << width) - 1)) << low


def major(value: int) -> int:
    return bitfield(value, 37, 4)


def m_system(x6: int, *, r1: int = 0, r2: int = 0, r3: int = 0,
             qp: int = 0) -> int:
    """Canonical M-unit major-1 system-register/translation encoding."""
    return (major(1) | bitfield(x6, 27, 6) | bitfield(r3, 20, 7)
            | bitfield(r2, 13, 7) | bitfield(r1, 6, 7)
            | bitfield(qp, 0, 6))


def m_mask(x4: int, mask: int, *, qp: int = 0) -> int:
    """Encode M44 SUM/RUM/SSM/RSM's split 24-bit immediate."""
    if x4 not in (4, 5, 6, 7):
        raise ValueError("M44 x4 must select SUM/RUM/SSM/RSM")
    if not 0 <= mask < (1 << 24):
        raise ValueError("M44 mask must fit in 24 bits")
    return (
        bitfield(x4, 27, 4)
        | bitfield(mask & 0x7f, 6, 7)
        | bitfield((mask >> 7) & 0x7f, 13, 7)
        | bitfield((mask >> 14) & 0x7f, 20, 7)
        | bitfield((mask >> 21) & 0x3, 31, 2)
        | bitfield((mask >> 23) & 1, 36, 1)
        | bitfield(qp, 0, 6)
    )


def mov_immar(ar: int = 65, immediate: int = 0x2a, *, qp: int = 0,
              unit: str = "I") -> int:
    """Encode I27 or M30 ``mov ar = imm8``."""
    if unit not in ("I", "M"):
        raise ValueError("MOV_IMMAR unit must be I or M")
    immediate &= 0xff
    x6 = 0x0a if unit == "I" else 0x28
    return (bitfield(x6, 27, 6) | bitfield(ar, 20, 7)
            | bitfield(immediate & 0x7f, 13, 7)
            | bitfield(immediate >> 7, 36, 1)
            | bitfield(qp, 0, 6))


def mov_current_ip(r1: int = 20, *, qp: int = 0) -> int:
    return bitfield(0x30, 27, 6) | bitfield(r1, 6, 7) | qp


def m_serial(x6: int, *, qp: int = 0) -> int:
    return bitfield(x6, 27, 6) | bitfield(qp, 0, 6)


def b_system(x6: int) -> int:
    return bitfield(x6, 27, 6)


def br_ia(b2: int = 6) -> int:
    return bitfield(0x20, 27, 6) | bitfield(b2, 13, 3) | bitfield(1, 6, 3)


def brp(relative: bool = True, *, return_form: bool = False) -> int:
    """Encode B6 IP-relative or B7 indirect/return branch prediction."""
    if relative:
        if return_form:
            raise ValueError("B6 relative BRP has no return form")
        return major(7)
    return major(2) | bitfield(0x11 if return_form else 0x10, 27, 6)


def break_m(immediate: int = 0x12345, *, qp: int = 0) -> int:
    immediate &= (1 << 21) - 1
    return (bitfield(immediate & 0xfffff, 6, 20)
            | bitfield(immediate >> 20, 36, 1) | qp)


@dataclass(frozen=True)
class SystemOpcodeSpec:
    opcode: str
    family: str
    unit: str
    predicable: bool
    privilege: str
    nat: str
    tb_end: str
    owner: str
    must_end_group: bool = False


def _s(opcode: str, family: str, unit: str = "M", predicable: bool = True,
       privilege: str = "none", nat: str = "none",
       tb_end: str = "continue", owner: str = "focused",
       must_end_group: bool = False) -> SystemOpcodeSpec:
    return SystemOpcodeSpec(opcode, family, unit, predicable, privilege,
                            nat, tb_end, owner, must_end_group)


# ``privilege`` is architectural, not the coarse pre-rewrite ledger value:
# "always" means CPL0 is required; "register" or "pmd" is operand/state
# dependent.  ``nat`` distinguishes consumption from THASH/TTAG propagation.
SYSTEM_OPCODE_SPECS: Tuple[SystemOpcodeSpec, ...] = (
    _s("IA64_OP_BREAK", "break", predicable=True, tb_end="no-return",
       owner="exception"),
    _s("IA64_OP_BR_IA", "branch", unit="B", predicable=False,
       tb_end="no-return", owner="control"),
    _s("IA64_OP_MOV_IMMAR", "move-gr-to-ar", unit="I",
       privilege="register", tb_end="conditional-bundle"),
    _s("IA64_OP_MOV_CRGR", "move-cr-to-gr", privilege="always",
       tb_end="conditional-bundle"),
    _s("IA64_OP_MOV_GRCR", "move-gr-to-cr", privilege="always",
       nat="value", tb_end="bundle"),
    _s("IA64_OP_SSM", "state-control", privilege="always",
       tb_end="bundle"),
    _s("IA64_OP_RSM", "state-control", privilege="always",
       tb_end="bundle"),
    _s("IA64_OP_ITR_D", "mmu", privilege="always", nat="value,index",
       tb_end="bundle", owner="mmu"),
    _s("IA64_OP_ITR_I", "mmu", privilege="always", nat="value,index",
       tb_end="slot", owner="mmu"),
    _s("IA64_OP_PTR_D", "mmu", privilege="always", nat="address,size",
       tb_end="bundle", owner="mmu"),
    _s("IA64_OP_PTR_I", "mmu", privilege="always", nat="address,size",
       tb_end="bundle", owner="mmu"),
    _s("IA64_OP_PTC_L", "mmu", privilege="always", nat="address,size",
       tb_end="bundle", owner="mmu"),
    _s("IA64_OP_PTC_G", "mmu", privilege="always", nat="address,size",
       tb_end="bundle", owner="mmu", must_end_group=True),
    _s("IA64_OP_TPA", "mmu", privilege="always", nat="address",
       owner="mmu"),
    _s("IA64_OP_SYNC_I", "state-control", tb_end="slot",
       owner="direct"),
    _s("IA64_OP_SRLZ", "state-control", tb_end="slot", owner="serialize"),
    _s("IA64_OP_SRLZ_D", "state-control", tb_end="slot",
       owner="serialize"),
    _s("IA64_OP_MF", "state-control", owner="direct"),
    _s("IA64_OP_MF_A", "state-control", owner="direct"),
    _s("IA64_OP_PROBE_R", "mmu", nat="address,level", owner="mmu"),
    _s("IA64_OP_PROBE_W", "mmu", nat="address,level", owner="mmu"),
    _s("IA64_OP_PROBE_RW", "mmu", nat="address", owner="mmu"),
    _s("IA64_OP_TAK", "mmu", privilege="always", nat="address",
       owner="mmu"),
    _s("IA64_OP_THASH", "mmu", nat="propagate-address", owner="mmu"),
    _s("IA64_OP_TTAG", "mmu", nat="propagate-address", owner="mmu"),
    _s("IA64_OP_PTC_E", "mmu", privilege="always", nat="address",
       tb_end="bundle", owner="mmu"),
    _s("IA64_OP_ITC_D", "mmu", privilege="always", nat="value",
       tb_end="bundle", owner="mmu", must_end_group=True),
    _s("IA64_OP_ITC_I", "mmu", privilege="always", nat="value",
       tb_end="slot", owner="mmu", must_end_group=True),
    _s("IA64_OP_PTC_GA", "mmu", privilege="always", nat="address,size",
       tb_end="bundle", owner="mmu", must_end_group=True),
    _s("IA64_OP_MOV_PSRGR", "system-register-move", privilege="always"),
    _s("IA64_OP_MOV_GRPSR", "system-register-move", privilege="always",
       nat="value", tb_end="bundle"),
    _s("IA64_OP_MOV_RRGR", "system-register-move", privilege="always",
       nat="index"),
    _s("IA64_OP_MOV_GRRR", "system-register-move", privilege="always",
       nat="value,index", tb_end="bundle"),
    _s("IA64_OP_BSW0", "state-control", unit="B", predicable=False,
       privilege="always", tb_end="control", owner="control",
       must_end_group=True),
    _s("IA64_OP_BSW1", "state-control", unit="B", predicable=False,
       privilege="always", tb_end="control", owner="control",
       must_end_group=True),
    _s("IA64_OP_EPC", "state-control", unit="B", predicable=False,
       tb_end="control", owner="control"),
    _s("IA64_OP_MOV_PKRGR_INDEXED", "system-register-move",
       privilege="always", nat="index"),
    _s("IA64_OP_MOV_GRPKR_INDEXED", "system-register-move",
       privilege="always", nat="value,index", tb_end="bundle"),
    _s("IA64_OP_MOV_UMGR", "system-register-move", owner="direct"),
    _s("IA64_OP_MOV_GRUM", "system-register-move", nat="value",
       tb_end="bundle"),
    _s("IA64_OP_MOV_IBRGR_INDEXED", "system-register-move",
       privilege="always", nat="index"),
    _s("IA64_OP_MOV_GRIBR_INDEXED", "system-register-move",
       privilege="always", nat="value,index"),
    _s("IA64_OP_MOV_DBRGR_INDEXED", "system-register-move",
       privilege="always", nat="index"),
    _s("IA64_OP_MOV_GRDBR_INDEXED", "system-register-move",
       privilege="always", nat="value,index"),
    _s("IA64_OP_MOV_PMCGR_INDEXED", "system-register-move",
       privilege="always", nat="index"),
    _s("IA64_OP_MOV_GRPMC_INDEXED", "system-register-move",
       privilege="always", nat="value,index"),
    _s("IA64_OP_MOV_PMDGR_INDEXED", "system-register-move",
       privilege="pmd", nat="index"),
    _s("IA64_OP_MOV_GRPMD_INDEXED", "system-register-move",
       privilege="always", nat="value,index"),
    _s("IA64_OP_MOV_CPUID_INDEXED", "system-register-move", nat="index"),
    _s("IA64_OP_MOV_DAHRGR_INDEXED", "system-register-move",
       privilege="always", nat="index"),
    _s("IA64_OP_MOV_MSRGR", "system-register-move", privilege="always",
       nat="index"),
    _s("IA64_OP_MOV_GRMSR", "system-register-move", privilege="always",
       nat="value,index", tb_end="bundle"),
    _s("IA64_OP_MOV_CURRENT_IP", "system-register-move", unit="I",
       owner="direct"),
    _s("IA64_OP_VMSW", "state-control", unit="B", predicable=False,
       privilege="feature", tb_end="control", owner="control"),
    _s("IA64_OP_RUM", "state-control", tb_end="bundle"),
    _s("IA64_OP_SUM_UM", "state-control", tb_end="bundle"),
    _s("IA64_OP_BRP", "branch", unit="B", predicable=False,
       owner="direct"),
)


SYSTEM_OPCODES = tuple(spec.opcode for spec in SYSTEM_OPCODE_SPECS)
SPEC_BY_OPCODE: Dict[str, SystemOpcodeSpec] = {
    spec.opcode: spec for spec in SYSTEM_OPCODE_SPECS
}

# The two broad AR-move opcodes are closed as prerequisites because their
# register selector determines the architectural unit, privilege, value-mask,
# and RSE behavior.  They remain outside the exact 57-row Macro D inventory.
PRECLOSED_SYSTEM_PREREQUISITES = (
    "IA64_OP_MOV_ARGR",
    "IA64_OP_MOV_GRAR",
)


_M_X6 = {
    "IA64_OP_MOV_CRGR": 0x24,
    "IA64_OP_MOV_GRCR": 0x2c,
    "IA64_OP_ITR_D": 0x0e,
    "IA64_OP_ITR_I": 0x0f,
    "IA64_OP_PTR_D": 0x0c,
    "IA64_OP_PTR_I": 0x0d,
    "IA64_OP_PTC_L": 0x09,
    "IA64_OP_PTC_G": 0x0a,
    "IA64_OP_TPA": 0x1e,
    "IA64_OP_PROBE_R": 0x18,
    "IA64_OP_PROBE_W": 0x19,
    "IA64_OP_PROBE_RW": 0x31,
    "IA64_OP_TAK": 0x1f,
    "IA64_OP_THASH": 0x1a,
    "IA64_OP_TTAG": 0x1b,
    "IA64_OP_PTC_E": 0x34,
    "IA64_OP_ITC_D": 0x2e,
    "IA64_OP_ITC_I": 0x2f,
    "IA64_OP_PTC_GA": 0x0b,
    "IA64_OP_MOV_PSRGR": 0x25,
    "IA64_OP_MOV_GRPSR": 0x2d,
    "IA64_OP_MOV_RRGR": 0x10,
    "IA64_OP_MOV_GRRR": 0x00,
    "IA64_OP_MOV_PKRGR_INDEXED": 0x13,
    "IA64_OP_MOV_GRPKR_INDEXED": 0x03,
    "IA64_OP_MOV_UMGR": 0x21,
    "IA64_OP_MOV_GRUM": 0x29,
    "IA64_OP_MOV_IBRGR_INDEXED": 0x12,
    "IA64_OP_MOV_GRIBR_INDEXED": 0x02,
    "IA64_OP_MOV_DBRGR_INDEXED": 0x11,
    "IA64_OP_MOV_GRDBR_INDEXED": 0x01,
    "IA64_OP_MOV_PMCGR_INDEXED": 0x14,
    "IA64_OP_MOV_GRPMC_INDEXED": 0x04,
    "IA64_OP_MOV_PMDGR_INDEXED": 0x15,
    "IA64_OP_MOV_GRPMD_INDEXED": 0x05,
    "IA64_OP_MOV_CPUID_INDEXED": 0x17,
    "IA64_OP_MOV_DAHRGR_INDEXED": 0x20,
    "IA64_OP_MOV_MSRGR": 0x16,
    "IA64_OP_MOV_GRMSR": 0x06,
}


def encode_system_opcode(opcode: str, *, qp: int = 0, r1: int = 20,
                         r2: int = 21, r3: int = 22) -> int:
    """Return one canonical raw slot for each of the 57 owned rows."""
    if opcode == "IA64_OP_BREAK":
        return break_m(qp=qp)
    if opcode == "IA64_OP_BR_IA":
        return br_ia(6)
    if opcode == "IA64_OP_MOV_IMMAR":
        return mov_immar(qp=qp)
    if opcode in _M_X6:
        read_r1_r3 = {
            "IA64_OP_MOV_CRGR", "IA64_OP_TPA", "IA64_OP_TAK",
            "IA64_OP_THASH", "IA64_OP_TTAG", "IA64_OP_MOV_RRGR",
            "IA64_OP_MOV_PKRGR_INDEXED", "IA64_OP_MOV_IBRGR_INDEXED",
            "IA64_OP_MOV_DBRGR_INDEXED", "IA64_OP_MOV_PMCGR_INDEXED",
            "IA64_OP_MOV_PMDGR_INDEXED", "IA64_OP_MOV_CPUID_INDEXED",
            "IA64_OP_MOV_DAHRGR_INDEXED", "IA64_OP_MOV_MSRGR",
        }
        write_r2_r3 = {
            "IA64_OP_MOV_GRCR", "IA64_OP_ITR_D", "IA64_OP_ITR_I",
            "IA64_OP_PTR_D", "IA64_OP_PTR_I", "IA64_OP_PTC_L",
            "IA64_OP_PTC_G", "IA64_OP_PTC_GA", "IA64_OP_MOV_GRRR",
            "IA64_OP_MOV_GRPKR_INDEXED", "IA64_OP_MOV_GRIBR_INDEXED",
            "IA64_OP_MOV_GRDBR_INDEXED", "IA64_OP_MOV_GRPMC_INDEXED",
            "IA64_OP_MOV_GRPMD_INDEXED", "IA64_OP_MOV_GRMSR",
        }
        if opcode in read_r1_r3:
            return m_system(_M_X6[opcode], r1=r1, r3=r3, qp=qp)
        if opcode in write_r2_r3:
            return m_system(_M_X6[opcode], r2=r2, r3=r3, qp=qp)
        if opcode in {"IA64_OP_PROBE_R", "IA64_OP_PROBE_W"}:
            return m_system(_M_X6[opcode], r1=r1, r2=0, r3=r3, qp=qp)
        if opcode == "IA64_OP_PROBE_RW":
            return m_system(_M_X6[opcode], r3=r3, qp=qp)
        if opcode == "IA64_OP_PTC_E":
            return m_system(_M_X6[opcode], r3=r3, qp=qp)
        if opcode in {"IA64_OP_ITC_D", "IA64_OP_ITC_I"}:
            return m_system(_M_X6[opcode], r2=r2, qp=qp)
        if opcode in {"IA64_OP_MOV_PSRGR", "IA64_OP_MOV_UMGR"}:
            return m_system(_M_X6[opcode], r1=r1, qp=qp)
        if opcode in {"IA64_OP_MOV_GRPSR", "IA64_OP_MOV_GRUM"}:
            return m_system(_M_X6[opcode], r2=r2, qp=qp)
        raise AssertionError("unclassified M-system shape: " + opcode)
    if opcode == "IA64_OP_SSM":
        return m_mask(6, 1 << 14, qp=qp)
    if opcode == "IA64_OP_RSM":
        return m_mask(7, 1 << 14, qp=qp)
    if opcode == "IA64_OP_SYNC_I":
        return m_serial(0x33, qp=qp)
    if opcode == "IA64_OP_SRLZ":
        return m_serial(0x31, qp=qp)
    if opcode == "IA64_OP_SRLZ_D":
        return m_serial(0x30, qp=qp)
    if opcode == "IA64_OP_MF":
        return m_serial(0x22, qp=qp)
    if opcode == "IA64_OP_MF_A":
        return m_serial(0x23, qp=qp)
    if opcode == "IA64_OP_BSW0":
        return b_system(0x0c)
    if opcode == "IA64_OP_BSW1":
        return b_system(0x0d)
    if opcode == "IA64_OP_EPC":
        return b_system(0x10)
    if opcode == "IA64_OP_MOV_CURRENT_IP":
        return mov_current_ip(r1, qp=qp)
    if opcode == "IA64_OP_VMSW":
        return b_system(0x18)
    if opcode == "IA64_OP_RUM":
        return m_mask(5, 1 << 3, qp=qp)
    if opcode == "IA64_OP_SUM_UM":
        return m_mask(4, 1 << 3, qp=qp)
    if opcode == "IA64_OP_BRP":
        return brp(True)
    raise KeyError(opcode)


# Normalized encoding variants whose semantics differ within one ledger row.
# They are consumed by both static coverage checks and focused runtime tests.
ENCODING_VARIANTS = {
    # BREAK's B9 form is unpredicated with IIM=0; X1 is the low slot of
    # an MLX pair and the decoder supplies its paired 41 high immediate bits.
    "IA64_OP_BREAK": (
        ("M", break_m()),
        ("I", break_m()),
        ("F", break_m()),
        ("B", 0),
        ("X-low", break_m()),
    ),
    "IA64_OP_MOV_IMMAR": (
        ("I", mov_immar(unit="I")),
        ("M", mov_immar(ar=0, unit="M")),
    ),
    "IA64_OP_PROBE_R": (
        ("M39-imm", m_system(0x18)),
        ("M38-reg", m_system(0x38)),
        ("M40-fault", m_system(0x32)),
    ),
    "IA64_OP_PROBE_W": (
        ("M39-imm", m_system(0x19)),
        ("M38-reg", m_system(0x39)),
        ("M40-fault", m_system(0x33)),
    ),
    "IA64_OP_PROBE_RW": (("M40-fault", m_system(0x31)),),
    "IA64_OP_VMSW": (("B8-zero", b_system(0x18)),
                       ("B8-one", b_system(0x19))),
    "IA64_OP_BRP": (("B6-relative", brp(True)),
                      ("B7-indirect", brp(False)),
                      ("B7-return", brp(False, return_form=True))),
}


def validate_inventory() -> None:
    if len(SYSTEM_OPCODE_SPECS) != 57:
        raise AssertionError("system/control inventory must contain 57 rows")
    if len(SPEC_BY_OPCODE) != 57:
        raise AssertionError("system/control inventory contains duplicates")
    if {spec.opcode for spec in SYSTEM_OPCODE_SPECS
            if spec.must_end_group} != {
        "IA64_OP_ITC_D", "IA64_OP_ITC_I", "IA64_OP_PTC_G",
        "IA64_OP_PTC_GA", "IA64_OP_BSW0", "IA64_OP_BSW1",
    }:
        raise AssertionError("system/control group-end placement drift")
    for spec in SYSTEM_OPCODE_SPECS:
        raw = encode_system_opcode(spec.opcode, qp=1 if spec.predicable else 0)
        if not 0 <= raw < (1 << 41):
            raise AssertionError(spec.opcode + " does not fit an IA-64 slot")


validate_inventory()
