#!/usr/bin/env python3
"""Independent architectural contract for the IA-64 FP-compute tranche.

The generated opcode ledger is deliberately *not* the source of this table.
The rows below are reconciled against Intel SDM volume 3, sections F1--F14
and M18--M19, and against Ski's instruction inventory.  In particular, the
old ``IA64_OP_FMOV`` row is retained only as a dead decoder alias: there is no
architected ``fmov`` instruction and the old major-0 catch-all accepted a
large amount of reserved F-unit space.  Intel volume 3 section 4.1 draws an
important distinction between constant-zero and white-space fields: the
latter are ignored and all of their values execute the same instruction.

``lowering`` describes the intended full-TCG owner:

* ``direct`` -- decoded integer/bit TCG, including NaTVal propagation;
* ``focused-helper`` -- a bounded format/SoftFloat transaction which receives
  decoded fields, never a raw 41-bit slot;
* ``dead-alias`` -- no decoder output and no runtime owner.

The fault/trap split is significant.  FP faults happen before the instruction
result and FPSR flags are committed; FP traps happen after both are committed.
Paired instructions must evaluate both lanes before making either decision.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class FloatingOpcode:
    opcode: str
    unit: str
    format: str
    group: str
    lowering: str
    helper: str | None
    kernel: str | None
    inputs: tuple[str, ...]
    outputs: tuple[str, ...]
    natval: str
    fpsr: str
    lanes: int = 1
    qualification: str = "preserve"
    may_fault: bool = False
    may_trap: bool = False
    may_branch: bool = False


def _op(
    opcode: str,
    format: str,
    group: str,
    lowering: str,
    kernel: str | None,
    inputs: tuple[str, ...],
    outputs: tuple[str, ...],
    *,
    unit: str = "F",
    natval: str = "propagate",
    fpsr: str = "none",
    lanes: int = 1,
    qualification: str = "preserve",
    may_fault: bool = False,
    may_trap: bool = False,
    may_branch: bool = False,
) -> FloatingOpcode:
    helper = "fp_compute" if lowering == "focused-helper" else None
    return FloatingOpcode(
        f"IA64_OP_{opcode}", unit, format, group, lowering, helper, kernel,
        inputs, outputs, natval, fpsr, lanes, qualification,
        may_fault, may_trap, may_branch,
    )


FP_OPCODES = (
    # F1 scalar arithmetic.  pc is encoded by major/x; sf selects the FPSR
    # status field.  V/D/Z are pre-result faults, O/U/I post-result traps.
    _op("FADD", "F1", "scalar-arithmetic", "focused-helper", "fadd",
        ("f2", "f3", "sf", "pc"), ("f1", "fpsr"),
        fpsr="faults-and-traps", may_fault=True, may_trap=True),
    _op("FSUB", "F1", "scalar-arithmetic", "focused-helper", "fsub",
        ("f2", "f3", "sf", "pc"), ("f1", "fpsr"),
        fpsr="faults-and-traps", may_fault=True, may_trap=True),
    _op("FMPY", "F1", "scalar-arithmetic", "focused-helper", "fmpy",
        ("f2", "f3", "sf", "pc"), ("f1", "fpsr"),
        fpsr="faults-and-traps", may_fault=True, may_trap=True),
    _op("FMA", "F1", "scalar-arithmetic", "focused-helper", "fma4",
        ("f2", "f3", "f4", "sf", "pc"), ("f1", "fpsr"),
        fpsr="faults-and-traps", may_fault=True, may_trap=True),
    _op("FMS", "F1", "scalar-arithmetic", "focused-helper", "fms",
        ("f2", "f3", "f4", "sf", "pc"), ("f1", "fpsr"),
        fpsr="faults-and-traps", may_fault=True, may_trap=True),
    _op("FNMA", "F1", "scalar-arithmetic", "focused-helper", "fnma4",
        ("f2", "f3", "f4", "sf", "pc"), ("f1", "fpsr"),
        fpsr="faults-and-traps", may_fault=True, may_trap=True),
    _op("FNORM", "F1", "scalar-arithmetic", "focused-helper", "fnorm",
        ("f2", "sf", "pc"), ("f1", "fpsr"),
        fpsr="faults-and-traps", may_fault=True, may_trap=True),

    # F2/F3 exact significand operations.  xma.h is signed multiplication
    # followed by an *unsigned* 64-bit addend, as the Intel pseudocode states.
    _op("XMA_L", "F2", "significand", "direct", None,
        ("f2", "f3", "f4", "signed-product"), ("f1",)),
    _op("XMA_H", "F2", "significand", "direct", None,
        ("f2", "f3", "f4", "signed-product"), ("f1",)),
    _op("XMA_HU", "F2", "significand", "direct", None,
        ("f2", "f3", "f4", "unsigned-product"), ("f1",)),
    _op("XMPY_HU", "F2", "significand", "direct", None,
        ("f3", "f4", "unsigned-product"), ("f1",)),
    _op("FSELECT", "F3", "significand", "direct", None,
        ("f2-mask", "f3", "f4"), ("f1",)),

    # F4/F5 predicate producers.  The unc forms clear the predicate pair even
    # when qp is false and therefore also validate p1 != p2 in that arm.
    _op("FCMP", "F4", "predicate", "focused-helper", "fcmp",
        ("f2", "f3", "relation", "sf", "unc"),
        ("p1", "p2", "fpsr"), natval="predicate-pair-zero",
        fpsr="faults-only", qualification="unc-clear-pair",
        may_fault=True),
    _op("FCLASS", "F5", "predicate", "direct", None,
        ("f2", "class-mask", "unc"), ("p1", "p2"),
        natval="class-mask-or-pair-zero", qualification="unc-clear-pair"),

    # F8 scalar min/max select f3 on equality or any NaN.  They can signal
    # invalid/denormal/SWA faults but never a post-result trap.
    _op("FMIN", "F8", "scalar-minmax", "focused-helper", "fmin",
        ("f2", "f3", "sf"), ("f1", "fpsr"),
        fpsr="faults-only", may_fault=True),
    _op("FMAX", "F8", "scalar-minmax", "focused-helper", "fmax",
        ("f2", "f3", "sf"), ("f1", "fpsr"),
        fpsr="faults-only", may_fault=True),
    _op("FAMIN", "F8", "scalar-minmax", "focused-helper", "famin",
        ("f2", "f3", "sf"), ("f1", "fpsr"),
        fpsr="faults-only", may_fault=True),
    _op("FAMAX", "F8", "scalar-minmax", "focused-helper", "famax",
        ("f2", "f3", "sf"), ("f1", "fpsr"),
        fpsr="faults-only", may_fault=True),

    # F6/F7 approximation instructions clear p2 before qualification.  For
    # paired forms p2 is the AND of the two lane-success predicates.
    _op("FRCPA", "F6", "approximation", "focused-helper", "frcpa",
        ("f2", "f3", "sf"), ("f1", "p2", "fpsr"),
        fpsr="faults-only", qualification="clear-p2", may_fault=True),
    _op("FPRCPA", "F6", "approximation", "focused-helper", "fprcpa",
        ("f2", "f3", "sf"), ("f1", "p2", "fpsr"),
        fpsr="faults-only", lanes=2, qualification="clear-p2",
        may_fault=True),
    _op("FPRSQRTA", "F7", "approximation", "focused-helper", "fprsqrta",
        ("f3", "sf"), ("f1", "p2", "fpsr"),
        fpsr="faults-only", lanes=2, qualification="clear-p2",
        may_fault=True),
    _op("FRSQRTA", "F7", "approximation", "focused-helper", "frsqrta",
        ("f3", "sf"), ("f1", "p2", "fpsr"),
        fpsr="faults-only", qualification="clear-p2", may_fault=True),

    # There is no architected FMOV encoding.  This enum used to be the sink
    # for unrecognized major-0 F-unit forms; it must become decoder-dead.
    _op("FMOV", "reserved", "dead-reserved", "dead-alias", None,
        (), (), natval="none"),

    # F10/F11 conversions.  fcvt.xf is exact, has no FPSR interaction, and is
    # explicitly in Intel's fp-non-arith class; it is direct integer TCG.
    _op("FCVT_XF", "F11", "scalar-convert", "direct", None,
        ("f2-significand",), ("f1",)),
    _op("FCVT_FX", "F10", "scalar-convert", "focused-helper", "fcvt_fx",
        ("f2", "truncate", "sf"), ("f1", "fpsr"),
        fpsr="faults-and-traps", may_fault=True, may_trap=True),
    _op("FCVT_FXU", "F10", "scalar-convert", "focused-helper", "fcvt_fx",
        ("f2", "unsigned", "truncate", "sf"), ("f1", "fpsr"),
        fpsr="faults-and-traps", may_fault=True, may_trap=True),
    _op("FPABS", "F9", "packed-sign", "direct", None,
        ("f2",), ("f1",)),
    _op("FPNEG", "F9", "packed-sign", "direct", None,
        ("f2",), ("f1",)),
    _op("FPNEGABS", "F9", "packed-sign", "direct", None,
        ("f2",), ("f1",)),

    # M18/M19 bridge GR NaT and FR NaTVal.  S/D format conversion is a bounded
    # helper; EXP/SIG are exact decoded bit moves.
    _op("GETF_D", "M19", "register-transfer", "focused-helper", "getf",
        ("f2",), ("r1", "nat"), unit="M", natval="fr-to-gr-nat"),
    _op("GETF_S", "M19", "register-transfer", "focused-helper", "getf",
        ("f2",), ("r1", "nat"), unit="M", natval="fr-to-gr-nat"),
    _op("GETF_EXP", "M19", "register-transfer", "direct", None,
        ("f2",), ("r1", "nat"), unit="M", natval="fr-to-gr-nat"),
    _op("GETF_SIG", "M19", "register-transfer", "direct", None,
        ("f2",), ("r1", "nat"), unit="M", natval="fr-to-gr-nat"),
    _op("SETF_D", "M18", "register-transfer", "focused-helper", "setf_d",
        ("r2", "nat"), ("f1",), unit="M", natval="gr-nat-to-fr"),
    _op("SETF_S", "M18", "register-transfer", "focused-helper", "setf_s",
        ("r2", "nat"), ("f1",), unit="M", natval="gr-nat-to-fr"),
    _op("SETF_EXP", "M18", "register-transfer", "direct", None,
        ("r2", "nat"), ("f1",), unit="M", natval="gr-nat-to-fr"),
    _op("SETF_SIG", "M18", "register-transfer", "direct", None,
        ("r2", "nat"), ("f1",), unit="M", natval="gr-nat-to-fr"),

    _op("FMERGE", "F9", "scalar-merge", "direct", None,
        ("f2-negated-sign", "f3-exp-sig"), ("f1",)),
    _op("FMERGE_S", "F9", "scalar-merge", "direct", None,
        ("f2-sign", "f3-exp-sig"), ("f1",)),
    _op("FMERGE_SE", "F9", "scalar-merge", "direct", None,
        ("f2-sign-exp", "f3-significand"), ("f1",)),

    _op("FSETC", "F12", "status-control", "direct", None,
        ("sf0-controls", "sf", "amask", "omask"), ("fpsr",),
        natval="none", fpsr="set-controls", may_fault=True),
    _op("FCLRF", "F13", "status-control", "direct", None,
        ("sf",), ("fpsr",), natval="none", fpsr="clear-flags"),
    _op("FCHKF", "F14", "status-control", "direct", None,
        ("sf-flags", "sf0-flags", "global-traps"), ("ip",),
        natval="none", fpsr="check-flags", may_fault=True,
        may_branch=True),

    # Exact significand transformations.  Every result has positive sign and
    # FP_INTEGER_EXP, except that any source NaTVal propagates NaTVal.
    _op("FPACK", "F9", "packed-format", "focused-helper", "fpack",
        ("f2-register-format", "f3-register-format"), ("f1",)),
    _op("FAND", "F9", "packed-bit", "direct", None,
        ("f2", "f3"), ("f1",)),
    _op("FANDCM", "F9", "packed-bit", "direct", None,
        ("f2", "f3"), ("f1",)),
    _op("FOR", "F9", "packed-bit", "direct", None,
        ("f2", "f3"), ("f1",)),
    _op("FXOR", "F9", "packed-bit", "direct", None,
        ("f2", "f3"), ("f1",)),
    _op("FSWAP", "F9", "packed-bit", "direct", None,
        ("f2-left", "f3-right"), ("f1",)),
    _op("FSWAP_NL", "F9", "packed-bit", "direct", None,
        ("f2-left", "f3-negated-right"), ("f1",)),
    _op("FSWAP_NR", "F9", "packed-bit", "direct", None,
        ("f2-negated-left", "f3-right"), ("f1",)),
    _op("FMIX_LR", "F9", "packed-bit", "direct", None,
        ("f2-left", "f3-right"), ("f1",)),
    _op("FMIX_R", "F9", "packed-bit", "direct", None,
        ("f2-right", "f3-right"), ("f1",)),
    _op("FMIX_L", "F9", "packed-bit", "direct", None,
        ("f2-left", "f3-left"), ("f1",)),
    _op("FSXT_R", "F9", "packed-bit", "direct", None,
        ("sign(f2-right)", "f3-right"), ("f1",)),
    _op("FSXT_L", "F9", "packed-bit", "direct", None,
        ("sign(f2-left)", "f3-left"), ("f1",)),

    _op("FPMERGE", "F9", "packed-merge", "direct", None,
        ("negated-lane-signs(f2)", "lane-payloads(f3)"), ("f1",),
        lanes=2),
    _op("FPMERGE_S", "F9", "packed-merge", "direct", None,
        ("lane-signs(f2)", "lane-payloads(f3)"), ("f1",), lanes=2),
    _op("FPMERGE_SE", "F9", "packed-merge", "direct", None,
        ("lane-sign-exponents(f2)", "lane-fractions(f3)"), ("f1",),
        lanes=2),

    # Paired arithmetic is an atomic two-lane transaction.  Lane exception
    # bits are encoded separately in ISR for faults and ORed for FPSR/traps.
    _op("FPMIN", "F8", "packed-arithmetic", "focused-helper", "fpminmax",
        ("f2", "f3", "min", "sf"), ("f1", "fpsr"), lanes=2,
        fpsr="paired-faults-only", may_fault=True),
    _op("FPMAX", "F8", "packed-arithmetic", "focused-helper", "fpminmax",
        ("f2", "f3", "max", "sf"), ("f1", "fpsr"), lanes=2,
        fpsr="paired-faults-only", may_fault=True),
    _op("FPAMIN", "F8", "packed-arithmetic", "focused-helper", "fpminmax",
        ("f2", "f3", "abs-min", "sf"), ("f1", "fpsr"), lanes=2,
        fpsr="paired-faults-only", may_fault=True),
    _op("FPAMAX", "F8", "packed-arithmetic", "focused-helper", "fpminmax",
        ("f2", "f3", "abs-max", "sf"), ("f1", "fpsr"), lanes=2,
        fpsr="paired-faults-only", may_fault=True),
    _op("FPCMP", "F8", "packed-arithmetic", "focused-helper", "fpcmp",
        ("f2", "f3", "relation", "sf"), ("f1", "fpsr"), lanes=2,
        fpsr="paired-faults-only", may_fault=True),
    _op("FPCVT", "F10", "packed-arithmetic", "focused-helper", "fpcvt",
        ("f2", "signed-or-unsigned", "truncate", "sf"),
        ("f1", "fpsr"), lanes=2, fpsr="paired-faults-and-traps",
        may_fault=True, may_trap=True),
    _op("FPMA", "F1", "packed-arithmetic", "focused-helper", "fpma",
        ("f2", "f3", "f4", "add", "sf"), ("f1", "fpsr"), lanes=2,
        fpsr="paired-faults-and-traps", may_fault=True, may_trap=True),
    _op("FPMS", "F1", "packed-arithmetic", "focused-helper", "fpma",
        ("f2", "f3", "f4", "subtract", "sf"), ("f1", "fpsr"),
        lanes=2, fpsr="paired-faults-and-traps", may_fault=True,
        may_trap=True),
    _op("FPNMA", "F1", "packed-arithmetic", "focused-helper", "fpma",
        ("f2", "f3", "f4", "negated", "sf"), ("f1", "fpsr"),
        lanes=2, fpsr="paired-faults-and-traps", may_fault=True,
        may_trap=True),
)


FP_OPCODE_NAMES = frozenset(op.opcode for op in FP_OPCODES)
FP_LIVE_OPCODES = tuple(op for op in FP_OPCODES
                        if op.lowering != "dead-alias")
FP_LIVE_OPCODE_NAMES = frozenset(op.opcode for op in FP_LIVE_OPCODES)
FP_DEAD_OPCODE_NAMES = FP_OPCODE_NAMES - FP_LIVE_OPCODE_NAMES
FP_DIRECT_OPCODE_NAMES = frozenset(
    op.opcode for op in FP_LIVE_OPCODES if op.lowering == "direct"
)
FP_HELPER_OPCODE_NAMES = frozenset(
    op.opcode for op in FP_LIVE_OPCODES if op.lowering == "focused-helper"
)


# Complete direct FP-compute tranche.  Twenty-seven rows are exact FR-format
# transforms; the remaining eight are exact predicate, GR/FR transfer, FPSR,
# and check-branch operations.  None uses the bounded SoftFloat helper.
FP_EXACT_DIRECT_OPCODE_NAMES = frozenset({
    "IA64_OP_FCLASS",
    "IA64_OP_GETF_EXP",
    "IA64_OP_GETF_SIG",
    "IA64_OP_SETF_EXP",
    "IA64_OP_SETF_SIG",
    "IA64_OP_FSETC",
    "IA64_OP_FCLRF",
    "IA64_OP_FCHKF",
    "IA64_OP_XMA_L",
    "IA64_OP_XMA_H",
    "IA64_OP_XMA_HU",
    "IA64_OP_XMPY_HU",
    "IA64_OP_FSELECT",
    "IA64_OP_FCVT_XF",
    "IA64_OP_FPABS",
    "IA64_OP_FPNEG",
    "IA64_OP_FPNEGABS",
    "IA64_OP_FMERGE",
    "IA64_OP_FMERGE_S",
    "IA64_OP_FMERGE_SE",
    "IA64_OP_FAND",
    "IA64_OP_FANDCM",
    "IA64_OP_FOR",
    "IA64_OP_FXOR",
    "IA64_OP_FSWAP",
    "IA64_OP_FSWAP_NL",
    "IA64_OP_FSWAP_NR",
    "IA64_OP_FMIX_LR",
    "IA64_OP_FMIX_R",
    "IA64_OP_FMIX_L",
    "IA64_OP_FSXT_R",
    "IA64_OP_FSXT_L",
    "IA64_OP_FPMERGE",
    "IA64_OP_FPMERGE_S",
    "IA64_OP_FPMERGE_SE",
})


# Ignored fields from Intel volume 3's F1--F14 and M18--M19 diagrams.  The
# tuples are (least-significant bit, width).  Software should encode ignored
# fields as zero, but a processor must ignore nonzero values in this revision;
# they are therefore live aliases, never reserved encodings.
FP_IGNORED_FIELDS = {
    "F3": ((34, 2),),
    "F5": ((35, 2),),
    "F7": ((13, 7),),
    "F8": ((36, 1),),
    "F9": ((34, 3),),
    "F10": ((36, 1), (20, 7)),
    "F11": ((34, 3), (20, 7)),
    "F12": ((36, 1), (6, 7)),
    "F13": ((36, 1), (6, 21)),
    "F14": ((26, 1),),
    "M18": ((28, 2), (20, 7)),
    "M19": ((28, 2), (20, 7)),
}


# Exact unused form values consumed by the obsolete major=0, bit36=0,
# bit33=0 FMOV catch-all.  Bits 35:34 are ignored by F9.  The old decoder
# therefore had 136 genuinely illegal (ignored-bits, form) pairs, plus 12
# noncanonical but live aliases of fmerge.{s,ns,se}/fpack which it also
# misdecoded as FMOV: 136 + 12 == 148 catch-all collisions.
FMOV_ILLEGAL_FORMS = (
    0x02, 0x03, 0x06, 0x07, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
    0x13, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
    0x27, 0x29, 0x2A, 0x2B, 0x30, 0x31, 0x32, 0x33, 0x37, 0x38, 0x3E,
    0x3F,
)
FMOV_ILLEGAL_FORM_PAIRS = tuple(
    (ignored_35_34, form)
    for ignored_35_34 in range(4)
    for form in FMOV_ILLEGAL_FORMS
)
FMOV_LIVE_ALIAS_FORMS = (0x10, 0x11, 0x12, 0x28)
FMOV_MISDECODED_LIVE_ALIAS_PAIRS = tuple(
    (ignored_35_34, form)
    for ignored_35_34 in range(1, 4)
    for form in FMOV_LIVE_ALIAS_FORMS
)
FMOV_CATCHALL_FORM_PAIRS = (
    FMOV_ILLEGAL_FORM_PAIRS + FMOV_MISDECODED_LIVE_ALIAS_PAIRS
)


def validate() -> None:
    assert len(FP_OPCODES) == 68
    assert len(FP_OPCODE_NAMES) == len(FP_OPCODES)
    assert len(FP_LIVE_OPCODES) == 67
    assert FP_DEAD_OPCODE_NAMES == {"IA64_OP_FMOV"}
    assert len(FP_DIRECT_OPCODE_NAMES) == 35
    assert len(FP_EXACT_DIRECT_OPCODE_NAMES) == 35
    assert FP_EXACT_DIRECT_OPCODE_NAMES == FP_DIRECT_OPCODE_NAMES
    assert len(FP_HELPER_OPCODE_NAMES) == 32
    assert sum(op.may_branch for op in FP_LIVE_OPCODES) == 1
    assert all(op.unit in {"F", "M"} for op in FP_LIVE_OPCODES)
    assert all(op.lanes in {1, 2} for op in FP_LIVE_OPCODES)
    assert all(op.lowering != "focused-helper" or
               (op.helper == "fp_compute" and op.kernel)
               for op in FP_LIVE_OPCODES)
    assert all(op.lowering != "direct" or
               (op.helper is None and op.kernel is None)
               for op in FP_LIVE_OPCODES)
    assert all(not op.may_trap or op.may_fault for op in FP_LIVE_OPCODES)
    assert set(FP_IGNORED_FIELDS) == {
        "F3", "F5", "F7", "F8", "F9", "F10", "F11", "F12", "F13",
        "F14", "M18", "M19",
    }
    assert all(start >= 0 and width > 0 and start + width <= 41
               for fields in FP_IGNORED_FIELDS.values()
               for start, width in fields)
    assert len(FMOV_ILLEGAL_FORMS) == 34
    assert len(FMOV_ILLEGAL_FORM_PAIRS) == 136
    assert len(FMOV_MISDECODED_LIVE_ALIAS_PAIRS) == 12
    assert len(FMOV_CATCHALL_FORM_PAIRS) == 148
    assert len(set(FMOV_CATCHALL_FORM_PAIRS)) == 148


validate()
