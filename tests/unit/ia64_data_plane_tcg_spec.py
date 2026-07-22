#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Independent 63-row specification for the remaining IA-64 data plane.

The table is intentionally independent of the translator.  It records the
decoder-normalized opcode, architectural side effects, the bounded helper
class permitted in a direct-TCG lowering, and one executable encoding for
every row.  Decoder aliases are kept separately so a rewrite cannot make an
alias disappear merely because the canonical form works.

Intel SDM Vol. 3 defines only ``ld8.fill`` and ``st8.spill``.  The current
decoder nevertheless exposes width-specific LD1/2/4FILL and ST1/2/4SPILL
opcodes.  Those six rows are marked ``decoder-reserved-width`` rather than
being presented as architectural instructions.  The reference QEMU executes
their encoded width; Ski always executes the architectural eight-byte form.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Tuple


FAMILY_COUNTS = {
    "integer-load": 25,
    "integer-store": 5,
    "atomic": 11,
    "floating-load": 8,
    "floating-store": 5,
    "cache": 4,
    "checked-alat": 3,
    "memory-hint": 2,
}


def bits(value: int, low: int, width: int) -> int:
    return (value & ((1 << width) - 1)) << low


def major(value: int) -> int:
    return bits(value, 37, 4)


def _gr(value: int) -> None:
    if not 0 <= value < 128:
        raise ValueError("register number must fit in seven bits")


def _qp(value: int) -> None:
    if not 0 <= value < 64:
        raise ValueError("predicate must fit in six bits")


WIDTH_CODE = {1: 0, 2: 1, 4: 2, 8: 3}


def m_x6a(major_opcode: int, x6a: int, *, r1: int = 20, r2: int = 21,
          r3: int = 10, qp: int = 0, x: int = 0, m: int = 0,
          hint: int = 0) -> int:
    """Encode the common M-unit memory layout used by M2/M6/M9/M13."""
    for reg in (r1, r2, r3):
        _gr(reg)
    _qp(qp)
    return (
        major(major_opcode)
        | bits(m, 36, 1)
        | bits(x6a, 30, 6)
        | bits(hint, 28, 2)
        | bits(x, 27, 1)
        | bits(r3, 20, 7)
        | bits(r2, 13, 7)
        | bits(r1, 6, 7)
        | qp
    )


def integer_load(width: int, kind: str, *, r1: int = 20, r2: int = 21,
                 r3: int = 10, qp: int = 0, update: str = "none",
                 imm: int = 1) -> int:
    bases = {
        "s": 0x04,
        "a": 0x08,
        "sa": 0x0c,
        "fill": 0x18,
        "c.clr": 0x20,
        "c.nc": 0x24,
        "c.clr.acq": 0x28,
    }
    if width not in WIDTH_CODE or kind not in bases:
        raise ValueError("unknown integer-load width/type")
    x6a = bases[kind] + WIDTH_CODE[width]
    if update == "none":
        return m_x6a(4, x6a, r1=r1, r2=r2, r3=r3, qp=qp)
    if update == "reg":
        return m_x6a(4, x6a, r1=r1, r2=r2, r3=r3, qp=qp, m=1)
    if update == "imm":
        if not -256 <= imm <= 255:
            raise ValueError("load update must fit signed imm9")
        encoded = imm & 0x1ff
        return (
            m_x6a(5, x6a, r1=r1, r2=0, r3=r3, qp=qp,
                  x=(encoded >> 7) & 1, m=(encoded >> 8) & 1)
            | bits(encoded & 0x7f, 13, 7)
        )
    raise ValueError("load update must be none, reg, or imm")


def integer_load_split_alias(width: int, kind: str, *, r1: int = 20,
                             r2: int = 21, r3: int = 10,
                             qp: int = 0) -> int:
    """Old split-extension aliases accepted by decode.c.

    ``s`` uses x/hint=001 with x6a 0..3.  Check loads use x/hint=011
    (clear) or 111 (no-clear), again with x6a 0..3.
    """
    code = WIDTH_CODE[width]
    if kind == "s":
        return m_x6a(4, code, r1=r1, r2=r2, r3=r3, qp=qp, x=1)
    if kind == "c.clr":
        return m_x6a(4, code, r1=r1, r2=r2, r3=r3, qp=qp,
                     x=1, hint=1)
    if kind == "c.nc":
        return m_x6a(4, code, r1=r1, r2=r2, r3=r3, qp=qp,
                     x=1, hint=3)
    raise ValueError("split alias exists only for s/c.clr/c.nc")


def ld16(*, r1: int = 20, r3: int = 10, qp: int = 0,
         acquire: bool = False) -> int:
    return m_x6a(4, 0x2c if acquire else 0x28, r1=r1, r2=0,
                 r3=r3, qp=qp, x=1)


def integer_spill(width: int, *, r2: int = 21, r3: int = 10,
                  qp: int = 0, imm: int | None = None) -> int:
    x6a = 0x38 + WIDTH_CODE[width]
    if imm is None:
        return m_x6a(4, x6a, r1=0, r2=r2, r3=r3, qp=qp)
    if not -256 <= imm <= 255:
        raise ValueError("spill update must fit signed imm9")
    encoded = imm & 0x1ff
    raw = m_x6a(5, x6a, r1=0, r2=r2, r3=r3, qp=qp,
                  x=(encoded >> 7) & 1, m=(encoded >> 8) & 1)
    return raw | bits(encoded & 0x7f, 6, 7)


def st16(*, r2: int = 21, r3: int = 10, qp: int = 0,
         release: bool = False, hint_bits: int = 0) -> int:
    # Accepted x6 values are 01/03/05/07 and 21/23/25/27.
    x6 = 0x01 | ((hint_bits & 3) << 1) | (0x20 if release else 0)
    return (major(4) | bits(6, 33, 3) | bits(x6, 27, 6)
            | bits(r3, 20, 7) | bits(r2, 13, 7) | qp)


def atomic(opcode: str, *, r1: int = 20, r2: int = 21, r3: int = 10,
           qp: int = 0, release: bool = False, inc_index: int = 3) -> int:
    if opcode == "IA64_OP_CMP8XCHG16":
        return m_x6a(4, 0x24 if release else 0x20, r1=r1, r2=r2,
                     r3=r3, qp=qp, x=1)
    for stem in ("XCHG", "CMPXCHG"):
        if opcode.startswith("IA64_OP_" + stem):
            width = int(opcode.removeprefix("IA64_OP_" + stem))
            code = WIDTH_CODE[width]
            x3 = 1 if stem == "XCHG" else 0
            if stem == "XCHG" and release:
                raise ValueError("xchg is acquire-only")
            return (major(4) | bits(1, 27, 1)
                    | bits(code & 1, 30, 1) | bits(code >> 1, 31, 1)
                    | bits(1 if release else 0, 32, 1)
                    | bits(x3, 33, 3) | bits(r3, 20, 7)
                    | bits(r2, 13, 7) | bits(r1, 6, 7) | qp)
    if opcode in ("IA64_OP_FETCHADD4", "IA64_OP_FETCHADD8"):
        width = int(opcode[-1])
        x6a = (0x16 if release else 0x12) + (width == 8)
        return (m_x6a(4, x6a, r1=r1, r2=0, r3=r3, qp=qp, x=1)
                | bits(inc_index, 13, 3))
    raise ValueError("unknown atomic opcode")


def atomic_legacy(opcode: str, *, r1: int = 20, r2: int = 21,
                  r3: int = 10, qp: int = 0) -> int:
    """Non-SDM b=2/b=3 aliases normalized by the prototype decoder."""
    if opcode.startswith("IA64_OP_XCHG"):
        width = int(opcode.removeprefix("IA64_OP_XCHG"))
        xm, xhint = {1: (0, 0), 2: (0, 1), 4: (1, 0), 8: (1, 1)}[width]
        return (major(2) | bits(xm, 29, 2) | bits(xhint, 27, 2)
                | bits(r3, 20, 7) | bits(r2, 13, 7)
                | bits(r1, 6, 7) | qp)
    if opcode.startswith("IA64_OP_CMPXCHG"):
        width = int(opcode.removeprefix("IA64_OP_CMPXCHG"))
        xm, xhint = {1: (2, 0), 2: (2, 1), 4: (3, 0), 8: (3, 1)}[width]
        return (major(2) | bits(xm, 29, 2) | bits(xhint, 27, 2)
                | bits(r3, 20, 7) | bits(r2, 13, 7)
                | bits(r1, 6, 7) | qp)
    if opcode in ("IA64_OP_FETCHADD4", "IA64_OP_FETCHADD8"):
        xm = 0 if opcode.endswith("4") else 1
        return (major(3) | bits(xm, 29, 2) | bits(r3, 20, 7)
                | bits(r2, 13, 7) | bits(r1, 6, 7) | qp)
    raise ValueError("no legacy alias for opcode")


FP_X6_LOW = {
    "IA64_OP_LDFE": 0,
    "IA64_OP_LDF8": 1,
    "IA64_OP_LDFS": 2,
    "IA64_OP_LDFD": 3,
    "IA64_OP_LDFP8": 1,
    "IA64_OP_LDFPS": 2,
    "IA64_OP_LDFPD": 3,
}
FP_ATTR_BASE = {
    "normal": 0x00,
    "s": 0x04,
    "a": 0x08,
    "sa": 0x0c,
    "c.clr": 0x20,
    "c.nc": 0x24,
}
FP_STORE_X6 = {
    "IA64_OP_STFE": 0x30,
    "IA64_OP_STF8": 0x31,
    "IA64_OP_STFS": 0x32,
    "IA64_OP_STFD": 0x33,
    "IA64_OP_STF_SPILL": 0x3b,
}


def floating_load(opcode: str, *, attr: str = "normal", f1: int = 20,
                  f2: int = 21, r3: int = 10, qp: int = 0,
                  update: str = "none", imm: int = 1) -> int:
    if opcode == "IA64_OP_LDF_FILL":
        if attr != "normal":
            raise ValueError("ldf.fill has no speculative/ALAT completer")
        x6a = 0x1b
        pair = False
    else:
        x6a = FP_ATTR_BASE[attr] + FP_X6_LOW[opcode]
        pair = opcode.startswith("IA64_OP_LDFP")
    if pair:
        if update not in ("none", "fixed"):
            raise ValueError("ldfp update is absent or implied-size")
        return m_x6a(6, x6a, r1=f1, r2=f2, r3=r3, qp=qp,
                     x=1, m=(update == "fixed"))
    if update == "none":
        return m_x6a(6, x6a, r1=f1, r2=0, r3=r3, qp=qp)
    if update == "reg":
        return m_x6a(6, x6a, r1=f1, r2=f2, r3=r3, qp=qp, m=1)
    if update == "imm":
        encoded = imm & 0x1ff
        return (m_x6a(7, x6a, r1=f1, r2=0, r3=r3, qp=qp,
                      x=(encoded >> 7) & 1, m=(encoded >> 8) & 1)
                | bits(encoded & 0x7f, 13, 7))
    raise ValueError("unknown floating-load update")


def floating_store(opcode: str, *, f2: int = 20, r3: int = 10,
                   qp: int = 0, imm: int | None = None) -> int:
    x6a = FP_STORE_X6[opcode]
    if imm is None:
        return m_x6a(6, x6a, r1=0, r2=f2, r3=r3, qp=qp)
    encoded = imm & 0x1ff
    return (m_x6a(7, x6a, r1=0, r2=f2, r3=r3, qp=qp,
                  x=(encoded >> 7) & 1, m=(encoded >> 8) & 1)
            | bits(encoded & 0x7f, 6, 7))


def chk_s(*, reg: int = 20, fp: bool = False, qp: int = 0) -> int:
    # Zero displacement is sufficient for decode/admission coverage.
    return major(1) | bits(3 if fp else 1, 33, 3) | bits(reg, 13, 7) | qp


def chk_a(*, reg: int = 20, fp: bool = False, clear: bool = False,
          qp: int = 0) -> int:
    x3 = (6 if fp else 4) + clear
    return bits(x3, 33, 3) | bits(reg, 6, 7) | qp


def cache_control(opcode: str, *, reg: int = 20, fp: bool = False,
                  qp: int = 0, coherent: bool = False) -> int:
    if opcode == "IA64_OP_FWB":
        return bits(0x20, 27, 6) | qp
    if opcode == "IA64_OP_INVALA":
        return bits(0x10, 27, 6) | qp
    if opcode == "IA64_OP_INVALAT":
        return bits(0x13 if fp else 0x12, 27, 6) | bits(reg, 6, 7) | qp
    if opcode == "IA64_OP_FC":
        return (major(1) | bits(1 if coherent else 0, 36, 1)
                | bits(0x30, 27, 6) | bits(reg, 20, 7) | qp)
    raise ValueError("unknown cache opcode")


def lfetch(*, fault: bool = False, exclusive: bool = False,
           r2: int = 21, r3: int = 10, qp: int = 0,
           update: str = "none", imm: int = 1) -> int:
    x6a = 0x2c + (2 if fault else 0) + (1 if exclusive else 0)
    if update == "none":
        return m_x6a(6, x6a, r1=0, r2=0, r3=r3, qp=qp)
    if update == "reg":
        return m_x6a(6, x6a, r1=0, r2=r2, r3=r3, qp=qp, m=1)
    if update == "imm":
        encoded = imm & 0x1ff
        return (m_x6a(7, x6a, r1=0, r2=0, r3=r3, qp=qp,
                      x=(encoded >> 7) & 1, m=(encoded >> 8) & 1)
                | bits(encoded & 0x7f, 13, 7))
    raise ValueError("unknown lfetch update")


@dataclass(frozen=True)
class DataPlaneOpcodeSpec:
    opcode: str
    family: str
    width: int
    semantic: str
    forms: str
    ordering: str
    nat: str
    alignment: str
    alat: str
    lowering: str
    helper_class: str
    isa_status: str
    decoder_map: str
    runtime_group: str


def _s(opcode: str, family: str, width: int, semantic: str, forms: str,
       ordering: str, nat: str, alignment: str, alat: str,
       lowering: str, helper_class: str, isa_status: str,
       decoder_map: str, runtime_group: str) -> DataPlaneOpcodeSpec:
    return DataPlaneOpcodeSpec(
        opcode, family, width, semantic, forms, ordering, nat, alignment,
        alat, lowering, helper_class, isa_status, decoder_map, runtime_group,
    )


_rows = []
for kind, stem, semantic, nat, alat, helper in (
    ("s", "S", "control-speculative-load", "defer-to-gr-nat", "none",
     "speculative-probe"),
    ("a", "A", "advanced-load", "consume-base", "replace;set-on-success",
     "alat-translation"),
    ("sa", "SA", "control-and-data-speculative-load", "defer-to-gr-nat",
     "replace;set-on-success", "speculative-probe+alat"),
    ("fill", "FILL", "spill-fill-load", "consume-base;result-from-unat",
     "none", "unat"),
    ("c.clr", "C_CLR", "checked-load-clear", "consume-base",
     "hit-preserve-result-and-clear;miss-normal", "alat-translation"),
    ("c.nc", "C_NC", "checked-load-no-clear", "consume-base",
     "hit-preserve-result;miss-load-and-set", "alat-translation"),
):
    for width in (1, 2, 4, 8):
        isa = ("architectural" if kind != "fill" or width == 8
               else "decoder-reserved-width")
        aliases = (
            "x6a={:#04x};split-x/hint-branch-shadowed-by-cmpxchg".format(
                {"s": 4, "a": 8, "sa": 12, "fill": 24,
                 "c.clr": 32, "c.nc": 36}[kind] + WIDTH_CODE[width]
            ) if kind in ("s", "c.clr", "c.nc") else
            "x6a={:#04x}".format(
                {"a": 8, "sa": 12, "fill": 24}[kind]
                + WIDTH_CODE[width]
            )
        )
        _rows.append(_s(
            "IA64_OP_LD{}{}".format(width, stem), "integer-load", width,
            semantic, "M2-none/reg-update;M3-imm9", "unordered", nat,
            "ordinary-psr.ac", alat, "direct-tcg+focused-helper", helper,
            isa, aliases, "integer-spec-alat-fill",
        ))

_rows.append(_s(
    "IA64_OP_LD16", "integer-load", 16, "wide-load-to-gr-and-ar.csd",
    "M2-none;normal/acquire", "unordered-or-acquire", "consume-base",
    "strict-16-byte", "none", "direct-tcg+focused-helper", "wide-memory",
    "architectural", "x=1,x6a=0x28/0x2c;hint-ignored", "wide-spill",
))

_rows.append(_s(
    "IA64_OP_ST16", "integer-store", 16,
    "atomic-wide-store-from-gr-and-ar.csd", "M6-none;normal/release",
    "unordered-or-release", "consume-base-then-value", "strict-16-byte",
    "invalidate-overlap", "direct-tcg", "wide-memory",
    "architectural", "x6=01/03/05/07 or 21/23/25/27", "wide-spill",
))
for width in (1, 2, 4, 8):
    _rows.append(_s(
        "IA64_OP_ST{}SPILL".format(width), "integer-store", width,
        "spill-store-and-unat", "M6-none;M5-imm9", "unordered",
        "consume-base;source-nat-is-data", "ordinary-psr.ac",
        "invalidate-overlap", "direct-tcg+focused-helper", "unat",
        "architectural" if width == 8 else "decoder-reserved-width",
        "x6a={:#04x}".format(0x38 + WIDTH_CODE[width]), "wide-spill",
    ))

for stem in ("XCHG", "CMPXCHG"):
    for width in (1, 2, 4, 8):
        opcode = "IA64_OP_{}{}".format(stem, width)
        _rows.append(_s(
            opcode, "atomic", width,
            "exchange" if stem == "XCHG" else "compare-exchange-ar.ccv",
            "M16-primary;legacy-major2-alias",
            "acquire" if stem == "XCHG" else "acquire-or-release",
            "consume-address-then-value", "strict-natural",
            "invalidate-on-store", "direct-tcg" if stem == "XCHG"
            else "focused-helper", "atomic-rmw" if stem == "XCHG"
            else "atomic-cmpxchg", "architectural",
            "primary-size-bits;legacy b=2 xm/xhint",
            "atomic",
        ))
_rows.append(_s(
    "IA64_OP_CMP8XCHG16", "atomic", 16, "compare-8-exchange-16",
    "M16-acquire/release", "acquire-or-release",
    "consume-address-then-value", "strict-8-byte",
    "invalidate-16-on-store", "focused-helper", "atomic-cmp8xchg16",
    "architectural", "x=1,x6a=0x20/0x24", "atomic",
))
for width in (4, 8):
    _rows.append(_s(
        "IA64_OP_FETCHADD{}".format(width), "atomic", width,
        "fetch-add-immediate-or-legacy-register",
        "M17-inc3;legacy-major3-register-alias", "acquire-or-release",
        "consume-address;legacy-alias-also-consumes-value",
        "strict-natural", "invalidate-overlap", "direct-tcg", "atomic-rmw",
        "architectural-primary+decoder-only-register-alias",
        "x=1,x6a=0x12/13/16/17;legacy b=3", "atomic",
    ))

for opcode, width, semantic in (
    ("IA64_OP_LDFD", 8, "fp-double-load"),
    ("IA64_OP_LDFS", 4, "fp-single-load"),
    ("IA64_OP_LDF_FILL", 16, "fp-spill-format-load"),
    ("IA64_OP_LDFP8", 16, "fp-pair-significand-load"),
    ("IA64_OP_LDFPD", 16, "fp-pair-double-load"),
    ("IA64_OP_LDFPS", 8, "fp-pair-single-load"),
    ("IA64_OP_LDF8", 8, "fp-significand-load"),
    ("IA64_OP_LDFE", 10, "fp-extended-load"),
):
    pair = opcode.startswith("IA64_OP_LDFP")
    fill = opcode == "IA64_OP_LDF_FILL"
    _rows.append(_s(
        opcode, "floating-load", width, semantic,
        "M11/M12" if pair else "M9/M7/M8",
        "unordered", "defer-to-natval-or-consume-base",
        "ordinary-psr.ac;reference-16-byte-span-for-e/fill",
        "normal/s/a/sa/c.clr/c.nc" if not fill else "none",
        "direct-tcg+focused-helper", "fp-memory+alat",
        "architectural",
        ("x6a low={};attr=x6a>>2;pair-x=1".format(FP_X6_LOW[opcode])
         if not fill else "x6a=0x1b"),
        "floating-memory",
    ))

for opcode, width, semantic in (
    ("IA64_OP_STFD", 8, "fp-double-store"),
    ("IA64_OP_STFS", 4, "fp-single-store"),
    ("IA64_OP_STF_SPILL", 16, "fp-spill-format-store"),
    ("IA64_OP_STF8", 8, "fp-significand-store"),
    ("IA64_OP_STFE", 10, "fp-extended-store"),
):
    decoder_map = "x6a={:#04x}".format(FP_STORE_X6[opcode])
    if opcode == "IA64_OP_STFD":
        decoder_map += ";legacy-x6a=0x02-branch-shadowed-by-LDFS"
    elif opcode == "IA64_OP_STFS":
        decoder_map += ";legacy-x6a=0x03-branch-shadowed-by-LDFD"
    elif opcode == "IA64_OP_STF_SPILL":
        decoder_map += ";duplicate-late-branch-shadowed-by-primary-store"
    _rows.append(_s(
        opcode, "floating-store", width, semantic, "M13-none;M10-imm9",
        "unordered", "consume-base;consume-natval-except-spill",
        "ordinary-psr.ac;reference-16-byte-span-for-e/spill",
        "invalidate-overlap", "direct-tcg+focused-helper", "fp-memory",
        "architectural", decoder_map,
        "floating-memory",
    ))

_rows.extend((
    _s("IA64_OP_FWB", "cache", 0, "flush-write-buffer-hint", "M24",
       "unordered-hint", "none", "none", "none", "direct-tcg", "none",
       "architectural", "x6=0x20", "cache-hint"),
    _s("IA64_OP_FC", "cache", 1, "flush-cache-or-icache-coherent", "M28",
       "unordered-nonaccess", "consume-address", "none", "none",
       "focused-helper", "cache-translation", "architectural",
       "major=1,x6=0x30,x=0(fc)/1(fc.i)", "cache-hint"),
    _s("IA64_OP_INVALA", "cache", 0, "invalidate-all-alat", "M24",
       "unordered", "none", "none", "clear-all", "focused-helper", "alat",
       "architectural", "x6=0x10", "cache-hint"),
    _s("IA64_OP_INVALAT", "cache", 0, "invalidate-one-gr-or-fr-alat", "M26/M27",
       "unordered", "none", "none", "clear-selected", "focused-helper",
       "alat", "architectural", "x6=0x12(gr)/0x13(fr)", "cache-hint"),
    _s("IA64_OP_CHK_S", "checked-alat", 0, "branch-if-gr-nat-or-fp-natval",
       "I20/M20/M21", "branch", "test-not-consume", "none", "none",
       "direct-tcg+focused-helper", "checked-branch", "architectural",
       "M major=1,x3=1(gr)/3(fr);I alias", "checked-branch"),
    _s("IA64_OP_CHK_A", "checked-alat", 0, "branch-if-alat-miss-no-clear",
       "M22/M23", "branch", "none", "none", "test-retain",
       "direct-tcg+focused-helper", "checked-branch+alat", "architectural",
       "x3=4(gr)/6(fr)", "checked-branch"),
    _s("IA64_OP_CHK_A_CLR", "checked-alat", 0,
       "branch-if-alat-miss-clear-on-hit", "M22/M23", "branch", "none",
       "none", "test-clear-on-hit", "direct-tcg+focused-helper",
       "checked-branch+alat", "architectural", "x3=5(gr)/7(fr)",
       "checked-branch"),
    _s("IA64_OP_LFETCH", "memory-hint", 1, "nonfaulting-line-prefetch",
       "M18/M20/M22;normal/exclusive", "unordered-hint",
       "suppress-on-base-nat-or-psr.ed", "none", "none",
       "direct-tcg", "none", "architectural", "x6a=0x2c/0x2d",
       "cache-hint"),
    _s("IA64_OP_LFETCH_FAULT", "memory-hint", 1, "faulting-line-prefetch",
       "M18/M20/M22;normal/exclusive", "unordered-nonaccess",
       "consume-base-unless-psr.ed", "none", "none",
       "focused-helper", "lfetch-translation", "architectural",
       "x6a=0x2e/0x2f", "cache-hint"),
))


DATA_PLANE_OPCODE_SPECS: Tuple[DataPlaneOpcodeSpec, ...] = tuple(_rows)
DATA_PLANE_OPCODES = tuple(row.opcode for row in DATA_PLANE_OPCODE_SPECS)
SPEC_BY_OPCODE: Dict[str, DataPlaneOpcodeSpec] = {
    row.opcode: row for row in DATA_PLANE_OPCODE_SPECS
}


def primary_encoding(opcode: str, *, qp: int = 0) -> int:
    row = SPEC_BY_OPCODE[opcode]
    if row.family == "integer-load":
        if opcode == "IA64_OP_LD16":
            return ld16(qp=qp)
        for kind, stem in (("c.clr", "C_CLR"), ("c.nc", "C_NC"),
                           ("fill", "FILL"), ("sa", "SA"),
                           ("s", "S"), ("a", "A")):
            if opcode.endswith(stem):
                return integer_load(row.width, kind, qp=qp)
    if row.family == "integer-store":
        return st16(qp=qp) if opcode == "IA64_OP_ST16" else integer_spill(
            row.width, qp=qp
        )
    if row.family == "atomic":
        return atomic(opcode, qp=qp)
    if row.family == "floating-load":
        return floating_load(opcode, qp=qp)
    if row.family == "floating-store":
        return floating_store(opcode, qp=qp)
    if opcode == "IA64_OP_CHK_S":
        return chk_s(qp=qp)
    if opcode == "IA64_OP_CHK_A":
        return chk_a(qp=qp)
    if opcode == "IA64_OP_CHK_A_CLR":
        return chk_a(clear=True, qp=qp)
    if row.family == "cache":
        return cache_control(opcode, qp=qp)
    if opcode == "IA64_OP_LFETCH":
        return lfetch(qp=qp)
    if opcode == "IA64_OP_LFETCH_FAULT":
        return lfetch(fault=True, qp=qp)
    raise AssertionError("missing primary encoder for " + opcode)


PRIMARY_ENCODINGS: Dict[str, int] = {
    opcode: primary_encoding(opcode) for opcode in DATA_PLANE_OPCODES
}


@dataclass(frozen=True)
class AliasEncoding:
    name: str
    opcode: str
    raw: int
    status: str


def _aliases() -> Iterable[AliasEncoding]:
    for width in (1, 2, 4, 8):
        for kind, stem in (("s", "S"), ("c.clr", "C_CLR"),
                           ("c.nc", "C_NC")):
            opcode = "IA64_OP_LD{}{}".format(width, stem)
            yield AliasEncoding("split-{}-{}".format(kind, width), opcode,
                                integer_load_split_alias(width, kind),
                                "shadowed-by-cmpxchg")
    for opcode in DATA_PLANE_OPCODES:
        if opcode.startswith("IA64_OP_XCHG") or opcode.startswith(
            "IA64_OP_CMPXCHG"
        ) or opcode in ("IA64_OP_FETCHADD4", "IA64_OP_FETCHADD8"):
            yield AliasEncoding("legacy-" + opcode.removeprefix("IA64_OP_").lower(),
                                opcode, atomic_legacy(opcode),
                                "decoder-only")
    for opcode in (
        "IA64_OP_LDFD", "IA64_OP_LDFS", "IA64_OP_LDFP8",
        "IA64_OP_LDFPD", "IA64_OP_LDFPS", "IA64_OP_LDF8",
        "IA64_OP_LDFE",
    ):
        for attr in ("s", "a", "sa", "c.clr", "c.nc"):
            yield AliasEncoding(
                "{}-{}".format(opcode.removeprefix("IA64_OP_").lower(), attr),
                opcode, floating_load(opcode, attr=attr),
                "architectural-completer",
            )
    yield AliasEncoding("fc.i", "IA64_OP_FC",
                        cache_control("IA64_OP_FC", coherent=True),
                        "architectural-completer")
    yield AliasEncoding("lfetch.excl", "IA64_OP_LFETCH",
                        lfetch(exclusive=True), "architectural-completer")
    yield AliasEncoding("lfetch.fault.excl", "IA64_OP_LFETCH_FAULT",
                        lfetch(fault=True, exclusive=True),
                        "architectural-completer")
    yield AliasEncoding("invala.e-fp", "IA64_OP_INVALAT",
                        cache_control("IA64_OP_INVALAT", fp=True),
                        "architectural-form")
    yield AliasEncoding("chk.s-fp", "IA64_OP_CHK_S", chk_s(fp=True),
                        "architectural-form")
    yield AliasEncoding("chk.a-fp", "IA64_OP_CHK_A", chk_a(fp=True),
                        "architectural-form")
    yield AliasEncoding("chk.a.clr-fp", "IA64_OP_CHK_A_CLR",
                        chk_a(fp=True, clear=True), "architectural-form")


ALIAS_ENCODINGS: Tuple[AliasEncoding, ...] = tuple(_aliases())


REFERENCE_ANCHORS = {
    "qemu-decode": "target/ia64/cpu.c:ia64_memory_opcode_from_x6a",
    "qemu-data": "target/ia64/cpu.c:ia64_gen_speculative_load",
    "qemu-atomic": "target/ia64/op_helper.c:helper_cmpxchg",
    "qemu-fp": "target/ia64/op_helper.c:helper_ldfe",
    "ski-load": "src/exec.incl.c:LD_SA_EX",
    "ski-memory": "src/mem_exec.tmpl.c:ldFillEx",
    "manual-check": "Volume 3: Instruction Reference 3:34 chk",
    "manual-memory": "Volume 3: Instruction Reference 3:150 ld",
    "manual-fp": "Volume 3: Instruction Reference 3:156 ldf",
    "manual-hint": "Volume 3: Instruction Reference 3:163 lfetch",
}
