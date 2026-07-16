#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Focused no-OS runtime matrix for direct IA-64 integer memory lowering.

This test deliberately uses literal architectural expectations instead of the
pre-rewrite interpreter as an oracle.  It imports the process/monitor harness
from test-ia64-full-tcg.py, but owns its memory encoders, programs, semantic
checks, and TCG-op trace checks here.
"""

import argparse
import dataclasses
import importlib.util
from pathlib import Path
import re
import sys
from typing import Dict, List, Optional, Sequence, Tuple


def _load_harness():
    path = Path(__file__).with_name("test-ia64-full-tcg.py")
    spec = importlib.util.spec_from_file_location(
        "_ia64_full_tcg_memory_harness", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load IA-64 full-TCG runtime harness")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


H = _load_harness()

WIDTHS = (1, 2, 4, 8)
WIDTH_CODE = {1: 0, 2: 1, 4: 2, 8: 3}
DATA_PATTERN = 0x8877665544332211
LE_VALUES = {
    1: 0x11,
    2: 0x2211,
    4: 0x44332211,
    8: DATA_PATTERN,
}
BE_VALUES = {
    1: 0x11,
    2: 0x1122,
    4: 0x11223344,
    8: 0x1122334455667788,
}
IA64_PSR_BE = 1 << 1
IA64_PSR_AC = 1 << 3
IA64_ISR_W = 1 << 33
IA64_ISR_NA = 1 << 35


def _check_gr(reg: int) -> None:
    if not 0 <= reg < 128:
        raise ValueError("GR must fit in seven bits")


def load(width: int, r1: int, r3: int, *, qp: int = 0,
         reg_update: Optional[int] = None,
         imm_update: Optional[int] = None,
         acquire: bool = False) -> int:
    """Encode ordinary M1/M2/M3 unsigned integer load forms."""
    if width not in WIDTH_CODE:
        raise ValueError("load width must be 1, 2, 4, or 8")
    _check_gr(r1)
    _check_gr(r3)
    if not 0 <= qp < 64:
        raise ValueError("qualifying predicate must fit in six bits")
    if reg_update is not None and imm_update is not None:
        raise ValueError("load may have only one base update")

    x6a = (0x14 if acquire else 0x00) + WIDTH_CODE[width]
    raw = (
        H.bitfield(x6a, 30, 6)
        | H.bitfield(r3, 20, 7)
        | H.bitfield(r1, 6, 7)
        | H.bitfield(qp, 0, 6)
    )
    if reg_update is not None:
        _check_gr(reg_update)
        return (
            H.op(4)
            | H.bitfield(1, 36, 1)
            | H.bitfield(reg_update, 13, 7)
            | raw
        )
    if imm_update is not None:
        if not -256 <= imm_update <= 255:
            raise ValueError("load update must fit signed imm9")
        encoded = imm_update & 0x1ff
        return (
            H.op(5)
            | H.bitfield(encoded & 0x7f, 13, 7)
            | H.bitfield((encoded >> 7) & 1, 27, 1)
            | H.bitfield((encoded >> 8) & 1, 36, 1)
            | raw
        )
    return H.op(4) | raw


def store(width: int, r2: int, r3: int, *, qp: int = 0,
          imm_update: Optional[int] = None,
          release: bool = False) -> int:
    """Encode ordinary M4/M5 integer store and store-release forms."""
    if width not in WIDTH_CODE:
        raise ValueError("store width must be 1, 2, 4, or 8")
    _check_gr(r2)
    _check_gr(r3)
    if not 0 <= qp < 64:
        raise ValueError("qualifying predicate must fit in six bits")

    x6a = (0x34 if release else 0x30) + WIDTH_CODE[width]
    raw = (
        H.bitfield(x6a, 30, 6)
        | H.bitfield(r3, 20, 7)
        | H.bitfield(r2, 13, 7)
        | H.bitfield(qp, 0, 6)
    )
    if imm_update is None:
        return H.op(4) | raw
    if not -256 <= imm_update <= 255:
        raise ValueError("store update must fit signed imm9")
    encoded = imm_update & 0x1ff
    return (
        H.op(5)
        | H.bitfield(encoded & 0x7f, 6, 7)
        | H.bitfield((encoded >> 7) & 1, 27, 1)
        | H.bitfield((encoded >> 8) & 1, 36, 1)
        | raw
    )


@dataclasses.dataclass(frozen=True)
class TraceExpectation:
    kind: str
    width: int
    endian: str = "le"
    barrier: Optional[str] = None


def _memory_trace_check(trace: str, bundle_ip: int,
                        expected: TraceExpectation) -> None:
    if expected.kind not in ("ld", "st"):
        raise ValueError("trace kind must be ld or st")
    if expected.endian not in ("le", "be"):
        raise ValueError("trace endian must be le or be")

    token = {
        (1, "le"): "ub",
        (1, "be"): "ub",
        (2, "le"): "leuw",
        (2, "be"): "beuw",
        (4, "le"): "leul",
        (4, "be"): "beul",
        (8, "le"): "leq",
        (8, "be"): "beq",
    }[(expected.width, expected.endian)]
    op_re = re.compile(
        r"(?m)^\s*qemu_{}_i64\b[^\n]*$".format(expected.kind)
    )

    for section in H._tcg_op_sections(trace, bundle_ip):
        op_match = op_re.search(section)
        H._require(
            op_match is not None,
            "memory bundle 0x{:x} lacks direct qemu_{}_i64".format(
                bundle_ip, expected.kind
            ),
        )
        op_line = op_match.group(0)
        H._require(
            re.search(r"(?:^|[^a-z0-9_]){}(?:[^a-z0-9_]|$)".format(token),
                      op_line) is not None,
            "memory bundle 0x{:x} expected {} memop, got {!r}".format(
                bundle_ip, token, op_line.strip()
            ),
        )
        H._require(
            re.search(
                r"(?m)^\s*call (?:exec_bundle|exec_slot|"
                r"fast_ldst[^,]*|raw[^,]*),",
                section,
            ) is None,
            "memory bundle 0x{:x} reached a legacy/raw memory seam".format(
                bundle_ip
            ),
        )

        op_pos = op_match.start()
        nat_calls = [
            match.start() for match in re.finditer(
                r"(?m)^\s*call raise_data_register_nat_consumption,",
                section,
            )
        ]
        expected_nat_calls = 1 if expected.kind == "ld" else 2
        H._require(
            len(nat_calls) == expected_nat_calls and
            all(position < op_pos for position in nat_calls),
            "memory bundle 0x{:x} expected {} ordered data-NaT checks "
            "before qemu_{}, found {}".format(
                bundle_ip, expected_nat_calls, expected.kind,
                len(nat_calls),
            ),
        )

        unaligned_calls = [
            match.start() for match in re.finditer(
                r"(?m)^\s*call raise_unaligned_data_reference,", section
            )
        ]
        expected_unaligned_calls = 0 if expected.width == 1 else 1
        H._require(
            len(unaligned_calls) == expected_unaligned_calls and
            all(position < op_pos for position in unaligned_calls),
            "memory bundle 0x{:x} has the wrong focused alignment-check "
            "shape".format(bundle_ip),
        )

        alat_calls = [
            match.start() for match in re.finditer(
                r"(?m)^\s*call memory_store_alat_invalidate,", section
            )
        ]
        if expected.kind == "st":
            H._require(
                len(alat_calls) == 1 and alat_calls[0] > op_pos,
                "store bundle 0x{:x} must invalidate ALAT after qemu_st"
                .format(bundle_ip),
            )
        else:
            H._require(
                not alat_calls,
                "load bundle 0x{:x} unexpectedly invalidates ALAT".format(
                    bundle_ip
                ),
            )

        barriers = [
            match.start()
            for match in re.finditer(r"(?m)^\s*mb\b", section)
        ]
        if expected.barrier == "acquire":
            H._require(
                any(position > op_pos for position in barriers),
                "acquire load 0x{:x} lacks a post-load barrier".format(
                    bundle_ip
                ),
            )
        elif expected.barrier == "release":
            H._require(
                any(position < op_pos for position in barriers),
                "release store 0x{:x} lacks a pre-store barrier".format(
                    bundle_ip
                ),
            )
        elif expected.barrier is not None:
            raise ValueError("unknown memory barrier expectation")


def run_traced(qemu: Path, program, expectations: Dict[int, TraceExpectation],
               *, preserve_fault_slot: bool = False):
    """Run through the shared harness while extending its direct trace gate."""
    original = H._require_typed_direct_trace

    def require_memory_trace(trace: str, bundle_ip: int) -> None:
        original(trace, bundle_ip)
        _memory_trace_check(trace, bundle_ip, expectations[bundle_ip])

    H._require_typed_direct_trace = require_memory_trace
    try:
        return H.run_program(
            qemu,
            program,

            preserve_fault_slot=preserve_fault_slot,
            typed_direct_trace_ips=tuple(expectations),
            one_bundle_per_tb=True,
        )
    finally:
        H._require_typed_direct_trace = original


def _append_i_setup(bundles: List[object], address: int,
                    instructions: Sequence[int]) -> int:
    for index in range(0, len(instructions), 2):
        slot1 = instructions[index]
        slot2 = (
            instructions[index + 1]
            if index + 1 < len(instructions) else H.nop_i()
        )
        bundles.append(H.Bundle(address, 0x03, H.nop_m(), slot1, slot2))
        address += 0x10
    return address


def _append_memory(bundles: List[object], address: int, raw: int) -> int:
    bundles.append(H.Bundle(address, 0x01, raw, H.nop_i(), H.nop_i()))
    return address + 0x10


def _finish_program(name: str, bundles: List[object], address: int,
                    data: Sequence[object] = ()):
    terminal_ip = address
    bundles.append(H.spin_bundle(terminal_ip))
    return H.Program(
        name=name,
        bundles=tuple(bundles),
        terminal_ip=terminal_ip,
        data=tuple(data),
    )


def _load_update_program(mode: str):
    if mode not in ("none", "register", "immediate"):
        raise ValueError("unknown load-update mode")
    bundles: List[object] = []
    address = 0x10
    bases = (10, 11, 12, 13)
    targets = (20, 21, 22, 23)
    increments = (14, 15, 16, 17)
    immediates = (-256, -1, 1, 255)

    setup = [H.adds(reg, 0x1000, 0) for reg in bases]
    if mode == "register":
        setup.extend(
            H.adds(reg, width, 0)
            for reg, width in zip(increments, WIDTHS)
        )
    address = _append_i_setup(bundles, address, setup)

    trace: Dict[int, TraceExpectation] = {}
    for index, width in enumerate(WIDTHS):
        kwargs = {}
        barrier = None
        if mode == "register":
            kwargs = {"reg_update": increments[index], "acquire": True}
            barrier = "acquire"
        elif mode == "immediate":
            kwargs = {"imm_update": immediates[index]}
        raw = load(width, targets[index], bases[index], **kwargs)
        trace[address] = TraceExpectation("ld", width, barrier=barrier)
        address = _append_memory(bundles, address, raw)

    program = _finish_program(
        "ordinary loads: {} base update".format(mode),
        bundles,
        address,
        (H.DataWord(0x1000, DATA_PATTERN, 8),),
    )
    return program, trace, bases, targets, increments, immediates


def test_load_update_matrix(qemu: Path) -> str:
    for mode in ("none", "register", "immediate"):
        (program, trace, bases, targets,
         increments, immediates) = _load_update_program(mode)
        snapshot = run_traced(qemu, program, trace)
        H._require(not snapshot.exception_pending,
                   "{} load matrix raised an exception".format(mode))
        for index, width in enumerate(WIDTHS):
            H._require(
                snapshot.gr[targets[index]] == LE_VALUES[width],
                "{} ld{} returned 0x{:x}, expected 0x{:x}".format(
                    mode, width, snapshot.gr[targets[index]],
                    LE_VALUES[width],
                ),
            )
            expected_base = 0x1000
            if mode == "register":
                expected_base += width
            elif mode == "immediate":
                expected_base = (expected_base + immediates[index]) & H.U64_MASK
            H._require(
                snapshot.gr[bases[index]] == expected_base,
                "{} ld{} base update produced 0x{:x}, expected 0x{:x}"
                .format(mode, width, snapshot.gr[bases[index]], expected_base),
            )
        tracked = sum(1 << reg for reg in bases + targets)
        if mode == "register":
            tracked |= sum(1 << reg for reg in increments)
        H._require((snapshot.nat_low & tracked) == 0,
                   "successful load matrix created an unexpected NaT")
    return (
        "ld1/2/4/8 pass no-update, register-update acquire, and signed-imm9 "
        "update goldens with exact bases, values, NaTs, endian memops, and "
        "post-load barriers"
    )


def _store_update_program(release: bool):
    bundles: List[object] = []
    address = 0x10
    no_bases = (4, 5, 6, 7)
    imm_bases = (8, 9, 10, 11)
    shadows = (12, 13, 14, 15)
    sources = (16, 17, 18, 19)
    no_results = (20, 21, 22, 23)
    imm_results = (24, 25, 26, 27)
    no_addresses = tuple(0x1200 + index * 0x10 for index in range(4))
    imm_addresses = tuple(0x1280 + index * 0x10 for index in range(4))
    source_values = (0x5a, 0x1234, -2, -1)

    setup: List[int] = []
    setup.extend(H.adds(reg, value, 0)
                 for reg, value in zip(no_bases, no_addresses))
    setup.extend(H.adds(reg, value, 0)
                 for reg, value in zip(imm_bases, imm_addresses))
    setup.extend(H.adds(reg, value, 0)
                 for reg, value in zip(shadows, imm_addresses))
    setup.extend(H.adds(reg, value, 0)
                 for reg, value in zip(sources, source_values))
    address = _append_i_setup(bundles, address, setup)

    trace: Dict[int, TraceExpectation] = {}
    barrier = "release" if release else None
    for index, width in enumerate(WIDTHS):
        raw = store(width, sources[index], no_bases[index], release=release)
        trace[address] = TraceExpectation("st", width, barrier=barrier)
        address = _append_memory(bundles, address, raw)
    for index, width in enumerate(WIDTHS):
        raw = store(
            width,
            sources[index],
            imm_bases[index],
            imm_update=width,
            release=release,
        )
        trace[address] = TraceExpectation("st", width, barrier=barrier)
        address = _append_memory(bundles, address, raw)
    for index, width in enumerate(WIDTHS):
        raw = load(width, no_results[index], no_bases[index])
        trace[address] = TraceExpectation("ld", width)
        address = _append_memory(bundles, address, raw)
    for index, width in enumerate(WIDTHS):
        raw = load(width, imm_results[index], shadows[index])
        trace[address] = TraceExpectation("ld", width)
        address = _append_memory(bundles, address, raw)

    data = tuple(
        H.DataWord(location, 0, 8)
        for location in no_addresses + imm_addresses
    )
    program = _finish_program(
        "ordinary {}stores: no and imm base update".format(
            "release " if release else ""
        ),
        bundles,
        address,
        data,
    )
    metadata = (
        no_bases, imm_bases, shadows, sources, no_results, imm_results,
        no_addresses, imm_addresses, source_values,
    )
    return program, trace, metadata


def test_store_update_matrix(qemu: Path) -> str:
    for release in (False, True):
        program, trace, metadata = _store_update_program(release)
        (no_bases, imm_bases, shadows, sources, no_results, imm_results,
         no_addresses, imm_addresses, source_values) = metadata
        snapshot = run_traced(qemu, program, trace)
        label = "release" if release else "ordinary"
        H._require(not snapshot.exception_pending,
                   "{} store matrix raised an exception".format(label))
        for index, width in enumerate(WIDTHS):
            mask = (1 << (width * 8)) - 1
            expected_value = source_values[index] & mask
            H._require(
                snapshot.gr[no_results[index]] == expected_value and
                snapshot.gr[imm_results[index]] == expected_value,
                "{} st{} round trip expected 0x{:x}, got 0x{:x}/0x{:x}"
                .format(
                    label, width, expected_value,
                    snapshot.gr[no_results[index]],
                    snapshot.gr[imm_results[index]],
                ),
            )
            H._require(
                snapshot.gr[no_bases[index]] == no_addresses[index],
                "{} st{} no-update changed its base".format(label, width),
            )
            H._require(
                snapshot.gr[imm_bases[index]] == imm_addresses[index] + width
                and snapshot.gr[shadows[index]] == imm_addresses[index],
                "{} st{} immediate update or shadow is wrong".format(
                    label, width
                ),
            )
        tracked_regs = (
            no_bases + imm_bases + shadows + sources +
            no_results + imm_results
        )
        tracked = sum(1 << reg for reg in tracked_regs)
        H._require((snapshot.nat_low & tracked) == 0,
                   "successful store matrix created an unexpected NaT")
    return (
        "st1/2/4/8 and st1/2/4/8.rel pass both no-update and imm9-update "
        "round trips; direct stores truncate correctly, update last, place "
        "release barriers before qemu_st, and invalidate ALAT afterward"
    )


def _endian_program():
    bundles: List[object] = []
    address = 0x10
    load_bases = (4, 5, 6, 7)
    store_bases = (8, 9, 10, 11)
    sources = (12, 13, 14, 15)
    load_results = (20, 21, 22, 23)
    store_results = (24, 25, 26, 27)
    store_addresses = tuple(0x1400 + index * 0x10 for index in range(4))
    source_values = (0x5a, 0x1234, -2, -2)

    setup: List[int] = []
    setup.extend(H.adds(reg, 0x1000, 0) for reg in load_bases)
    setup.extend(H.adds(reg, value, 0)
                 for reg, value in zip(store_bases, store_addresses))
    setup.extend(H.adds(reg, value, 0)
                 for reg, value in zip(sources, source_values))
    address = _append_i_setup(bundles, address, setup)

    bundles.append(H.Bundle(address, 0x01, H.ssm(IA64_PSR_BE),
                            H.nop_i(), H.nop_i()))
    address += 0x10
    bundles.append(H.Bundle(address, 0x01, H.srlz_d(),
                            H.nop_i(), H.nop_i()))
    address += 0x10

    trace: Dict[int, TraceExpectation] = {}
    for index, width in enumerate(WIDTHS):
        trace[address] = TraceExpectation("ld", width, endian="be")
        address = _append_memory(
            bundles, address,
            load(width, load_results[index], load_bases[index]),
        )
    for index, width in enumerate(WIDTHS):
        trace[address] = TraceExpectation("st", width, endian="be")
        address = _append_memory(
            bundles, address,
            store(width, sources[index], store_bases[index]),
        )

    bundles.append(H.Bundle(address, 0x01, H.rsm(IA64_PSR_BE),
                            H.nop_i(), H.nop_i()))
    address += 0x10
    bundles.append(H.Bundle(address, 0x01, H.srlz_d(),
                            H.nop_i(), H.nop_i()))
    address += 0x10

    for index, width in enumerate(WIDTHS):
        trace[address] = TraceExpectation("ld", width, endian="le")
        address = _append_memory(
            bundles, address,
            load(width, store_results[index], store_bases[index]),
        )

    data = (
        H.DataWord(0x1000, DATA_PATTERN, 8),
        *(H.DataWord(location, 0, 8) for location in store_addresses),
    )
    program = _finish_program(
        "PSR.be direct load/store TB keying", bundles, address, data
    )
    metadata = (load_results, store_results, source_values)
    return program, trace, metadata


def test_endian_tb_keying(qemu: Path) -> str:
    program, trace, metadata = _endian_program()
    load_results, store_results, source_values = metadata
    snapshot = run_traced(qemu, program, trace)
    H._require(not snapshot.exception_pending,
               "PSR.be memory program raised an exception")
    H._require((snapshot.psr & IA64_PSR_BE) == 0,
               "RSM did not clear PSR.be before the terminal TB")
    for index, width in enumerate(WIDTHS):
        H._require(
            snapshot.gr[load_results[index]] == BE_VALUES[width],
            "big-endian ld{} returned 0x{:x}, expected 0x{:x}".format(
                width, snapshot.gr[load_results[index]], BE_VALUES[width]
            ),
        )
        mask = (1 << (width * 8)) - 1
        stored = source_values[index] & mask
        expected_le = int.from_bytes(
            stored.to_bytes(width, "big"), "little"
        )
        H._require(
            snapshot.gr[store_results[index]] == expected_le,
            "big-endian st{} observed through LE expected 0x{:x}, got "
            "0x{:x}".format(
                width, expected_le, snapshot.gr[store_results[index]]
            ),
        )
    return (
        "separate TBs keyed by PSR.be select beuw/beul/beq for loads/stores; "
        "literal byte-order goldens survive BE set/serialize and clear/"
        "serialize transitions"
    )


def _alias_predicate_program():
    bundles: List[object] = []
    address = 0x10
    setup = (
        H.adds(10, 0x1000, 0),
        H.adds(11, 4, 0),
        H.adds(12, 0x1000, 0),
        H.adds(14, 0x1000, 0),
        H.adds(15, 0x1600, 0),
        H.adds(16, 0x1600, 0),
        H.adds(18, -1, 0),
        H.adds(19, 0x1700, 0),
        H.adds(20, 0x55, 0),
        H.adds(23, 0x66, 0),
    )
    address = _append_i_setup(bundles, address, setup)
    trace: Dict[int, TraceExpectation] = {}

    rows = (
        (load(8, 10, 10), TraceExpectation("ld", 8)),
        (load(8, 11, 12, reg_update=11), TraceExpectation("ld", 8)),
        (load(8, 13, 14, reg_update=14), TraceExpectation("ld", 8)),
        (store(8, 15, 15), TraceExpectation("st", 8)),
        (load(8, 17, 16), TraceExpectation("ld", 8)),
        (load(8, 23, 18, qp=1), TraceExpectation("ld", 8)),
    )
    for raw, expected in rows:
        trace[address] = expected
        address = _append_memory(bundles, address, raw)

    # Statically illegal r0 destination: a false qualifier must suppress it.
    address = _append_memory(bundles, address, load(8, 0, 18, qp=1))

    # A valid false-qualified store must not touch memory or its operands.
    trace[address] = TraceExpectation("st", 8)
    address = _append_memory(bundles, address, store(8, 20, 19, qp=1))
    trace[address] = TraceExpectation("ld", 8)
    address = _append_memory(bundles, address, load(8, 22, 19))

    program = _finish_program(
        "ordinary memory legal aliases and false qualification",
        bundles,
        address,
        (
            H.DataWord(0x1000, DATA_PATTERN, 8),
            H.DataWord(0x1600, 0, 8),
            H.DataWord(0x1700, 0x777, 8),
        ),
    )
    return program, trace


def test_aliases_and_predication(qemu: Path) -> str:
    program, trace = _alias_predicate_program()
    snapshot = run_traced(qemu, program, trace)
    H._require(not snapshot.exception_pending,
               "legal-alias/nullification program raised an exception")
    H._require(snapshot.gr[10] == DATA_PATTERN,
               "no-update load r1==r3 did not retain the loaded result")
    H._require(
        snapshot.gr[11] == DATA_PATTERN and snapshot.gr[12] == 0x1004,
        "register-update load r1==r2 lost its saved increment",
    )
    H._require(
        snapshot.gr[13] == DATA_PATTERN and snapshot.gr[14] == 0x2000,
        "register-update load r2==r3 lost its saved base/increment pair",
    )
    H._require(
        snapshot.gr[15] == 0x1600 and snapshot.gr[17] == 0x1600,
        "store source==base did not store its group-entry address",
    )
    H._require(
        snapshot.gr[18] == H.U64_MASK and snapshot.gr[23] == 0x66,
        "false invalid-address load changed its base or destination",
    )
    H._require(
        snapshot.gr[19] == 0x1700 and snapshot.gr[20] == 0x55 and
        snapshot.gr[22] == 0x777,
        "false-qualified store changed memory or an operand",
    )
    return (
        "legal r1==r3 no-update, r1==r2 and r2==r3 register-update loads, "
        "and source==base store use group-entry pairs; p1=false suppresses "
        "invalid memory, a statically illegal r0 target, and store effects"
    )


def _nat_update_program():
    bundles: List[object] = []
    address = 0x10
    address = _append_i_setup(
        bundles,
        address,
        (
            H.adds(1, 1, 0),
            H.adds(2, 0x1000, 0),
            H.adds(10, 0x1800, 0),
        ),
    )
    bundles.append(H.Bundle(address, 0x01, H.mov_m_grar(36, 1),
                            H.nop_i(), H.nop_i()))
    address += 0x10
    address = _append_memory(bundles, address, H.ld8_fill(12, 2))
    trace = {address: TraceExpectation("ld", 8)}
    address = _append_memory(
        bundles, address, load(8, 20, 10, reg_update=12)
    )
    program = _finish_program(
        "load register-update propagates increment NaT",
        bundles,
        address,
        (
            H.DataWord(0x1000, 4, 8),
            H.DataWord(0x1800, DATA_PATTERN, 8),
        ),
    )
    return program, trace


def _nat_fault_program(mode: str):
    if mode not in ("load-base", "store-value", "store-both"):
        raise ValueError("unknown data-NaT fault mode")
    bundles: List[object] = list(H._interruption_collection_setup())
    address = 0x30
    address = _append_i_setup(
        bundles,
        address,
        (
            H.adds(1, 1, 0),
            H.adds(2, 0x1000, 0),
            H.adds(10, 0x1fff, 0),
        ),
    )
    bundles.append(H.Bundle(address, 0x01, H.mov_m_grar(36, 1),
                            H.nop_i(), H.nop_i()))
    address += 0x10

    if mode == "load-base":
        address = _append_memory(bundles, address, H.ld8_fill(10, 2))
        fault_raw = load(8, 20, 10)
        kind = "ld"
    elif mode == "store-value":
        address = _append_memory(bundles, address, H.ld8_fill(11, 2))
        fault_raw = store(8, 11, 10)
        kind = "st"
    else:
        address = _append_memory(bundles, address, H.ld8_fill(10, 2))
        address = _append_memory(bundles, address, H.ld8_fill(11, 2))
        fault_raw = store(8, 11, 10)
        kind = "st"

    fault_ip = address
    address = _append_memory(bundles, address, fault_raw)
    bundles.append(H._exception_vector_spin(
        H.IA64_REGISTER_NAT_CONSUMPTION_VECTOR
    ))
    program = H.Program(
        name="ordinary memory {} Register NaT Consumption".format(mode),
        bundles=tuple(bundles),
        terminal_ip=H.IA64_REGISTER_NAT_CONSUMPTION_VECTOR,
        data=(H.DataWord(0x1000, 0x1fff, 8),),
    )
    trace = {fault_ip: TraceExpectation(kind, 8)}
    return program, trace, fault_ip, fault_raw, kind


def _require_data_nat_fault(snapshot, *, fault_ip: int, fault_raw: int,
                            kind: str, address_nat: bool) -> None:
    access_bit = H.IA64_ISR_R if kind == "ld" else IA64_ISR_W
    expected_isr = H.IA64_ISR_CODE_REGISTER_NAT_CONSUMPTION | access_bit
    if address_nat:
        expected_isr |= IA64_ISR_NA
    H._require(
        snapshot.ip == H.IA64_REGISTER_NAT_CONSUMPTION_VECTOR and
        snapshot.exception_pending and
        snapshot.exception_kind == "register-nat-consumption" and
        snapshot.exception_vector == H.IA64_REGISTER_NAT_CONSUMPTION_VECTOR,
        "ordinary {} data-NaT did not reach Register NaT Consumption"
        .format(kind),
    )
    H._require(
        snapshot.exception_source == fault_ip and
        snapshot.exception_address == fault_ip and
        snapshot.cr_ifa == fault_ip,
        "ordinary {} data-NaT published the wrong source/address/IFA"
        .format(kind),
    )
    H._require(
        snapshot.cr_isr == expected_isr and snapshot.cr_iip == fault_ip,
        "ordinary {} data-NaT expected ISR/IIP 0x{:x}/0x{:x}, got "
        "0x{:x}/0x{:x}".format(
            kind, expected_isr, fault_ip, snapshot.cr_isr, snapshot.cr_iip
        ),
    )
    H._require(
        snapshot.slot_valid and snapshot.slot_ip == fault_ip and
        snapshot.slot_ri == 0 and
        snapshot.slot_type == H.IA64_SLOT_TYPE_M and
        snapshot.slot_raw == (fault_raw & H.SLOT_MASK),
        "ordinary {} data-NaT lost its exact M-slot publication".format(kind),
    )
    H._require(
        (snapshot.cr_ipsr & H.IA64_PSR_IC) != 0 and
        ((snapshot.cr_ipsr >> H.IA64_PSR_RI_SHIFT) & 3) == 0 and
        not snapshot.psr_ic_inflight,
        "ordinary {} data-NaT lost collected IC/RI or serialization".format(
            kind
        ),
    )


def test_nat_access_and_priority(qemu: Path) -> str:
    propagation_program, propagation_trace = _nat_update_program()
    propagated = run_traced(qemu, propagation_program, propagation_trace)
    H._require(not propagated.exception_pending,
               "NaT-tagged load increment was incorrectly consumed")
    H._require(
        propagated.gr[20] == DATA_PATTERN and propagated.gr[10] == 0x1804,
        "NaT-tagged register update lost its load value or arithmetic base",
    )
    H._require(
        (propagated.nat_low & ((1 << 10) | (1 << 12) | (1 << 20))) ==
        ((1 << 10) | (1 << 12)),
        "load register update did not propagate increment NaT to the base "
        "while clearing the loaded target",
    )

    for mode in ("load-base", "store-value", "store-both"):
        program, trace, fault_ip, fault_raw, kind = _nat_fault_program(mode)
        snapshot = run_traced(
            qemu, program, trace, preserve_fault_slot=True
        )
        _require_data_nat_fault(
            snapshot,
            fault_ip=fault_ip,
            fault_raw=fault_raw,
            kind=kind,
            address_nat=mode != "store-value",
        )
        expected_nat = (1 << 10) if mode == "load-base" else (1 << 11)
        if mode == "store-both":
            expected_nat |= 1 << 10
        H._require(
            (snapshot.nat_low & ((1 << 10) | (1 << 11))) == expected_nat,
            "{} did not preserve the seeded base/value NaTs".format(mode),
        )
    return (
        "register increments propagate NaT without consumption; base-load, "
        "value-store, and dual-NaT store faults preserve exact R/W/NA ISR, "
        "slot, IC/RI, and preempt cross-page alignment, while traces place "
        "base then value NaT gates before direct memory"
    )


def _relaxed_alignment_program():
    bundles: List[object] = []
    address = 0x10
    address = _append_i_setup(
        bundles,
        address,
        (
            H.adds(10, 0x1801, 0),
            H.adds(11, 0x1901, 0),
            H.adds(12, 0x1234, 0),
            H.adds(13, 0x1901, 0),
        ),
    )
    trace: Dict[int, TraceExpectation] = {}
    trace[address] = TraceExpectation("ld", 4)
    address = _append_memory(bundles, address, load(4, 20, 10))
    trace[address] = TraceExpectation("st", 2)
    address = _append_memory(bundles, address, store(2, 12, 11))
    trace[address] = TraceExpectation("ld", 2)
    address = _append_memory(bundles, address, load(2, 21, 13))
    program = _finish_program(
        "AC-clear same-page unaligned ordinary memory",
        bundles,
        address,
        (
            H.DataWord(0x1800, DATA_PATTERN, 8),
            H.DataWord(0x1900, 0, 8),
        ),
    )
    return program, trace


def _unaligned_fault_program(kind: str):
    if kind not in ("ac-load", "cross-store"):
        raise ValueError("unknown unaligned fault mode")
    bundles: List[object] = list(H._interruption_collection_setup())
    address = 0x30
    if kind == "ac-load":
        address = _append_i_setup(
            bundles, address, (H.adds(10, 0x1801, 0),)
        )
        bundles.append(H.Bundle(address, 0x01, H.ssm(IA64_PSR_AC),
                                H.nop_i(), H.nop_i()))
        address += 0x10
        bundles.append(H.Bundle(address, 0x01, H.srlz_d(),
                                H.nop_i(), H.nop_i()))
        address += 0x10
        fault_raw = load(4, 20, 10)
        access = "ld"
        fault_address = 0x1801
    else:
        address = _append_i_setup(
            bundles,
            address,
            (H.adds(10, 0x1fff, 0), H.adds(11, 0x55, 0)),
        )
        fault_raw = store(8, 11, 10)
        access = "st"
        fault_address = 0x1fff

    fault_ip = address
    address = _append_memory(bundles, address, fault_raw)
    bundles.append(H._exception_vector_spin(
        H.IA64_UNALIGNED_DATA_REFERENCE_VECTOR
    ))
    program = H.Program(
        name="ordinary memory {} Unaligned Data Reference".format(kind),
        bundles=tuple(bundles),
        terminal_ip=H.IA64_UNALIGNED_DATA_REFERENCE_VECTOR,
        data=(H.DataWord(0x1800, DATA_PATTERN, 8),),
    )
    trace = {fault_ip: TraceExpectation(access, 4 if access == "ld" else 8)}
    return program, trace, fault_ip, fault_raw, access, fault_address


def _require_unaligned_fault(snapshot, *, fault_ip: int, fault_raw: int,
                             access: str, fault_address: int) -> None:
    expected_isr = H.IA64_ISR_R if access == "ld" else IA64_ISR_W
    H._require(
        snapshot.ip == H.IA64_UNALIGNED_DATA_REFERENCE_VECTOR and
        snapshot.exception_pending and
        snapshot.exception_kind == "unaligned-data-reference" and
        snapshot.exception_vector == H.IA64_UNALIGNED_DATA_REFERENCE_VECTOR,
        "ordinary {} did not reach Unaligned Data Reference".format(access),
    )
    H._require(
        snapshot.exception_source == fault_ip and
        snapshot.exception_address == fault_address and
        snapshot.cr_ifa == fault_address,
        "ordinary {} unaligned fault lost its exact address".format(access),
    )
    H._require(
        snapshot.cr_isr == expected_isr and snapshot.cr_iip == fault_ip,
        "ordinary {} unaligned fault has wrong R/W ISR or IIP".format(
            access
        ),
    )
    H._require(
        snapshot.slot_valid and snapshot.slot_ip == fault_ip and
        snapshot.slot_ri == 0 and
        snapshot.slot_type == H.IA64_SLOT_TYPE_M and
        snapshot.slot_raw == (fault_raw & H.SLOT_MASK),
        "ordinary {} unaligned fault lost exact M-slot state".format(access),
    )


def test_alignment_policy(qemu: Path) -> str:
    relaxed_program, relaxed_trace = _relaxed_alignment_program()
    relaxed = run_traced(qemu, relaxed_program, relaxed_trace)
    H._require(not relaxed.exception_pending,
               "AC-clear same-page unaligned memory unexpectedly faulted")
    H._require(
        relaxed.gr[20] == 0x55443322 and relaxed.gr[21] == 0x1234,
        "AC-clear unaligned load/store returned 0x{:x}/0x{:x}".format(
            relaxed.gr[20], relaxed.gr[21]
        ),
    )

    for mode in ("ac-load", "cross-store"):
        (program, trace, fault_ip, fault_raw,
         access, fault_address) = _unaligned_fault_program(mode)
        snapshot = run_traced(
            qemu, program, trace, preserve_fault_slot=True
        )
        _require_unaligned_fault(
            snapshot,
            fault_ip=fault_ip,
            fault_raw=fault_raw,
            access=access,
            fault_address=fault_address,
        )
        if mode == "ac-load":
            H._require((snapshot.cr_ipsr & IA64_PSR_AC) != 0,
                       "AC-strict load did not preserve AC in IPSR")
        else:
            H._require((snapshot.cr_ipsr & IA64_PSR_AC) == 0,
                       "cross-page store unexpectedly set AC")
    return (
        "AC-clear same-page unaligned ld4/st2 succeeds; AC-set ld4 and "
        "AC-clear cross-page st8 raise precise read/write Unaligned Data "
        "Reference with exact IFA and M-slot publication"
    )


def _print_failure(exc: Exception) -> None:
    for line in str(exc).splitlines() or [repr(exc)]:
        print("# " + line)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--qemu",
        required=True,
        type=Path,
        help="path to qemu-system-ia64 (an .exe is accepted on Windows)",
    )
    args = parser.parse_args(argv)
    qemu = args.qemu.expanduser().resolve()
    tests = (
        ("ordinary load width/update matrix", test_load_update_matrix),
        ("ordinary and release store matrix", test_store_update_matrix),
        ("PSR.be TB-keyed memory", test_endian_tb_keying),
        ("memory aliases and nullification", test_aliases_and_predication),
        ("memory NaT access and priority", test_nat_access_and_priority),
        ("ordinary memory alignment policy", test_alignment_policy),
    )

    print("TAP version 13")
    print("1..{}".format(len(tests)))
    if not qemu.is_file():
        for index, (name, _test) in enumerate(tests, start=1):
            print("not ok {} - {}".format(index, name))
        print("# QEMU executable does not exist: {}".format(qemu))
        return 1

    failures = 0
    for index, (name, test) in enumerate(tests, start=1):
        try:
            detail = test(qemu)
            print("ok {} - {}".format(index, name))
            print("# " + detail)
        except Exception as exc:
            failures += 1
            print("not ok {} - {}".format(index, name))
            _print_failure(exc)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
