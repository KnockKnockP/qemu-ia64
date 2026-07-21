#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Independent E2 execution for the first IA-64 architectural tranche."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import tempfile
import time
from types import ModuleType
from typing import Callable, Sequence


CASE_TIMEOUT = 5.0
PROCESS_EXIT_TIMEOUT = 2.0
U64_MASK = (1 << 64) - 1
LEGAL_TEMPLATES = (
    (0x00, "MII"), (0x01, "MII"), (0x02, "MII"), (0x03, "MII"),
    (0x04, "MLX"), (0x05, "MLX"),
    (0x08, "MMI"), (0x09, "MMI"), (0x0A, "MMI"), (0x0B, "MMI"),
    (0x0C, "MFI"), (0x0D, "MFI"), (0x0E, "MMF"), (0x0F, "MMF"),
    (0x10, "MIB"), (0x11, "MIB"), (0x12, "MBB"), (0x13, "MBB"),
    (0x16, "BBB"), (0x17, "BBB"), (0x18, "MMB"), (0x19, "MMB"),
    (0x1C, "MFB"), (0x1D, "MFB"),
)


class TrancheFailure(RuntimeError):
    def __init__(self, classification: str, message: str):
        super().__init__(message)
        self.classification = classification


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TrancheFailure("normative-assertion-failure", message)


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise TrancheFailure(
            "test-infrastructure-failure", f"cannot import {path}"
        )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class TrancheGuest:
    def __init__(self, infrastructure: ModuleType, harness: ModuleType,
                 memory: ModuleType, floating: ModuleType,
                 runner: ModuleType, protocol: dict, cases: list[dict]):
        self.infrastructure = infrastructure
        self.h = harness
        self.m = memory
        self.f = floating
        self.r = runner
        self.protocol = protocol
        self.cases = cases
        self.g = infrastructure.GuestBuilder(
            harness, memory, runner, protocol
        )

    def reset_predicates(self) -> None:
        self.g.emit(
            0x01, self.h.nop_m(), self.h.adds(28, 0, 0), self.h.nop_i()
        )
        self.g.emit(
            0x01, self.h.nop_m(), self.h.mov_grpr(28, 0x1FFFF),
            self.h.nop_i(),
        )

    def begin(self, generation: int) -> None:
        enums = self.r.ENUMS
        self.g.command_wait(generation, 16, generation)
        self.g.emit(
            0x01, self.h.mov_m_argr(21, self.h.IA64_AR_ITC),
            self.h.nop_i(), self.h.nop_i(),
        )
        self.g.heartbeat(
            generation, enums["phase"]["running"], generation * 2 - 1, 21
        )
        self.g.command_wait(
            generation, 24, enums["command"]["continue"]
        )

    def publish_result(self, case: dict, actual_register: int,
                       expected: int) -> None:
        generation = case["execution"]["generation"]
        record = self.protocol["record_types"]["result"]
        stride = self.protocol["memory_map"]["result_stride"]
        base = (
            self.r.memory_address(self.protocol, "result_queue")
            + (generation - 1) * stride
        )
        self.g.emit(
            0x01, self.h.mov_m_argr(22, self.h.IA64_AR_ITC),
            self.h.nop_i(), self.h.nop_i(),
        )
        self.g.emit(
            0x01, self.h.nop_m(), self.h.sub(23, 22, 21), self.h.nop_i()
        )
        self.g.movl(29, expected)
        self.g.emit(
            0x03, self.h.nop_m(),
            self.h.cmp_rr(6, 7, actual_register, 29, "eq"), self.h.nop_i(),
        )
        values = (
            0, 1, record["size"], self.protocol["profile"]["id"],
            generation, 700, case["case_id"], case["normative_token"],
            0, self.r.ENUMS["phase"]["complete"], 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0,
            self.r.ENUMS["retry_result"]["not-requested"], 0, 0,
            self.r.ENUMS["classification"]["pass"],
        )
        self.g.words(base, values)
        self.g.movl(11, expected)
        self.g.store_register(base + 88, 11)
        self.g.store_register(base + 96, actual_register)
        self.g.store_register(base + 176, 23)
        self.g.emit(
            0x01, self.h.nop_m(), self.h.adds(11, 1, 0), self.h.nop_i()
        )
        self.g.movl(10, base + 184)
        self.g.emit(
            0x01, self.h.st8(11, 10, qp=7),
            self.h.nop_i(), self.h.nop_i(),
        )
        self.g.movl(11, int(record["magic"], 16))
        self.g.store_register(base, 11, release=True)
        self.g.clear_boundary()
        self.g.heartbeat(
            generation, self.r.ENUMS["phase"]["complete"],
            generation * 2, 22,
        )

    def bundle_format(self) -> tuple[int, int]:
        data = 0x1020304050607080
        self.g.movl(20, 0x7000)
        self.g.emit(
            0x01,
            self.m.load(8, 30, 20),
            self.h.adds(31, 0x155, 0),
            self.h.adds(32, 0x2AA, 0),
        )
        self.g.emit(
            0x03, self.h.nop_m(), self.h.shl_imm(31, 31, 8),
            self.h.shl_imm(32, 32, 20),
        )
        self.g.emit(
            0x03, self.h.nop_m(), self.h.add(33, 30, 31), self.h.nop_i()
        )
        self.g.emit(
            0x03, self.h.nop_m(), self.h.add(30, 33, 32), self.h.nop_i()
        )
        return 30, (data + (0x155 << 8) + (0x2AA << 20)) & U64_MASK

    def template_map(self) -> tuple[int, int]:
        slots = {
            "M": self.h.nop_m(),
            "I": self.h.nop_i(),
            "F": self.h.nop_i(),
            "B": 2 << 37,
        }
        for template, units in LEGAL_TEMPLATES:
            if units == "MLX":
                self.g.emit(template, slots["M"], 0, self.h.nop_i())
            else:
                self.g.emit(template, *(slots[unit] for unit in units))
        self.g.emit(
            0x01, self.h.nop_m(),
            self.h.adds(30, len(LEGAL_TEMPLATES), 0), self.h.nop_i(),
        )
        return 30, len(LEGAL_TEMPLATES)

    def sequential_order(self) -> tuple[int, int]:
        first_ip = self.g.address
        self.g.emit(
            0x01, self.h.nop_m(), self.h.mov_current_ip(30),
            self.h.mov_current_ip(31),
        )
        self.g.emit(
            0x01, self.h.nop_m(), self.h.mov_current_ip(32), self.h.nop_i()
        )
        self.g.emit(
            0x01, self.h.nop_m(), self.h.add(33, 30, 31), self.h.nop_i()
        )
        self.g.emit(
            0x01, self.h.nop_m(), self.h.add(30, 33, 32), self.h.nop_i()
        )
        return 30, first_ip * 2 + first_ip + 0x10

    def stop_visibility(self) -> tuple[int, int]:
        self.g.emit(
            0x01, self.h.nop_m(), self.h.nop_i(),
            self.h.adds(20, 0x33, 0),
        )
        self.g.emit(
            0x01, self.h.nop_m(), self.h.adds(30, 0, 20), self.h.nop_i()
        )
        return 30, 0x33

    def group_entry_war(self) -> tuple[int, int]:
        self.g.emit(
            0x01, self.h.nop_m(), self.h.adds(20, 0x11, 0), self.h.nop_i()
        )
        self.g.emit(
            0x01, self.h.nop_m(), self.h.adds(30, 0, 20),
            self.h.adds(20, 0x22, 0),
        )
        self.g.emit(
            0x01, self.h.nop_m(), self.h.shl_imm(30, 30, 8),
            self.h.nop_i(),
        )
        self.g.emit(
            0x01, self.h.nop_m(), self.h.add(30, 30, 20), self.h.nop_i()
        )
        return 30, 0x1122

    def fr_read(self, register: int) -> tuple[int, int]:
        self.g.emit(
            0x01, self.f.raw_getf("d", 30, register),
            self.h.nop_i(), self.h.nop_i(),
        )
        return 30, 0 if register == 0 else 0x3FF0000000000000

    def gr0_read(self) -> tuple[int, int]:
        self.reset_predicates()
        self.g.emit(
            0x01, self.h.nop_m(), self.h.add(30, 0, 0), self.h.nop_i()
        )
        self.g.emit(
            0x01, self.h.nop_m(),
            self.h.predicate_test(
                "tnat", 6, 7, relation="z", update="normal", r3=30
            ),
            self.h.nop_i(),
        )
        self.g.emit(
            0x01, self.h.nop_m(), self.h.mov_prgr(30), self.h.nop_i()
        )
        return 30, 0x41

    def pr0_read(self) -> tuple[int, int]:
        self.reset_predicates()
        self.g.emit(
            0x01, self.h.nop_m(), self.h.mov_prgr(30),
            self.h.adds(31, 1, 0, qp=0),
        )
        self.g.emit(
            0x01, self.h.nop_m(), self.h.shl_imm(30, 30, 8),
            self.h.nop_i(),
        )
        self.g.emit(
            0x01, self.h.nop_m(), self.h.add(30, 30, 31), self.h.nop_i()
        )
        return 30, 0x101

    def pr0_write(self) -> tuple[int, int]:
        self.reset_predicates()
        self.g.emit(
            0x01, self.h.nop_m(),
            self.h.cmp_rr(0, 6, 0, 0, "lt"), self.h.nop_i(),
        )
        self.g.emit(
            0x01, self.h.nop_m(), self.h.mov_prgr(30), self.h.nop_i()
        )
        return 30, 0x41

    def build_case(self, case: dict) -> None:
        self.begin(case["execution"]["generation"])
        builders: dict[str, Callable[[], tuple[int, int]]] = {
            "BND-001-BUNDLE-FORMAT": self.bundle_format,
            "BND-001-TEMPLATE-MAP": self.template_map,
            "BND-003-SEQUENTIAL-ORDER": self.sequential_order,
            "GRP-002-STOP-VISIBILITY": self.stop_visibility,
            "GRP-004-GROUP-ENTRY-REGISTER": self.group_entry_war,
            "REG-004-FR0-READ": lambda: self.fr_read(0),
            "REG-004-FR1-READ": lambda: self.fr_read(1),
            "REG-004-GR0-READ": self.gr0_read,
            "REG-004-PR0-READ": self.pr0_read,
            "REG-004-PR0-WRITE": self.pr0_write,
        }
        actual, expected = builders[case["normative_row"]]()
        self.publish_result(case, actual, expected)

    def program(self):
        for case in self.cases:
            self.build_case(case)
        terminal = self.g.address
        self.g.bundles.append(self.h.spin_bundle(terminal))
        return self.h.Program(
            name="first architectural tranche persistent batch",
            bundles=tuple(self.g.bundles), terminal_ip=terminal,
            data=(
                self.h.DataWord(
                    self.r.memory_address(self.protocol, "command_queue"), 0, 8
                ),
                self.h.DataWord(
                    self.r.memory_address(self.protocol, "heartbeat"), 0, 8
                ),
                self.h.DataWord(
                    self.r.memory_address(self.protocol, "scratch"), 0, 8
                ),
                self.h.DataWord(0x7000, 0x1020304050607080, 8),
            ),
        )


def run_persistent(root: Path, qemu: Path, harness: ModuleType,
                   memory: ModuleType, floating: ModuleType,
                   runner: ModuleType, infrastructure: ModuleType,
                   protocol: dict, cases: list[dict]) -> list[dict]:
    program = TrancheGuest(
        infrastructure, harness, memory, floating, runner, protocol, cases
    ).program()
    image_end = max(
        [bundle.address + 16 for bundle in program.bundles]
        + [word.address + word.size for word in program.data]
    )
    image = bytearray(image_end)
    for bundle in program.bundles:
        low, high = harness.bundle_words(bundle)
        struct.pack_into("<QQ", image, bundle.address, low, high)
    for word in program.data:
        image[word.address:word.address + word.size] = word.value.to_bytes(
            word.size, "little"
        )
    temporary = tempfile.TemporaryDirectory(prefix="ia64-tranche-")
    image_path = Path(temporary.name) / "guest.img"
    image_path.write_bytes(image)

    monitor_port = harness._free_tcp_port()
    gdb_port = harness._free_tcp_port()
    arguments = [
        str(qemu), "-L", str(root / "pc-bios"),
        "-machine", "vibtanium", "-m", "128M", "-smp", "1", "-S",
        "-display", "none", "-serial", "none",
        "-monitor", (
            f"tcp:127.0.0.1:{monitor_port},server=on,wait=off,nodelay=on"
        ),
        "-gdb", f"tcp:127.0.0.1:{gdb_port},server=on,wait=off",
        "-no-reboot",
        "-device", f"loader,file={image_path.as_posix()},addr=0x0",
        "-device", f"loader,addr=0x{program.entry:x},cpu-num=0",
    ]
    creationflags = (
        getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
    )
    process = subprocess.Popen(
        arguments, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT, text=True, encoding="utf-8",
        errors="replace", env=harness._child_environment(),
        creationflags=creationflags,
    )
    monitor = None
    gdb = None
    results = []
    try:
        monitor = harness._connect_monitor(process, monitor_port)
        harness._recv_hmp_prompt(monitor)
        gdb = harness._connect_gdb(process, gdb_port)
        if not harness._gdb_rsp_command(gdb, "?").startswith("T"):
            raise TrancheFailure(
                "test-infrastructure-failure", "GDB did not report a stop"
            )
        command_base = runner.memory_address(protocol, "command_queue")
        heartbeat_base = runner.memory_address(protocol, "heartbeat")
        result_base = runner.memory_address(protocol, "result_queue")
        heartbeat_size = protocol["record_types"]["heartbeat"]["size"]
        result_size = protocol["record_types"]["result"]["size"]
        stride = protocol["memory_map"]["result_stride"]

        for case in cases:
            generation = case["execution"]["generation"]
            infrastructure.gdb_write(
                gdb, harness, command_base,
                runner.encode_command(protocol, generation, "run"),
            )
            running = {}

            def running_heartbeat() -> bool:
                decoded = infrastructure.optional_record(
                    runner, protocol, "heartbeat",
                    infrastructure.gdb_memory(
                        gdb, harness, heartbeat_base, heartbeat_size
                    ),
                )
                if decoded is None:
                    return False
                if (
                    decoded["generation"] == generation
                    and decoded["phase"] == runner.ENUMS["phase"]["running"]
                ):
                    running.update(decoded)
                    return True
                return False

            infrastructure.poll_stopped(
                process, monitor, running_heartbeat, harness, "heartbeat-loss"
            )
            untouched = infrastructure.gdb_memory(
                gdb, harness, result_base + (generation - 1) * stride, 8
            )
            if int.from_bytes(untouched, "little") != 0:
                raise TrancheFailure(
                    "guest-test-harness-failure",
                    "result appeared before its running heartbeat",
                )
            infrastructure.gdb_write(
                gdb, harness, command_base,
                runner.encode_command(protocol, generation, "continue"),
            )
            completed = {}

            def completed_record() -> bool:
                heartbeat = infrastructure.optional_record(
                    runner, protocol, "heartbeat",
                    infrastructure.gdb_memory(
                        gdb, harness, heartbeat_base, heartbeat_size
                    ),
                )
                result = infrastructure.optional_record(
                    runner, protocol, "result",
                    infrastructure.gdb_memory(
                        gdb, harness,
                        result_base + (generation - 1) * stride, result_size,
                    ),
                )
                if heartbeat is None or result is None:
                    return False
                if (
                    heartbeat["generation"] == generation
                    and heartbeat["phase"]
                    == runner.ENUMS["phase"]["complete"]
                    and result["generation"] == generation
                ):
                    completed.update(result)
                    return True
                return False

            infrastructure.poll_stopped(
                process, monitor, completed_record, harness, "qemu-hang"
            )
            require(completed["test_id"] == 700, "result test id changed")
            require(
                completed["case_id"] == case["case_id"]
                and completed["normative_id"] == case["normative_token"],
                f"{case['id']}: result identity mismatch",
            )
            require(
                completed["classification"]
                == runner.ENUMS["classification"]["pass"],
                f"{case['id']}: guest reported normative failure",
            )
            require(
                completed["actual_state"] == completed["expected_state"],
                f"{case['id']}: expected 0x{completed['expected_state']:x}, "
                f"got 0x{completed['actual_state']:x}",
            )
            require(
                running["sequence"] == generation * 2 - 1,
                f"{case['id']}: heartbeat sequence mismatch",
            )
            results.append(completed)
        return results
    finally:
        if gdb is not None:
            gdb.close()
        if monitor is not None:
            try:
                monitor.sendall(b"quit\n")
            except OSError:
                pass
            monitor.close()
        if process.poll() is None:
            process.terminate()
        try:
            process.communicate(timeout=PROCESS_EXIT_TIMEOUT)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=PROCESS_EXIT_TIMEOUT)
        temporary.cleanup()


def run_fault_repair_retry(qemu: Path, h: ModuleType, runner: ModuleType,
                           protocol: dict, case: dict) -> dict:
    prefix_program = h.equal_target_prefix_fault_program()
    prefix = h.run_program(
        qemu, prefix_program, preserve_fault_slot=True,
        typed_fault_trace_ip=0x50,
    )
    require(
        prefix.exception_pending
        and prefix.exception_kind == "illegal-operation"
        and prefix.exception_vector == h.IA64_GENERAL_EXCEPTION_VECTOR,
        "slot-1 prefix case did not report Illegal Operation",
    )
    require(
        prefix.cr_iip == 0x50
        and ((prefix.cr_ipsr >> h.IA64_PSR_RI_SHIFT) & 3) == 1
        and prefix.cr_iipa == 0x50,
        "slot-1 prefix case saved the wrong IIP/RI/IIPA",
    )
    require(
        prefix.pr == ((1 << 0) | (1 << 1) | (1 << 12))
        and prefix.gr[20] == 77 and prefix.gr[21] == 0,
        "slot-1 fault did not expose exactly its committed prefix",
    )

    slot2_program = h.equal_target_unc_nat_fault_program()
    slot2 = h.run_program(
        qemu, slot2_program, preserve_fault_slot=True,
        typed_fault_trace_ip=0x70,
    )
    require(
        slot2.exception_pending
        and slot2.exception_kind == "illegal-operation"
        and slot2.exception_vector == h.IA64_GENERAL_EXCEPTION_VECTOR,
        "slot-2 prefix case did not report Illegal Operation",
    )
    require(
        slot2.cr_iip == 0x70
        and ((slot2.cr_ipsr >> h.IA64_PSR_RI_SHIFT) & 3) == 2
        and slot2.cr_iipa == 0x70,
        "slot-2 prefix case saved the wrong IIP/RI/IIPA",
    )
    require(
        slot2.pr == ((1 << 0) | (1 << 14))
        and slot2.gr[4] == 0x123456789ABCDEF0
        and slot2.nat_low == (1 << 4)
        and slot2.gr[23] == 66 and slot2.gr[24] == 0,
        "slot-2 fault lost its prefix, NaT input, or post-fault exclusion",
    )

    program, restored_pfs, backing, replacement = (
        h.typed_return_register_fill_fault_program()
    )
    repaired = h.run_program(
        qemu, program, typed_return_traces=((0xA0, 3),),
        typed_rfi_traces=(h.IA64_ALTERNATE_DATA_TLB_VECTOR + 0x60,),
        one_bundle_per_tb=True,
    )
    expected_isr = h.IA64_ISR_R | h.IA64_ISR_RS | h.IA64_ISR_IR
    require(
        repaired.ip == program.terminal_ip
        and repaired.exception_pending
        and repaired.exception_kind == "alternate-data-tlb-miss"
        and repaired.exception_vector == h.IA64_ALTERNATE_DATA_TLB_VECTOR,
        "repair/retry case did not return to its terminal",
    )
    require(
        repaired.exception_source == 0x100
        and repaired.exception_address == 0x8018
        and repaired.cr_iip == 0x100
        and repaired.cr_ifa == 0x8018
        and repaired.cr_iipa == 0xA0
        and repaired.cr_isr == expected_isr
        and repaired.gr[6] == expected_isr,
        "repair/retry case saved an inexact interruption tuple",
    )
    require(
        repaired.gr[5] == 0
        and repaired.gr[12] == (h.IA64_PSR_IC | h.IA64_PSR_RT)
        and repaired.cr_ipsr == h.IA64_PSR_IC,
        "repair handler did not preserve IFS.v=0 or clear only saved RT",
    )
    require(
        repaired.cfm == (4 | (4 << 7))
        and repaired.gr[22] == 0x2A
        and repaired.gr[23] == restored_pfs
        and repaired.gr[32:36] == backing[:3] + (replacement,)
        and repaired.gr[25] == replacement,
        "retry replayed state or failed to consume the replacement word",
    )
    require(
        repaired.rse_base == 92
        and repaired.rse_bsp == 0x8000
        and repaired.rse_bspstore == 0x8000
        and repaired.rse_bspload == 0x8000,
        "retry did not complete the exact backing span",
    )

    record = protocol["record_types"]["result"]
    words = (
        int(record["magic"], 16), 1, record["size"],
        protocol["profile"]["id"], 0, 700, case["case_id"],
        case["normative_token"], 0, runner.ENUMS["phase"]["complete"],
        0, 0, replacement, 1, 1, h.IA64_ALTERNATE_DATA_TLB_VECTOR,
        0x100, repaired.gr[12], repaired.gr[6], 0,
        runner.ENUMS["retry_result"]["repaired-pass"], 0, 0,
        runner.ENUMS["classification"]["pass"],
    )
    return runner.record_words(
        protocol, "result", struct.pack("<24Q", *words)
    )


def load_cases(root: Path) -> list[dict]:
    path = root / "tests/ia64-conformance/first-architectural-tranche.json"
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise TrancheFailure("test-infrastructure-failure", str(exc)) from exc
    return document["cases"]


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.source_root.resolve()
    qemu = args.binary.resolve()
    h = load_module(
        root / "tests/unit/test-ia64-full-tcg.py", "ia64_tranche_harness"
    )
    m = load_module(
        root / "tests/unit/test-ia64-memory-tcg.py", "ia64_tranche_memory"
    )
    f = load_module(
        root / "tests/unit/test-ia64-fp-tcg.py", "ia64_tranche_floating"
    )
    runner = load_module(
        root / "scripts/ia64-conformance-runner.py", "ia64_tranche_protocol"
    )
    infrastructure = load_module(
        root / "tests/unit/test-ia64-conformance-runner.py",
        "ia64_tranche_infrastructure",
    )
    static_validator = load_module(
        root / "scripts/ia64-validate-first-architectural-tranche.py",
        "ia64_tranche_static_validator",
    )
    try:
        try:
            static_validator.validate_literal_bundle_fields()
        except Exception as exc:
            raise TrancheFailure(
                "test-infrastructure-failure",
                f"independent bundle pack/extract oracle failed: {exc}",
            ) from exc
        protocol = runner.load_protocol(
            root / "tests/ia64-conformance/runner-protocol.json"
        )
        cases = load_cases(root)
        persistent_cases = [
            case for case in cases
            if case["execution"]["lane"] == "persistent-guest"
        ]
        fault_case = next(
            case for case in cases
            if case["normative_row"] == "GRP-007-FAULT-COMMITMENT"
        )
        results = run_persistent(
            root, qemu, h, m, f, runner, infrastructure, protocol,
            persistent_cases,
        )
        repair = run_fault_repair_retry(qemu, h, runner, protocol, fault_case)
        require(
            repair["retry_result"]
            == runner.ENUMS["retry_result"]["repaired-pass"],
            "normalized repair/retry result was not repaired-pass",
        )
    except h.HarnessError as exc:
        print("not ok 1 - first architectural tranche "
              f"[guest-test-harness-failure]: {exc}")
        return 1
    except (TrancheFailure, infrastructure.BatchFailure,
            runner.RunnerError) as exc:
        classification = getattr(exc, "classification", "malformed-result")
        print(f"not ok 1 - first architectural tranche "
              f"[{classification}]: {exc}")
        return 1
    print(
        "ok 1 - first architectural tranche passed 11 cases "
        "(10 persistent, 1 precise repair/retry)"
    )
    print("# normative-tokens=" + ",".join(
        str(result["normative_id"]) for result in results
    ) + f",{repair['normative_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
