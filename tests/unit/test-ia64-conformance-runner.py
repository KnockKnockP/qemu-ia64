#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Minimal persistent IA-64 bare-metal conformance batch.

This is a runner self-test, not normative architectural evidence.  One QEMU
process executes three commanded guest cases.  Binary heartbeat records are
observed before their corresponding result records, and the second case proves
that poisoned register and memory state from the first case was cleared.
"""

from __future__ import annotations

import argparse
import importlib.util
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
from types import ModuleType
from typing import Callable, Sequence


CASE_TIMEOUT = 5.0
PROCESS_EXIT_TIMEOUT = 2.0


class BatchFailure(RuntimeError):
    def __init__(self, classification: str, message: str):
        super().__init__(message)
        self.classification = classification


def load_module(path: Path, name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise BatchFailure(
            "test-infrastructure-failure", f"cannot import {path}"
        )
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


class GuestBuilder:
    def __init__(self, harness: ModuleType, memory: ModuleType,
                 runner: ModuleType, protocol: dict):
        self.h = harness
        self.m = memory
        self.r = runner
        self.protocol = protocol
        self.address = 0x10
        self.bundles = []

    def emit(self, template: int, slot0: int, slot1: int,
             slot2: int) -> int:
        address = self.address
        self.bundles.append(
            self.h.Bundle(address, template, slot0, slot1, slot2)
        )
        self.address += 0x10
        return address

    def movl(self, register: int, value: int) -> None:
        value &= (1 << 64) - 1
        l_slot = (value >> 22) & ((1 << 41) - 1)
        x_slot = (
            self.h.bitfield(register, 6, 7)
            | self.h.bitfield(value & 0x7f, 13, 7)
            | self.h.bitfield((value >> 21) & 1, 21, 1)
            | self.h.bitfield((value >> 16) & 0x1f, 22, 5)
            | self.h.bitfield((value >> 7) & 0x1ff, 27, 9)
            | self.h.bitfield((value >> 63) & 1, 36, 1)
            | self.h.bitfield(6, 37, 4)
        )
        self.emit(0x05, self.h.nop_m(), l_slot, x_slot)

    def words(self, base: int, values: Sequence[int]) -> None:
        if not values:
            return
        self.movl(10, base)
        self.movl(11, values[0])
        for index in range(len(values)):
            following = values[index + 1] if index + 1 < len(values) else 0
            if not -8192 <= following <= 8191:
                raise ValueError("only the first protocol word may need movl")
            self.emit(
                0x01,
                self.m.store(8, 11, 10, imm_update=8),
                self.h.adds(11, following, 0),
                self.h.nop_i(),
            )

    def store_register(self, address: int, register: int,
                       qp: int = 0, release: bool = False) -> None:
        self.movl(10, address)
        self.emit(
            0x01, self.m.store(
                8, register, 10, qp=qp, release=release
            ),
            self.h.nop_i(), self.h.nop_i(),
        )

    def command_wait(self, generation: int, field_offset: int,
                     expected: int) -> None:
        command = self.r.memory_address(self.protocol, "command_queue")
        self.movl(10, command + field_offset)
        self.emit(
            0x01, self.h.nop_m(),
            self.h.adds(3, expected, 0), self.h.nop_i(),
        )
        loop = self.address
        self.emit(
            0x01, self.m.load(8, 2, 10, acquire=True),
            self.h.nop_i(), self.h.nop_i(),
        )
        self.emit(
            0x03, self.h.nop_m(),
            self.h.cmp_rr(6, 7, 2, 3, "eq"), self.h.nop_i(),
        )
        self.emit(
            0x11, self.h.nop_m(), self.h.nop_i(),
            self.h.br_cond(self.address, loop, qp=7),
        )

    def heartbeat(self, generation: int, phase: int, sequence: int,
                  tick_register: int) -> None:
        record = self.protocol["record_types"]["heartbeat"]
        values = (
            0, 1, generation, phase, sequence, 0,
        )
        base = self.r.memory_address(self.protocol, "heartbeat")
        self.words(base, values)
        self.store_register(base + 40, tick_register)
        self.movl(11, int(record["magic"], 16))
        self.store_register(base, 11, release=True)

    def result(self, generation: int, case_id: int,
               initial: int, expected: int, actual_register: int,
               elapsed_register: int, failure_qp: int = 0) -> None:
        record = self.protocol["record_types"]["result"]
        stride = self.protocol["memory_map"]["result_stride"]
        base = (
            self.r.memory_address(self.protocol, "result_queue")
            + (generation - 1) * stride
        )
        values = (
            0, 1, record["size"],
            self.protocol["profile"]["id"], generation, 600, case_id, 0,
            0, self.r.ENUMS["phase"]["complete"], initial, expected, 0,
            0, 0, 0, 0, 0, 0, 0,
            self.r.ENUMS["retry_result"]["not-requested"], 0, 0,
            self.r.ENUMS["classification"]["pass"],
        )
        self.words(base, values)
        self.store_register(base + 96, actual_register)
        self.store_register(base + 176, elapsed_register)
        if failure_qp:
            self.emit(
                0x01, self.h.nop_m(),
                self.h.adds(11, 1, 0), self.h.nop_i(),
            )
            self.movl(10, base + 184)
            self.emit(
                0x01, self.h.st8(11, 10, qp=failure_qp),
                self.h.nop_i(), self.h.nop_i(),
            )
        self.movl(11, int(record["magic"], 16))
        self.store_register(base, 11, release=True)

    def clear_boundary(self) -> None:
        command = self.r.memory_address(self.protocol, "command_queue")
        scratch = self.r.memory_address(self.protocol, "scratch")
        self.emit(
            0x01, self.h.nop_m(),
            self.h.adds(11, 0, 0), self.h.adds(20, 0, 0),
        )
        self.store_register(scratch, 11)
        self.store_register(command + 16, 11)
        self.store_register(command + 24, 11)

    def build_case(self, generation: int, case_id: int) -> None:
        enums = self.r.ENUMS
        scratch = self.r.memory_address(self.protocol, "scratch")
        self.command_wait(generation, 16, generation)
        self.emit(
            0x01, self.h.mov_m_argr(21, self.h.IA64_AR_ITC),
            self.h.nop_i(), self.h.nop_i(),
        )
        self.heartbeat(
            generation, enums["phase"]["running"], generation * 2 - 1, 21
        )
        self.command_wait(
            generation, 24, enums["command"]["continue"]
        )

        failure_qp = 0
        actual_register = 30
        if generation == 2:
            self.movl(10, scratch)
            self.emit(
                0x01, self.h.ld8(30, 10),
                self.h.nop_i(), self.h.nop_i(),
            )
            self.emit(
                0x01, self.h.nop_m(),
                self.h.add(31, 30, 20), self.h.nop_i(),
            )
            self.emit(
                0x03, self.h.nop_m(),
                self.h.cmp_rr(6, 7, 31, 0, "eq"), self.h.nop_i(),
            )
            actual_register = 31
            failure_qp = 7
        else:
            self.emit(
                0x01, self.h.nop_m(),
                self.h.adds(30, generation if generation == 3 else 0, 0),
                self.h.nop_i(),
            )

        self.emit(
            0x01, self.h.mov_m_argr(22, self.h.IA64_AR_ITC),
            self.h.nop_i(), self.h.nop_i(),
        )
        self.emit(
            0x01, self.h.nop_m(),
            self.h.sub(23, 22, 21), self.h.nop_i(),
        )
        expected = generation if generation == 3 else 0
        self.result(
            generation, case_id, 0, expected, actual_register, 23,
            failure_qp=failure_qp,
        )

        if generation < 3:
            self.movl(10, scratch)
            self.emit(
                0x01, self.h.nop_m(),
                self.h.adds(11, 0x55, 0),
                self.h.adds(20, 0x66, 0),
            )
            self.emit(
                0x01, self.h.st8(11, 10),
                self.h.nop_i(), self.h.nop_i(),
            )
        self.clear_boundary()
        self.heartbeat(
            generation, enums["phase"]["complete"], generation * 2, 22
        )

    def program(self):
        for generation in range(1, 4):
            self.build_case(generation, generation)
        terminal = self.address
        self.bundles.append(self.h.spin_bundle(terminal))
        return self.h.Program(
            name="persistent conformance runner self-test",
            bundles=tuple(self.bundles), terminal_ip=terminal,
            data=(
                self.h.DataWord(
                    self.r.memory_address(self.protocol, "command_queue"),
                    0, 8,
                ),
                self.h.DataWord(
                    self.r.memory_address(self.protocol, "heartbeat"), 0, 8,
                ),
                self.h.DataWord(
                    self.r.memory_address(self.protocol, "scratch"), 0, 8,
                ),
            ),
        )


def gdb_memory(gdb: socket.socket, harness: ModuleType,
               address: int, size: int) -> bytes:
    response = harness._gdb_rsp_command(
        gdb, "m{:x},{:x}".format(address, size)
    )
    if response.startswith("E") or len(response) != size * 2:
        raise BatchFailure(
            "test-infrastructure-failure",
            f"GDB memory read failed at 0x{address:x}: {response}",
        )
    try:
        return bytes.fromhex(response)
    except ValueError as exc:
        raise BatchFailure("malformed-result", str(exc)) from exc


def gdb_write(gdb: socket.socket, harness: ModuleType,
              address: int, payload: bytes) -> None:
    response = harness._gdb_rsp_command(
        gdb, "M{:x},{:x}:{}".format(address, len(payload), payload.hex())
    )
    if response != "OK":
        raise BatchFailure(
            "test-infrastructure-failure",
            f"GDB memory write failed at 0x{address:x}: {response}",
        )


def optional_record(runner: ModuleType, protocol: dict, name: str,
                    payload: bytes) -> dict | None:
    if int.from_bytes(payload[:8], "little") == 0:
        return None
    try:
        return runner.record_words(protocol, name, payload)
    except runner.RunnerError as exc:
        raise BatchFailure("malformed-result", str(exc)) from exc


def poll_stopped(process: subprocess.Popen, monitor: socket.socket,
                 predicate: Callable[[], bool], harness: ModuleType,
                 classification: str) -> None:
    deadline = time.monotonic() + CASE_TIMEOUT
    delay = 0.002
    while time.monotonic() < deadline:
        if process.poll() is not None:
            output = process.stdout.read() if process.stdout else ""
            category = (
                "qemu-assertion" if "assert" in output.lower()
                else "qemu-abort" if process.returncode else "unexpected-exit"
            )
            raise BatchFailure(category, output or "QEMU exited")
        harness._hmp_command(monitor, "cont")
        time.sleep(delay)
        harness._hmp_command(monitor, "stop")
        if predicate():
            return
        delay = min(delay * 2, 0.02)
    raise BatchFailure(classification, "persistent guest progress timed out")


def run_batch(root: Path, qemu: Path) -> list[dict]:
    harness = load_module(
        root / "tests/unit/test-ia64-full-tcg.py", "ia64_batch_harness"
    )
    memory = load_module(
        root / "tests/unit/test-ia64-memory-tcg.py", "ia64_batch_memory"
    )
    runner = load_module(
        root / "scripts/ia64-conformance-runner.py", "ia64_batch_protocol"
    )
    try:
        protocol = runner.load_protocol(
            root / "tests/ia64-conformance/runner-protocol.json"
        )
    except runner.RunnerError as exc:
        raise BatchFailure("test-infrastructure-failure", str(exc)) from exc
    program = GuestBuilder(harness, memory, runner, protocol).program()
    monitor_port = harness._free_tcp_port()
    gdb_port = harness._free_tcp_port()
    arguments = [
        str(qemu), "-L", str(root / "pc-bios"),
        "-machine", "vibtanium", "-m", "128M", "-smp", "1", "-S",
        "-display", "none", "-serial", "none",
        "-monitor", (
            "tcp:127.0.0.1:{},server=on,wait=off,nodelay=on"
            .format(monitor_port)
        ),
        "-gdb", "tcp:127.0.0.1:{},server=on,wait=off".format(gdb_port),
        "-no-reboot",
    ]
    arguments.extend(harness._loader_arguments(program))
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
            raise BatchFailure(
                "test-infrastructure-failure", "GDB did not report a stop"
            )
        command_base = runner.memory_address(protocol, "command_queue")
        heartbeat_base = runner.memory_address(protocol, "heartbeat")
        result_base = runner.memory_address(protocol, "result_queue")
        heartbeat_size = protocol["record_types"]["heartbeat"]["size"]
        result_size = protocol["record_types"]["result"]["size"]
        stride = protocol["memory_map"]["result_stride"]

        for generation in range(1, 4):
            gdb_write(
                gdb, harness, command_base,
                runner.encode_command(protocol, generation, "run"),
            )
            running = {}

            def running_heartbeat() -> bool:
                decoded = optional_record(
                    runner, protocol, "heartbeat",
                    gdb_memory(
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

            poll_stopped(
                process, monitor, running_heartbeat, harness, "heartbeat-loss"
            )
            untouched = gdb_memory(
                gdb, harness, result_base + (generation - 1) * stride, 8
            )
            if int.from_bytes(untouched, "little") != 0:
                raise BatchFailure(
                    "guest-test-harness-failure",
                    "result appeared before the running heartbeat rendezvous",
                )
            gdb_write(
                gdb, harness, command_base,
                runner.encode_command(protocol, generation, "continue"),
            )
            completed = {}

            def completed_record() -> bool:
                heartbeat = optional_record(
                    runner, protocol, "heartbeat",
                    gdb_memory(
                        gdb, harness, heartbeat_base, heartbeat_size
                    ),
                )
                result = optional_record(
                    runner, protocol, "result",
                    gdb_memory(
                        gdb, harness,
                        result_base + (generation - 1) * stride,
                        result_size,
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

            poll_stopped(
                process, monitor, completed_record, harness, "qemu-hang"
            )
            if completed["classification"] != 0:
                raise BatchFailure(
                    "normative-assertion-failure",
                    f"guest case {generation} reported failure",
                )
            if completed["actual_state"] != completed["expected_state"]:
                raise BatchFailure(
                    "guest-test-harness-failure",
                    f"guest case {generation} state mismatch",
                )
            if running["sequence"] != generation * 2 - 1:
                raise BatchFailure(
                    "malformed-result", "heartbeat sequence did not advance"
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


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        results = run_batch(args.source_root.resolve(), args.binary.resolve())
    except BatchFailure as exc:
        print(f"not ok 1 - persistent runner [{exc.classification}]: {exc}")
        return 1
    print("ok 1 - persistent runner completed {} isolated cases".format(
        len(results)
    ))
    print("# generations={} elapsed-ticks={}".format(
        ",".join(str(row["generation"]) for row in results),
        ",".join(str(row["elapsed_ticks"]) for row in results),
    ))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
