#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""True TCP migration gate for an open IA-64 typed issue group.

This is deliberately a thin orchestration layer over test-ia64-full-tcg.py.
The shared harness remains the single owner of IA-64 encoders, the migration
program, HMP/GDB framing, register snapshots, and exact snapshot comparison.
"""

import argparse
import importlib.util
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
from types import ModuleType
from typing import List, Optional, Sequence, Tuple


def _load_harness() -> ModuleType:
    path = Path(__file__).with_name("test-ia64-full-tcg.py")
    spec = importlib.util.spec_from_file_location(
        "_ia64_full_tcg_tcp_migration_harness", path
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load IA-64 full-TCG runtime harness")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


H = _load_harness()


def _creation_flags() -> int:
    if os.name == "nt":
        return getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return 0


def _qemu_img(qemu: Path) -> Path:
    name = "qemu-img.exe" if qemu.suffix.lower() == ".exe" else "qemu-img"
    image_tool = qemu.with_name(name)
    if not image_tool.is_file():
        raise H.HarnessError(
            "TCP migration needs the sibling qemu-img: {}".format(image_tool)
        )
    return image_tool


def _create_media(qemu_img: Path, path: Path) -> None:
    result = subprocess.run(
        [str(qemu_img), "create", "-f", "qcow2", str(path), "192M"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=H._child_environment(),
        timeout=H.MIGRATION_TIMEOUT,
        creationflags=_creation_flags(),
    )
    if result.returncode != 0:
        raise H.HarnessError(
            "qemu-img could not create {}: {}".format(
                path.name, (result.stdout or "").strip()
            )
        )


def _common_arguments(qemu: Path, program, media: Path) -> List[str]:
    arguments = [
        str(qemu),
        "-L",
        str(H.FIRMWARE_DIR),
        "-machine",
        "vibtanium",
        "-m",
        "128M",
        "-smp",
        "1",
        "-S",
        "-display",
        "none",
        "-serial",
        "none",
        "-no-reboot",
        "-accel",
        "tcg,one-insn-per-tb=on",
        # The GDB checkpoint deliberately leaves the source in RUN_STATE_DEBUG.
        # That host debugger runstate is not architectural guest state and is
        # not a valid incoming-migration target.  Omitting only global runstate
        # keeps the destination paused via -S while all CPU/typed VMState moves.
        "-global",
        "migration.store-global-state=off",
        "-drive",
        "if=none,id=tcp-migration-media,file={},format=qcow2".format(media),
    ]
    arguments.extend(H._loader_arguments(program))
    return arguments


def _start_qemu(arguments: Sequence[str]) -> subprocess.Popen:
    return subprocess.Popen(
        list(arguments),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=H._child_environment(),
        creationflags=_creation_flags(),
    )


def _hmp_checked(monitor: socket.socket, command: str) -> str:
    output = H._hmp_command(monitor, command)
    if re.search(r"(?im)^error:\s", output):
        raise H.HarnessError(
            "HMP {!r} failed:\n{}".format(command, output.strip())
        )
    return output


def _migration_status(output: str) -> Optional[str]:
    match = re.search(r"(?im)^Status:\s+([a-z-]+)\s*$", output)
    return match.group(1).lower() if match is not None else None


def _wait_for_completed(monitor: socket.socket, label: str) -> str:
    deadline = time.monotonic() + H.MIGRATION_TIMEOUT
    last_output = ""
    last_status: Optional[str] = None
    terminal_failures = {
        "cancelled", "cancelling", "failed", "colo", "postcopy-paused"
    }
    while time.monotonic() < deadline:
        last_output = _hmp_checked(monitor, "info migrate")
        last_status = _migration_status(last_output)
        if last_status == "completed":
            return last_output
        if last_status in terminal_failures:
            raise H.HarnessError(
                "{} migration reached status {}:\n{}".format(
                    label, last_status, last_output.strip()
                )
            )
        time.sleep(0.025)
    raise H.HarnessError(
        "{} migration did not complete within {:.1f}s; last status {!r}:\n{}"
        .format(label, H.MIGRATION_TIMEOUT, last_status, last_output.strip())
    )


def _wait_for_terminal(monitor: socket.socket, program):
    deadline = time.monotonic() + H.PROGRAM_TIMEOUT
    delay = 0.01
    last_ip: Optional[int] = None
    while time.monotonic() < deadline:
        _hmp_checked(monitor, "cont")
        time.sleep(delay)
        _hmp_checked(monitor, "stop")
        candidate = H.parse_snapshot(
            _hmp_checked(monitor, "info registers")
        )
        last_ip = candidate.ip
        if candidate.ip == program.terminal_ip:
            return candidate
        delay = min(delay * 2, 0.1)
    raise H.HarnessError(
        "TCP migration destination did not reach terminal IP 0x{:x}; "
        "last IP was {}".format(
            program.terminal_ip,
            "unavailable" if last_ip is None else "0x{:x}".format(last_ip),
        )
    )


def _close_socket(stream: Optional[socket.socket]) -> None:
    if stream is not None:
        try:
            stream.close()
        except OSError:
            pass


def run_tcp_migration(qemu: Path) -> str:
    qemu_img = _qemu_img(qemu)
    program = H.typed_epoch_migration_program()
    source_process: Optional[subprocess.Popen] = None
    destination_process: Optional[subprocess.Popen] = None
    source_monitor: Optional[socket.socket] = None
    destination_monitor: Optional[socket.socket] = None
    gdb: Optional[socket.socket] = None
    source_output = ""
    destination_output = ""
    failure: Optional[Exception] = None
    result_detail: Optional[str] = None

    with tempfile.TemporaryDirectory(
        prefix="ia64-typed-tcp-migration-"
    ) as directory:
        temporary = Path(directory)
        source_media = temporary / "source.qcow2"
        destination_media = temporary / "destination.qcow2"
        _create_media(qemu_img, source_media)
        _create_media(qemu_img, destination_media)
        if source_media == destination_media:
            raise H.HarnessError("source and destination media must be distinct")

        destination_monitor_port = H._free_tcp_port()
        source_monitor_port = H._free_tcp_port()
        gdb_port = H._free_tcp_port()
        migration_port = H._free_tcp_port()
        destination_arguments = _common_arguments(
            qemu, program, destination_media
        ) + [
            "-monitor",
            "tcp:127.0.0.1:{},server=on,wait=off,nodelay=on".format(
                destination_monitor_port
            ),
            "-incoming",
            "defer",
        ]
        source_arguments = _common_arguments(qemu, program, source_media) + [
            "-monitor",
            "tcp:127.0.0.1:{},server=on,wait=off,nodelay=on".format(
                source_monitor_port
            ),
            "-gdb",
            "tcp:127.0.0.1:{},server=on,wait=off".format(gdb_port),
        ]

        try:
            destination_process = _start_qemu(destination_arguments)
            destination_monitor = H._connect_monitor(
                destination_process, destination_monitor_port
            )
            H._recv_hmp_prompt(destination_monitor)
            _hmp_checked(
                destination_monitor,
                "migrate_incoming tcp:127.0.0.1:{}".format(migration_port),
            )

            source_process = _start_qemu(source_arguments)
            if source_process.pid == destination_process.pid:
                raise H.HarnessError(
                    "source and destination QEMU must have distinct PIDs"
                )
            source_monitor = H._connect_monitor(
                source_process, source_monitor_port
            )
            H._recv_hmp_prompt(source_monitor)
            gdb = H._connect_gdb(source_process, gdb_port)
            initial_stop = H._gdb_rsp_command(gdb, "?")
            if not initial_stop.startswith(("S05", "T05")):
                raise H.HarnessError(
                    "source GDB stub did not begin stopped: {}".format(
                        initial_stop
                    )
                )
            breakpoint = H._gdb_rsp_command(gdb, "Z0,50,10")
            if breakpoint != "OK":
                raise H.HarnessError(
                    "source GDB stub rejected checkpoint 0x50: {}".format(
                        breakpoint
                    )
                )
            H._gdb_rsp_send(gdb, "c")
            stop = H._gdb_rsp_receive(gdb, H.PROGRAM_TIMEOUT)
            if not stop.startswith(("S05", "T05")):
                raise H.HarnessError(
                    "source did not stop at the TCP checkpoint: {}".format(
                        stop
                    )
                )
            _hmp_checked(source_monitor, "stop")
            checkpoint = H.parse_snapshot(
                _hmp_checked(source_monitor, "info registers")
            )
            H._require(
                checkpoint.ip == 0x50 and
                checkpoint.gr[1] == 5 and checkpoint.gr[2] == 0 and
                checkpoint.gr[16] == program.data[0].value and
                checkpoint.gr[17] ==
                    (program.data[0].value + 4) & ((1 << 64) - 1) and
                checkpoint.gr[18] == 0 and
                checkpoint.nat_low == 0 and checkpoint.nat_high == 0 and
                not checkpoint.exception_pending,
                "source did not capture the open check-forward prefix "
                "exactly",
            )
            removed = H._gdb_rsp_command(gdb, "z0,50,10")
            if removed != "OK":
                raise H.HarnessError(
                    "source GDB stub could not remove checkpoint: {}".format(
                        removed
                    )
                )
            gdb.close()
            gdb = None

            _hmp_checked(
                source_monitor,
                "migrate -d tcp:127.0.0.1:{}".format(migration_port),
            )
            source_status = _wait_for_completed(source_monitor, "outgoing")
            destination_status = _wait_for_completed(
                destination_monitor, "incoming"
            )
            H._require(
                _migration_status(source_status) == "completed" and
                _migration_status(destination_status) == "completed",
                "TCP migration did not report completed at both endpoints",
            )

            restored = H.parse_snapshot(
                _hmp_checked(destination_monitor, "info registers")
            )
            differences = H.successful_snapshot_differences(
                checkpoint, restored
            )
            H._require(
                not differences,
                "TCP destination did not restore the exact checkpoint:\n  "
                + "\n  ".join(differences),
            )

            final = _wait_for_terminal(destination_monitor, program)
            H._require(
                not final.exception_pending and final.ip == 0x60 and
                final.gr[1] == 5 and final.gr[2] == 0 and
                final.gr[16] == program.data[0].value and
                final.gr[17] ==
                    (program.data[0].value + 4) & ((1 << 64) - 1) and
                final.gr[18] ==
                    (program.data[0].value + 8) & ((1 << 64) - 1) and
                final.nat_low == 0 and final.nat_high == 0,
                "TCP continuation lost the ordinary-entry or check-forward "
                "view: IP=0x{:x} r1=0x{:x} r2=0x{:x} r16=0x{:x} "
                "r17=0x{:x} r18=0x{:x} NaT=0x{:x}:0x{:x}"
                .format(
                    final.ip, final.gr[1], final.gr[2],
                    final.gr[16], final.gr[17], final.gr[18],
                    final.nat_high, final.nat_low,
                ),
            )
            result_detail = (
                "distinct source/destination PIDs {}/{} completed true TCP "
                "migration; open-group IP 0x50 restored exact immutable-entry "
                "and check-forward state and resumed to IP 0x60"
                .format(source_process.pid, destination_process.pid)
            )
        except Exception as exc:
            failure = exc
        finally:
            for stream in (gdb, source_monitor, destination_monitor):
                _close_socket(stream)
            if source_process is not None:
                try:
                    source_output += H._terminate_child(source_process)
                except Exception as cleanup_exc:
                    if failure is None:
                        failure = cleanup_exc
            if destination_process is not None:
                try:
                    destination_output += H._terminate_child(
                        destination_process
                    )
                except Exception as cleanup_exc:
                    if failure is None:
                        failure = cleanup_exc

        if failure is not None:
            detail = str(failure)
            if source_output.strip():
                detail += "\nSource QEMU output:\n" + source_output.strip()
            if destination_output.strip():
                detail += (
                    "\nDestination QEMU output:\n" +
                    destination_output.strip()
                )
            raise H.HarnessError(detail) from failure

    assert result_detail is not None
    return result_detail


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

    print("TAP version 13")
    print("1..1")
    if not qemu.is_file():
        print("not ok 1 - typed issue-group TCP migration resume")
        print("# QEMU executable does not exist: {}".format(qemu))
        return 1

    started = time.monotonic()
    try:
        detail = run_tcp_migration(qemu)
        print("ok 1 - typed issue-group TCP migration resume")
        print("# {} ({:.3f}s)".format(detail, time.monotonic() - started))
        return 0
    except Exception as exc:
        print("not ok 1 - typed issue-group TCP migration resume")
        _print_failure(exc)
        print("# duration {:.3f}s".format(time.monotonic() - started))
        return 1


if __name__ == "__main__":
    sys.exit(main())
