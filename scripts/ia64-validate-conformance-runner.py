#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Validate the IA-64 persistent-runner protocol and foundation builders."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys
from types import ModuleType
from typing import Sequence


class ValidationError(RuntimeError):
    pass


def load_module(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("ia64_runner", path)
    if spec is None or spec.loader is None:
        raise ValidationError(f"cannot import runner module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def self_test(module: ModuleType, protocol: dict) -> None:
    command = module.encode_command(protocol, 7, "run")
    command_words = module.record_words(protocol, "command", command)
    if command_words["generation"] != 7 or command_words["opcode"] != 1:
        raise ValidationError("command round trip failed")

    heartbeat_values = (
        int(protocol["record_types"]["heartbeat"]["magic"], 16),
        1, 7, module.ENUMS["phase"]["running"], 13, 99,
    )
    heartbeat = module.record_words(
        protocol, "heartbeat", struct.pack("<6Q", *heartbeat_values)
    )
    if heartbeat["sequence"] != 13 or heartbeat["elapsed_ticks"] != 99:
        raise ValidationError("heartbeat round trip failed")

    result_values = [0] * 24
    result_values[0] = int(
        protocol["record_types"]["result"]["magic"], 16
    )
    result_values[1] = 1
    result_values[2] = protocol["record_types"]["result"]["size"]
    result_values[3] = protocol["profile"]["id"]
    result_values[4] = 7
    result_values[9] = module.ENUMS["phase"]["complete"]
    result = module.record_words(
        protocol, "result", struct.pack("<24Q", *result_values)
    )
    if result["generation"] != 7 or result["classification"] != 0:
        raise ValidationError("result round trip failed")

    ivt = module.IVTImage(0x10000)
    ivt.install(0x1000, bytes(range(16)))
    if ivt.image[0x1000:0x1010] != bytes(range(16)):
        raise ValidationError("IVT builder did not retain a handler bundle")
    try:
        ivt.install(0x5000, bytes(0x110))
    except module.RunnerError:
        pass
    else:
        raise ValidationError("IVT builder accepted an oversized handler")

    insertion = module.TranslationInsertion(
        physical_address=0x400000, page_size=22,
    )
    translation, itir = insertion.encode()
    expected = 0x400000 | 1 | (1 << 5) | (1 << 6) | (3 << 9)
    if translation != expected or itir != 22 << 2:
        raise ValidationError("translation insertion encoding changed")
    vhpt = module.ShortVHPTBuilder(0x20000, 17, 22)
    entry = vhpt.map(0x800000, insertion)
    if entry != 0x20010 or vhpt.entries[entry] != translation:
        raise ValidationError("short VHPT placement changed")

    repair = module.RepairRetry(
        vector=0x1000, fault_ip=0x4000, retry_ip=0x4000,
        committed_prefix=1,
    )
    repair.validate()
    try:
        module.RepairRetry(
            vector=0x1000, fault_ip=0x4000, retry_ip=0x4010,
            committed_prefix=1,
        ).validate()
    except module.RunnerError:
        pass
    else:
        raise ValidationError("repair/retry accepted a different retry IP")


def validate_required_gate(root: Path) -> None:
    closure_path = root / "tests/ia64-conformance/closure-map.json"
    gate_path = root / "scripts/ia64-run-required-conformance.sh"
    closure = json.loads(closure_path.read_text(encoding="utf-8"))
    gate = gate_path.read_text(encoding="utf-8")
    missing = [
        name for name in closure["infrastructure_tests"]
        if f"qemu:{name}" not in gate
    ]
    if missing:
        raise ValidationError(
            "required gate omits closure infrastructure tests: "
            + ", ".join(sorted(missing))
        )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root", type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--check", action="store_true")
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    root = args.root.resolve()
    module = load_module(root / "scripts/ia64-conformance-runner.py")
    protocol = module.load_protocol(
        root / "tests/ia64-conformance/runner-protocol.json"
    )
    self_test(module, protocol)
    validate_required_gate(root)
    print(
        "IA-64 conformance runner protocol verified: "
        "3 record types; 13 failure classes; IVT, short-VHPT, and "
        "repair/retry builders; required gate covers closure infrastructure"
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(1)
