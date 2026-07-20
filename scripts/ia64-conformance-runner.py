#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Shared protocol and architectural builders for IA-64 conformance shards."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import struct
from typing import Any


SPDX_DECLARATION = "SPDX-" + "License-Identifier: GPL-2.0-or-later"
SCHEMA = "vibtanium.ia64.conformance-runner-protocol"
SCHEMA_VERSION = 1
RECORD_FIELDS = {
    "command": ("magic", "format_version", "generation", "opcode"),
    "heartbeat": (
        "magic", "format_version", "generation", "phase", "sequence",
        "elapsed_ticks",
    ),
    "result": (
        "magic", "format_version", "record_size", "profile", "generation",
        "test_id", "case_id", "normative_id", "seed", "phase",
        "initial_state", "expected_state", "actual_state",
        "expected_interruption", "actual_interruption", "vector",
        "saved_iip", "saved_ipsr", "saved_isr", "committed_prefix",
        "retry_result", "external_transactions", "elapsed_ticks",
        "classification",
    ),
}
ENUMS = {
    "command": {"run": 1, "continue": 2, "stop": 3},
    "phase": {"idle": 0, "running": 1, "complete": 2,
              "repair": 3, "retry": 4},
    "retry_result": {"not-requested": 0, "repaired-pass": 1,
                     "repair-failed": 2, "retry-failed": 3},
    "classification": {
        "pass": 0,
        "normative-assertion-failure": 1,
        "guest-test-harness-failure": 2,
        "malformed-result": 3,
        "heartbeat-loss": 4,
        "qemu-hang": 5,
        "qemu-assertion": 6,
        "qemu-abort": 7,
        "host-crash": 8,
        "missing-output": 9,
        "unexpected-exit": 10,
        "unavailable-prerequisite": 11,
        "test-infrastructure-failure": 12,
    },
}
MEMORY_KEYS = (
    "command_queue", "heartbeat", "result_queue", "result_stride",
    "scratch", "ivt", "short_vhpt",
)
ISOLATION_STEPS = (
    "restore-declared-registers",
    "clear-test-memory",
    "clear-pending-test-events",
    "advance-generation",
    "verify-no-state-leak",
)
SUPPORTED_PAGE_SIZES = (12, 13, 14, 16, 18, 20, 21, 22, 24, 26, 28, 30)


class RunnerError(RuntimeError):
    pass


def _exact_keys(value: Any, expected: set[str], label: str) -> None:
    if not isinstance(value, dict):
        raise RunnerError(f"{label}: expected an object")
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing or extra:
        raise RunnerError(
            f"{label}: missing={missing or 'none'} extra={extra or 'none'}"
        )


def load_protocol(path: Path) -> dict[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise RunnerError(
            f"cannot load runner protocol {path}: {exc}"
        ) from exc
    validate_protocol(document)
    return document


def validate_protocol(document: Any) -> None:
    _exact_keys(
        document,
        {
            "$comment", "schema", "schema_version", "profile",
            "publication", "record_types", "enums", "memory_map",
            "case_isolation", "architecture_builders",
        },
        "protocol root",
    )
    if document["$comment"] != SPDX_DECLARATION:
        raise RunnerError("runner protocol SPDX declaration changed")
    if document["schema"] != SCHEMA or document["schema_version"] != 1:
        raise RunnerError("unsupported runner protocol schema or version")
    if document["profile"] != {"id": 1, "name": "vibtanium-strict-up"}:
        raise RunnerError("runner protocol profile changed")
    if document["publication"] != {
        "completion_marker": "magic",
        "writer_order": "payload-then-release-magic",
        "reader_rule": "ignore-zero-magic-reject-nonzero-invalid",
    }:
        raise RunnerError("runner protocol publication rule changed")
    if document["enums"] != ENUMS:
        raise RunnerError("runner protocol enum assignments changed")

    records = document["record_types"]
    _exact_keys(records, set(RECORD_FIELDS), "record_types")
    for name, expected_names in RECORD_FIELDS.items():
        record = records[name]
        _exact_keys(record, {"magic", "size", "fields"}, f"{name} record")
        if not isinstance(record["magic"], str):
            raise RunnerError(f"{name}: magic must be hexadecimal text")
        try:
            magic = int(record["magic"], 16)
        except ValueError as exc:
            raise RunnerError(f"{name}: invalid magic") from exc
        if magic <= 0 or magic >= 1 << 64:
            raise RunnerError(f"{name}: magic is outside u64")
        if record["size"] != len(expected_names) * 8:
            raise RunnerError(f"{name}: record size does not match fields")
        fields = record["fields"]
        if not isinstance(fields, list) or len(fields) != len(expected_names):
            raise RunnerError(f"{name}: field count changed")
        for index, (field, expected_name) in enumerate(
            zip(fields, expected_names)
        ):
            _exact_keys(field, {"name", "offset", "type"},
                        f"{name} field {index}")
            if field != {
                "name": expected_name, "offset": index * 8,
                "type": "u64-le",
            }:
                raise RunnerError(f"{name}: field {index} layout changed")

    memory = document["memory_map"]
    _exact_keys(memory, set(MEMORY_KEYS), "memory_map")
    ranges = []
    for key in MEMORY_KEYS:
        value = memory[key]
        if key == "result_stride":
            if value < records["result"]["size"] or value % 16:
                raise RunnerError("result stride is too small or unaligned")
            continue
        if not isinstance(value, str):
            raise RunnerError(f"memory_map {key}: expected hexadecimal text")
        address = int(value, 16)
        if address % 16:
            raise RunnerError(f"memory_map {key}: address is not aligned")
        ranges.append(address)
    if len(ranges) != len(set(ranges)):
        raise RunnerError("memory map contains overlapping base addresses")
    if tuple(document["case_isolation"]) != ISOLATION_STEPS:
        raise RunnerError("case isolation sequence changed")

    builders = document["architecture_builders"]
    _exact_keys(builders, {"ivt", "short_vhpt", "repair_retry"},
                "architecture_builders")
    if builders["ivt"] != {"alignment": 32768, "size": 32768}:
        raise RunnerError("IVT builder geometry changed")
    if builders["short_vhpt"] != {
        "entry_size": 8, "minimum_size_bits": 15,
    }:
        raise RunnerError("short VHPT builder geometry changed")
    if builders["repair_retry"] != {
        "records_vector_state": True, "requires_same_retry_ip": True,
    }:
        raise RunnerError("repair/retry contract changed")


def memory_address(protocol: dict[str, Any], name: str) -> int:
    value = protocol["memory_map"][name]
    return value if isinstance(value, int) else int(value, 16)


def record_words(protocol: dict[str, Any], name: str,
                 payload: bytes) -> dict[str, int]:
    record = protocol["record_types"][name]
    if len(payload) != record["size"]:
        raise RunnerError(
            f"{name}: expected {record['size']} bytes, got {len(payload)}"
        )
    values = struct.unpack("<" + "Q" * (len(payload) // 8), payload)
    decoded = dict(zip(RECORD_FIELDS[name], values))
    if decoded["magic"] != int(record["magic"], 16):
        raise RunnerError(f"{name}: bad record magic")
    if decoded["format_version"] != SCHEMA_VERSION:
        raise RunnerError(f"{name}: bad record version")
    if name == "result":
        if decoded["record_size"] != record["size"]:
            raise RunnerError("result: embedded record size mismatch")
        if decoded["profile"] != protocol["profile"]["id"]:
            raise RunnerError("result: unexpected profile")
        if decoded["phase"] != ENUMS["phase"]["complete"]:
            raise RunnerError("result: final phase is not complete")
        if decoded["classification"] not in ENUMS["classification"].values():
            raise RunnerError("result: unknown failure classification")
        if decoded["retry_result"] not in ENUMS["retry_result"].values():
            raise RunnerError("result: unknown retry result")
    elif name == "heartbeat":
        if decoded["phase"] not in ENUMS["phase"].values():
            raise RunnerError("heartbeat: unknown phase")
    return decoded


def encode_command(protocol: dict[str, Any], generation: int,
                   opcode: str) -> bytes:
    if generation <= 0:
        raise RunnerError("command generation must be positive")
    try:
        opcode_value = ENUMS["command"][opcode]
    except KeyError as exc:
        raise RunnerError(f"unknown command opcode: {opcode}") from exc
    words = (
        int(protocol["record_types"]["command"]["magic"], 16),
        SCHEMA_VERSION,
        generation,
        opcode_value,
    )
    return struct.pack("<4Q", *words)


class IVTImage:
    """Deterministic 32-KiB IVT image with architected vector boundaries."""

    SIZE = 0x8000

    def __init__(self, base: int):
        if base % self.SIZE:
            raise RunnerError("IVT base must be 32-KiB aligned")
        self.base = base
        self.image = bytearray(self.SIZE)

    @staticmethod
    def vector_capacity(offset: int) -> int:
        if offset < 0 or offset >= IVTImage.SIZE or offset % 0x100:
            raise RunnerError("invalid IVT vector offset")
        return 0x400 if offset < 0x5000 else 0x100

    def install(self, offset: int, code: bytes) -> None:
        capacity = self.vector_capacity(offset)
        if not code or len(code) % 16 or len(code) > capacity:
            raise RunnerError("IVT handler must contain fitting whole bundles")
        self.image[offset:offset + len(code)] = code


@dataclass(frozen=True)
class TranslationInsertion:
    physical_address: int
    page_size: int = 12
    key: int = 0
    memory_attribute: int = 0
    access_rights: int = 3
    privilege_level: int = 0
    present: bool = True
    accessed: bool = True
    dirty: bool = True
    exception_deferral: bool = False

    def encode(self) -> tuple[int, int]:
        if self.page_size not in SUPPORTED_PAGE_SIZES:
            raise RunnerError("unsupported IA-64 page size")
        if self.physical_address & ((1 << self.page_size) - 1):
            raise RunnerError("physical address is not page aligned")
        if self.physical_address >= 1 << 50:
            raise RunnerError("physical address exceeds insertion PPN field")
        if self.memory_attribute not in (0, 4, 5, 6, 7):
            raise RunnerError("reserved memory attribute")
        if not 0 <= self.access_rights < 8:
            raise RunnerError("access rights must fit three bits")
        if not 0 <= self.privilege_level < 4:
            raise RunnerError("privilege level must fit two bits")
        if not 0 <= self.key < 1 << 24:
            raise RunnerError("protection key must fit 24 bits")
        if not self.present:
            return 0, self.page_size << 2
        translation = (
            self.physical_address
            | int(self.present)
            | (self.memory_attribute << 2)
            | (int(self.accessed) << 5)
            | (int(self.dirty) << 6)
            | (self.privilege_level << 7)
            | (self.access_rights << 9)
            | (int(self.exception_deferral) << 52)
        )
        itir = (self.key << 8) | (self.page_size << 2)
        return translation, itir


class ShortVHPTBuilder:
    """Region-based short-format VHPT entry placement and image builder."""

    def __init__(self, base: int, size_bits: int, page_size: int):
        if size_bits < 15 or size_bits >= 61:
            raise RunnerError("short VHPT size must be between 2^15 and 2^60")
        if base & ((1 << size_bits) - 1):
            raise RunnerError("short VHPT base must be table-size aligned")
        if page_size not in SUPPORTED_PAGE_SIZES:
            raise RunnerError("unsupported short VHPT page size")
        self.base = base
        self.size_bits = size_bits
        self.page_size = page_size
        self.entries: dict[int, int] = {}

    def entry_address(self, virtual_address: int) -> int:
        region = virtual_address & 0xe000000000000000
        page_number = (
            virtual_address & 0x0007ffffffffffff
        ) >> self.page_size
        offset = (page_number << 3) & ((1 << self.size_bits) - 1)
        return region | self.base | offset

    def map(self, virtual_address: int,
            insertion: TranslationInsertion) -> int:
        if insertion.page_size != self.page_size:
            raise RunnerError("VHPT mapping page size disagrees with builder")
        address = self.entry_address(virtual_address)
        translation, _ = insertion.encode()
        self.entries[address] = translation
        return address


@dataclass(frozen=True)
class RepairRetry:
    vector: int
    fault_ip: int
    retry_ip: int
    committed_prefix: int

    def validate(self) -> None:
        IVTImage.vector_capacity(self.vector)
        if self.fault_ip & 0xf or self.retry_ip & 0xf:
            raise RunnerError("repair/retry IP must be bundle aligned")
        if self.retry_ip != self.fault_ip:
            raise RunnerError(
                "repair/retry must resume at the faulting bundle"
            )
        if not 0 <= self.committed_prefix <= 2:
            raise RunnerError("committed prefix must be a slot count")
