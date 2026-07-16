#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Macro-G production-cutover gate for the IA-64 full-TCG engine.

The normal mode describes the release end state and is intentionally stricter
than the in-progress full-only developer role.  ``--inventory`` reports the
same findings without failing, which makes the gate useful before cutover.
``--self-check`` builds a synthetic, closed 428-row source tree and injects one
failure per detector; it does not depend on the state of the checkout.

When a production executable is supplied, symbol inspection invokes ``nm`` as
an argv vector (never through a shell) and the string scan reads the PE image
directly.  This is reliable for Windows paths containing spaces and does not
depend on a separately installed ``strings`` program.
"""

from __future__ import annotations

import argparse
from collections import Counter
import csv
from dataclasses import dataclass
import importlib.util
import io
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from types import ModuleType
from typing import Callable, Iterable, Sequence


LEDGER_PATH = Path("docs/devel/ia64-opcode-ledger.csv")
LEDGER_COLUMNS = (
    "ordinal",
    "opcode",
    "decoder_status",
    "family",
    "sources",
    "destinations",
    "predication",
    "nat_rule",
    "may_fault",
    "tb_end",
    "lowering_owner",
    "focused_helper_whitelist",
    "test_owner",
    "typed_admission",
    "closure",
    "legacy_oracle",
    "reference_tcg",
    "exception_tests",
    "system_evidence",
)
EXPECTED_OPCODE_COUNT = 428
REQUIRED_FOCUSED_HELPER_CATEGORIES = frozenset(
    {
        "ATOMIC",
        "CALL_FRAME",
        "DATA_PLANE",
        "RETURN_FRAME",
        "RFI",
        "RSE_SPINE",
        "SPECIAL_LDST",
        "SYSTEM_PLANE",
    }
)
REQUIRED_FOCUSED_HELPER_BOUNDARIES = {
    "ATOMIC": (
        "ia64_tr_emit_decoded_data_plane_atomic",
        "ia64_tr_emit_decoded_data_plane_cmp8xchg16",
    ),
    "CALL_FRAME": ("ia64_tr_emit_call_frame_transition",),
    "DATA_PLANE": (
        "ia64_tr_emit_decoded_checked_branch_split",
        "ia64_tr_emit_decoded_data_plane_cache_control",
        "ia64_tr_emit_decoded_data_plane_lfetch",
        "ia64_tr_emit_decoded_fp_focused",
    ),
    "RETURN_FRAME": ("ia64_tr_emit_typed_return_exit",),
    "RFI": ("ia64_tr_emit_decoded_rfi",),
    "RSE_SPINE": ("ia64_tr_emit_decoded_rse_spine",),
    "SPECIAL_LDST": (
        "ia64_tr_emit_decoded_data_plane_fp_load",
        "ia64_tr_emit_decoded_data_plane_fp_store",
        "ia64_tr_emit_decoded_data_plane_integer_load",
        "ia64_tr_emit_decoded_data_plane_integer_spill",
    ),
    "SYSTEM_PLANE": (
        "ia64_tr_emit_decoded_application_move",
        "ia64_tr_emit_decoded_system",
    ),
}
FORBIDDEN_PRODUCTION_SOURCES = (
    "debug-trace.c",
    "interp.c",
    "interp-ldst.c",
    "oracle-perf.c",
    "tcg-classify.c",
)

# These switches choose between execution engines, migration-only lowering
# paths, or fallback implementations.  Diagnostic/profile knobs are not in
# this list: Macro G removes selectors, not unrelated observability controls.
FORBIDDEN_SELECTOR_STRINGS = (
    "VIBTANIUM_FULL_TCG_REWRITE",
    "VIBTANIUM_TCG_FAST_DISABLE",
    "VIBTANIUM_TCG_LDST_INLINE",
    "VIBTANIUM_TCG_ZERO_HELPER",
    "VIBTANIUM_TCG_REGION",
    "VIBTANIUM_TCG_CONDITIONAL_REGION",
    "VIBTANIUM_TCG_SPEC_CHECK",
)
UNRELEASABLE_MARKER = "IA64_FULL_ONLY_DEVELOPER_BUILD_UNRELEASABLE"

FORBIDDEN_LINK_FRAGMENTS = (
    "helper_exec_bundle",
    "helper_exec_bundle_lookup_ptr",
    "helper_exec_slot",
    "ia64_exec_bundle_impl",
    "exec_predecoded_slot",
    "ia64_insn_exec_bundle",
    "ia64_debug_hooks_active",
    "ia64_trace_execve",
    "ia64_firmware_dispatch_gate",
    "vibtanium_efi_dispatch_gate",
    "helper_full_only_unimplemented",
    "helper_fast_",
    "helper_start_fast_bundle",
    "helper_finish_fast_bundle",
    "helper_finish_fast_tb",
    "helper_finish_direct_branch_bundle",
    "helper_finish_indirect_branch_bundle",
    "helper_perf_direct_branch_fallback",
    "helper_perf_tcg_ldst_fallback",
    "ia64_perf_count_tcg_fallback_reason",
    "ia64_tcg_fallback_",
)

SOURCE_PATTERNS = (
    (
        "source.generic-dispatch",
        re.compile(
            r"\b(?:gen_)?helper_exec_(?:bundle(?:_lookup_ptr)?|slot)\b|"
            r"\b(?:[a-zA-Z0-9_]+_)?exec_bundle(?:_lookup_ptr)?\b|"
            r"\b(?:[a-zA-Z0-9_]+_)?exec_slot\b|"
            r"\bia64_exec_bundle_impl\b|\bia64_insn_exec_bundle\b|"
            r"\bIA64InsnReport\b|\bexec_predecoded_slot\b"
        ),
        "generic bundle/slot dispatcher remains in production sources",
    ),
    (
        "source.host-firmware-dispatch",
        re.compile(
            r"\bia64_firmware_dispatch_gate\b|\bvibtanium_efi_dispatch_gate\b|"
            r"\bIA64_FIRMWARE_EFI_(?:CALL_GATE|PAL_PROC|SAL_PROC|"
            r"START_IMAGE_RETURN_GATE|EVENT_NOTIFY_RETURN_GATE)\b"
        ),
        "host-dispatched or magic-address firmware path remains in production",
    ),
    (
        "source.workload-recognizer",
        re.compile(
            r"\bIA64_WINDOWS_BREAK_IMMEDIATE\b|\b0x80015\b|"
            r"(?:env->ip|bundle_ip|source_ip)\s*==\s*0x[0-9a-fA-F]{4,}"
        ),
        "workload-specific break/IP recognizer remains in production",
    ),
    (
        "source.pending-fill",
        re.compile(r"\bpending_fill(?:_[a-zA-Z0-9_]+)?\b"),
        "legacy pending-fill coexistence state remains in production",
    ),
    (
        "source.full-only-terminator",
        re.compile(r"full_only_unimplemented|" + UNRELEASABLE_MARKER),
        "developer host-fatal/unreleasable path remains in production",
    ),
    (
        "source.fast-helper",
        re.compile(
            r"\b(?:(?:gen_)?helper_)?(?:fast_[a-z0-9_]+|start_fast_bundle|"
            r"finish_fast_(?:bundle|tb)|finish_(?:direct|indirect)_branch_bundle)\b",
            re.IGNORECASE,
        ),
        "hybrid fast-path helper ABI remains in production",
    ),
    (
        "source.fallback-descriptor",
        re.compile(r"\b(?:IA64_TCG_FALLBACK|ia64_tcg_fallback_)", re.IGNORECASE),
        "fallback selector/packed-descriptor machinery remains in production",
    ),
    (
        "source.fallback-counter",
        re.compile(
            r"(?:perf_(?:direct_branch|tcg_ldst)_fallback|"
            r"ia64_perf_count_tcg_fallback_reason|tcg\.fallback\.)"
        ),
        "runtime fallback counter remains in production",
    ),
    (
        "source.selector-code",
        re.compile(
            r"\bia64_tr_full_tcg_rewrite_enabled\b|"
            r"\bia64_tr_translate_(?:fast|partial)_bundle\b|"
            r"\bia64_tr_emit_exec_bundle(?:_lookup_ptr)?\b|"
            r"\brewrite_region_selected\b"
        ),
        "fast/partial/full runtime selection code remains in production",
    ),
    (
        "source.classifier-include",
        re.compile(r"#\s*include\s+\"tcg-classify\.h\""),
        "production source still includes the legacy classifier interface",
    ),
)


@dataclass(frozen=True)
class Finding:
    code: str
    detail: str


def finding(catalog: list[Finding], code: str, detail: str) -> None:
    catalog.append(Finding(code, detail))


def read_text(root: Path, relative: str, catalog: list[Finding]) -> str | None:
    path = root / relative
    try:
        return path.read_text(encoding="utf-8")
    except OSError as exc:
        finding(catalog, "source.missing", f"cannot read {relative}: {exc}")
        return None


def c_function_body(source: str, name: str) -> str | None:
    """Return a simple C function body, including its outer braces."""
    match = re.search(
        rf"\b{re.escape(name)}\s*\([^;]*?\)\s*\{{",
        source,
        re.DOTALL,
    )
    if match is None:
        return None
    opening = source.find("{", match.start())
    depth = 0
    for offset in range(opening, len(source)):
        if source[offset] == "{":
            depth += 1
        elif source[offset] == "}":
            depth -= 1
            if depth == 0:
                return source[opening : offset + 1]
    return None


def parse_opcode_enum(text: str) -> list[str]:
    match = re.search(
        r"typedef\s+enum\s+IA64Opcode\s*\{(.*?)\bIA64_OP_COUNT\s*,",
        text,
        re.DOTALL,
    )
    if match is None:
        return []
    return re.findall(r"\bIA64_OP_[A-Z0-9_]+\b", match.group(1))


def parse_trait_rows(text: str) -> list[tuple[str, ...]]:
    rows: list[tuple[str, ...]] = []
    for match in re.finditer(r"IA64_OPCODE\((.*?)\)", text, re.DOTALL):
        fields = tuple(field.strip() for field in match.group(1).split(","))
        if len(fields) == 8:
            rows.append(fields)
    return rows


def audit_ledger(root: Path, catalog: list[Finding]) -> None:
    ledger_text = read_text(root, str(LEDGER_PATH), catalog)
    decode_text = read_text(root, "target/ia64/decode.h", catalog)
    trait_text = read_text(root, "target/ia64/opcode-traits.def", catalog)
    if ledger_text is None or decode_text is None or trait_text is None:
        return

    reader = csv.DictReader(io.StringIO(ledger_text))
    if tuple(reader.fieldnames or ()) != LEDGER_COLUMNS:
        finding(
            catalog,
            "ledger.columns",
            "ledger columns do not exactly match the production evidence schema",
        )
        return
    rows = list(reader)
    enum_names = parse_opcode_enum(decode_text)
    trait_rows = parse_trait_rows(trait_text)
    trait_names = [row[0] for row in trait_rows]
    ledger_names = [row["opcode"] for row in rows]

    if len(rows) != EXPECTED_OPCODE_COUNT:
        finding(
            catalog,
            "ledger.count",
            f"ledger has {len(rows)} rows; expected {EXPECTED_OPCODE_COUNT}",
        )
    if len(enum_names) != EXPECTED_OPCODE_COUNT:
        finding(
            catalog,
            "ledger.enum-count",
            f"IA64Opcode has {len(enum_names)} entries; expected {EXPECTED_OPCODE_COUNT}",
        )
    if enum_names and ledger_names != enum_names:
        finding(catalog, "ledger.enum-order", "ledger rows do not exactly match IA64Opcode")
    if enum_names and trait_names != enum_names:
        finding(catalog, "ledger.trait-order", "trait rows do not exactly match IA64Opcode")

    bad_ordinals: list[str] = []
    for expected, row in enumerate(rows):
        try:
            actual = int(row["ordinal"], 10)
        except ValueError:
            actual = -1
        if actual != expected:
            bad_ordinals.append(f"{row['opcode']}={row['ordinal']!r}")
    if bad_ordinals:
        finding(
            catalog,
            "ledger.ordinals",
            "non-contiguous ledger ordinals: " + ", ".join(bad_ordinals[:5]),
        )

    duplicates = [name for name, count in Counter(ledger_names).items() if count != 1]
    if duplicates:
        finding(
            catalog,
            "ledger.unique",
            "duplicate/missing opcode keys: " + ", ".join(sorted(duplicates)[:5]),
        )

    live_rows = [row for row in rows if row["decoder_status"] == "live"]
    open_rows = [row["opcode"] for row in live_rows if row["closure"].lower() == "open"]
    if open_rows:
        finding(
            catalog,
            "ledger.open",
            f"{len(open_rows)} live rows remain OPEN: " + ", ".join(open_rows[:8]),
        )

    nonclosed = [
        row["opcode"] for row in live_rows if row["closure"].lower() != "closed"
    ]
    if nonclosed:
        finding(
            catalog,
            "ledger.not-closed",
            f"{len(nonclosed)} live rows are not family-closed: "
            + ", ".join(nonclosed[:8]),
        )

    partial = [
        row["opcode"] for row in live_rows if row["typed_admission"].lower() != "full"
    ]
    if partial:
        finding(
            catalog,
            "ledger.not-full",
            f"{len(partial)} live rows lack full typed admission: "
            + ", ".join(partial[:8]),
        )

    legacy_owned = [
        row["opcode"]
        for row in live_rows
        if row["lowering_owner"] not in {"direct-tcg", "focused-helper"}
    ]
    if legacy_owned:
        finding(
            catalog,
            "ledger.legacy-owner",
            f"{len(legacy_owned)} live rows lack typed ownership: "
            + ", ".join(legacy_owned[:8]),
        )

    missing_tests = [
        row["opcode"] for row in live_rows if row["test_owner"] in {"", "none"}
    ]
    if missing_tests:
        finding(
            catalog,
            "ledger.missing-test",
            f"{len(missing_tests)} live rows lack a test owner: "
            + ", ".join(missing_tests[:8]),
        )

    bad_focused = [
        row["opcode"]
        for row in live_rows
        if row["lowering_owner"] == "focused-helper"
        and row["focused_helper_whitelist"] in {"", "none"}
    ]
    if bad_focused:
        finding(
            catalog,
            "ledger.unwhitelisted-helper",
            "focused-helper rows without a helper trait: " + ", ".join(bad_focused[:8]),
        )

    invalid_rows = [row for row in rows if row["decoder_status"] == "illegal"]
    if (
        len(invalid_rows) != 1
        or invalid_rows[0]["opcode"] != "IA64_OP_ILLEGAL"
        or invalid_rows[0]["ordinal"] != "0"
    ):
        finding(catalog, "ledger.illegal-row", "IA64_OP_ILLEGAL is not the unique row zero")

    unknown_status = [
        row["opcode"]
        for row in rows
        if row["decoder_status"] not in {"illegal", "live", "decoder-dead-alias"}
    ]
    if unknown_status:
        finding(
            catalog,
            "ledger.decoder-status",
            "unknown decoder status: " + ", ".join(unknown_status[:8]),
        )

    trait_by_name = {row[0]: row for row in trait_rows}
    trait_drift: list[str] = []
    for row in rows:
        trait = trait_by_name.get(row["opcode"])
        if trait is None:
            continue
        owner = trait[2].lower().replace("_", "-")
        helper = trait[3].lower().replace("_", "-")
        if owner != row["lowering_owner"] or helper != row["focused_helper_whitelist"]:
            trait_drift.append(row["opcode"])
        if row["decoder_status"] == "live" and trait[7] in {"OPEN", "TYPED_PARTIAL"}:
            trait_drift.append(row["opcode"])
    if trait_drift:
        finding(
            catalog,
            "ledger.trait-drift",
            "ledger owner/helper/lifecycle differs from traits: "
            + ", ".join(sorted(set(trait_drift))[:8]),
        )


def option_block(text: str, name: str) -> str | None:
    match = re.search(
        rf"option\(\s*['\"]{re.escape(name)}['\"](.*?)\n\s*\)",
        text,
        re.DOTALL,
    )
    if match is None:
        # Meson commonly closes this short option on the description line.
        match = re.search(
            rf"option\(\s*['\"]{re.escape(name)}['\"](.*?description\s*:.*?)\)",
            text,
            re.DOTALL,
        )
    return None if match is None else match.group(0)


def is_oracle_condition(condition: str) -> bool:
    lowered = condition.lower().strip()
    return not lowered.startswith("not ") and "dual" in lowered and "oracle" in lowered


@dataclass(frozen=True)
class MesonSource:
    name: str
    line: int
    oracle_only: bool


def meson_sources(text: str) -> list[MesonSource]:
    conditions: list[str] = []
    sources: list[MesonSource] = []
    files_block_depth = 0
    files_block_oracle = False
    for line_number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if re.match(r"^if\s+", stripped):
            conditions.append(re.sub(r"^if\s+", "", stripped))
        elif re.match(r"^elif\s+", stripped):
            if conditions:
                conditions.pop()
            conditions.append(re.sub(r"^elif\s+", "", stripped))
        elif stripped == "else":
            if conditions:
                conditions[-1] = "not " + conditions[-1]
        elif re.match(r"^endif\b", stripped):
            if conditions:
                conditions.pop()
        block_start = re.search(
            r"\b([a-zA-Z0-9_]*oracle[a-zA-Z0-9_]*)\.add\s*\(\s*files\s*\(",
            line,
            re.IGNORECASE,
        )
        generic_start = re.search(
            r"\b[a-zA-Z0-9_]+\.add\s*\(\s*files\s*\(", line
        )
        if files_block_depth == 0 and generic_start is not None:
            files_block_oracle = block_start is not None
            files_block_depth = (
                line[generic_start.start():].count("(")
                - line[generic_start.start():].count(")")
            )
        for source in re.findall(r"['\"]([^'\"]+\.c)['\"]", line):
            sources.append(
                MesonSource(
                    source,
                    line_number,
                    files_block_oracle
                    or any(is_oracle_condition(condition) for condition in conditions),
                )
            )
        if files_block_depth > 0 and generic_start is None:
            files_block_depth += line.count("(") - line.count(")")
        if files_block_depth <= 0:
            files_block_depth = 0
            files_block_oracle = False
    return sources


def audit_roles_and_sources(root: Path, catalog: list[Finding]) -> set[Path]:
    options = read_text(root, "meson_options.txt", catalog)
    top_meson = read_text(root, "meson.build", catalog)
    target_meson = read_text(root, "target/ia64/meson.build", catalog)
    hw_meson = read_text(root, "hw/ia64/meson.build", catalog)
    if options is None or top_meson is None or target_meson is None or hw_meson is None:
        return set()

    block = option_block(options, "ia64_engine_role")
    if block is not None:
        finding(catalog, "role.option", "removed ia64_engine_role option remains")
    for owner, text in (
        ("meson_options.txt", options),
        ("meson.build", top_meson),
        ("target/ia64/meson.build", target_meson),
    ):
        for obsolete in (
            "ia64_engine_role",
            "dual-oracle",
            "CONFIG_IA64_FULL_ONLY_DEV",
            "UNRELEASABLE",
        ):
            if obsolete in text:
                finding(catalog, "role.remnant", f"{owner} retains {obsolete}")

    sources = meson_sources(target_meson)
    forbidden = [
        source for source in sources
        if Path(source.name).name in FORBIDDEN_PRODUCTION_SOURCES
    ]
    if forbidden:
        finding(
            catalog,
            "source.legacy-link",
            "forbidden source is in the production source set: "
            + ", ".join(f"{item.name}:{item.line}" for item in forbidden),
        )

    production_names = [source.name for source in sources]
    for required in ("decode.c", "translate.c", "opcode-traits.c"):
        if not any(Path(name).name == required for name in production_names):
            finding(catalog, "source.production-core", f"production source set lacks {required}")

    obsolete_full_only = root / "target/ia64/full-only.c"
    if obsolete_full_only.exists():
        finding(
            catalog,
            "source.obsolete-full-only",
            "target/ia64/full-only.c remains after the production role replaced it",
        )

    target_dir = root / "target/ia64"
    production: set[Path] = set()
    for name in production_names:
        path = Path(name)
        candidate = path if path.is_absolute() else target_dir / path
        if candidate.exists():
            production.add(candidate.resolve())
    helper_h = target_dir / "helper.h"
    if helper_h.exists():
        production.add(helper_h.resolve())

    hw_dir = root / "hw/ia64"
    for source in meson_sources(hw_meson):
        path = Path(source.name)
        candidate = path if path.is_absolute() else hw_dir / path
        if candidate.exists():
            production.add(candidate.resolve())
    public_hw_dir = root / "include/hw/ia64"
    if public_hw_dir.exists():
        production.update(path.resolve() for path in public_hw_dir.glob("*.h"))

    # Follow only local IA-64 target/machine includes.  This models the actual
    # target and machine source sets without pulling unrelated generic QEMU code
    # into the architecture-specific policy scan.
    queue = list(production)
    local_roots = tuple(
        directory.resolve() for directory in (target_dir, hw_dir, public_hw_dir)
        if directory.exists()
    )
    while queue:
        path = queue.pop()
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for include in re.findall(r"#\s*include\s+\"([^\"]+)\"", text):
            candidates = (
                path.parent / include,
                target_dir / include,
                hw_dir / include,
                root / "include" / include,
                root / include,
            )
            for candidate in candidates:
                try:
                    resolved = candidate.resolve()
                    if not any(
                        resolved == local_root or resolved.is_relative_to(local_root)
                        for local_root in local_roots
                    ):
                        continue
                except OSError:
                    continue
                if resolved.exists() and resolved not in production:
                    production.add(resolved)
                    queue.append(resolved)
                break
    return production


def iter_helper_calls(text: str) -> Iterable[tuple[int, str]]:
    for match in re.finditer(r"\bgen_helper_[a-zA-Z0-9_]+\s*\(", text):
        depth = 1
        index = match.end()
        while index < len(text) and depth:
            if text[index] == "(":
                depth += 1
            elif text[index] == ")":
                depth -= 1
            index += 1
        if depth == 0:
            yield match.start(), text[match.start():index]


def audit_production_text(root: Path, paths: set[Path], catalog: list[Finding]) -> None:
    grouped: dict[str, tuple[str, list[str]]] = {
        code: (message, []) for code, _, message in SOURCE_PATTERNS
    }
    selector_hits: list[str] = []
    raw_hits: list[str] = []

    for path in sorted(paths):
        try:
            text = path.read_text(encoding="utf-8")
            display = str(path.relative_to(root))
        except (OSError, ValueError):
            continue
        for code, pattern, _ in SOURCE_PATTERNS:
            matches = list(pattern.finditer(text))
            if matches:
                line = text.count("\n", 0, matches[0].start()) + 1
                grouped[code][1].append(f"{display}:{line}")
        for selector in FORBIDDEN_SELECTOR_STRINGS:
            offset = text.find(selector)
            if offset >= 0:
                selector_hits.append(
                    f"{selector}@{display}:{text.count(chr(10), 0, offset) + 1}"
                )
        for offset, call in iter_helper_calls(text):
            if re.search(r"(?:->\s*raw\b|\b(?:type_raw|slot_raw)\b)", call):
                raw_hits.append(f"{display}:{text.count(chr(10), 0, offset) + 1}")
        for match in re.finditer(
            r"\bHELPER\([^)]+\)\s*\([^)]*\b(?:raw|type_raw|slot_raw)\b",
            text,
            re.DOTALL,
        ):
            raw_hits.append(f"{display}:{text.count(chr(10), 0, match.start()) + 1}")

    for code, (message, locations) in grouped.items():
        if locations:
            suffix = "" if len(locations) <= 6 else f" (+{len(locations) - 6} more)"
            finding(catalog, code, f"{message}: {', '.join(locations[:6])}{suffix}")
    if selector_hits:
        finding(
            catalog,
            "source.runtime-selector",
            "runtime selector strings remain: " + ", ".join(selector_hits[:8]),
        )
    if raw_hits:
        finding(
            catalog,
            "source.raw-helper",
            "a C helper receives raw slot bits: " + ", ".join(raw_hits[:8]),
        )

    translate_path = root / "target/ia64/translate.c"
    try:
        translate = translate_path.read_text(encoding="utf-8")
    except OSError:
        return
    if (
        "IA64_DECODE_OK" not in translate
        or "ia64_tr_emit_decoded_illegal_operation" not in translate
        or "gen_helper_raise_illegal_operation" not in translate
    ):
        finding(
            catalog,
            "invalid.static-lowering",
            "typed decode failure lacks an explicit architectural Illegal Operation lowering",
        )

    guard_names = re.findall(
        r"static\s+(?:bool|void)\s+"
        r"([a-zA-Z0-9_]*(?:helper[a-zA-Z0-9_]*(?:allow|whitelist|valid)|"
        r"(?:allow|whitelist|valid)[a-zA-Z0-9_]*helper)[a-zA-Z0-9_]*)"
        r"\s*\([^)]*IA64OpcodeHelper[^)]*\)",
        translate,
        re.DOTALL | re.IGNORECASE,
    )
    guarded = (
        "ia64_opcode_traits_for" in translate
        and re.search(r"helper_whitelist\s*==", translate) is not None
        and any(len(re.findall(rf"\b{re.escape(name)}\b", translate)) >= 2
                for name in guard_names)
    )
    if not guarded:
        finding(
            catalog,
            "traits.helper-guard",
            "typed focused-helper emission is not authorized through helper_whitelist",
        )

    helper_sites = set(
        re.findall(
            r"\bia64_tr_require_helper\s*\([^;]*?"
            r"\bIA64_OPCODE_HELPER_([A-Z0-9_]+)\s*\)\s*;",
            translate,
            re.DOTALL,
        )
    )
    missing_helper_sites = sorted(
        REQUIRED_FOCUSED_HELPER_CATEGORIES - helper_sites
    )
    if missing_helper_sites:
        finding(
            catalog,
            "traits.helper-sites",
            "focused-helper categories lack enforced emitter boundaries: "
            + ", ".join(missing_helper_sites),
        )

    missing_boundaries: list[str] = []
    for category, functions in REQUIRED_FOCUSED_HELPER_BOUNDARIES.items():
        marker = f"IA64_OPCODE_HELPER_{category}"
        for function in functions:
            body = c_function_body(translate, function)
            if body is None or not re.search(
                rf"\bia64_tr_require_helper\s*\([^;]*?\b{marker}\s*\)\s*;",
                body,
                re.DOTALL,
            ):
                missing_boundaries.append(f"{category}:{function}")
    if missing_boundaries:
        finding(
            catalog,
            "traits.helper-boundary",
            "focused-helper authorization is absent from concrete emitters: "
            + ", ".join(missing_boundaries),
        )


def audit_test_registration(root: Path, catalog: list[Finding]) -> None:
    meson = read_text(root, "tests/unit/meson.build", catalog)
    if meson is None:
        return
    marker = "test-ia64-production-cutover"
    start = meson.find(marker)
    if start < 0:
        finding(catalog, "smoke.registration", "production cutover gate is not registered")
        return
    block = meson[start:start + 1800]
    required = ("--source-root", "--binary", "--nm", "--runtime-smoke", "--harness")
    missing = [token for token in required if token not in block]
    if missing:
        finding(
            catalog,
            "smoke.arguments",
            "registered production gate lacks: " + ", ".join(missing),
        )
    if "ia64_engine_role" in meson or "dual-oracle" in meson:
        finding(
            catalog,
            "smoke.role",
            "test registration retains a removed IA-64 engine role",
        )


def parse_nm_symbols(output: str) -> set[str]:
    symbols: set[str] = set()
    for line in output.splitlines():
        fields = line.strip().split()
        if len(fields) >= 2:
            symbol = fields[-1]
            if re.match(r"^[_A-Za-z?@$][^\s]*$", symbol):
                symbols.add(symbol.lstrip("_"))
    return symbols


def audit_symbol_text(output: str, catalog: list[Finding]) -> None:
    symbols = parse_nm_symbols(output)
    hits = sorted(
        symbol
        for symbol in symbols
        if any(fragment in symbol for fragment in FORBIDDEN_LINK_FRAGMENTS)
    )
    if hits:
        finding(
            catalog,
            "binary.generic-symbol",
            f"production link has {len(hits)} hybrid symbols: " + ", ".join(hits[:10]),
        )


def audit_image_bytes(image: bytes, catalog: list[Finding]) -> None:
    hits: list[str] = []
    for value in (*FORBIDDEN_SELECTOR_STRINGS, UNRELEASABLE_MARKER):
        encoded = value.encode("ascii")
        if encoded in image or value.encode("utf-16le") in image:
            hits.append(value)
    if hits:
        finding(
            catalog,
            "binary.forbidden-string",
            "production image contains runtime selector/marker strings: "
            + ", ".join(hits),
        )


def audit_binary(binary: Path, nm: str, catalog: list[Finding]) -> None:
    try:
        image = binary.read_bytes()
    except OSError as exc:
        finding(catalog, "binary.read", f"cannot read {binary}: {exc}")
        return
    audit_image_bytes(image, catalog)
    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        result = subprocess.run(
            [nm, "-a", str(binary)],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            creationflags=creationflags,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        finding(catalog, "binary.nm", f"cannot inspect symbols with {nm!r}: {exc}")
        return
    if result.returncode != 0:
        finding(
            catalog,
            "binary.nm",
            f"nm returned {result.returncode}: {result.stderr.strip()}",
        )
        return
    audit_symbol_text(result.stdout, catalog)


def load_harness(path: Path) -> ModuleType:
    spec = importlib.util.spec_from_file_location("ia64_production_smoke_harness", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import IA-64 harness from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def production_environment(
    *_args: object,
    extra_path: Sequence[Path] = (),
    **_kwargs: object,
) -> dict[str, str]:
    environment = os.environ.copy()
    for name in list(environment):
        if name.startswith("VIBTANIUM_"):
            del environment[name]
    if extra_path:
        prefix = os.pathsep.join(str(path) for path in extra_path)
        environment["PATH"] = prefix + os.pathsep + environment.get("PATH", "")
    return environment


def run_runtime_smoke(
    binary: Path,
    harness_path: Path,
    catalog: list[Finding],
    runtime_path: Sequence[Path] = (),
) -> None:
    try:
        harness = load_harness(harness_path)
        original_environment = harness._child_environment
        harness._child_environment = (
            lambda *args, **kwargs: production_environment(
                *args, extra_path=runtime_path, **kwargs
            )
        )
        try:
            valid = harness.run_program(binary, harness.core_program())
            if valid.gr[1] != 42 or valid.gr[2] != 7:
                raise AssertionError("selector-free typed core program produced wrong GRs")

            invalid_program = harness.Program(
                name="production reserved-template architectural fault",
                bundles=(
                    harness.Bundle(0x10, 0x06, 0, 0, 0),
                    harness._illegal_vector_spin(),
                ),
                terminal_ip=harness.IA64_GENERAL_EXCEPTION_VECTOR,
            )
            invalid = harness.run_program(
                binary, invalid_program, preserve_fault_slot=True
            )
            if (
                invalid.ip != harness.IA64_GENERAL_EXCEPTION_VECTOR
                or invalid.exception_kind != "illegal-operation"
                or invalid.exception_source != 0x10
                or not invalid.slot_valid
                or invalid.slot_ip != 0x10
                or invalid.slot_ri != 0
            ):
                raise AssertionError(
                    "reserved template lacked a precise guest architectural fault: "
                    f"{invalid}"
                )
        finally:
            harness._child_environment = original_environment
    except Exception as exc:
        finding(catalog, "smoke.runtime", str(exc))


def audit_tree(root: Path) -> list[Finding]:
    # Windows may expose a TemporaryDirectory through an 8.3 alias while
    # Path.resolve() returns its long name.  Normalize once so source-closure
    # paths remain comparable in both the self-check and normal invocation.
    root = root.resolve()
    catalog: list[Finding] = []
    audit_ledger(root, catalog)
    production = audit_roles_and_sources(root, catalog)
    audit_production_text(root, production, catalog)
    audit_test_registration(root, catalog)
    return catalog


def fixture_ledger(opcodes: Sequence[str]) -> str:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=LEDGER_COLUMNS, lineterminator="\n")
    writer.writeheader()
    for ordinal, opcode in enumerate(opcodes):
        illegal = ordinal == 0
        writer.writerow(
            {
                "ordinal": ordinal,
                "opcode": opcode,
                "decoder_status": "illegal" if illegal else "live",
                "family": "illegal" if illegal else "integer",
                "sources": "none" if illegal else "gr",
                "destinations": "none" if illegal else "gr",
                "predication": "none" if illegal else "normal",
                "nat_rule": "none" if illegal else "propagate",
                "may_fault": "explicit" if illegal else "nat",
                "tb_end": "control-flow" if illegal else "continue",
                "lowering_owner": "illegal" if illegal else "direct-tcg",
                "focused_helper_whitelist": "none",
                "test_owner": "decode" if illegal else "full-tcg",
                "typed_admission": "n/a" if illegal else "full",
                "closure": "n/a" if illegal else "closed",
                "legacy_oracle": "n/a" if illegal else "yes",
                "reference_tcg": "n/a" if illegal else "yes",
                "exception_tests": "decode" if illegal else "none",
                "system_evidence": "none" if illegal else "no-os",
            }
        )
    return output.getvalue()


def create_self_check_tree(root: Path) -> None:
    target = root / "target/ia64"
    tests = root / "tests/unit"
    ledger_dir = root / LEDGER_PATH.parent
    target.mkdir(parents=True)
    tests.mkdir(parents=True)
    ledger_dir.mkdir(parents=True)
    opcodes = ["IA64_OP_ILLEGAL"] + [
        f"IA64_OP_SELF_CHECK_{index:03d}" for index in range(1, EXPECTED_OPCODE_COUNT)
    ]
    (target / "decode.h").write_text(
        "typedef enum IA64Opcode {\n    "
        + ",\n    ".join(opcodes)
        + ",\n    IA64_OP_COUNT,\n} IA64Opcode;\n",
        encoding="utf-8",
    )
    trait_lines = [
        "IA64_OPCODE(IA64_OP_ILLEGAL, ILLEGAL, ILLEGAL, NONE, DECODE, "
        "DECODE, NONE, ILLEGAL)"
    ]
    trait_lines.extend(
        f"IA64_OPCODE({opcode}, INTEGER, DIRECT_TCG, NONE, FULL_TCG, "
        "NONE, NO_OS, TYPED)"
        for opcode in opcodes[1:]
    )
    (target / "opcode-traits.def").write_text(
        "\n".join(trait_lines) + "\n", encoding="utf-8"
    )
    (root / LEDGER_PATH).write_text(fixture_ledger(opcodes), encoding="utf-8")
    (root / "meson_options.txt").write_text("", encoding="utf-8")
    (root / "meson.build").write_text("", encoding="utf-8")
    (target / "meson.build").write_text(
        "ia64_ss.add(files(\n  'decode.c',\n  'opcode-traits.c',\n  'translate.c',\n))\n",
        encoding="utf-8",
    )
    (root / "hw/ia64").mkdir(parents=True)
    (root / "hw/ia64/meson.build").write_text("", encoding="utf-8")
    (target / "decode.c").write_text("/* typed decoder */\n", encoding="utf-8")
    (target / "opcode-traits.c").write_text("/* trait table */\n", encoding="utf-8")
    (target / "helper.h").write_text(
        "DEF_HELPER_FLAGS_1(raise_illegal_operation, TCG_CALL_NO_RETURN, env)\n",
        encoding="utf-8",
    )
    helper_boundaries = "".join(
        f"static void {function}(void)\n{{\n"
        f"    ia64_tr_require_helper(opcode, "
        f"IA64_OPCODE_HELPER_{category});\n"
        "}\n"
        for category, functions in REQUIRED_FOCUSED_HELPER_BOUNDARIES.items()
        for function in functions
    )
    (target / "translate.c").write_text(
        "static bool ia64_tr_helper_allowed(IA64Opcode opcode, "
        "IA64OpcodeHelper helper)\n{\n"
        "    const IA64OpcodeTraits *traits = ia64_opcode_traits_for(opcode);\n"
        "    return traits && traits->helper_whitelist == helper;\n}\n"
        "static void ia64_tr_require_helper(IA64Opcode opcode, "
        "IA64OpcodeHelper helper)\n{\n"
        "    g_assert(ia64_tr_helper_allowed(opcode, helper));\n}\n"
        + helper_boundaries
        +
        "static void ia64_tr_emit_decoded_illegal_operation(void)\n{\n"
        "    if (status != IA64_DECODE_OK) {\n"
        "        gen_helper_raise_illegal_operation(tcg_env);\n"
        "    }\n}\n",
        encoding="utf-8",
    )
    (tests / "meson.build").write_text(
        "test('test-ia64-production-cutover', python, args: [\n"
        "    'test-ia64-production-cutover.py', '--source-root', root,\n"
        "    '--binary', emulator, '--nm', nm, '--runtime-smoke',\n"
        "    '--harness', 'test-ia64-full-tcg.py'])\n",
        encoding="utf-8",
    )


def expect_injected_finding(
    root: Path,
    relative: str,
    mutate: Callable[[str], str],
    expected_code: str,
) -> None:
    path = root / relative
    original = path.read_text(encoding="utf-8")
    try:
        changed = mutate(original)
        if changed == original:
            raise AssertionError(f"self-check mutation for {expected_code} was a no-op")
        path.write_text(changed, encoding="utf-8")
        codes = {item.code for item in audit_tree(root)}
        if expected_code not in codes:
            raise AssertionError(
                f"self-check did not detect {expected_code}; observed {sorted(codes)}"
            )
    finally:
        path.write_text(original, encoding="utf-8")


def run_self_check() -> None:
    with tempfile.TemporaryDirectory(prefix="ia64-production-cutover-") as temporary:
        root = Path(temporary)
        create_self_check_tree(root)
        baseline = audit_tree(root)
        if baseline:
            raise AssertionError(
                "synthetic closed tree did not pass: "
                + "; ".join(f"{item.code}: {item.detail}" for item in baseline)
            )

        expect_injected_finding(
            root,
            str(LEDGER_PATH),
            lambda text: "\n".join(text.splitlines()[:-1]) + "\n",
            "ledger.count",
        )
        expect_injected_finding(
            root,
            str(LEDGER_PATH),
            lambda text: text.replace(",closed,yes,yes,", ",open,yes,yes,", 1),
            "ledger.open",
        )
        expect_injected_finding(
            root,
            "meson_options.txt",
            lambda text: text + (
                "option('ia64_engine_role', type: 'string',\n"
                "       description: 'obsolete role')\n"
            ),
            "role.option",
        )
        expect_injected_finding(
            root,
            "target/ia64/meson.build",
            lambda text: "ia64_ss.add(files('interp.c'))\n" + text,
            "source.legacy-link",
        )
        expect_injected_finding(
            root,
            "target/ia64/translate.c",
            lambda text: text + "\nvoid bad(void) { gen_helper_exec_slot(tcg_env); }\n",
            "source.generic-dispatch",
        )
        expect_injected_finding(
            root,
            "target/ia64/translate.c",
            lambda text: text + '\nconst char *bad = "VIBTANIUM_FULL_TCG_REWRITE";\n',
            "source.runtime-selector",
        )
        expect_injected_finding(
            root,
            "target/ia64/translate.c",
            lambda text: text + "\nvoid bad(void) { gen_helper_rse_alloc(x, insn->raw); }\n",
            "source.raw-helper",
        )
        expect_injected_finding(
            root,
            "target/ia64/translate.c",
            lambda text: text.replace("traits->helper_whitelist == helper", "true"),
            "traits.helper-guard",
        )
        expect_injected_finding(
            root,
            "target/ia64/translate.c",
            lambda text: text.replace(
                "IA64_OPCODE_HELPER_SYSTEM_PLANE",
                "IA64_OPCODE_HELPER_NONE",
                1,
            ),
            "traits.helper-boundary",
        )
        expect_injected_finding(
            root,
            "target/ia64/translate.c",
            lambda text: text.replace(
                "IA64_OPCODE_HELPER_SYSTEM_PLANE",
                "IA64_OPCODE_HELPER_NONE",
            ),
            "traits.helper-sites",
        )
        expect_injected_finding(
            root,
            "target/ia64/translate.c",
            lambda text: text.replace("gen_helper_raise_illegal_operation", "raise_bad"),
            "invalid.static-lowering",
        )
        expect_injected_finding(
            root,
            "tests/unit/meson.build",
            lambda text: text.replace("--runtime-smoke", "--no-smoke"),
            "smoke.arguments",
        )

        symbols: list[Finding] = []
        audit_symbol_text(
            "0000000140001000 T helper_exec_bundle\n"
            "0000000140002000 T ia64_translate_init\n",
            symbols,
        )
        if not any(item.code == "binary.generic-symbol" for item in symbols):
            raise AssertionError("self-check did not detect a generic linked symbol")
        strings: list[Finding] = []
        audit_image_bytes(b"prefix\0" + UNRELEASABLE_MARKER.encode("ascii"), strings)
        if not any(item.code == "binary.forbidden-string" for item in strings):
            raise AssertionError("self-check did not detect a forbidden image string")


def print_findings(catalog: Sequence[Finding]) -> None:
    counts = Counter(item.code for item in catalog)
    for item in catalog:
        print(f"[{item.code}] {item.detail}")
    if catalog:
        summary = ", ".join(f"{code}={count}" for code, count in sorted(counts.items()))
        print(f"IA-64 production cutover inventory: {len(catalog)} finding(s); {summary}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-root",
        type=Path,
        default=Path(__file__).resolve().parents[2],
        help="QEMU source root (default: inferred from this script)",
    )
    parser.add_argument("--binary", type=Path, help="production qemu-system-ia64.exe")
    parser.add_argument("--nm", help="nm executable; required with --binary")
    parser.add_argument("--harness", type=Path, help="test-ia64-full-tcg.py path")
    parser.add_argument(
        "--runtime-smoke",
        action="store_true",
        help="run selector-free valid and invalid guest microprograms",
    )
    parser.add_argument(
        "--inventory",
        action="store_true",
        help="report current gaps but exit successfully",
    )
    parser.add_argument(
        "--self-check",
        action="store_true",
        help="prove every detector against synthetic pass/fail fixtures",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_check:
        run_self_check()
        print("IA-64 production cutover gate self-check passed")
        return 0

    root = args.source_root.resolve()
    catalog = audit_tree(root)
    if args.binary is not None:
        if args.nm is None:
            finding(catalog, "cli.nm", "--nm is required with --binary")
        else:
            audit_binary(args.binary.resolve(), args.nm, catalog)
    elif args.nm is not None:
        finding(catalog, "cli.binary", "--nm has no effect without --binary")

    if args.runtime_smoke:
        if args.binary is None or args.harness is None:
            finding(
                catalog,
                "cli.smoke",
                "--runtime-smoke requires both --binary and --harness",
            )
        else:
            runtime_path: list[Path] = []
            if args.nm is not None:
                nm_path = Path(args.nm)
                if nm_path.is_absolute() or nm_path.parent != Path("."):
                    runtime_path.append(nm_path.resolve().parent)
            run_runtime_smoke(
                args.binary.resolve(),
                args.harness.resolve(),
                catalog,
                runtime_path,
            )

    print_findings(catalog)
    if args.inventory:
        print("IA-64 production cutover inventory completed (non-enforcing mode)")
        return 0
    if catalog:
        print("IA-64 production cutover gate failed", file=sys.stderr)
        return 1
    print("IA-64 production cutover gate passed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, OSError, RuntimeError) as exc:
        print(f"IA-64 production cutover gate failed: {exc}", file=sys.stderr)
        sys.exit(1)
