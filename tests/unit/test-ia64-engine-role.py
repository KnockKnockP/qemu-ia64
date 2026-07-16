#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Structural and linked-symbol gate for the sole IA-64 production engine."""

import argparse
from pathlib import Path
import subprocess
import sys


FORBIDDEN_PRODUCTION_SOURCES = (
    "debug-trace.c",
    "interp.c",
    "interp-ldst.c",
    "oracle-perf.c",
    "tcg-classify.c",
)
FORBIDDEN_LINK_SYMBOLS = (
    "helper_exec_bundle",
    "helper_exec_bundle_lookup_ptr",
    "helper_exec_slot",
    "ia64_exec_bundle_impl",
    "ia64_insn_exec_bundle",
    "exec_predecoded_slot",
    "ia64_debug_hooks_active",
    "ia64_trace_execve",
)
FORBIDDEN_SELECTOR_STRINGS = (
    "VIBTANIUM_FULL_TCG_REWRITE",
    "VIBTANIUM_TCG_FAST_DISABLE",
    "VIBTANIUM_TCG_ZERO_HELPER",
    "VIBTANIUM_TCG_REGION",
    "dual-oracle",
    "full-only-dev",
    "CONFIG_IA64_FULL_ONLY_DEV",
    "IA64_FULL_ONLY_DEVELOPER_BUILD_UNRELEASABLE",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def read(root: Path, relative: str) -> str:
    return (root / relative).read_text(encoding="utf-8")


def check_sources(root: Path) -> None:
    options = read(root, "meson_options.txt")
    top_meson = read(root, "meson.build")
    target_meson = read(root, "target/ia64/meson.build")

    for text, owner in ((options, "meson_options.txt"),
                        (top_meson, "meson.build"),
                        (target_meson, "target/ia64/meson.build")):
        require("ia64_engine_role" not in text,
                f"{owner} retains the removed IA-64 engine role")
        require("dual-oracle" not in text,
                f"{owner} retains the removed dual-oracle role")

    for source in FORBIDDEN_PRODUCTION_SOURCES:
        require(f"'{source}'" not in target_meson and
                f'"{source}"' not in target_meson,
                f"production source set still links {source}")
    for source in ("decode.c", "opcode-traits.c", "translate.c"):
        require(f"'{source}'" in target_meson,
                f"typed production core source {source} is missing")
    require(not (root / "target/ia64/full-only.c").exists(),
            "obsolete target/ia64/full-only.c remains")


def symbol_table(nm: str, binary: Path) -> str:
    result = subprocess.run(
        [nm, "-a", str(binary)],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    require(result.returncode == 0,
            f"nm failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout


def check_binary(binary: Path, nm: str) -> None:
    symbols = symbol_table(nm, binary)
    image = binary.read_bytes()

    for symbol in FORBIDDEN_LINK_SYMBOLS:
        require(symbol not in symbols,
                f"production link contains forbidden symbol {symbol}")
    for marker in FORBIDDEN_SELECTOR_STRINGS:
        require(marker.encode() not in image,
                f"production executable contains forbidden marker {marker}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--nm")
    args = parser.parse_args()

    check_sources(args.source_root)
    if args.binary is not None:
        require(args.nm is not None, "--nm is required with --binary")
        check_binary(args.binary, args.nm)
    print("IA-64 sole production-engine gate passed")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AssertionError, OSError) as exc:
        print(f"IA-64 engine gate failed: {exc}", file=sys.stderr)
        sys.exit(1)
