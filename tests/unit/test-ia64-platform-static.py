#!/usr/bin/env python3
"""Structural guardrails for IA-64 platform/TCG handoff wiring."""

from __future__ import annotations

import argparse
import pathlib


def require(source: str, tokens: tuple[str, ...], label: str) -> None:
    missing = [token for token in tokens if token not in source]
    if missing:
        raise AssertionError(f"{label} is missing: {', '.join(missing)}")


def forbid(source: str, tokens: tuple[str, ...], label: str) -> None:
    present = [token for token in tokens if token in source]
    if present:
        raise AssertionError(f"{label} contains forbidden seams: "
                             f"{', '.join(present)}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-root", type=pathlib.Path, required=True)
    args = parser.parse_args()
    root = args.source_root

    console = (root / "hw/ia64/efi-console.c").read_text(encoding="utf-8")
    machine = (root / "hw/ia64/vibtanium.c").read_text(encoding="utf-8")
    firmware_hook = (root / "target/ia64/firmware-hook.c").read_text(
        encoding="utf-8"
    )
    helper = (root / "target/ia64/helper.h").read_text(encoding="utf-8")
    translate = (root / "target/ia64/translate.c").read_text(encoding="utf-8")

    require(console, (
        "AddressSpace *io_as;",
        "address_space_stb(efi_console.io_as, port, value,",
        "address_space_ldub(efi_console.io_as, port,",
    ), "EFI VGA machine-I/O routing")
    require(machine, (
        "vibtanium_efi_console_init(vga, &vms->pci_io_as);",
    ), "Vibtanium EFI VGA I/O-space handoff")
    forbid(console, (
        "address_space_stb(&address_space_io",
        "address_space_ldub(&address_space_io",
    ), "EFI VGA global-I/O routing")

    require(helper, (
        "DEF_HELPER_1(firmware_linux_cmdline_append, void, env)",
    ), "Linux command-line helper declaration")
    require(firmware_hook, (
        "void HELPER(firmware_linux_cmdline_append)(CPUIA64State *env)",
        "cpu->neg.can_do_io = true;",
        "ia64_firmware_maybe_apply_linux_cmdline_append(env);",
    ), "Linux command-line helper implementation")
    require(translate, (
        "if (ia64_firmware_linux_cmdline_append_pending()) {",
        "gen_helper_firmware_linux_cmdline_append(tcg_env);",
    ), "Linux command-line TB-boundary hook")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
