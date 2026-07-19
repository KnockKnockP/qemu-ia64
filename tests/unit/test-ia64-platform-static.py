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
    efi = (root / "hw/ia64/efi.c").read_text(encoding="utf-8")
    services = (root / "hw/ia64/efi-services.c").read_text(encoding="utf-8")
    gtk = (root / "ui/gtk.c").read_text(encoding="utf-8")
    boot_manager = (root / "hw/ia64/efi-boot-manager.c").read_text(
        encoding="utf-8"
    )
    cpu = (root / "target/ia64/cpu.c").read_text(encoding="utf-8")
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
        "vibtanium_efi_boot_manager_destroy(vms);",
        "run_on_cpu(CPU(vms->cpu), vibtanium_cpu_reset_on_cpu",
        "vibtanium_load_efi_app(vms, machine);",
    ), "Vibtanium EFI VGA I/O-space handoff")
    require(efi, (
        'aml_name_decl("_S5", pkg)',
    ), "Vibtanium ACPI soft-off description")
    require(efi, (
        "ia64_firmware_identity_tlb_fill(",
    ), "EFI image-entry translation handoff")
    require(services, (
        "qemu_system_reset_request(SHUTDOWN_CAUSE_GUEST_RESET);",
        "qemu_system_shutdown_request(SHUTDOWN_CAUSE_GUEST_SHUTDOWN);",
    ), "Vibtanium EFI ResetSystem lifecycle dispatch")
    require(gtk, (
        "gd_menu_reset(GtkMenuItem *item, void *opaque)",
        "qmp_system_reset(NULL);",
        "gd_menu_powerdown(GtkMenuItem *item, void *opaque)",
        "qmp_system_powerdown(NULL);",
        "gd_menu_quit(GtkMenuItem *item, void *opaque)",
        "qmp_quit(NULL);",
    ), "GTK Machine menu lifecycle dispatch")
    require(boot_manager, (
        "if (!bm->choices || bm->choices->len == 0)",
        "vibtanium_efi_boot_manager_destroy(vms);",
        "vms->cpu->env.firmware_boot_wait = true;",
        "vms->cpu->env.firmware_boot_wait = false;",
    ), "EFI reset-to-image CPU hold")
    require(cpu, (
        "if (cpu->env.firmware_boot_wait)",
        "if (firmware_installed)",
        "target lookup so this same SoftMMU fill consumes it",
    ), "IA-64 reset execution-state cleanup")
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
