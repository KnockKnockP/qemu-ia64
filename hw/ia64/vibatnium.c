/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "hw/char/serial-mm.h"
#include "hw/core/cpu.h"
#include "hw/core/loader.h"
#include "hw/ia64/efi.h"
#include "hw/ia64/vibatnium.h"
#include "system/address-spaces.h"
#include "system/system.h"

static void vibatnium_uart_irq(void *opaque, int n, int level)
{
    /*
     * Phase 7 wires the UART to a stable interrupt sink, but deliberately
     * leaves IA-64 interrupt-controller and external-interrupt delivery for a
     * later phase.
     */
    (void)opaque;
    (void)n;
    (void)level;
}

static void vibatnium_load_efi_app(VibatniumMachineState *vms,
                                   MachineState *machine)
{
    Error *local_err = NULL;
    VibatniumEfiImage image;

    if (!machine->kernel_filename) {
        return;
    }

    if (!vibatnium_efi_image_from_file(machine->kernel_filename,
                                       VIBATNIUM_EFI_APP_BASE, &image,
                                       &local_err)) {
        error_reportf_err(local_err, "could not load IA-64 EFI app '%s': ",
                          machine->kernel_filename);
        exit(1);
    }

    if (machine->ram_size <= image.load_base ||
        image.size > machine->ram_size - image.load_base) {
        error_report("IA-64 EFI app '%s' image size 0x%" PRIx64
                     " at 0x%016" PRIx64 " does not fit in RAM",
                     machine->kernel_filename, (uint64_t)image.size,
                     image.load_base);
        vibatnium_efi_image_destroy(&image);
        exit(1);
    }

    rom_add_blob_fixed("vibatnium.efi-app", image.data, image.size,
                       image.load_base);
    vibatnium_efi_prepare_cpu(&vms->cpu->env, &image);

    warn_report("%s", image.message);
    warn_report("vibatnium EFI handoff image-handle=0x%016" PRIx64
                " system-table=0x%016" PRIx64
                " con-out=0x%016" PRIx64
                " loaded-image=0x%016" PRIx64,
                (uint64_t)VIBATNIUM_EFI_IMAGE_HANDLE,
                (uint64_t)VIBATNIUM_EFI_SYSTEM_TABLE,
                (uint64_t)VIBATNIUM_EFI_CON_OUT,
                (uint64_t)VIBATNIUM_EFI_LOADED_IMAGE);
    warn_report("IA-64 instruction execution is still unimplemented; "
                "starting the CPU will stop at the first translated bundle");

    vibatnium_efi_image_destroy(&image);
}

static void vibatnium_init(MachineState *machine)
{
    VibatniumMachineState *vms = VIBATNIUM_MACHINE(machine);
    MemoryRegion *sysmem = get_system_memory();

    if (machine->ram_size > VIBATNIUM_RAM_LIMIT) {
        error_report("vibatnium RAM must fit below the placeholder MMIO window "
                     "(maximum %" PRIu64 " bytes)",
                     (uint64_t)VIBATNIUM_RAM_LIMIT);
        exit(1);
    }

    vms->cpu = IA64_CPU(cpu_create(machine->cpu_type));

    memory_region_add_subregion(sysmem, VIBATNIUM_RAM_BASE, machine->ram);

    qemu_init_irq_child(OBJECT(machine), "uart-irq", &vms->uart_irq,
                        vibatnium_uart_irq, vms, 0);
    serial_mm_init(sysmem, VIBATNIUM_UART_BASE, 0, &vms->uart_irq, 115200,
                   serial_hd(0), DEVICE_LITTLE_ENDIAN);

    memory_region_init_ram(&vms->nvram, NULL, "vibatnium.nvram",
                           VIBATNIUM_NVRAM_SIZE, &error_fatal);
    memory_region_add_subregion(sysmem, VIBATNIUM_NVRAM_BASE, &vms->nvram);

    memory_region_init_ram(&vms->firmware, NULL, "vibatnium.firmware",
                           VIBATNIUM_FIRMWARE_SIZE,
                           &error_fatal);
    memory_region_set_readonly(&vms->firmware, true);
    memory_region_add_subregion(sysmem, VIBATNIUM_FIRMWARE_BASE,
                                &vms->firmware);

    vibatnium_load_efi_app(vms, machine);
}

static void vibatnium_machine_class_init(ObjectClass *oc, const void *data)
{
    MachineClass *mc = MACHINE_CLASS(oc);

    mc->desc = "Synthetic IA-64 machine skeleton";
    mc->init = vibatnium_init;
    mc->max_cpus = 1;
    mc->default_cpu_type = TYPE_ITANIUM2_CPU;
    mc->default_ram_size = 512 * MiB;
    mc->default_ram_id = "vibatnium.ram";
    mc->no_cdrom = 1;
    mc->no_floppy = 1;
    mc->no_parallel = 1;
}

static const TypeInfo vibatnium_machine_typeinfo = {
    .name = TYPE_VIBATNIUM_MACHINE,
    .parent = TYPE_MACHINE,
    .instance_size = sizeof(VibatniumMachineState),
    .class_init = vibatnium_machine_class_init,
};

static void vibatnium_machine_register_types(void)
{
    type_register_static(&vibatnium_machine_typeinfo);
}

type_init(vibatnium_machine_register_types)
