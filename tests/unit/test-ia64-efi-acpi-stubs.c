/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "hw/acpi/acpi.h"
#include "hw/acpi/bios-linker-loader.h"
#include "hw/core/boards.h"

int acpi_checksum(const uint8_t *data, int len)
{
    uint8_t sum = 0;

    for (int i = 0; i < len; i++) {
        sum += data[i];
    }
    return -sum;
}

void bios_linker_loader_add_checksum(BIOSLinker *linker, const char *file,
                                     unsigned start_offset, unsigned size,
                                     unsigned checksum_offset)
{
    g_assert_not_reached();
}

BIOSLinker *bios_linker_loader_init(void)
{
    g_assert_not_reached();
}

void bios_linker_loader_cleanup(BIOSLinker *linker)
{
    g_assert_not_reached();
}

void bios_linker_loader_alloc(BIOSLinker *linker, const char *file_name,
                              GArray *file_blob, uint32_t alloc_align,
                              bool alloc_fseg)
{
    g_assert_not_reached();
}

void bios_linker_loader_add_pointer(BIOSLinker *linker,
                                    const char *dest_file,
                                    uint32_t dst_patched_offset,
                                    uint8_t dst_patched_size,
                                    const char *src_file,
                                    uint32_t src_offset)
{
    g_assert_not_reached();
}

bool machine_find_lowest_level_cache_at_topo_level(const MachineState *ms,
                                                   int *lowest_cache_level,
                                                   CpuTopologyLevel topo_level)
{
    return false;
}

bool machine_defines_cache_at_topo_level(const MachineState *ms,
                                         CpuTopologyLevel topology)
{
    return false;
}
