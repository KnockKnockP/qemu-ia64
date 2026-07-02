/*
 * ACPI PCI _CRS helpers
 *
 * Copyright (C) 2008-2010  Kevin O'Connor <kevin@koconnor.net>
 * Copyright (C) 2006 Fabrice Bellard
 * Copyright (C) 2013 Red Hat Inc
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/acpi/aml-build.h"
#include "hw/pci/pci_host.h"
#include "hw/pci/pci_bus.h"
#include "hw/pci/pci_bridge.h"

static void crs_range_free(gpointer data)
{
    CrsRangeEntry *entry = (CrsRangeEntry *)data;

    g_free(entry);
}

static gint crs_range_compare(gconstpointer a, gconstpointer b)
{
    CrsRangeEntry *entry_a = *(CrsRangeEntry **)a;
    CrsRangeEntry *entry_b = *(CrsRangeEntry **)b;

    if (entry_a->base < entry_b->base) {
        return -1;
    } else if (entry_a->base > entry_b->base) {
        return 1;
    } else {
        return 0;
    }
}

/*
 * crs_range_merge - merges adjacent ranges in the given array.
 * Array elements are deleted and replaced with the merged ranges.
 */
static void crs_range_merge(GPtrArray *range)
{
    g_autoptr(GPtrArray) tmp = g_ptr_array_new_with_free_func(crs_range_free);
    CrsRangeEntry *entry;
    uint64_t range_base, range_limit;
    int i;

    if (!range->len) {
        return;
    }

    g_ptr_array_sort(range, crs_range_compare);

    entry = g_ptr_array_index(range, 0);
    range_base = entry->base;
    range_limit = entry->limit;
    for (i = 1; i < range->len; i++) {
        entry = g_ptr_array_index(range, i);
        if (entry->base - 1 == range_limit) {
            range_limit = entry->limit;
        } else {
            crs_range_insert(tmp, range_base, range_limit);
            range_base = entry->base;
            range_limit = entry->limit;
        }
    }
    crs_range_insert(tmp, range_base, range_limit);

    g_ptr_array_set_size(range, 0);
    for (i = 0; i < tmp->len; i++) {
        entry = g_ptr_array_index(tmp, i);
        crs_range_insert(range, entry->base, entry->limit);
    }
}

Aml *build_crs(PCIHostState *host, CrsRangeSet *range_set, uint32_t io_offset,
               uint32_t mmio32_offset, uint64_t mmio64_offset,
               uint16_t bus_nr_offset)
{
    Aml *crs = aml_resource_template();
    CrsRangeSet temp_range_set;
    CrsRangeEntry *entry;
    uint8_t max_bus = pci_bus_num(host->bus);
    uint8_t type;
    int devfn;
    int i;

    crs_range_set_init(&temp_range_set);
    for (devfn = 0; devfn < ARRAY_SIZE(host->bus->devices); devfn++) {
        uint64_t range_base, range_limit;
        PCIDevice *dev = host->bus->devices[devfn];

        if (!dev) {
            continue;
        }

        for (i = 0; i < PCI_NUM_REGIONS; i++) {
            PCIIORegion *r = &dev->io_regions[i];

            range_base = r->addr;
            range_limit = r->addr + r->size - 1;

            /*
             * Work-around for old bioses that do not support multiple root
             * buses.
             */
            if (!range_base || range_base > range_limit) {
                continue;
            }

            if (r->type & PCI_BASE_ADDRESS_SPACE_IO) {
                crs_range_insert(temp_range_set.io_ranges,
                                 range_base, range_limit);
            } else {
                uint64_t length = range_limit - range_base + 1;

                if (range_limit <= UINT32_MAX && length <= UINT32_MAX) {
                    crs_range_insert(temp_range_set.mem_ranges, range_base,
                                     range_limit);
                } else {
                    crs_range_insert(temp_range_set.mem_64bit_ranges,
                                     range_base, range_limit);
                }
            }
        }

        type = dev->config[PCI_HEADER_TYPE] & ~PCI_HEADER_TYPE_MULTI_FUNCTION;
        if (type == PCI_HEADER_TYPE_BRIDGE) {
            uint8_t subordinate = dev->config[PCI_SUBORDINATE_BUS];

            if (subordinate > max_bus) {
                max_bus = subordinate;
            }

            range_base = pci_bridge_get_base(dev, PCI_BASE_ADDRESS_SPACE_IO);
            range_limit = pci_bridge_get_limit(dev, PCI_BASE_ADDRESS_SPACE_IO);

            /*
             * Work-around for old bioses that do not support multiple root
             * buses.
             */
            if (range_base && range_base <= range_limit) {
                crs_range_insert(temp_range_set.io_ranges,
                                 range_base, range_limit);
            }

            range_base =
                pci_bridge_get_base(dev, PCI_BASE_ADDRESS_SPACE_MEMORY);
            range_limit =
                pci_bridge_get_limit(dev, PCI_BASE_ADDRESS_SPACE_MEMORY);

            /*
             * Work-around for old bioses that do not support multiple root
             * buses.
             */
            if (range_base && range_base <= range_limit) {
                uint64_t length = range_limit - range_base + 1;

                if (range_limit <= UINT32_MAX && length <= UINT32_MAX) {
                    crs_range_insert(temp_range_set.mem_ranges,
                                     range_base, range_limit);
                } else {
                    crs_range_insert(temp_range_set.mem_64bit_ranges,
                                     range_base, range_limit);
                }
            }

            range_base =
                pci_bridge_get_base(dev, PCI_BASE_ADDRESS_MEM_PREFETCH);
            range_limit =
                pci_bridge_get_limit(dev, PCI_BASE_ADDRESS_MEM_PREFETCH);

            /*
             * Work-around for old bioses that do not support multiple root
             * buses.
             */
            if (range_base && range_base <= range_limit) {
                uint64_t length = range_limit - range_base + 1;

                if (range_limit <= UINT32_MAX && length <= UINT32_MAX) {
                    crs_range_insert(temp_range_set.mem_ranges,
                                     range_base, range_limit);
                } else {
                    crs_range_insert(temp_range_set.mem_64bit_ranges,
                                     range_base, range_limit);
                }
            }
        }
    }

    crs_range_merge(temp_range_set.io_ranges);
    for (i = 0; i < temp_range_set.io_ranges->len; i++) {
        entry = g_ptr_array_index(temp_range_set.io_ranges, i);
        aml_append(crs,
                   aml_dword_io(AML_MIN_FIXED, AML_MAX_FIXED,
                                AML_POS_DECODE, AML_ENTIRE_RANGE,
                                0, entry->base, entry->limit, io_offset,
                                entry->limit - entry->base + 1));
        crs_range_insert(range_set->io_ranges, entry->base, entry->limit);
    }

    crs_range_merge(temp_range_set.mem_ranges);
    for (i = 0; i < temp_range_set.mem_ranges->len; i++) {
        entry = g_ptr_array_index(temp_range_set.mem_ranges, i);
        assert(entry->limit <= UINT32_MAX &&
               (entry->limit - entry->base + 1) <= UINT32_MAX);
        aml_append(crs,
                   aml_dword_memory(AML_POS_DECODE, AML_MIN_FIXED,
                                    AML_MAX_FIXED, AML_NON_CACHEABLE,
                                    AML_READ_WRITE,
                                    0, entry->base, entry->limit, mmio32_offset,
                                    entry->limit - entry->base + 1));
        crs_range_insert(range_set->mem_ranges, entry->base, entry->limit);
    }

    crs_range_merge(temp_range_set.mem_64bit_ranges);
    for (i = 0; i < temp_range_set.mem_64bit_ranges->len; i++) {
        entry = g_ptr_array_index(temp_range_set.mem_64bit_ranges, i);
        aml_append(crs,
                   aml_qword_memory(AML_POS_DECODE, AML_MIN_FIXED,
                                    AML_MAX_FIXED, AML_NON_CACHEABLE,
                                    AML_READ_WRITE,
                                    0, entry->base, entry->limit, mmio64_offset,
                                    entry->limit - entry->base + 1));
        crs_range_insert(range_set->mem_64bit_ranges,
                         entry->base, entry->limit);
    }

    crs_range_set_free(&temp_range_set);

    aml_append(crs,
        aml_word_bus_number(AML_MIN_FIXED, AML_MAX_FIXED, AML_POS_DECODE,
                            0, pci_bus_num(host->bus), max_bus,
                            bus_nr_offset,
                            max_bus - pci_bus_num(host->bus) + 1));

    return crs;
}
