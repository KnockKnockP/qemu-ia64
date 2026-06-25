/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "accel/tcg/cpu-ldst.h"
#include "bundle.h"
#include "cpu.h"
#include "exception.h"
#include "exec-smoke.h"
#include "exec/helper-proto.h"
#include "hw/ia64/efi.h"
#include "hw/ia64/efi-storage.h"

static void abort_unsupported_slot(CPUIA64State *env,
                                   const IA64DecodedBundle *decoded,
                                   int slot)
{
    char bundle_text[192];
    char slot_text[256];

    ia64_format_decoded_bundle(decoded, bundle_text, sizeof(bundle_text));
    ia64_format_slot_class(decoded, slot, slot_text, sizeof(slot_text));

    cpu_abort(env_cpu(env),
              "IA-64 execution frontier at IP=0x%016" PRIx64
              ": unsupported instruction %s; bundle %s\n",
              env->ip, slot_text, bundle_text);
}

static void abort_zero_branch(CPUIA64State *env,
                              const IA64DecodedBundle *decoded,
                              int slot)
{
    char bundle_text[192];
    char slot_text[256];

    ia64_format_decoded_bundle(decoded, bundle_text, sizeof(bundle_text));
    ia64_format_slot_class(decoded, slot, slot_text, sizeof(slot_text));

    cpu_abort(env_cpu(env),
              "IA-64 execution frontier at IP=0x%016" PRIx64
              ": branch target became zero in %s; bundle %s\n",
              env->ip, slot_text, bundle_text);
}

enum {
    EFI_BOOT_SERVICE_BASE = 0,
    EFI_RUNTIME_SERVICE_BASE =
        EFI_BOOT_SERVICE_BASE + VIBATNIUM_EFI_BOOT_SERVICE_COUNT,
    EFI_CON_OUT_SERVICE_BASE =
        EFI_RUNTIME_SERVICE_BASE + VIBATNIUM_EFI_RUNTIME_SERVICE_COUNT,
    EFI_CON_IN_SERVICE_BASE =
        EFI_CON_OUT_SERVICE_BASE + VIBATNIUM_EFI_CON_OUT_SERVICE_COUNT,
    EFI_BLOCK_IO_SERVICE_BASE =
        EFI_CON_IN_SERVICE_BASE + VIBATNIUM_EFI_CON_IN_SERVICE_COUNT,
    EFI_SIMPLE_FILE_SYSTEM_SERVICE_BASE =
        EFI_BLOCK_IO_SERVICE_BASE + VIBATNIUM_EFI_BLOCK_IO_SERVICE_COUNT,
    EFI_FILE_SERVICE_BASE =
        EFI_SIMPLE_FILE_SYSTEM_SERVICE_BASE +
        VIBATNIUM_EFI_SIMPLE_FILE_SYSTEM_SERVICE_COUNT,
    EFI_SERVICE_DESCRIPTOR_COUNT =
        EFI_FILE_SERVICE_BASE + VIBATNIUM_EFI_FILE_SERVICE_COUNT,
};

#define EFI_MAX_INSTALLED_PROTOCOLS 64
#define EFI_MAX_FILE_HANDLES 64
#define EFI_MAX_EVENTS 64
#define EFI_MAX_PAGE_ALLOCATIONS 64
#define EFI_MAX_PATH_CHARS 512
#define EFI_MAX_FILE_READ_BYTES (128 * 1024 * 1024)
#define EFI_PAGE_SIZE UINT64_C(4096)
#define EFI_MEMORY_DESCRIPTOR_SIZE UINT64_C(40)
#define EFI_MEMORY_DESCRIPTOR_VERSION 1
#define EFI_GUEST_RAM_TOP UINT64_C(0x20000000)
#define EFI_PAGE_ALLOC_BASE UINT64_C(0x03000000)
#define EFI_PAGE_ALLOC_SIZE UINT64_C(0x01000000)
#define EFI_LOW_CONVENTIONAL_BASE UINT64_C(0x00100000)
#define EFI_LOW_CONVENTIONAL_PAGES UINT64_C(0x00000f00)
#define EFI_HIGH_CONVENTIONAL_BASE UINT64_C(0x04000000)
#define EFI_HIGH_CONVENTIONAL_PAGES \
    ((EFI_GUEST_RAM_TOP - EFI_HIGH_CONVENTIONAL_BASE) / EFI_PAGE_SIZE)

enum {
    EFI_RESERVED_MEMORY_TYPE = 0,
    EFI_LOADER_CODE = 1,
    EFI_LOADER_DATA = 2,
    EFI_BOOT_SERVICES_CODE = 3,
    EFI_BOOT_SERVICES_DATA = 4,
    EFI_CONVENTIONAL_MEMORY = 7,
};

enum {
    EFI_ALLOCATE_ANY_PAGES = 0,
    EFI_ALLOCATE_MAX_ADDRESS = 1,
    EFI_ALLOCATE_ADDRESS = 2,
};

#define EFI_MEMORY_WB UINT64_C(0x0000000000000008)

typedef struct EfiInstalledProtocol {
    bool in_use;
    uint64_t handle;
    uint8_t guid[16];
    uint64_t interface;
} EfiInstalledProtocol;

typedef struct EfiGuestFile {
    bool in_use;
    uint64_t address;
    bool is_directory;
    char path[EFI_MAX_PATH_CHARS];
    uint8_t *data;
    size_t size;
    uint64_t position;
} EfiGuestFile;

typedef struct EfiGuestEvent {
    bool in_use;
    uint64_t handle;
    uint32_t type;
    bool signaled;
    bool timer;
} EfiGuestEvent;

typedef struct EfiPageAllocation {
    bool in_use;
    uint64_t address;
    uint64_t pages;
    uint32_t type;
} EfiPageAllocation;

typedef struct EfiMemoryRange {
    uint32_t type;
    uint64_t address;
    uint64_t pages;
    uint64_t attributes;
} EfiMemoryRange;

static VibatniumEfiBlockDevice efi_boot_media;
static char *efi_boot_media_name;
static bool efi_boot_media_valid;
static uint64_t efi_pool_next = VIBATNIUM_EFI_POOL_BASE;
static uint64_t efi_page_alloc_next = EFI_PAGE_ALLOC_BASE;
static uint64_t efi_memory_map_key = 1;
static uint64_t efi_dynamic_handle_next = UINT64_C(0x00073000);
static uint64_t efi_next_event_handle = VIBATNIUM_EFI_CON_IN_WAIT_EVENT + 1;
static bool efi_conin_enter_pending = true;
static EfiInstalledProtocol efi_installed_protocols[EFI_MAX_INSTALLED_PROTOCOLS];
static EfiGuestFile efi_guest_files[EFI_MAX_FILE_HANDLES];
static EfiGuestEvent efi_guest_events[EFI_MAX_EVENTS];
static EfiPageAllocation efi_page_allocations[EFI_MAX_PAGE_ALLOCATIONS];

static const uint8_t efi_loaded_image_guid[16] = {
    0xa1, 0x31, 0x1b, 0x5b, 0x62, 0x95, 0xd2, 0x11,
    0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
};

static const uint8_t efi_simple_text_output_guid[16] = {
    0xc2, 0x77, 0x74, 0x38, 0xc7, 0x69, 0xd2, 0x11,
    0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
};

static const uint8_t efi_simple_text_input_guid[16] = {
    0xc1, 0x77, 0x74, 0x38, 0xc7, 0x69, 0xd2, 0x11,
    0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
};

static const uint8_t efi_device_path_guid[16] = {
    0x91, 0x6e, 0x57, 0x09, 0x3f, 0x6d, 0xd2, 0x11,
    0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
};

static const uint8_t efi_block_io_guid[16] = {
    0x21, 0x5b, 0x4e, 0x96, 0x59, 0x64, 0xd2, 0x11,
    0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
};

static const uint8_t efi_simple_file_system_guid[16] = {
    0x22, 0x5b, 0x4e, 0x96, 0x59, 0x64, 0xd2, 0x11,
    0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
};

static const uint8_t efi_file_info_guid[16] = {
    0x92, 0x6e, 0x57, 0x09, 0x3f, 0x6d, 0xd2, 0x11,
    0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
};

static bool efi_gate_service_index(uint64_t gate_ip, unsigned *index)
{
    uint64_t offset;

    if (gate_ip < VIBATNIUM_EFI_CALL_GATE_BASE) {
        return false;
    }

    offset = gate_ip - VIBATNIUM_EFI_CALL_GATE_BASE;
    if ((offset & (IA64_BUNDLE_SIZE - 1)) != 0) {
        return false;
    }
    offset /= IA64_BUNDLE_SIZE;
    if (offset >= EFI_SERVICE_DESCRIPTOR_COUNT) {
        return false;
    }

    *index = offset;
    return true;
}

static bool efi_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBATNIUM_EFI_TRACE") != NULL;
    }
    return enabled != 0;
}

static bool ia64_progress_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBATNIUM_IA64_PROGRESS") != NULL;
    }
    return enabled != 0;
}

static void ia64_progress_trace_bundle(CPUIA64State *env)
{
    static uint64_t count;

    count++;
    if (!ia64_progress_trace_enabled() || (count & UINT64_C(0xfffff)) != 0) {
        return;
    }

    fprintf(stderr,
            "[ia64-progress] bundles=%" PRIu64 " ip=0x%016" PRIx64
            " psr=0x%016" PRIx64 " cfm=0x%016" PRIx64
            " lc=0x%016" PRIx64 " ec=0x%016" PRIx64
            " bspstore=0x%016" PRIx64 " b0=0x%016" PRIx64 "\n",
            count, env->ip, env->psr, env->cfm, env->ar[IA64_AR_LC],
            env->ar[IA64_AR_EC], env->ar[IA64_AR_BSPSTORE], env->br[0]);
}

static void ia64_progress_trace_event(CPUIA64State *env, const char *event,
                                      uint64_t value, uint64_t next_ip)
{
    static uint64_t event_count;

    if (!ia64_progress_trace_enabled()) {
        return;
    }
    event_count++;
    if (event_count > 16 && (event_count & UINT64_C(0xffff)) != 0) {
        return;
    }

    fprintf(stderr,
            "[ia64-progress] event=%s ip=0x%016" PRIx64
            " value=0x%016" PRIx64 " next=0x%016" PRIx64
            " psr=0x%016" PRIx64 " cfm=0x%016" PRIx64 "\n",
            event, env->ip, value, next_ip, env->psr, env->cfm);
}

static const char *efi_service_group_name(unsigned service_index,
                                          unsigned *group_index)
{
    if (service_index < EFI_RUNTIME_SERVICE_BASE) {
        *group_index = service_index - EFI_BOOT_SERVICE_BASE;
        return "boot";
    }
    if (service_index < EFI_CON_OUT_SERVICE_BASE) {
        *group_index = service_index - EFI_RUNTIME_SERVICE_BASE;
        return "runtime";
    }
    if (service_index < EFI_CON_IN_SERVICE_BASE) {
        *group_index = service_index - EFI_CON_OUT_SERVICE_BASE;
        return "conout";
    }
    if (service_index < EFI_BLOCK_IO_SERVICE_BASE) {
        *group_index = service_index - EFI_CON_IN_SERVICE_BASE;
        return "conin";
    }
    if (service_index < EFI_SIMPLE_FILE_SYSTEM_SERVICE_BASE) {
        *group_index = service_index - EFI_BLOCK_IO_SERVICE_BASE;
        return "blockio";
    }
    if (service_index < EFI_FILE_SERVICE_BASE) {
        *group_index = service_index - EFI_SIMPLE_FILE_SYSTEM_SERVICE_BASE;
        return "simplefs";
    }
    *group_index = service_index - EFI_FILE_SERVICE_BASE;
    return "file";
}

static void efi_trace_service(CPUIA64State *env, unsigned service_index,
                              uint64_t result)
{
    unsigned group_index = 0;
    const char *group;

    if (!efi_trace_enabled()) {
        return;
    }

    group = efi_service_group_name(service_index, &group_index);
    fprintf(stderr,
            "[efi] ip=0x%016" PRIx64 " service=%s[%u] status=%s "
            "r32=0x%016" PRIx64 " r33=0x%016" PRIx64
            " r34=0x%016" PRIx64 " r35=0x%016" PRIx64 "\n",
            env->ip, group, group_index, vibatnium_efi_status_name(result),
            ia64_read_gr(env, 32), ia64_read_gr(env, 33),
            ia64_read_gr(env, 34), ia64_read_gr(env, 35));
}

static void efi_guest_stq(CPUIA64State *env, uint64_t address, uint64_t value)
{
    cpu_stq_le_data_ra(env, address, value, GETPC());
}

static void efi_guest_stl(CPUIA64State *env, uint64_t address, uint32_t value)
{
    cpu_stl_le_data_ra(env, address, value, GETPC());
}

static void efi_guest_stw(CPUIA64State *env, uint64_t address, uint16_t value)
{
    cpu_stw_le_data_ra(env, address, value, GETPC());
}

static void efi_guest_stb(CPUIA64State *env, uint64_t address, uint8_t value)
{
    cpu_stb_data_ra(env, address, value, GETPC());
}

static uint64_t efi_guest_ldq(CPUIA64State *env, uint64_t address)
{
    return cpu_ldq_le_data_ra(env, address, GETPC());
}

static uint8_t efi_guest_ldb(CPUIA64State *env, uint64_t address)
{
    return cpu_ldub_data_ra(env, address, GETPC());
}

static void efi_guest_read_bytes(CPUIA64State *env, uint64_t address,
                                 void *buffer, size_t size)
{
    uint8_t *bytes = buffer;

    for (size_t i = 0; i < size; i++) {
        bytes[i] = efi_guest_ldb(env, address + i);
    }
}

static void efi_guest_write_bytes(CPUIA64State *env, uint64_t address,
                                  const void *buffer, size_t size)
{
    const uint8_t *bytes = buffer;

    for (size_t i = 0; i < size; i++) {
        efi_guest_stb(env, address + i, bytes[i]);
    }
}

static bool efi_guid_bytes_equal(const uint8_t a[16], const uint8_t b[16])
{
    return memcmp(a, b, 16) == 0;
}

static void efi_guest_read_guid(CPUIA64State *env, uint64_t address,
                                uint8_t guid[16])
{
    efi_guest_read_bytes(env, address, guid, 16);
}

static uint32_t efi_crc32(const uint8_t *data, size_t size)
{
    uint32_t crc = 0xffffffff;

    for (size_t i = 0; i < size; i++) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++) {
            crc = (crc & 1) ? (crc >> 1) ^ 0xedb88320U : crc >> 1;
        }
    }

    return ~crc;
}

static uint64_t efi_pool_alloc_raw(uint64_t size)
{
    uint64_t address = QEMU_ALIGN_UP(efi_pool_next, 16);
    uint64_t next = QEMU_ALIGN_UP(address + MAX(size, UINT64_C(1)), 16);

    if (next < address ||
        next > VIBATNIUM_EFI_POOL_BASE + VIBATNIUM_EFI_POOL_SIZE) {
        return 0;
    }

    efi_pool_next = next;
    return address;
}

static bool efi_page_range_end(uint64_t address, uint64_t pages,
                               uint64_t *end)
{
    uint64_t size;

    if (pages == 0 || address % EFI_PAGE_SIZE != 0 ||
        pages > UINT64_MAX / EFI_PAGE_SIZE) {
        return false;
    }

    size = pages * EFI_PAGE_SIZE;
    if (address > UINT64_MAX - size) {
        return false;
    }

    *end = address + size;
    return true;
}

static bool efi_page_range_in_region(uint64_t address, uint64_t pages,
                                     uint64_t base, uint64_t region_pages)
{
    uint64_t end;
    uint64_t region_end;

    if (!efi_page_range_end(address, pages, &end) ||
        !efi_page_range_end(base, region_pages, &region_end)) {
        return false;
    }

    return address >= base && end <= region_end;
}

static bool efi_page_ranges_overlap(uint64_t a, uint64_t a_pages,
                                    uint64_t b, uint64_t b_pages)
{
    uint64_t a_end;
    uint64_t b_end;

    if (!efi_page_range_end(a, a_pages, &a_end) ||
        !efi_page_range_end(b, b_pages, &b_end)) {
        return true;
    }

    return a < b_end && b < a_end;
}

static bool efi_page_range_usable(uint64_t address, uint64_t pages)
{
    if (efi_page_range_in_region(address, pages,
                                 EFI_PAGE_ALLOC_BASE,
                                 EFI_PAGE_ALLOC_SIZE / EFI_PAGE_SIZE)) {
        return true;
    }
    if (efi_page_range_in_region(address, pages,
                                 EFI_LOW_CONVENTIONAL_BASE,
                                 EFI_LOW_CONVENTIONAL_PAGES)) {
        return true;
    }
    return efi_page_range_in_region(address, pages,
                                    EFI_HIGH_CONVENTIONAL_BASE,
                                    EFI_HIGH_CONVENTIONAL_PAGES);
}

static bool efi_page_range_available(uint64_t address, uint64_t pages)
{
    uint64_t end;

    if (!efi_page_range_end(address, pages, &end) ||
        end > EFI_GUEST_RAM_TOP || !efi_page_range_usable(address, pages)) {
        return false;
    }

    for (unsigned i = 0; i < EFI_MAX_PAGE_ALLOCATIONS; i++) {
        EfiPageAllocation *alloc = &efi_page_allocations[i];

        if (alloc->in_use &&
            efi_page_ranges_overlap(address, pages,
                                    alloc->address, alloc->pages)) {
            return false;
        }
    }

    return true;
}

static bool efi_record_page_allocation(uint64_t address, uint64_t pages,
                                       uint32_t type)
{
    for (unsigned i = 0; i < EFI_MAX_PAGE_ALLOCATIONS; i++) {
        EfiPageAllocation *alloc = &efi_page_allocations[i];

        if (!alloc->in_use) {
            alloc->in_use = true;
            alloc->address = address;
            alloc->pages = pages;
            alloc->type = type;
            efi_memory_map_key++;
            return true;
        }
    }

    return false;
}

static bool efi_find_free_pages(uint64_t pages, uint64_t max_address,
                                uint64_t *address)
{
    static const struct {
        uint64_t base;
        uint64_t pages;
    } regions[] = {
        { EFI_PAGE_ALLOC_BASE, EFI_PAGE_ALLOC_SIZE / EFI_PAGE_SIZE },
        { EFI_HIGH_CONVENTIONAL_BASE, EFI_HIGH_CONVENTIONAL_PAGES },
        { EFI_LOW_CONVENTIONAL_BASE, EFI_LOW_CONVENTIONAL_PAGES },
    };
    uint64_t allocation_end;

    if (!efi_page_range_end(0, pages, &allocation_end)) {
        return false;
    }

    for (unsigned region = 0; region < ARRAY_SIZE(regions); region++) {
        uint64_t region_base = regions[region].base;
        uint64_t region_end = region_base + regions[region].pages * EFI_PAGE_SIZE;
        uint64_t limit_end = region_end;
        uint64_t cursor = region_base;

        if (region == 0) {
            cursor = MAX(QEMU_ALIGN_UP(efi_page_alloc_next, EFI_PAGE_SIZE),
                         region_base);
        }
        if (max_address < region_base) {
            continue;
        }
        if (max_address < region_end - 1) {
            limit_end = max_address + 1;
        }

        while (cursor <= limit_end &&
               allocation_end <= limit_end - cursor) {
            if (efi_page_range_available(cursor, pages)) {
                *address = cursor;
                if (region == 0) {
                    efi_page_alloc_next = cursor + allocation_end;
                }
                return true;
            }
            cursor += EFI_PAGE_SIZE;
        }
    }

    return false;
}

static uint64_t efi_allocate_pages(CPUIA64State *env)
{
    uint64_t allocate_type = ia64_read_gr(env, 32);
    uint64_t memory_type = ia64_read_gr(env, 33);
    uint64_t pages = ia64_read_gr(env, 34);
    uint64_t memory = ia64_read_gr(env, 35);
    uint64_t address;
    uint64_t max_address = EFI_GUEST_RAM_TOP - 1;

    if (memory == 0 || pages == 0) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }

    switch (allocate_type) {
    case EFI_ALLOCATE_ANY_PAGES:
        if (!efi_find_free_pages(pages, max_address, &address)) {
            return VIBATNIUM_EFI_OUT_OF_RESOURCES;
        }
        break;
    case EFI_ALLOCATE_MAX_ADDRESS:
        max_address = efi_guest_ldq(env, memory);
        if (!efi_find_free_pages(pages, max_address, &address)) {
            efi_guest_stq(env, memory, 0);
            return VIBATNIUM_EFI_OUT_OF_RESOURCES;
        }
        break;
    case EFI_ALLOCATE_ADDRESS:
        address = efi_guest_ldq(env, memory);
        if (!efi_page_range_available(address, pages)) {
            return VIBATNIUM_EFI_NOT_FOUND;
        }
        break;
    default:
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }

    if (!efi_record_page_allocation(address, pages, memory_type)) {
        return VIBATNIUM_EFI_OUT_OF_RESOURCES;
    }
    efi_guest_stq(env, memory, address);
    return VIBATNIUM_EFI_SUCCESS;
}

static uint64_t efi_free_pages(CPUIA64State *env)
{
    uint64_t address = ia64_read_gr(env, 32);
    uint64_t pages = ia64_read_gr(env, 33);

    for (unsigned i = 0; i < EFI_MAX_PAGE_ALLOCATIONS; i++) {
        EfiPageAllocation *alloc = &efi_page_allocations[i];

        if (alloc->in_use && alloc->address == address &&
            alloc->pages == pages) {
            memset(alloc, 0, sizeof(*alloc));
            efi_memory_map_key++;
            return VIBATNIUM_EFI_SUCCESS;
        }
    }

    return VIBATNIUM_EFI_INVALID_PARAMETER;
}

static unsigned efi_emit_memory_descriptor(CPUIA64State *env, uint64_t map,
                                           unsigned index,
                                           const EfiMemoryRange *range)
{
    uint64_t descriptor;

    if (range->pages == 0) {
        return index;
    }

    if (map != 0) {
        descriptor = map + index * EFI_MEMORY_DESCRIPTOR_SIZE;
        efi_guest_stl(env, descriptor, range->type);
        efi_guest_stl(env, descriptor + 4, 0);
        efi_guest_stq(env, descriptor + 8, range->address);
        efi_guest_stq(env, descriptor + 16, 0);
        efi_guest_stq(env, descriptor + 24, range->pages);
        efi_guest_stq(env, descriptor + 32, range->attributes);
    }

    return index + 1;
}

static const EfiPageAllocation *efi_next_allocation_in_range(uint64_t cursor,
                                                            uint64_t end)
{
    const EfiPageAllocation *best = NULL;

    for (unsigned i = 0; i < EFI_MAX_PAGE_ALLOCATIONS; i++) {
        EfiPageAllocation *alloc = &efi_page_allocations[i];
        uint64_t alloc_end;

        if (!alloc->in_use ||
            !efi_page_range_end(alloc->address, alloc->pages, &alloc_end) ||
            alloc_end <= cursor || alloc->address >= end) {
            continue;
        }
        if (!best || alloc->address < best->address) {
            best = alloc;
        }
    }

    return best;
}

static unsigned efi_emit_split_conventional(CPUIA64State *env, uint64_t map,
                                            unsigned index, uint64_t base,
                                            uint64_t pages)
{
    uint64_t cursor = base;
    uint64_t end = base + pages * EFI_PAGE_SIZE;

    while (cursor < end) {
        const EfiPageAllocation *alloc =
            efi_next_allocation_in_range(cursor, end);
        uint64_t alloc_end;

        if (!alloc) {
            EfiMemoryRange conventional = {
                .type = EFI_CONVENTIONAL_MEMORY,
                .address = cursor,
                .pages = (end - cursor) / EFI_PAGE_SIZE,
                .attributes = EFI_MEMORY_WB,
            };
            return efi_emit_memory_descriptor(env, map, index,
                                              &conventional);
        }

        if (alloc->address > cursor) {
            EfiMemoryRange conventional = {
                .type = EFI_CONVENTIONAL_MEMORY,
                .address = cursor,
                .pages = (alloc->address - cursor) / EFI_PAGE_SIZE,
                .attributes = EFI_MEMORY_WB,
            };
            index = efi_emit_memory_descriptor(env, map, index,
                                               &conventional);
        }

        if (!efi_page_range_end(alloc->address, alloc->pages, &alloc_end)) {
            break;
        }
        if (alloc_end > end) {
            alloc_end = end;
        }
        if (alloc_end > cursor) {
            EfiMemoryRange allocation = {
                .type = alloc->type,
                .address = MAX(alloc->address, cursor),
                .pages = (alloc_end - MAX(alloc->address, cursor)) /
                         EFI_PAGE_SIZE,
                .attributes = EFI_MEMORY_WB,
            };
            index = efi_emit_memory_descriptor(env, map, index, &allocation);
            cursor = alloc_end;
        } else {
            cursor += EFI_PAGE_SIZE;
        }
    }

    return index;
}

static unsigned efi_emit_memory_map(CPUIA64State *env, uint64_t map)
{
    unsigned index = 0;
    const EfiMemoryRange zero_page_firmware = {
        .type = EFI_BOOT_SERVICES_DATA,
        .address = 0,
        .pages = 0x100,
        .attributes = EFI_MEMORY_WB,
    };
    const EfiMemoryRange loader_image = {
        .type = EFI_LOADER_CODE,
        .address = VIBATNIUM_EFI_APP_BASE,
        .pages = 0xf00,
        .attributes = EFI_MEMORY_WB,
    };
    const EfiMemoryRange firmware_work = {
        .type = EFI_BOOT_SERVICES_DATA,
        .address = VIBATNIUM_EFI_STACK_BASE,
        .pages = 0x100,
        .attributes = EFI_MEMORY_WB,
    };
    const EfiMemoryRange pool = {
        .type = EFI_BOOT_SERVICES_DATA,
        .address = VIBATNIUM_EFI_POOL_BASE,
        .pages = VIBATNIUM_EFI_POOL_SIZE / EFI_PAGE_SIZE,
        .attributes = EFI_MEMORY_WB,
    };
    const EfiMemoryRange page_arena = {
        .type = EFI_BOOT_SERVICES_DATA,
        .address = EFI_PAGE_ALLOC_BASE,
        .pages = EFI_PAGE_ALLOC_SIZE / EFI_PAGE_SIZE,
        .attributes = EFI_MEMORY_WB,
    };

    index = efi_emit_memory_descriptor(env, map, index, &zero_page_firmware);
    index = efi_emit_split_conventional(env, map, index,
                                        EFI_LOW_CONVENTIONAL_BASE,
                                        EFI_LOW_CONVENTIONAL_PAGES);
    index = efi_emit_memory_descriptor(env, map, index, &loader_image);
    index = efi_emit_memory_descriptor(env, map, index, &firmware_work);
    index = efi_emit_memory_descriptor(env, map, index, &pool);
    index = efi_emit_memory_descriptor(env, map, index, &page_arena);
    index = efi_emit_split_conventional(env, map, index,
                                        EFI_HIGH_CONVENTIONAL_BASE,
                                        EFI_HIGH_CONVENTIONAL_PAGES);
    return index;
}

static uint64_t efi_get_memory_map(CPUIA64State *env)
{
    uint64_t memory_map_size = ia64_read_gr(env, 32);
    uint64_t memory_map = ia64_read_gr(env, 33);
    uint64_t map_key = ia64_read_gr(env, 34);
    uint64_t descriptor_size = ia64_read_gr(env, 35);
    uint64_t descriptor_version = ia64_read_gr(env, 36);
    uint64_t provided;
    uint64_t required = (uint64_t)efi_emit_memory_map(env, 0) *
                        EFI_MEMORY_DESCRIPTOR_SIZE;

    if (memory_map_size == 0 || map_key == 0 || descriptor_size == 0 ||
        descriptor_version == 0) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }

    provided = efi_guest_ldq(env, memory_map_size);
    efi_guest_stq(env, memory_map_size, required);
    efi_guest_stq(env, descriptor_size, EFI_MEMORY_DESCRIPTOR_SIZE);
    efi_guest_stl(env, descriptor_version, EFI_MEMORY_DESCRIPTOR_VERSION);

    if (memory_map == 0 || provided < required) {
        return VIBATNIUM_EFI_BUFFER_TOO_SMALL;
    }

    efi_emit_memory_map(env, memory_map);
    efi_guest_stq(env, map_key, efi_memory_map_key);
    return VIBATNIUM_EFI_SUCCESS;
}

static uint64_t efi_exit_boot_services(CPUIA64State *env)
{
    uint64_t image_handle = ia64_read_gr(env, 32);
    uint64_t map_key = ia64_read_gr(env, 33);

    if (image_handle != VIBATNIUM_EFI_IMAGE_HANDLE ||
        map_key != efi_memory_map_key) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }

    return VIBATNIUM_EFI_SUCCESS;
}

void vibatnium_efi_register_boot_media(
    const VibatniumEfiBlockDevice *boot_media)
{
    for (unsigned i = 0; i < EFI_MAX_FILE_HANDLES; i++) {
        g_clear_pointer(&efi_guest_files[i].data, g_free);
        memset(&efi_guest_files[i], 0, sizeof(efi_guest_files[i]));
    }
    memset(efi_installed_protocols, 0, sizeof(efi_installed_protocols));
    memset(efi_guest_events, 0, sizeof(efi_guest_events));
    memset(efi_page_allocations, 0, sizeof(efi_page_allocations));
    efi_pool_next = VIBATNIUM_EFI_POOL_BASE;
    efi_page_alloc_next = EFI_PAGE_ALLOC_BASE;
    efi_memory_map_key = 1;
    efi_dynamic_handle_next = UINT64_C(0x00073000);
    efi_next_event_handle = VIBATNIUM_EFI_CON_IN_WAIT_EVENT + 1;
    efi_conin_enter_pending = true;

    g_clear_pointer(&efi_boot_media_name, g_free);
    memset(&efi_boot_media, 0, sizeof(efi_boot_media));
    efi_boot_media_valid = false;

    if (!boot_media) {
        return;
    }

    efi_boot_media = *boot_media;
    efi_boot_media_name = g_strdup(boot_media->name);
    efi_boot_media.name = efi_boot_media_name;
    efi_boot_media_valid = boot_media->read != NULL;
}

static uint64_t efi_preinstalled_interface(uint64_t handle,
                                           const uint8_t guid[16])
{
    if (handle == VIBATNIUM_EFI_IMAGE_HANDLE &&
        efi_guid_bytes_equal(guid, efi_loaded_image_guid)) {
        return VIBATNIUM_EFI_LOADED_IMAGE;
    }

    if (handle != VIBATNIUM_EFI_BOOT_DEVICE_HANDLE) {
        return 0;
    }

    if (efi_guid_bytes_equal(guid, efi_simple_text_output_guid)) {
        return VIBATNIUM_EFI_CON_OUT;
    }
    if (efi_guid_bytes_equal(guid, efi_simple_text_input_guid)) {
        return VIBATNIUM_EFI_CON_IN;
    }
    if (efi_guid_bytes_equal(guid, efi_device_path_guid)) {
        return VIBATNIUM_EFI_DEVICE_PATH;
    }
    if (efi_boot_media_valid && efi_guid_bytes_equal(guid, efi_block_io_guid)) {
        return VIBATNIUM_EFI_BLOCK_IO;
    }
    if (efi_boot_media_valid &&
        efi_guid_bytes_equal(guid, efi_simple_file_system_guid)) {
        return VIBATNIUM_EFI_SIMPLE_FILE_SYSTEM;
    }

    return 0;
}

static EfiInstalledProtocol *efi_find_installed_protocol(uint64_t handle,
                                                         const uint8_t guid[16])
{
    for (unsigned i = 0; i < EFI_MAX_INSTALLED_PROTOCOLS; i++) {
        if (efi_installed_protocols[i].in_use &&
            efi_installed_protocols[i].handle == handle &&
            efi_guid_bytes_equal(efi_installed_protocols[i].guid, guid)) {
            return &efi_installed_protocols[i];
        }
    }
    return NULL;
}

static uint64_t efi_resolve_interface(uint64_t handle, const uint8_t guid[16],
                                      uint64_t *interface)
{
    EfiInstalledProtocol *installed;
    uint64_t preinstalled = efi_preinstalled_interface(handle, guid);

    if (preinstalled != 0) {
        *interface = preinstalled;
        return VIBATNIUM_EFI_SUCCESS;
    }

    installed = efi_find_installed_protocol(handle, guid);
    if (installed) {
        *interface = installed->interface;
        return VIBATNIUM_EFI_SUCCESS;
    }

    *interface = 0;
    return VIBATNIUM_EFI_NOT_FOUND;
}

static uint64_t efi_handle_protocol(CPUIA64State *env)
{
    uint64_t handle = ia64_read_gr(env, 32);
    uint64_t protocol = ia64_read_gr(env, 33);
    uint64_t interface = ia64_read_gr(env, 34);
    uint8_t guid[16];
    uint64_t interface_address;
    uint64_t status;

    if (protocol == 0 || interface == 0) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }

    efi_guest_read_guid(env, protocol, guid);
    status = efi_resolve_interface(handle, guid, &interface_address);
    if (status == VIBATNIUM_EFI_SUCCESS) {
        efi_guest_stq(env, interface, interface_address);
        return status;
    }

    efi_guest_stq(env, interface, 0);
    return status;
}

static bool efi_add_unique_handle(uint64_t *handles, unsigned capacity,
                                  unsigned *count, uint64_t handle)
{
    for (unsigned i = 0; i < *count; i++) {
        if (handles[i] == handle) {
            return true;
        }
    }

    if (*count < capacity) {
        handles[*count] = handle;
    }
    (*count)++;
    return *count <= capacity;
}

static unsigned efi_locate_handles_for_protocol(CPUIA64State *env,
                                                uint64_t protocol,
                                                uint64_t *handles,
                                                unsigned capacity)
{
    uint8_t guid[16];
    unsigned count = 0;

    efi_guest_read_guid(env, protocol, guid);

    if (efi_guid_bytes_equal(guid, efi_loaded_image_guid)) {
        efi_add_unique_handle(handles, capacity, &count,
                              VIBATNIUM_EFI_IMAGE_HANDLE);
    }

    if (efi_guid_bytes_equal(guid, efi_simple_text_output_guid) ||
        efi_guid_bytes_equal(guid, efi_simple_text_input_guid) ||
        efi_guid_bytes_equal(guid, efi_device_path_guid) ||
        (efi_boot_media_valid &&
         (efi_guid_bytes_equal(guid, efi_block_io_guid) ||
          efi_guid_bytes_equal(guid, efi_simple_file_system_guid)))) {
        efi_add_unique_handle(handles, capacity, &count,
                              VIBATNIUM_EFI_BOOT_DEVICE_HANDLE);
    }

    for (unsigned i = 0; i < EFI_MAX_INSTALLED_PROTOCOLS; i++) {
        if (efi_installed_protocols[i].in_use &&
            efi_guid_bytes_equal(efi_installed_protocols[i].guid, guid)) {
            efi_add_unique_handle(handles, capacity, &count,
                                  efi_installed_protocols[i].handle);
        }
    }

    return count;
}

static uint64_t efi_locate_handle(CPUIA64State *env)
{
    uint64_t search_type = ia64_read_gr(env, 32);
    uint64_t protocol = ia64_read_gr(env, 33);
    uint64_t size_ptr = ia64_read_gr(env, 35);
    uint64_t buffer = ia64_read_gr(env, 36);
    uint64_t handles[4];
    unsigned count;
    uint64_t required;
    uint64_t provided;

    if (search_type != 2 || protocol == 0 || size_ptr == 0) {
        return VIBATNIUM_EFI_UNSUPPORTED;
    }

    count = efi_locate_handles_for_protocol(env, protocol, handles,
                                            ARRAY_SIZE(handles));
    required = count * sizeof(uint64_t);
    provided = efi_guest_ldq(env, size_ptr);
    efi_guest_stq(env, size_ptr, required);
    if (count == 0) {
        return VIBATNIUM_EFI_NOT_FOUND;
    }

    if (buffer == 0 || provided < required) {
        return VIBATNIUM_EFI_BUFFER_TOO_SMALL;
    }

    for (unsigned i = 0; i < count; i++) {
        efi_guest_stq(env, buffer + i * sizeof(uint64_t), handles[i]);
    }
    return VIBATNIUM_EFI_SUCCESS;
}

static uint64_t efi_install_protocol_interface(CPUIA64State *env)
{
    uint64_t handle_ptr = ia64_read_gr(env, 32);
    uint64_t protocol = ia64_read_gr(env, 33);
    uint64_t interface_type = ia64_read_gr(env, 34);
    uint64_t interface = ia64_read_gr(env, 35);
    uint64_t handle;
    uint8_t guid[16];

    if (handle_ptr == 0 || protocol == 0 || interface == 0) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }

    handle = efi_guest_ldq(env, handle_ptr);
    if (handle == 0) {
        handle = efi_dynamic_handle_next++;
        efi_guest_stq(env, handle_ptr, handle);
    }
    efi_guest_read_guid(env, protocol, guid);
    if (efi_preinstalled_interface(handle, guid) != 0 ||
        efi_find_installed_protocol(handle, guid) != NULL) {
        return VIBATNIUM_EFI_ACCESS_DENIED;
    }

    for (unsigned i = 0; i < EFI_MAX_INSTALLED_PROTOCOLS; i++) {
        if (!efi_installed_protocols[i].in_use) {
            efi_installed_protocols[i].in_use = true;
            efi_installed_protocols[i].handle = handle;
            memcpy(efi_installed_protocols[i].guid, guid, sizeof(guid));
            efi_installed_protocols[i].interface = interface;
            (void)interface_type;
            return VIBATNIUM_EFI_SUCCESS;
        }
    }

    return VIBATNIUM_EFI_OUT_OF_RESOURCES;
}

static uint64_t efi_uninstall_protocol_interface(CPUIA64State *env)
{
    uint64_t handle = ia64_read_gr(env, 32);
    uint64_t protocol = ia64_read_gr(env, 33);
    uint64_t interface = ia64_read_gr(env, 34);
    uint8_t guid[16];
    EfiInstalledProtocol *installed;

    if (handle == 0 || protocol == 0) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }

    efi_guest_read_guid(env, protocol, guid);
    installed = efi_find_installed_protocol(handle, guid);
    if (!installed || (interface != 0 && installed->interface != interface)) {
        return VIBATNIUM_EFI_NOT_FOUND;
    }

    memset(installed, 0, sizeof(*installed));
    return VIBATNIUM_EFI_SUCCESS;
}

static uint64_t efi_locate_protocol(CPUIA64State *env)
{
    uint64_t protocol = ia64_read_gr(env, 32);
    uint64_t interface = ia64_read_gr(env, 34);
    uint64_t handles[8];
    unsigned count;

    if (protocol == 0 || interface == 0) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }

    count = efi_locate_handles_for_protocol(env, protocol, handles,
                                            ARRAY_SIZE(handles));
    if (count == 0) {
        efi_guest_stq(env, interface, 0);
        return VIBATNIUM_EFI_NOT_FOUND;
    }

    ia64_write_gr(env, 32, handles[0]);
    ia64_write_gr(env, 33, protocol);
    ia64_write_gr(env, 34, interface);
    return efi_handle_protocol(env);
}

static uint64_t efi_close_protocol(CPUIA64State *env)
{
    uint64_t handle = ia64_read_gr(env, 32);
    uint64_t protocol = ia64_read_gr(env, 33);
    uint8_t guid[16];
    uint64_t interface_address;

    if (handle == 0 || protocol == 0) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }

    efi_guest_read_guid(env, protocol, guid);
    return efi_resolve_interface(handle, guid, &interface_address);
}

static uint64_t efi_calculate_crc32(CPUIA64State *env)
{
    uint64_t data = ia64_read_gr(env, 32);
    uint64_t size = ia64_read_gr(env, 33);
    uint64_t crc_ptr = ia64_read_gr(env, 34);
    g_autofree uint8_t *bytes = NULL;

    if (data == 0 || crc_ptr == 0 || size > EFI_MAX_FILE_READ_BYTES) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }

    bytes = g_malloc(size ? size : 1);
    efi_guest_read_bytes(env, data, bytes, size);
    efi_guest_stl(env, crc_ptr, efi_crc32(bytes, size));
    return VIBATNIUM_EFI_SUCCESS;
}

static uint64_t efi_copy_mem(CPUIA64State *env)
{
    uint64_t destination = ia64_read_gr(env, 32);
    uint64_t source = ia64_read_gr(env, 33);
    uint64_t length = ia64_read_gr(env, 34);
    g_autofree uint8_t *bytes = NULL;

    if (length > EFI_MAX_FILE_READ_BYTES) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }

    bytes = g_malloc(length ? length : 1);
    efi_guest_read_bytes(env, source, bytes, length);
    efi_guest_write_bytes(env, destination, bytes, length);
    return VIBATNIUM_EFI_SUCCESS;
}

static uint64_t efi_set_mem(CPUIA64State *env)
{
    uint64_t buffer = ia64_read_gr(env, 32);
    uint64_t size = ia64_read_gr(env, 33);
    uint8_t value = ia64_read_gr(env, 34);

    if (size > EFI_MAX_FILE_READ_BYTES) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }

    for (uint64_t i = 0; i < size; i++) {
        efi_guest_stb(env, buffer + i, value);
    }
    return VIBATNIUM_EFI_SUCCESS;
}

static uint64_t efi_allocate_pool(CPUIA64State *env)
{
    uint64_t size = ia64_read_gr(env, 33);
    uint64_t buffer = ia64_read_gr(env, 34);
    uint64_t address;

    if (buffer == 0) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }

    address = efi_pool_alloc_raw(size);
    if (address == 0) {
        efi_guest_stq(env, buffer, 0);
        return VIBATNIUM_EFI_OUT_OF_RESOURCES;
    }

    efi_guest_stq(env, buffer, address);
    return VIBATNIUM_EFI_SUCCESS;
}

static void efi_write_file_protocol(CPUIA64State *env, uint64_t address)
{
    efi_guest_stq(env, address, VIBATNIUM_EFI_PROTOCOL_REVISION);
    for (unsigned i = 0; i < VIBATNIUM_EFI_FILE_SERVICE_COUNT; i++) {
        efi_guest_stq(env, address + 8 + i * sizeof(uint64_t),
                      VIBATNIUM_EFI_DESCRIPTOR_BASE +
                      (EFI_FILE_SERVICE_BASE + i) * IA64_BUNDLE_SIZE);
    }
}

static EfiGuestFile *efi_find_file(uint64_t address)
{
    for (unsigned i = 0; i < EFI_MAX_FILE_HANDLES; i++) {
        if (efi_guest_files[i].in_use && efi_guest_files[i].address == address) {
            return &efi_guest_files[i];
        }
    }
    return NULL;
}

static EfiGuestFile *efi_create_file_node(CPUIA64State *env, const char *path,
                                          bool is_directory, uint8_t *data,
                                          size_t size)
{
    uint64_t address = efi_pool_alloc_raw(8 + 10 * sizeof(uint64_t));

    if (address == 0) {
        g_free(data);
        return NULL;
    }

    for (unsigned i = 0; i < EFI_MAX_FILE_HANDLES; i++) {
        EfiGuestFile *file = &efi_guest_files[i];

        if (file->in_use) {
            continue;
        }

        memset(file, 0, sizeof(*file));
        file->in_use = true;
        file->address = address;
        file->is_directory = is_directory;
        g_strlcpy(file->path, path ? path : "", sizeof(file->path));
        file->data = data;
        file->size = size;
        efi_write_file_protocol(env, address);
        return file;
    }

    g_free(data);
    return NULL;
}

static uint64_t efi_storage_status_to_efi(VibatniumEfiStorageStatus status)
{
    switch (status) {
    case VIBATNIUM_EFI_STORAGE_OK:
        return VIBATNIUM_EFI_SUCCESS;
    case VIBATNIUM_EFI_STORAGE_READ_ERROR:
    case VIBATNIUM_EFI_STORAGE_INVALID_FILESYSTEM:
        return VIBATNIUM_EFI_DEVICE_ERROR;
    case VIBATNIUM_EFI_STORAGE_UNSUPPORTED:
        return VIBATNIUM_EFI_UNSUPPORTED;
    case VIBATNIUM_EFI_STORAGE_NO_ISO9660:
    case VIBATNIUM_EFI_STORAGE_NOT_FOUND:
    default:
        return VIBATNIUM_EFI_NOT_FOUND;
    }
}

static void efi_read_utf16_path(CPUIA64State *env, uint64_t address,
                                char *out, size_t out_size)
{
    size_t n = 0;

    if (out_size == 0) {
        return;
    }

    for (unsigned i = 0; i < EFI_MAX_PATH_CHARS - 1 && n + 1 < out_size; i++) {
        uint16_t ch = cpu_lduw_le_data_ra(env, address + i * 2, GETPC());

        if (ch == 0) {
            break;
        }
        if (ch == '\\') {
            out[n++] = '/';
        } else if (ch < 0x80) {
            out[n++] = ch;
        } else {
            out[n++] = '?';
        }
    }
    out[n] = '\0';
}

static void efi_join_normalized_path(const char *base, const char *name,
                                     char *out, size_t out_size)
{
    char combined[EFI_MAX_PATH_CHARS * 2];
    char **parts;
    size_t out_len = 0;

    if (out_size == 0) {
        return;
    }
    out[0] = '\0';

    if (!name || name[0] == '\0') {
        g_strlcpy(combined, base ? base : "", sizeof(combined));
    } else if (name[0] == '/') {
        g_strlcpy(combined, name, sizeof(combined));
    } else if (base && base[0] != '\0') {
        g_snprintf(combined, sizeof(combined), "%s/%s", base, name);
    } else {
        g_strlcpy(combined, name, sizeof(combined));
    }

    parts = g_strsplit(combined, "/", -1);
    for (char **part = parts; *part; part++) {
        if ((*part)[0] == '\0' || g_strcmp0(*part, ".") == 0) {
            continue;
        }
        if (g_strcmp0(*part, "..") == 0) {
            char *slash = strrchr(out, '/');

            if (slash) {
                *slash = '\0';
                out_len = strlen(out);
            } else {
                out[0] = '\0';
                out_len = 0;
            }
            continue;
        }
        if (out_len != 0 && out_len + 1 < out_size) {
            out[out_len++] = '/';
            out[out_len] = '\0';
        }
        g_strlcpy(out + out_len, *part, out_size - out_len);
        out_len = strlen(out);
    }
    g_strfreev(parts);
}

static const char *efi_file_base_name(const char *path)
{
    const char *slash;

    if (!path || path[0] == '\0') {
        return "\\";
    }

    slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static void efi_write_utf16_ascii(CPUIA64State *env, uint64_t address,
                                  const char *text)
{
    while (*text) {
        efi_guest_stw(env, address, (uint8_t)*text++);
        address += 2;
    }
    efi_guest_stw(env, address, 0);
}

static uint64_t efi_simplefs_open_volume(CPUIA64State *env)
{
    uint64_t this_ptr = ia64_read_gr(env, 32);
    uint64_t root_out = ia64_read_gr(env, 33);
    EfiGuestFile *root;

    if (this_ptr != VIBATNIUM_EFI_SIMPLE_FILE_SYSTEM || root_out == 0 ||
        !efi_boot_media_valid) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }

    root = efi_create_file_node(env, "", true, NULL, 0);
    if (!root) {
        return VIBATNIUM_EFI_OUT_OF_RESOURCES;
    }

    efi_guest_stq(env, root_out, root->address);
    return VIBATNIUM_EFI_SUCCESS;
}

static uint64_t efi_file_open(CPUIA64State *env)
{
    uint64_t this_ptr = ia64_read_gr(env, 32);
    uint64_t new_handle_out = ia64_read_gr(env, 33);
    uint64_t name_ptr = ia64_read_gr(env, 34);
    uint64_t open_mode = ia64_read_gr(env, 35);
    EfiGuestFile *parent = efi_find_file(this_ptr);
    char name[EFI_MAX_PATH_CHARS];
    char path[EFI_MAX_PATH_CHARS];
    char storage_path[EFI_MAX_PATH_CHARS + 2];
    Error *local_err = NULL;
    VibatniumEfiStorageReport report = {
        .status = VIBATNIUM_EFI_STORAGE_NOT_FOUND,
        .message = "path has not been opened",
    };
    VibatniumEfiFile storage_file;
    g_autofree char *source = g_malloc0(384);
    uint8_t *data = NULL;
    size_t size = 0;
    EfiGuestFile *file;

    if (!parent || new_handle_out == 0 || name_ptr == 0) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }
    if ((open_mode & UINT64_C(0x2)) != 0) {
        return VIBATNIUM_EFI_WRITE_PROTECTED;
    }

    efi_read_utf16_path(env, name_ptr, name, sizeof(name));
    efi_join_normalized_path(parent->path, name, path, sizeof(path));
    g_snprintf(storage_path, sizeof(storage_path), "/%s", path);

    efi_guest_stq(env, new_handle_out, 0);
    if (efi_trace_enabled()) {
        fprintf(stderr,
                "[efi-file] open request this=0x%016" PRIx64
                " out=0x%016" PRIx64 " name='%s' mode=0x%" PRIx64
                " parent='%s' path='%s'\n",
                this_ptr, new_handle_out, name, open_mode, parent->path,
                storage_path);
    }

    if (!efi_boot_media_valid) {
        return VIBATNIUM_EFI_NOT_FOUND;
    }

    if (vibatnium_efi_iso9660_find_path(&efi_boot_media, storage_path,
                                        &storage_file, &report,
                                        &local_err)) {
        if (storage_file.is_directory) {
            file = efi_create_file_node(env, path, true, NULL, 0);
            if (!file) {
                return VIBATNIUM_EFI_OUT_OF_RESOURCES;
            }

            efi_guest_stq(env, new_handle_out, file->address);
            if (efi_trace_enabled()) {
                fprintf(stderr, "[efi-file] open dir='%s' handle=0x%016"
                        PRIx64 "\n",
                        path, file->address);
            }
            return VIBATNIUM_EFI_SUCCESS;
        }

        if (vibatnium_efi_iso9660_read_file(&efi_boot_media, &storage_file,
                                            &data, &size, &report,
                                            &local_err)) {
            g_snprintf(source, 384, "%s:%s",
                       efi_boot_media.name ? efi_boot_media.name : "<unnamed>",
                       storage_path);
        }
    }
    error_free(local_err);
    local_err = NULL;

    if (!data &&
        !vibatnium_efi_cdrom_read_path(&efi_boot_media, storage_path, &data,
                                       &size, source, 384, &report,
                                       &local_err)) {
        uint64_t status = efi_storage_status_to_efi(report.status);

        if (efi_trace_enabled()) {
            fprintf(stderr, "[efi-file] open path='%s' status=%s\n",
                    storage_path,
                    vibatnium_efi_storage_status_name(report.status));
        }
        error_free(local_err);
        return status;
    }

    if (efi_trace_enabled()) {
        fprintf(stderr, "[efi-file] open path='%s' size=0x%" PRIx64
                " source=%s\n",
                storage_path, (uint64_t)size, source);
    }

    file = efi_create_file_node(env, path, false, data, size);
    if (!file) {
        efi_guest_stq(env, new_handle_out, 0);
        return VIBATNIUM_EFI_OUT_OF_RESOURCES;
    }

    efi_guest_stq(env, new_handle_out, file->address);
    return VIBATNIUM_EFI_SUCCESS;
}

static uint64_t efi_file_close(CPUIA64State *env)
{
    EfiGuestFile *file = efi_find_file(ia64_read_gr(env, 32));

    if (file) {
        g_clear_pointer(&file->data, g_free);
        memset(file, 0, sizeof(*file));
    }
    return VIBATNIUM_EFI_SUCCESS;
}

static uint64_t efi_file_read(CPUIA64State *env)
{
    EfiGuestFile *file = efi_find_file(ia64_read_gr(env, 32));
    uint64_t size_ptr = ia64_read_gr(env, 33);
    uint64_t buffer = ia64_read_gr(env, 34);
    uint64_t requested;
    uint64_t remaining;
    uint64_t actual;

    if (!file || size_ptr == 0) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }
    if (file->is_directory) {
        return VIBATNIUM_EFI_UNSUPPORTED;
    }

    requested = efi_guest_ldq(env, size_ptr);
    if (requested > EFI_MAX_FILE_READ_BYTES) {
        requested = EFI_MAX_FILE_READ_BYTES;
    }
    remaining = file->position < file->size ? file->size - file->position : 0;
    actual = MIN(requested, remaining);
    if (actual > 0) {
        if (buffer == 0) {
            return VIBATNIUM_EFI_INVALID_PARAMETER;
        }
        efi_guest_write_bytes(env, buffer, file->data + file->position,
                              actual);
        file->position += actual;
    }
    if (efi_trace_enabled()) {
        fprintf(stderr, "[efi-file] read path='%s' requested=0x%" PRIx64
                " actual=0x%" PRIx64 " position=0x%" PRIx64 "\n",
                file->path, requested, actual, file->position);
    }
    efi_guest_stq(env, size_ptr, actual);
    return VIBATNIUM_EFI_SUCCESS;
}

static uint64_t efi_file_get_position(CPUIA64State *env)
{
    EfiGuestFile *file = efi_find_file(ia64_read_gr(env, 32));
    uint64_t pos_out = ia64_read_gr(env, 33);

    if (!file || pos_out == 0) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }
    if (file->is_directory) {
        return VIBATNIUM_EFI_UNSUPPORTED;
    }
    efi_guest_stq(env, pos_out, file->position);
    return VIBATNIUM_EFI_SUCCESS;
}

static uint64_t efi_file_set_position(CPUIA64State *env)
{
    EfiGuestFile *file = efi_find_file(ia64_read_gr(env, 32));
    uint64_t position = ia64_read_gr(env, 33);

    if (!file) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }
    if (file->is_directory) {
        return position == 0 ? VIBATNIUM_EFI_SUCCESS
                             : VIBATNIUM_EFI_UNSUPPORTED;
    }
    if (position == UINT64_MAX) {
        position = file->size;
    }
    if (position > file->size) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }
    file->position = position;
    return VIBATNIUM_EFI_SUCCESS;
}

static uint64_t efi_file_get_info(CPUIA64State *env)
{
    EfiGuestFile *file = efi_find_file(ia64_read_gr(env, 32));
    uint64_t info_type = ia64_read_gr(env, 33);
    uint64_t size_ptr = ia64_read_gr(env, 34);
    uint64_t buffer = ia64_read_gr(env, 35);
    uint8_t guid[16];
    const char *name;
    uint64_t name_bytes;
    uint64_t required;
    uint64_t provided;

    if (!file || info_type == 0 || size_ptr == 0) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }

    efi_guest_read_guid(env, info_type, guid);
    if (!efi_guid_bytes_equal(guid, efi_file_info_guid)) {
        return VIBATNIUM_EFI_UNSUPPORTED;
    }

    name = efi_file_base_name(file->path);
    name_bytes = (strlen(name) + 1) * 2;
    required = 80 + name_bytes;
    provided = efi_guest_ldq(env, size_ptr);
    efi_guest_stq(env, size_ptr, required);
    if (buffer == 0 || provided < required) {
        return VIBATNIUM_EFI_BUFFER_TOO_SMALL;
    }

    for (uint64_t i = 0; i < required; i++) {
        efi_guest_stb(env, buffer + i, 0);
    }
    efi_guest_stq(env, buffer, required);
    efi_guest_stq(env, buffer + 8, file->size);
    efi_guest_stq(env, buffer + 16, file->size);
    efi_guest_stq(env, buffer + 72, file->is_directory ? 0x10 : 0x1);
    efi_write_utf16_ascii(env, buffer + 80, name);
    return VIBATNIUM_EFI_SUCCESS;
}

static uint64_t efi_dispatch_file(CPUIA64State *env, unsigned index)
{
    switch (index) {
    case 0:
        return efi_file_open(env);
    case 1:
        return efi_file_close(env);
    case 2:
        efi_file_close(env);
        return VIBATNIUM_EFI_WRITE_PROTECTED;
    case 3:
        return efi_file_read(env);
    case 4:
        return VIBATNIUM_EFI_WRITE_PROTECTED;
    case 5:
        return efi_file_get_position(env);
    case 6:
        return efi_file_set_position(env);
    case 7:
        return efi_file_get_info(env);
    case 8:
        return VIBATNIUM_EFI_WRITE_PROTECTED;
    case 9:
        return VIBATNIUM_EFI_SUCCESS;
    default:
        return VIBATNIUM_EFI_UNSUPPORTED;
    }
}

static uint64_t efi_dispatch_simple_file_system(CPUIA64State *env,
                                                unsigned index)
{
    switch (index) {
    case 0:
        return efi_simplefs_open_volume(env);
    default:
        return VIBATNIUM_EFI_UNSUPPORTED;
    }
}

static uint64_t efi_dispatch_block_io(CPUIA64State *env, unsigned index)
{
    uint64_t this_ptr = ia64_read_gr(env, 32);
    uint32_t block_size = efi_boot_media.block_size
        ? efi_boot_media.block_size
        : 2048;

    if (this_ptr != VIBATNIUM_EFI_BLOCK_IO || !efi_boot_media_valid) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }

    switch (index) {
    case 0:
        return VIBATNIUM_EFI_SUCCESS;
    case 1: {
        uint64_t media_id = ia64_read_gr(env, 33);
        uint64_t lba = ia64_read_gr(env, 34);
        uint64_t buffer_size = ia64_read_gr(env, 35);
        uint64_t buffer = ia64_read_gr(env, 36);
        uint64_t offset = lba * block_size;
        Error *local_err = NULL;
        g_autofree uint8_t *data = NULL;
        int ret;

        if (media_id != 1 || buffer_size > EFI_MAX_FILE_READ_BYTES ||
            (buffer_size != 0 && buffer == 0) ||
            (block_size != 0 && (buffer_size % block_size) != 0) ||
            (lba != 0 && offset / lba != block_size)) {
            return VIBATNIUM_EFI_INVALID_PARAMETER;
        }
        data = g_malloc(buffer_size ? buffer_size : 1);
        ret = efi_boot_media.read(efi_boot_media.opaque, offset, buffer_size,
                                  data, &local_err);
        if (ret < 0) {
            error_free(local_err);
            return VIBATNIUM_EFI_DEVICE_ERROR;
        }
        if (buffer_size != 0) {
            efi_guest_write_bytes(env, buffer, data, buffer_size);
        }
        return VIBATNIUM_EFI_SUCCESS;
    }
    case 2:
        return VIBATNIUM_EFI_WRITE_PROTECTED;
    case 3:
        return VIBATNIUM_EFI_SUCCESS;
    default:
        return VIBATNIUM_EFI_UNSUPPORTED;
    }
}

static EfiGuestEvent *efi_find_event(uint64_t handle)
{
    if (handle == VIBATNIUM_EFI_CON_IN_WAIT_EVENT) {
        static EfiGuestEvent conin_event;

        conin_event = (EfiGuestEvent) {
            .in_use = true,
            .handle = VIBATNIUM_EFI_CON_IN_WAIT_EVENT,
            .type = 0,
            .signaled = efi_conin_enter_pending,
            .timer = false,
        };
        return &conin_event;
    }

    for (unsigned i = 0; i < EFI_MAX_EVENTS; i++) {
        if (efi_guest_events[i].in_use &&
            efi_guest_events[i].handle == handle) {
            return &efi_guest_events[i];
        }
    }
    return NULL;
}

static uint64_t efi_create_event(CPUIA64State *env)
{
    uint64_t type = ia64_read_gr(env, 32);
    uint64_t event_out = ia64_read_gr(env, 36);

    if (type > UINT32_MAX || event_out == 0) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }

    for (unsigned i = 0; i < EFI_MAX_EVENTS; i++) {
        EfiGuestEvent *event = &efi_guest_events[i];

        if (event->in_use) {
            continue;
        }

        memset(event, 0, sizeof(*event));
        event->in_use = true;
        event->handle = efi_next_event_handle++;
        event->type = type;
        efi_guest_stq(env, event_out, event->handle);
        return VIBATNIUM_EFI_SUCCESS;
    }

    efi_guest_stq(env, event_out, 0);
    return VIBATNIUM_EFI_OUT_OF_RESOURCES;
}

static uint64_t efi_set_timer(CPUIA64State *env)
{
    uint64_t handle = ia64_read_gr(env, 32);
    uint64_t timer_type = ia64_read_gr(env, 33);
    EfiGuestEvent *event = efi_find_event(handle);

    if (!event || handle == VIBATNIUM_EFI_CON_IN_WAIT_EVENT) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }

    event->timer = timer_type != 0;
    event->signaled = timer_type != 0;
    return VIBATNIUM_EFI_SUCCESS;
}

static bool efi_event_is_ready(EfiGuestEvent *event)
{
    if (!event) {
        return false;
    }
    if (event->handle == VIBATNIUM_EFI_CON_IN_WAIT_EVENT) {
        return efi_conin_enter_pending;
    }
    return event->signaled || event->timer;
}

static uint64_t efi_wait_for_event(CPUIA64State *env)
{
    uint64_t count = ia64_read_gr(env, 32);
    uint64_t events = ia64_read_gr(env, 33);
    uint64_t index_out = ia64_read_gr(env, 34);
    int first_valid = -1;

    if (count == 0 || count > EFI_MAX_EVENTS || events == 0 ||
        index_out == 0) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }

    for (uint64_t i = 0; i < count; i++) {
        uint64_t handle = efi_guest_ldq(env, events + i * sizeof(uint64_t));
        EfiGuestEvent *event = efi_find_event(handle);

        if (!event) {
            return VIBATNIUM_EFI_INVALID_PARAMETER;
        }
        if (first_valid < 0) {
            first_valid = i;
        }
        if (efi_event_is_ready(event)) {
            efi_guest_stq(env, index_out, i);
            if (event->timer) {
                event->signaled = false;
            }
            return VIBATNIUM_EFI_SUCCESS;
        }
    }

    if (first_valid >= 0) {
        efi_guest_stq(env, index_out, first_valid);
        return VIBATNIUM_EFI_SUCCESS;
    }
    return VIBATNIUM_EFI_NOT_READY;
}

static uint64_t efi_signal_event(CPUIA64State *env)
{
    EfiGuestEvent *event = efi_find_event(ia64_read_gr(env, 32));

    if (!event || event->handle == VIBATNIUM_EFI_CON_IN_WAIT_EVENT) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }

    event->signaled = true;
    return VIBATNIUM_EFI_SUCCESS;
}

static uint64_t efi_close_event(CPUIA64State *env)
{
    EfiGuestEvent *event = efi_find_event(ia64_read_gr(env, 32));

    if (!event || event->handle == VIBATNIUM_EFI_CON_IN_WAIT_EVENT) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }

    memset(event, 0, sizeof(*event));
    return VIBATNIUM_EFI_SUCCESS;
}

static uint64_t efi_check_event(CPUIA64State *env)
{
    EfiGuestEvent *event = efi_find_event(ia64_read_gr(env, 32));

    if (!event) {
        return VIBATNIUM_EFI_INVALID_PARAMETER;
    }
    return efi_event_is_ready(event) ? VIBATNIUM_EFI_SUCCESS
                                     : VIBATNIUM_EFI_NOT_READY;
}

static uint64_t efi_dispatch_boot_service(CPUIA64State *env, unsigned index)
{
    switch (index) {
    case 0:
        return 4; /* RaiseTPL returns the previous TPL, not EFI_STATUS. */
    case 1:
    case 6:
    case VIBATNIUM_EFI_BOOT_STALL_INDEX:
    case VIBATNIUM_EFI_BOOT_SET_WATCHDOG_INDEX:
        return VIBATNIUM_EFI_SUCCESS;
    case VIBATNIUM_EFI_BOOT_ALLOCATE_PAGES_INDEX:
        return efi_allocate_pages(env);
    case VIBATNIUM_EFI_BOOT_FREE_PAGES_INDEX:
        return efi_free_pages(env);
    case VIBATNIUM_EFI_BOOT_GET_MEMORY_MAP_INDEX:
        return efi_get_memory_map(env);
    case 5:
        return efi_allocate_pool(env);
    case 7:
        return efi_create_event(env);
    case 8:
        return efi_set_timer(env);
    case 9:
        return efi_wait_for_event(env);
    case 10:
        return efi_signal_event(env);
    case 11:
        return efi_close_event(env);
    case 12:
        return efi_check_event(env);
    case VIBATNIUM_EFI_BOOT_INSTALL_PROTOCOL_INDEX:
        return efi_install_protocol_interface(env);
    case VIBATNIUM_EFI_BOOT_UNINSTALL_PROTOCOL_INDEX:
        return efi_uninstall_protocol_interface(env);
    case VIBATNIUM_EFI_BOOT_HANDLE_PROTOCOL_INDEX:
        return efi_handle_protocol(env);
    case VIBATNIUM_EFI_BOOT_LOCATE_HANDLE_INDEX:
        return efi_locate_handle(env);
    case VIBATNIUM_EFI_BOOT_EXIT_BOOT_SERVICES_INDEX:
        return efi_exit_boot_services(env);
    case VIBATNIUM_EFI_BOOT_OPEN_PROTOCOL_INDEX:
        return efi_handle_protocol(env);
    case VIBATNIUM_EFI_BOOT_CLOSE_PROTOCOL_INDEX:
        return efi_close_protocol(env);
    case VIBATNIUM_EFI_BOOT_LOCATE_PROTOCOL_INDEX:
        return efi_locate_protocol(env);
    case VIBATNIUM_EFI_BOOT_CALCULATE_CRC32_INDEX:
        return efi_calculate_crc32(env);
    case VIBATNIUM_EFI_BOOT_COPY_MEM_INDEX:
        return efi_copy_mem(env);
    case VIBATNIUM_EFI_BOOT_SET_MEM_INDEX:
        return efi_set_mem(env);
    default:
        return VIBATNIUM_EFI_UNSUPPORTED;
    }
}

static uint64_t efi_dispatch_runtime_service(CPUIA64State *env, unsigned index)
{
    switch (index) {
    case 6: /* GetVariable */
    case 7: /* GetNextVariableName */
        return VIBATNIUM_EFI_NOT_FOUND;
    case 8: /* SetVariable */
        return VIBATNIUM_EFI_SUCCESS;
    default:
        return VIBATNIUM_EFI_UNSUPPORTED;
    }
}

static void efi_console_output_string(CPUIA64State *env)
{
    uint64_t text = ia64_read_gr(env, 33);
    GString *line;

    if (text == 0) {
        return;
    }

    line = g_string_new(NULL);
    for (unsigned i = 0; i < 4096; i++) {
        uint16_t ch = cpu_lduw_le_data_ra(env, text + i * 2, GETPC());

        if (ch == 0) {
            break;
        }
        if (ch == '\r') {
            continue;
        }
        g_string_append_c(line, ch < 0x80 ? (char)ch : '?');
    }
    if (line->len != 0) {
        fprintf(stderr, "%s", line->str);
    }
    g_string_free(line, true);
}

static uint64_t efi_dispatch_console_out(CPUIA64State *env, unsigned index)
{
    uint64_t columns = ia64_read_gr(env, 34);
    uint64_t rows = ia64_read_gr(env, 35);

    switch (index) {
    case 0: /* Reset */
        return VIBATNIUM_EFI_SUCCESS;
    case 1: /* OutputString */
        efi_console_output_string(env);
        return VIBATNIUM_EFI_SUCCESS;
    case 2: /* TestString */
        return VIBATNIUM_EFI_SUCCESS;
    case 3: /* QueryMode */
        if (columns == 0 || rows == 0) {
            return VIBATNIUM_EFI_INVALID_PARAMETER;
        }
        efi_guest_stq(env, columns, 80);
        efi_guest_stq(env, rows, 25);
        return VIBATNIUM_EFI_SUCCESS;
    case 4: /* SetMode */
    case 5: /* SetAttribute */
    case 6: /* ClearScreen */
    case 7: /* SetCursorPosition */
    case 8: /* EnableCursor */
        return VIBATNIUM_EFI_SUCCESS;
    default:
        return VIBATNIUM_EFI_UNSUPPORTED;
    }
}

static uint64_t efi_dispatch_console_in(CPUIA64State *env, unsigned index)
{
    uint64_t key = ia64_read_gr(env, 33);

    switch (index) {
    case 0: /* Reset */
        efi_conin_enter_pending = true;
        return VIBATNIUM_EFI_SUCCESS;
    case 1: /* ReadKeyStroke */
        if (key == 0) {
            return VIBATNIUM_EFI_INVALID_PARAMETER;
        }
        if (!efi_conin_enter_pending) {
            return VIBATNIUM_EFI_NOT_READY;
        }
        efi_guest_stw(env, key, 0);
        efi_guest_stw(env, key + 2, '\r');
        efi_conin_enter_pending = false;
        return VIBATNIUM_EFI_SUCCESS;
    default:
        return VIBATNIUM_EFI_UNSUPPORTED;
    }
}

bool vibatnium_efi_dispatch_gate(CPUIA64State *env, uint64_t gate_ip)
{
    unsigned service_index;
    uint64_t result = VIBATNIUM_EFI_UNSUPPORTED;

    if (!env || !efi_gate_service_index(gate_ip, &service_index)) {
        return false;
    }

    if (service_index < EFI_RUNTIME_SERVICE_BASE) {
        result = efi_dispatch_boot_service(env,
                                           service_index -
                                           EFI_BOOT_SERVICE_BASE);
    } else if (service_index < EFI_CON_OUT_SERVICE_BASE) {
        result = efi_dispatch_runtime_service(env,
                                              service_index -
                                              EFI_RUNTIME_SERVICE_BASE);
    } else if (service_index >= EFI_CON_OUT_SERVICE_BASE &&
               service_index < EFI_CON_IN_SERVICE_BASE) {
        result = efi_dispatch_console_out(env,
                                          service_index -
                                          EFI_CON_OUT_SERVICE_BASE);
    } else if (service_index >= EFI_CON_IN_SERVICE_BASE &&
               service_index < EFI_BLOCK_IO_SERVICE_BASE) {
        result = efi_dispatch_console_in(env,
                                         service_index -
                                         EFI_CON_IN_SERVICE_BASE);
    } else if (service_index >= EFI_BLOCK_IO_SERVICE_BASE &&
               service_index < EFI_SIMPLE_FILE_SYSTEM_SERVICE_BASE) {
        result = efi_dispatch_block_io(env,
                                       service_index -
                                       EFI_BLOCK_IO_SERVICE_BASE);
    } else if (service_index >= EFI_SIMPLE_FILE_SYSTEM_SERVICE_BASE &&
               service_index < EFI_FILE_SERVICE_BASE) {
        result = efi_dispatch_simple_file_system(
            env, service_index - EFI_SIMPLE_FILE_SYSTEM_SERVICE_BASE);
    } else if (service_index >= EFI_FILE_SERVICE_BASE &&
               service_index < EFI_SERVICE_DESCRIPTOR_COUNT) {
        result = efi_dispatch_file(env,
                                   service_index - EFI_FILE_SERVICE_BASE);
    }

    ia64_write_gr(env, 8, result);
    efi_trace_service(env, service_index, result);
    ia64_return_from_call_frame(env, env->br[0]);
    return true;
}

static uint64_t ia64_ld_le_unaligned(CPUIA64State *env, uint64_t address,
                                     uint8_t width)
{
    uint64_t value = 0;

    for (uint8_t i = 0; i < width; i++) {
        value |= (uint64_t)cpu_ldub_data_ra(env, address + i, GETPC())
            << (i * 8);
    }

    return value;
}

static void ia64_st_le_unaligned(CPUIA64State *env, uint64_t address,
                                 uint8_t width, uint64_t value)
{
    for (uint8_t i = 0; i < width; i++) {
        cpu_stb_data_ra(env, address + i, (value >> (i * 8)) & 0xff,
                        GETPC());
    }
}

static uint64_t ia64_ldst_read(CPUIA64State *env, uint64_t address,
                               uint8_t width)
{
    if (width > 1 && (address & (width - 1)) != 0) {
        return ia64_ld_le_unaligned(env, address, width);
    }

    switch (width) {
    case 1:
        return cpu_ldub_data_ra(env, address, GETPC());
    case 2:
        return cpu_lduw_le_data_ra(env, address, GETPC());
    case 4:
        return cpu_ldl_le_data_ra(env, address, GETPC());
    case 8:
        return cpu_ldq_le_data_ra(env, address, GETPC());
    default:
        g_assert_not_reached();
    }
}

static void ia64_ldst_write(CPUIA64State *env, uint64_t address,
                            uint8_t width, uint64_t value)
{
    if (width > 1 && (address & (width - 1)) != 0) {
        ia64_st_le_unaligned(env, address, width, value);
        return;
    }

    switch (width) {
    case 1:
        cpu_stb_data_ra(env, address, value, GETPC());
        break;
    case 2:
        cpu_stw_le_data_ra(env, address, value, GETPC());
        break;
    case 4:
        cpu_stl_le_data_ra(env, address, value, GETPC());
        break;
    case 8:
        cpu_stq_le_data_ra(env, address, value, GETPC());
        break;
    default:
        g_assert_not_reached();
    }
}

static bool exec_ldst_immediate(CPUIA64State *env,
                                const IA64LdstImmediate *decoded)
{
    uint64_t address = ia64_read_gr(env, decoded->base);
    uint64_t update;

    switch (decoded->kind) {
    case IA64_LDST_IMM_LOAD:
        if (decoded->target != 0) {
            ia64_write_gr(env, decoded->target,
                          ia64_ldst_read(env, address, decoded->width));
        }
        break;
    case IA64_LDST_IMM_STORE:
        ia64_ldst_write(env, address, decoded->width,
                        ia64_read_gr(env, decoded->source));
        break;
    case IA64_LDST_IMM_PREFETCH:
        break;
    default:
        g_assert_not_reached();
    }

    if (decoded->base_update) {
        update = decoded->update_from_register
            ? ia64_read_gr(env, decoded->update_source)
            : (uint64_t)decoded->immediate;
        ia64_write_gr(env, decoded->base, address + update);
    }
    env->gr[0] = 0;
    return true;
}

static uint32_t helper_map_fr(CPUIA64State *env, uint32_t reg)
{
    if (reg < 32) {
        return reg;
    }
    return 32 + ((reg - 32 + env->rse.rrb_fr) % (IA64_FR_COUNT - 32));
}

static void helper_write_fr_raw(CPUIA64State *env, uint32_t reg,
                                uint64_t low, uint64_t high)
{
    uint32_t mapped;

    if (reg >= IA64_FR_COUNT || reg < 2) {
        return;
    }

    mapped = helper_map_fr(env, reg);
    env->fr[mapped].raw[0] = low;
    env->fr[mapped].raw[1] = high;
}

static void exec_floating_load(CPUIA64State *env,
                               const IA64FloatingMemoryInstruction *decoded,
                               uint64_t address)
{
    switch (decoded->format) {
    case IA64_FLOAT_FMT_SINGLE:
        helper_write_fr_raw(env, decoded->freg,
                            ia64_ldst_read(env, address, 4),
                            0x1003e);
        break;
    case IA64_FLOAT_FMT_DOUBLE:
    case IA64_FLOAT_FMT_SIGNIFICAND:
        helper_write_fr_raw(env, decoded->freg,
                            ia64_ldst_read(env, address, 8),
                            0x1003e);
        break;
    case IA64_FLOAT_FMT_EXTENDED:
    case IA64_FLOAT_FMT_SPILL_FILL:
        helper_write_fr_raw(env, decoded->freg,
                            ia64_ldst_read(env, address, 8),
                            ia64_ldst_read(env, address + 8, 8));
        break;
    default:
        g_assert_not_reached();
    }
}

static void exec_floating_store(CPUIA64State *env,
                                const IA64FloatingMemoryInstruction *decoded,
                                uint64_t address)
{
    uint32_t mapped = helper_map_fr(env, decoded->freg);
    uint64_t low = env->fr[mapped].raw[0];
    uint64_t high = env->fr[mapped].raw[1];

    switch (decoded->format) {
    case IA64_FLOAT_FMT_SINGLE:
        ia64_ldst_write(env, address, 4, low);
        break;
    case IA64_FLOAT_FMT_DOUBLE:
    case IA64_FLOAT_FMT_SIGNIFICAND:
        ia64_ldst_write(env, address, 8, low);
        break;
    case IA64_FLOAT_FMT_EXTENDED:
    case IA64_FLOAT_FMT_SPILL_FILL:
        ia64_ldst_write(env, address, 8, low);
        ia64_ldst_write(env, address + 8, 8, high);
        break;
    default:
        g_assert_not_reached();
    }
}

static bool exec_floating_memory(CPUIA64State *env,
                                 const IA64FloatingMemoryInstruction *decoded)
{
    uint64_t address = ia64_read_gr(env, decoded->base);
    uint64_t update;

    switch (decoded->kind) {
    case IA64_FLOAT_MEM_LOAD:
        exec_floating_load(env, decoded, address);
        break;
    case IA64_FLOAT_MEM_STORE:
        exec_floating_store(env, decoded, address);
        break;
    default:
        g_assert_not_reached();
    }

    if (decoded->base_update) {
        update = decoded->update_from_register
            ? ia64_read_gr(env, decoded->update_source)
            : (uint64_t)decoded->immediate;
        ia64_write_gr(env, decoded->base, address + update);
    }
    return true;
}

static bool exec_counted_store_loop(CPUIA64State *env,
                                    const IA64CountedStoreLoop *loop,
                                    uint64_t *next_ip)
{
    uint64_t loop_count = env->ar[IA64_AR_LC];
    uint64_t iterations;
    uint64_t address;
    uint64_t value;
    uint64_t update;

    if (!env || !loop || !next_ip || loop_count == UINT64_MAX) {
        return false;
    }

    iterations = loop_count + 1;
    address = ia64_read_gr(env, loop->store.base);
    value = ia64_read_gr(env, loop->store.source);
    update = (uint64_t)loop->store.immediate;

    for (uint64_t i = 0; i < iterations; i++) {
        ia64_ldst_write(env, address, loop->store.width, value);
        address += update;
    }

    ia64_write_gr(env, loop->store.base, address);
    env->ar[IA64_AR_LC] = 0;
    *next_ip = loop->fallthrough_ip;
    env->gr[0] = 0;
    return true;
}

void HELPER(exec_bundle)(CPUIA64State *env,
                         uint32_t tmpl,
                         uint64_t slot0,
                         uint64_t slot1,
                         uint64_t slot2)
{
    CPUState *cpu = env_cpu(env);
    IA64DecodedBundle decoded;
    uint64_t next_ip = env->ip + IA64_BUNDLE_SIZE;
    bool exception_taken = false;

    /*
     * This target still interprets complete IA-64 bundles inside one C helper.
     * Nested memory helpers therefore cannot hand QEMU a translated-code return
     * address for cpu_io_recompile().  Allow helper-owned I/O directly until the
     * translator grows per-instruction memory ops.
     */
    cpu->neg.can_do_io = true;

    decoded.tmpl = tmpl & 0x1f;
    decoded.slot[0] = slot0 & IA64_SLOT_MASK;
    decoded.slot[1] = slot1 & IA64_SLOT_MASK;
    decoded.slot[2] = slot2 & IA64_SLOT_MASK;
    decoded.info = ia64_template_info(decoded.tmpl);
    decoded.valid = decoded.info->valid;

    if (!decoded.valid) {
        abort_unsupported_slot(env, &decoded, 0);
    }

    ia64_progress_trace_bundle(env);

    if (vibatnium_efi_dispatch_gate(env, env->ip)) {
        return;
    }

    {
        IA64CountedStoreLoop store_loop;

        if (ia64_decode_counted_store_loop(&decoded, env->ip, &store_loop) &&
            exec_counted_store_loop(env, &store_loop, &next_ip)) {
            env->ip = next_ip;
            env->cr[IA64_CR_IIP] = env->ip;
            return;
        }
    }

    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        IA64SlotType type = decoded.info->slot_type[slot];
        uint64_t raw = decoded.slot[slot];
        uint8_t qp = ia64_slot_predicate(raw);
        IA64LdstImmediate ldst;
        IA64FloatingMemoryInstruction fldst;
        IA64CompareInstruction cmp;
        IA64PredicateTestInstruction pred_test;
        IA64ExtractInstruction extract;
        IA64DepositInstruction deposit;
        IA64IntegerExtendInstruction int_ext;

        if (decoded.info->long_immediate && slot == 1) {
            uint8_t x_qp = ia64_slot_predicate(decoded.slot[2]);

            if (ia64_read_pr(env, x_qp)) {
                if (!ia64_exec_lx_movl(env, decoded.slot[1],
                                       decoded.slot[2])) {
                    abort_unsupported_slot(env, &decoded, 1);
                }
            }
            slot++;
            continue;
        }

        if (!ia64_read_pr(env, qp) &&
            !(type == IA64_SLOT_TYPE_B && ia64_slot_major_opcode(raw) == 0x4 &&
              (((raw >> 6) & 0x7) == 2 || ((raw >> 6) & 0x7) == 3))) {
            continue;
        }
        if (ia64_exec_smoke_slot_supported(type, raw)) {
            continue;
        }
        if (ia64_slot_is_i_nop(type, raw)) {
            continue;
        }
        if (ia64_slot_is_m34_alloc(type, raw)) {
            ia64_exec_m34_alloc(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mov_ip(type, raw)) {
            ia64_exec_i_mov_ip(env, raw, env->ip);
            continue;
        }
        if (ia64_slot_is_i_mov_from_branch(type, raw)) {
            ia64_exec_i_mov_from_branch(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mov_to_branch(type, raw)) {
            ia64_exec_i_mov_to_branch(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mov_from_predicate(type, raw)) {
            ia64_exec_i_mov_from_predicate(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mov_to_predicate(type, raw)) {
            ia64_exec_i_mov_to_predicate(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mov_to_rotating_predicate_immediate(type, raw)) {
            ia64_exec_i_mov_to_rotating_predicate_immediate(env, raw);
            continue;
        }
        if (ia64_slot_is_mov_to_application(type, raw)) {
            ia64_exec_mov_to_application(env, type, raw);
            continue;
        }
        if (ia64_slot_is_mov_from_application(type, raw)) {
            ia64_exec_mov_from_application(env, type, raw);
            continue;
        }
        if (ia64_slot_is_mov_to_application_immediate(type, raw)) {
            ia64_exec_mov_to_application_immediate(env, type, raw);
            continue;
        }
        if (ia64_slot_is_m_check_advanced(type, raw)) {
            ia64_exec_m_check_advanced(env, raw, env->ip, &next_ip);
            if (next_ip == 0) {
                abort_zero_branch(env, &decoded, slot);
            }
            if (next_ip != env->ip + IA64_BUNDLE_SIZE) {
                break;
            }
            continue;
        }
        if (ia64_slot_is_m_processor_mask(type, raw) &&
            ia64_exec_m_processor_mask(env, raw)) {
            continue;
        }
        if (ia64_slot_is_m_mov_from_processor_status(type, raw) &&
            ia64_exec_m_mov_from_processor_status(env, raw)) {
            continue;
        }
        if (ia64_slot_is_m_mov_to_processor_status(type, raw) &&
            ia64_exec_m_mov_to_processor_status(env, raw)) {
            continue;
        }
        if (ia64_slot_is_m_break(type, raw)) {
            uint64_t iim = ia64_m_break_immediate(raw);
            char detail[64];

            snprintf(detail, sizeof(detail), "break.m iim=0x%" PRIx64, iim);
            ia64_record_exception(env, IA64_EXCEPTION_BREAK, iim,
                                  MMU_INST_FETCH, detail);
            env->cr[IA64_CR_IPSR] = env->psr;
            env->cr[IA64_CR_IIM] = iim;
            next_ip = env->cr[IA64_CR_IVA] + UINT64_C(0x2c00);
            ia64_progress_trace_event(env, "break.m", iim, next_ip);
            exception_taken = true;
            break;
        }
        if (ia64_slot_is_m_mov_to_region_register(type, raw) &&
            ia64_exec_m_mov_to_region_register(env, raw)) {
            continue;
        }
        if (ia64_slot_is_m_mov_from_region_register(type, raw) &&
            ia64_exec_m_mov_from_region_register(env, raw)) {
            continue;
        }
        if (ia64_slot_is_m_mov_to_control(type, raw) &&
            ia64_exec_m_mov_to_control(env, raw)) {
            continue;
        }
        if (ia64_slot_is_m_mov_from_control(type, raw) &&
            ia64_exec_m_mov_from_control(env, raw)) {
            continue;
        }
        if (ia64_slot_is_m_insert_translation(type, raw) &&
            ia64_exec_m_insert_translation(env, raw)) {
            continue;
        }
        if (ia64_slot_is_m_virtual_translation(type, raw) &&
            ia64_exec_m_virtual_translation(env, raw)) {
            continue;
        }
        if (ia64_slot_is_m_system_noop(type, raw)) {
            continue;
        }
        if (ia64_slot_is_m_setf(type, raw) && ia64_exec_m_setf(env, raw)) {
            continue;
        }
        if (ia64_slot_is_m_getf(type, raw) && ia64_exec_m_getf(env, raw)) {
            continue;
        }
        if (ia64_decode_extract(type, raw, &extract) &&
            ia64_exec_extract(env, &extract)) {
            continue;
        }
        if (ia64_decode_deposit(type, raw, &deposit) &&
            ia64_exec_deposit(env, &deposit)) {
            continue;
        }
        if (ia64_slot_is_i_shift_right_pair(type, raw) &&
            ia64_exec_i_shift_right_pair(env, raw)) {
            continue;
        }
        if (ia64_decode_integer_extend(type, raw, &int_ext) &&
            ia64_exec_integer_extend(env, &int_ext)) {
            continue;
        }
        if (ia64_slot_is_f_reciprocal_approx(type, raw) &&
            ia64_exec_f_reciprocal_approx(env, raw)) {
            continue;
        }
        if (ia64_slot_is_f_misc(type, raw) &&
            ia64_exec_f_misc(env, raw)) {
            continue;
        }
        if (ia64_slot_is_f_multiply_add(type, raw) &&
            ia64_exec_f_multiply_add(env, raw)) {
            continue;
        }
        if (ia64_slot_is_f_select_or_xma(type, raw) &&
            ia64_exec_f_select_or_xma(env, raw)) {
            continue;
        }
        if (ia64_decode_floating_memory(type, raw, &fldst) &&
            exec_floating_memory(env, &fldst)) {
            continue;
        }
        if (ia64_decode_ldst_immediate(type, raw, &ldst) &&
            exec_ldst_immediate(env, &ldst)) {
            continue;
        }
        if (ia64_decode_compare(type, raw, &cmp) &&
            ia64_exec_compare(env, &cmp)) {
            continue;
        }
        if (ia64_decode_predicate_test(type, raw, &pred_test) &&
            ia64_exec_predicate_test(env, &pred_test)) {
            continue;
        }
        if (ia64_slot_is_alu_add(type, raw)) {
            ia64_exec_alu_add(env, raw);
            continue;
        }
        if (ia64_slot_is_alu_sub(type, raw)) {
            ia64_exec_alu_sub(env, raw);
            continue;
        }
        if (ia64_slot_is_alu_logic(type, raw)) {
            ia64_exec_alu_logic(env, raw);
            continue;
        }
        if (ia64_slot_is_alu_addp4(type, raw)) {
            ia64_exec_alu_addp4(env, raw);
            continue;
        }
        if (ia64_slot_is_alu_shladd(type, raw)) {
            ia64_exec_alu_shladd(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mux(type, raw)) {
            ia64_exec_i_mux(env, raw);
            continue;
        }
        if (ia64_slot_is_i_variable_shift(type, raw)) {
            ia64_exec_i_variable_shift(env, raw);
            continue;
        }
        if (ia64_slot_is_addl(type, raw)) {
            ia64_exec_addl(env, raw);
            continue;
        }
        if (ia64_slot_is_b_branch_relative(type, raw)) {
            ia64_exec_b_branch_relative(env, raw, env->ip, &next_ip);
            if (next_ip == 0) {
                abort_zero_branch(env, &decoded, slot);
            }
            if (next_ip != env->ip + IA64_BUNDLE_SIZE) {
                break;
            }
            continue;
        }
        if (ia64_slot_is_b_call_relative(type, raw)) {
            ia64_exec_b_call_relative(env, raw, env->ip, &next_ip);
            if (next_ip == 0) {
                abort_zero_branch(env, &decoded, slot);
            }
            break;
        }
        if (ia64_slot_is_b_indirect_branch(type, raw)) {
            ia64_exec_b_indirect_branch(env, raw, env->ip, &next_ip);
            if (next_ip == 0) {
                abort_zero_branch(env, &decoded, slot);
            }
            break;
        }
        if (ia64_slot_is_b_predict_or_nop(type, raw)) {
            continue;
        }
        if (decoded.info->long_immediate && type == IA64_SLOT_TYPE_X) {
            abort_unsupported_slot(env, &decoded, 1);
        }

        abort_unsupported_slot(env, &decoded, slot);
    }

    env->ip = next_ip;
    if (!exception_taken) {
        env->cr[IA64_CR_IIP] = env->ip;
    }
}
