/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "accel/tcg/cpu-ldst.h"
#include "accel/tcg/getpc.h"
#include "hw/ia64/efi.h"
#include "hw/ia64/efi-storage.h"
#include "hw/ia64/efi-vars.h"
#include "hw/ia64/vibtanium.h"
#include "qemu/error-report.h"
#include "system/memory.h"
#include "target/ia64/insn.h"
#include "target/ia64/perf.h"
#include "trace-target_ia64.h"

enum {
    EFI_BOOT_SERVICE_BASE = 0,
    EFI_RUNTIME_SERVICE_BASE =
        EFI_BOOT_SERVICE_BASE + VIBTANIUM_EFI_BOOT_SERVICE_COUNT,
    EFI_CON_OUT_SERVICE_BASE =
        EFI_RUNTIME_SERVICE_BASE + VIBTANIUM_EFI_RUNTIME_SERVICE_COUNT,
    EFI_CON_IN_SERVICE_BASE =
        EFI_CON_OUT_SERVICE_BASE + VIBTANIUM_EFI_CON_OUT_SERVICE_COUNT,
    EFI_BLOCK_IO_SERVICE_BASE =
        EFI_CON_IN_SERVICE_BASE + VIBTANIUM_EFI_CON_IN_SERVICE_COUNT,
    EFI_SIMPLE_FILE_SYSTEM_SERVICE_BASE =
        EFI_BLOCK_IO_SERVICE_BASE + VIBTANIUM_EFI_BLOCK_IO_SERVICE_COUNT,
    EFI_FILE_SERVICE_BASE =
        EFI_SIMPLE_FILE_SYSTEM_SERVICE_BASE +
        VIBTANIUM_EFI_SIMPLE_FILE_SYSTEM_SERVICE_COUNT,
    EFI_GOP_SERVICE_BASE =
        EFI_FILE_SERVICE_BASE + VIBTANIUM_EFI_FILE_SERVICE_COUNT,
    EFI_SERVICE_DESCRIPTOR_COUNT =
        EFI_GOP_SERVICE_BASE + VIBTANIUM_EFI_GOP_SERVICE_COUNT,
};

#define EFI_MAX_INSTALLED_PROTOCOLS 64
#define EFI_MAX_FILE_HANDLES 64
#define EFI_MAX_EVENTS 64
#define EFI_MAX_PAGE_ALLOCATIONS 64
#define EFI_MAX_PATH_CHARS 512
#define EFI_MAX_VAR_NAME_CHARS 1024
#define EFI_MAX_VARIABLE_DATA_SIZE (1024 * 1024)
#define EFI_MAX_FILE_READ_BYTES (128 * 1024 * 1024)
#define EFI_PAGE_SIZE UINT64_C(4096)
#define EFI_MEMORY_DESCRIPTOR_SIZE UINT64_C(40)
#define EFI_MEMORY_DESCRIPTOR_VERSION 1
#define EFI_GUEST_RAM_TOP UINT64_C(0x20000000)
#define EFI_LINUX_APPEND_BASE UINT64_C(0x03fff000)
#define EFI_LINUX_APPEND_SIZE UINT64_C(0x00001000)
#define EFI_PAGE_ALLOC_BASE UINT64_C(0x03000000)
#define EFI_PAGE_ALLOC_SIZE (EFI_LINUX_APPEND_BASE - EFI_PAGE_ALLOC_BASE)
#define EFI_RUNTIME_GRANULE_BASE UINT64_C(0x00000000)
#define EFI_RUNTIME_GRANULE_SIZE UINT64_C(0x01000000)
#define EFI_LOW_CONVENTIONAL_BASE EFI_RUNTIME_GRANULE_SIZE
#define EFI_LOW_CONVENTIONAL_PAGES UINT64_C(0)
#define EFI_HIGH_CONVENTIONAL_BASE UINT64_C(0x04000000)
#define EFI_HIGH_CONVENTIONAL_PAGES \
    ((EFI_GUEST_RAM_TOP - EFI_HIGH_CONVENTIONAL_BASE) / EFI_PAGE_SIZE)
#define EFI_DEFAULT_LOADER_IMAGE_PAGES \
    ((VIBTANIUM_EFI_STACK_BASE - VIBTANIUM_EFI_APP_BASE) / EFI_PAGE_SIZE)
#define IA64_REGION_OFFSET_MASK UINT64_C(0x1fffffffffffffff)

enum {
    EFI_RESERVED_MEMORY_TYPE = 0,
    EFI_LOADER_CODE = 1,
    EFI_LOADER_DATA = 2,
    EFI_BOOT_SERVICES_CODE = 3,
    EFI_BOOT_SERVICES_DATA = 4,
    EFI_RUNTIME_SERVICES_CODE = 5,
    EFI_RUNTIME_SERVICES_DATA = 6,
    EFI_CONVENTIONAL_MEMORY = 7,
    EFI_ACPI_RECLAIM_MEMORY = 9,
    EFI_MEMORY_MAPPED_IO = 11,
    EFI_MEMORY_MAPPED_IO_PORT_SPACE = 12,
};

enum {
    EFI_ALLOCATE_ANY_PAGES = 0,
    EFI_ALLOCATE_MAX_ADDRESS = 1,
    EFI_ALLOCATE_ADDRESS = 2,
};

#define EFI_MEMORY_UC UINT64_C(0x0000000000000001)
#define EFI_MEMORY_WB UINT64_C(0x0000000000000008)
#define EFI_MEMORY_RUNTIME UINT64_C(0x8000000000000000)
#define EFI_UNSPECIFIED_TIMEZONE 0x07ff
#define IA64_KERNEL_PAGE_OFFSET UINT64_C(0xe000000000000000)
#define EFI_TIMER_CANCEL   0
#define EFI_TIMER_PERIODIC 1
#define EFI_TIMER_RELATIVE 2

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
    bool timer_active;
    bool timer_periodic;
    uint64_t timer_period;
    uint64_t timer_due;
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

typedef enum EfiMemoryMapRecordKind {
    EFI_MEMORY_MAP_RECORD_DIRECT,
    EFI_MEMORY_MAP_RECORD_CONVENTIONAL_SPLIT,
    EFI_MEMORY_MAP_RECORD_RUNTIME_WITH_LOADER,
    EFI_MEMORY_MAP_RECORD_LOADER_IF_NEEDED,
} EfiMemoryMapRecordKind;

typedef struct EfiMemoryMapRecord {
    EfiMemoryMapRecordKind kind;
    EfiMemoryRange range;
} EfiMemoryMapRecord;

static const EfiMemoryMapRecord efi_memory_map_records[] = {
    {
        .kind = EFI_MEMORY_MAP_RECORD_RUNTIME_WITH_LOADER,
        .range = {
            .type = EFI_RUNTIME_SERVICES_DATA,
            .address = EFI_RUNTIME_GRANULE_BASE,
            .pages = (VIBTANIUM_VGA_LEGACY_BASE - EFI_RUNTIME_GRANULE_BASE) /
                     EFI_PAGE_SIZE,
            .attributes = EFI_MEMORY_WB | EFI_MEMORY_RUNTIME,
        },
    },
    {
        .kind = EFI_MEMORY_MAP_RECORD_DIRECT,
        .range = {
            .type = EFI_MEMORY_MAPPED_IO,
            .address = VIBTANIUM_VGA_LEGACY_BASE,
            .pages = VIBTANIUM_VGA_LEGACY_SIZE / EFI_PAGE_SIZE,
            .attributes = EFI_MEMORY_UC,
        },
    },
    {
        .kind = EFI_MEMORY_MAP_RECORD_RUNTIME_WITH_LOADER,
        .range = {
            .type = EFI_RUNTIME_SERVICES_DATA,
            .address = VIBTANIUM_VGA_LEGACY_BASE + VIBTANIUM_VGA_LEGACY_SIZE,
            .pages = (EFI_RUNTIME_GRANULE_SIZE -
                      (VIBTANIUM_VGA_LEGACY_BASE +
                       VIBTANIUM_VGA_LEGACY_SIZE)) / EFI_PAGE_SIZE,
            .attributes = EFI_MEMORY_WB | EFI_MEMORY_RUNTIME,
        },
    },
    {
        .kind = EFI_MEMORY_MAP_RECORD_CONVENTIONAL_SPLIT,
        .range = {
            .type = EFI_CONVENTIONAL_MEMORY,
            .address = EFI_LOW_CONVENTIONAL_BASE,
            .pages = EFI_LOW_CONVENTIONAL_PAGES,
            .attributes = EFI_MEMORY_WB,
        },
    },
    {
        .kind = EFI_MEMORY_MAP_RECORD_LOADER_IF_NEEDED,
    },
    {
        .kind = EFI_MEMORY_MAP_RECORD_DIRECT,
        .range = {
            .type = EFI_BOOT_SERVICES_DATA,
            .address = VIBTANIUM_EFI_STACK_BASE,
            .pages = 0x100,
            .attributes = EFI_MEMORY_WB,
        },
    },
    {
        .kind = EFI_MEMORY_MAP_RECORD_DIRECT,
        .range = {
            .type = EFI_BOOT_SERVICES_DATA,
            .address = VIBTANIUM_EFI_POOL_BASE,
            .pages = VIBTANIUM_EFI_POOL_SIZE / EFI_PAGE_SIZE,
            .attributes = EFI_MEMORY_WB,
        },
    },
    {
        .kind = EFI_MEMORY_MAP_RECORD_DIRECT,
        .range = {
            .type = EFI_BOOT_SERVICES_DATA,
            .address = EFI_PAGE_ALLOC_BASE,
            .pages = EFI_PAGE_ALLOC_SIZE / EFI_PAGE_SIZE,
            .attributes = EFI_MEMORY_WB,
        },
    },
    {
        .kind = EFI_MEMORY_MAP_RECORD_DIRECT,
        .range = {
            .type = EFI_ACPI_RECLAIM_MEMORY,
            .address = EFI_LINUX_APPEND_BASE,
            .pages = EFI_LINUX_APPEND_SIZE / EFI_PAGE_SIZE,
            .attributes = EFI_MEMORY_WB,
        },
    },
    {
        .kind = EFI_MEMORY_MAP_RECORD_CONVENTIONAL_SPLIT,
        .range = {
            .type = EFI_CONVENTIONAL_MEMORY,
            .address = EFI_HIGH_CONVENTIONAL_BASE,
            .pages = EFI_HIGH_CONVENTIONAL_PAGES,
            .attributes = EFI_MEMORY_WB,
        },
    },
    {
        .kind = EFI_MEMORY_MAP_RECORD_DIRECT,
        .range = {
            .type = EFI_MEMORY_MAPPED_IO,
            .address = VIBTANIUM_FRAMEBUFFER_BASE,
            .pages = VIBTANIUM_FRAMEBUFFER_SIZE / EFI_PAGE_SIZE,
            .attributes = EFI_MEMORY_UC,
        },
    },
    {
        .kind = EFI_MEMORY_MAP_RECORD_DIRECT,
        .range = {
            .type = EFI_MEMORY_MAPPED_IO_PORT_SPACE,
            .address = VIBTANIUM_IO_PORT_BASE,
            .pages = VIBTANIUM_IO_PORT_SIZE / EFI_PAGE_SIZE,
            .attributes = EFI_MEMORY_UC | EFI_MEMORY_RUNTIME,
        },
    },
};

static VibtaniumEfiBlockDevice efi_boot_media;
static char *efi_boot_media_name;
static bool efi_boot_media_valid;
static uint64_t efi_pool_next = VIBTANIUM_EFI_POOL_BASE;
static uint64_t efi_page_alloc_next = EFI_PAGE_ALLOC_BASE;
static uint64_t efi_memory_map_key = 1;
static uint64_t efi_dynamic_handle_next = UINT64_C(0x00073000);
static uint64_t efi_next_event_handle = VIBTANIUM_EFI_CON_IN_WAIT_EVENT + 1;
static uint64_t efi_loaded_image_base = VIBTANIUM_EFI_APP_BASE;
static uint64_t efi_loaded_image_pages = EFI_DEFAULT_LOADER_IMAGE_PAGES;
static uint32_t efi_high_monotonic_count;
static char *efi_linux_cmdline_append;
static bool efi_linux_cmdline_append_done = true;
static EfiInstalledProtocol efi_installed_protocols[EFI_MAX_INSTALLED_PROTOCOLS];
static EfiGuestFile efi_guest_files[EFI_MAX_FILE_HANDLES];
static EfiGuestEvent efi_guest_events[EFI_MAX_EVENTS];
static EfiPageAllocation efi_page_allocations[EFI_MAX_PAGE_ALLOCATIONS];

#define EFI_INPUT_QUEUE_LENGTH 32

static VibtaniumEfiInputKey efi_conin_queue[EFI_INPUT_QUEUE_LENGTH];
static unsigned efi_conin_queue_head;
static unsigned efi_conin_queue_count;
static bool efi_conin_auto_enter;

static bool efi_conin_has_key(void)
{
    return efi_conin_queue_count != 0;
}

bool vibtanium_efi_input_enqueue(uint16_t scan_code, uint16_t unicode_char)
{
    unsigned index;

    if ((scan_code == 0 && unicode_char == 0) ||
        efi_conin_queue_count >= EFI_INPUT_QUEUE_LENGTH) {
        return false;
    }

    index = (efi_conin_queue_head + efi_conin_queue_count) %
            EFI_INPUT_QUEUE_LENGTH;
    efi_conin_queue[index] = (VibtaniumEfiInputKey) {
        .scan_code = scan_code,
        .unicode_char = unicode_char,
    };
    efi_conin_queue_count++;
    return true;
}

bool vibtanium_efi_input_has_key(void)
{
    return efi_conin_has_key();
}

bool vibtanium_efi_input_dequeue(VibtaniumEfiInputKey *key)
{
    if (!efi_conin_has_key()) {
        return false;
    }

    *key = efi_conin_queue[efi_conin_queue_head];
    efi_conin_queue_head = (efi_conin_queue_head + 1) %
                           EFI_INPUT_QUEUE_LENGTH;
    efi_conin_queue_count--;
    return true;
}

static bool efi_conin_dequeue(VibtaniumEfiInputKey *key)
{
    return vibtanium_efi_input_dequeue(key);
}

static void efi_conin_reset(void)
{
    efi_conin_queue_head = 0;
    efi_conin_queue_count = 0;
    if (efi_conin_auto_enter) {
        vibtanium_efi_input_enqueue(0, '\r');
    }
}

void vibtanium_efi_input_set_auto_enter(bool enabled)
{
    efi_conin_auto_enter = enabled;
}

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

static const uint8_t efi_graphics_output_guid[16] = {
    0xde, 0xa9, 0x42, 0x90, 0xdc, 0x23, 0x38, 0x4a,
    0x96, 0xfb, 0x7a, 0xde, 0xd0, 0x80, 0x51, 0x6a,
};

#define IA64_PSR_IT_BIT UINT64_C(0x0000001000000000)

typedef enum IA64LinuxAppendResult {
    IA64_LINUX_APPEND_NOT_READY,
    IA64_LINUX_APPEND_APPLIED,
    IA64_LINUX_APPEND_ALREADY_PRESENT,
    IA64_LINUX_APPEND_TOO_LATE,
} IA64LinuxAppendResult;

static uint64_t ia64_region_offset(uint64_t address)
{
    return address & IA64_REGION_OFFSET_MASK;
}

static bool efi_gate_address_is_valid_alias(uint64_t address)
{
    uint64_t region = address & ~IA64_REGION_OFFSET_MASK;

    return region == 0 || region == IA64_KERNEL_PAGE_OFFSET;
}

static uint64_t efi_service_descriptor_address(unsigned service_index)
{
    return VIBTANIUM_EFI_DESCRIPTOR_BASE + (uint64_t)service_index * 16;
}

static uint64_t efi_service_gate_address(unsigned service_index)
{
    return VIBTANIUM_EFI_CALL_GATE_BASE +
           (uint64_t)service_index * IA64_BUNDLE_SIZE;
}

static bool efi_gate_service_index(uint64_t gate_ip, unsigned *index)
{
    uint64_t offset;

    if (!efi_gate_address_is_valid_alias(gate_ip)) {
        return false;
    }
    gate_ip = ia64_region_offset(gate_ip);
    if (gate_ip < VIBTANIUM_EFI_CALL_GATE_BASE) {
        return false;
    }

    offset = gate_ip - VIBTANIUM_EFI_CALL_GATE_BASE;
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
        enabled = g_getenv("VIBTANIUM_EFI_TRACE") != NULL;
    }
    return enabled != 0;
}

static bool efi_memory_map_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = efi_trace_enabled() ||
                  g_getenv("VIBTANIUM_EFI_MAP_TRACE") != NULL;
    }
    return enabled != 0;
}

void vibtanium_efi_set_linux_cmdline_append(const char *append)
{
    g_autofree char *trimmed = append ? g_strdup(append) : NULL;

    g_free(efi_linux_cmdline_append);
    efi_linux_cmdline_append = NULL;
    if (trimmed) {
        g_strstrip(trimmed);
        if (trimmed[0]) {
            efi_linux_cmdline_append = g_strdup(trimmed);
        }
    }
    efi_linux_cmdline_append_done = efi_linux_cmdline_append == NULL;
}

static bool ia64_linux_cmdline_contains_token(const char *command_line,
                                              const char *token)
{
    g_autofree char *haystack = g_ascii_strdown(command_line, -1);
    g_autofree char *needle = g_ascii_strdown(token, -1);

    return haystack && needle && strstr(haystack, needle);
}

static bool ia64_linux_cmdline_looks_like_elilo(const char *command_line)
{
    return strstr(command_line, "BOOT_IMAGE=") ||
           ia64_linux_cmdline_contains_token(command_line, "initrd=") ||
           ia64_linux_cmdline_contains_token(command_line, "root=") ||
           strstr(command_line, " ro");
}

static IA64LinuxAppendResult ia64_try_apply_linux_cmdline_append(
    CPUIA64State *env)
{
    g_autoptr(GString) existing = NULL;
    g_autoptr(GString) combined = NULL;
    const char *separator;
    uint64_t boot_param;
    uint64_t command_line;
    size_t prefix_len;
    bool terminated = false;

    if (!efi_linux_cmdline_append || efi_linux_cmdline_append_done) {
        return IA64_LINUX_APPEND_ALREADY_PRESENT;
    }
    if (env->psr & IA64_PSR_IT_BIT) {
        return IA64_LINUX_APPEND_TOO_LATE;
    }

    boot_param = ia64_read_gr(env, 28);
    if (boot_param == 0 || (boot_param & 7) != 0 ||
        boot_param + 8 > EFI_GUEST_RAM_TOP) {
        return IA64_LINUX_APPEND_NOT_READY;
    }

    command_line = cpu_ldq_le_data_ra(env, boot_param, GETPC());
    if (command_line == 0 || command_line >= EFI_GUEST_RAM_TOP) {
        return IA64_LINUX_APPEND_NOT_READY;
    }

    existing = g_string_new(NULL);
    for (unsigned i = 0; i < 1024 && command_line + i < EFI_GUEST_RAM_TOP; i++) {
        uint8_t ch = cpu_ldub_data_ra(env, command_line + i, GETPC());

        if (ch == 0) {
            terminated = true;
            break;
        }
        if (ch < 0x20 || ch > 0x7e) {
            return IA64_LINUX_APPEND_NOT_READY;
        }
        g_string_append_c(existing, (char)ch);
    }

    if (!terminated || existing->len == 0 ||
        !ia64_linux_cmdline_looks_like_elilo(existing->str)) {
        return IA64_LINUX_APPEND_NOT_READY;
    }
    if (strstr(existing->str, efi_linux_cmdline_append)) {
        trace_ia64_linux_cmdline_append(env->ip, boot_param, command_line,
                                        "already-present", existing->str);
        warn_report("vibtanium Linux cmdline append already present: \"%s\"",
                    existing->str);
        return IA64_LINUX_APPEND_ALREADY_PRESENT;
    }

    separator = strstr(existing->str, " -- ");
    combined = g_string_new(NULL);
    if (separator) {
        prefix_len = separator - existing->str;
        g_string_append_len(combined, existing->str, prefix_len);
        g_string_append_c(combined, ' ');
        g_string_append(combined, efi_linux_cmdline_append);
        g_string_append(combined, separator);
    } else {
        g_string_append(combined, existing->str);
        g_string_append_c(combined, ' ');
        g_string_append(combined, efi_linux_cmdline_append);
    }

    if (combined->len + 1 > EFI_LINUX_APPEND_SIZE) {
        trace_ia64_linux_cmdline_append(env->ip, boot_param, command_line,
                                        "too-long", combined->str);
        warn_report("vibtanium Linux cmdline append too long: %zu bytes",
                    combined->len + 1);
        return IA64_LINUX_APPEND_TOO_LATE;
    }

    for (unsigned i = 0; i < combined->len; i++) {
        cpu_stb_data_ra(env, EFI_LINUX_APPEND_BASE + i,
                        (uint8_t)combined->str[i], GETPC());
    }
    cpu_stb_data_ra(env, EFI_LINUX_APPEND_BASE + combined->len, 0, GETPC());
    cpu_stq_le_data_ra(env, boot_param, EFI_LINUX_APPEND_BASE, GETPC());
    trace_ia64_linux_cmdline_append(env->ip, boot_param, command_line,
                                    "applied", combined->str);
    warn_report("vibtanium Linux cmdline append -> \"%s\"", combined->str);
    return IA64_LINUX_APPEND_APPLIED;
}

void vibtanium_efi_maybe_apply_linux_cmdline_append(CPUIA64State *env)
{
    IA64LinuxAppendResult result;

    if (efi_linux_cmdline_append_done) {
        return;
    }

    result = ia64_try_apply_linux_cmdline_append(env);
    if (result != IA64_LINUX_APPEND_NOT_READY) {
        efi_linux_cmdline_append_done = true;
    }
}

bool vibtanium_efi_linux_cmdline_append_pending(void)
{
    return !efi_linux_cmdline_append_done;
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
    if (service_index < EFI_GOP_SERVICE_BASE) {
        *group_index = service_index - EFI_FILE_SERVICE_BASE;
        return "file";
    }
    *group_index = service_index - EFI_GOP_SERVICE_BASE;
    return "gop";
}

static void efi_trace_service(CPUIA64State *env, unsigned service_index,
                              uint64_t result)
{
    unsigned group_index = 0;
    const char *group;
    const char *status = vibtanium_efi_status_name(result);

    group = efi_service_group_name(service_index, &group_index);
    trace_ia64_efi_service(env->ip, group, group_index, status,
                           ia64_read_gr(env, 32), ia64_read_gr(env, 33),
                           ia64_read_gr(env, 34), ia64_read_gr(env, 35),
                           ia64_read_gr(env, 36));
    if (!efi_trace_enabled()) {
        return;
    }

    fprintf(stderr,
            "[efi] ip=0x%016" PRIx64 " service=%s[%u] status=%s "
            "r32=0x%016" PRIx64 " r33=0x%016" PRIx64
            " r34=0x%016" PRIx64 " r35=0x%016" PRIx64
            " r36=0x%016" PRIx64 "\n",
            env->ip, group, group_index, status, ia64_read_gr(env, 32),
            ia64_read_gr(env, 33), ia64_read_gr(env, 34),
            ia64_read_gr(env, 35), ia64_read_gr(env, 36));
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

static uint32_t efi_guest_ldl(CPUIA64State *env, uint64_t address)
{
    return cpu_ldl_le_data_ra(env, address, GETPC());
}

static uint16_t efi_guest_ldw(CPUIA64State *env, uint64_t address)
{
    return cpu_lduw_le_data_ra(env, address, GETPC());
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

static void efi_format_guid(const uint8_t guid[16], char out[37])
{
    g_snprintf(out, 37,
               "%02x%02x%02x%02x-%02x%02x-%02x%02x-"
               "%02x%02x-%02x%02x%02x%02x%02x%02x",
               guid[3], guid[2], guid[1], guid[0],
               guid[5], guid[4], guid[7], guid[6],
               guid[8], guid[9], guid[10], guid[11],
               guid[12], guid[13], guid[14], guid[15]);
}

static int efi_guid_hex_value(char ch)
{
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

static bool efi_parse_guid_byte(const char *guid, unsigned offset,
                                uint8_t *byte)
{
    int hi = efi_guid_hex_value(guid[offset]);
    int lo = efi_guid_hex_value(guid[offset + 1]);

    if (hi < 0 || lo < 0) {
        return false;
    }
    *byte = (hi << 4) | lo;
    return true;
}

static bool efi_parse_guid(const char *guid, uint8_t out[16])
{
    uint8_t canonical[16];
    static const unsigned hex_offsets[16] = {
        0, 2, 4, 6, 9, 11, 14, 16,
        19, 21, 24, 26, 28, 30, 32, 34,
    };

    if (!guid || strlen(guid) != 36 ||
        guid[8] != '-' || guid[13] != '-' ||
        guid[18] != '-' || guid[23] != '-') {
        return false;
    }

    for (unsigned i = 0; i < ARRAY_SIZE(canonical); i++) {
        if (!efi_parse_guid_byte(guid, hex_offsets[i], &canonical[i])) {
            return false;
        }
    }

    out[0] = canonical[3];
    out[1] = canonical[2];
    out[2] = canonical[1];
    out[3] = canonical[0];
    out[4] = canonical[5];
    out[5] = canonical[4];
    out[6] = canonical[7];
    out[7] = canonical[6];
    memcpy(out + 8, canonical + 8, 8);
    return true;
}

static char *efi_read_utf16_name(CPUIA64State *env, uint64_t address)
{
    g_autofree gunichar2 *chars = NULL;
    GError *err = NULL;
    char *name;
    unsigned count = 0;

    if (address == 0) {
        return NULL;
    }

    chars = g_new0(gunichar2, EFI_MAX_VAR_NAME_CHARS + 1);
    for (; count < EFI_MAX_VAR_NAME_CHARS; count++) {
        chars[count] = efi_guest_ldw(env, address + count * 2);
        if (chars[count] == 0) {
            break;
        }
    }
    if (count == EFI_MAX_VAR_NAME_CHARS) {
        return NULL;
    }

    name = g_utf16_to_utf8(chars, count, NULL, NULL, &err);
    g_clear_error(&err);
    return name;
}

static uint64_t efi_utf16_name_size(const char *name, uint64_t *size)
{
    g_autofree gunichar2 *chars = NULL;
    GError *err = NULL;
    glong written = 0;

    chars = g_utf8_to_utf16(name ? name : "", -1, NULL, &written, &err);
    if (!chars) {
        g_clear_error(&err);
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }
    *size = (uint64_t)(written + 1) * 2;
    return VIBTANIUM_EFI_SUCCESS;
}

static bool efi_write_utf16_name(CPUIA64State *env, uint64_t address,
                                 const char *name)
{
    g_autofree gunichar2 *chars = NULL;
    GError *err = NULL;
    glong written = 0;

    chars = g_utf8_to_utf16(name ? name : "", -1, NULL, &written, &err);
    if (!chars) {
        g_clear_error(&err);
        return false;
    }

    for (glong i = 0; i < written; i++) {
        efi_guest_stw(env, address + i * 2, chars[i]);
    }
    efi_guest_stw(env, address + written * 2, 0);
    return true;
}

static void efi_guest_write_guid(CPUIA64State *env, uint64_t address,
                                 const char *guid)
{
    uint8_t bytes[16];

    if (!efi_parse_guid(guid, bytes)) {
        memset(bytes, 0, sizeof(bytes));
    }
    efi_guest_write_bytes(env, address, bytes, sizeof(bytes));
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
        next > VIBTANIUM_EFI_POOL_BASE + VIBTANIUM_EFI_POOL_SIZE) {
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
    uint32_t recorded_type;
    uint64_t address;
    uint64_t max_address = EFI_GUEST_RAM_TOP - 1;

    if (memory == 0 || pages == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    switch (allocate_type) {
    case EFI_ALLOCATE_ANY_PAGES:
        if (!efi_find_free_pages(pages, max_address, &address)) {
            return VIBTANIUM_EFI_OUT_OF_RESOURCES;
        }
        break;
    case EFI_ALLOCATE_MAX_ADDRESS:
        max_address = efi_guest_ldq(env, memory);
        if (!efi_find_free_pages(pages, max_address, &address)) {
            efi_guest_stq(env, memory, 0);
            return VIBTANIUM_EFI_OUT_OF_RESOURCES;
        }
        break;
    case EFI_ALLOCATE_ADDRESS:
        address = efi_guest_ldq(env, memory);
        if (!efi_page_range_available(address, pages)) {
            return VIBTANIUM_EFI_NOT_FOUND;
        }
        break;
    default:
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    recorded_type = vibtanium_efi_page_allocation_memory_type(allocate_type,
                                                              memory_type);
    if (!efi_record_page_allocation(address, pages, recorded_type)) {
        return VIBTANIUM_EFI_OUT_OF_RESOURCES;
    }
    if (efi_memory_map_trace_enabled()) {
        fprintf(stderr,
                "[efi-alloc] type=%" PRIu64 " memory-type=%" PRIu64
                " recorded-type=%u pages=0x%016" PRIx64
                " phys=0x%016" PRIx64 "\n",
                allocate_type, memory_type, recorded_type, pages, address);
    }
    efi_guest_stq(env, memory, address);
    return VIBTANIUM_EFI_SUCCESS;
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
            return VIBTANIUM_EFI_SUCCESS;
        }
    }

    return VIBTANIUM_EFI_INVALID_PARAMETER;
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
        if (efi_memory_map_trace_enabled()) {
            fprintf(stderr,
                    "[efi-map] index=%u type=%u phys=0x%016" PRIx64
                    " pages=0x%016" PRIx64 " attr=0x%016" PRIx64 "\n",
                    index, range->type, range->address, range->pages,
                    range->attributes);
        }
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

static unsigned efi_emit_runtime_and_loader(CPUIA64State *env, uint64_t map,
                                            unsigned index,
                                            const EfiMemoryRange *runtime,
                                            const EfiMemoryRange *loader,
                                            bool *loader_emitted)
{
    uint64_t runtime_end;
    uint64_t loader_end;

    *loader_emitted = false;

    if (!efi_page_range_end(runtime->address, runtime->pages, &runtime_end) ||
        !efi_page_range_end(loader->address, loader->pages, &loader_end) ||
        loader->address >= runtime_end ||
        loader_end <= runtime->address) {
        return efi_emit_memory_descriptor(env, map, index, runtime);
    }

    if (runtime->address < loader->address) {
        EfiMemoryRange before = *runtime;

        before.pages = (loader->address - runtime->address) / EFI_PAGE_SIZE;
        index = efi_emit_memory_descriptor(env, map, index, &before);
    }

    index = efi_emit_memory_descriptor(env, map, index, loader);
    *loader_emitted = true;

    if (loader_end < runtime_end) {
        EfiMemoryRange after = *runtime;

        after.address = loader_end;
        after.pages = (runtime_end - loader_end) / EFI_PAGE_SIZE;
        index = efi_emit_memory_descriptor(env, map, index, &after);
    }

    return index;
}

static unsigned efi_emit_memory_map(CPUIA64State *env, uint64_t map)
{
    unsigned index = 0;
    bool loader_emitted = false;
    const EfiMemoryRange loader_image = {
        .type = EFI_LOADER_CODE,
        .address = efi_loaded_image_base,
        .pages = efi_loaded_image_pages,
        .attributes = EFI_MEMORY_WB,
    };

    for (unsigned i = 0; i < ARRAY_SIZE(efi_memory_map_records); i++) {
        const EfiMemoryMapRecord *record = &efi_memory_map_records[i];
        bool range_loader_emitted;

        switch (record->kind) {
        case EFI_MEMORY_MAP_RECORD_DIRECT:
            index = efi_emit_memory_descriptor(env, map, index,
                                               &record->range);
            break;
        case EFI_MEMORY_MAP_RECORD_CONVENTIONAL_SPLIT:
            index = efi_emit_split_conventional(env, map, index,
                                                record->range.address,
                                                record->range.pages);
            break;
        case EFI_MEMORY_MAP_RECORD_RUNTIME_WITH_LOADER:
            index = efi_emit_runtime_and_loader(env, map, index,
                                                &record->range,
                                                &loader_image,
                                                &range_loader_emitted);
            loader_emitted |= range_loader_emitted;
            break;
        case EFI_MEMORY_MAP_RECORD_LOADER_IF_NEEDED:
            if (!loader_emitted) {
                index = efi_emit_memory_descriptor(env, map, index,
                                                   &loader_image);
            }
            break;
        }
    }

    return index;
}

void vibtanium_efi_register_loaded_image(uint64_t image_base,
                                         uint64_t image_size)
{
    uint64_t aligned_base;
    uint64_t image_end;
    uint64_t aligned_end;

    if (image_size == 0 || image_base > UINT64_MAX - image_size) {
        efi_loaded_image_base = VIBTANIUM_EFI_APP_BASE;
        efi_loaded_image_pages = EFI_DEFAULT_LOADER_IMAGE_PAGES;
        efi_memory_map_key++;
        return;
    }

    image_end = image_base + image_size;
    if (image_end > UINT64_MAX - (EFI_PAGE_SIZE - 1)) {
        efi_loaded_image_base = VIBTANIUM_EFI_APP_BASE;
        efi_loaded_image_pages = EFI_DEFAULT_LOADER_IMAGE_PAGES;
        efi_memory_map_key++;
        return;
    }

    aligned_base = image_base & ~(EFI_PAGE_SIZE - 1);
    aligned_end = QEMU_ALIGN_UP(image_end, EFI_PAGE_SIZE);
    if (image_base == VIBTANIUM_EFI_APP_BASE) {
        efi_loaded_image_base = VIBTANIUM_EFI_APP_BASE;
        efi_loaded_image_pages = EFI_DEFAULT_LOADER_IMAGE_PAGES;
    } else {
        efi_loaded_image_base = aligned_base;
        efi_loaded_image_pages = (aligned_end - aligned_base) / EFI_PAGE_SIZE;
    }
    efi_memory_map_key++;
}

static uint64_t efi_get_memory_map(CPUIA64State *env)
{
    uint64_t memory_map_size = ia64_read_gr(env, 32);
    uint64_t memory_map = ia64_read_gr(env, 33);
    uint64_t map_key = ia64_read_gr(env, 34);
    uint64_t descriptor_size = ia64_read_gr(env, 35);
    uint64_t descriptor_version = ia64_read_gr(env, 36);
    uint64_t provided = 0;
    uint64_t required = (uint64_t)efi_emit_memory_map(env, 0) *
                        EFI_MEMORY_DESCRIPTOR_SIZE;

    if (memory_map_size == 0 || map_key == 0 || descriptor_size == 0 ||
        descriptor_version == 0) {
        trace_ia64_efi_memory_map(env->ip, provided, required,
                                  efi_memory_map_key, "invalid-parameter");
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    provided = efi_guest_ldq(env, memory_map_size);
    efi_guest_stq(env, memory_map_size, required);
    efi_guest_stq(env, descriptor_size, EFI_MEMORY_DESCRIPTOR_SIZE);
    efi_guest_stl(env, descriptor_version, EFI_MEMORY_DESCRIPTOR_VERSION);

    if (memory_map == 0 || provided < required) {
        trace_ia64_efi_memory_map(env->ip, provided, required,
                                  efi_memory_map_key, "buffer-too-small");
        return VIBTANIUM_EFI_BUFFER_TOO_SMALL;
    }

    efi_emit_memory_map(env, memory_map);
    efi_guest_stq(env, map_key, efi_memory_map_key);
    trace_ia64_efi_memory_map(env->ip, provided, required,
                              efi_memory_map_key, "success");
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_exit_boot_services(CPUIA64State *env)
{
    uint64_t image_handle = ia64_read_gr(env, 32);
    uint64_t map_key = ia64_read_gr(env, 33);

    if (image_handle != VIBTANIUM_EFI_IMAGE_HANDLE ||
        map_key != efi_memory_map_key) {
        trace_ia64_efi_exit_boot_services(env->ip, image_handle, map_key,
                                          efi_memory_map_key,
                                          "invalid-parameter");
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    trace_ia64_efi_exit_boot_services(env->ip, image_handle, map_key,
                                      efi_memory_map_key, "success");
    vibtanium_efi_console_set_input_active(false);
    vibtanium_efi_console_set_vga_text_active(true);
    return VIBTANIUM_EFI_SUCCESS;
}

void vibtanium_efi_register_boot_media(
    const VibtaniumEfiBlockDevice *boot_media)
{
    for (unsigned i = 0; i < EFI_MAX_FILE_HANDLES; i++) {
        g_clear_pointer(&efi_guest_files[i].data, g_free);
        memset(&efi_guest_files[i], 0, sizeof(efi_guest_files[i]));
    }
    memset(efi_installed_protocols, 0, sizeof(efi_installed_protocols));
    memset(efi_guest_events, 0, sizeof(efi_guest_events));
    memset(efi_page_allocations, 0, sizeof(efi_page_allocations));
    efi_pool_next = VIBTANIUM_EFI_POOL_BASE;
    efi_page_alloc_next = EFI_PAGE_ALLOC_BASE;
    efi_memory_map_key = 1;
    efi_dynamic_handle_next = UINT64_C(0x00073000);
    efi_next_event_handle = VIBTANIUM_EFI_CON_IN_WAIT_EVENT + 1;
    efi_loaded_image_base = VIBTANIUM_EFI_APP_BASE;
    efi_loaded_image_pages = EFI_DEFAULT_LOADER_IMAGE_PAGES;
    efi_high_monotonic_count = 0;
    efi_conin_reset();

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
    if (handle == VIBTANIUM_EFI_IMAGE_HANDLE &&
        efi_guid_bytes_equal(guid, efi_loaded_image_guid)) {
        return VIBTANIUM_EFI_LOADED_IMAGE;
    }

    if (handle != VIBTANIUM_EFI_BOOT_DEVICE_HANDLE) {
        return 0;
    }

    if (efi_guid_bytes_equal(guid, efi_simple_text_output_guid)) {
        return VIBTANIUM_EFI_CON_OUT;
    }
    if (efi_guid_bytes_equal(guid, efi_simple_text_input_guid)) {
        return VIBTANIUM_EFI_CON_IN;
    }
    if (efi_guid_bytes_equal(guid, efi_device_path_guid)) {
        return VIBTANIUM_EFI_DEVICE_PATH;
    }
    if (efi_guid_bytes_equal(guid, efi_graphics_output_guid)) {
        return VIBTANIUM_EFI_GOP;
    }
    if (efi_boot_media_valid && efi_guid_bytes_equal(guid, efi_block_io_guid)) {
        return VIBTANIUM_EFI_BLOCK_IO;
    }
    if (efi_boot_media_valid &&
        efi_guid_bytes_equal(guid, efi_simple_file_system_guid)) {
        return VIBTANIUM_EFI_SIMPLE_FILE_SYSTEM;
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
        return VIBTANIUM_EFI_SUCCESS;
    }

    installed = efi_find_installed_protocol(handle, guid);
    if (installed) {
        *interface = installed->interface;
        return VIBTANIUM_EFI_SUCCESS;
    }

    *interface = 0;
    return VIBTANIUM_EFI_NOT_FOUND;
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
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    efi_guest_read_guid(env, protocol, guid);
    status = efi_resolve_interface(handle, guid, &interface_address);
    if (status == VIBTANIUM_EFI_SUCCESS) {
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
                              VIBTANIUM_EFI_IMAGE_HANDLE);
    }

    if (efi_guid_bytes_equal(guid, efi_simple_text_output_guid) ||
        efi_guid_bytes_equal(guid, efi_simple_text_input_guid) ||
        efi_guid_bytes_equal(guid, efi_device_path_guid) ||
        efi_guid_bytes_equal(guid, efi_graphics_output_guid) ||
        (efi_boot_media_valid &&
         (efi_guid_bytes_equal(guid, efi_block_io_guid) ||
          efi_guid_bytes_equal(guid, efi_simple_file_system_guid)))) {
        efi_add_unique_handle(handles, capacity, &count,
                              VIBTANIUM_EFI_BOOT_DEVICE_HANDLE);
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
        return VIBTANIUM_EFI_UNSUPPORTED;
    }

    count = efi_locate_handles_for_protocol(env, protocol, handles,
                                            ARRAY_SIZE(handles));
    required = count * sizeof(uint64_t);
    provided = efi_guest_ldq(env, size_ptr);
    efi_guest_stq(env, size_ptr, required);
    if (count == 0) {
        return VIBTANIUM_EFI_NOT_FOUND;
    }

    if (buffer == 0 || provided < required) {
        return VIBTANIUM_EFI_BUFFER_TOO_SMALL;
    }

    for (unsigned i = 0; i < count; i++) {
        efi_guest_stq(env, buffer + i * sizeof(uint64_t), handles[i]);
    }
    return VIBTANIUM_EFI_SUCCESS;
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
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    handle = efi_guest_ldq(env, handle_ptr);
    if (handle == 0) {
        handle = efi_dynamic_handle_next++;
        efi_guest_stq(env, handle_ptr, handle);
    }
    efi_guest_read_guid(env, protocol, guid);
    if (efi_preinstalled_interface(handle, guid) != 0 ||
        efi_find_installed_protocol(handle, guid) != NULL) {
        return VIBTANIUM_EFI_ACCESS_DENIED;
    }

    for (unsigned i = 0; i < EFI_MAX_INSTALLED_PROTOCOLS; i++) {
        if (!efi_installed_protocols[i].in_use) {
            efi_installed_protocols[i].in_use = true;
            efi_installed_protocols[i].handle = handle;
            memcpy(efi_installed_protocols[i].guid, guid, sizeof(guid));
            efi_installed_protocols[i].interface = interface;
            (void)interface_type;
            return VIBTANIUM_EFI_SUCCESS;
        }
    }

    return VIBTANIUM_EFI_OUT_OF_RESOURCES;
}

static uint64_t efi_uninstall_protocol_interface(CPUIA64State *env)
{
    uint64_t handle = ia64_read_gr(env, 32);
    uint64_t protocol = ia64_read_gr(env, 33);
    uint64_t interface = ia64_read_gr(env, 34);
    uint8_t guid[16];
    EfiInstalledProtocol *installed;

    if (handle == 0 || protocol == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    efi_guest_read_guid(env, protocol, guid);
    installed = efi_find_installed_protocol(handle, guid);
    if (!installed || (interface != 0 && installed->interface != interface)) {
        return VIBTANIUM_EFI_NOT_FOUND;
    }

    memset(installed, 0, sizeof(*installed));
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_locate_protocol(CPUIA64State *env)
{
    uint64_t protocol = ia64_read_gr(env, 32);
    uint64_t interface = ia64_read_gr(env, 34);
    uint64_t handles[8];
    unsigned count;

    if (protocol == 0 || interface == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    count = efi_locate_handles_for_protocol(env, protocol, handles,
                                            ARRAY_SIZE(handles));
    if (count == 0) {
        efi_guest_stq(env, interface, 0);
        return VIBTANIUM_EFI_NOT_FOUND;
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
        return VIBTANIUM_EFI_INVALID_PARAMETER;
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
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    bytes = g_malloc(size ? size : 1);
    efi_guest_read_bytes(env, data, bytes, size);
    efi_guest_stl(env, crc_ptr, efi_crc32(bytes, size));
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_copy_mem(CPUIA64State *env)
{
    uint64_t destination = ia64_read_gr(env, 32);
    uint64_t source = ia64_read_gr(env, 33);
    uint64_t length = ia64_read_gr(env, 34);
    g_autofree uint8_t *bytes = NULL;

    if (length > EFI_MAX_FILE_READ_BYTES) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    bytes = g_malloc(length ? length : 1);
    efi_guest_read_bytes(env, source, bytes, length);
    efi_guest_write_bytes(env, destination, bytes, length);
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_set_mem(CPUIA64State *env)
{
    uint64_t buffer = ia64_read_gr(env, 32);
    uint64_t size = ia64_read_gr(env, 33);
    uint8_t value = ia64_read_gr(env, 34);

    if (size > EFI_MAX_FILE_READ_BYTES) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    for (uint64_t i = 0; i < size; i++) {
        efi_guest_stb(env, buffer + i, value);
    }
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_allocate_pool(CPUIA64State *env)
{
    uint64_t size = ia64_read_gr(env, 33);
    uint64_t buffer = ia64_read_gr(env, 34);
    uint64_t address;

    if (buffer == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    address = efi_pool_alloc_raw(size);
    if (address == 0) {
        efi_guest_stq(env, buffer, 0);
        return VIBTANIUM_EFI_OUT_OF_RESOURCES;
    }

    efi_guest_stq(env, buffer, address);
    return VIBTANIUM_EFI_SUCCESS;
}

static void efi_write_file_protocol(CPUIA64State *env, uint64_t address)
{
    efi_guest_stq(env, address, VIBTANIUM_EFI_PROTOCOL_REVISION);
    for (unsigned i = 0; i < VIBTANIUM_EFI_FILE_SERVICE_COUNT; i++) {
        efi_guest_stq(env, address + 8 + i * sizeof(uint64_t),
                      VIBTANIUM_EFI_DESCRIPTOR_BASE +
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

static uint64_t efi_storage_status_to_efi(VibtaniumEfiStorageStatus status)
{
    switch (status) {
    case VIBTANIUM_EFI_STORAGE_OK:
        return VIBTANIUM_EFI_SUCCESS;
    case VIBTANIUM_EFI_STORAGE_READ_ERROR:
    case VIBTANIUM_EFI_STORAGE_INVALID_FILESYSTEM:
        return VIBTANIUM_EFI_DEVICE_ERROR;
    case VIBTANIUM_EFI_STORAGE_UNSUPPORTED:
        return VIBTANIUM_EFI_UNSUPPORTED;
    case VIBTANIUM_EFI_STORAGE_NO_ISO9660:
    case VIBTANIUM_EFI_STORAGE_NOT_FOUND:
    default:
        return VIBTANIUM_EFI_NOT_FOUND;
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

    if (this_ptr != VIBTANIUM_EFI_SIMPLE_FILE_SYSTEM || root_out == 0 ||
        !efi_boot_media_valid) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    root = efi_create_file_node(env, "", true, NULL, 0);
    if (!root) {
        return VIBTANIUM_EFI_OUT_OF_RESOURCES;
    }

    efi_guest_stq(env, root_out, root->address);
    return VIBTANIUM_EFI_SUCCESS;
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
    VibtaniumEfiStorageReport report = {
        .status = VIBTANIUM_EFI_STORAGE_NOT_FOUND,
        .message = "path has not been opened",
    };
    g_autofree char *source = g_malloc0(384);
    uint8_t *data = NULL;
    size_t size = 0;
    bool is_directory = false;
    EfiGuestFile *file;

    if (!parent || new_handle_out == 0 || name_ptr == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }
    if ((open_mode & UINT64_C(0x2)) != 0) {
        return VIBTANIUM_EFI_WRITE_PROTECTED;
    }

    efi_read_utf16_path(env, name_ptr, name, sizeof(name));
    efi_join_normalized_path(parent->path, name, path, sizeof(path));
    g_snprintf(storage_path, sizeof(storage_path), "/%s", path);
    trace_ia64_efi_file_open_request(env->ip, this_ptr, new_handle_out, name,
                                     open_mode, parent->path, storage_path);

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
        return VIBTANIUM_EFI_NOT_FOUND;
    }

    if (!vibtanium_efi_media_open_path(&efi_boot_media, storage_path,
                                       &is_directory, &data, &size, source,
                                       384, &report, &local_err)) {
        uint64_t status = efi_storage_status_to_efi(report.status);

        trace_ia64_efi_file_open_result(
            env->ip, storage_path, vibtanium_efi_storage_status_name(report.status),
            0, 0, report.message);
        if (efi_trace_enabled()) {
            fprintf(stderr, "[efi-file] open path='%s' status=%s\n",
                    storage_path,
                    vibtanium_efi_storage_status_name(report.status));
        }
        error_free(local_err);
        return status;
    }

    if (is_directory) {
        file = efi_create_file_node(env, path, true, NULL, 0);
        if (!file) {
            return VIBTANIUM_EFI_OUT_OF_RESOURCES;
        }

        efi_guest_stq(env, new_handle_out, file->address);
        trace_ia64_efi_file_open_result(env->ip, storage_path,
                                        "success-directory",
                                        file->address, 0, source);
        if (efi_trace_enabled()) {
            fprintf(stderr, "[efi-file] open dir='%s' handle=0x%016"
                    PRIx64 "\n",
                    path, file->address);
        }
        return VIBTANIUM_EFI_SUCCESS;
    }

    if (efi_trace_enabled()) {
        fprintf(stderr, "[efi-file] open path='%s' size=0x%" PRIx64
                " source=%s\n",
                storage_path, (uint64_t)size, source);
    }

    file = efi_create_file_node(env, path, false, data, size);
    if (!file) {
        efi_guest_stq(env, new_handle_out, 0);
        return VIBTANIUM_EFI_OUT_OF_RESOURCES;
    }

    efi_guest_stq(env, new_handle_out, file->address);
    trace_ia64_efi_file_open_result(env->ip, storage_path, "success",
                                    file->address, size, source);
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_file_close(CPUIA64State *env)
{
    EfiGuestFile *file = efi_find_file(ia64_read_gr(env, 32));

    if (file) {
        g_clear_pointer(&file->data, g_free);
        memset(file, 0, sizeof(*file));
    }
    return VIBTANIUM_EFI_SUCCESS;
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
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }
    if (file->is_directory) {
        return VIBTANIUM_EFI_UNSUPPORTED;
    }

    requested = efi_guest_ldq(env, size_ptr);
    if (requested > EFI_MAX_FILE_READ_BYTES) {
        requested = EFI_MAX_FILE_READ_BYTES;
    }
    remaining = file->position < file->size ? file->size - file->position : 0;
    actual = MIN(requested, remaining);
    if (actual > 0) {
        if (buffer == 0) {
            return VIBTANIUM_EFI_INVALID_PARAMETER;
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
    trace_ia64_efi_file_read(env->ip, file->path, requested, actual,
                             file->position);
    efi_guest_stq(env, size_ptr, actual);
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_file_get_position(CPUIA64State *env)
{
    EfiGuestFile *file = efi_find_file(ia64_read_gr(env, 32));
    uint64_t pos_out = ia64_read_gr(env, 33);

    if (!file || pos_out == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }
    if (file->is_directory) {
        return VIBTANIUM_EFI_UNSUPPORTED;
    }
    efi_guest_stq(env, pos_out, file->position);
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_file_set_position(CPUIA64State *env)
{
    EfiGuestFile *file = efi_find_file(ia64_read_gr(env, 32));
    uint64_t position = ia64_read_gr(env, 33);

    if (!file) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }
    if (file->is_directory) {
        return position == 0 ? VIBTANIUM_EFI_SUCCESS
                             : VIBTANIUM_EFI_UNSUPPORTED;
    }
    if (position == UINT64_MAX) {
        position = file->size;
    }
    if (position > file->size) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }
    file->position = position;
    return VIBTANIUM_EFI_SUCCESS;
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
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    efi_guest_read_guid(env, info_type, guid);
    if (!efi_guid_bytes_equal(guid, efi_file_info_guid)) {
        return VIBTANIUM_EFI_UNSUPPORTED;
    }

    name = efi_file_base_name(file->path);
    name_bytes = (strlen(name) + 1) * 2;
    required = 80 + name_bytes;
    provided = efi_guest_ldq(env, size_ptr);
    efi_guest_stq(env, size_ptr, required);
    if (buffer == 0 || provided < required) {
        return VIBTANIUM_EFI_BUFFER_TOO_SMALL;
    }

    for (uint64_t i = 0; i < required; i++) {
        efi_guest_stb(env, buffer + i, 0);
    }
    efi_guest_stq(env, buffer, required);
    efi_guest_stq(env, buffer + 8, file->size);
    efi_guest_stq(env, buffer + 16, file->size);
    efi_guest_stq(env, buffer + 72, file->is_directory ? 0x10 : 0x1);
    efi_write_utf16_ascii(env, buffer + 80, name);
    return VIBTANIUM_EFI_SUCCESS;
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
        return VIBTANIUM_EFI_WRITE_PROTECTED;
    case 3:
        return efi_file_read(env);
    case 4:
        return VIBTANIUM_EFI_WRITE_PROTECTED;
    case 5:
        return efi_file_get_position(env);
    case 6:
        return efi_file_set_position(env);
    case 7:
        return efi_file_get_info(env);
    case 8:
        return VIBTANIUM_EFI_WRITE_PROTECTED;
    case 9:
        return VIBTANIUM_EFI_SUCCESS;
    default:
        return VIBTANIUM_EFI_UNSUPPORTED;
    }
}

static uint64_t efi_dispatch_simple_file_system(CPUIA64State *env,
                                                unsigned index)
{
    switch (index) {
    case 0:
        return efi_simplefs_open_volume(env);
    default:
        return VIBTANIUM_EFI_UNSUPPORTED;
    }
}

static uint64_t efi_dispatch_block_io(CPUIA64State *env, unsigned index)
{
    uint64_t this_ptr = ia64_read_gr(env, 32);
    uint32_t block_size = efi_boot_media.block_size
        ? efi_boot_media.block_size
        : 2048;

    if (this_ptr != VIBTANIUM_EFI_BLOCK_IO || !efi_boot_media_valid) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    switch (index) {
    case 0:
        return VIBTANIUM_EFI_SUCCESS;
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
            return VIBTANIUM_EFI_INVALID_PARAMETER;
        }
        data = g_malloc(buffer_size ? buffer_size : 1);
        ret = efi_boot_media.read(efi_boot_media.opaque, offset, buffer_size,
                                  data, &local_err);
        if (ret < 0) {
            error_free(local_err);
            return VIBTANIUM_EFI_DEVICE_ERROR;
        }
        if (buffer_size != 0) {
            efi_guest_write_bytes(env, buffer, data, buffer_size);
        }
        return VIBTANIUM_EFI_SUCCESS;
    }
    case 2:
        return VIBTANIUM_EFI_WRITE_PROTECTED;
    case 3:
        return VIBTANIUM_EFI_SUCCESS;
    default:
        return VIBTANIUM_EFI_UNSUPPORTED;
    }
}

static EfiGuestEvent *efi_find_event(uint64_t handle)
{
    if (handle == VIBTANIUM_EFI_CON_IN_WAIT_EVENT) {
        static EfiGuestEvent conin_event;

        conin_event = (EfiGuestEvent) {
            .in_use = true,
            .handle = VIBTANIUM_EFI_CON_IN_WAIT_EVENT,
            .type = 0,
            .signaled = efi_conin_has_key(),
            .timer_active = false,
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
    uint64_t raw_type = ia64_read_gr(env, 32);
    uint64_t event_out = ia64_read_gr(env, 36);
    uint32_t type;

    if (!vibtanium_efi_decode_uint32_arg(raw_type, &type) ||
        event_out == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
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
        return VIBTANIUM_EFI_SUCCESS;
    }

    efi_guest_stq(env, event_out, 0);
    return VIBTANIUM_EFI_OUT_OF_RESOURCES;
}

static uint64_t efi_itc_now(CPUIA64State *env)
{
    ia64_itc_sync(env);
    return env->ar[IA64_AR_ITC];
}

static uint64_t efi_set_timer(CPUIA64State *env)
{
    uint64_t handle = ia64_read_gr(env, 32);
    uint64_t timer_type = ia64_read_gr(env, 33);
    uint64_t trigger_time = ia64_read_gr(env, 34);
    EfiGuestEvent *event = efi_find_event(handle);

    if (!event || handle == VIBTANIUM_EFI_CON_IN_WAIT_EVENT) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    switch (timer_type) {
    case EFI_TIMER_CANCEL:
        event->timer_active = false;
        event->timer_periodic = false;
        event->timer_period = 0;
        event->timer_due = 0;
        event->signaled = false;
        return VIBTANIUM_EFI_SUCCESS;
    case EFI_TIMER_PERIODIC:
    case EFI_TIMER_RELATIVE:
        /* UEFI trigger times are in 100 ns units; event state is ITC ticks. */
        event->timer_active = true;
        event->timer_periodic = timer_type == EFI_TIMER_PERIODIC;
        event->timer_period = trigger_time * IA64_ITC_TICKS_PER_100NS;
        event->timer_due = efi_itc_now(env) +
                           trigger_time * IA64_ITC_TICKS_PER_100NS;
        event->signaled = trigger_time == 0;
        return VIBTANIUM_EFI_SUCCESS;
    default:
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }
}

static bool efi_event_timer_due(CPUIA64State *env, EfiGuestEvent *event)
{
    return event->timer_active &&
           vibtanium_efi_timer_due(efi_itc_now(env), event->timer_due);
}

static void efi_event_consume(CPUIA64State *env, EfiGuestEvent *event)
{
    if (!event || event->handle == VIBTANIUM_EFI_CON_IN_WAIT_EVENT) {
        return;
    }

    if (efi_event_timer_due(env, event)) {
        if (event->timer_periodic && event->timer_period != 0) {
            do {
                event->timer_due += event->timer_period;
            } while (vibtanium_efi_timer_due(efi_itc_now(env),
                                             event->timer_due));
        } else {
            event->timer_active = false;
            event->timer_periodic = false;
            event->timer_period = 0;
            event->timer_due = 0;
        }
    }
    event->signaled = false;
}

static bool efi_event_is_ready(CPUIA64State *env, EfiGuestEvent *event)
{
    if (!event) {
        return false;
    }
    if (event->handle == VIBTANIUM_EFI_CON_IN_WAIT_EVENT) {
        return efi_conin_has_key();
    }
    if (efi_event_timer_due(env, event)) {
        event->signaled = true;
    }
    return event->signaled;
}

static bool efi_timer_before(uint64_t now, uint64_t left, uint64_t right)
{
    return left - now < right - now;
}

static bool efi_event_next_timer(CPUIA64State *env, EfiGuestEvent *event,
                                 uint64_t *due)
{
    if (!event || event->handle == VIBTANIUM_EFI_CON_IN_WAIT_EVENT ||
        !event->timer_active) {
        return false;
    }

    if (efi_event_timer_due(env, event)) {
        *due = efi_itc_now(env);
    } else {
        *due = event->timer_due;
    }
    return true;
}

static void efi_write_event_index(CPUIA64State *env, uint64_t index_out,
                                  uint64_t index)
{
    efi_guest_stq(env, index_out, index);
}

static bool efi_wait_timer_candidate(CPUIA64State *env, EfiGuestEvent *event,
                                     uint64_t index, uint64_t *timer_index,
                                     uint64_t *timer_due)
{
    uint64_t due;

    if (!efi_event_next_timer(env, event, &due)) {
        return false;
    }

    if (*timer_index == UINT64_MAX ||
        efi_timer_before(efi_itc_now(env), due, *timer_due)) {
        *timer_index = index;
        *timer_due = due;
    }
    return true;
}

static void efi_block_until_timer(CPUIA64State *env, uint64_t timer_due)
{
    /*
     * Warp guest time forward to the deadline instead of making the caller
     * spin; boot loaders wait out multi-second delays this way.
     */
    ia64_itc_warp_to(env, timer_due);
}

static uint64_t efi_wait_ready_event(CPUIA64State *env, uint64_t count,
                                     uint64_t events, uint64_t index_out,
                                     bool *found_ready,
                                     uint64_t *timer_index,
                                     uint64_t *timer_due)
{
    for (uint64_t i = 0; i < count; i++) {
        uint64_t handle = efi_guest_ldq(env, events + i * sizeof(uint64_t));
        EfiGuestEvent *event = efi_find_event(handle);

        if (!event) {
            return VIBTANIUM_EFI_INVALID_PARAMETER;
        }
        if (efi_event_is_ready(env, event)) {
            efi_write_event_index(env, index_out, i);
            efi_event_consume(env, event);
            *found_ready = true;
            return VIBTANIUM_EFI_SUCCESS;
        }
        efi_wait_timer_candidate(env, event, i, timer_index, timer_due);
    }
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_wait_for_event(CPUIA64State *env)
{
    uint64_t count = ia64_read_gr(env, 32);
    uint64_t events = ia64_read_gr(env, 33);
    uint64_t index_out = ia64_read_gr(env, 34);
    uint64_t timer_index = UINT64_MAX;
    uint64_t timer_due = 0;
    bool found_ready = false;
    uint64_t status;

    if (count == 0 || count > EFI_MAX_EVENTS || events == 0 ||
        index_out == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    status = efi_wait_ready_event(env, count, events, index_out,
                                  &found_ready, &timer_index, &timer_due);
    if (status != VIBTANIUM_EFI_SUCCESS || found_ready) {
        return status;
    }

    if (timer_index != UINT64_MAX) {
        uint64_t handle;
        EfiGuestEvent *event;

        efi_block_until_timer(env, timer_due);
        handle = efi_guest_ldq(env, events + timer_index * sizeof(uint64_t));
        event = efi_find_event(handle);
        if (!event || !efi_event_is_ready(env, event)) {
            return VIBTANIUM_EFI_NOT_READY;
        }
        efi_write_event_index(env, index_out, timer_index);
        efi_event_consume(env, event);
        return VIBTANIUM_EFI_SUCCESS;
    }

    return VIBTANIUM_EFI_NOT_READY;
}

static uint64_t efi_signal_event(CPUIA64State *env)
{
    EfiGuestEvent *event = efi_find_event(ia64_read_gr(env, 32));

    if (!event || event->handle == VIBTANIUM_EFI_CON_IN_WAIT_EVENT) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    event->signaled = true;
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_close_event(CPUIA64State *env)
{
    EfiGuestEvent *event = efi_find_event(ia64_read_gr(env, 32));

    if (!event || event->handle == VIBTANIUM_EFI_CON_IN_WAIT_EVENT) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    memset(event, 0, sizeof(*event));
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_check_event(CPUIA64State *env)
{
    EfiGuestEvent *event = efi_find_event(ia64_read_gr(env, 32));

    if (!event) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }
    return efi_event_is_ready(env, event) ? VIBTANIUM_EFI_SUCCESS
                                          : VIBTANIUM_EFI_NOT_READY;
}

static uint64_t efi_dispatch_boot_service(CPUIA64State *env, unsigned index)
{
    switch (index) {
    case 0:
        return 4; /* RaiseTPL returns the previous TPL, not EFI_STATUS. */
    case 1:
    case 6:
    case VIBTANIUM_EFI_BOOT_STALL_INDEX:
    case VIBTANIUM_EFI_BOOT_SET_WATCHDOG_INDEX:
        return VIBTANIUM_EFI_SUCCESS;
    case VIBTANIUM_EFI_BOOT_ALLOCATE_PAGES_INDEX:
        return efi_allocate_pages(env);
    case VIBTANIUM_EFI_BOOT_FREE_PAGES_INDEX:
        return efi_free_pages(env);
    case VIBTANIUM_EFI_BOOT_GET_MEMORY_MAP_INDEX:
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
    case VIBTANIUM_EFI_BOOT_INSTALL_PROTOCOL_INDEX:
        return efi_install_protocol_interface(env);
    case VIBTANIUM_EFI_BOOT_UNINSTALL_PROTOCOL_INDEX:
        return efi_uninstall_protocol_interface(env);
    case VIBTANIUM_EFI_BOOT_HANDLE_PROTOCOL_INDEX:
        return efi_handle_protocol(env);
    case VIBTANIUM_EFI_BOOT_LOCATE_HANDLE_INDEX:
        return efi_locate_handle(env);
    case VIBTANIUM_EFI_BOOT_EXIT_BOOT_SERVICES_INDEX:
        return efi_exit_boot_services(env);
    case VIBTANIUM_EFI_BOOT_OPEN_PROTOCOL_INDEX:
        return efi_handle_protocol(env);
    case VIBTANIUM_EFI_BOOT_CLOSE_PROTOCOL_INDEX:
        return efi_close_protocol(env);
    case VIBTANIUM_EFI_BOOT_LOCATE_PROTOCOL_INDEX:
        return efi_locate_protocol(env);
    case VIBTANIUM_EFI_BOOT_CALCULATE_CRC32_INDEX:
        return efi_calculate_crc32(env);
    case VIBTANIUM_EFI_BOOT_COPY_MEM_INDEX:
        return efi_copy_mem(env);
    case VIBTANIUM_EFI_BOOT_SET_MEM_INDEX:
        return efi_set_mem(env);
    default:
        return VIBTANIUM_EFI_UNSUPPORTED;
    }
}

static void efi_write_time(CPUIA64State *env, uint64_t time)
{
    efi_guest_stw(env, time, 2026);
    efi_guest_stb(env, time + 2, 6);
    efi_guest_stb(env, time + 3, 26);
    efi_guest_stb(env, time + 4, 0);
    efi_guest_stb(env, time + 5, 0);
    efi_guest_stb(env, time + 6, 0);
    efi_guest_stb(env, time + 7, 0);
    efi_guest_stl(env, time + 8, 0);
    efi_guest_stw(env, time + 12, EFI_UNSPECIFIED_TIMEZONE);
    efi_guest_stb(env, time + 14, 0);
    efi_guest_stb(env, time + 15, 0);
}

static void efi_write_time_capabilities(CPUIA64State *env,
                                        uint64_t capabilities)
{
    efi_guest_stl(env, capabilities, 1);
    efi_guest_stl(env, capabilities + 4, 50000000);
    efi_guest_stb(env, capabilities + 8, 0);
}

static bool efi_runtime_range_contains(uint64_t base, uint64_t pages,
                                       uint64_t address)
{
    uint64_t size;
    uint64_t end;

    if (pages > UINT64_MAX / EFI_PAGE_SIZE) {
        return false;
    }
    size = pages * EFI_PAGE_SIZE;
    if (base > UINT64_MAX - size) {
        return false;
    }
    end = base + size;
    return address >= base && address < end;
}

static uint64_t efi_runtime_virtual_address(CPUIA64State *env,
                                            uint64_t memory_map_size,
                                            uint64_t descriptor_size,
                                            uint64_t memory_map,
                                            uint64_t physical)
{
    if (memory_map != 0 && descriptor_size >= EFI_MEMORY_DESCRIPTOR_SIZE &&
        memory_map_size >= EFI_MEMORY_DESCRIPTOR_SIZE) {
        uint64_t limit = memory_map_size - EFI_MEMORY_DESCRIPTOR_SIZE;

        for (uint64_t offset = 0; offset <= limit; offset += descriptor_size) {
            uint64_t descriptor = memory_map + offset;
            uint64_t attributes = efi_guest_ldq(env, descriptor + 32);
            uint64_t phys = efi_guest_ldq(env, descriptor + 8);
            uint64_t virt = efi_guest_ldq(env, descriptor + 16);
            uint64_t pages = efi_guest_ldq(env, descriptor + 24);

            if ((attributes & EFI_MEMORY_RUNTIME) != 0 && virt != 0 &&
                efi_runtime_range_contains(phys, pages, physical)) {
                return virt + (physical - phys);
            }
        }
    }

    return IA64_KERNEL_PAGE_OFFSET + ia64_region_offset(physical);
}

static void efi_runtime_convert_service_descriptors(CPUIA64State *env,
                                                    uint64_t memory_map_size,
                                                    uint64_t descriptor_size,
                                                    uint64_t memory_map)
{
    for (unsigned i = 0; i < VIBTANIUM_EFI_RUNTIME_SERVICE_COUNT; i++) {
        unsigned service_index = EFI_RUNTIME_SERVICE_BASE + i;
        uint64_t descriptor = efi_service_descriptor_address(service_index);
        uint64_t gate = efi_service_gate_address(service_index);

        efi_guest_stq(env, descriptor,
                      efi_runtime_virtual_address(env, memory_map_size,
                                                  descriptor_size, memory_map,
                                                  gate));
        efi_guest_stq(env, descriptor + 8,
                      efi_runtime_virtual_address(env, memory_map_size,
                                                  descriptor_size, memory_map,
                                                  VIBTANIUM_EFI_SYSTEM_TABLE));
    }
}

static uint64_t efi_runtime_get_time(CPUIA64State *env)
{
    uint64_t time = ia64_read_gr(env, 32);
    uint64_t capabilities = ia64_read_gr(env, 33);

    if (time == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    efi_write_time(env, time);
    if (capabilities != 0) {
        efi_write_time_capabilities(env, capabilities);
    }
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_runtime_get_wakeup_time(CPUIA64State *env)
{
    uint64_t enabled = ia64_read_gr(env, 32);
    uint64_t pending = ia64_read_gr(env, 33);
    uint64_t time = ia64_read_gr(env, 34);

    if (enabled == 0 || pending == 0 || time == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    efi_guest_stb(env, enabled, 0);
    efi_guest_stb(env, pending, 0);
    efi_write_time(env, time);
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_runtime_set_virtual_address_map(CPUIA64State *env)
{
    uint64_t memory_map_size = ia64_read_gr(env, 32);
    uint64_t descriptor_size = ia64_read_gr(env, 33);
    uint64_t descriptor_version = ia64_read_gr(env, 34);
    uint64_t memory_map = ia64_read_gr(env, 35);

    if (descriptor_version != EFI_MEMORY_DESCRIPTOR_VERSION ||
        descriptor_size < EFI_MEMORY_DESCRIPTOR_SIZE ||
        (memory_map == 0 && memory_map_size != 0)) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    efi_runtime_convert_service_descriptors(env, memory_map_size,
                                            descriptor_size, memory_map);
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_runtime_convert_pointer(CPUIA64State *env)
{
    uint64_t pointer = ia64_read_gr(env, 33);
    uint64_t physical;

    if (pointer == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    physical = efi_guest_ldq(env, pointer);
    if (physical != 0) {
        efi_guest_stq(env, pointer,
                      IA64_KERNEL_PAGE_OFFSET + ia64_region_offset(physical));
    }
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_runtime_get_next_high_mono_count(CPUIA64State *env)
{
    uint64_t count = ia64_read_gr(env, 32);

    if (count == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    efi_guest_stl(env, count, efi_high_monotonic_count++);
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_runtime_read_variable_identity(CPUIA64State *env,
                                                   uint64_t name_ptr,
                                                   uint64_t guid_ptr,
                                                   char **name,
                                                   char guid[37])
{
    uint8_t guid_bytes[16];

    if (name_ptr == 0 || guid_ptr == 0 || !name || !guid) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    *name = efi_read_utf16_name(env, name_ptr);
    if (!*name) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    efi_guest_read_guid(env, guid_ptr, guid_bytes);
    efi_format_guid(guid_bytes, guid);
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_runtime_get_variable(CPUIA64State *env)
{
    uint64_t name_ptr = ia64_read_gr(env, 32);
    uint64_t guid_ptr = ia64_read_gr(env, 33);
    uint64_t attributes_ptr = ia64_read_gr(env, 34);
    uint64_t data_size_ptr = ia64_read_gr(env, 35);
    uint64_t data_ptr = ia64_read_gr(env, 36);
    g_autofree char *name = NULL;
    char guid[37];
    uint32_t attributes = 0;
    const uint8_t *data = NULL;
    size_t data_size = 0;
    uint64_t provided;
    uint64_t status;

    if (data_size_ptr == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    status = efi_runtime_read_variable_identity(env, name_ptr, guid_ptr,
                                                &name, guid);
    if (status != VIBTANIUM_EFI_SUCCESS) {
        return status;
    }

    provided = efi_guest_ldq(env, data_size_ptr);
    status = vibtanium_efi_vars_get(guid, name, &attributes, &data,
                                    &data_size);
    if (status != VIBTANIUM_EFI_SUCCESS) {
        return status;
    }

    efi_guest_stq(env, data_size_ptr, data_size);
    if (provided < data_size) {
        return VIBTANIUM_EFI_BUFFER_TOO_SMALL;
    }
    if (data_size != 0 && data_ptr == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    if (attributes_ptr != 0) {
        efi_guest_stl(env, attributes_ptr, attributes);
    }
    if (data_size != 0) {
        efi_guest_write_bytes(env, data_ptr, data, data_size);
    }
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_runtime_get_next_variable_name(CPUIA64State *env)
{
    uint64_t size_ptr = ia64_read_gr(env, 32);
    uint64_t name_ptr = ia64_read_gr(env, 33);
    uint64_t guid_ptr = ia64_read_gr(env, 34);
    g_autofree char *name = NULL;
    g_autofree char *next_name = NULL;
    char guid[37];
    char next_guid[37];
    uint64_t provided;
    uint64_t required = 0;
    uint64_t status;

    if (size_ptr == 0 || name_ptr == 0 || guid_ptr == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    provided = efi_guest_ldq(env, size_ptr);
    status = efi_runtime_read_variable_identity(env, name_ptr, guid_ptr,
                                                &name, guid);
    if (status != VIBTANIUM_EFI_SUCCESS) {
        return status;
    }

    status = vibtanium_efi_vars_next_name(guid, name, next_guid,
                                          sizeof(next_guid), &next_name);
    if (status != VIBTANIUM_EFI_SUCCESS) {
        return status;
    }

    status = efi_utf16_name_size(next_name, &required);
    if (status != VIBTANIUM_EFI_SUCCESS) {
        return status;
    }

    efi_guest_stq(env, size_ptr, required);
    if (provided < required) {
        return VIBTANIUM_EFI_BUFFER_TOO_SMALL;
    }

    if (!efi_write_utf16_name(env, name_ptr, next_name)) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }
    efi_guest_write_guid(env, guid_ptr, next_guid);
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_runtime_set_variable(CPUIA64State *env)
{
    uint64_t name_ptr = ia64_read_gr(env, 32);
    uint64_t guid_ptr = ia64_read_gr(env, 33);
    uint64_t raw_attributes = ia64_read_gr(env, 34);
    uint64_t data_size = ia64_read_gr(env, 35);
    uint64_t data_ptr = ia64_read_gr(env, 36);
    g_autofree char *name = NULL;
    g_autofree uint8_t *data = NULL;
    char guid[37];
    uint64_t status;
    Error *local_err = NULL;

    status = efi_runtime_read_variable_identity(env, name_ptr, guid_ptr,
                                                &name, guid);
    if (status != VIBTANIUM_EFI_SUCCESS) {
        return status;
    }
    if ((raw_attributes >> 32) != 0 || data_size > EFI_MAX_VARIABLE_DATA_SIZE) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }
    if (data_size != 0 && data_ptr == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    if (data_size != 0) {
        data = g_malloc(data_size);
        efi_guest_read_bytes(env, data_ptr, data, data_size);
    }

    status = vibtanium_efi_vars_set(guid, name, raw_attributes, data,
                                    data_size, &local_err);
    if (local_err) {
        warn_report("vibtanium EFI SetVariable %s:%s failed: %s",
                    guid, name, error_get_pretty(local_err));
        error_free(local_err);
    }
    return status;
}

static uint64_t efi_dispatch_runtime_service(CPUIA64State *env, unsigned index)
{
    switch (index) {
    case 0: /* GetTime */
        return efi_runtime_get_time(env);
    case 1: /* SetTime */
        return ia64_read_gr(env, 32) != 0 ? VIBTANIUM_EFI_SUCCESS
                                          : VIBTANIUM_EFI_INVALID_PARAMETER;
    case 2: /* GetWakeupTime */
        return efi_runtime_get_wakeup_time(env);
    case 3: /* SetWakeupTime */
        return VIBTANIUM_EFI_SUCCESS;
    case 4: /* SetVirtualAddressMap */
        return efi_runtime_set_virtual_address_map(env);
    case 5: /* ConvertPointer */
        return efi_runtime_convert_pointer(env);
    case 6: /* GetVariable */
        return efi_runtime_get_variable(env);
    case 7: /* GetNextVariableName */
        return efi_runtime_get_next_variable_name(env);
    case 8: /* SetVariable */
        return efi_runtime_set_variable(env);
    case 9: /* GetNextHighMonotonicCount */
        return efi_runtime_get_next_high_mono_count(env);
    case 10: /* ResetSystem */
        return VIBTANIUM_EFI_SUCCESS;
    default:
        return VIBTANIUM_EFI_UNSUPPORTED;
    }
}

static void efi_console_write_mode_state(CPUIA64State *env)
{
    efi_guest_stl(env, VIBTANIUM_EFI_CON_OUT_MODE + 8,
                  vibtanium_efi_console_attribute());
    efi_guest_stl(env, VIBTANIUM_EFI_CON_OUT_MODE + 12,
                  vibtanium_efi_console_cursor_column());
    efi_guest_stl(env, VIBTANIUM_EFI_CON_OUT_MODE + 16,
                  vibtanium_efi_console_cursor_row());
    efi_guest_stb(env, VIBTANIUM_EFI_CON_OUT_MODE + 20,
                  vibtanium_efi_console_cursor_visible());
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
            vibtanium_efi_console_putchar(ch);
            continue;
        }
        vibtanium_efi_console_putchar(ch);
        g_string_append_c(line, ch < 0x80 ? (char)ch : '?');
    }
    if (line->len != 0) {
        fprintf(stderr, "%s", line->str);
    }
    g_string_free(line, true);
    efi_console_write_mode_state(env);
}

static uint64_t efi_dispatch_console_out(CPUIA64State *env, unsigned index)
{
    uint64_t arg1 = ia64_read_gr(env, 33);
    uint64_t arg2 = ia64_read_gr(env, 34);
    uint64_t arg3 = ia64_read_gr(env, 35);

    switch (index) {
    case 0: /* Reset */
        vibtanium_efi_console_reset();
        efi_console_write_mode_state(env);
        return VIBTANIUM_EFI_SUCCESS;
    case 1: /* OutputString */
        efi_console_output_string(env);
        return VIBTANIUM_EFI_SUCCESS;
    case 2: /* TestString */
        return VIBTANIUM_EFI_SUCCESS;
    case 3: /* QueryMode */
        if (arg1 != 0 || arg2 == 0 || arg3 == 0) {
            return VIBTANIUM_EFI_INVALID_PARAMETER;
        }
        efi_guest_stq(env, arg2, 80);
        efi_guest_stq(env, arg3, 25);
        return VIBTANIUM_EFI_SUCCESS;
    case 4: /* SetMode */
        if (arg1 != 0) {
            return VIBTANIUM_EFI_UNSUPPORTED;
        }
        vibtanium_efi_console_clear();
        efi_guest_stl(env, VIBTANIUM_EFI_CON_OUT_MODE + 4, 0);
        efi_console_write_mode_state(env);
        return VIBTANIUM_EFI_SUCCESS;
    case 5: /* SetAttribute */
        vibtanium_efi_console_set_attribute(arg1);
        efi_console_write_mode_state(env);
        return VIBTANIUM_EFI_SUCCESS;
    case 6: /* ClearScreen */
        vibtanium_efi_console_clear();
        efi_console_write_mode_state(env);
        return VIBTANIUM_EFI_SUCCESS;
    case 7: /* SetCursorPosition */
        if (!vibtanium_efi_console_set_cursor_position(arg1, arg2)) {
            return VIBTANIUM_EFI_INVALID_PARAMETER;
        }
        efi_console_write_mode_state(env);
        return VIBTANIUM_EFI_SUCCESS;
    case 8: /* EnableCursor */
        vibtanium_efi_console_enable_cursor(arg1 != 0);
        efi_console_write_mode_state(env);
        return VIBTANIUM_EFI_SUCCESS;
    default:
        return VIBTANIUM_EFI_UNSUPPORTED;
    }
}

static void efi_gop_write_mode_info(CPUIA64State *env, uint64_t info)
{
    efi_guest_stl(env, info, 0);
    efi_guest_stl(env, info + 4, VIBTANIUM_FRAMEBUFFER_WIDTH);
    efi_guest_stl(env, info + 8, VIBTANIUM_FRAMEBUFFER_HEIGHT);
    efi_guest_stl(env, info + 12, 1);
    efi_guest_stl(env, info + 16, 0);
    efi_guest_stl(env, info + 20, 0);
    efi_guest_stl(env, info + 24, 0);
    efi_guest_stl(env, info + 28, 0);
    efi_guest_stl(env, info + 32, VIBTANIUM_FRAMEBUFFER_WIDTH);
}

static bool efi_gop_rect_valid(uint64_t x, uint64_t y,
                               uint64_t width, uint64_t height)
{
    return width <= VIBTANIUM_FRAMEBUFFER_WIDTH &&
           height <= VIBTANIUM_FRAMEBUFFER_HEIGHT &&
           x <= VIBTANIUM_FRAMEBUFFER_WIDTH - width &&
           y <= VIBTANIUM_FRAMEBUFFER_HEIGHT - height;
}

static uint64_t efi_gop_pixel_address(uint64_t x, uint64_t y)
{
    return VIBTANIUM_FRAMEBUFFER_BASE +
           (y * VIBTANIUM_FRAMEBUFFER_WIDTH + x) * sizeof(uint32_t);
}

static uint64_t efi_gop_query_mode(CPUIA64State *env)
{
    uint64_t mode_number = ia64_read_gr(env, 33);
    uint64_t size_of_info = ia64_read_gr(env, 34);
    uint64_t info_ptr = ia64_read_gr(env, 35);
    uint64_t info;

    if (size_of_info == 0 || info_ptr == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }
    if (mode_number != 0) {
        return VIBTANIUM_EFI_UNSUPPORTED;
    }

    info = efi_pool_alloc_raw(36);
    if (info == 0) {
        return VIBTANIUM_EFI_OUT_OF_RESOURCES;
    }

    efi_gop_write_mode_info(env, info);
    efi_guest_stq(env, size_of_info, 36);
    efi_guest_stq(env, info_ptr, info);
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_gop_set_mode(CPUIA64State *env)
{
    uint64_t mode_number = ia64_read_gr(env, 33);

    if (mode_number != 0) {
        return VIBTANIUM_EFI_UNSUPPORTED;
    }

    efi_guest_stl(env, VIBTANIUM_EFI_GOP_MODE + 4, 0);
    vibtanium_efi_console_clear();
    efi_console_write_mode_state(env);
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_gop_blt(CPUIA64State *env)
{
    uint64_t blt_buffer = ia64_read_gr(env, 33);
    uint64_t operation = ia64_read_gr(env, 34);
    uint64_t source_x = ia64_read_gr(env, 35);
    uint64_t source_y = ia64_read_gr(env, 36);
    uint64_t dest_x = ia64_read_gr(env, 37);
    uint64_t dest_y = ia64_read_gr(env, 38);
    uint64_t width = ia64_read_gr(env, 39);
    uint64_t height = ia64_read_gr(env, 40);
    uint64_t delta = ia64_read_gr(env, 41);

    if (width == 0 || height == 0) {
        return VIBTANIUM_EFI_SUCCESS;
    }

    switch (operation) {
    case 0: { /* EfiBltVideoFill */
        uint32_t pixel;

        if (blt_buffer == 0 ||
            !efi_gop_rect_valid(dest_x, dest_y, width, height)) {
            return VIBTANIUM_EFI_INVALID_PARAMETER;
        }

        pixel = efi_guest_ldl(env, blt_buffer);
        for (uint64_t row = 0; row < height; row++) {
            for (uint64_t col = 0; col < width; col++) {
                efi_guest_stl(env, efi_gop_pixel_address(dest_x + col,
                                                         dest_y + row),
                              pixel);
            }
        }
        vibtanium_efi_console_update_rect(dest_x, dest_y, width, height);
        return VIBTANIUM_EFI_SUCCESS;
    }
    case 1: { /* EfiBltVideoToBltBuffer */
        if (blt_buffer == 0 ||
            !efi_gop_rect_valid(source_x, source_y, width, height)) {
            return VIBTANIUM_EFI_INVALID_PARAMETER;
        }
        if (delta == 0) {
            delta = width * sizeof(uint32_t);
        }
        for (uint64_t row = 0; row < height; row++) {
            for (uint64_t col = 0; col < width; col++) {
                uint32_t pixel =
                    efi_guest_ldl(env, efi_gop_pixel_address(source_x + col,
                                                             source_y + row));
                efi_guest_stl(env,
                              blt_buffer + row * delta +
                              col * sizeof(uint32_t),
                              pixel);
            }
        }
        return VIBTANIUM_EFI_SUCCESS;
    }
    case 2: { /* EfiBltBufferToVideo */
        if (blt_buffer == 0 ||
            !efi_gop_rect_valid(dest_x, dest_y, width, height)) {
            return VIBTANIUM_EFI_INVALID_PARAMETER;
        }
        if (delta == 0) {
            delta = width * sizeof(uint32_t);
        }
        for (uint64_t row = 0; row < height; row++) {
            for (uint64_t col = 0; col < width; col++) {
                uint32_t pixel =
                    efi_guest_ldl(env,
                                  blt_buffer + (source_y + row) * delta +
                                  (source_x + col) * sizeof(uint32_t));
                efi_guest_stl(env, efi_gop_pixel_address(dest_x + col,
                                                         dest_y + row),
                              pixel);
            }
        }
        vibtanium_efi_console_update_rect(dest_x, dest_y, width, height);
        return VIBTANIUM_EFI_SUCCESS;
    }
    case 3: { /* EfiBltVideoToVideo */
        g_autofree uint32_t *pixels = NULL;

        if (!efi_gop_rect_valid(source_x, source_y, width, height) ||
            !efi_gop_rect_valid(dest_x, dest_y, width, height) ||
            width > SIZE_MAX / height ||
            width * height > SIZE_MAX / sizeof(uint32_t)) {
            return VIBTANIUM_EFI_INVALID_PARAMETER;
        }

        pixels = g_new(uint32_t, width * height);
        for (uint64_t row = 0; row < height; row++) {
            for (uint64_t col = 0; col < width; col++) {
                pixels[row * width + col] =
                    efi_guest_ldl(env, efi_gop_pixel_address(source_x + col,
                                                             source_y + row));
            }
        }
        for (uint64_t row = 0; row < height; row++) {
            for (uint64_t col = 0; col < width; col++) {
                efi_guest_stl(env, efi_gop_pixel_address(dest_x + col,
                                                         dest_y + row),
                              pixels[row * width + col]);
            }
        }
        vibtanium_efi_console_update_rect(dest_x, dest_y, width, height);
        return VIBTANIUM_EFI_SUCCESS;
    }
    default:
        return VIBTANIUM_EFI_UNSUPPORTED;
    }
}

static uint64_t efi_dispatch_gop(CPUIA64State *env, unsigned index)
{
    switch (index) {
    case 0:
        return efi_gop_query_mode(env);
    case 1:
        return efi_gop_set_mode(env);
    case 2:
        return efi_gop_blt(env);
    default:
        return VIBTANIUM_EFI_UNSUPPORTED;
    }
}

static uint64_t efi_dispatch_console_in(CPUIA64State *env, unsigned index)
{
    uint64_t key = ia64_read_gr(env, 33);
    VibtaniumEfiInputKey input_key;

    switch (index) {
    case 0: /* Reset */
        efi_conin_reset();
        return VIBTANIUM_EFI_SUCCESS;
    case 1: /* ReadKeyStroke */
        if (key == 0) {
            return VIBTANIUM_EFI_INVALID_PARAMETER;
        }
        if (!efi_conin_dequeue(&input_key)) {
            return VIBTANIUM_EFI_NOT_READY;
        }
        efi_guest_stw(env, key, input_key.scan_code);
        efi_guest_stw(env, key + 2, input_key.unicode_char);
        return VIBTANIUM_EFI_SUCCESS;
    default:
        return VIBTANIUM_EFI_UNSUPPORTED;
    }
}

bool vibtanium_efi_dispatch_gate(CPUIA64State *env, uint64_t gate_ip)
{
    unsigned service_index;
    uint64_t result = VIBTANIUM_EFI_UNSUPPORTED;

    if (!env) {
        return false;
    }
    if (!efi_gate_service_index(gate_ip, &service_index)) {
        return vibtanium_firmware_dispatch_gate(env, gate_ip);
    }

    IA64_PERF_INC(IA64_PERF_FIRMWARE_EFI);
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
               service_index < EFI_GOP_SERVICE_BASE) {
        result = efi_dispatch_file(env,
                                   service_index - EFI_FILE_SERVICE_BASE);
    } else if (service_index >= EFI_GOP_SERVICE_BASE &&
               service_index < EFI_SERVICE_DESCRIPTOR_COUNT) {
        result = efi_dispatch_gop(env,
                                  service_index - EFI_GOP_SERVICE_BASE);
    }

    ia64_write_gr(env, 8, result);
    efi_trace_service(env, service_index, result);
    ia64_return_from_call_frame(env, env->br[0]);
    return true;
}
