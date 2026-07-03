/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "accel/tcg/cpu-ldst.h"
#include "accel/tcg/cpu-loop.h"
#include "accel/tcg/getpc.h"
#include "hw/ia64/efi.h"
#include "hw/pci/pci.h"
#include "hw/pci/pci_host.h"
#include "qemu/main-loop.h"
#include "target/ia64/firmware.h"
#include "target/ia64/insn.h"
#include "target/ia64/perf.h"
#include "trace-target_ia64.h"

#define IA64_REGION_OFFSET_MASK UINT64_C(0x1fffffffffffffff)
#define IA64_FIRMWARE_STATUS_SUCCESS UINT64_C(0)
#define IA64_FIRMWARE_STATUS_UNIMPLEMENTED UINT64_C(0xffffffffffffffff)
#define IA64_FIRMWARE_STATUS_INVALID_ARGUMENT UINT64_C(0xfffffffffffffffe)
#define IA64_FIRMWARE_STATUS_REQUIRES_MEMORY UINT64_C(0xfffffffffffffff7)
/*
 * Platform base frequency reported by SAL_FREQ_BASE and PAL_FREQ_BASE.  With
 * the 1/1 PAL ITC ratio below this is also the ITC frequency, which the
 * target really implements: AR.ITC follows the QEMU virtual clock at
 * IA64_ITC_FREQUENCY_HZ.
 */
#define IA64_FIRMWARE_DEFAULT_BASE_FREQUENCY ((uint64_t)IA64_ITC_FREQUENCY_HZ)
#define IA64_PAL_FREQ_RATIO(den, num) \
    ((((uint64_t)(num)) << 32) | (uint32_t)(den))
#define IA64_PAL_VERSION UINT64_C(0x0000002300000000)
#define IA64_PAL_CACHE_LEVELS UINT64_C(2)
#define IA64_PAL_UNIQUE_CACHES UINT64_C(2)
#define IA64_PAL_DATA_OR_UNIFIED_CACHE_TYPE UINT64_C(2)
#define IA64_PROCESSOR_IDENTIFIER_REGISTER_COUNT UINT64_C(5)
#define IA64_IMPLEMENTED_PERF_MON_REGISTER_COUNT UINT64_C(8)
#define IA64_MAXIMUM_PERF_MON_REGISTER_COUNT UINT64_C(256)
#define IA64_MINIMUM_PHYSICAL_STACKED_REGISTERS UINT64_C(96)
#define IA64_MINIMUM_TRANSLATION_REGISTER_COUNT UINT64_C(8)

static PCIBus *firmware_pci_bus;

void ia64_firmware_set_pci_bus(PCIBus *bus)
{
    firmware_pci_bus = bus;
}

typedef enum IA64PalProcedureId {
    IA64_PAL_CACHE_FLUSH = 1,
    IA64_PAL_CACHE_INFO = 2,
    IA64_PAL_CACHE_INIT = 3,
    IA64_PAL_CACHE_SUMMARY = 4,
    IA64_PAL_MEMORY_ATTRIBUTES = 5,
    IA64_PAL_PTCE_INFO = 6,
    IA64_PAL_VIRTUAL_MEMORY_INFO = 7,
    IA64_PAL_VIRTUAL_MEMORY_SUMMARY = 8,
    IA64_PAL_BUS_GET_FEATURES = 9,
    IA64_PAL_BUS_SET_FEATURES = 10,
    IA64_PAL_DEBUG_INFO = 11,
    IA64_PAL_FIXED_ADDRESS = 12,
    IA64_PAL_FREQUENCY_BASE = 13,
    IA64_PAL_FREQUENCY_RATIOS = 14,
    IA64_PAL_PERFORMANCE_MONITOR_INFO = 15,
    IA64_PAL_PLATFORM_ADDR = 16,
    IA64_PAL_PROCESSOR_GET_FEATURES = 17,
    IA64_PAL_PROCESSOR_SET_FEATURES = 18,
    IA64_PAL_RSE_INFO = 19,
    IA64_PAL_VERSION_PROC = 20,
    IA64_PAL_MACHINE_CHECK_CLEAR_LOG = 21,
    IA64_PAL_MACHINE_CHECK_DRAIN = 22,
    IA64_PAL_MACHINE_CHECK_EXPECTED = 23,
    IA64_PAL_MACHINE_CHECK_DYNAMIC_STATE = 24,
    IA64_PAL_MACHINE_CHECK_REGISTER_MEMORY = 27,
    IA64_PAL_HALT = 28,
    IA64_PAL_HALT_LIGHT = 29,
    IA64_PAL_CACHE_LINE_INIT = 31,
    IA64_PAL_VIRTUAL_MEMORY_PAGE_SIZE = 34,
    IA64_PAL_REGISTER_INFO = 39,
    IA64_PAL_PREFETCH_VISIBILITY = 41,
    IA64_PAL_LOGICAL_TO_PHYSICAL = 42,
    IA64_PAL_CACHE_SHARED_INFO = 43,
    IA64_PAL_SHUTDOWN = 44,
    IA64_PAL_COPY_PAL = 256,
    IA64_PAL_HALT_INFO = 257,
    IA64_PAL_TEST_PROC = 258,
    IA64_PAL_CACHE_READ = 259,
    IA64_PAL_CACHE_WRITE = 260,
    IA64_PAL_VIRTUAL_MEMORY_TR_READ = 261,
    IA64_PAL_GET_PSTATE = 262,
    IA64_PAL_SET_PSTATE = 263,
    IA64_PAL_BRAND_INFO = 274,
    IA64_PAL_MACHINE_CHECK_ERROR_INJECT = 276,
} IA64PalProcedureId;

typedef enum IA64SalProcedureId {
    IA64_SAL_SET_VECTORS = 0x01000000,
    IA64_SAL_GET_STATE_INFO = 0x01000001,
    IA64_SAL_GET_STATE_INFO_SIZE = 0x01000002,
    IA64_SAL_CLEAR_STATE_INFO = 0x01000003,
    IA64_SAL_MACHINE_CHECK_RENDEZVOUS = 0x01000004,
    IA64_SAL_MACHINE_CHECK_SET_PARAMETERS = 0x01000005,
    IA64_SAL_REGISTER_PHYSICAL_ADDRESS = 0x01000006,
    IA64_SAL_VERSION_PROC = 0x01000007,
    IA64_SAL_CACHE_FLUSH = 0x01000008,
    IA64_SAL_CACHE_INIT = 0x01000009,
    IA64_SAL_PCI_CONFIG_READ = 0x01000010,
    IA64_SAL_PCI_CONFIG_WRITE = 0x01000011,
    IA64_SAL_FREQUENCY_BASE = 0x01000012,
} IA64SalProcedureId;

typedef struct IA64FirmwareResult {
    uint64_t status;
    uint64_t ret0;
    uint64_t ret1;
    uint64_t ret2;
} IA64FirmwareResult;

#define IA64_KERNEL_PAGE_OFFSET UINT64_C(0xe000000000000000)

static uint64_t ia64_region_offset(uint64_t address)
{
    return address & IA64_REGION_OFFSET_MASK;
}

static bool efi_gate_address_is_valid_alias(uint64_t address)
{
    uint64_t region = address & ~IA64_REGION_OFFSET_MASK;

    return region == 0 || region == IA64_KERNEL_PAGE_OFFSET;
}

static bool efi_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_EFI_TRACE") != NULL;
    }
    return enabled != 0;
}

static IA64FirmwareResult firmware_success(uint64_t ret0, uint64_t ret1,
                                           uint64_t ret2)
{
    return (IA64FirmwareResult) {
        .status = IA64_FIRMWARE_STATUS_SUCCESS,
        .ret0 = ret0,
        .ret1 = ret1,
        .ret2 = ret2,
    };
}

static IA64FirmwareResult firmware_status(uint64_t status)
{
    return (IA64FirmwareResult) {
        .status = status,
    };
}

static const char *firmware_status_name(uint64_t status)
{
    switch (status) {
    case IA64_FIRMWARE_STATUS_SUCCESS:
        return "ok";
    case IA64_FIRMWARE_STATUS_UNIMPLEMENTED:
        return "unimplemented";
    case IA64_FIRMWARE_STATUS_INVALID_ARGUMENT:
        return "invalid-argument";
    case IA64_FIRMWARE_STATUS_REQUIRES_MEMORY:
        return "requires-memory";
    default:
        return "unknown";
    }
}

static const char *pal_procedure_name(uint64_t function_id)
{
    switch (function_id) {
    case IA64_PAL_CACHE_FLUSH:
        return "PAL_CACHE_FLUSH";
    case IA64_PAL_CACHE_INFO:
        return "PAL_CACHE_INFO";
    case IA64_PAL_CACHE_INIT:
        return "PAL_CACHE_INIT";
    case IA64_PAL_CACHE_SUMMARY:
        return "PAL_CACHE_SUMMARY";
    case IA64_PAL_MEMORY_ATTRIBUTES:
        return "PAL_MEM_ATTRIB";
    case IA64_PAL_PTCE_INFO:
        return "PAL_PTCE_INFO";
    case IA64_PAL_VIRTUAL_MEMORY_INFO:
        return "PAL_VM_INFO";
    case IA64_PAL_VIRTUAL_MEMORY_SUMMARY:
        return "PAL_VM_SUMMARY";
    case IA64_PAL_BUS_GET_FEATURES:
        return "PAL_BUS_GET_FEATURES";
    case IA64_PAL_BUS_SET_FEATURES:
        return "PAL_BUS_SET_FEATURES";
    case IA64_PAL_DEBUG_INFO:
        return "PAL_DEBUG_INFO";
    case IA64_PAL_FIXED_ADDRESS:
        return "PAL_FIXED_ADDR";
    case IA64_PAL_FREQUENCY_BASE:
        return "PAL_FREQ_BASE";
    case IA64_PAL_FREQUENCY_RATIOS:
        return "PAL_FREQ_RATIOS";
    case IA64_PAL_PERFORMANCE_MONITOR_INFO:
        return "PAL_PERF_MON_INFO";
    case IA64_PAL_PLATFORM_ADDR:
        return "PAL_PLATFORM_ADDR";
    case IA64_PAL_PROCESSOR_GET_FEATURES:
        return "PAL_PROC_GET_FEATURES";
    case IA64_PAL_PROCESSOR_SET_FEATURES:
        return "PAL_PROC_SET_FEATURES";
    case IA64_PAL_RSE_INFO:
        return "PAL_RSE_INFO";
    case IA64_PAL_VERSION_PROC:
        return "PAL_VERSION";
    case IA64_PAL_MACHINE_CHECK_CLEAR_LOG:
        return "PAL_MC_CLEAR_LOG";
    case IA64_PAL_MACHINE_CHECK_DRAIN:
        return "PAL_MC_DRAIN";
    case IA64_PAL_MACHINE_CHECK_EXPECTED:
        return "PAL_MC_EXPECTED";
    case IA64_PAL_MACHINE_CHECK_DYNAMIC_STATE:
        return "PAL_MC_DYNAMIC_STATE";
    case IA64_PAL_MACHINE_CHECK_REGISTER_MEMORY:
        return "PAL_MC_REGISTER_MEM";
    case IA64_PAL_HALT:
        return "PAL_HALT";
    case IA64_PAL_HALT_LIGHT:
        return "PAL_HALT_LIGHT";
    case IA64_PAL_CACHE_LINE_INIT:
        return "PAL_CACHE_LINE_INIT";
    case IA64_PAL_VIRTUAL_MEMORY_PAGE_SIZE:
        return "PAL_VM_PAGE_SIZE";
    case IA64_PAL_PREFETCH_VISIBILITY:
        return "PAL_PREFETCH_VISIBILITY";
    case IA64_PAL_LOGICAL_TO_PHYSICAL:
        return "PAL_LOGICAL_TO_PHYSICAL";
    case IA64_PAL_CACHE_SHARED_INFO:
        return "PAL_CACHE_SHARED_INFO";
    case IA64_PAL_SHUTDOWN:
        return "PAL_SHUTDOWN";
    case IA64_PAL_COPY_PAL:
        return "PAL_COPY_PAL";
    case IA64_PAL_HALT_INFO:
        return "PAL_HALT_INFO";
    case IA64_PAL_TEST_PROC:
        return "PAL_TEST_PROC";
    case IA64_PAL_CACHE_READ:
        return "PAL_CACHE_READ";
    case IA64_PAL_CACHE_WRITE:
        return "PAL_CACHE_WRITE";
    case IA64_PAL_VIRTUAL_MEMORY_TR_READ:
        return "PAL_VM_TR_READ";
    case IA64_PAL_GET_PSTATE:
        return "PAL_GET_PSTATE";
    case IA64_PAL_SET_PSTATE:
        return "PAL_SET_PSTATE";
    case IA64_PAL_BRAND_INFO:
        return "PAL_BRAND_INFO";
    case IA64_PAL_MACHINE_CHECK_ERROR_INJECT:
        return "PAL_MC_ERROR_INJECT";
    default:
        return "PAL_UNKNOWN";
    }
}

static const char *sal_procedure_name(uint64_t function_id)
{
    switch (function_id) {
    case IA64_SAL_SET_VECTORS:
        return "SAL_SET_VECTORS";
    case IA64_SAL_GET_STATE_INFO:
        return "SAL_GET_STATE_INFO";
    case IA64_SAL_GET_STATE_INFO_SIZE:
        return "SAL_GET_STATE_INFO_SIZE";
    case IA64_SAL_CLEAR_STATE_INFO:
        return "SAL_CLEAR_STATE_INFO";
    case IA64_SAL_MACHINE_CHECK_RENDEZVOUS:
        return "SAL_MC_RENDEZ";
    case IA64_SAL_MACHINE_CHECK_SET_PARAMETERS:
        return "SAL_MC_SET_PARAMS";
    case IA64_SAL_REGISTER_PHYSICAL_ADDRESS:
        return "SAL_REGISTER_PHYSICAL_ADDR";
    case IA64_SAL_VERSION_PROC:
        return "SAL_VERSION";
    case IA64_SAL_CACHE_FLUSH:
        return "SAL_CACHE_FLUSH";
    case IA64_SAL_CACHE_INIT:
        return "SAL_CACHE_INIT";
    case IA64_SAL_PCI_CONFIG_READ:
        return "SAL_PCI_CONFIG_READ";
    case IA64_SAL_PCI_CONFIG_WRITE:
        return "SAL_PCI_CONFIG_WRITE";
    case IA64_SAL_FREQUENCY_BASE:
        return "SAL_FREQ_BASE";
    default:
        return "SAL_UNKNOWN";
    }
}

static uint64_t pal_supported_page_size_mask(void)
{
    return (UINT64_C(1) << 12) |
           (UINT64_C(1) << 14) |
           (UINT64_C(1) << 16) |
           (UINT64_C(1) << 21) |
           (UINT64_C(1) << 24) |
           (UINT64_C(1) << 28);
}

static uint64_t pal_cache_info1(void)
{
    const uint64_t unified = 1;
    const uint64_t associativity = UINT64_C(1) << 8;
    const uint64_t line_size_64 = UINT64_C(6) << 16;
    const uint64_t stride_64 = UINT64_C(6) << 24;
    const uint64_t store_latency = UINT64_C(1) << 32;
    const uint64_t load_latency = UINT64_C(1) << 40;

    return unified | associativity | line_size_64 | stride_64 |
           store_latency | load_latency;
}

static uint64_t pal_cache_info2(uint64_t level)
{
    const uint64_t size = level == 0 ? 32 * 1024 : 256 * 1024;
    const uint64_t tag_least_bit = 6;
    const uint64_t tag_most_bit = 43;

    return size | (tag_least_bit << 40) | (tag_most_bit << 48);
}

static IA64FirmwareResult pal_cache_info(uint64_t level, uint64_t type)
{
    if (level >= IA64_PAL_CACHE_LEVELS ||
        type != IA64_PAL_DATA_OR_UNIFIED_CACHE_TYPE) {
        return firmware_status(IA64_FIRMWARE_STATUS_INVALID_ARGUMENT);
    }
    return firmware_success(pal_cache_info1(), pal_cache_info2(level), 0);
}

static uint64_t pal_vm_summary1(void)
{
    const uint64_t hardware_walker = 1;
    const uint64_t physical_address_size = 44;
    const uint64_t key_size = 24;
    const uint64_t hash_tag_id = 18;
    const uint64_t unique_translation_caches = 1;
    const uint64_t translation_cache_levels = 1;

    return hardware_walker |
           (physical_address_size << 1) |
           (key_size << 8) |
           ((uint64_t)IA64_PKR_COUNT << 16) |
           (hash_tag_id << 24) |
           (IA64_MINIMUM_TRANSLATION_REGISTER_COUNT << 32) |
           (IA64_MINIMUM_TRANSLATION_REGISTER_COUNT << 40) |
           (unique_translation_caches << 48) |
           (translation_cache_levels << 56);
}

static uint64_t pal_vm_summary2(void)
{
    const uint64_t implemented_va_msb = 50;
    const uint64_t region_identifier_size = 18;

    return implemented_va_msb | (region_identifier_size << 8);
}

static uint64_t pal_single_processor_logical_overview(void)
{
    const uint64_t logical_processors = 1;
    const uint64_t threads_per_core = 1;
    const uint64_t cores_per_processor = 1;
    const uint64_t physical_processor_id = 0;

    return logical_processors | (threads_per_core << 16) |
           (cores_per_processor << 32) | (physical_processor_id << 48);
}

static void firmware_guest_write_bytes(CPUIA64State *env, uint64_t address,
                                       const uint8_t *bytes, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        cpu_stb_data_ra(env, address + i, bytes[i], GETPC());
    }
}

static IA64FirmwareResult pal_brand_info(CPUIA64State *env,
                                         uint64_t selector,
                                         uint64_t buffer)
{
    uint8_t brand[128];
    const char *name = "Vibtanium IA-64";

    if (selector != 0 || buffer == 0) {
        return firmware_status(IA64_FIRMWARE_STATUS_REQUIRES_MEMORY);
    }

    memset(brand, 0, sizeof(brand));
    memcpy(brand, name, MIN(strlen(name), sizeof(brand) - 1));
    firmware_guest_write_bytes(env, buffer, brand, sizeof(brand));
    return firmware_success(0, 0, 0);
}

static IA64FirmwareResult dispatch_pal(CPUIA64State *env,
                                       uint64_t function_id,
                                       uint64_t arg0, uint64_t arg1)
{
    switch (function_id) {
    case IA64_PAL_CACHE_FLUSH:
    case IA64_PAL_CACHE_INIT:
    case IA64_PAL_CACHE_LINE_INIT:
    case IA64_PAL_PROCESSOR_GET_FEATURES:
    case IA64_PAL_PROCESSOR_SET_FEATURES:
    case IA64_PAL_BUS_GET_FEATURES:
    case IA64_PAL_BUS_SET_FEATURES:
    case IA64_PAL_MACHINE_CHECK_CLEAR_LOG:
    case IA64_PAL_MACHINE_CHECK_DRAIN:
    case IA64_PAL_MACHINE_CHECK_EXPECTED:
    case IA64_PAL_MACHINE_CHECK_DYNAMIC_STATE:
    case IA64_PAL_MACHINE_CHECK_REGISTER_MEMORY:
    case IA64_PAL_HALT:
    case IA64_PAL_HALT_LIGHT:
    case IA64_PAL_FIXED_ADDRESS:
    case IA64_PAL_PLATFORM_ADDR:
    case IA64_PAL_SHUTDOWN:
        return firmware_success(0, 0, 0);
    case IA64_PAL_COPY_PAL:
    case IA64_PAL_TEST_PROC:
    case IA64_PAL_CACHE_READ:
    case IA64_PAL_CACHE_WRITE:
    case IA64_PAL_VIRTUAL_MEMORY_TR_READ:
    case IA64_PAL_GET_PSTATE:
    case IA64_PAL_SET_PSTATE:
    case IA64_PAL_MACHINE_CHECK_ERROR_INJECT:
        return firmware_status(IA64_FIRMWARE_STATUS_UNIMPLEMENTED);
    case IA64_PAL_CACHE_INFO:
        return pal_cache_info(arg0, arg1);
    case IA64_PAL_CACHE_SUMMARY:
        return firmware_success(IA64_PAL_CACHE_LEVELS,
                                IA64_PAL_UNIQUE_CACHES, 0);
    case IA64_PAL_MEMORY_ATTRIBUTES:
        return firmware_success(0, 0, 0);
    case IA64_PAL_VIRTUAL_MEMORY_SUMMARY:
        return firmware_success(pal_vm_summary1(), pal_vm_summary2(), 0);
    case IA64_PAL_VIRTUAL_MEMORY_INFO:
        return firmware_success(pal_supported_page_size_mask(), 61, 0);
    case IA64_PAL_VIRTUAL_MEMORY_PAGE_SIZE:
        return firmware_success(pal_supported_page_size_mask(),
                                pal_supported_page_size_mask(), 0);
    case IA64_PAL_PTCE_INFO:
        return firmware_success(1, 4096, 0);
    case IA64_PAL_REGISTER_INFO:
        return firmware_success(IA64_AR_COUNT, IA64_CR_COUNT,
                                IA64_PROCESSOR_IDENTIFIER_REGISTER_COUNT);
    case IA64_PAL_RSE_INFO:
        return firmware_success(IA64_MINIMUM_PHYSICAL_STACKED_REGISTERS,
                                0, 0);
    case IA64_PAL_VERSION_PROC:
        return firmware_success(IA64_PAL_VERSION, IA64_PAL_VERSION, 0);
    case IA64_PAL_DEBUG_INFO:
        return firmware_success(8, 8, 0);
    case IA64_PAL_FREQUENCY_BASE:
        return firmware_success(IA64_FIRMWARE_DEFAULT_BASE_FREQUENCY, 0, 0);
    case IA64_PAL_FREQUENCY_RATIOS:
        /*
         * PAL encodes frequency ratios as { uint32_t den, num }.  Linux uses
         * ITC frequency = SAL_FREQ_BASE_PLATFORM * num / den for scheduling
         * and delay loops.  The target backs AR.ITC with the QEMU virtual
         * clock at exactly IA64_ITC_FREQUENCY_HZ, so a 1/1 ratio on the
         * 100 MHz base makes the advertised and implemented rates identical.
         */
        return firmware_success(IA64_PAL_FREQ_RATIO(1, 1),
                                IA64_PAL_FREQ_RATIO(1, 1),
                                IA64_PAL_FREQ_RATIO(1, 1));
    case IA64_PAL_PERFORMANCE_MONITOR_INFO:
        return firmware_success(IA64_IMPLEMENTED_PERF_MON_REGISTER_COUNT,
                                IA64_MAXIMUM_PERF_MON_REGISTER_COUNT, 0);
    case IA64_PAL_PREFETCH_VISIBILITY:
        return firmware_success(1, 0, 0);
    case IA64_PAL_LOGICAL_TO_PHYSICAL:
        return arg0 == 0 || arg0 == UINT64_MAX
               ? firmware_success(pal_single_processor_logical_overview(),
                                  0, 0)
               : firmware_status(IA64_FIRMWARE_STATUS_INVALID_ARGUMENT);
    case IA64_PAL_HALT_INFO:
        return firmware_success(UINT64_C(1000) | (UINT64_C(1000) << 16) |
                                (UINT64_C(10) << 32) |
                                (UINT64_C(1) << 60) |
                                (UINT64_C(1) << 61), 0, 0);
    case IA64_PAL_BRAND_INFO:
        return pal_brand_info(env, arg0, arg1);
    default:
        return firmware_status(IA64_FIRMWARE_STATUS_UNIMPLEMENTED);
    }
}

static bool pal_uses_static_calling_convention(uint64_t function_id)
{
    return !ia64_pal_uses_stacked_calling_convention(function_id);
}

static bool sal_pci_config_address(uint64_t sal_addr, uint64_t mode,
                                   uint32_t *pci_addr)
{
    uint64_t segment;
    uint64_t bus;
    uint64_t devfn;
    uint64_t reg;

    if (!firmware_pci_bus) {
        return false;
    }

    switch (mode) {
    case 0:
        segment = (sal_addr >> 24) & 0xffff;
        bus = (sal_addr >> 16) & 0xff;
        devfn = (sal_addr >> 8) & 0xff;
        reg = sal_addr & 0xff;
        break;
    case 1:
        segment = (sal_addr >> 28) & 0xffff;
        bus = (sal_addr >> 20) & 0xff;
        devfn = (sal_addr >> 12) & 0xff;
        reg = sal_addr & 0xfff;
        break;
    default:
        return false;
    }

    if (segment != 0 || reg >= PCI_CONFIG_SPACE_SIZE) {
        return false;
    }

    *pci_addr = (bus << 16) | (devfn << 8) | reg;
    return true;
}

static uint64_t sal_pci_config_default_read(uint64_t size)
{
    switch (size) {
    case 1:
        return 0xff;
    case 2:
        return 0xffff;
    case 4:
        return 0xffffffff;
    default:
        return UINT64_MAX;
    }
}

static uint32_t sal_pci_data_read_locked(uint32_t pci_addr, unsigned size)
{
    uint32_t value;
    bool locked = bql_locked();

    if (!locked) {
        bql_lock();
    }
    value = pci_data_read(firmware_pci_bus, pci_addr, size);
    if (!locked) {
        bql_unlock();
    }

    return value;
}

static void sal_pci_data_write_locked(uint32_t pci_addr,
                                      uint32_t value,
                                      unsigned size)
{
    bool locked = bql_locked();

    if (!locked) {
        bql_lock();
    }
    pci_data_write(firmware_pci_bus, pci_addr, value, size);
    if (!locked) {
        bql_unlock();
    }
}

static IA64FirmwareResult sal_pci_config_read(uint64_t sal_addr,
                                              uint64_t size,
                                              uint64_t mode)
{
    uint32_t pci_addr;

    switch (size) {
    case 1:
    case 2:
    case 4:
        break;
    default:
        return firmware_status(IA64_FIRMWARE_STATUS_INVALID_ARGUMENT);
    }

    if (!sal_pci_config_address(sal_addr, mode, &pci_addr)) {
        return firmware_success(sal_pci_config_default_read(size), 0, 0);
    }

    return firmware_success(sal_pci_data_read_locked(pci_addr, size),
                            0, 0);
}

static IA64FirmwareResult sal_pci_config_write(uint64_t sal_addr,
                                                uint64_t size,
                                                uint64_t value,
                                                uint64_t mode)
{
    uint32_t pci_addr;

    switch (size) {
    case 1:
    case 2:
    case 4:
        break;
    default:
        return firmware_status(IA64_FIRMWARE_STATUS_INVALID_ARGUMENT);
    }

    if (sal_pci_config_address(sal_addr, mode, &pci_addr)) {
        sal_pci_data_write_locked(pci_addr, value, size);
    }

    return firmware_success(0, 0, 0);
}

static IA64FirmwareResult dispatch_sal(uint64_t function_id, uint64_t arg0,
                                       uint64_t arg1, uint64_t arg2,
                                       uint64_t arg3)
{
    switch (function_id) {
    case IA64_SAL_GET_STATE_INFO:
    case IA64_SAL_CLEAR_STATE_INFO:
    case IA64_SAL_CACHE_FLUSH:
    case IA64_SAL_CACHE_INIT:
    case IA64_SAL_SET_VECTORS:
    case IA64_SAL_MACHINE_CHECK_RENDEZVOUS:
    case IA64_SAL_MACHINE_CHECK_SET_PARAMETERS:
    case IA64_SAL_REGISTER_PHYSICAL_ADDRESS:
        return firmware_success(0, 0, 0);
    case IA64_SAL_GET_STATE_INFO_SIZE:
        return firmware_success(0, 0, 0);
    case IA64_SAL_VERSION_PROC:
        return firmware_success(UINT64_C(0x0000000200000009), 0, 0);
    case IA64_SAL_FREQUENCY_BASE:
        return firmware_success(IA64_FIRMWARE_DEFAULT_BASE_FREQUENCY, 0, 0);
    case IA64_SAL_PCI_CONFIG_READ:
        return sal_pci_config_read(arg0, arg1, arg2);
    case IA64_SAL_PCI_CONFIG_WRITE:
        return sal_pci_config_write(arg0, arg1, arg2, arg3);
    default:
        return firmware_status(IA64_FIRMWARE_STATUS_UNIMPLEMENTED);
    }
}

static void firmware_trace_call(CPUIA64State *env, const char *source,
                                const char *function, uint64_t function_id,
                                uint64_t arg0, uint64_t arg1,
                                uint64_t arg2,
                                IA64FirmwareResult result)
{
    const char *status = firmware_status_name(result.status);

    trace_ia64_firmware_call(env->ip, source, function, status, function_id,
                             arg0, arg1, result.ret0, result.ret1,
                             result.ret2);
    if (!efi_trace_enabled()) {
        return;
    }

    fprintf(stderr,
            "[ia64-firmware] ip=0x%016" PRIx64 " source=%s function=%s"
            " id=0x%016" PRIx64 " status=%s arg0=0x%016" PRIx64
            " arg1=0x%016" PRIx64 " arg2=0x%016" PRIx64
            " ret0=0x%016" PRIx64 " ret1=0x%016" PRIx64
            " ret2=0x%016" PRIx64 "\n",
            env->ip, source, function, function_id, status, arg0, arg1, arg2,
            result.ret0, result.ret1, result.ret2);
}

static void firmware_invalidate_result_alat(CPUIA64State *env)
{
    uint32_t valid_mask = env->alat.valid_mask;

    if (valid_mask == 0) {
        return;
    }

    for (unsigned i = 0; i < IA64_ALAT_COUNT; i++) {
        IA64AlatEntry *entry = &env->alat.entries[i];

        if ((valid_mask & (1u << i)) != 0 &&
            entry->target >= 8 && entry->target <= 11) {
            ia64_alat_set_valid(env, i, false);
        }
    }
}

static void firmware_write_result(CPUIA64State *env,
                                  IA64FirmwareResult result,
                                  bool stacked_return)
{
    env->gr[8] = result.status;
    env->gr[9] = result.ret0;
    env->gr[10] = result.ret1;
    env->gr[11] = result.ret2;
    firmware_invalidate_result_alat(env);
    env->gr[0] = 0;

    if (stacked_return) {
        ia64_return_from_call_frame(env, env->br[0]);
    } else {
        env->ip = env->br[0] & ~0xfULL;
        env->cr[IA64_CR_IIP] = env->ip;
    }
}

static void ia64_perf_count_pal_call(uint64_t function_id)
{
    static uint64_t reported_other[8];
    static unsigned reported_other_count;

    if (!ia64_perf_enabled()) {
        return;
    }

    switch (function_id) {
    case IA64_PAL_CACHE_FLUSH:
    case IA64_PAL_CACHE_INIT:
    case IA64_PAL_CACHE_LINE_INIT:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_CACHE_MAINT);
        break;
    case IA64_PAL_HALT:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_HALT);
        break;
    case IA64_PAL_HALT_LIGHT:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_HALT_LIGHT);
        break;
    case IA64_PAL_CACHE_INFO:
    case IA64_PAL_CACHE_SUMMARY:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_CACHE_INFO);
        break;
    case IA64_PAL_MEMORY_ATTRIBUTES:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_MEMORY_ATTRIBUTES);
        break;
    case IA64_PAL_PTCE_INFO:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_PTCE_INFO);
        break;
    case IA64_PAL_RSE_INFO:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_RSE_INFO);
        break;
    case IA64_PAL_VIRTUAL_MEMORY_INFO:
    case IA64_PAL_VIRTUAL_MEMORY_SUMMARY:
    case IA64_PAL_VIRTUAL_MEMORY_PAGE_SIZE:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_VM_PAGE_SIZE);
        break;
    case IA64_PAL_BUS_GET_FEATURES:
    case IA64_PAL_BUS_SET_FEATURES:
    case IA64_PAL_PROCESSOR_GET_FEATURES:
    case IA64_PAL_PROCESSOR_SET_FEATURES:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_FEATURES);
        break;
    case IA64_PAL_DEBUG_INFO:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_DEBUG);
        break;
    case IA64_PAL_FREQUENCY_BASE:
    case IA64_PAL_FREQUENCY_RATIOS:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_FREQUENCY);
        break;
    case IA64_PAL_PERFORMANCE_MONITOR_INFO:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_PERF_MONITOR);
        break;
    case IA64_PAL_FIXED_ADDRESS:
    case IA64_PAL_PLATFORM_ADDR:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_FIXED_PLATFORM);
        break;
    case IA64_PAL_VERSION_PROC:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_VERSION);
        break;
    case IA64_PAL_REGISTER_INFO:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_REGISTER_INFO);
        break;
    case IA64_PAL_PREFETCH_VISIBILITY:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_PREFETCH);
        break;
    case IA64_PAL_LOGICAL_TO_PHYSICAL:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_LOGICAL_TO_PHYSICAL);
        break;
    case IA64_PAL_CACHE_SHARED_INFO:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_CACHE_SHARED);
        break;
    case IA64_PAL_SHUTDOWN:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_SHUTDOWN);
        break;
    case IA64_PAL_COPY_PAL:
    case IA64_PAL_TEST_PROC:
    case IA64_PAL_CACHE_READ:
    case IA64_PAL_CACHE_WRITE:
    case IA64_PAL_VIRTUAL_MEMORY_TR_READ:
    case IA64_PAL_GET_PSTATE:
    case IA64_PAL_SET_PSTATE:
    case IA64_PAL_MACHINE_CHECK_ERROR_INJECT:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_OTHER);
        break;
    case IA64_PAL_HALT_INFO:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_HALT_INFO);
        break;
    case IA64_PAL_BRAND_INFO:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_BRAND);
        break;
    case IA64_PAL_MACHINE_CHECK_CLEAR_LOG:
    case IA64_PAL_MACHINE_CHECK_DRAIN:
    case IA64_PAL_MACHINE_CHECK_EXPECTED:
    case IA64_PAL_MACHINE_CHECK_DYNAMIC_STATE:
    case IA64_PAL_MACHINE_CHECK_REGISTER_MEMORY:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_MACHINE_CHECK);
        break;
    default:
        for (unsigned i = 0; i < reported_other_count; i++) {
            if (reported_other[i] == function_id) {
                goto count_other;
            }
        }
        if (reported_other_count < ARRAY_SIZE(reported_other)) {
            fprintf(stderr,
                    "[ia64-perf] firmware.pal.other_id.%u=0x%016" PRIx64
                    "\n",
                    reported_other_count, function_id);
            reported_other[reported_other_count++] = function_id;
        }
count_other:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_OTHER);
        break;
    }
}

bool vibtanium_firmware_dispatch_gate(CPUIA64State *env, uint64_t gate_ip)
{
    uint64_t physical;
    IA64FirmwareResult result;
    uint64_t function_id;
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;
    uint64_t arg3;

    if (!efi_gate_address_is_valid_alias(gate_ip)) {
        return false;
    }
    physical = ia64_region_offset(gate_ip);

    if (physical == VIBTANIUM_EFI_PAL_PROC) {
        bool static_call;

        IA64_PERF_INC(IA64_PERF_FIRMWARE_PAL);
        function_id = ia64_read_gr(env, 28);
        static_call = pal_uses_static_calling_convention(function_id);
        if (static_call) {
            arg0 = ia64_read_gr(env, 29);
            arg1 = ia64_read_gr(env, 30);
            arg2 = ia64_read_gr(env, 31);
        } else {
            /*
             * PAL stacked calls copy arguments to out0-out3 before br.call;
             * at the gate they are visible as the callee's in0-in3.
             */
            function_id = ia64_read_gr(env, 32);
            arg0 = ia64_read_gr(env, 33);
            arg1 = ia64_read_gr(env, 34);
            arg2 = ia64_read_gr(env, 35);
        }
        ia64_perf_count_pal_call(function_id);
        result = dispatch_pal(env, function_id, arg0, arg1);
        firmware_trace_call(env, "pal", pal_procedure_name(function_id),
                            function_id, arg0, arg1, arg2, result);
        firmware_write_result(env, result, !static_call);
        if ((function_id == IA64_PAL_HALT ||
             function_id == IA64_PAL_HALT_LIGHT) &&
            result.status == IA64_FIRMWARE_STATUS_SUCCESS) {
            CPUState *cs = env_cpu(env);

            /*
             * PAL halt completes when an external interrupt arrives.  The
             * return values and IP are committed above, so the vCPU can
             * sleep until has_work() sees CPU_INTERRUPT_HARD or a
             * deliverable interrupt (ITM deadline timer, device, IPI).
             * AR.ITC keeps running while halted because it follows the QEMU
             * virtual clock.
             */
            cs->halted = 1;
            cs->exception_index = EXCP_HLT;
            cpu_loop_exit(cs);
        }
        return true;
    }

    if (physical == VIBTANIUM_EFI_SAL_PROC) {
        IA64_PERF_INC(IA64_PERF_FIRMWARE_SAL);
        function_id = ia64_read_gr(env, 32);
        arg0 = ia64_read_gr(env, 33);
        arg1 = ia64_read_gr(env, 34);
        arg2 = ia64_read_gr(env, 35);
        arg3 = ia64_read_gr(env, 36);
        result = dispatch_sal(function_id, arg0, arg1, arg2, arg3);
        firmware_trace_call(env, "sal", sal_procedure_name(function_id),
                            function_id, arg0, arg1, arg2, result);
        firmware_write_result(env, result, true);
        return true;
    }

    return false;
}
