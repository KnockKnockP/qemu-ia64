/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HW_IA64_EFI_H
#define HW_IA64_EFI_H

#include "qapi/error.h"
#include "target/ia64/cpu.h"

typedef struct MemoryRegion MemoryRegion;

#define VIBTANIUM_EFI_PE_MACHINE_IA64 0x0200

#define VIBTANIUM_EFI_APP_BASE          UINT64_C(0x01000000)
#define VIBTANIUM_EFI_IMAGE_HANDLE      UINT64_C(0x00070000)
#define VIBTANIUM_EFI_LOADED_IMAGE      UINT64_C(0x00071000)
#define VIBTANIUM_EFI_BOOT_DEVICE_HANDLE UINT64_C(0x00072000)
#define VIBTANIUM_EFI_CON_IN_WAIT_EVENT UINT64_C(0x00074000)
#define VIBTANIUM_EFI_SYSTEM_TABLE      UINT64_C(0x00080000)
#define VIBTANIUM_EFI_CON_IN            UINT64_C(0x00080800)
#define VIBTANIUM_EFI_CON_OUT           UINT64_C(0x00081000)
#define VIBTANIUM_EFI_CON_OUT_MODE      UINT64_C(0x00081100)
#define VIBTANIUM_EFI_BOOT_SERVICES     UINT64_C(0x00082000)
#define VIBTANIUM_EFI_RUNTIME_SERVICES  UINT64_C(0x00083000)
#define VIBTANIUM_EFI_DESCRIPTOR_BASE   UINT64_C(0x00084000)
#define VIBTANIUM_EFI_CALL_GATE_BASE    UINT64_C(0x00085000)
#define VIBTANIUM_EFI_START_IMAGE_RETURN_GATE UINT64_C(0x00085600)
#define VIBTANIUM_EFI_FIRMWARE_VENDOR   UINT64_C(0x00086000)
#define VIBTANIUM_EFI_CONFIGURATION_TABLE UINT64_C(0x00086100)
#define VIBTANIUM_EFI_DEVICE_PATH       UINT64_C(0x00086200)
#define VIBTANIUM_EFI_BLOCK_IO          UINT64_C(0x00086300)
#define VIBTANIUM_EFI_BLOCK_IO_MEDIA    UINT64_C(0x00086340)
#define VIBTANIUM_EFI_SIMPLE_FILE_SYSTEM UINT64_C(0x00086400)
#define VIBTANIUM_EFI_SAL_PROC          UINT64_C(0x00100000)
#define VIBTANIUM_EFI_SAL_GP            UINT64_C(0x00101000)
#define VIBTANIUM_EFI_PAL_PROC          UINT64_C(0x0008f000)
#define VIBTANIUM_EFI_SAL_SYSTEM_TABLE  UINT64_C(0x00086600)
#define VIBTANIUM_EFI_HCDP_TABLE        UINT64_C(0x00086700)
#define VIBTANIUM_EFI_ACPI_RSDP         UINT64_C(0x00086800)
#define VIBTANIUM_EFI_ACPI_RSDT         UINT64_C(0x00086840)
#define VIBTANIUM_EFI_ACPI_XSDT         UINT64_C(0x00086880)
#define VIBTANIUM_EFI_ACPI_FADT         UINT64_C(0x00086900)
#define VIBTANIUM_EFI_ACPI_DSDT         UINT64_C(0x00086a00)
#define VIBTANIUM_EFI_ACPI_MADT         UINT64_C(0x00086b00)
#define VIBTANIUM_EFI_ACPI_FACS         UINT64_C(0x00086c00)
#define VIBTANIUM_EFI_GOP               UINT64_C(0x00088000)
#define VIBTANIUM_EFI_GOP_MODE          UINT64_C(0x00088020)
#define VIBTANIUM_EFI_GOP_MODE_INFO     UINT64_C(0x00088048)
#define VIBTANIUM_EFI_LOAD_OPTIONS      UINT64_C(0x00088100)
#define VIBTANIUM_EFI_LOAD_OPTIONS_SIZE UINT64_C(0x00001000)
#define VIBTANIUM_EFI_LOADED_IMAGE_FILE_PATH UINT64_C(0x00089100)
#define VIBTANIUM_EFI_BLOB_BASE         UINT64_C(0x00070000)
#define VIBTANIUM_EFI_BLOB_SIZE         UINT64_C(0x00020000)
#define VIBTANIUM_EFI_GATE_SIZE         16
#define VIBTANIUM_EFI_STACK_BASE        UINT64_C(0x01f00000)
#define VIBTANIUM_EFI_STACK_SIZE        UINT64_C(0x00040000)
#define VIBTANIUM_EFI_BACKING_STORE_BASE UINT64_C(0x01f40000)
#define VIBTANIUM_EFI_BACKING_STORE_SIZE UINT64_C(0x00040000)
#define VIBTANIUM_EFI_POOL_BASE         UINT64_C(0x08000000)
#define VIBTANIUM_EFI_POOL_SIZE         UINT64_C(0x01000000)

#define VIBTANIUM_EFI_BOOT_SERVICE_COUNT    43
#define VIBTANIUM_EFI_RUNTIME_SERVICE_COUNT 11
#define VIBTANIUM_EFI_CON_OUT_SERVICE_COUNT 9
#define VIBTANIUM_EFI_CON_IN_SERVICE_COUNT  2
#define VIBTANIUM_EFI_BLOCK_IO_SERVICE_COUNT 4
#define VIBTANIUM_EFI_SIMPLE_FILE_SYSTEM_SERVICE_COUNT 1
#define VIBTANIUM_EFI_FILE_SERVICE_COUNT 10
#define VIBTANIUM_EFI_GOP_SERVICE_COUNT 3

#define VIBTANIUM_EFI_BOOT_ALLOCATE_PAGES_INDEX       2
#define VIBTANIUM_EFI_BOOT_FREE_PAGES_INDEX           3
#define VIBTANIUM_EFI_BOOT_GET_MEMORY_MAP_INDEX       4
#define VIBTANIUM_EFI_BOOT_INSTALL_PROTOCOL_INDEX 13
#define VIBTANIUM_EFI_BOOT_UNINSTALL_PROTOCOL_INDEX 15
#define VIBTANIUM_EFI_BOOT_HANDLE_PROTOCOL_INDEX 16
#define VIBTANIUM_EFI_BOOT_LOCATE_HANDLE_INDEX 19
#define VIBTANIUM_EFI_BOOT_LOAD_IMAGE_INDEX        22
#define VIBTANIUM_EFI_BOOT_START_IMAGE_INDEX       23
#define VIBTANIUM_EFI_BOOT_EXIT_INDEX              24
#define VIBTANIUM_EFI_BOOT_EXIT_BOOT_SERVICES_INDEX  26
#define VIBTANIUM_EFI_BOOT_STALL_INDEX               28
#define VIBTANIUM_EFI_BOOT_SET_WATCHDOG_INDEX    29
#define VIBTANIUM_EFI_BOOT_OPEN_PROTOCOL_INDEX    32
#define VIBTANIUM_EFI_BOOT_CLOSE_PROTOCOL_INDEX   33
#define VIBTANIUM_EFI_BOOT_LOCATE_PROTOCOL_INDEX  37
#define VIBTANIUM_EFI_BOOT_CALCULATE_CRC32_INDEX  40
#define VIBTANIUM_EFI_BOOT_COPY_MEM_INDEX         41
#define VIBTANIUM_EFI_BOOT_SET_MEM_INDEX          42

#define VIBTANIUM_EFI_ERROR(code) \
    (UINT64_C(0x8000000000000000) | UINT64_C(code))
#define VIBTANIUM_EFI_SUCCESS           UINT64_C(0x0000000000000000)
#define VIBTANIUM_EFI_LOAD_ERROR        VIBTANIUM_EFI_ERROR(1)
#define VIBTANIUM_EFI_INVALID_PARAMETER VIBTANIUM_EFI_ERROR(2)
#define VIBTANIUM_EFI_UNSUPPORTED       VIBTANIUM_EFI_ERROR(3)
#define VIBTANIUM_EFI_BUFFER_TOO_SMALL  VIBTANIUM_EFI_ERROR(5)
#define VIBTANIUM_EFI_NOT_READY         VIBTANIUM_EFI_ERROR(6)
#define VIBTANIUM_EFI_DEVICE_ERROR      VIBTANIUM_EFI_ERROR(7)
#define VIBTANIUM_EFI_WRITE_PROTECTED   VIBTANIUM_EFI_ERROR(8)
#define VIBTANIUM_EFI_OUT_OF_RESOURCES  VIBTANIUM_EFI_ERROR(9)
#define VIBTANIUM_EFI_ACCESS_DENIED     VIBTANIUM_EFI_ERROR(15)
#define VIBTANIUM_EFI_NOT_FOUND         VIBTANIUM_EFI_ERROR(14)
#define VIBTANIUM_EFI_END_OF_FILE       VIBTANIUM_EFI_ERROR(31)

#define VIBTANIUM_EFI_PROTOCOL_REVISION UINT64_C(0x0000000000010000)

#define VIBTANIUM_EFI_RESERVED_MEMORY_TYPE 0
#define VIBTANIUM_EFI_LOADER_CODE          1
#define VIBTANIUM_EFI_LOADER_DATA          2
#define VIBTANIUM_EFI_RUNTIME_SERVICES_CODE 5
#define VIBTANIUM_EFI_PAL_CODE              13
#define VIBTANIUM_EFI_MEMORY_WB UINT64_C(0x0000000000000008)
#define VIBTANIUM_EFI_MEMORY_RUNTIME UINT64_C(0x8000000000000000)

#define VIBTANIUM_EFI_ALLOCATE_ANY_PAGES   0
#define VIBTANIUM_EFI_ALLOCATE_MAX_ADDRESS 1
#define VIBTANIUM_EFI_ALLOCATE_ADDRESS     2

#define VIBTANIUM_EFI_SCAN_UP        0x0001
#define VIBTANIUM_EFI_SCAN_DOWN      0x0002
#define VIBTANIUM_EFI_SCAN_RIGHT     0x0003
#define VIBTANIUM_EFI_SCAN_LEFT      0x0004
#define VIBTANIUM_EFI_SCAN_HOME      0x0005
#define VIBTANIUM_EFI_SCAN_END       0x0006
#define VIBTANIUM_EFI_SCAN_INSERT    0x0007
#define VIBTANIUM_EFI_SCAN_DELETE    0x0008
#define VIBTANIUM_EFI_SCAN_PAGE_UP   0x0009
#define VIBTANIUM_EFI_SCAN_PAGE_DOWN 0x000a
#define VIBTANIUM_EFI_SCAN_F1        0x000b
#define VIBTANIUM_EFI_SCAN_ESC       0x0017

struct VibtaniumEfiBlockDevice;

typedef struct VibtaniumEfiInputKey {
    uint16_t scan_code;
    uint16_t unicode_char;
} VibtaniumEfiInputKey;

typedef struct VibtaniumEfiFirmwareOptions {
    bool hcdp_serial_console;
} VibtaniumEfiFirmwareOptions;

typedef enum VibtaniumEfiService {
    VIBTANIUM_EFI_SERVICE_UNKNOWN,
    VIBTANIUM_EFI_SERVICE_LOADED_IMAGE_PROTOCOL,
    VIBTANIUM_EFI_SERVICE_OUTPUT_STRING,
    VIBTANIUM_EFI_SERVICE_EXIT,
    VIBTANIUM_EFI_SERVICE_EXIT_BOOT_SERVICES,
    VIBTANIUM_EFI_SERVICE_GET_VARIABLE,
    VIBTANIUM_EFI_SERVICE_SET_VARIABLE,
} VibtaniumEfiService;

typedef struct VibtaniumEfiImage {
    uint8_t *data;
    size_t size;
    uint64_t load_base;
    uint64_t entry_descriptor;
    uint64_t entry;
    uint64_t global_pointer;
    uint64_t preferred_image_base;
    uint32_t entry_rva;
    uint32_t size_of_image;
    uint32_t section_alignment;
    uint32_t relocation_rva;
    uint32_t relocation_size;
    uint16_t number_of_sections;
    uint8_t *load_options;
    size_t load_options_size;
    char efi_file_path[256];
    char source_path[256];
    char message[256];
} VibtaniumEfiImage;

typedef struct VibtaniumEfiServiceCall {
    VibtaniumEfiService service;
    const char *service_name;
    uint64_t guest_ip;
    uint64_t args[6];
    uint8_t nargs;
    uint64_t status;
    char message[320];
} VibtaniumEfiServiceCall;

typedef enum VibtaniumEfiFrontierKind {
    VIBTANIUM_EFI_FRONTIER_IMAGE_ENTRY,
    VIBTANIUM_EFI_FRONTIER_EFI_SERVICE_CALL,
    VIBTANIUM_EFI_FRONTIER_FILE_READ,
    VIBTANIUM_EFI_FRONTIER_MEMORY_MAP,
    VIBTANIUM_EFI_FRONTIER_EXIT_BOOT_SERVICES,
    VIBTANIUM_EFI_FRONTIER_KERNEL_ENTRY,
    VIBTANIUM_EFI_FRONTIER_BOOT_PARAMETERS,
    VIBTANIUM_EFI_FRONTIER_SAL_PAL_CALL,
} VibtaniumEfiFrontierKind;

bool vibtanium_efi_image_from_buffer(const char *path,
                                     const uint8_t *file,
                                     size_t file_size,
                                     uint64_t load_base,
                                     VibtaniumEfiImage *image,
                                     Error **errp);
bool vibtanium_efi_image_from_file(const char *path,
                                   uint64_t load_base,
                                   VibtaniumEfiImage *image,
                                   Error **errp);
bool vibtanium_efi_image_relocate(VibtaniumEfiImage *image,
                                  uint64_t load_base,
                                  Error **errp);
bool vibtanium_efi_decode_uint32_arg(uint64_t raw, uint32_t *value);
uint32_t vibtanium_efi_page_allocation_memory_type(uint64_t allocate_type,
                                                   uint64_t memory_type);
void vibtanium_efi_pal_code_memory_descriptor(uint32_t *type,
                                              uint64_t *address,
                                              uint64_t *pages,
                                              uint64_t *attributes);
void vibtanium_efi_runtime_code_memory_descriptor(uint64_t code_address,
                                                  uint32_t *type,
                                                  uint64_t *address,
                                                  uint64_t *pages,
                                                  uint64_t *attributes);
bool vibtanium_efi_timer_due(uint64_t now, uint64_t deadline);
void vibtanium_efi_image_destroy(VibtaniumEfiImage *image);

bool vibtanium_efi_cpu_is_pristine_for_handoff(const CPUIA64State *env);
bool vibtanium_efi_prepare_cpu(CPUIA64State *env,
                               const VibtaniumEfiImage *image);
void vibtanium_efi_loader_benchmark_start(void);
uint8_t *vibtanium_efi_build_firmware_blob(size_t *size,
                                           const VibtaniumEfiImage *image,
                                           const struct VibtaniumEfiBlockDevice *boot_media,
                                           const VibtaniumEfiFirmwareOptions *options);
void vibtanium_efi_build_branch_gate(
    uint8_t gate[VIBTANIUM_EFI_GATE_SIZE]);
bool vibtanium_firmware_dispatch_gate(CPUIA64State *env, uint64_t gate_ip);
bool vibtanium_efi_dispatch_gate(CPUIA64State *env, uint64_t gate_ip);
void vibtanium_efi_register_loaded_image(uint64_t image_base,
                                         uint64_t image_size);
void vibtanium_efi_set_guest_ram_size(uint64_t ram_size);
void vibtanium_efi_register_boot_media(
    const struct VibtaniumEfiBlockDevice *boot_media);
void vibtanium_efi_set_linux_cmdline_append(const char *append);
bool vibtanium_efi_linux_cmdline_append_pending(void);
void vibtanium_efi_maybe_apply_linux_cmdline_append(CPUIA64State *env);
void vibtanium_efi_input_set_auto_enter(bool enabled);
bool vibtanium_efi_input_enqueue(uint16_t scan_code, uint16_t unicode_char);
bool vibtanium_efi_input_has_key(void);
bool vibtanium_efi_input_dequeue(VibtaniumEfiInputKey *key);

void vibtanium_efi_console_init(MemoryRegion *framebuffer,
                                MemoryRegion *vga_legacy,
                                uint8_t *vga_crtc);
void vibtanium_efi_console_set_input_active(bool active);
void vibtanium_efi_console_set_vga_text_active(bool active);
void vibtanium_efi_console_recover_post_load(uint64_t ip);
void vibtanium_efi_console_reset(void);
void vibtanium_efi_console_clear(void);
void vibtanium_efi_console_putchar(uint16_t ch);
void vibtanium_efi_console_set_attribute(uint64_t attribute);
bool vibtanium_efi_console_set_cursor_position(uint64_t column, uint64_t row);
void vibtanium_efi_console_enable_cursor(bool visible);
uint32_t vibtanium_efi_console_attribute(void);
uint32_t vibtanium_efi_console_cursor_column(void);
uint32_t vibtanium_efi_console_cursor_row(void);
bool vibtanium_efi_console_cursor_visible(void);
void vibtanium_efi_console_update_rect(uint64_t x, uint64_t y,
                                       uint64_t width, uint64_t height);

const char *vibtanium_efi_status_name(uint64_t status);
const char *vibtanium_efi_service_name(VibtaniumEfiService service);
uint64_t vibtanium_efi_record_unimplemented_service(
    VibtaniumEfiServiceCall *call,
    VibtaniumEfiService service,
    uint64_t guest_ip,
    const uint64_t *args,
    uint8_t nargs);
const char *vibtanium_efi_frontier_name(VibtaniumEfiFrontierKind kind);
void vibtanium_efi_format_frontier(char *buffer,
                                   size_t buffer_size,
                                   VibtaniumEfiFrontierKind kind,
                                   uint64_t guest_ip,
                                   const char *state,
                                   const char *detail);

#endif
