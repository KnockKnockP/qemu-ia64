/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HW_IA64_EFI_H
#define HW_IA64_EFI_H

#include "qapi/error.h"
#include "target/ia64/cpu.h"

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
#define VIBTANIUM_EFI_FIRMWARE_VENDOR   UINT64_C(0x00086000)
#define VIBTANIUM_EFI_CONFIGURATION_TABLE UINT64_C(0x00086100)
#define VIBTANIUM_EFI_DEVICE_PATH       UINT64_C(0x00086200)
#define VIBTANIUM_EFI_BLOCK_IO          UINT64_C(0x00086300)
#define VIBTANIUM_EFI_BLOCK_IO_MEDIA    UINT64_C(0x00086340)
#define VIBTANIUM_EFI_SIMPLE_FILE_SYSTEM UINT64_C(0x00086400)
#define VIBTANIUM_EFI_PAL_PROC          UINT64_C(0x00086500)
#define VIBTANIUM_EFI_SAL_PROC          UINT64_C(0x00086510)
#define VIBTANIUM_EFI_SAL_GP            UINT64_C(0x00086520)
#define VIBTANIUM_EFI_SAL_SYSTEM_TABLE  UINT64_C(0x00086600)
#define VIBTANIUM_EFI_BLOB_BASE         UINT64_C(0x00070000)
#define VIBTANIUM_EFI_BLOB_SIZE         UINT64_C(0x00020000)
#define VIBTANIUM_EFI_STACK_BASE        UINT64_C(0x01f00000)
#define VIBTANIUM_EFI_STACK_SIZE        UINT64_C(0x00040000)
#define VIBTANIUM_EFI_BACKING_STORE_BASE UINT64_C(0x01f40000)
#define VIBTANIUM_EFI_BACKING_STORE_SIZE UINT64_C(0x00040000)
#define VIBTANIUM_EFI_POOL_BASE         UINT64_C(0x02000000)
#define VIBTANIUM_EFI_POOL_SIZE         UINT64_C(0x01000000)

#define VIBTANIUM_EFI_BOOT_SERVICE_COUNT    43
#define VIBTANIUM_EFI_RUNTIME_SERVICE_COUNT 11
#define VIBTANIUM_EFI_CON_OUT_SERVICE_COUNT 9
#define VIBTANIUM_EFI_CON_IN_SERVICE_COUNT  2
#define VIBTANIUM_EFI_BLOCK_IO_SERVICE_COUNT 4
#define VIBTANIUM_EFI_SIMPLE_FILE_SYSTEM_SERVICE_COUNT 1
#define VIBTANIUM_EFI_FILE_SERVICE_COUNT 10

#define VIBTANIUM_EFI_BOOT_ALLOCATE_PAGES_INDEX       2
#define VIBTANIUM_EFI_BOOT_FREE_PAGES_INDEX           3
#define VIBTANIUM_EFI_BOOT_GET_MEMORY_MAP_INDEX       4
#define VIBTANIUM_EFI_BOOT_INSTALL_PROTOCOL_INDEX 13
#define VIBTANIUM_EFI_BOOT_UNINSTALL_PROTOCOL_INDEX 15
#define VIBTANIUM_EFI_BOOT_HANDLE_PROTOCOL_INDEX 16
#define VIBTANIUM_EFI_BOOT_LOCATE_HANDLE_INDEX 19
#define VIBTANIUM_EFI_BOOT_EXIT_BOOT_SERVICES_INDEX  26
#define VIBTANIUM_EFI_BOOT_STALL_INDEX               28
#define VIBTANIUM_EFI_BOOT_SET_WATCHDOG_INDEX    29
#define VIBTANIUM_EFI_BOOT_OPEN_PROTOCOL_INDEX    32
#define VIBTANIUM_EFI_BOOT_CLOSE_PROTOCOL_INDEX   33
#define VIBTANIUM_EFI_BOOT_LOCATE_PROTOCOL_INDEX  37
#define VIBTANIUM_EFI_BOOT_CALCULATE_CRC32_INDEX  40
#define VIBTANIUM_EFI_BOOT_COPY_MEM_INDEX         41
#define VIBTANIUM_EFI_BOOT_SET_MEM_INDEX          42

#define VIBTANIUM_EFI_SUCCESS           UINT64_C(0x0000000000000000)
#define VIBTANIUM_EFI_LOAD_ERROR        UINT64_C(0x8000000000000001)
#define VIBTANIUM_EFI_INVALID_PARAMETER UINT64_C(0x8000000000000002)
#define VIBTANIUM_EFI_UNSUPPORTED       UINT64_C(0x8000000000000003)
#define VIBTANIUM_EFI_BUFFER_TOO_SMALL  UINT64_C(0x8000000000000005)
#define VIBTANIUM_EFI_NOT_READY         UINT64_C(0x8000000000000006)
#define VIBTANIUM_EFI_DEVICE_ERROR      UINT64_C(0x8000000000000007)
#define VIBTANIUM_EFI_WRITE_PROTECTED   UINT64_C(0x8000000000000008)
#define VIBTANIUM_EFI_OUT_OF_RESOURCES  UINT64_C(0x8000000000000009)
#define VIBTANIUM_EFI_ACCESS_DENIED     UINT64_C(0x800000000000000f)
#define VIBTANIUM_EFI_NOT_FOUND         UINT64_C(0x8000000000000014)
#define VIBTANIUM_EFI_END_OF_FILE       UINT64_C(0x800000000000001f)

#define VIBTANIUM_EFI_PROTOCOL_REVISION UINT64_C(0x0000000000010000)

struct VibtaniumEfiBlockDevice;

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
    uint16_t number_of_sections;
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
void vibtanium_efi_image_destroy(VibtaniumEfiImage *image);

void vibtanium_efi_prepare_cpu(CPUIA64State *env,
                               const VibtaniumEfiImage *image);
uint8_t *vibtanium_efi_build_firmware_blob(size_t *size,
                                           const VibtaniumEfiImage *image,
                                           const struct VibtaniumEfiBlockDevice *boot_media);
bool vibtanium_efi_dispatch_gate(CPUIA64State *env, uint64_t gate_ip);
void vibtanium_efi_register_boot_media(
    const struct VibtaniumEfiBlockDevice *boot_media);
void vibtanium_efi_set_linux_cmdline_append(const char *append);

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
