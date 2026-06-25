/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HW_IA64_EFI_H
#define HW_IA64_EFI_H

#include "qapi/error.h"
#include "target/ia64/cpu.h"

#define VIBATNIUM_EFI_PE_MACHINE_IA64 0x0200

#define VIBATNIUM_EFI_APP_BASE          UINT64_C(0x01000000)
#define VIBATNIUM_EFI_IMAGE_HANDLE      UINT64_C(0x00070000)
#define VIBATNIUM_EFI_LOADED_IMAGE      UINT64_C(0x00071000)
#define VIBATNIUM_EFI_SYSTEM_TABLE      UINT64_C(0x00080000)
#define VIBATNIUM_EFI_CON_OUT           UINT64_C(0x00081000)
#define VIBATNIUM_EFI_BOOT_SERVICES     UINT64_C(0x00082000)
#define VIBATNIUM_EFI_RUNTIME_SERVICES  UINT64_C(0x00083000)

#define VIBATNIUM_EFI_SUCCESS           UINT64_C(0x0000000000000000)
#define VIBATNIUM_EFI_LOAD_ERROR        UINT64_C(0x8000000000000001)
#define VIBATNIUM_EFI_INVALID_PARAMETER UINT64_C(0x8000000000000002)
#define VIBATNIUM_EFI_UNSUPPORTED       UINT64_C(0x8000000000000003)
#define VIBATNIUM_EFI_NOT_FOUND         UINT64_C(0x8000000000000014)

typedef enum VibatniumEfiService {
    VIBATNIUM_EFI_SERVICE_UNKNOWN,
    VIBATNIUM_EFI_SERVICE_LOADED_IMAGE_PROTOCOL,
    VIBATNIUM_EFI_SERVICE_OUTPUT_STRING,
    VIBATNIUM_EFI_SERVICE_EXIT,
    VIBATNIUM_EFI_SERVICE_EXIT_BOOT_SERVICES,
    VIBATNIUM_EFI_SERVICE_GET_VARIABLE,
    VIBATNIUM_EFI_SERVICE_SET_VARIABLE,
} VibatniumEfiService;

typedef struct VibatniumEfiImage {
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
} VibatniumEfiImage;

typedef struct VibatniumEfiServiceCall {
    VibatniumEfiService service;
    const char *service_name;
    uint64_t guest_ip;
    uint64_t args[6];
    uint8_t nargs;
    uint64_t status;
    char message[320];
} VibatniumEfiServiceCall;

typedef enum VibatniumEfiFrontierKind {
    VIBATNIUM_EFI_FRONTIER_IMAGE_ENTRY,
    VIBATNIUM_EFI_FRONTIER_EFI_SERVICE_CALL,
    VIBATNIUM_EFI_FRONTIER_FILE_READ,
    VIBATNIUM_EFI_FRONTIER_MEMORY_MAP,
    VIBATNIUM_EFI_FRONTIER_EXIT_BOOT_SERVICES,
    VIBATNIUM_EFI_FRONTIER_KERNEL_ENTRY,
    VIBATNIUM_EFI_FRONTIER_BOOT_PARAMETERS,
    VIBATNIUM_EFI_FRONTIER_SAL_PAL_CALL,
} VibatniumEfiFrontierKind;

bool vibatnium_efi_image_from_buffer(const char *path,
                                     const uint8_t *file,
                                     size_t file_size,
                                     uint64_t load_base,
                                     VibatniumEfiImage *image,
                                     Error **errp);
bool vibatnium_efi_image_from_file(const char *path,
                                   uint64_t load_base,
                                   VibatniumEfiImage *image,
                                   Error **errp);
void vibatnium_efi_image_destroy(VibatniumEfiImage *image);

void vibatnium_efi_prepare_cpu(CPUIA64State *env,
                               const VibatniumEfiImage *image);

const char *vibatnium_efi_status_name(uint64_t status);
const char *vibatnium_efi_service_name(VibatniumEfiService service);
uint64_t vibatnium_efi_record_unimplemented_service(
    VibatniumEfiServiceCall *call,
    VibatniumEfiService service,
    uint64_t guest_ip,
    const uint64_t *args,
    uint8_t nargs);
const char *vibatnium_efi_frontier_name(VibatniumEfiFrontierKind kind);
void vibatnium_efi_format_frontier(char *buffer,
                                   size_t buffer_size,
                                   VibatniumEfiFrontierKind kind,
                                   uint64_t guest_ip,
                                   const char *state,
                                   const char *detail);

#endif
