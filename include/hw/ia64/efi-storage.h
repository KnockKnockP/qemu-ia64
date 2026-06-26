/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HW_IA64_EFI_STORAGE_H
#define HW_IA64_EFI_STORAGE_H

#include "qapi/error.h"

#define VIBTANIUM_EFI_FALLBACK_PATH "/efi/boot/bootia64.efi"

typedef int (*VibtaniumEfiBlockReadFunc)(void *opaque,
                                         uint64_t offset,
                                         uint32_t bytes,
                                         void *buffer,
                                         Error **errp);

typedef enum VibtaniumEfiStorageStatus {
    VIBTANIUM_EFI_STORAGE_OK,
    VIBTANIUM_EFI_STORAGE_READ_ERROR,
    VIBTANIUM_EFI_STORAGE_NO_ISO9660,
    VIBTANIUM_EFI_STORAGE_INVALID_FILESYSTEM,
    VIBTANIUM_EFI_STORAGE_NOT_FOUND,
    VIBTANIUM_EFI_STORAGE_UNSUPPORTED,
} VibtaniumEfiStorageStatus;

typedef struct VibtaniumEfiBlockDevice {
    const char *name;
    uint64_t size;
    uint32_t block_size;
    bool read_only;
    bool removable;
    bool cdrom;
    VibtaniumEfiBlockReadFunc read;
    void *opaque;
} VibtaniumEfiBlockDevice;

typedef struct VibtaniumEfiFile {
    uint32_t extent_lba;
    uint32_t size;
    bool is_directory;
    char path[256];
    char device_name[128];
} VibtaniumEfiFile;

typedef struct VibtaniumEfiStorageReport {
    VibtaniumEfiStorageStatus status;
    char message[320];
} VibtaniumEfiStorageReport;

const char *vibtanium_efi_storage_status_name(
    VibtaniumEfiStorageStatus status);

bool vibtanium_efi_iso9660_find_path(VibtaniumEfiBlockDevice *dev,
                                     const char *path,
                                     VibtaniumEfiFile *file,
                                     VibtaniumEfiStorageReport *report,
                                     Error **errp);
bool vibtanium_efi_iso9660_read_file(VibtaniumEfiBlockDevice *dev,
                                     const VibtaniumEfiFile *file,
                                     uint8_t **data,
                                     size_t *size,
                                     VibtaniumEfiStorageReport *report,
                                     Error **errp);
bool vibtanium_efi_cdrom_read_path(VibtaniumEfiBlockDevice *dev,
                                   const char *path,
                                   uint8_t **data,
                                   size_t *size,
                                   char *source,
                                   size_t source_size,
                                   VibtaniumEfiStorageReport *report,
                                   Error **errp);

#endif
