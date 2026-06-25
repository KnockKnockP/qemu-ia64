/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HW_IA64_EFI_STORAGE_H
#define HW_IA64_EFI_STORAGE_H

#include "qapi/error.h"

#define VIBATNIUM_EFI_FALLBACK_PATH "/efi/boot/bootia64.efi"

typedef int (*VibatniumEfiBlockReadFunc)(void *opaque,
                                         uint64_t offset,
                                         uint32_t bytes,
                                         void *buffer,
                                         Error **errp);

typedef enum VibatniumEfiStorageStatus {
    VIBATNIUM_EFI_STORAGE_OK,
    VIBATNIUM_EFI_STORAGE_READ_ERROR,
    VIBATNIUM_EFI_STORAGE_NO_ISO9660,
    VIBATNIUM_EFI_STORAGE_INVALID_FILESYSTEM,
    VIBATNIUM_EFI_STORAGE_NOT_FOUND,
    VIBATNIUM_EFI_STORAGE_UNSUPPORTED,
} VibatniumEfiStorageStatus;

typedef struct VibatniumEfiBlockDevice {
    const char *name;
    uint64_t size;
    uint32_t block_size;
    bool read_only;
    bool removable;
    bool cdrom;
    VibatniumEfiBlockReadFunc read;
    void *opaque;
} VibatniumEfiBlockDevice;

typedef struct VibatniumEfiFile {
    uint32_t extent_lba;
    uint32_t size;
    bool is_directory;
    char path[256];
    char device_name[128];
} VibatniumEfiFile;

typedef struct VibatniumEfiStorageReport {
    VibatniumEfiStorageStatus status;
    char message[320];
} VibatniumEfiStorageReport;

const char *vibatnium_efi_storage_status_name(
    VibatniumEfiStorageStatus status);

bool vibatnium_efi_iso9660_find_path(VibatniumEfiBlockDevice *dev,
                                     const char *path,
                                     VibatniumEfiFile *file,
                                     VibatniumEfiStorageReport *report,
                                     Error **errp);
bool vibatnium_efi_iso9660_read_file(VibatniumEfiBlockDevice *dev,
                                     const VibatniumEfiFile *file,
                                     uint8_t **data,
                                     size_t *size,
                                     VibatniumEfiStorageReport *report,
                                     Error **errp);
bool vibatnium_efi_cdrom_read_path(VibatniumEfiBlockDevice *dev,
                                   const char *path,
                                   uint8_t **data,
                                   size_t *size,
                                   char *source,
                                   size_t source_size,
                                   VibatniumEfiStorageReport *report,
                                   Error **errp);

#endif
