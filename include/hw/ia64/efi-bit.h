/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef HW_IA64_EFI_BIT_H
#define HW_IA64_EFI_BIT_H

#include "hw/ia64/efi-storage.h"

extern const uint8_t vibtanium_efi_bit_blob[];
extern const size_t vibtanium_efi_bit_blob_size;

bool vibtanium_efi_bit_media_device(VibtaniumEfiBlockDevice *dev,
                                    Error **errp);

#endif
