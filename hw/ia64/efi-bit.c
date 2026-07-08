/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "hw/ia64/efi-bit.h"

#define BIT_SECTOR_SIZE 512
#define BIT_TOTAL_SECTORS 5000
#define BIT_FAT_SECTORS 20
#define BIT_ROOT_ENTRIES 16
#define BIT_ROOT_DIR_SECTORS 1
#define BIT_FIRST_DATA_SECTOR \
    (1 + BIT_FAT_SECTORS + BIT_ROOT_DIR_SECTORS)
#define BIT_MEDIA_BYTES (BIT_TOTAL_SECTORS * BIT_SECTOR_SIZE)
#define BIT_FAT_OFFSET BIT_SECTOR_SIZE
#define BIT_ROOT_OFFSET ((1 + BIT_FAT_SECTORS) * BIT_SECTOR_SIZE)
#define BIT_DATA_OFFSET (BIT_FIRST_DATA_SECTOR * BIT_SECTOR_SIZE)

typedef struct VibtaniumBitMedia {
    uint8_t *data;
    uint64_t size;
} VibtaniumBitMedia;

static void bit_wr16(uint8_t *p, uint16_t value)
{
    p[0] = value;
    p[1] = value >> 8;
}

static void bit_wr32(uint8_t *p, uint32_t value)
{
    p[0] = value;
    p[1] = value >> 8;
    p[2] = value >> 16;
    p[3] = value >> 24;
}

static uint8_t *bit_cluster_ptr(uint8_t *image, uint16_t cluster)
{
    return image + BIT_DATA_OFFSET +
           (uint64_t)(cluster - 2) * BIT_SECTOR_SIZE;
}

static void bit_fat_entry(uint8_t *fat, uint16_t cluster, uint16_t value)
{
    bit_wr16(fat + (uint64_t)cluster * sizeof(uint16_t), value);
}

static void bit_dir_entry(uint8_t *dir, size_t index, const char name[11],
                          uint8_t attr, uint16_t cluster, uint32_t size)
{
    uint8_t *entry = dir + index * 32;

    memset(entry, 0, 32);
    memcpy(entry, name, 11);
    entry[11] = attr;
    bit_wr16(entry + 26, cluster);
    bit_wr32(entry + 28, size);
}

static bool bit_build_media(uint8_t *image, Error **errp)
{
    static const char bit_text[] = "vibtanium-bit-ok\n";
    uint8_t *fat = image + BIT_FAT_OFFSET;
    uint8_t *root = image + BIT_ROOT_OFFSET;
    uint8_t *efi_dir = bit_cluster_ptr(image, 2);
    uint8_t *boot_dir = bit_cluster_ptr(image, 3);
    uint16_t bit_start_cluster = 4;
    uint16_t bit_clusters =
        (vibtanium_efi_bit_blob_size + BIT_SECTOR_SIZE - 1) /
        BIT_SECTOR_SIZE;
    uint16_t text_cluster = bit_start_cluster + bit_clusters;
    uint16_t last_cluster = text_cluster;
    uint16_t max_cluster =
        BIT_TOTAL_SECTORS - BIT_FIRST_DATA_SECTOR + 1;

    if (vibtanium_efi_bit_blob_size > UINT32_MAX) {
        error_setg(errp, "embedded BIT image is too large");
        return false;
    }
    if (last_cluster > max_cluster) {
        error_setg(errp, "embedded BIT media is too small");
        return false;
    }

    memset(image, 0, BIT_MEDIA_BYTES);
    image[0] = 0xeb;
    image[1] = 0x3c;
    image[2] = 0x90;
    memcpy(image + 3, "VIBTBIT", 7);
    bit_wr16(image + 11, BIT_SECTOR_SIZE);
    image[13] = 1;
    bit_wr16(image + 14, 1);
    image[16] = 1;
    bit_wr16(image + 17, BIT_ROOT_ENTRIES);
    bit_wr16(image + 19, BIT_TOTAL_SECTORS);
    image[21] = 0xf8;
    bit_wr16(image + 22, BIT_FAT_SECTORS);
    image[510] = 0x55;
    image[511] = 0xaa;

    fat[0] = 0xf8;
    fat[1] = 0xff;
    fat[2] = 0xff;
    fat[3] = 0xff;
    bit_fat_entry(fat, 2, 0xffff);
    bit_fat_entry(fat, 3, 0xffff);
    for (uint16_t i = 0; i < bit_clusters; i++) {
        uint16_t cluster = bit_start_cluster + i;
        bit_fat_entry(fat, cluster,
                      i + 1 == bit_clusters ? 0xffff : cluster + 1);
    }
    bit_fat_entry(fat, text_cluster, 0xffff);

    bit_dir_entry(root, 0, "EFI        ", 0x10, 2, 0);
    bit_dir_entry(efi_dir, 0, ".          ", 0x10, 2, 0);
    bit_dir_entry(efi_dir, 1, "..         ", 0x10, 0, 0);
    bit_dir_entry(efi_dir, 2, "BOOT       ", 0x10, 3, 0);
    bit_dir_entry(boot_dir, 0, ".          ", 0x10, 3, 0);
    bit_dir_entry(boot_dir, 1, "..         ", 0x10, 2, 0);
    bit_dir_entry(boot_dir, 2, "BOOTIA64EFI", 0x20, bit_start_cluster,
                  vibtanium_efi_bit_blob_size);
    bit_dir_entry(boot_dir, 3, "BIT     TXT", 0x20, text_cluster,
                  sizeof(bit_text) - 1);

    memcpy(bit_cluster_ptr(image, bit_start_cluster), vibtanium_efi_bit_blob,
           vibtanium_efi_bit_blob_size);
    memcpy(bit_cluster_ptr(image, text_cluster), bit_text, sizeof(bit_text) - 1);
    return true;
}

static int bit_media_pread(void *opaque, uint64_t offset, uint32_t bytes,
                           void *buffer, Error **errp)
{
    VibtaniumBitMedia *media = opaque;

    if (!media || !media->data ||
        offset > media->size || bytes > media->size - offset) {
        error_setg(errp,
                   "BIT media read beyond end offset=0x%" PRIx64
                   " bytes=0x%x media-size=0x%" PRIx64,
                   offset, bytes, media ? media->size : 0);
        return -EINVAL;
    }

    memcpy(buffer, media->data + offset, bytes);
    return 0;
}

bool vibtanium_efi_bit_media_device(VibtaniumEfiBlockDevice *dev,
                                    Error **errp)
{
    VibtaniumBitMedia *media;

    media = g_new0(VibtaniumBitMedia, 1);
    media->size = BIT_MEDIA_BYTES;
    media->data = g_malloc0(media->size);
    if (!bit_build_media(media->data, errp)) {
        g_free(media->data);
        g_free(media);
        return false;
    }

    *dev = (VibtaniumEfiBlockDevice) {
        .name = "vibtanium-bit",
        .size = media->size,
        .block_size = BIT_SECTOR_SIZE,
        .read_only = true,
        .removable = false,
        .cdrom = false,
        .read = bit_media_pread,
        .opaque = media,
    };
    return true;
}
