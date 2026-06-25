/*
 * IA-64 synthetic EFI storage discovery tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/ia64/efi-storage.h"

#define ISO_SECTOR_SIZE 2048
#define ISO_SECTORS 80
#define PVD_SECTOR 16
#define ROOT_SECTOR 20
#define EFI_SECTOR 21
#define BOOT_SECTOR 22
#define APP_SECTOR 23
#define CATALOG_SECTOR 39
#define BOOT_IMAGE_SECTOR 40

typedef struct MemoryIso {
    uint8_t bytes[ISO_SECTORS * ISO_SECTOR_SIZE];
    size_t size;
} MemoryIso;

static void store_le16(uint8_t *p, uint16_t value)
{
    p[0] = value;
    p[1] = value >> 8;
}

static void store_be16(uint8_t *p, uint16_t value)
{
    p[0] = value >> 8;
    p[1] = value;
}

static void store_le32(uint8_t *p, uint32_t value)
{
    p[0] = value;
    p[1] = value >> 8;
    p[2] = value >> 16;
    p[3] = value >> 24;
}

static void store_be32(uint8_t *p, uint32_t value)
{
    p[0] = value >> 24;
    p[1] = value >> 16;
    p[2] = value >> 8;
    p[3] = value;
}

static size_t write_record(uint8_t *dir, size_t offset, uint32_t extent,
                           uint32_t size, uint8_t flags,
                           const uint8_t *name, uint8_t name_len)
{
    uint8_t length = 33 + name_len + ((name_len & 1) == 0 ? 1 : 0);
    uint8_t *record = dir + offset;

    memset(record, 0, length);
    record[0] = length;
    store_le32(record + 2, extent);
    store_be32(record + 6, extent);
    store_le32(record + 10, size);
    store_be32(record + 14, size);
    record[25] = flags;
    store_le16(record + 28, 1);
    store_be16(record + 30, 1);
    record[32] = name_len;
    memcpy(record + 33, name, name_len);

    return offset + length;
}

static void write_fat_entry(uint8_t *dir, size_t index, const char name[11],
                            uint8_t attr, uint16_t cluster, uint32_t size)
{
    uint8_t *entry = dir + index * 32;

    memset(entry, 0, 32);
    memcpy(entry, name, 11);
    entry[11] = attr;
    store_le16(entry + 26, cluster);
    store_le32(entry + 28, size);
}

static void add_dot_records(uint8_t *dir, uint32_t self, uint32_t parent)
{
    static const uint8_t dot[] = { 0 };
    static const uint8_t dotdot[] = { 1 };
    size_t offset = 0;

    offset = write_record(dir, offset, self, ISO_SECTOR_SIZE, 0x02,
                          dot, sizeof(dot));
    write_record(dir, offset, parent, ISO_SECTOR_SIZE, 0x02,
                 dotdot, sizeof(dotdot));
}

static void make_iso(MemoryIso *iso)
{
    uint8_t *pvd;
    uint8_t *root;
    uint8_t *efi;
    uint8_t *boot;
    size_t offset;
    static const uint8_t root_name[] = { 0 };
    static const uint8_t efi_name[] = "EFI";
    static const uint8_t boot_name[] = "BOOT";
    static const uint8_t app_name[] = "BOOTIA64.EFI;1";

    memset(iso, 0, sizeof(*iso));
    iso->size = sizeof(iso->bytes);

    pvd = iso->bytes + PVD_SECTOR * ISO_SECTOR_SIZE;
    pvd[0] = 1;
    memcpy(pvd + 1, "CD001", 5);
    pvd[6] = 1;
    write_record(pvd, 156, ROOT_SECTOR, ISO_SECTOR_SIZE, 0x02,
                 root_name, sizeof(root_name));

    root = iso->bytes + ROOT_SECTOR * ISO_SECTOR_SIZE;
    add_dot_records(root, ROOT_SECTOR, ROOT_SECTOR);
    offset = root[0] + root[root[0]];
    write_record(root, offset, EFI_SECTOR, ISO_SECTOR_SIZE, 0x02,
                 efi_name, strlen((const char *)efi_name));

    efi = iso->bytes + EFI_SECTOR * ISO_SECTOR_SIZE;
    add_dot_records(efi, EFI_SECTOR, ROOT_SECTOR);
    offset = efi[0] + efi[efi[0]];
    write_record(efi, offset, BOOT_SECTOR, ISO_SECTOR_SIZE, 0x02,
                 boot_name, strlen((const char *)boot_name));

    boot = iso->bytes + BOOT_SECTOR * ISO_SECTOR_SIZE;
    add_dot_records(boot, BOOT_SECTOR, EFI_SECTOR);
    offset = boot[0] + boot[boot[0]];
    write_record(boot, offset, APP_SECTOR, 4, 0x00,
                 app_name, strlen((const char *)app_name));

    memcpy(iso->bytes + APP_SECTOR * ISO_SECTOR_SIZE, "IA64", 4);
}

static void make_eltorito_fat_iso(MemoryIso *iso)
{
    uint8_t *pvd;
    uint8_t *boot_record;
    uint8_t *catalog;
    uint8_t *image;
    uint8_t *fat;
    uint8_t *root;
    uint8_t *efi_dir;
    uint8_t *boot_dir;
    uint32_t image_base = BOOT_IMAGE_SECTOR * ISO_SECTOR_SIZE;
    uint32_t fat_offset = 512;
    uint32_t root_offset = (1 + 20) * 512;
    uint32_t data_offset = (1 + 20 + 1) * 512;
    static const uint8_t root_name[] = { 0 };

    memset(iso, 0, sizeof(*iso));
    iso->size = sizeof(iso->bytes);

    pvd = iso->bytes + PVD_SECTOR * ISO_SECTOR_SIZE;
    pvd[0] = 1;
    memcpy(pvd + 1, "CD001", 5);
    pvd[6] = 1;
    write_record(pvd, 156, ROOT_SECTOR, ISO_SECTOR_SIZE, 0x02,
                 root_name, sizeof(root_name));

    add_dot_records(iso->bytes + ROOT_SECTOR * ISO_SECTOR_SIZE,
                    ROOT_SECTOR, ROOT_SECTOR);

    boot_record = iso->bytes + (PVD_SECTOR + 1) * ISO_SECTOR_SIZE;
    boot_record[0] = 0;
    memcpy(boot_record + 1, "CD001", 5);
    boot_record[6] = 1;
    memcpy(boot_record + 7, "EL TORITO SPECIFICATION", 23);
    store_le32(boot_record + 0x47, CATALOG_SECTOR);

    catalog = iso->bytes + CATALOG_SECTOR * ISO_SECTOR_SIZE;
    catalog[0] = 1;
    catalog[0x1e] = 0x55;
    catalog[0x1f] = 0xaa;
    catalog[0x20] = 0x88;
    catalog[0x21] = 0x00;
    store_le16(catalog + 0x26, 16);
    store_le32(catalog + 0x28, BOOT_IMAGE_SECTOR);

    image = iso->bytes + image_base;
    image[0] = 0xeb;
    image[1] = 0x3c;
    image[2] = 0x90;
    memcpy(image + 3, "mkdosfs", 7);
    store_le16(image + 11, 512);
    image[13] = 1;
    store_le16(image + 14, 1);
    image[16] = 1;
    store_le16(image + 17, 16);
    store_le16(image + 19, 5000);
    image[21] = 0xf8;
    store_le16(image + 22, 20);
    image[510] = 0x55;
    image[511] = 0xaa;

    fat = image + fat_offset;
    fat[0] = 0xf8;
    fat[1] = 0xff;
    fat[2] = 0xff;
    fat[3] = 0xff;
    store_le16(fat + 2 * 2, 0xffff);
    store_le16(fat + 3 * 2, 0xffff);
    store_le16(fat + 4 * 2, 0xffff);

    root = image + root_offset;
    write_fat_entry(root, 0, "EFI        ", 0x10, 2, 0);

    efi_dir = image + data_offset;
    write_fat_entry(efi_dir, 0, ".          ", 0x10, 2, 0);
    write_fat_entry(efi_dir, 1, "..         ", 0x10, 0, 0);
    write_fat_entry(efi_dir, 2, "BOOT       ", 0x10, 3, 0);

    boot_dir = image + data_offset + 512;
    write_fat_entry(boot_dir, 0, ".          ", 0x10, 3, 0);
    write_fat_entry(boot_dir, 1, "..         ", 0x10, 2, 0);
    write_fat_entry(boot_dir, 2, "BOOTIA64EFI", 0x20, 4, 4);

    memcpy(image + data_offset + 2 * 512, "IA64", 4);
}

static int memory_iso_read(void *opaque, uint64_t offset, uint32_t bytes,
                           void *buffer, Error **errp)
{
    MemoryIso *iso = opaque;

    if (offset > iso->size || bytes > iso->size - offset) {
        error_setg(errp, "memory ISO read out of range");
        return -EINVAL;
    }

    memcpy(buffer, iso->bytes + offset, bytes);
    return 0;
}

static void init_device(VibatniumEfiBlockDevice *dev, MemoryIso *iso)
{
    *dev = (VibatniumEfiBlockDevice) {
        .name = "memory.iso",
        .size = iso->size,
        .block_size = ISO_SECTOR_SIZE,
        .read_only = true,
        .removable = true,
        .cdrom = true,
        .read = memory_iso_read,
        .opaque = iso,
    };
}

static void test_find_fallback_path(void)
{
    MemoryIso iso;
    VibatniumEfiBlockDevice dev;
    VibatniumEfiStorageReport report;
    VibatniumEfiFile file;
    Error *err = NULL;

    make_iso(&iso);
    init_device(&dev, &iso);

    g_assert_true(vibatnium_efi_iso9660_find_path(
                      &dev, "/EFI/BOOT/bootia64.efi", &file, &report, &err));
    g_assert_null(err);
    g_assert_cmpint(report.status, ==, VIBATNIUM_EFI_STORAGE_OK);
    g_assert_cmphex(file.extent_lba, ==, APP_SECTOR);
    g_assert_cmpuint(file.size, ==, 4);
    g_assert_false(file.is_directory);
    g_assert_cmpstr(file.device_name, ==, "memory.iso");
}

static void test_read_fallback_file(void)
{
    MemoryIso iso;
    VibatniumEfiBlockDevice dev;
    VibatniumEfiStorageReport report;
    VibatniumEfiFile file;
    g_autofree uint8_t *data = NULL;
    size_t size = 0;
    Error *err = NULL;

    make_iso(&iso);
    init_device(&dev, &iso);

    g_assert_true(vibatnium_efi_iso9660_find_path(
                      &dev, VIBATNIUM_EFI_FALLBACK_PATH, &file, &report,
                      &err));
    g_assert_true(vibatnium_efi_iso9660_read_file(&dev, &file, &data, &size,
                                                 &report, &err));
    g_assert_null(err);
    g_assert_cmpuint(size, ==, 4);
    g_assert_cmpmem(data, size, "IA64", 4);
    g_assert_nonnull(strstr(report.message, "read ISO9660 file"));
}

static void test_missing_path_reports_component(void)
{
    MemoryIso iso;
    VibatniumEfiBlockDevice dev;
    VibatniumEfiStorageReport report;
    VibatniumEfiFile file;
    Error *err = NULL;

    make_iso(&iso);
    init_device(&dev, &iso);

    g_assert_false(vibatnium_efi_iso9660_find_path(
                       &dev, "/efi/boot/missing.efi", &file, &report, &err));
    g_assert_nonnull(err);
    g_assert_cmpint(report.status, ==, VIBATNIUM_EFI_STORAGE_NOT_FOUND);
    g_assert_nonnull(strstr(report.message, "missing.efi"));
    error_free(err);
}

static void test_rejects_non_iso9660(void)
{
    MemoryIso iso;
    VibatniumEfiBlockDevice dev;
    VibatniumEfiStorageReport report;
    VibatniumEfiFile file;
    Error *err = NULL;

    make_iso(&iso);
    memset(iso.bytes + PVD_SECTOR * ISO_SECTOR_SIZE, 0, ISO_SECTOR_SIZE);
    init_device(&dev, &iso);

    g_assert_false(vibatnium_efi_iso9660_find_path(
                       &dev, VIBATNIUM_EFI_FALLBACK_PATH, &file, &report,
                       &err));
    g_assert_nonnull(err);
    g_assert_cmpint(report.status, ==, VIBATNIUM_EFI_STORAGE_NO_ISO9660);
    g_assert_nonnull(strstr(report.message, "primary volume"));
    error_free(err);
}

static void test_cdrom_read_path_uses_eltorito_fat(void)
{
    MemoryIso iso;
    VibatniumEfiBlockDevice dev;
    VibatniumEfiStorageReport report;
    g_autofree uint8_t *data = NULL;
    size_t size = 0;
    char source[256];
    Error *err = NULL;

    make_eltorito_fat_iso(&iso);
    init_device(&dev, &iso);

    g_assert_true(vibatnium_efi_cdrom_read_path(
                      &dev, VIBATNIUM_EFI_FALLBACK_PATH, &data, &size,
                      source, sizeof(source), &report, &err));
    g_assert_null(err);
    g_assert_cmpuint(size, ==, 4);
    g_assert_cmpmem(data, size, "IA64", 4);
    g_assert_nonnull(strstr(source, "eltorito"));
    g_assert_nonnull(strstr(report.message, "El Torito FAT16"));
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/ia64-efi-storage/find-fallback-path",
                    test_find_fallback_path);
    g_test_add_func("/ia64-efi-storage/read-fallback-file",
                    test_read_fallback_file);
    g_test_add_func("/ia64-efi-storage/missing-path-reports-component",
                    test_missing_path_reports_component);
    g_test_add_func("/ia64-efi-storage/rejects-non-iso9660",
                    test_rejects_non_iso9660);
    g_test_add_func("/ia64-efi-storage/cdrom-read-path-uses-eltorito-fat",
                    test_cdrom_read_path_uses_eltorito_fat);

    return g_test_run();
}
