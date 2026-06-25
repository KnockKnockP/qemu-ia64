/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "qemu/units.h"
#include "hw/ia64/efi-storage.h"

#define ISO_SECTOR_SIZE 2048
#define ISO_PRIMARY_VOLUME_SECTOR 16
#define ISO_MAX_DIRECTORY_BYTES (16 * MiB)
#define ISO_MAX_FILE_BYTES (128 * MiB)
#define ISO_MAX_VOLUME_DESCRIPTOR_SECTORS 64
#define FAT_MAX_CLUSTER_CHAIN_BYTES (128 * MiB)

typedef struct IsoRecord {
    uint32_t extent_lba;
    uint32_t size;
    uint8_t flags;
    char name[128];
} IsoRecord;

typedef struct FatContext {
    VibatniumEfiBlockDevice *dev;
    uint64_t image_offset;
    uint16_t bytes_per_sector;
    uint8_t sectors_per_cluster;
    uint16_t reserved_sectors;
    uint8_t fat_count;
    uint16_t root_entries;
    uint16_t sectors_per_fat;
    uint32_t total_sectors;
    uint32_t root_dir_sectors;
    uint32_t first_data_sector;
    uint32_t cluster_count;
    uint64_t fat_offset;
    uint64_t root_dir_offset;
    uint32_t root_dir_size;
    uint8_t *fat;
} FatContext;

typedef struct FatEntry {
    uint16_t cluster;
    uint32_t size;
    uint8_t attr;
    char name[32];
} FatEntry;

static uint16_t rd16(const uint8_t *p)
{
    return p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t rd32(const uint8_t *p)
{
    return p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint32_t dev_block_size(const VibatniumEfiBlockDevice *dev)
{
    return dev->block_size ? dev->block_size : ISO_SECTOR_SIZE;
}

static char *normalize_path_component(const char *component);

static void report_set(VibatniumEfiStorageReport *report,
                       VibatniumEfiStorageStatus status,
                       const char *fmt, ...) G_GNUC_PRINTF(3, 4);

static void report_set(VibatniumEfiStorageReport *report,
                       VibatniumEfiStorageStatus status,
                       const char *fmt, ...)
{
    va_list ap;

    if (!report) {
        return;
    }

    report->status = status;
    va_start(ap, fmt);
    g_vsnprintf(report->message, sizeof(report->message), fmt, ap);
    va_end(ap);
}

static bool dev_read(VibatniumEfiBlockDevice *dev,
                     uint64_t offset,
                     uint32_t bytes,
                     void *buffer,
                     VibatniumEfiStorageReport *report,
                     Error **errp)
{
    int ret;

    if (!dev || !dev->read) {
        error_setg(errp, "missing EFI block read callback");
        report_set(report, VIBATNIUM_EFI_STORAGE_READ_ERROR,
                   "missing EFI block read callback");
        return false;
    }

    if (dev->size && (offset > dev->size || bytes > dev->size - offset)) {
        error_setg(errp, "read beyond end of media");
        report_set(report, VIBATNIUM_EFI_STORAGE_READ_ERROR,
                   "read beyond end of media offset=0x%" PRIx64
                   " bytes=0x%x media-size=0x%" PRIx64,
                   offset, bytes, dev->size);
        return false;
    }

    ret = dev->read(dev->opaque, offset, bytes, buffer, errp);
    if (ret < 0) {
        report_set(report, VIBATNIUM_EFI_STORAGE_READ_ERROR,
                   "media read failed offset=0x%" PRIx64 " bytes=0x%x",
                   offset, bytes);
        return false;
    }

    return true;
}

static bool find_eltorito_boot_image(VibatniumEfiBlockDevice *dev,
                                     uint64_t *image_offset,
                                     uint32_t *sector_count,
                                     VibatniumEfiStorageReport *report,
                                     Error **errp)
{
    uint8_t sector[ISO_SECTOR_SIZE];
    uint8_t catalog[ISO_SECTOR_SIZE];
    uint32_t catalog_lba = 0;
    uint32_t image_lba;
    const uint8_t *entry;

    for (uint32_t i = ISO_PRIMARY_VOLUME_SECTOR + 1;
         i < ISO_MAX_VOLUME_DESCRIPTOR_SECTORS; i++) {
        if (!dev_read(dev, (uint64_t)i * ISO_SECTOR_SIZE, sizeof(sector),
                      sector, report, errp)) {
            return false;
        }

        if (memcmp(sector + 1, "CD001", 5) != 0) {
            continue;
        }
        if (sector[0] == 0xff) {
            break;
        }
        if (sector[0] == 0 &&
            memcmp(sector + 7, "EL TORITO SPECIFICATION", 23) == 0) {
            catalog_lba = rd32(sector + 0x47);
            break;
        }
    }

    if (catalog_lba == 0) {
        error_setg(errp, "ISO9660 media has no El Torito boot catalog");
        report_set(report, VIBATNIUM_EFI_STORAGE_NOT_FOUND,
                   "ISO9660 media has no El Torito boot catalog");
        return false;
    }

    if (!dev_read(dev, (uint64_t)catalog_lba * ISO_SECTOR_SIZE,
                  sizeof(catalog), catalog, report, errp)) {
        return false;
    }

    if (catalog[0] != 0x01 || catalog[0x1e] != 0x55 ||
        catalog[0x1f] != 0xaa) {
        error_setg(errp, "El Torito validation entry is invalid");
        report_set(report, VIBATNIUM_EFI_STORAGE_INVALID_FILESYSTEM,
                   "El Torito validation entry is invalid");
        return false;
    }

    entry = catalog + 0x20;
    if (entry[0] != 0x88) {
        error_setg(errp, "El Torito default entry is not bootable");
        report_set(report, VIBATNIUM_EFI_STORAGE_NOT_FOUND,
                   "El Torito default entry is not bootable");
        return false;
    }
    if (entry[1] != 0x00) {
        error_setg(errp, "El Torito boot media type 0x%02x is unsupported",
                   entry[1]);
        report_set(report, VIBATNIUM_EFI_STORAGE_UNSUPPORTED,
                   "El Torito boot media type 0x%02x is unsupported",
                   entry[1]);
        return false;
    }

    image_lba = rd32(entry + 8);
    if (image_lba == 0) {
        error_setg(errp, "El Torito default entry has zero image LBA");
        report_set(report, VIBATNIUM_EFI_STORAGE_INVALID_FILESYSTEM,
                   "El Torito default entry has zero image LBA");
        return false;
    }

    *image_offset = (uint64_t)image_lba * ISO_SECTOR_SIZE;
    *sector_count = rd16(entry + 6);
    report_set(report, VIBATNIUM_EFI_STORAGE_OK,
               "found El Torito no-emulation image catalog-lba=%u image-lba=%u "
               "sectors=%u",
               catalog_lba, image_lba, *sector_count);
    return true;
}

static void fat_short_name(const uint8_t *entry, char *out, size_t out_len)
{
    size_t n = 0;
    int name_end = 7;
    int ext_end = 10;

    while (name_end >= 0 && entry[name_end] == ' ') {
        name_end--;
    }
    while (ext_end >= 8 && entry[ext_end] == ' ') {
        ext_end--;
    }

    for (int i = 0; i <= name_end && n + 1 < out_len; i++) {
        out[n++] = g_ascii_tolower(entry[i]);
    }
    if (ext_end >= 8 && n + 1 < out_len) {
        out[n++] = '.';
        for (int i = 8; i <= ext_end && n + 1 < out_len; i++) {
            out[n++] = g_ascii_tolower(entry[i]);
        }
    }
    out[n] = '\0';
}

static uint16_t fat16_next_cluster(const FatContext *fat, uint16_t cluster)
{
    if (cluster >= fat->cluster_count + 2) {
        return 0xffff;
    }
    return rd16(fat->fat + cluster * 2);
}

static uint64_t fat_cluster_offset(const FatContext *fat, uint16_t cluster)
{
    return fat->image_offset +
           ((uint64_t)fat->first_data_sector +
            ((uint64_t)cluster - 2) * fat->sectors_per_cluster) *
           fat->bytes_per_sector;
}

static bool fat_read_bytes(FatContext *fat,
                           uint64_t offset,
                           uint32_t bytes,
                           void *buffer,
                           VibatniumEfiStorageReport *report,
                           Error **errp)
{
    return dev_read(fat->dev, fat->image_offset + offset, bytes, buffer,
                    report, errp);
}

static bool fat_init(FatContext *fat,
                     VibatniumEfiBlockDevice *dev,
                     uint64_t image_offset,
                     VibatniumEfiStorageReport *report,
                     Error **errp)
{
    uint8_t bpb[512];
    uint32_t total16;
    uint32_t fat_bytes;

    memset(fat, 0, sizeof(*fat));
    fat->dev = dev;
    fat->image_offset = image_offset;

    if (!dev_read(dev, image_offset, sizeof(bpb), bpb, report, errp)) {
        return false;
    }

    fat->bytes_per_sector = rd16(bpb + 11);
    fat->sectors_per_cluster = bpb[13];
    fat->reserved_sectors = rd16(bpb + 14);
    fat->fat_count = bpb[16];
    fat->root_entries = rd16(bpb + 17);
    total16 = rd16(bpb + 19);
    fat->sectors_per_fat = rd16(bpb + 22);
    fat->total_sectors = total16 ? total16 : rd32(bpb + 32);

    if (fat->bytes_per_sector != 512 || fat->sectors_per_cluster == 0 ||
        fat->reserved_sectors == 0 || fat->fat_count == 0 ||
        fat->root_entries == 0 || fat->sectors_per_fat == 0 ||
        fat->total_sectors == 0) {
        error_setg(errp, "El Torito image is not a supported FAT16 volume");
        report_set(report, VIBATNIUM_EFI_STORAGE_UNSUPPORTED,
                   "El Torito image is not a supported FAT16 volume");
        return false;
    }

    fat->root_dir_sectors =
        ((uint32_t)fat->root_entries * 32 + fat->bytes_per_sector - 1) /
        fat->bytes_per_sector;
    fat->first_data_sector = fat->reserved_sectors +
                             fat->fat_count * fat->sectors_per_fat +
                             fat->root_dir_sectors;
    if (fat->total_sectors <= fat->first_data_sector) {
        error_setg(errp, "FAT16 data area is empty");
        report_set(report, VIBATNIUM_EFI_STORAGE_INVALID_FILESYSTEM,
                   "FAT16 data area is empty");
        return false;
    }

    fat->cluster_count =
        (fat->total_sectors - fat->first_data_sector) /
        fat->sectors_per_cluster;
    if (fat->cluster_count < 4085 || fat->cluster_count >= 65525) {
        error_setg(errp, "FAT cluster count %u is not FAT16",
                   fat->cluster_count);
        report_set(report, VIBATNIUM_EFI_STORAGE_UNSUPPORTED,
                   "FAT cluster count %u is not FAT16", fat->cluster_count);
        return false;
    }

    fat->fat_offset = (uint64_t)fat->reserved_sectors * fat->bytes_per_sector;
    fat->root_dir_offset = ((uint64_t)fat->reserved_sectors +
                            fat->fat_count * fat->sectors_per_fat) *
                           fat->bytes_per_sector;
    fat->root_dir_size = (uint32_t)fat->root_entries * 32;

    fat_bytes = (uint32_t)fat->sectors_per_fat * fat->bytes_per_sector;
    if (fat_bytes > 4 * MiB) {
        error_setg(errp, "FAT16 table is too large");
        report_set(report, VIBATNIUM_EFI_STORAGE_UNSUPPORTED,
                   "FAT16 table is too large");
        return false;
    }

    fat->fat = g_malloc(fat_bytes);
    if (!fat_read_bytes(fat, fat->fat_offset, fat_bytes, fat->fat, report,
                        errp)) {
        g_free(fat->fat);
        fat->fat = NULL;
        return false;
    }

    return true;
}

static void fat_destroy(FatContext *fat)
{
    g_free(fat->fat);
    fat->fat = NULL;
}

static bool fat_read_cluster_chain(FatContext *fat,
                                   uint16_t start_cluster,
                                   size_t limit,
                                   GByteArray *out,
                                   VibatniumEfiStorageReport *report,
                                   Error **errp)
{
    uint16_t cluster = start_cluster;
    uint32_t cluster_bytes = (uint32_t)fat->sectors_per_cluster *
                             fat->bytes_per_sector;
    g_autofree uint8_t *buffer = g_malloc(cluster_bytes);

    while (cluster >= 2 && cluster < 0xfff8) {
        uint16_t next;

        if (cluster >= fat->cluster_count + 2) {
            error_setg(errp, "FAT16 cluster %u is outside the data area",
                       cluster);
            report_set(report, VIBATNIUM_EFI_STORAGE_INVALID_FILESYSTEM,
                       "FAT16 cluster %u is outside the data area", cluster);
            return false;
        }
        if (out->len + cluster_bytes > limit ||
            out->len + cluster_bytes > FAT_MAX_CLUSTER_CHAIN_BYTES) {
            error_setg(errp, "FAT16 cluster chain exceeds limit");
            report_set(report, VIBATNIUM_EFI_STORAGE_UNSUPPORTED,
                       "FAT16 cluster chain exceeds limit");
            return false;
        }

        if (!dev_read(fat->dev, fat_cluster_offset(fat, cluster),
                      cluster_bytes, buffer, report, errp)) {
            return false;
        }
        g_byte_array_append(out, buffer, cluster_bytes);

        next = fat16_next_cluster(fat, cluster);
        if (next >= 0xfff8) {
            break;
        }
        if (next == 0 || next == cluster) {
            error_setg(errp, "FAT16 cluster chain is invalid at %u", cluster);
            report_set(report, VIBATNIUM_EFI_STORAGE_INVALID_FILESYSTEM,
                       "FAT16 cluster chain is invalid at %u", cluster);
            return false;
        }
        cluster = next;
    }

    return true;
}

static bool fat_load_directory(FatContext *fat,
                               uint16_t cluster,
                               bool root,
                               GByteArray **entries,
                               VibatniumEfiStorageReport *report,
                               Error **errp)
{
    *entries = g_byte_array_new();

    if (root) {
        g_byte_array_set_size(*entries, fat->root_dir_size);
        if (!fat_read_bytes(fat, fat->root_dir_offset, fat->root_dir_size,
                            (*entries)->data, report, errp)) {
            g_byte_array_free(*entries, true);
            *entries = NULL;
            return false;
        }
        return true;
    }

    if (!fat_read_cluster_chain(fat, cluster, FAT_MAX_CLUSTER_CHAIN_BYTES,
                                *entries, report, errp)) {
        g_byte_array_free(*entries, true);
        *entries = NULL;
        return false;
    }

    return true;
}

static bool fat_search_directory(FatContext *fat,
                                 uint16_t dir_cluster,
                                 bool root,
                                 const char *component,
                                 FatEntry *match,
                                 VibatniumEfiStorageReport *report,
                                 Error **errp)
{
    g_autofree char *wanted = normalize_path_component(component);
    GByteArray *entries = NULL;
    bool found = false;

    if (!fat_load_directory(fat, dir_cluster, root, &entries, report, errp)) {
        return false;
    }

    for (size_t offset = 0; offset + 32 <= entries->len; offset += 32) {
        const uint8_t *entry = entries->data + offset;
        uint8_t attr = entry[11];
        char name[32];

        if (entry[0] == 0x00) {
            break;
        }
        if (entry[0] == 0xe5 || attr == 0x0f || (attr & 0x08)) {
            continue;
        }

        fat_short_name(entry, name, sizeof(name));
        if (g_strcmp0(name, wanted) != 0) {
            continue;
        }

        memset(match, 0, sizeof(*match));
        match->cluster = rd16(entry + 26);
        match->size = rd32(entry + 28);
        match->attr = attr;
        g_strlcpy(match->name, name, sizeof(match->name));
        found = true;
        break;
    }

    g_byte_array_free(entries, true);

    if (!found) {
        error_setg(errp, "FAT16 component '%s' was not found", component);
        report_set(report, VIBATNIUM_EFI_STORAGE_NOT_FOUND,
                   "FAT16 component '%s' was not found", component);
        return false;
    }

    report_set(report, VIBATNIUM_EFI_STORAGE_OK,
               "found FAT16 component '%s' cluster=%u size=0x%x",
               component, match->cluster, match->size);
    return true;
}

static bool fat_find_path(FatContext *fat,
                          const char *path,
                          FatEntry *entry,
                          VibatniumEfiStorageReport *report,
                          Error **errp)
{
    char **components = g_strsplit(path, "/", -1);
    bool root = true;
    uint16_t dir_cluster = 0;
    bool ok = false;

    memset(entry, 0, sizeof(*entry));

    for (char **component = components; *component; component++) {
        FatEntry next;
        Error *local_err = NULL;
        bool last;

        if (**component == '\0') {
            continue;
        }

        last = true;
        for (char **lookahead = component + 1; *lookahead; lookahead++) {
            if (**lookahead != '\0') {
                last = false;
                break;
            }
        }

        if (!fat_search_directory(fat, dir_cluster, root, *component, &next,
                                  report, &local_err)) {
            error_propagate(errp, local_err);
            goto out;
        }
        if (!last && !(next.attr & 0x10)) {
            error_setg(errp, "FAT16 component '%s' is not a directory",
                       *component);
            report_set(report, VIBATNIUM_EFI_STORAGE_INVALID_FILESYSTEM,
                       "FAT16 component '%s' is not a directory", *component);
            goto out;
        }

        *entry = next;
        root = false;
        dir_cluster = next.cluster;
    }

    ok = true;

out:
    g_strfreev(components);
    return ok;
}

static bool eltorito_fat_read_path(VibatniumEfiBlockDevice *dev,
                                   const char *path,
                                   uint8_t **data,
                                   size_t *size,
                                   VibatniumEfiStorageReport *report,
                                   Error **errp)
{
    FatContext fat;
    FatEntry entry;
    uint64_t image_offset = 0;
    uint32_t sector_count = 0;
    GByteArray *contents = NULL;
    bool ok = false;

    memset(&fat, 0, sizeof(fat));
    if (!find_eltorito_boot_image(dev, &image_offset, &sector_count, report,
                                  errp)) {
        return false;
    }
    if (!fat_init(&fat, dev, image_offset, report, errp)) {
        return false;
    }
    if (!fat_find_path(&fat, path, &entry, report, errp)) {
        goto out;
    }
    if (entry.attr & 0x10) {
        error_setg(errp, "FAT16 path '%s' is a directory", path);
        report_set(report, VIBATNIUM_EFI_STORAGE_INVALID_FILESYSTEM,
                   "FAT16 path '%s' is a directory", path);
        goto out;
    }
    if (entry.size > ISO_MAX_FILE_BYTES) {
        error_setg(errp, "FAT16 file '%s' is too large", path);
        report_set(report, VIBATNIUM_EFI_STORAGE_UNSUPPORTED,
                   "FAT16 file '%s' is too large", path);
        goto out;
    }

    contents = g_byte_array_new();
    if (!fat_read_cluster_chain(&fat, entry.cluster, FAT_MAX_CLUSTER_CHAIN_BYTES,
                                contents, report, errp)) {
        g_byte_array_free(contents, true);
        goto out;
    }

    *size = MIN((size_t)entry.size, contents->len);
    *data = g_malloc(MAX(*size, 1));
    memcpy(*data, contents->data, *size);
    g_byte_array_free(contents, true);
    report_set(report, VIBATNIUM_EFI_STORAGE_OK,
               "read El Torito FAT16 file '%s' size 0x%zx", path, *size);
    ok = true;

out:
    fat_destroy(&fat);
    return ok;
}

static void normalize_iso_name(const uint8_t *raw, uint8_t len,
                               char *out, size_t out_len)
{
    size_t n = 0;

    if (out_len == 0) {
        return;
    }

    if (len == 1 && raw[0] == 0) {
        g_strlcpy(out, ".", out_len);
        return;
    }
    if (len == 1 && raw[0] == 1) {
        g_strlcpy(out, "..", out_len);
        return;
    }

    for (uint8_t i = 0; i < len && n + 1 < out_len; i++) {
        char c = raw[i];

        if (c == ';') {
            break;
        }
        if (c == '\0') {
            break;
        }
        out[n++] = g_ascii_tolower(c);
    }

    while (n > 0 && out[n - 1] == '.') {
        n--;
    }
    out[n] = '\0';
}

static char *normalize_path_component(const char *component)
{
    g_autofree char *lower = g_ascii_strdown(component, -1);
    char *semi;

    semi = strchr(lower, ';');
    if (semi) {
        *semi = '\0';
    }
    while (*lower && lower[strlen(lower) - 1] == '.') {
        lower[strlen(lower) - 1] = '\0';
    }

    return g_strdup(lower);
}

static bool parse_record(const uint8_t *record, size_t available,
                         IsoRecord *out,
                         VibatniumEfiStorageReport *report,
                         Error **errp)
{
    uint8_t length;
    uint8_t name_len;

    if (available < 1) {
        error_setg(errp, "ISO9660 directory record is truncated");
        report_set(report, VIBATNIUM_EFI_STORAGE_INVALID_FILESYSTEM,
                   "ISO9660 directory record is truncated");
        return false;
    }

    length = record[0];
    if (length < 34 || length > available) {
        error_setg(errp, "invalid ISO9660 directory record length %u", length);
        report_set(report, VIBATNIUM_EFI_STORAGE_INVALID_FILESYSTEM,
                   "invalid ISO9660 directory record length %u", length);
        return false;
    }

    name_len = record[32];
    if (33 + name_len > length) {
        error_setg(errp, "invalid ISO9660 file identifier length %u", name_len);
        report_set(report, VIBATNIUM_EFI_STORAGE_INVALID_FILESYSTEM,
                   "invalid ISO9660 file identifier length %u", name_len);
        return false;
    }

    memset(out, 0, sizeof(*out));
    out->extent_lba = rd32(record + 2);
    out->size = rd32(record + 10);
    out->flags = record[25];
    normalize_iso_name(record + 33, name_len, out->name, sizeof(out->name));
    return true;
}

static bool read_directory(VibatniumEfiBlockDevice *dev,
                           const IsoRecord *dir,
                           uint8_t **data,
                           size_t *size,
                           VibatniumEfiStorageReport *report,
                           Error **errp)
{
    uint32_t block_size = dev_block_size(dev);
    uint64_t offset = (uint64_t)dir->extent_lba * block_size;

    if (!(dir->flags & 0x02)) {
        error_setg(errp, "ISO9660 record is not a directory");
        report_set(report, VIBATNIUM_EFI_STORAGE_INVALID_FILESYSTEM,
                   "ISO9660 record is not a directory");
        return false;
    }
    if (dir->size == 0 || dir->size > ISO_MAX_DIRECTORY_BYTES) {
        error_setg(errp, "unsupported ISO9660 directory size 0x%x", dir->size);
        report_set(report, VIBATNIUM_EFI_STORAGE_UNSUPPORTED,
                   "unsupported ISO9660 directory size 0x%x", dir->size);
        return false;
    }

    *data = g_malloc(dir->size);
    *size = dir->size;
    if (!dev_read(dev, offset, dir->size, *data, report, errp)) {
        g_free(*data);
        *data = NULL;
        *size = 0;
        return false;
    }

    return true;
}

static bool search_directory(VibatniumEfiBlockDevice *dev,
                             const IsoRecord *dir,
                             const char *component,
                             IsoRecord *match,
                             VibatniumEfiStorageReport *report,
                             Error **errp)
{
    g_autofree char *wanted = normalize_path_component(component);
    g_autofree uint8_t *data = NULL;
    size_t size = 0;
    size_t offset = 0;
    uint32_t block_size = dev_block_size(dev);

    if (!read_directory(dev, dir, &data, &size, report, errp)) {
        return false;
    }

    while (offset < size) {
        uint8_t length = data[offset];
        IsoRecord record;
        Error *local_err = NULL;

        if (length == 0) {
            offset = ((offset / block_size) + 1) * block_size;
            continue;
        }

        if (!parse_record(data + offset, size - offset, &record, report,
                          &local_err)) {
            error_propagate(errp, local_err);
            return false;
        }

        if (g_strcmp0(record.name, wanted) == 0) {
            *match = record;
            report_set(report, VIBATNIUM_EFI_STORAGE_OK,
                       "found ISO9660 component '%s' at LBA %u size 0x%x",
                       component, match->extent_lba, match->size);
            return true;
        }

        offset += length;
    }

    error_setg(errp, "ISO9660 component '%s' was not found", component);
    report_set(report, VIBATNIUM_EFI_STORAGE_NOT_FOUND,
               "ISO9660 component '%s' was not found", component);
    return false;
}

const char *vibatnium_efi_storage_status_name(
    VibatniumEfiStorageStatus status)
{
    switch (status) {
    case VIBATNIUM_EFI_STORAGE_OK:
        return "ok";
    case VIBATNIUM_EFI_STORAGE_READ_ERROR:
        return "read-error";
    case VIBATNIUM_EFI_STORAGE_NO_ISO9660:
        return "no-iso9660";
    case VIBATNIUM_EFI_STORAGE_INVALID_FILESYSTEM:
        return "invalid-filesystem";
    case VIBATNIUM_EFI_STORAGE_NOT_FOUND:
        return "not-found";
    case VIBATNIUM_EFI_STORAGE_UNSUPPORTED:
        return "unsupported";
    default:
        return "unknown";
    }
}

bool vibatnium_efi_iso9660_find_path(VibatniumEfiBlockDevice *dev,
                                     const char *path,
                                     VibatniumEfiFile *file,
                                     VibatniumEfiStorageReport *report,
                                     Error **errp)
{
    uint8_t sector[ISO_SECTOR_SIZE];
    IsoRecord current;
    char **components;
    bool ok = false;

    g_return_val_if_fail(dev != NULL, false);
    g_return_val_if_fail(path != NULL, false);
    g_return_val_if_fail(file != NULL, false);

    memset(file, 0, sizeof(*file));
    report_set(report, VIBATNIUM_EFI_STORAGE_NOT_FOUND,
               "path '%s' has not been searched", path);

    if (dev_block_size(dev) != ISO_SECTOR_SIZE) {
        error_setg(errp, "unsupported EFI block size %u", dev_block_size(dev));
        report_set(report, VIBATNIUM_EFI_STORAGE_UNSUPPORTED,
                   "unsupported EFI block size %u", dev_block_size(dev));
        return false;
    }

    if (!dev_read(dev, ISO_PRIMARY_VOLUME_SECTOR * ISO_SECTOR_SIZE,
                  sizeof(sector), sector, report, errp)) {
        return false;
    }

    if (sector[0] != 1 || memcmp(sector + 1, "CD001", 5) != 0 ||
        sector[6] != 1) {
        error_setg(errp, "media does not expose an ISO9660 primary volume");
        report_set(report, VIBATNIUM_EFI_STORAGE_NO_ISO9660,
                   "media does not expose an ISO9660 primary volume");
        return false;
    }

    if (!parse_record(sector + 156, sizeof(sector) - 156, &current,
                      report, errp)) {
        return false;
    }

    components = g_strsplit(path, "/", -1);
    for (char **component = components; *component; component++) {
        IsoRecord next;
        Error *local_err = NULL;

        if (**component == '\0') {
            continue;
        }

        if (!search_directory(dev, &current, *component, &next, report,
                              &local_err)) {
            error_propagate(errp, local_err);
            goto out;
        }
        current = next;
    }

    file->extent_lba = current.extent_lba;
    file->size = current.size;
    file->is_directory = (current.flags & 0x02) != 0;
    g_strlcpy(file->path, path, sizeof(file->path));
    g_strlcpy(file->device_name, dev->name ? dev->name : "<unnamed>",
              sizeof(file->device_name));
    report_set(report, VIBATNIUM_EFI_STORAGE_OK,
               "found ISO9660 path '%s' on '%s' at LBA %u size 0x%x",
               file->path, file->device_name, file->extent_lba, file->size);
    ok = true;

out:
    g_strfreev(components);
    return ok;
}

bool vibatnium_efi_iso9660_read_file(VibatniumEfiBlockDevice *dev,
                                     const VibatniumEfiFile *file,
                                     uint8_t **data,
                                     size_t *size,
                                     VibatniumEfiStorageReport *report,
                                     Error **errp)
{
    uint32_t block_size;
    uint64_t offset;

    g_return_val_if_fail(dev != NULL, false);
    g_return_val_if_fail(file != NULL, false);
    g_return_val_if_fail(data != NULL, false);
    g_return_val_if_fail(size != NULL, false);

    *data = NULL;
    *size = 0;

    if (file->is_directory) {
        error_setg(errp, "ISO9660 path '%s' is a directory", file->path);
        report_set(report, VIBATNIUM_EFI_STORAGE_INVALID_FILESYSTEM,
                   "ISO9660 path '%s' is a directory", file->path);
        return false;
    }
    if (file->size > ISO_MAX_FILE_BYTES) {
        error_setg(errp, "unsupported ISO9660 file size 0x%x", file->size);
        report_set(report, VIBATNIUM_EFI_STORAGE_UNSUPPORTED,
                   "unsupported ISO9660 file size 0x%x", file->size);
        return false;
    }

    block_size = dev_block_size(dev);
    offset = (uint64_t)file->extent_lba * block_size;
    *data = g_malloc(MAX(file->size, 1));
    *size = file->size;

    if (file->size &&
        !dev_read(dev, offset, file->size, *data, report, errp)) {
        g_free(*data);
        *data = NULL;
        *size = 0;
        return false;
    }

    report_set(report, VIBATNIUM_EFI_STORAGE_OK,
               "read ISO9660 file '%s' from '%s' size 0x%zx",
               file->path, file->device_name, *size);
    return true;
}

bool vibatnium_efi_cdrom_read_path(VibatniumEfiBlockDevice *dev,
                                   const char *path,
                                   uint8_t **data,
                                   size_t *size,
                                   char *source,
                                   size_t source_size,
                                   VibatniumEfiStorageReport *report,
                                   Error **errp)
{
    VibatniumEfiFile iso_file;
    Error *iso_err = NULL;
    Error *fat_err = NULL;
    VibatniumEfiStorageReport iso_report;
    VibatniumEfiStorageReport fat_report;

    g_return_val_if_fail(data != NULL, false);
    g_return_val_if_fail(size != NULL, false);

    *data = NULL;
    *size = 0;
    if (source && source_size) {
        source[0] = '\0';
    }

    if (vibatnium_efi_iso9660_find_path(dev, path, &iso_file, &iso_report,
                                        &iso_err) &&
        vibatnium_efi_iso9660_read_file(dev, &iso_file, data, size,
                                        &iso_report, &iso_err)) {
        if (source && source_size) {
            g_snprintf(source, source_size, "%s:%s",
                       dev->name ? dev->name : "<unnamed>", path);
        }
        if (report) {
            *report = iso_report;
        }
        return true;
    }

    if (eltorito_fat_read_path(dev, path, data, size, &fat_report,
                               &fat_err)) {
        if (source && source_size) {
            g_snprintf(source, source_size, "%s:eltorito:%s",
                       dev->name ? dev->name : "<unnamed>", path);
        }
        if (report) {
            *report = fat_report;
        }
        error_free(iso_err);
        return true;
    }

    error_setg(errp, "CD-ROM path '%s' not found; ISO9660: %s; "
               "El Torito FAT16: %s",
               path,
               iso_err ? error_get_pretty(iso_err) : iso_report.message,
               fat_err ? error_get_pretty(fat_err) : fat_report.message);
    report_set(report, VIBATNIUM_EFI_STORAGE_NOT_FOUND,
               "CD-ROM path '%s' not found; ISO9660: %s; El Torito FAT16: %s",
               path, iso_report.message, fat_report.message);
    error_free(iso_err);
    error_free(fat_err);
    return false;
}
