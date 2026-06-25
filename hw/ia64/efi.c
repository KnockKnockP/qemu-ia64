/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "hw/ia64/efi.h"
#include "target/ia64/bundle.h"
#include "target/ia64/exec-smoke.h"

#define PE32_MAGIC  0x10b
#define PE32P_MAGIC 0x20b

#define PE_SIGNATURE_OFFSET 0x3c
#define PE_SIGNATURE_SIZE   4
#define COFF_HEADER_SIZE    20
#define SECTION_HEADER_SIZE 40
#define PE32_DATA_DIRECTORY_OFFSET  96
#define PE32P_DATA_DIRECTORY_OFFSET 112
#define PE_DIRECTORY_BASE_RELOCATION 5
#define PE_BASE_RELOCATION_ABSOLUTE 0
#define PE_BASE_RELOCATION_DIR64    10

#define MAX_EFI_IMAGE_SIZE (128 * 1024 * 1024)

static bool range_ok(size_t size, uint64_t offset, uint64_t length)
{
    return offset <= size && length <= size - offset;
}

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

static void wr32(uint8_t *p, uint32_t value)
{
    for (int i = 0; i < 4; i++) {
        p[i] = value >> (i * 8);
    }
}

static uint64_t rd64(const uint8_t *p)
{
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

static void wr64(uint8_t *p, uint64_t value)
{
    for (int i = 0; i < 8; i++) {
        p[i] = value >> (i * 8);
    }
}

static void blob_wr32(uint8_t *blob, size_t size, uint64_t address,
                      uint32_t value)
{
    g_assert(address >= VIBATNIUM_EFI_BLOB_BASE);
    g_assert(address + sizeof(uint32_t) <=
             VIBATNIUM_EFI_BLOB_BASE + size);
    wr32(blob + (address - VIBATNIUM_EFI_BLOB_BASE), value);
}

static void blob_wr64(uint8_t *blob, size_t size, uint64_t address,
                      uint64_t value)
{
    g_assert(address >= VIBATNIUM_EFI_BLOB_BASE);
    g_assert(address + sizeof(uint64_t) <=
             VIBATNIUM_EFI_BLOB_BASE + size);
    wr64(blob + (address - VIBATNIUM_EFI_BLOB_BASE), value);
}

static uint8_t *blob_ptr(uint8_t *blob, size_t size, uint64_t address,
                         size_t bytes)
{
    g_assert(address >= VIBATNIUM_EFI_BLOB_BASE);
    g_assert(address + bytes <= VIBATNIUM_EFI_BLOB_BASE + size);
    return blob + (address - VIBATNIUM_EFI_BLOB_BASE);
}

static uint32_t efi_crc32(const uint8_t *data, size_t size)
{
    uint32_t crc = 0xffffffff;

    for (size_t i = 0; i < size; i++) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++) {
            crc = (crc & 1) ? (crc >> 1) ^ 0xedb88320U : crc >> 1;
        }
    }

    return ~crc;
}

static void write_table_header(uint8_t *table, size_t size,
                               uint64_t signature)
{
    wr64(table, signature);
    wr32(table + 8, 0x00010000);
    wr32(table + 12, size);
    wr32(table + 16, 0);
    wr32(table + 20, 0);
    wr32(table + 16, efi_crc32(table, size));
}

static void write_ia64_bundle(uint8_t *blob, size_t size, uint64_t address,
                              uint8_t tmpl, uint64_t slot0, uint64_t slot1,
                              uint64_t slot2)
{
    unsigned __int128 raw = (tmpl & 0x1f) |
        ((unsigned __int128)(slot0 & IA64_SLOT_MASK) << 5) |
        ((unsigned __int128)(slot1 & IA64_SLOT_MASK) << 46) |
        ((unsigned __int128)(slot2 & IA64_SLOT_MASK) << 87);
    uint8_t *p = blob_ptr(blob, size, address, IA64_BUNDLE_SIZE);

    for (int i = 0; i < IA64_BUNDLE_SIZE; i++) {
        p[i] = raw >> (i * 8);
    }
}

static void write_return_gate(uint8_t *blob, size_t size, uint64_t address)
{
    const uint64_t nop = 1ULL << 27;
    const uint64_t br_ret_b0 = 0x21ULL << 27;

    write_ia64_bundle(blob, size, address, 0x11, nop, nop, br_ret_b0);
}

static uint64_t service_descriptor_address(unsigned service_index)
{
    return VIBATNIUM_EFI_DESCRIPTOR_BASE + service_index * 16;
}

static uint64_t service_gate_address(unsigned service_index)
{
    return VIBATNIUM_EFI_CALL_GATE_BASE +
           (uint64_t)service_index * IA64_BUNDLE_SIZE;
}

static void write_service_descriptor(uint8_t *blob, size_t size,
                                     unsigned service_index)
{
    uint64_t descriptor = service_descriptor_address(service_index);
    uint64_t gate = service_gate_address(service_index);

    blob_wr64(blob, size, descriptor, gate);
    blob_wr64(blob, size, descriptor + 8, VIBATNIUM_EFI_SYSTEM_TABLE);
    write_return_gate(blob, size, gate);
}

static void write_guid(uint8_t *blob, size_t size, uint64_t address,
                       const uint8_t guid[16])
{
    memcpy(blob_ptr(blob, size, address, 16), guid, 16);
}

static void efi_image_reset(VibatniumEfiImage *image)
{
    memset(image, 0, sizeof(*image));
}

static bool apply_base_relocations(uint8_t *memory_image,
                                   uint32_t size_of_image,
                                   uint64_t delta,
                                   uint32_t reloc_rva,
                                   uint32_t reloc_size,
                                   Error **errp)
{
    uint32_t offset;
    uint32_t end;

    if (delta == 0) {
        return true;
    }
    if (reloc_rva == 0 || reloc_size == 0) {
        error_setg(errp,
                   "EFI image relocation required but no relocation "
                   "directory is present");
        return false;
    }
    if (reloc_rva > size_of_image || reloc_size > size_of_image - reloc_rva) {
        error_setg(errp, "EFI image relocation directory is outside image");
        return false;
    }

    offset = reloc_rva;
    end = reloc_rva + reloc_size;
    while (offset + 8 <= end) {
        uint32_t page_rva = rd32(memory_image + offset);
        uint32_t block_size = rd32(memory_image + offset + 4);
        uint32_t count;

        if (block_size < 8 || block_size > end - offset) {
            error_setg(errp, "EFI image relocation block is malformed");
            return false;
        }

        count = (block_size - 8) / 2;
        for (uint32_t i = 0; i < count; i++) {
            uint16_t entry = rd16(memory_image + offset + 8 + i * 2);
            uint16_t type = entry >> 12;
            uint32_t fixup_rva = page_rva + (entry & 0x0fff);
            uint64_t value;

            switch (type) {
            case PE_BASE_RELOCATION_ABSOLUTE:
                break;
            case PE_BASE_RELOCATION_DIR64:
                if (fixup_rva > size_of_image ||
                    8 > size_of_image - fixup_rva) {
                    error_setg(errp,
                               "EFI image DIR64 relocation target 0x%x is "
                               "outside image",
                               fixup_rva);
                    return false;
                }
                value = rd64(memory_image + fixup_rva);
                wr64(memory_image + fixup_rva, value + delta);
                break;
            default:
                error_setg(errp, "unsupported EFI image relocation type %u",
                           type);
                return false;
            }
        }

        offset += block_size;
    }

    return true;
}

bool vibatnium_efi_image_from_buffer(const char *path,
                                     const uint8_t *file,
                                     size_t file_size,
                                     uint64_t load_base,
                                     VibatniumEfiImage *image,
                                     Error **errp)
{
    uint32_t pe_offset;
    const uint8_t *pe;
    const uint8_t *coff;
    const uint8_t *optional;
    const uint8_t *section_table;
    uint16_t machine;
    uint16_t sections;
    uint16_t optional_size;
    uint16_t optional_magic;
    uint32_t entry_rva;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t section_alignment;
    uint32_t number_of_rva_and_sizes = 0;
    uint32_t data_directory_offset;
    uint32_t reloc_rva = 0;
    uint32_t reloc_size = 0;
    uint64_t preferred_image_base;
    uint64_t entry_descriptor;
    uint64_t code_entry;
    uint64_t global_pointer;
    uint8_t *memory_image;

    g_return_val_if_fail(image != NULL, false);
    efi_image_reset(image);

    if (!file || file_size < 0x40) {
        error_setg(errp, "EFI image is too small");
        return false;
    }
    if (file[0] != 'M' || file[1] != 'Z') {
        error_setg(errp, "EFI image does not have an MZ header");
        return false;
    }
    if (!range_ok(file_size, PE_SIGNATURE_OFFSET, sizeof(uint32_t))) {
        error_setg(errp, "EFI image DOS header is truncated");
        return false;
    }

    pe_offset = rd32(file + PE_SIGNATURE_OFFSET);
    if (!range_ok(file_size, pe_offset,
                  PE_SIGNATURE_SIZE + COFF_HEADER_SIZE)) {
        error_setg(errp, "EFI image PE header is outside the file");
        return false;
    }

    pe = file + pe_offset;
    if (memcmp(pe, "PE\0\0", PE_SIGNATURE_SIZE) != 0) {
        error_setg(errp, "EFI image does not have a PE signature");
        return false;
    }

    coff = pe + PE_SIGNATURE_SIZE;
    machine = rd16(coff);
    sections = rd16(coff + 2);
    optional_size = rd16(coff + 16);

    if (machine != VIBATNIUM_EFI_PE_MACHINE_IA64) {
        error_setg(errp, "EFI image machine 0x%04x is not IA-64", machine);
        return false;
    }
    if (sections == 0) {
        error_setg(errp, "EFI image has no sections");
        return false;
    }
    if (!range_ok(file_size, pe_offset + PE_SIGNATURE_SIZE + COFF_HEADER_SIZE,
                  optional_size)) {
        error_setg(errp, "EFI image optional header is truncated");
        return false;
    }

    optional = coff + COFF_HEADER_SIZE;
    optional_magic = rd16(optional);
    if (optional_magic != PE32_MAGIC && optional_magic != PE32P_MAGIC) {
        error_setg(errp, "EFI image optional header magic 0x%04x is unsupported",
                   optional_magic);
        return false;
    }
    if (optional_size < 64) {
        error_setg(errp, "EFI image optional header is too small");
        return false;
    }

    entry_rva = rd32(optional + 16);
    preferred_image_base = optional_magic == PE32P_MAGIC ?
                           rd64(optional + 24) : rd32(optional + 28);
    section_alignment = rd32(optional + 32);
    size_of_image = rd32(optional + 56);
    size_of_headers = rd32(optional + 60);
    data_directory_offset = optional_magic == PE32P_MAGIC ?
                            PE32P_DATA_DIRECTORY_OFFSET :
                            PE32_DATA_DIRECTORY_OFFSET;
    if (optional_size >= data_directory_offset) {
        uint32_t number_offset = data_directory_offset - 4;

        number_of_rva_and_sizes = rd32(optional + number_offset);
        if (number_of_rva_and_sizes > PE_DIRECTORY_BASE_RELOCATION &&
            optional_size >= data_directory_offset +
                             (PE_DIRECTORY_BASE_RELOCATION + 1) * 8) {
            const uint8_t *reloc_dir =
                optional + data_directory_offset +
                PE_DIRECTORY_BASE_RELOCATION * 8;

            reloc_rva = rd32(reloc_dir);
            reloc_size = rd32(reloc_dir + 4);
        }
    }

    if (section_alignment == 0) {
        error_setg(errp, "EFI image has zero section alignment");
        return false;
    }
    if (size_of_image == 0 || size_of_image > MAX_EFI_IMAGE_SIZE) {
        error_setg(errp, "EFI image size 0x%x is unsupported", size_of_image);
        return false;
    }
    if (size_of_headers > size_of_image) {
        error_setg(errp, "EFI image headers exceed image size");
        return false;
    }
    if (entry_rva >= size_of_image) {
        error_setg(errp, "EFI image entry RVA 0x%x is outside image size 0x%x",
                   entry_rva, size_of_image);
        return false;
    }
    if (entry_rva > size_of_image || 16 > size_of_image - entry_rva) {
        error_setg(errp,
                   "EFI image IA-64 entry descriptor RVA 0x%x is truncated",
                   entry_rva);
        return false;
    }
    if (UINT64_MAX - load_base < size_of_image) {
        error_setg(errp, "EFI image load address overflows");
        return false;
    }

    section_table = optional + optional_size;
    if (!range_ok(file_size, section_table - file,
                  (uint64_t)sections * SECTION_HEADER_SIZE)) {
        error_setg(errp, "EFI image section table is truncated");
        return false;
    }

    memory_image = g_malloc0(size_of_image);
    memcpy(memory_image, file, MIN((size_t)size_of_headers, file_size));

    for (uint16_t i = 0; i < sections; i++) {
        const uint8_t *section = section_table + i * SECTION_HEADER_SIZE;
        uint32_t virtual_size = rd32(section + 8);
        uint32_t virtual_address = rd32(section + 12);
        uint32_t raw_size = rd32(section + 16);
        uint32_t raw_pointer = rd32(section + 20);
        uint32_t copy_size = raw_size;

        if (raw_size == 0) {
            continue;
        }
        if (!range_ok(file_size, raw_pointer, raw_size)) {
            error_setg(errp, "EFI image section %u raw data is truncated", i);
            g_free(memory_image);
            return false;
        }
        if (virtual_address >= size_of_image) {
            error_setg(errp, "EFI image section %u VA 0x%x is outside image",
                       i, virtual_address);
            g_free(memory_image);
            return false;
        }
        if (virtual_size != 0 && virtual_size < copy_size) {
            copy_size = virtual_size;
        }
        if (copy_size > size_of_image - virtual_address) {
            error_setg(errp, "EFI image section %u exceeds image size", i);
            g_free(memory_image);
            return false;
        }

        memcpy(memory_image + virtual_address, file + raw_pointer, copy_size);
    }

    if (!apply_base_relocations(memory_image, size_of_image,
                                load_base - preferred_image_base,
                                reloc_rva, reloc_size, errp)) {
        g_free(memory_image);
        return false;
    }

    entry_descriptor = load_base + entry_rva;
    code_entry = rd64(memory_image + entry_rva);
    global_pointer = rd64(memory_image + entry_rva + 8);
    if (code_entry == 0) {
        error_setg(errp, "EFI image IA-64 entry descriptor has zero entry");
        g_free(memory_image);
        return false;
    }

    image->data = memory_image;
    image->size = size_of_image;
    image->load_base = load_base;
    image->entry_descriptor = entry_descriptor;
    image->entry = code_entry;
    image->global_pointer = global_pointer;
    image->preferred_image_base = preferred_image_base;
    image->entry_rva = entry_rva;
    image->size_of_image = size_of_image;
    image->section_alignment = section_alignment;
    image->number_of_sections = sections;
    g_strlcpy(image->source_path, path ? path : "<buffer>",
              sizeof(image->source_path));
    g_snprintf(image->message, sizeof(image->message),
               "loaded IA-64 EFI image path=%s load=0x%016" PRIx64
               " descriptor=0x%016" PRIx64 " entry=0x%016" PRIx64
               " gp=0x%016" PRIx64 " size=0x%x sections=%u",
               image->source_path, image->load_base, image->entry_descriptor,
               image->entry, image->global_pointer, image->size_of_image,
               image->number_of_sections);

    return true;
}

bool vibatnium_efi_image_from_file(const char *path,
                                   uint64_t load_base,
                                   VibatniumEfiImage *image,
                                   Error **errp)
{
    g_autoptr(GError) gerr = NULL;
    g_autofree gchar *contents = NULL;
    gsize length = 0;

    if (!path || !*path) {
        error_setg(errp, "EFI image path is empty");
        return false;
    }

    if (!g_file_get_contents(path, &contents, &length, &gerr)) {
        error_setg(errp, "%s", gerr->message);
        return false;
    }

    return vibatnium_efi_image_from_buffer(path, (const uint8_t *)contents,
                                           length, load_base, image, errp);
}

void vibatnium_efi_image_destroy(VibatniumEfiImage *image)
{
    if (!image) {
        return;
    }

    g_free(image->data);
    efi_image_reset(image);
}

enum {
    EFI_BOOT_SERVICE_BASE = 0,
    EFI_RUNTIME_SERVICE_BASE =
        EFI_BOOT_SERVICE_BASE + VIBATNIUM_EFI_BOOT_SERVICE_COUNT,
    EFI_CON_OUT_SERVICE_BASE =
        EFI_RUNTIME_SERVICE_BASE + VIBATNIUM_EFI_RUNTIME_SERVICE_COUNT,
    EFI_CON_IN_SERVICE_BASE =
        EFI_CON_OUT_SERVICE_BASE + VIBATNIUM_EFI_CON_OUT_SERVICE_COUNT,
    EFI_SERVICE_DESCRIPTOR_COUNT =
        EFI_CON_IN_SERVICE_BASE + VIBATNIUM_EFI_CON_IN_SERVICE_COUNT,
};

static const uint8_t efi_loaded_image_guid[16] = {
    0xa1, 0x31, 0x1b, 0x5b, 0x62, 0x95, 0xd2, 0x11,
    0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
};

static void write_utf16_ascii(uint8_t *blob, size_t size, uint64_t address,
                              const char *text)
{
    uint8_t *p = blob_ptr(blob, size, address, (strlen(text) + 1) * 2);

    while (*text) {
        p[0] = *text++;
        p[1] = 0;
        p += 2;
    }
    p[0] = 0;
    p[1] = 0;
}

static void write_loaded_image(uint8_t *blob, size_t size,
                               const VibatniumEfiImage *image)
{
    uint64_t image_base = image ? image->load_base : 0;
    uint64_t image_size = image ? image->size : 0;

    blob_wr32(blob, size, VIBATNIUM_EFI_LOADED_IMAGE, 0x1000);
    blob_wr64(blob, size, VIBATNIUM_EFI_LOADED_IMAGE + 16,
              VIBATNIUM_EFI_SYSTEM_TABLE);
    blob_wr64(blob, size, VIBATNIUM_EFI_LOADED_IMAGE + 24,
              VIBATNIUM_EFI_BOOT_DEVICE_HANDLE);
    blob_wr64(blob, size, VIBATNIUM_EFI_LOADED_IMAGE + 64, image_base);
    blob_wr64(blob, size, VIBATNIUM_EFI_LOADED_IMAGE + 72, image_size);
    blob_wr32(blob, size, VIBATNIUM_EFI_LOADED_IMAGE + 80, 1);
    blob_wr32(blob, size, VIBATNIUM_EFI_LOADED_IMAGE + 84, 2);
}

static void write_system_table(uint8_t *blob, size_t size)
{
    uint8_t *table = blob_ptr(blob, size, VIBATNIUM_EFI_SYSTEM_TABLE, 120);

    blob_wr64(blob, size, VIBATNIUM_EFI_SYSTEM_TABLE + 24,
              VIBATNIUM_EFI_FIRMWARE_VENDOR);
    blob_wr32(blob, size, VIBATNIUM_EFI_SYSTEM_TABLE + 32, 1);
    blob_wr64(blob, size, VIBATNIUM_EFI_SYSTEM_TABLE + 40,
              VIBATNIUM_EFI_BOOT_DEVICE_HANDLE);
    blob_wr64(blob, size, VIBATNIUM_EFI_SYSTEM_TABLE + 48,
              VIBATNIUM_EFI_CON_IN);
    blob_wr64(blob, size, VIBATNIUM_EFI_SYSTEM_TABLE + 56,
              VIBATNIUM_EFI_BOOT_DEVICE_HANDLE);
    blob_wr64(blob, size, VIBATNIUM_EFI_SYSTEM_TABLE + 64,
              VIBATNIUM_EFI_CON_OUT);
    blob_wr64(blob, size, VIBATNIUM_EFI_SYSTEM_TABLE + 72,
              VIBATNIUM_EFI_BOOT_DEVICE_HANDLE);
    blob_wr64(blob, size, VIBATNIUM_EFI_SYSTEM_TABLE + 80,
              VIBATNIUM_EFI_CON_OUT);
    blob_wr64(blob, size, VIBATNIUM_EFI_SYSTEM_TABLE + 88,
              VIBATNIUM_EFI_RUNTIME_SERVICES);
    blob_wr64(blob, size, VIBATNIUM_EFI_SYSTEM_TABLE + 96,
              VIBATNIUM_EFI_BOOT_SERVICES);
    blob_wr64(blob, size, VIBATNIUM_EFI_SYSTEM_TABLE + 104, 0);
    blob_wr64(blob, size, VIBATNIUM_EFI_SYSTEM_TABLE + 112,
              VIBATNIUM_EFI_CONFIGURATION_TABLE);
    write_table_header(table, 120, 0x5453595320494249ULL);
}

static void write_service_table(uint8_t *blob, size_t size, uint64_t address,
                                uint64_t signature, unsigned service_base,
                                unsigned service_count, int reserved_index)
{
    size_t table_size = 24 + service_count * sizeof(uint64_t);
    uint8_t *table = blob_ptr(blob, size, address, table_size);

    for (unsigned i = 0; i < service_count; i++) {
        uint64_t slot = i == (unsigned)reserved_index
            ? 0
            : service_descriptor_address(service_base + i);
        blob_wr64(blob, size, address + 24 + i * sizeof(uint64_t), slot);
    }
    write_table_header(table, table_size, signature);
}

static void write_console_protocols(uint8_t *blob, size_t size)
{
    for (unsigned i = 0; i < VIBATNIUM_EFI_CON_OUT_SERVICE_COUNT; i++) {
        blob_wr64(blob, size, VIBATNIUM_EFI_CON_OUT + i * sizeof(uint64_t),
                  service_descriptor_address(EFI_CON_OUT_SERVICE_BASE + i));
    }
    blob_wr64(blob, size,
              VIBATNIUM_EFI_CON_OUT +
              VIBATNIUM_EFI_CON_OUT_SERVICE_COUNT * sizeof(uint64_t),
              VIBATNIUM_EFI_CON_OUT_MODE);
    blob_wr32(blob, size, VIBATNIUM_EFI_CON_OUT_MODE, 1);
    blob_wr32(blob, size, VIBATNIUM_EFI_CON_OUT_MODE + 4, 0);
    blob_wr32(blob, size, VIBATNIUM_EFI_CON_OUT_MODE + 8, 0x07);
    blob_ptr(blob, size, VIBATNIUM_EFI_CON_OUT_MODE + 20, 1)[0] = 1;

    for (unsigned i = 0; i < VIBATNIUM_EFI_CON_IN_SERVICE_COUNT; i++) {
        blob_wr64(blob, size, VIBATNIUM_EFI_CON_IN + i * sizeof(uint64_t),
                  service_descriptor_address(EFI_CON_IN_SERVICE_BASE + i));
    }
}

uint8_t *vibatnium_efi_build_firmware_blob(size_t *size,
                                           const VibatniumEfiImage *image)
{
    uint8_t *blob;

    if (size) {
        *size = VIBATNIUM_EFI_BLOB_SIZE;
    }

    blob = g_malloc0(VIBATNIUM_EFI_BLOB_SIZE);
    write_utf16_ascii(blob, VIBATNIUM_EFI_BLOB_SIZE,
                      VIBATNIUM_EFI_FIRMWARE_VENDOR, "Vibatnium");
    for (unsigned i = 0; i < EFI_SERVICE_DESCRIPTOR_COUNT; i++) {
        write_service_descriptor(blob, VIBATNIUM_EFI_BLOB_SIZE, i);
    }

    write_loaded_image(blob, VIBATNIUM_EFI_BLOB_SIZE, image);
    write_console_protocols(blob, VIBATNIUM_EFI_BLOB_SIZE);
    write_service_table(blob, VIBATNIUM_EFI_BLOB_SIZE,
                        VIBATNIUM_EFI_BOOT_SERVICES,
                        0x56524553544f4f42ULL,
                        EFI_BOOT_SERVICE_BASE,
                        VIBATNIUM_EFI_BOOT_SERVICE_COUNT, 17);
    write_service_table(blob, VIBATNIUM_EFI_BLOB_SIZE,
                        VIBATNIUM_EFI_RUNTIME_SERVICES,
                        0x56524553544e5552ULL,
                        EFI_RUNTIME_SERVICE_BASE,
                        VIBATNIUM_EFI_RUNTIME_SERVICE_COUNT, -1);
    write_system_table(blob, VIBATNIUM_EFI_BLOB_SIZE);
    write_guid(blob, VIBATNIUM_EFI_BLOB_SIZE, VIBATNIUM_EFI_CONFIGURATION_TABLE,
               efi_loaded_image_guid);

    return blob;
}

void vibatnium_efi_prepare_cpu(CPUIA64State *env,
                               const VibatniumEfiImage *image)
{
    if (!env || !image) {
        return;
    }

    env->ip = image->entry;
    env->cr[IA64_CR_IIP] = image->entry;
    ia64_write_gr(env, 0, 0);
    ia64_write_gr(env, 1, image->global_pointer);
    ia64_write_gr(env, 12,
                  VIBATNIUM_EFI_STACK_BASE + VIBATNIUM_EFI_STACK_SIZE - 16);
    ia64_write_gr(env, 32, VIBATNIUM_EFI_IMAGE_HANDLE);
    ia64_write_gr(env, 33, VIBATNIUM_EFI_SYSTEM_TABLE);

    env->rse.bsp = VIBATNIUM_EFI_BACKING_STORE_BASE;
    env->rse.bspstore = VIBATNIUM_EFI_BACKING_STORE_BASE;
    env->ar[IA64_AR_BSP] = env->rse.bsp;
    env->ar[IA64_AR_BSPSTORE] = env->rse.bspstore;
}

const char *vibatnium_efi_status_name(uint64_t status)
{
    switch (status) {
    case VIBATNIUM_EFI_SUCCESS:
        return "success";
    case VIBATNIUM_EFI_LOAD_ERROR:
        return "load-error";
    case VIBATNIUM_EFI_INVALID_PARAMETER:
        return "invalid-parameter";
    case VIBATNIUM_EFI_UNSUPPORTED:
        return "unsupported";
    case VIBATNIUM_EFI_OUT_OF_RESOURCES:
        return "out-of-resources";
    case VIBATNIUM_EFI_NOT_FOUND:
        return "not-found";
    default:
        return "unknown";
    }
}

const char *vibatnium_efi_service_name(VibatniumEfiService service)
{
    switch (service) {
    case VIBATNIUM_EFI_SERVICE_LOADED_IMAGE_PROTOCOL:
        return "LoadedImageProtocol";
    case VIBATNIUM_EFI_SERVICE_OUTPUT_STRING:
        return "SimpleTextOutput.OutputString";
    case VIBATNIUM_EFI_SERVICE_EXIT:
        return "BootServices.Exit";
    case VIBATNIUM_EFI_SERVICE_EXIT_BOOT_SERVICES:
        return "BootServices.ExitBootServices";
    case VIBATNIUM_EFI_SERVICE_GET_VARIABLE:
        return "RuntimeServices.GetVariable";
    case VIBATNIUM_EFI_SERVICE_SET_VARIABLE:
        return "RuntimeServices.SetVariable";
    case VIBATNIUM_EFI_SERVICE_UNKNOWN:
    default:
        return "unknown-service";
    }
}

uint64_t vibatnium_efi_record_unimplemented_service(
    VibatniumEfiServiceCall *call,
    VibatniumEfiService service,
    uint64_t guest_ip,
    const uint64_t *args,
    uint8_t nargs)
{
    size_t offset;
    uint8_t count;

    g_return_val_if_fail(call != NULL, VIBATNIUM_EFI_INVALID_PARAMETER);

    memset(call, 0, sizeof(*call));
    count = MIN(nargs, (uint8_t)G_N_ELEMENTS(call->args));
    call->service = service;
    call->service_name = vibatnium_efi_service_name(service);
    call->guest_ip = guest_ip;
    call->nargs = count;
    call->status = VIBATNIUM_EFI_UNSUPPORTED;

    for (uint8_t i = 0; i < count; i++) {
        call->args[i] = args ? args[i] : 0;
    }

    offset = g_snprintf(call->message, sizeof(call->message),
                        "EFI service unimplemented service=%s ip=0x%016"
                        PRIx64 " args=[",
                        call->service_name, call->guest_ip);
    for (uint8_t i = 0; i < count && offset < sizeof(call->message); i++) {
        offset += g_snprintf(call->message + offset,
                             sizeof(call->message) - offset,
                             "%s0x%016" PRIx64, i == 0 ? "" : ",",
                             call->args[i]);
    }
    if (offset < sizeof(call->message)) {
        g_snprintf(call->message + offset, sizeof(call->message) - offset,
                   "] status=%s(0x%016" PRIx64 ")",
                   vibatnium_efi_status_name(call->status), call->status);
    }

    return call->status;
}

const char *vibatnium_efi_frontier_name(VibatniumEfiFrontierKind kind)
{
    switch (kind) {
    case VIBATNIUM_EFI_FRONTIER_IMAGE_ENTRY:
        return "image-entry";
    case VIBATNIUM_EFI_FRONTIER_EFI_SERVICE_CALL:
        return "efi-service-call";
    case VIBATNIUM_EFI_FRONTIER_FILE_READ:
        return "file-read";
    case VIBATNIUM_EFI_FRONTIER_MEMORY_MAP:
        return "memory-map";
    case VIBATNIUM_EFI_FRONTIER_EXIT_BOOT_SERVICES:
        return "exit-boot-services";
    case VIBATNIUM_EFI_FRONTIER_KERNEL_ENTRY:
        return "kernel-entry";
    case VIBATNIUM_EFI_FRONTIER_BOOT_PARAMETERS:
        return "boot-parameters";
    case VIBATNIUM_EFI_FRONTIER_SAL_PAL_CALL:
        return "sal-pal-call";
    default:
        return "unknown-frontier";
    }
}

void vibatnium_efi_format_frontier(char *buffer,
                                   size_t buffer_size,
                                   VibatniumEfiFrontierKind kind,
                                   uint64_t guest_ip,
                                   const char *state,
                                   const char *detail)
{
    if (!buffer || buffer_size == 0) {
        return;
    }

    g_snprintf(buffer, buffer_size,
               "vibatnium EFI frontier kind=%s ip=0x%016" PRIx64
               " state=%s detail=%s",
               vibatnium_efi_frontier_name(kind), guest_ip,
               state ? state : "unknown",
               detail ? detail : "none");
}
