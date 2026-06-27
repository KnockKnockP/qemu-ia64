/*
 * IA-64 synthetic EFI app launch tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/ia64/efi.h"
#include "hw/ia64/efi-storage.h"
#include "target/ia64/exec-smoke.h"

#define SYNTHETIC_PE_SIZE 0x400
#define SYNTHETIC_PE_OFFSET 0x80
#define SYNTHETIC_OPT_SIZE 0xf0
#define SYNTHETIC_SECTION_OFFSET \
    (SYNTHETIC_PE_OFFSET + 4 + 20 + SYNTHETIC_OPT_SIZE)
#define SYNTHETIC_RAW_OFFSET 0x200
#define SYNTHETIC_TEXT_RVA 0x1000
#define SYNTHETIC_DESCRIPTOR_RVA 0x1100
#define SYNTHETIC_RELOC_RVA 0x1180
#define SYNTHETIC_IMAGE_SIZE 0x2000
#define SYNTHETIC_GP_RVA 0x1800
#define IA64_PSR_BN_BIT UINT64_C(0x0000100000000000)

static void store_le16(uint8_t *p, uint16_t value)
{
    p[0] = value;
    p[1] = value >> 8;
}

static void store_le32(uint8_t *p, uint32_t value)
{
    p[0] = value;
    p[1] = value >> 8;
    p[2] = value >> 16;
    p[3] = value >> 24;
}

static void store_le64(uint8_t *p, uint64_t value)
{
    for (int i = 0; i < 8; i++) {
        p[i] = value >> (i * 8);
    }
}

static uint64_t load_le64(const uint8_t *p)
{
    uint64_t value = 0;

    for (int i = 7; i >= 0; i--) {
        value = (value << 8) | p[i];
    }
    return value;
}

static uint32_t load_le32(const uint8_t *p)
{
    uint32_t value = 0;

    for (int i = 3; i >= 0; i--) {
        value = (value << 8) | p[i];
    }
    return value;
}

static uint8_t byte_sum(const uint8_t *p, size_t size)
{
    uint32_t sum = 0;

    for (size_t i = 0; i < size; i++) {
        sum = (sum + p[i]) & 0xff;
    }
    return sum;
}

static const uint8_t *firmware_ptr(const uint8_t *blob, uint64_t address)
{
    g_assert_cmphex(address, >=, VIBTANIUM_EFI_BLOB_BASE);
    g_assert_cmphex(address, <,
                    VIBTANIUM_EFI_BLOB_BASE + VIBTANIUM_EFI_BLOB_SIZE);
    return blob + (address - VIBTANIUM_EFI_BLOB_BASE);
}

static const uint8_t efi_sal_system_table_guid[16] = {
    0x32, 0x2d, 0x9d, 0xeb, 0x88, 0x2d, 0xd3, 0x11,
    0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d,
};

static const uint8_t efi_hcdp_table_guid[16] = {
    0x8d, 0x93, 0x51, 0xf9, 0x0b, 0x62, 0xef, 0x42,
    0x82, 0x79, 0xa8, 0x4b, 0x79, 0x61, 0x78, 0x98,
};

static const uint8_t efi_acpi20_table_guid[16] = {
    0x71, 0xe8, 0x68, 0x88, 0xf1, 0xe4, 0xd3, 0x11,
    0xbc, 0x22, 0x00, 0x80, 0xc7, 0x3c, 0x88, 0x81,
};

static void make_synthetic_ia64_pe(uint8_t *pe,
                                   uint16_t machine,
                                   uint64_t preferred_base,
                                   bool with_relocs)
{
    uint8_t *coff;
    uint8_t *optional;
    uint8_t *section;
    uint8_t *descriptor;
    uint8_t *reloc;

    memset(pe, 0, SYNTHETIC_PE_SIZE);
    pe[0] = 'M';
    pe[1] = 'Z';
    store_le32(pe + 0x3c, SYNTHETIC_PE_OFFSET);

    pe[SYNTHETIC_PE_OFFSET] = 'P';
    pe[SYNTHETIC_PE_OFFSET + 1] = 'E';
    coff = pe + SYNTHETIC_PE_OFFSET + 4;
    store_le16(coff, machine);
    store_le16(coff + 2, 1);
    store_le16(coff + 16, SYNTHETIC_OPT_SIZE);

    optional = coff + 20;
    store_le16(optional, 0x20b);
    store_le32(optional + 16, SYNTHETIC_DESCRIPTOR_RVA);
    store_le64(optional + 24, preferred_base);
    store_le32(optional + 32, 0x1000);
    store_le32(optional + 36, 0x200);
    store_le32(optional + 56, SYNTHETIC_IMAGE_SIZE);
    store_le32(optional + 60, 0x200);
    store_le32(optional + 108, 16);
    if (with_relocs) {
        store_le32(optional + 112 + 5 * 8, SYNTHETIC_RELOC_RVA);
        store_le32(optional + 112 + 5 * 8 + 4, 16);
    }

    section = pe + SYNTHETIC_SECTION_OFFSET;
    memcpy(section, ".text", 5);
    store_le32(section + 8, 0x200);
    store_le32(section + 12, SYNTHETIC_TEXT_RVA);
    store_le32(section + 16, 0x200);
    store_le32(section + 20, SYNTHETIC_RAW_OFFSET);

    pe[SYNTHETIC_RAW_OFFSET] = 0x55;
    pe[SYNTHETIC_RAW_OFFSET + 1] = 0xaa;

    descriptor = pe + SYNTHETIC_RAW_OFFSET +
                 (SYNTHETIC_DESCRIPTOR_RVA - SYNTHETIC_TEXT_RVA);
    store_le64(descriptor, preferred_base + SYNTHETIC_TEXT_RVA);
    store_le64(descriptor + 8, preferred_base + SYNTHETIC_GP_RVA);

    if (with_relocs) {
        reloc = pe + SYNTHETIC_RAW_OFFSET +
                (SYNTHETIC_RELOC_RVA - SYNTHETIC_TEXT_RVA);
        store_le32(reloc, SYNTHETIC_TEXT_RVA);
        store_le32(reloc + 4, 16);
        store_le16(reloc + 8,
                   (10 << 12) |
                   (SYNTHETIC_DESCRIPTOR_RVA - SYNTHETIC_TEXT_RVA));
        store_le16(reloc + 10,
                   (10 << 12) |
                   (SYNTHETIC_DESCRIPTOR_RVA + 8 - SYNTHETIC_TEXT_RVA));
        store_le16(reloc + 12, 0);
        store_le16(reloc + 14, 0);
    }
}

static void test_loads_synthetic_ia64_pe(void)
{
    uint8_t pe[SYNTHETIC_PE_SIZE];
    VibtaniumEfiImage image;
    Error *err = NULL;

    make_synthetic_ia64_pe(pe, VIBTANIUM_EFI_PE_MACHINE_IA64,
                           VIBTANIUM_EFI_APP_BASE, false);

    g_assert_true(vibtanium_efi_image_from_buffer("synthetic.efi", pe,
                                                 sizeof(pe),
                                                 VIBTANIUM_EFI_APP_BASE,
                                                 &image, &err));
    g_assert_null(err);
    g_assert_cmphex(image.load_base, ==, VIBTANIUM_EFI_APP_BASE);
    g_assert_cmphex(image.entry_descriptor, ==,
                    VIBTANIUM_EFI_APP_BASE + SYNTHETIC_DESCRIPTOR_RVA);
    g_assert_cmphex(image.entry, ==,
                    VIBTANIUM_EFI_APP_BASE + SYNTHETIC_TEXT_RVA);
    g_assert_cmphex(image.global_pointer, ==,
                    VIBTANIUM_EFI_APP_BASE + SYNTHETIC_GP_RVA);
    g_assert_cmpuint(image.size, ==, SYNTHETIC_IMAGE_SIZE);
    g_assert_cmphex(image.data[SYNTHETIC_TEXT_RVA], ==, 0x55);
    g_assert_cmphex(image.data[SYNTHETIC_TEXT_RVA + 1], ==, 0xaa);
    g_assert_nonnull(strstr(image.message, "loaded IA-64 EFI image"));

    vibtanium_efi_image_destroy(&image);
}

static void test_rejects_non_ia64_pe(void)
{
    uint8_t pe[SYNTHETIC_PE_SIZE];
    VibtaniumEfiImage image;
    Error *err = NULL;

    make_synthetic_ia64_pe(pe, 0x8664, VIBTANIUM_EFI_APP_BASE, false);

    g_assert_false(vibtanium_efi_image_from_buffer("x64.efi", pe, sizeof(pe),
                                                  VIBTANIUM_EFI_APP_BASE,
                                                  &image, &err));
    g_assert_nonnull(err);
    g_assert_nonnull(strstr(error_get_pretty(err), "not IA-64"));
    error_free(err);
}

static void test_prepare_cpu_entry_abi(void)
{
    uint8_t pe[SYNTHETIC_PE_SIZE];
    VibtaniumEfiImage image;
    CPUIA64State env;
    Error *err = NULL;

    make_synthetic_ia64_pe(pe, VIBTANIUM_EFI_PE_MACHINE_IA64,
                           VIBTANIUM_EFI_APP_BASE, false);
    g_assert_true(vibtanium_efi_image_from_buffer("synthetic.efi", pe,
                                                 sizeof(pe),
                                                 VIBTANIUM_EFI_APP_BASE,
                                                 &image, &err));
    g_assert_null(err);

    ia64_cpu_reset_synthetic_itanium2(&env);
    vibtanium_efi_prepare_cpu(&env, &image);

    g_assert_cmphex(env.ip, ==,
                    VIBTANIUM_EFI_APP_BASE + SYNTHETIC_TEXT_RVA);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, env.ip);
    g_assert_cmphex(env.gr[1], ==,
                    VIBTANIUM_EFI_APP_BASE + SYNTHETIC_GP_RVA);
    g_assert_cmphex(ia64_read_gr(&env, 12), ==,
                    VIBTANIUM_EFI_STACK_BASE +
                    VIBTANIUM_EFI_STACK_SIZE - 16);
    g_assert_cmphex(ia64_read_gr(&env, 32), ==, VIBTANIUM_EFI_IMAGE_HANDLE);
    g_assert_cmphex(ia64_read_gr(&env, 33), ==, VIBTANIUM_EFI_SYSTEM_TABLE);
    g_assert_cmphex(env.psr & IA64_PSR_BN_BIT, ==, IA64_PSR_BN_BIT);
    ia64_write_gr(&env, 28, 0x123456789abcdef0ULL);
    env.psr &= ~IA64_PSR_BN_BIT;
    g_assert_cmphex(ia64_read_gr(&env, 28), ==, 0);
    env.psr |= IA64_PSR_BN_BIT;
    g_assert_cmphex(ia64_read_gr(&env, 28), ==, 0x123456789abcdef0ULL);
    g_assert_cmphex(env.ar[IA64_AR_BSP], ==,
                    VIBTANIUM_EFI_BACKING_STORE_BASE);
    g_assert_cmphex(env.ar[IA64_AR_BSPSTORE], ==,
                    VIBTANIUM_EFI_BACKING_STORE_BASE);
    g_assert_cmphex(env.gr[0], ==, 0);

    vibtanium_efi_image_destroy(&image);
}

static void test_builds_guest_firmware_tables(void)
{
    VibtaniumEfiImage image = {
        .load_base = VIBTANIUM_EFI_APP_BASE,
        .size = 0x123450,
    };
    VibtaniumEfiBlockDevice boot_media = {
        .size = 2048 * 10,
        .block_size = 2048,
        .read_only = true,
        .removable = true,
        .cdrom = true,
    };
    size_t blob_size = 0;
    uint8_t *blob = vibtanium_efi_build_firmware_blob(&blob_size, &image,
                                                      &boot_media);
    uint64_t boot_services;
    uint64_t runtime_services;
    uint64_t get_time_descriptor;
    uint64_t get_time_gate;
    uint64_t set_virtual_address_map_descriptor;
    uint64_t handle_protocol_descriptor;
    uint64_t handle_protocol_gate;
    const uint8_t *config_entry;
    const uint8_t *sal_config_entry;
    const uint8_t *sal_table;
    const uint8_t *sal_entry;
    const uint8_t *hcdp_config_entry;
    const uint8_t *hcdp_table;
    const uint8_t *hcdp_uart;
    const uint8_t *rsdp;
    const uint8_t *rsdt;
    const uint8_t *xsdt;
    const uint8_t *fadt;
    const uint8_t *dsdt;
    const uint8_t *madt;
    const uint8_t *facs;
    unsigned block_io_base;
    unsigned simplefs_base;

    g_assert_cmpuint(blob_size, ==, VIBTANIUM_EFI_BLOB_SIZE);

    boot_services = load_le64(firmware_ptr(
        blob, VIBTANIUM_EFI_SYSTEM_TABLE + 96));
    g_assert_cmphex(boot_services, ==, VIBTANIUM_EFI_BOOT_SERVICES);
    runtime_services = load_le64(firmware_ptr(
        blob, VIBTANIUM_EFI_SYSTEM_TABLE + 88));
    g_assert_cmphex(runtime_services, ==, VIBTANIUM_EFI_RUNTIME_SERVICES);
    g_assert_cmphex(load_le64(firmware_ptr(
                         blob, VIBTANIUM_EFI_SYSTEM_TABLE + 104)),
                    ==, 3);
    g_assert_cmphex(load_le64(firmware_ptr(
                         blob, VIBTANIUM_EFI_SYSTEM_TABLE + 112)),
                    ==, VIBTANIUM_EFI_CONFIGURATION_TABLE);

    handle_protocol_descriptor = load_le64(firmware_ptr(
        blob,
        VIBTANIUM_EFI_BOOT_SERVICES + 24 +
        VIBTANIUM_EFI_BOOT_HANDLE_PROTOCOL_INDEX * 8));
    g_assert_cmphex(handle_protocol_descriptor, ==,
                    VIBTANIUM_EFI_DESCRIPTOR_BASE +
                    VIBTANIUM_EFI_BOOT_HANDLE_PROTOCOL_INDEX * 16);

    handle_protocol_gate = load_le64(firmware_ptr(
        blob, handle_protocol_descriptor));
    g_assert_cmphex(handle_protocol_gate, ==,
                    VIBTANIUM_EFI_CALL_GATE_BASE +
                    VIBTANIUM_EFI_BOOT_HANDLE_PROTOCOL_INDEX * 16);
    g_assert_cmphex(load_le64(firmware_ptr(blob,
                                           handle_protocol_descriptor + 8)),
                    ==, VIBTANIUM_EFI_SYSTEM_TABLE);

    g_assert_cmphex(load_le64(firmware_ptr(blob,
                                           VIBTANIUM_EFI_LOADED_IMAGE + 16)),
                    ==, VIBTANIUM_EFI_SYSTEM_TABLE);
    g_assert_cmphex(load_le64(firmware_ptr(blob,
                                           VIBTANIUM_EFI_LOADED_IMAGE + 32)),
                    ==, VIBTANIUM_EFI_DEVICE_PATH);
    g_assert_cmphex(load_le64(firmware_ptr(blob,
                                           VIBTANIUM_EFI_LOADED_IMAGE + 64)),
                    ==, VIBTANIUM_EFI_APP_BASE);
    g_assert_cmphex(load_le64(firmware_ptr(blob,
                                           VIBTANIUM_EFI_LOADED_IMAGE + 72)),
                    ==, image.size);
    g_assert_cmphex(load_le64(firmware_ptr(
                         blob,
                         VIBTANIUM_EFI_CON_IN +
                         VIBTANIUM_EFI_CON_IN_SERVICE_COUNT * 8)),
                    ==, VIBTANIUM_EFI_CON_IN_WAIT_EVENT);

    g_assert_cmphex(load_le64(firmware_ptr(
                         blob,
                         VIBTANIUM_EFI_BOOT_SERVICES + 24 + 17 * 8)),
                    ==, 0);
    g_assert_cmphex(firmware_ptr(blob, handle_protocol_gate)[0], !=, 0);

    get_time_descriptor = load_le64(firmware_ptr(
        blob, VIBTANIUM_EFI_RUNTIME_SERVICES + 24));
    g_assert_cmphex(get_time_descriptor, ==,
                    VIBTANIUM_EFI_DESCRIPTOR_BASE +
                    VIBTANIUM_EFI_BOOT_SERVICE_COUNT * 16);
    get_time_gate = load_le64(firmware_ptr(blob, get_time_descriptor));
    g_assert_cmphex(get_time_gate, ==,
                    VIBTANIUM_EFI_CALL_GATE_BASE +
                    VIBTANIUM_EFI_BOOT_SERVICE_COUNT * 16);
    g_assert_cmphex(firmware_ptr(blob, get_time_gate)[0], !=, 0);
    set_virtual_address_map_descriptor = load_le64(firmware_ptr(
        blob, VIBTANIUM_EFI_RUNTIME_SERVICES + 24 + 4 * 8));
    g_assert_cmphex(set_virtual_address_map_descriptor, ==,
                    VIBTANIUM_EFI_DESCRIPTOR_BASE +
                    (VIBTANIUM_EFI_BOOT_SERVICE_COUNT + 4) * 16);

    config_entry = firmware_ptr(blob, VIBTANIUM_EFI_CONFIGURATION_TABLE);
    g_assert_cmpmem(config_entry, 16, efi_acpi20_table_guid, 16);
    g_assert_cmphex(load_le64(config_entry + 16),
                    ==, VIBTANIUM_EFI_ACPI_RSDP);
    sal_config_entry = config_entry + 24;
    g_assert_cmpmem(sal_config_entry, 16, efi_sal_system_table_guid, 16);
    g_assert_cmphex(load_le64(sal_config_entry + 16),
                    ==, VIBTANIUM_EFI_SAL_SYSTEM_TABLE);
    hcdp_config_entry = config_entry + 48;
    g_assert_cmpmem(hcdp_config_entry, 16, efi_hcdp_table_guid, 16);
    g_assert_cmphex(load_le64(hcdp_config_entry + 16),
                    ==, VIBTANIUM_EFI_HCDP_TABLE);

    rsdp = firmware_ptr(blob, VIBTANIUM_EFI_ACPI_RSDP);
    g_assert_cmpmem(rsdp, 8, "RSD PTR ", 8);
    g_assert_cmpuint(rsdp[15], ==, 2);
    g_assert_cmphex(load_le32(rsdp + 16), ==, VIBTANIUM_EFI_ACPI_RSDT);
    g_assert_cmphex(load_le32(rsdp + 20), ==, 36);
    g_assert_cmphex(load_le64(rsdp + 24), ==, VIBTANIUM_EFI_ACPI_XSDT);
    g_assert_cmphex(byte_sum(rsdp, 20), ==, 0);
    g_assert_cmphex(byte_sum(rsdp, 36), ==, 0);

    rsdt = firmware_ptr(blob, VIBTANIUM_EFI_ACPI_RSDT);
    g_assert_cmpmem(rsdt, 4, "RSDT", 4);
    g_assert_cmphex(load_le32(rsdt + 4), ==, 44);
    g_assert_cmphex(byte_sum(rsdt, 44), ==, 0);
    g_assert_cmphex(load_le32(rsdt + 36), ==, VIBTANIUM_EFI_ACPI_FADT);
    g_assert_cmphex(load_le32(rsdt + 40), ==, VIBTANIUM_EFI_ACPI_MADT);

    xsdt = firmware_ptr(blob, VIBTANIUM_EFI_ACPI_XSDT);
    g_assert_cmpmem(xsdt, 4, "XSDT", 4);
    g_assert_cmphex(load_le32(xsdt + 4), ==, 52);
    g_assert_cmphex(byte_sum(xsdt, 52), ==, 0);
    g_assert_cmphex(load_le64(xsdt + 36), ==, VIBTANIUM_EFI_ACPI_FADT);
    g_assert_cmphex(load_le64(xsdt + 44), ==, VIBTANIUM_EFI_ACPI_MADT);

    fadt = firmware_ptr(blob, VIBTANIUM_EFI_ACPI_FADT);
    g_assert_cmpmem(fadt, 4, "FACP", 4);
    g_assert_cmphex(load_le32(fadt + 4), ==, 244);
    g_assert_cmpuint(fadt[8], ==, 3);
    g_assert_cmphex(byte_sum(fadt, 244), ==, 0);
    g_assert_cmphex(load_le32(fadt + 36), ==, VIBTANIUM_EFI_ACPI_FACS);
    g_assert_cmphex(load_le32(fadt + 40), ==, VIBTANIUM_EFI_ACPI_DSDT);
    g_assert_cmphex(load_le64(fadt + 132), ==, VIBTANIUM_EFI_ACPI_FACS);
    g_assert_cmphex(load_le64(fadt + 140), ==, VIBTANIUM_EFI_ACPI_DSDT);

    dsdt = firmware_ptr(blob, VIBTANIUM_EFI_ACPI_DSDT);
    g_assert_cmpmem(dsdt, 4, "DSDT", 4);
    g_assert_cmphex(load_le32(dsdt + 4), ==, 94);
    g_assert_cmphex(byte_sum(dsdt, 94), ==, 0);
    g_assert_cmpmem(dsdt + 45, 4, "COM1", 4);
    g_assert_cmpmem(dsdt + 50, 4, "_HID", 4);
    g_assert_cmphex(dsdt[54], ==, 0x0c);
    g_assert_cmphex(dsdt[55], ==, 0x41);
    g_assert_cmphex(dsdt[56], ==, 0xd0);
    g_assert_cmphex(dsdt[57], ==, 0x05);
    g_assert_cmphex(dsdt[58], ==, 0x01);
    g_assert_cmpmem(dsdt + 81, 8, "\x47\x01\xf8\x03\xf8\x03\x00\x08", 8);
    g_assert_cmpmem(dsdt + 89, 3, "\x22\x10\x00", 3);

    madt = firmware_ptr(blob, VIBTANIUM_EFI_ACPI_MADT);
    g_assert_cmpmem(madt, 4, "APIC", 4);
    g_assert_cmphex(load_le32(madt + 4), ==, 76);
    g_assert_cmphex(byte_sum(madt, 76), ==, 0);
    g_assert_cmphex(load_le32(madt + 36), ==, 0xfee00000);
    g_assert_cmpuint(madt[44], ==, 7);
    g_assert_cmpuint(madt[45], ==, 16);
    g_assert_cmphex(load_le32(madt + 52), ==, 1);
    g_assert_cmpuint(madt[60], ==, 6);
    g_assert_cmpuint(madt[61], ==, 16);
    g_assert_cmphex(load_le32(madt + 64), ==, 0);
    g_assert_cmphex(load_le64(madt + 68), ==, 0xfec00000);

    facs = firmware_ptr(blob, VIBTANIUM_EFI_ACPI_FACS);
    g_assert_cmpmem(facs, 4, "FACS", 4);
    g_assert_cmphex(load_le32(facs + 4), ==, 64);
    g_assert_cmpuint(facs[32], ==, 2);

    sal_table = firmware_ptr(blob, VIBTANIUM_EFI_SAL_SYSTEM_TABLE);
    g_assert_cmphex(load_le32(sal_table), ==, 0x5f545353);
    g_assert_cmphex(load_le32(sal_table + 4), ==, 144);
    g_assert_cmpuint(sal_table[8], ==, 1);
    g_assert_cmpuint(sal_table[9], ==, 0);
    g_assert_cmpuint(sal_table[10] | (sal_table[11] << 8), ==, 1);
    g_assert_cmphex(byte_sum(sal_table, 144), ==, 0);
    sal_entry = sal_table + 96;
    g_assert_cmpuint(sal_entry[0], ==, 0);
    g_assert_cmphex(load_le64(sal_entry + 8), ==, VIBTANIUM_EFI_PAL_PROC);
    g_assert_cmphex(load_le64(sal_entry + 16), ==, VIBTANIUM_EFI_SAL_PROC);
    g_assert_cmphex(load_le64(sal_entry + 24), ==, VIBTANIUM_EFI_SAL_GP);
    g_assert_cmphex(firmware_ptr(blob, VIBTANIUM_EFI_PAL_PROC)[0], !=, 0);
    g_assert_cmphex(firmware_ptr(blob, VIBTANIUM_EFI_SAL_PROC)[0], !=, 0);
    g_assert_cmpint(memcmp(firmware_ptr(blob, VIBTANIUM_EFI_PAL_PROC),
                           firmware_ptr(blob, VIBTANIUM_EFI_SAL_PROC), 16),
                    ==, 0);
    g_assert_cmpint(memcmp(firmware_ptr(blob, VIBTANIUM_EFI_PAL_PROC),
                           firmware_ptr(blob, handle_protocol_gate), 16),
                    !=, 0);
    g_assert_cmphex(load_le64(firmware_ptr(blob, VIBTANIUM_EFI_SAL_GP)),
                    ==, 0);

    hcdp_table = firmware_ptr(blob, VIBTANIUM_EFI_HCDP_TABLE);
    g_assert_cmpmem(hcdp_table, 4, "HCDP", 4);
    g_assert_cmphex(load_le32(hcdp_table + 4), ==, 88);
    g_assert_cmpuint(hcdp_table[8], ==, 3);
    g_assert_cmphex(byte_sum(hcdp_table, 88), ==, 0);
    g_assert_cmphex(load_le32(hcdp_table + 36), ==, 1);
    hcdp_uart = hcdp_table + 40;
    g_assert_cmpuint(hcdp_uart[0], ==, 0);
    g_assert_cmpuint(hcdp_uart[1], ==, 8);
    g_assert_cmphex(load_le64(hcdp_uart + 8), ==, 115200);
    g_assert_cmpuint(hcdp_uart[16], ==, 1);
    g_assert_cmphex(load_le64(hcdp_uart + 20), ==, 0x3f8);
    g_assert_cmphex(hcdp_uart[41], ==, 1 << 2);

    block_io_base = VIBTANIUM_EFI_BOOT_SERVICE_COUNT +
                    VIBTANIUM_EFI_RUNTIME_SERVICE_COUNT +
                    VIBTANIUM_EFI_CON_OUT_SERVICE_COUNT +
                    VIBTANIUM_EFI_CON_IN_SERVICE_COUNT;
    simplefs_base = block_io_base + VIBTANIUM_EFI_BLOCK_IO_SERVICE_COUNT;

    g_assert_cmphex(load_le64(firmware_ptr(blob, VIBTANIUM_EFI_BLOCK_IO)),
                    ==, VIBTANIUM_EFI_PROTOCOL_REVISION);
    g_assert_cmphex(load_le64(firmware_ptr(blob, VIBTANIUM_EFI_BLOCK_IO + 8)),
                    ==, VIBTANIUM_EFI_BLOCK_IO_MEDIA);
    g_assert_cmphex(load_le64(firmware_ptr(blob, VIBTANIUM_EFI_BLOCK_IO + 24)),
                    ==, VIBTANIUM_EFI_DESCRIPTOR_BASE +
                    (block_io_base + 1) * 16);
    g_assert_cmpuint(load_le32(firmware_ptr(blob,
                                            VIBTANIUM_EFI_BLOCK_IO_MEDIA + 12)),
                     ==, 2048);
    g_assert_cmphex(load_le64(firmware_ptr(blob,
                                           VIBTANIUM_EFI_BLOCK_IO_MEDIA + 24)),
                    ==, 9);

    g_assert_cmphex(load_le64(firmware_ptr(
                         blob, VIBTANIUM_EFI_SIMPLE_FILE_SYSTEM)),
                    ==, VIBTANIUM_EFI_PROTOCOL_REVISION);
    g_assert_cmphex(load_le64(firmware_ptr(
                         blob, VIBTANIUM_EFI_SIMPLE_FILE_SYSTEM + 8)),
                    ==, VIBTANIUM_EFI_DESCRIPTOR_BASE + simplefs_base * 16);

    g_free(blob);
}

static void test_relocates_ia64_entry_descriptor(void)
{
    uint8_t pe[SYNTHETIC_PE_SIZE];
    VibtaniumEfiImage image;
    Error *err = NULL;

    make_synthetic_ia64_pe(pe, VIBTANIUM_EFI_PE_MACHINE_IA64, 0, true);

    g_assert_true(vibtanium_efi_image_from_buffer("synthetic-reloc.efi", pe,
                                                 sizeof(pe),
                                                 VIBTANIUM_EFI_APP_BASE,
                                                 &image, &err));
    g_assert_null(err);
    g_assert_cmphex(image.preferred_image_base, ==, 0);
    g_assert_cmphex(image.entry_descriptor, ==,
                    VIBTANIUM_EFI_APP_BASE + SYNTHETIC_DESCRIPTOR_RVA);
    g_assert_cmphex(image.entry, ==,
                    VIBTANIUM_EFI_APP_BASE + SYNTHETIC_TEXT_RVA);
    g_assert_cmphex(image.global_pointer, ==,
                    VIBTANIUM_EFI_APP_BASE + SYNTHETIC_GP_RVA);

    vibtanium_efi_image_destroy(&image);
}

static void test_unimplemented_service_log(void)
{
    VibtaniumEfiServiceCall call;
    uint64_t args[] = { 0x1111, 0x2222, 0x3333 };

    g_assert_cmphex(vibtanium_efi_record_unimplemented_service(
                        &call, VIBTANIUM_EFI_SERVICE_OUTPUT_STRING,
                        0x4444, args, G_N_ELEMENTS(args)),
                    ==, VIBTANIUM_EFI_UNSUPPORTED);

    g_assert_cmpstr(call.service_name, ==,
                    "SimpleTextOutput.OutputString");
    g_assert_nonnull(strstr(call.message,
                            "service=SimpleTextOutput.OutputString"));
    g_assert_nonnull(strstr(call.message, "ip=0x0000000000004444"));
    g_assert_nonnull(strstr(call.message, "0x0000000000001111"));
    g_assert_nonnull(strstr(call.message,
                            "status=unsupported(0x8000000000000003)"));
}

static void test_frontier_log_format(void)
{
    char message[384];

    vibtanium_efi_format_frontier(message, sizeof(message),
                                  VIBTANIUM_EFI_FRONTIER_KERNEL_ENTRY,
                                  0x1043ad0, "none-observed",
                                  "blocked before ELILO");

    g_assert_nonnull(strstr(message, "kind=kernel-entry"));
    g_assert_nonnull(strstr(message, "ip=0x0000000001043ad0"));
    g_assert_nonnull(strstr(message, "state=none-observed"));
    g_assert_nonnull(strstr(message, "blocked before ELILO"));
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/ia64-efi-app/load-synthetic-ia64-pe",
                    test_loads_synthetic_ia64_pe);
    g_test_add_func("/ia64-efi-app/reject-non-ia64-pe",
                    test_rejects_non_ia64_pe);
    g_test_add_func("/ia64-efi-app/prepare-cpu-entry-abi",
                    test_prepare_cpu_entry_abi);
    g_test_add_func("/ia64-efi-app/build-guest-firmware-tables",
                    test_builds_guest_firmware_tables);
    g_test_add_func("/ia64-efi-app/relocate-entry-descriptor",
                    test_relocates_ia64_entry_descriptor);
    g_test_add_func("/ia64-efi-app/unimplemented-service-log",
                    test_unimplemented_service_log);
    g_test_add_func("/ia64-efi-app/frontier-log-format",
                    test_frontier_log_format);

    return g_test_run();
}
