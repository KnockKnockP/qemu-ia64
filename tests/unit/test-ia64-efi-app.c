/*
 * IA-64 synthetic EFI app launch tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/ia64/efi.h"
#include "hw/ia64/efi-storage.h"
#include "hw/ia64/vibtanium.h"
#include "target/ia64/insn.h"

#define SYNTHETIC_PE_SIZE 0x400
#define SYNTHETIC_PE_OFFSET 0x80
#define SYNTHETIC_OPT_SIZE 0xf0
#define SYNTHETIC_SECTION_OFFSET \
    (SYNTHETIC_PE_OFFSET + 4 + 20 + SYNTHETIC_OPT_SIZE)
#define SYNTHETIC_RAW_OFFSET 0x200
#define SYNTHETIC_TEXT_RVA 0x1000
#define SYNTHETIC_DESCRIPTOR_RVA 0x1100
#define SYNTHETIC_MOVL_RVA 0x1120
#define SYNTHETIC_RELOC_RVA 0x1180
#define SYNTHETIC_IMAGE_SIZE 0x2000
#define SYNTHETIC_GP_RVA 0x1800
#define SYNTHETIC_MOVL_TARGET 36
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

static uint16_t load_le16(const uint8_t *p)
{
    return p[0] | ((uint16_t)p[1] << 8);
}

static void store_ia64_bundle(uint8_t *p, uint8_t tmpl,
                              uint64_t slot0, uint64_t slot1,
                              uint64_t slot2)
{
    unsigned __int128 raw = (tmpl & 0x1f) |
        ((unsigned __int128)(slot0 & IA64_SLOT_MASK) << 5) |
        ((unsigned __int128)(slot1 & IA64_SLOT_MASK) << 46) |
        ((unsigned __int128)(slot2 & IA64_SLOT_MASK) << 87);

    for (int i = 0; i < IA64_BUNDLE_SIZE; i++) {
        p[i] = raw >> (i * 8);
    }
}

static void make_lx_movl(uint64_t value, uint8_t target,
                         uint64_t *l_raw, uint64_t *x_raw)
{
    *l_raw = (value >> 22) & IA64_SLOT_MASK;
    *x_raw = (6ULL << 37) | ((uint64_t)target << 6) |
             ((value & 0x7fULL) << 13) |
             (((value >> 21) & 0x1ULL) << 21) |
             (((value >> 16) & 0x1fULL) << 22) |
             (((value >> 7) & 0x1ffULL) << 27) |
             (((value >> 63) & 0x1ULL) << 36);
}

static uint8_t byte_sum(const uint8_t *p, size_t size)
{
    uint32_t sum = 0;

    for (size_t i = 0; i < size; i++) {
        sum = (sum + p[i]) & 0xff;
    }
    return sum;
}

static bool bytes_contain(const uint8_t *haystack, size_t haystack_size,
                          const void *needle, size_t needle_size)
{
    if (needle_size > haystack_size) {
        return false;
    }
    for (size_t i = 0; i <= haystack_size - needle_size; i++) {
        if (memcmp(haystack + i, needle, needle_size) == 0) {
            return true;
        }
    }
    return false;
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

static const uint8_t efi_acpi_table_guid[16] = {
    0x30, 0x2d, 0x9d, 0xeb, 0x88, 0x2d, 0xd3, 0x11,
    0x9a, 0x16, 0x00, 0x90, 0x27, 0x3f, 0xc1, 0x4d,
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

static void make_synthetic_ia64_pe_with_movl_reloc(uint8_t *pe)
{
    uint8_t *optional;
    uint8_t *movl;
    uint8_t *reloc;
    uint64_t l_raw;
    uint64_t x_raw;

    make_synthetic_ia64_pe(pe, VIBTANIUM_EFI_PE_MACHINE_IA64, 0, true);

    optional = pe + SYNTHETIC_PE_OFFSET + 4 + 20;
    store_le32(optional + 112 + 5 * 8 + 4, 20);

    movl = pe + SYNTHETIC_RAW_OFFSET +
           (SYNTHETIC_MOVL_RVA - SYNTHETIC_TEXT_RVA);
    make_lx_movl(SYNTHETIC_GP_RVA, SYNTHETIC_MOVL_TARGET,
                 &l_raw, &x_raw);
    store_ia64_bundle(movl, 0x04, IA64_INSN_NOP_RAW, l_raw, x_raw);

    reloc = pe + SYNTHETIC_RAW_OFFSET +
            (SYNTHETIC_RELOC_RVA - SYNTHETIC_TEXT_RVA);
    store_le32(reloc + 4, 20);
    store_le16(reloc + 12,
               (9 << 12) |
               (SYNTHETIC_MOVL_RVA + 1 - SYNTHETIC_TEXT_RVA));
    store_le16(reloc + 14, 0);
    store_le16(reloc + 16, 0);
    store_le16(reloc + 18, 0);
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
    g_assert_true(vibtanium_efi_cpu_is_pristine_for_handoff(&env));
    g_assert_true(vibtanium_efi_prepare_cpu(&env, &image));
    g_assert_false(vibtanium_efi_cpu_is_pristine_for_handoff(&env));

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
    g_assert_cmphex(env.ar[IA64_AR_KR0], ==, VIBTANIUM_IO_PORT_BASE);
    g_assert_cmphex(env.gr[0], ==, 0);

    vibtanium_efi_image_destroy(&image);
}

static void test_prepare_cpu_preserves_restored_state(void)
{
    const uint64_t live_ip = UINT64_C(0xa000000100012ba0);
    const uint64_t live_iva = UINT64_C(0xa000000100000000);
    const uint64_t live_gp = UINT64_C(0xa000000100bd2000);
    const uint64_t live_sp = UINT64_C(0xa000000100bc7d80);
    const uint64_t live_tp = UINT64_C(0xe00000000a818000);
    const uint64_t live_bsp = UINT64_C(0xa000000100bc0f18);
    const uint64_t live_bspstore = UINT64_C(0xa000000100bc0ed8);
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
    env.ip = live_ip;
    env.cr[IA64_CR_IIP] = live_ip;
    env.cr[IA64_CR_IVA] = live_iva;
    ia64_write_gr(&env, 1, live_gp);
    ia64_write_gr(&env, 12, live_sp);
    ia64_write_gr(&env, 13, live_tp);
    env.rse.bsp = live_bsp;
    env.rse.bspstore = live_bspstore;
    env.rse.bsp_load = live_bspstore;
    env.ar[IA64_AR_BSP] = live_bsp;
    env.ar[IA64_AR_BSPSTORE] = live_bspstore;
    env.ar[IA64_AR_KR0] = UINT64_C(0xfeedface);
    ia64_set_cfm(&env, ia64_make_cfm(43, 21, 5));

    g_assert_false(vibtanium_efi_cpu_is_pristine_for_handoff(&env));
    g_assert_false(vibtanium_efi_prepare_cpu(&env, &image));
    g_assert_cmphex(env.ip, ==, live_ip);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, live_ip);
    g_assert_cmphex(env.cr[IA64_CR_IVA], ==, live_iva);
    g_assert_cmphex(env.gr[1], ==, live_gp);
    g_assert_cmphex(ia64_read_gr(&env, 12), ==, live_sp);
    g_assert_cmphex(ia64_read_gr(&env, 13), ==, live_tp);
    g_assert_cmphex(env.rse.bsp, ==, live_bsp);
    g_assert_cmphex(env.rse.bspstore, ==, live_bspstore);
    g_assert_cmphex(env.ar[IA64_AR_BSP], ==, live_bsp);
    g_assert_cmphex(env.ar[IA64_AR_BSPSTORE], ==, live_bspstore);
    g_assert_cmphex(env.ar[IA64_AR_KR0], ==, UINT64_C(0xfeedface));
    g_assert_cmphex(env.cfm, ==, ia64_make_cfm(43, 21, 5));

    vibtanium_efi_image_destroy(&image);
}

static void test_builds_guest_firmware_tables(void)
{
    uint8_t load_options[] = { 0x45, 0x00, 0x46, 0x00, 0x00, 0x00 };
    VibtaniumEfiImage image = {
        .load_base = VIBTANIUM_EFI_APP_BASE,
        .size = 0x123450,
        .load_options = load_options,
        .load_options_size = sizeof(load_options),
        .efi_file_path = "/efi/boot/bootia64.efi",
    };
    VibtaniumEfiBlockDevice boot_media = {
        .size = 2048 * 10,
        .block_size = 2048,
        .read_only = true,
        .removable = true,
        .cdrom = true,
    };
    const uint8_t expected_device_path[] = {
        0x01, 0x01, 0x06, 0x00, 0x00, 0x01,
        0x03, 0x01, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x04, 0x02, 0x18, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x7f, 0xff, 0x04, 0x00,
    };
    size_t blob_size = 0;
    uint8_t sal_gate[VIBTANIUM_EFI_GATE_SIZE];
    uint8_t *blob = vibtanium_efi_build_firmware_blob(&blob_size, &image,
                                                      &boot_media, NULL);
    uint64_t boot_services;
    uint64_t runtime_services;
    uint64_t get_time_descriptor;
    uint64_t get_time_gate;
    uint64_t set_virtual_address_map_descriptor;
    uint64_t handle_protocol_descriptor;
    uint64_t handle_protocol_gate;
    const uint8_t *config_entry;
    const uint8_t *acpi20_config_entry;
    const uint8_t *sal_config_entry;
    const uint8_t *sal_table;
    const uint8_t *sal_entry;
    const uint8_t *rsdp;
    const uint8_t *rsdt;
    const uint8_t *xsdt;
    const uint8_t *fadt;
    const uint8_t *dsdt;
    const uint8_t *madt;
    const uint8_t *dbgp;
    const uint8_t *facs;
    const uint8_t *loaded_image_file_path;
    uint64_t rsdp_addr;
    uint64_t sal_table_addr;
    uint64_t rsdt_addr;
    uint64_t xsdt_addr;
    uint64_t fadt_addr;
    uint64_t dsdt_addr;
    uint64_t madt_addr;
    uint64_t dbgp_addr;
    uint64_t facs_addr;
    uint32_t dsdt_length;
    size_t loaded_image_file_path_chars;
    uint16_t loaded_image_file_path_length;
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
                    ==, VIBTANIUM_EFI_LOADED_IMAGE_FILE_PATH);
    g_assert_cmpmem(firmware_ptr(blob, VIBTANIUM_EFI_DEVICE_PATH),
                    sizeof(expected_device_path),
                    expected_device_path, sizeof(expected_device_path));
    loaded_image_file_path = firmware_ptr(
        blob, VIBTANIUM_EFI_LOADED_IMAGE_FILE_PATH);
    loaded_image_file_path_chars = strlen(image.efi_file_path);
    loaded_image_file_path_length = 4 + (loaded_image_file_path_chars + 1) * 2;
    g_assert_cmphex(loaded_image_file_path[0], ==, 0x04);
    g_assert_cmphex(loaded_image_file_path[1], ==, 0x04);
    g_assert_cmphex(load_le16(loaded_image_file_path + 2), ==,
                    loaded_image_file_path_length);
    for (size_t i = 0; i < loaded_image_file_path_chars; i++) {
        uint16_t expected_ch =
            image.efi_file_path[i] == '/' ? '\\' : image.efi_file_path[i];

        g_assert_cmphex(load_le16(loaded_image_file_path + 4 + i * 2), ==,
                        expected_ch);
    }
    g_assert_cmphex(load_le16(loaded_image_file_path + 4 +
                              loaded_image_file_path_chars * 2),
                    ==, 0);
    g_assert_cmphex(loaded_image_file_path[loaded_image_file_path_length],
                    ==, 0x7f);
    g_assert_cmphex(loaded_image_file_path[loaded_image_file_path_length + 1],
                    ==, 0xff);
    g_assert_cmphex(load_le16(loaded_image_file_path +
                              loaded_image_file_path_length + 2),
                    ==, 0x04);
    g_assert_cmphex(load_le32(firmware_ptr(blob,
                                           VIBTANIUM_EFI_LOADED_IMAGE + 48)),
                    ==, sizeof(load_options));
    g_assert_cmphex(load_le64(firmware_ptr(blob,
                                           VIBTANIUM_EFI_LOADED_IMAGE + 56)),
                    ==, VIBTANIUM_EFI_LOAD_OPTIONS);
    g_assert_cmpmem(firmware_ptr(blob, VIBTANIUM_EFI_LOAD_OPTIONS),
                    sizeof(load_options), load_options,
                    sizeof(load_options));
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
    g_assert_cmpmem(config_entry, 16, efi_acpi_table_guid, 16);
    rsdp_addr = load_le64(config_entry + 16);
    g_assert_cmphex(rsdp_addr, ==, VIBTANIUM_EFI_ACPI_RSDP);
    acpi20_config_entry = config_entry + 24;
    g_assert_cmpmem(acpi20_config_entry, 16, efi_acpi20_table_guid, 16);
    g_assert_cmphex(load_le64(acpi20_config_entry + 16), ==, rsdp_addr);
    sal_config_entry = config_entry + 48;
    g_assert_cmpmem(sal_config_entry, 16, efi_sal_system_table_guid, 16);
    sal_table_addr = load_le64(sal_config_entry + 16);
    g_assert_cmphex(sal_table_addr, ==, VIBTANIUM_EFI_SAL_SYSTEM_TABLE);
    g_assert_false(bytes_contain(config_entry, 96,
                                 efi_hcdp_table_guid,
                                 sizeof(efi_hcdp_table_guid)));

    rsdp = firmware_ptr(blob, rsdp_addr);
    g_assert_cmpmem(rsdp, 8, "RSD PTR ", 8);
    g_assert_cmpuint(rsdp[15], ==, 2);
    rsdt_addr = load_le32(rsdp + 16);
    xsdt_addr = load_le64(rsdp + 24);
    g_assert_cmphex(load_le32(rsdp + 20), ==, 36);
    g_assert_cmphex(byte_sum(rsdp, 20), ==, 0);
    g_assert_cmphex(byte_sum(rsdp, 36), ==, 0);

    rsdt = firmware_ptr(blob, rsdt_addr);
    g_assert_cmpmem(rsdt, 4, "RSDT", 4);
    g_assert_cmphex(load_le32(rsdt + 4), ==, 48);
    g_assert_cmphex(byte_sum(rsdt, 48), ==, 0);
    fadt_addr = load_le32(rsdt + 36);
    madt_addr = load_le32(rsdt + 40);
    dbgp_addr = load_le32(rsdt + 44);

    xsdt = firmware_ptr(blob, xsdt_addr);
    g_assert_cmpmem(xsdt, 4, "XSDT", 4);
    g_assert_cmphex(load_le32(xsdt + 4), ==, 60);
    g_assert_cmphex(byte_sum(xsdt, 60), ==, 0);
    g_assert_cmphex(load_le64(xsdt + 36), ==, fadt_addr);
    g_assert_cmphex(load_le64(xsdt + 44), ==, madt_addr);
    g_assert_cmphex(load_le64(xsdt + 52), ==, dbgp_addr);

    fadt = firmware_ptr(blob, fadt_addr);
    g_assert_cmpmem(fadt, 4, "FACP", 4);
    g_assert_cmphex(load_le32(fadt + 4), ==, 244);
    g_assert_cmpuint(fadt[8], ==, 3);
    g_assert_cmphex(byte_sum(fadt, 244), ==, 0);
    facs_addr = load_le32(fadt + 36);
    dsdt_addr = load_le32(fadt + 40);
    g_assert_cmphex(load_le16(fadt + 46), ==, VIBTANIUM_ACPI_SCI_IRQ);
    g_assert_cmphex(load_le32(fadt + 56), ==, VIBTANIUM_ACPI_PM_BASE);
    g_assert_cmphex(load_le32(fadt + 64), ==,
                    VIBTANIUM_ACPI_PM_BASE + 4);
    g_assert_cmphex(load_le32(fadt + 76), ==,
                    VIBTANIUM_ACPI_PM_BASE + 8);
    g_assert_cmpuint(fadt[88], ==, 4);
    g_assert_cmpuint(fadt[89], ==, 2);
    g_assert_cmpuint(fadt[91], ==, 4);
    g_assert_cmphex(load_le64(fadt + 132), ==, facs_addr);
    g_assert_cmphex(load_le64(fadt + 140), ==, dsdt_addr);
    g_assert_cmpuint(fadt[148], ==, 1);
    g_assert_cmphex(load_le64(fadt + 152), ==, VIBTANIUM_ACPI_PM_BASE);
    g_assert_cmpuint(fadt[172], ==, 1);
    g_assert_cmphex(load_le64(fadt + 176), ==,
                    VIBTANIUM_ACPI_PM_BASE + 4);
    g_assert_cmpuint(fadt[208], ==, 1);
    g_assert_cmphex(load_le64(fadt + 212), ==,
                    VIBTANIUM_ACPI_PM_BASE + 8);

    dsdt = firmware_ptr(blob, dsdt_addr);
    dsdt_length = load_le32(dsdt + 4);
    g_assert_cmpmem(dsdt, 4, "DSDT", 4);
    g_assert_cmphex(dsdt_length, >=, 36);
    g_assert_cmphex(byte_sum(dsdt, dsdt_length), ==, 0);
    g_assert_true(bytes_contain(dsdt, dsdt_length, "COM1", 4));
    g_assert_true(bytes_contain(dsdt, dsdt_length, "KBD_", 4));
    g_assert_true(bytes_contain(dsdt, dsdt_length, "PCI0", 4));
    g_assert_true(bytes_contain(dsdt, dsdt_length,
                                "\x0c\x41\xd0\x05\x01", 5));
    g_assert_true(bytes_contain(dsdt, dsdt_length,
                                "\x0c\x41\xd0\x03\x03", 5));
    g_assert_true(bytes_contain(dsdt, dsdt_length,
                                "\x0c\x41\xd0\x0a\x03", 5));
    g_assert_true(bytes_contain(dsdt, dsdt_length,
                                "\x47\x01\xf8\x03\xf8\x03\x00\x08", 8));
    g_assert_true(bytes_contain(dsdt, dsdt_length,
                                "\x47\x01\x60\x00\x60\x00\x01\x01", 8));
    g_assert_true(bytes_contain(dsdt, dsdt_length,
                                "\x47\x01\x64\x00\x64\x00\x01\x01", 8));
    g_assert_true(bytes_contain(dsdt, dsdt_length,
                                "\x88\x0d\x00\x02\x0c\x00", 6));

    madt = firmware_ptr(blob, madt_addr);
    g_assert_cmpmem(madt, 4, "APIC", 4);
    g_assert_cmphex(load_le32(madt + 4), ==, 72);
    g_assert_cmphex(byte_sum(madt, 72), ==, 0);
    g_assert_cmphex(load_le32(madt + 36), ==, 0xfee00000);
    g_assert_cmpuint(madt[44], ==, 7);
    g_assert_cmpuint(madt[45], ==, 12);
    g_assert_cmphex(load_le32(madt + 52), ==, 1);
    g_assert_cmpuint(madt[56], ==, 6);
    g_assert_cmpuint(madt[57], ==, 16);
    g_assert_cmphex(load_le32(madt + 60), ==, 0);
    g_assert_cmphex(load_le64(madt + 64), ==, 0xfec00000);

    dbgp = firmware_ptr(blob, dbgp_addr);
    g_assert_cmpmem(dbgp, 4, "DBGP", 4);
    g_assert_cmphex(load_le32(dbgp + 4), ==, 52);
    g_assert_cmpuint(dbgp[8], ==, 1);
    g_assert_cmphex(byte_sum(dbgp, 52), ==, 0);
    g_assert_cmpuint(dbgp[36], ==, 0);
    g_assert_cmpuint(dbgp[40], ==, 1);
    g_assert_cmpuint(dbgp[41], ==, 8);
    g_assert_cmpuint(dbgp[42], ==, 0);
    g_assert_cmpuint(dbgp[43], ==, 1);
    g_assert_cmphex(load_le64(dbgp + 44), ==, VIBTANIUM_LEGACY_COM1_BASE);

    facs = firmware_ptr(blob, facs_addr);
    g_assert_cmpmem(facs, 4, "FACS", 4);
    g_assert_cmphex(load_le32(facs + 4), ==, 64);
    g_assert_cmpuint(facs[32], ==, 2);

    sal_table = firmware_ptr(blob, sal_table_addr);
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
    vibtanium_efi_build_branch_gate(sal_gate);
    g_assert_cmphex(sal_gate[0], !=, 0);
    g_assert_cmpint(memcmp(firmware_ptr(blob, VIBTANIUM_EFI_PAL_PROC),
                           sal_gate, sizeof(sal_gate)),
                    ==, 0);
    g_assert_cmpint(memcmp(firmware_ptr(blob, VIBTANIUM_EFI_PAL_PROC),
                           firmware_ptr(blob, handle_protocol_gate), 16),
                    !=, 0);
    g_assert_cmphex(VIBTANIUM_EFI_SAL_GP, ==,
                    VIBTANIUM_EFI_SAL_PROC + 0x1000);
    g_assert_cmphex(firmware_ptr(blob,
                                 VIBTANIUM_EFI_START_IMAGE_RETURN_GATE)[0],
                    !=, 0);
    g_assert_cmphex(firmware_ptr(blob,
                                 VIBTANIUM_EFI_EVENT_NOTIFY_RETURN_GATE)[0],
                    !=, 0);

    g_assert_cmphex(load_le32(firmware_ptr(blob, VIBTANIUM_EFI_HCDP_TABLE)),
                    ==, 0);

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

static void test_builds_hcdp_serial_console_table(void)
{
    VibtaniumEfiImage image = {
        .load_base = VIBTANIUM_EFI_APP_BASE,
        .size = 0x123450,
    };
    VibtaniumEfiFirmwareOptions options = {
        .hcdp_serial_console = true,
    };
    size_t blob_size = 0;
    uint8_t *blob = vibtanium_efi_build_firmware_blob(&blob_size, &image,
                                                      NULL, &options);
    const uint8_t *config_entry;
    const uint8_t *hcdp_config_entry;
    const uint8_t *hcdp_table;
    const uint8_t *hcdp_uart;
    uint64_t hcdp_table_addr;

    g_assert_cmpuint(blob_size, ==, VIBTANIUM_EFI_BLOB_SIZE);
    g_assert_cmphex(load_le64(firmware_ptr(
                         blob, VIBTANIUM_EFI_SYSTEM_TABLE + 104)),
                    ==, 4);

    config_entry = firmware_ptr(blob, VIBTANIUM_EFI_CONFIGURATION_TABLE);
    hcdp_config_entry = config_entry + 72;
    g_assert_cmpmem(hcdp_config_entry, 16, efi_hcdp_table_guid, 16);
    hcdp_table_addr = load_le64(hcdp_config_entry + 16);
    g_assert_cmphex(hcdp_table_addr, ==, VIBTANIUM_EFI_HCDP_TABLE);

    hcdp_table = firmware_ptr(blob, hcdp_table_addr);
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

static void test_runtime_driver_uses_runtime_memory(void)
{
    uint8_t pe[SYNTHETIC_PE_SIZE];
    uint8_t *optional;
    VibtaniumEfiImage image;
    Error *err = NULL;

    make_synthetic_ia64_pe(pe, VIBTANIUM_EFI_PE_MACHINE_IA64,
                           VIBTANIUM_EFI_APP_BASE, false);
    optional = pe + SYNTHETIC_PE_OFFSET + 4 + 20;
    store_le16(optional + 68, VIBTANIUM_EFI_SUBSYSTEM_RUNTIME_DRIVER);

    g_assert_true(vibtanium_efi_image_from_buffer(
        "runtime-driver.efi", pe, sizeof(pe), VIBTANIUM_EFI_APP_BASE,
        &image, &err));
    g_assert_null(err);
    g_assert_cmpuint(image.subsystem, ==,
                     VIBTANIUM_EFI_SUBSYSTEM_RUNTIME_DRIVER);
    g_assert_cmpuint(vibtanium_efi_loaded_image_memory_type(&image), ==,
                     VIBTANIUM_EFI_RUNTIME_SERVICES_CODE);
    image.subsystem = 10;
    g_assert_cmpuint(vibtanium_efi_loaded_image_memory_type(&image), ==,
                     VIBTANIUM_EFI_RESERVED_MEMORY_TYPE);

    vibtanium_efi_image_destroy(&image);
}

static void test_relocates_ia64_movl_imm64(void)
{
    uint8_t pe[SYNTHETIC_PE_SIZE];
    VibtaniumEfiImage image;
    IA64DecodedBundle decoded;
    Error *err = NULL;

    make_synthetic_ia64_pe_with_movl_reloc(pe);

    g_assert_true(vibtanium_efi_image_from_buffer("synthetic-movl.efi", pe,
                                                 sizeof(pe),
                                                 VIBTANIUM_EFI_APP_BASE,
                                                 &image, &err));
    g_assert_null(err);
    g_assert_true(ia64_decode_bundle(image.data + SYNTHETIC_MOVL_RVA,
                                     &decoded));
    g_assert_true(ia64_slot_pair_is_lx_movl(decoded.slot[1],
                                            decoded.slot[2]));
    g_assert_cmpuint((decoded.slot[2] >> 6) & 0x7f, ==,
                     SYNTHETIC_MOVL_TARGET);
    g_assert_cmphex(ia64_lx_movl_imm64(decoded.slot[1], decoded.slot[2]),
                    ==, VIBTANIUM_EFI_APP_BASE + SYNTHETIC_GP_RVA);

    vibtanium_efi_image_destroy(&image);
}

static void test_relocates_parsed_image_without_reparse(void)
{
    uint8_t pe[SYNTHETIC_PE_SIZE];
    VibtaniumEfiImage image;
    Error *err = NULL;

    make_synthetic_ia64_pe(pe, VIBTANIUM_EFI_PE_MACHINE_IA64, 0, true);
    g_assert_true(vibtanium_efi_image_from_buffer("synthetic-reloc.efi", pe,
                                                 sizeof(pe), 0,
                                                 &image, &err));
    g_assert_null(err);
    g_assert_cmphex(image.entry, ==, SYNTHETIC_TEXT_RVA);

    g_assert_true(vibtanium_efi_image_relocate(
        &image, VIBTANIUM_EFI_APP_BASE, &err));
    g_assert_null(err);
    g_assert_cmphex(image.entry_descriptor, ==,
                    VIBTANIUM_EFI_APP_BASE + SYNTHETIC_DESCRIPTOR_RVA);
    g_assert_cmphex(image.entry, ==,
                    VIBTANIUM_EFI_APP_BASE + SYNTHETIC_TEXT_RVA);
    g_assert_cmphex(image.global_pointer, ==,
                    VIBTANIUM_EFI_APP_BASE + SYNTHETIC_GP_RVA);

    vibtanium_efi_image_destroy(&image);
}

static void test_hot_relocates_unchanged_fixups(void)
{
    const uint64_t virtual_base = UINT64_C(0xe000000001000000);
    uint8_t pe[SYNTHETIC_PE_SIZE];
    g_autofree uint8_t *current = NULL;
    VibtaniumEfiImage image;
    Error *err = NULL;

    make_synthetic_ia64_pe(pe, VIBTANIUM_EFI_PE_MACHINE_IA64, 0, true);
    g_assert_true(vibtanium_efi_image_from_buffer(
        "synthetic-runtime.efi", pe, sizeof(pe), VIBTANIUM_EFI_APP_BASE,
        &image, &err));
    g_assert_null(err);
    current = g_memdup2(image.data, image.size);

    g_assert_true(vibtanium_efi_image_hot_relocate(
        &image, current, image.size, virtual_base, &err));
    g_assert_null(err);
    g_assert_cmphex(load_le64(current + SYNTHETIC_DESCRIPTOR_RVA), ==,
                    virtual_base + SYNTHETIC_TEXT_RVA);
    g_assert_cmphex(load_le64(current + SYNTHETIC_DESCRIPTOR_RVA + 8), ==,
                    virtual_base + SYNTHETIC_GP_RVA);
    g_assert_cmphex(image.entry, ==,
                    VIBTANIUM_EFI_APP_BASE + SYNTHETIC_TEXT_RVA);

    vibtanium_efi_image_destroy(&image);
}

static void test_hot_relocation_preserves_modified_fixup(void)
{
    const uint64_t virtual_base = UINT64_C(0xe000000001000000);
    const uint64_t callback_value = UINT64_C(0xe123456789abcdef);
    uint8_t pe[SYNTHETIC_PE_SIZE];
    g_autofree uint8_t *current = NULL;
    VibtaniumEfiImage image;
    Error *err = NULL;

    make_synthetic_ia64_pe(pe, VIBTANIUM_EFI_PE_MACHINE_IA64, 0, true);
    g_assert_true(vibtanium_efi_image_from_buffer(
        "synthetic-runtime.efi", pe, sizeof(pe), VIBTANIUM_EFI_APP_BASE,
        &image, &err));
    g_assert_null(err);
    current = g_memdup2(image.data, image.size);
    store_le64(current + SYNTHETIC_DESCRIPTOR_RVA, callback_value);

    g_assert_true(vibtanium_efi_image_hot_relocate(
        &image, current, image.size, virtual_base, &err));
    g_assert_null(err);
    g_assert_cmphex(load_le64(current + SYNTHETIC_DESCRIPTOR_RVA), ==,
                    callback_value);
    g_assert_cmphex(load_le64(current + SYNTHETIC_DESCRIPTOR_RVA + 8), ==,
                    virtual_base + SYNTHETIC_GP_RVA);

    vibtanium_efi_image_destroy(&image);
}

static void test_hot_relocates_ia64_movl(void)
{
    const uint64_t virtual_base = UINT64_C(0xe000000001000000);
    uint8_t pe[SYNTHETIC_PE_SIZE];
    g_autofree uint8_t *current = NULL;
    VibtaniumEfiImage image;
    IA64DecodedBundle decoded;
    Error *err = NULL;

    make_synthetic_ia64_pe_with_movl_reloc(pe);
    g_assert_true(vibtanium_efi_image_from_buffer(
        "synthetic-runtime-movl.efi", pe, sizeof(pe),
        VIBTANIUM_EFI_APP_BASE, &image, &err));
    g_assert_null(err);
    current = g_memdup2(image.data, image.size);

    g_assert_true(vibtanium_efi_image_hot_relocate(
        &image, current, image.size, virtual_base, &err));
    g_assert_null(err);
    g_assert_true(ia64_decode_bundle(current + SYNTHETIC_MOVL_RVA,
                                     &decoded));
    g_assert_true(ia64_slot_pair_is_lx_movl(decoded.slot[1],
                                            decoded.slot[2]));
    g_assert_cmphex(ia64_lx_movl_imm64(decoded.slot[1], decoded.slot[2]),
                    ==, virtual_base + SYNTHETIC_GP_RVA);

    vibtanium_efi_image_destroy(&image);
}

static void test_loads_fixed_ia64_pe_at_preferred_base(void)
{
    uint8_t pe[SYNTHETIC_PE_SIZE];
    VibtaniumEfiImage image;
    Error *err = NULL;

    make_synthetic_ia64_pe(pe, VIBTANIUM_EFI_PE_MACHINE_IA64, 0, false);

    g_assert_true(vibtanium_efi_image_from_buffer("synthetic-fixed.efi", pe,
                                                 sizeof(pe),
                                                 VIBTANIUM_EFI_APP_BASE,
                                                 &image, &err));
    g_assert_null(err);
    g_assert_cmphex(image.preferred_image_base, ==, 0);
    g_assert_cmphex(image.load_base, ==, 0);
    g_assert_cmphex(image.entry_descriptor, ==, SYNTHETIC_DESCRIPTOR_RVA);
    g_assert_cmphex(image.entry, ==, SYNTHETIC_TEXT_RVA);
    g_assert_cmphex(image.global_pointer, ==, SYNTHETIC_GP_RVA);
    g_assert_nonnull(strstr(image.message, "fixed-preferred-base"));

    vibtanium_efi_image_destroy(&image);
}

static void test_decodes_sign_extended_uint32_args(void)
{
    uint32_t value = 0;

    g_assert_true(vibtanium_efi_decode_uint32_arg(0, &value));
    g_assert_cmphex(value, ==, 0);
    g_assert_true(vibtanium_efi_decode_uint32_arg(UINT64_C(0x80000000),
                                                 &value));
    g_assert_cmphex(value, ==, 0x80000000);
    g_assert_true(vibtanium_efi_decode_uint32_arg(UINT64_C(0xffffffff80000000),
                                                 &value));
    g_assert_cmphex(value, ==, 0x80000000);
    g_assert_true(vibtanium_efi_decode_uint32_arg(UINT64_MAX, &value));
    g_assert_cmphex(value, ==, 0xffffffff);
    g_assert_false(vibtanium_efi_decode_uint32_arg(UINT64_C(0x100000000),
                                                  &value));
}

static void test_exact_loader_pages_are_reserved(void)
{
    g_assert_cmpuint(vibtanium_efi_page_allocation_memory_type(
                         VIBTANIUM_EFI_ALLOCATE_ADDRESS,
                         VIBTANIUM_EFI_LOADER_DATA),
                     ==, VIBTANIUM_EFI_RESERVED_MEMORY_TYPE);
    g_assert_cmpuint(vibtanium_efi_page_allocation_memory_type(
                         VIBTANIUM_EFI_ALLOCATE_ADDRESS,
                         VIBTANIUM_EFI_LOADER_CODE),
                     ==, VIBTANIUM_EFI_RESERVED_MEMORY_TYPE);
    g_assert_cmpuint(vibtanium_efi_page_allocation_memory_type(
                         VIBTANIUM_EFI_ALLOCATE_ANY_PAGES,
                         VIBTANIUM_EFI_LOADER_DATA),
                     ==, VIBTANIUM_EFI_LOADER_DATA);
}

static void test_pal_code_has_efi_memory_descriptor(void)
{
    uint32_t type = 0;
    uint64_t address = 0;
    uint64_t pages = 0;
    uint64_t attributes = 0;

    vibtanium_efi_pal_code_memory_descriptor(&type, &address, &pages,
                                              &attributes);

    g_assert_cmpuint(type, ==, VIBTANIUM_EFI_PAL_CODE);
    g_assert_cmphex(address, ==, VIBTANIUM_EFI_PAL_PROC);
    g_assert_cmphex(address & 0xfff, ==, 0);
    g_assert_cmphex(pages, ==, 1);
    g_assert_cmphex(attributes, ==, VIBTANIUM_EFI_MEMORY_WB);
    g_assert_cmphex(address, >=, VIBTANIUM_EFI_BLOB_BASE);
    g_assert_cmphex(address + pages * 0x1000, <=,
                    VIBTANIUM_EFI_BLOB_BASE + VIBTANIUM_EFI_BLOB_SIZE);
}

static void assert_runtime_code_memory_descriptor(uint64_t code_address)
{
    uint32_t type = 0;
    uint64_t address = 0;
    uint64_t pages = 0;
    uint64_t attributes = 0;

    vibtanium_efi_runtime_code_memory_descriptor(
        code_address, &type, &address, &pages, &attributes);

    g_assert_cmpuint(type, ==, VIBTANIUM_EFI_RUNTIME_SERVICES_CODE);
    g_assert_cmphex(address, ==, code_address);
    g_assert_cmphex(address & 0xfff, ==, 0);
    g_assert_cmphex(pages, ==, 1);
    g_assert_cmphex(attributes, ==,
                    VIBTANIUM_EFI_MEMORY_WB |
                    VIBTANIUM_EFI_MEMORY_RUNTIME);
}

static void test_firmware_code_has_efi_memory_descriptors(void)
{
    assert_runtime_code_memory_descriptor(VIBTANIUM_EFI_CALL_GATE_BASE);
    assert_runtime_code_memory_descriptor(VIBTANIUM_EFI_SAL_PROC);
    g_assert_cmphex(VIBTANIUM_EFI_SAL_GP & ~UINT64_C(0xfff), !=,
                    VIBTANIUM_EFI_SAL_PROC);
}

static void test_timer_deadline_wraps(void)
{
    g_assert_true(vibtanium_efi_timer_due(100, 100));
    g_assert_true(vibtanium_efi_timer_due(101, 100));
    g_assert_false(vibtanium_efi_timer_due(99, 100));

    g_assert_true(vibtanium_efi_timer_due(0, UINT64_MAX));
    g_assert_false(vibtanium_efi_timer_due(UINT64_MAX, 0));
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
    g_test_add_func("/ia64-efi-app/runtime-driver-uses-runtime-memory",
                    test_runtime_driver_uses_runtime_memory);
    g_test_add_func("/ia64-efi-app/reject-non-ia64-pe",
                    test_rejects_non_ia64_pe);
    g_test_add_func("/ia64-efi-app/prepare-cpu-entry-abi",
                    test_prepare_cpu_entry_abi);
    g_test_add_func("/ia64-efi-app/prepare-cpu-preserves-restored-state",
                    test_prepare_cpu_preserves_restored_state);
    g_test_add_func("/ia64-efi-app/build-guest-firmware-tables",
                    test_builds_guest_firmware_tables);
    g_test_add_func("/ia64-efi-app/build-hcdp-serial-console-table",
                    test_builds_hcdp_serial_console_table);
    g_test_add_func("/ia64-efi-app/relocate-entry-descriptor",
                    test_relocates_ia64_entry_descriptor);
    g_test_add_func("/ia64-efi-app/relocate-ia64-movl-imm64",
                    test_relocates_ia64_movl_imm64);
    g_test_add_func("/ia64-efi-app/relocate-parsed-image",
                    test_relocates_parsed_image_without_reparse);
    g_test_add_func("/ia64-efi-app/hot-relocate-unchanged-fixups",
                    test_hot_relocates_unchanged_fixups);
    g_test_add_func("/ia64-efi-app/hot-relocate-preserves-modified-fixup",
                    test_hot_relocation_preserves_modified_fixup);
    g_test_add_func("/ia64-efi-app/hot-relocate-ia64-movl",
                    test_hot_relocates_ia64_movl);
    g_test_add_func("/ia64-efi-app/load-fixed-at-preferred-base",
                    test_loads_fixed_ia64_pe_at_preferred_base);
    g_test_add_func("/ia64-efi-app/decode-sign-extended-uint32-args",
                    test_decodes_sign_extended_uint32_args);
    g_test_add_func("/ia64-efi-app/exact-loader-pages-are-reserved",
                    test_exact_loader_pages_are_reserved);
    g_test_add_func("/ia64-efi-app/pal-code-has-efi-memory-descriptor",
                    test_pal_code_has_efi_memory_descriptor);
    g_test_add_func("/ia64-efi-app/firmware-code-has-efi-memory-descriptors",
                    test_firmware_code_has_efi_memory_descriptors);
    g_test_add_func("/ia64-efi-app/timer-deadline-wraps",
                    test_timer_deadline_wraps);
    g_test_add_func("/ia64-efi-app/unimplemented-service-log",
                    test_unimplemented_service_log);
    g_test_add_func("/ia64-efi-app/frontier-log-format",
                    test_frontier_log_format);

    return g_test_run();
}
