/*
 * IA-64 synthetic EFI app launch tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/ia64/efi.h"
#include "target/ia64/exec-smoke.h"

#define SYNTHETIC_PE_SIZE 0x400
#define SYNTHETIC_PE_OFFSET 0x80
#define SYNTHETIC_OPT_SIZE 0xf0
#define SYNTHETIC_SECTION_OFFSET \
    (SYNTHETIC_PE_OFFSET + 4 + 20 + SYNTHETIC_OPT_SIZE)
#define SYNTHETIC_RAW_OFFSET 0x200
#define SYNTHETIC_TEXT_RVA 0x1000
#define SYNTHETIC_IMAGE_SIZE 0x2000

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

static void make_synthetic_ia64_pe(uint8_t *pe, uint16_t machine)
{
    uint8_t *coff;
    uint8_t *optional;
    uint8_t *section;

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
    store_le32(optional + 16, SYNTHETIC_TEXT_RVA);
    store_le64(optional + 24, VIBATNIUM_EFI_APP_BASE);
    store_le32(optional + 32, 0x1000);
    store_le32(optional + 36, 0x200);
    store_le32(optional + 56, SYNTHETIC_IMAGE_SIZE);
    store_le32(optional + 60, 0x200);

    section = pe + SYNTHETIC_SECTION_OFFSET;
    memcpy(section, ".text", 5);
    store_le32(section + 8, 0x20);
    store_le32(section + 12, SYNTHETIC_TEXT_RVA);
    store_le32(section + 16, 0x200);
    store_le32(section + 20, SYNTHETIC_RAW_OFFSET);

    pe[SYNTHETIC_RAW_OFFSET] = 0x55;
    pe[SYNTHETIC_RAW_OFFSET + 1] = 0xaa;
}

static void test_loads_synthetic_ia64_pe(void)
{
    uint8_t pe[SYNTHETIC_PE_SIZE];
    VibatniumEfiImage image;
    Error *err = NULL;

    make_synthetic_ia64_pe(pe, VIBATNIUM_EFI_PE_MACHINE_IA64);

    g_assert_true(vibatnium_efi_image_from_buffer("synthetic.efi", pe,
                                                 sizeof(pe),
                                                 VIBATNIUM_EFI_APP_BASE,
                                                 &image, &err));
    g_assert_null(err);
    g_assert_cmphex(image.load_base, ==, VIBATNIUM_EFI_APP_BASE);
    g_assert_cmphex(image.entry, ==,
                    VIBATNIUM_EFI_APP_BASE + SYNTHETIC_TEXT_RVA);
    g_assert_cmpuint(image.size, ==, SYNTHETIC_IMAGE_SIZE);
    g_assert_cmphex(image.data[SYNTHETIC_TEXT_RVA], ==, 0x55);
    g_assert_cmphex(image.data[SYNTHETIC_TEXT_RVA + 1], ==, 0xaa);
    g_assert_nonnull(strstr(image.message, "loaded IA-64 EFI image"));

    vibatnium_efi_image_destroy(&image);
}

static void test_rejects_non_ia64_pe(void)
{
    uint8_t pe[SYNTHETIC_PE_SIZE];
    VibatniumEfiImage image;
    Error *err = NULL;

    make_synthetic_ia64_pe(pe, 0x8664);

    g_assert_false(vibatnium_efi_image_from_buffer("x64.efi", pe, sizeof(pe),
                                                  VIBATNIUM_EFI_APP_BASE,
                                                  &image, &err));
    g_assert_nonnull(err);
    g_assert_nonnull(strstr(error_get_pretty(err), "not IA-64"));
    error_free(err);
}

static void test_prepare_cpu_entry_abi(void)
{
    uint8_t pe[SYNTHETIC_PE_SIZE];
    VibatniumEfiImage image;
    CPUIA64State env;
    Error *err = NULL;

    make_synthetic_ia64_pe(pe, VIBATNIUM_EFI_PE_MACHINE_IA64);
    g_assert_true(vibatnium_efi_image_from_buffer("synthetic.efi", pe,
                                                 sizeof(pe),
                                                 VIBATNIUM_EFI_APP_BASE,
                                                 &image, &err));
    g_assert_null(err);

    ia64_cpu_reset_synthetic_itanium2(&env);
    vibatnium_efi_prepare_cpu(&env, &image);

    g_assert_cmphex(env.ip, ==,
                    VIBATNIUM_EFI_APP_BASE + SYNTHETIC_TEXT_RVA);
    g_assert_cmphex(env.cr[IA64_CR_IIP], ==, env.ip);
    g_assert_cmphex(env.gr[32], ==, VIBATNIUM_EFI_IMAGE_HANDLE);
    g_assert_cmphex(env.gr[33], ==, VIBATNIUM_EFI_SYSTEM_TABLE);
    g_assert_cmphex(env.gr[0], ==, 0);

    vibatnium_efi_image_destroy(&image);
}

static void test_unimplemented_service_log(void)
{
    VibatniumEfiServiceCall call;
    uint64_t args[] = { 0x1111, 0x2222, 0x3333 };

    g_assert_cmphex(vibatnium_efi_record_unimplemented_service(
                        &call, VIBATNIUM_EFI_SERVICE_OUTPUT_STRING,
                        0x4444, args, G_N_ELEMENTS(args)),
                    ==, VIBATNIUM_EFI_UNSUPPORTED);

    g_assert_cmpstr(call.service_name, ==,
                    "SimpleTextOutput.OutputString");
    g_assert_nonnull(strstr(call.message,
                            "service=SimpleTextOutput.OutputString"));
    g_assert_nonnull(strstr(call.message, "ip=0x0000000000004444"));
    g_assert_nonnull(strstr(call.message, "0x0000000000001111"));
    g_assert_nonnull(strstr(call.message,
                            "status=unsupported(0x8000000000000003)"));
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
    g_test_add_func("/ia64-efi-app/unimplemented-service-log",
                    test_unimplemented_service_log);

    return g_test_run();
}
