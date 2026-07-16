/*
 * Vibtanium guest-firmware platform ABI tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include <glib/gstdio.h>
#include "hw/ia64/vibtanium.h"
#include "hw/pci/pci.h"
#include "qobject/qdict.h"
#include "libqtest.h"

#define TEST_IA64_BUNDLE_SIZE 16

static char *test_path(const char *directory, const char *basename)
{
    char *path = g_build_filename(directory, basename, NULL);

    return g_strdelimit(path, "\\", '/');
}

static void write_test_firmware(const char *path)
{
    static const uint8_t source_portal[TEST_IA64_BUNDLE_SIZE] = {
        0x0a, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00,
        0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
    };
    uint8_t image[0x60 + TEST_IA64_BUNDLE_SIZE] = { 0 };
    g_autoptr(GError) err = NULL;

    memcpy(image + 0x60, source_portal, sizeof(source_portal));
    g_assert_true(g_file_set_contents(path, (const char *)image,
                                      sizeof(image), &err));
    g_assert_no_error(err);
}

static uint64_t portal_break_immediate(
    const uint8_t bundle[TEST_IA64_BUNDLE_SIZE])
{
    uint64_t low = ldq_le_p(bundle);
    uint64_t raw;

    g_assert_cmphex(low & 0x1f, ==, 0x0a);
    raw = (low >> 5) & ((UINT64_C(1) << 41) - 1);
    return (((raw >> 36) & 1) << 20) | ((raw >> 6) & 0xfffff);
}

static QTestState *start_guest_firmware(const char *firmware,
                                        const char *nvram)
{
    const char *firmware_dir = g_getenv("IA64_QTEST_FIRMWARE_DIR");

    g_assert_nonnull(firmware_dir);
    if (!firmware) {
        return qtest_initf("-L \"%s\" -M vibtanium,nvram=\"%s\" -m 128M",
                           firmware_dir, nvram);
    }
    return qtest_initf("-L \"%s\" -M vibtanium,nvram=\"%s\" -m 128M "
                       "-bios \"%s\"", firmware_dir, nvram, firmware);
}

static void test_default_firmware_search(void)
{
    QTestState *qts = start_guest_firmware(NULL, "none");

    g_assert_cmphex(qtest_readq(qts, VIBTANIUM_GUEST_FIRMWARE_HANDOFF), ==,
                    VIBTANIUM_GUEST_FIRMWARE_HANDOFF_MAGIC);
    qtest_quit(qts);
}

static void test_default_nvram_property(void)
{
    const char *firmware_dir = g_getenv("IA64_QTEST_FIRMWARE_DIR");
    QTestState *qts;
    QDict *response;

    g_assert_nonnull(firmware_dir);
    qts = qtest_initf("-L \"%s\" -M vibtanium -m 128M", firmware_dir);
    response = qtest_qmp(qts,
        "{ 'execute': 'qom-get', 'arguments': "
        "{ 'path': '/machine', 'property': 'nvram' } }");
    g_assert_cmpstr(qdict_get_str(response, "return"), ==, "auto");
    qobject_unref(response);
    qtest_quit(qts);
}

static void test_minimum_ram_rejected(void)
{
    const char *qemu = g_getenv("QTEST_QEMU_BINARY");
    const char *firmware_dir = g_getenv("IA64_QTEST_FIRMWARE_DIR");
    g_autofree char *standard_output = NULL;
    g_autofree char *standard_error = NULL;
    g_autoptr(GError) err = NULL;
    int wait_status;
    char *argv[] = {
        (char *)qemu,
        (char *)"-L", (char *)firmware_dir,
        (char *)"-M", (char *)"vibtanium,nvram=none",
        (char *)"-m", (char *)"127M",
        (char *)"-display", (char *)"none",
        NULL,
    };

    g_assert_nonnull(qemu);
    g_assert_nonnull(firmware_dir);
    g_assert_true(g_spawn_sync(NULL, argv, NULL, G_SPAWN_SEARCH_PATH,
                               NULL, NULL,
                               &standard_output, &standard_error,
                               &wait_status, &err));
    g_assert_no_error(err);
    g_assert_false(g_spawn_check_exit_status(wait_status, NULL));
    g_assert_nonnull(strstr(standard_error,
                            "vibtanium RAM must be at least"));
}

static void test_high_ram_relocation(void)
{
    const char *firmware_dir = g_getenv("IA64_QTEST_FIRMWARE_DIR");
    const uint64_t value = UINT64_C(0x0123456789abcdef);
    QTestState *qts;

    g_assert_nonnull(firmware_dir);
    qts = qtest_initf("-L \"%s\" -M vibtanium,nvram=none -m 2050M",
                      firmware_dir);

    qtest_writeq(qts, VIBTANIUM_HIGH_RAM_BASE, value);
    g_assert_cmphex(qtest_readq(qts, VIBTANIUM_HIGH_RAM_BASE), ==, value);

    /* The I/O SAPIC/scratch aperture displaces RAM above the 2 GiB limit. */
    qtest_writeq(qts, VIBTANIUM_LOW_RAM_LIMIT, ~value);
    g_assert_cmphex(qtest_readq(qts, VIBTANIUM_HIGH_RAM_BASE), ==, value);
    g_assert_cmphex(qtest_readq(qts, VIBTANIUM_LOW_RAM_LIMIT), !=, ~value);

    qtest_quit(qts);
}

static void test_loader_reset_pc_preserved(void)
{
    const char *firmware_dir = g_getenv("IA64_QTEST_FIRMWARE_DIR");
    g_autofree char *registers = NULL;
    QTestState *qts;

    g_assert_nonnull(firmware_dir);
    qts = qtest_initf("-L \"%s\" -M vibtanium,nvram=none -m 128M "
                      "-device loader,addr=0x200000,cpu-num=0",
                      firmware_dir);
    registers = qtest_hmp(qts, "info registers");
    g_assert_nonnull(strstr(registers, "IP  0000000000200000"));
    qtest_quit(qts);
}

static void test_platform_abi_and_nvram(void)
{
    g_autofree char *directory =
        g_dir_make_tmp("ia64-guest-firmware-XXXXXX", NULL);
    g_autofree char *firmware = NULL;
    g_autofree char *nvram = NULL;
    g_autofree char *contents = NULL;
    g_autoptr(GError) err = NULL;
    QTestState *qts;
    uint8_t portal[TEST_IA64_BUNDLE_SIZE];
    const uint64_t persisted = UINT64_C(0x0123456789abcdef);
    gsize length = 0;

    g_assert_nonnull(directory);
    firmware = test_path(directory, "firmware.bin");
    nvram = test_path(directory, "nvram.bin");
    write_test_firmware(firmware);

    qts = start_guest_firmware(firmware, nvram);
    g_assert_cmphex(qtest_readq(qts, VIBTANIUM_GUEST_FIRMWARE_HANDOFF), ==,
                    VIBTANIUM_GUEST_FIRMWARE_HANDOFF_MAGIC);
    g_assert_cmphex(qtest_readq(qts,
                    VIBTANIUM_GUEST_FIRMWARE_HANDOFF + 8), ==,
                    VIBTANIUM_GUEST_FIRMWARE_HANDOFF_VERSION);
    g_assert_cmphex(qtest_readq(qts,
                    VIBTANIUM_GUEST_FIRMWARE_HANDOFF + 24), ==, 1);

    qtest_memread(qts, VIBTANIUM_GUEST_FIRMWARE_BASE + 0x60,
                  portal, sizeof(portal));
    g_assert_cmphex(portal_break_immediate(portal), ==,
                    VIBTANIUM_GUEST_PAL_BREAK);

    qtest_writel(qts, VIBTANIUM_GUEST_VGA_FRAMEBUFFER_BASE + 0x100,
                 UINT32_C(0xa55a3cc3));
    g_assert_cmphex(qtest_readl(
                        qts,
                        VIBTANIUM_GUEST_VGA_FRAMEBUFFER_BASE + 0x100), ==,
                    UINT32_C(0xa55a3cc3));
    g_assert_cmphex(qtest_readl(qts, VIBTANIUM_GUEST_PCI_CONFIG_BASE), ==,
                    UINT32_MAX);
    g_assert_cmphex(qtest_readl(
                        qts, VIBTANIUM_GUEST_PCI_CONFIG_BASE + 0x8000), ==,
                    UINT32_C(0x29228086));
    g_assert_cmphex(qtest_readl(
                        qts, VIBTANIUM_GUEST_PCI_CONFIG_BASE + 0x10000), ==,
                    UINT32_C(0x003f106b));
    g_assert_cmphex(qtest_readl(
                        qts, VIBTANIUM_GUEST_PCI_CONFIG_BASE + 0x18000), ==,
                    UINT32_C(0x70208086));
    g_assert_cmphex(qtest_readl(
                        qts, VIBTANIUM_GUEST_PCI_CONFIG_BASE + 0x20000), ==,
                    UINT32_C(0x00121000));
    g_assert_cmphex(qtest_readl(
                        qts, VIBTANIUM_GUEST_PCI_CONFIG_BASE + 0x28000), ==,
                    UINT32_C(0x50461002));
    g_assert_cmphex(qtest_readl(
                        qts, VIBTANIUM_GUEST_PCI_CONFIG_BASE + 0x8000 +
                             PCI_BASE_ADDRESS_5) &
                    PCI_BASE_ADDRESS_MEM_MASK, ==,
                    VIBTANIUM_AHCI_MMIO_BASE);
    g_assert_cmphex(qtest_readl(
                        qts, VIBTANIUM_GUEST_PCI_CONFIG_BASE + 0x10000 +
                             PCI_BASE_ADDRESS_0) &
                    PCI_BASE_ADDRESS_MEM_MASK, ==,
                    VIBTANIUM_OHCI_MMIO_BASE);
    g_assert_cmphex(qtest_readl(
                        qts, VIBTANIUM_GUEST_PCI_CONFIG_BASE + 0x18000 +
                             PCI_BASE_ADDRESS_4) &
                    PCI_BASE_ADDRESS_IO_MASK, ==,
                    VIBTANIUM_UHCI_IO_BASE);
    g_assert_cmphex(qtest_readl(
                        qts, VIBTANIUM_GUEST_PCI_CONFIG_BASE + 0x20000 +
                             PCI_BASE_ADDRESS_1) &
                    PCI_BASE_ADDRESS_MEM_MASK, ==,
                    VIBTANIUM_LSI_MMIO_BASE);
    g_assert_cmphex(qtest_readl(
                        qts, VIBTANIUM_GUEST_PCI_CONFIG_BASE + 0x28000 +
                             PCI_BASE_ADDRESS_0) &
                    PCI_BASE_ADDRESS_MEM_MASK, ==,
                    VIBTANIUM_GUEST_VGA_FRAMEBUFFER_BASE);

    /* The PCI I/O root is 16 MiB, not QEMU's 64 KiB system_io region. */
    qtest_writel(qts, VIBTANIUM_GUEST_PCI_CONFIG_BASE + 0x18000 +
                      PCI_BASE_ADDRESS_4,
                 UINT32_C(0x00010001));
    g_assert_cmphex(qtest_readw(qts, VIBTANIUM_GUEST_IO_PORT_BASE +
                                     UINT64_C(0x10000)), !=,
                    UINT16_MAX);
    g_assert_cmphex(qtest_readb(
                        qts, VIBTANIUM_GUEST_IO_PORT_BASE +
                                 VIBTANIUM_GUEST_ACPI_PM_BASE +
                                 VIBTANIUM_GUEST_ACPI_RESET_OFFSET), ==, 0);

    qtest_writeq(qts, VIBTANIUM_GUEST_NVRAM_BASE + 0x100, persisted);
    qtest_writeq(qts,
                 VIBTANIUM_GUEST_NVRAM_BASE +
                     VIBTANIUM_GUEST_NVRAM_COMMIT_OFFSET,
                 VIBTANIUM_GUEST_NVRAM_COMMIT_MAGIC);
    g_assert_true(g_file_get_contents(nvram, &contents, &length, &err));
    g_assert_no_error(err);
    g_assert_cmpuint(length, ==, VIBTANIUM_NVRAM_SIZE);
    g_assert_cmphex(ldq_le_p((uint8_t *)contents + 0x100), ==, persisted);
    qtest_quit(qts);

    qts = start_guest_firmware(firmware, nvram);
    g_assert_cmphex(qtest_readq(qts,
                               VIBTANIUM_GUEST_NVRAM_BASE + 0x100), ==,
                    persisted);
    qtest_quit(qts);

    g_assert_cmpint(g_remove(nvram), ==, 0);
    g_assert_cmpint(g_remove(firmware), ==, 0);
    g_assert_cmpint(g_rmdir(directory), ==, 0);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/ia64-guest-firmware/default-search",
                   test_default_firmware_search);
    qtest_add_func("/ia64-guest-firmware/default-nvram-property",
                   test_default_nvram_property);
    qtest_add_func("/ia64-guest-firmware/minimum-ram-rejected",
                   test_minimum_ram_rejected);
    qtest_add_func("/ia64-guest-firmware/high-ram-relocation",
                   test_high_ram_relocation);
    qtest_add_func("/ia64-guest-firmware/loader-reset-pc",
                   test_loader_reset_pc_preserved);
    qtest_add_func("/ia64-guest-firmware/platform-abi-nvram",
                   test_platform_abi_and_nvram);
    return g_test_run();
}
