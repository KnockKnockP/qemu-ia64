/*
 * Vibtanium ACPI fixed-register tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/ia64/vibtanium.h"
#include "libqtest.h"

static uint64_t sparse_io_address(unsigned port)
{
    uint64_t offset = ((uint64_t)(port >> 2) << 12) | (port & 0xfff);

    return VIBTANIUM_IO_PORT_BASE + offset;
}

static void test_pm_registers(void)
{
    const char *firmware_dir = g_getenv("IA64_QTEST_FIRMWARE_DIR");
    QTestState *qts;
    uint64_t status = sparse_io_address(VIBTANIUM_ACPI_PM_BASE);
    uint64_t enable = sparse_io_address(VIBTANIUM_ACPI_PM_BASE + 2);
    uint64_t control = sparse_io_address(VIBTANIUM_ACPI_PM_BASE + 4);

    g_assert_nonnull(firmware_dir);
    qts = qtest_initf("-L \"%s\" -M vibtanium -m 128M", firmware_dir);

    g_assert_cmphex(qtest_readw(qts, status), ==,
                    ACPI_BITMASK_TIMER_STATUS);
    qtest_writew(qts, status, UINT16_MAX);
    g_assert_cmphex(qtest_readw(qts, status), ==, 0);

    qtest_writew(qts, enable, ACPI_BITMASK_POWER_BUTTON_ENABLE);
    g_assert_cmphex(qtest_readw(qts, enable), ==,
                    ACPI_BITMASK_POWER_BUTTON_ENABLE);
    g_assert_cmphex(qtest_readw(qts, control), ==,
                    ACPI_BITMASK_SCI_ENABLE);

    qtest_quit(qts);
}

static void test_guest_reset_request(void)
{
    const char *firmware_dir = g_getenv("IA64_QTEST_FIRMWARE_DIR");
    QTestState *qts;
    uint64_t reset = VIBTANIUM_GUEST_IO_PORT_BASE +
                     VIBTANIUM_GUEST_ACPI_PM_BASE +
                     VIBTANIUM_GUEST_ACPI_RESET_OFFSET;

    g_assert_nonnull(firmware_dir);
    qts = qtest_initf("-L \"%s\" -M vibtanium,nvram=none -m 128M",
                      firmware_dir);

    qtest_writeb(qts, reset, VIBTANIUM_GUEST_ACPI_RESET_VALUE);
    qtest_qmp_eventwait(qts, "RESET");
    qtest_quit(qts);
}

static void test_guest_shutdown_request(void)
{
    const char *firmware_dir = g_getenv("IA64_QTEST_FIRMWARE_DIR");
    g_autoptr(QDict) event = NULL;
    QTestState *qts;
    uint64_t control = sparse_io_address(VIBTANIUM_ACPI_PM_BASE + 4);

    g_assert_nonnull(firmware_dir);
    qts = qtest_initf("-L \"%s\" -M vibtanium,nvram=none -m 128M "
                      "-no-shutdown", firmware_dir);

    qtest_writew(qts, control, ACPI_BITMASK_SLEEP_ENABLE);
    event = qtest_qmp_eventwait_ref(qts, "SHUTDOWN");
    g_assert_true(qdict_get_bool(qdict_get_qdict(event, "data"), "guest"));
    qtest_quit(qts);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/ia64-acpi/pm-registers", test_pm_registers);
    qtest_add_func("/ia64-acpi/guest-reset", test_guest_reset_request);
    qtest_add_func("/ia64-acpi/guest-shutdown",
                   test_guest_shutdown_request);
    return g_test_run();
}
