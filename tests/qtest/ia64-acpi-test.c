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
    QTestState *qts = qtest_init(
        "-M vibtanium,efi-boot-manager=off -m 128M");
    uint64_t status = sparse_io_address(VIBTANIUM_ACPI_PM_BASE);
    uint64_t enable = sparse_io_address(VIBTANIUM_ACPI_PM_BASE + 2);
    uint64_t control = sparse_io_address(VIBTANIUM_ACPI_PM_BASE + 4);

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

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/ia64-acpi/pm-registers", test_pm_registers);
    return g_test_run();
}
