/*
 * IA-64 firmware interface tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "target/ia64/firmware.h"

static void test_pal_ptce_info_loop_encoding(void)
{
    uint32_t outer_count = IA64_FIRMWARE_PAL_PTCE_COUNTS >> 32;
    uint32_t inner_count = IA64_FIRMWARE_PAL_PTCE_COUNTS & UINT32_MAX;
    uint32_t outer_stride = IA64_FIRMWARE_PAL_PTCE_STRIDES >> 32;
    uint32_t inner_stride = IA64_FIRMWARE_PAL_PTCE_STRIDES & UINT32_MAX;

    g_assert_cmpuint(outer_count, ==, 1);
    g_assert_cmpuint(inner_count, ==, 1);
    g_assert_cmpuint(outer_stride, ==, 0);
    g_assert_cmpuint(inner_stride, ==, 0);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/ia64-firmware/pal-ptce-info-loop-encoding",
                    test_pal_ptce_info_loop_encoding);
    return g_test_run();
}
