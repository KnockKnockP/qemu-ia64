/*
 * Vibtanium legacy input integration tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "hw/ia64/vibtanium.h"
#include "libqtest.h"

#define I8042_STATUS_OUTPUT_FULL 0x01
#define I8042_STATUS_AUX_OUTPUT  0x20
#define I8042_WRITE_AUX          0xd4

#define PS2_ACK                  0xfa
#define PS2_SELF_TEST_OK         0xaa
#define PS2_SET_SAMPLE_RATE      0xf3
#define PS2_ENABLE               0xf4
#define PS2_GET_DEVICE_ID        0xf2
#define PS2_RESET                0xff

static uint64_t sparse_io_address(unsigned port)
{
    uint64_t offset = ((uint64_t)(port >> 2) << 12) | (port & 0xfff);

    return VIBTANIUM_IO_PORT_BASE + offset;
}

static void i8042_write(QTestState *qts, unsigned port, uint8_t value)
{
    qtest_writeb(qts, sparse_io_address(port), value);
}

static uint8_t i8042_read(QTestState *qts, unsigned port)
{
    return qtest_readb(qts, sparse_io_address(port));
}

static void ps2_write(QTestState *qts, uint8_t value)
{
    i8042_write(qts, VIBTANIUM_LEGACY_I8042_COMMAND_PORT,
                I8042_WRITE_AUX);
    i8042_write(qts, VIBTANIUM_LEGACY_I8042_DATA_PORT, value);
}

static uint8_t ps2_read(QTestState *qts)
{
    uint8_t status = i8042_read(qts,
                                VIBTANIUM_LEGACY_I8042_COMMAND_PORT);

    g_assert(status & I8042_STATUS_OUTPUT_FULL);
    g_assert(status & I8042_STATUS_AUX_OUTPUT);
    return i8042_read(qts, VIBTANIUM_LEGACY_I8042_DATA_PORT);
}

static void ps2_write_ack(QTestState *qts, uint8_t value)
{
    ps2_write(qts, value);
    g_assert(ps2_read(qts) == PS2_ACK);
}

static QTestState *input_test_init(void)
{
    const char *firmware_dir = g_getenv("IA64_QTEST_FIRMWARE_DIR");

    g_assert_nonnull(firmware_dir);
    return qtest_initf("-L \"%s\" -M vibtanium -m 128M", firmware_dir);
}

static void test_ps2_reset_and_identify(void)
{
    QTestState *qts = input_test_init();

    ps2_write(qts, PS2_RESET);
    g_assert(ps2_read(qts) == PS2_ACK);
    g_assert(ps2_read(qts) == PS2_SELF_TEST_OK);
    g_assert(ps2_read(qts) == 0x00);
    g_assert(!(i8042_read(qts, VIBTANIUM_LEGACY_I8042_COMMAND_PORT) &
               I8042_STATUS_OUTPUT_FULL));

    ps2_write(qts, PS2_GET_DEVICE_ID);
    g_assert(ps2_read(qts) == PS2_ACK);
    g_assert(ps2_read(qts) == 0x00);

    qtest_quit(qts);
}

static void test_ps2_motion_and_buttons(void)
{
    QTestState *qts = input_test_init();

    ps2_write_ack(qts, PS2_ENABLE);
    qtest_qmp_assert_success(
        qts,
        "{'execute':'input-send-event','arguments':{'events':["
        "{'type':'rel','data':{'axis':'x','value':10}},"
        "{'type':'rel','data':{'axis':'y','value':-5}},"
        "{'type':'btn','data':{'button':'left','down':true}},"
        "{'type':'btn','data':{'button':'middle','down':true}},"
        "{'type':'btn','data':{'button':'right','down':true}}]}}");

    g_assert(ps2_read(qts) == 0x0f);
    g_assert(ps2_read(qts) == 10);
    g_assert(ps2_read(qts) == 5);

    qtest_qmp_assert_success(
        qts,
        "{'execute':'input-send-event','arguments':{'events':["
        "{'type':'btn','data':{'button':'left','down':false}},"
        "{'type':'btn','data':{'button':'middle','down':false}},"
        "{'type':'btn','data':{'button':'right','down':false}}]}}");

    g_assert(ps2_read(qts) == 0x08);
    g_assert(ps2_read(qts) == 0);
    g_assert(ps2_read(qts) == 0);

    qtest_quit(qts);
}

static void test_imps2_wheel_protocol(void)
{
    QTestState *qts = input_test_init();
    static const uint8_t rates[] = { 200, 100, 80 };

    for (size_t i = 0; i < G_N_ELEMENTS(rates); i++) {
        ps2_write_ack(qts, PS2_SET_SAMPLE_RATE);
        ps2_write_ack(qts, rates[i]);
    }

    ps2_write(qts, PS2_GET_DEVICE_ID);
    g_assert(ps2_read(qts) == PS2_ACK);
    g_assert(ps2_read(qts) == 0x03);
    ps2_write_ack(qts, PS2_ENABLE);

    qtest_qmp_assert_success(
        qts,
        "{'execute':'input-send-event','arguments':{'events':["
        "{'type':'btn','data':{'button':'wheel-up','down':true}},"
        "{'type':'btn','data':{'button':'wheel-up','down':false}}]}}");

    g_assert(ps2_read(qts) == 0x08);
    g_assert(ps2_read(qts) == 0);
    g_assert(ps2_read(qts) == 0);
    g_assert(ps2_read(qts) == 0xff);

    qtest_quit(qts);
}

static void test_imex_buttons_protocol(void)
{
    QTestState *qts = input_test_init();
    static const uint8_t rates[] = { 200, 200, 80 };

    for (size_t i = 0; i < G_N_ELEMENTS(rates); i++) {
        ps2_write_ack(qts, PS2_SET_SAMPLE_RATE);
        ps2_write_ack(qts, rates[i]);
    }

    ps2_write(qts, PS2_GET_DEVICE_ID);
    g_assert(ps2_read(qts) == PS2_ACK);
    g_assert(ps2_read(qts) == 0x04);
    ps2_write_ack(qts, PS2_ENABLE);

    qtest_qmp_assert_success(
        qts,
        "{'execute':'input-send-event','arguments':{'events':["
        "{'type':'btn','data':{'button':'side','down':true}},"
        "{'type':'btn','data':{'button':'extra','down':true}}]}}");

    g_assert(ps2_read(qts) == 0x08);
    g_assert(ps2_read(qts) == 0);
    g_assert(ps2_read(qts) == 0);
    g_assert(ps2_read(qts) == 0x30);

    qtest_qmp_assert_success(
        qts,
        "{'execute':'input-send-event','arguments':{'events':["
        "{'type':'btn','data':{'button':'side','down':false}},"
        "{'type':'btn','data':{'button':'extra','down':false}}]}}");

    g_assert(ps2_read(qts) == 0x08);
    g_assert(ps2_read(qts) == 0);
    g_assert(ps2_read(qts) == 0);
    g_assert(ps2_read(qts) == 0);

    qtest_quit(qts);
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    qtest_add_func("/ia64-input/ps2/reset-identify",
                   test_ps2_reset_and_identify);
    qtest_add_func("/ia64-input/ps2/motion-buttons",
                   test_ps2_motion_and_buttons);
    qtest_add_func("/ia64-input/ps2/imps2-wheel",
                   test_imps2_wheel_protocol);
    qtest_add_func("/ia64-input/ps2/imex-buttons",
                   test_imex_buttons_protocol);
    return g_test_run();
}
