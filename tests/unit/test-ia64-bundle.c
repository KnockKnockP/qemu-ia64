/*
 * IA-64 bundle decoder tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "target/ia64/bundle.h"

static void store_le64(uint8_t *p, uint64_t value)
{
    for (int i = 0; i < 8; i++) {
        p[i] = value >> (i * 8);
    }
}

static void make_bundle(uint8_t *bundle, uint8_t tmpl,
                        uint64_t slot0, uint64_t slot1, uint64_t slot2)
{
    uint64_t lo;
    uint64_t hi;

    slot0 &= IA64_SLOT_MASK;
    slot1 &= IA64_SLOT_MASK;
    slot2 &= IA64_SLOT_MASK;

    lo = tmpl | (slot0 << 5) | ((slot1 & ((1ULL << 18) - 1)) << 46);
    hi = (slot1 >> 18) | (slot2 << 23);

    store_le64(bundle, lo);
    store_le64(bundle + 8, hi);
}

static void test_all_templates_classify(void)
{
    unsigned valid = 0;
    unsigned reserved = 0;
    unsigned long_immediate = 0;

    for (uint8_t tmpl = 0; tmpl < 32; tmpl++) {
        const IA64TemplateInfo *info = ia64_template_info(tmpl);

        g_assert_nonnull(info);
        g_assert_nonnull(info->name);

        if (info->valid) {
            valid++;
            for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
                g_assert_cmpint(info->slot_type[slot], !=,
                                IA64_SLOT_TYPE_INVALID);
            }
        } else {
            reserved++;
            g_assert_cmpstr(info->name, ==, "reserved");
        }

        if (info->long_immediate) {
            long_immediate++;
            g_assert_true(tmpl == 0x04 || tmpl == 0x05);
            g_assert_cmpint(info->slot_type[1], ==, IA64_SLOT_TYPE_L);
            g_assert_cmpint(info->slot_type[2], ==, IA64_SLOT_TYPE_X);
        }
    }

    g_assert_cmpuint(valid, ==, 24);
    g_assert_cmpuint(reserved, ==, 8);
    g_assert_cmpuint(long_immediate, ==, 2);
}

static void test_slot_extraction_little_endian(void)
{
    const uint64_t slot0 = 0x123456789abULL;
    const uint64_t slot1 = 0x0fedcba987ULL;
    const uint64_t slot2 = 0x1abcdef0123ULL;
    uint8_t bundle[IA64_BUNDLE_SIZE];
    IA64DecodedBundle decoded;

    make_bundle(bundle, 0x12, slot0, slot1, slot2);

    g_assert_true(ia64_decode_bundle(bundle, &decoded));
    g_assert_cmpuint(decoded.tmpl, ==, 0x12);
    g_assert_cmphex(decoded.slot[0], ==, slot0);
    g_assert_cmphex(decoded.slot[1], ==, slot1);
    g_assert_cmphex(decoded.slot[2], ==, slot2);
}

static void test_stop_bits(void)
{
    const IA64TemplateInfo *info;

    info = ia64_template_info(0x00);
    g_assert_false(info->stop_after_slot[0]);
    g_assert_false(info->stop_after_slot[1]);
    g_assert_false(info->stop_after_slot[2]);

    info = ia64_template_info(0x03);
    g_assert_false(info->stop_after_slot[0]);
    g_assert_true(info->stop_after_slot[1]);
    g_assert_true(info->stop_after_slot[2]);

    info = ia64_template_info(0x0a);
    g_assert_true(info->stop_after_slot[0]);
    g_assert_false(info->stop_after_slot[1]);
    g_assert_false(info->stop_after_slot[2]);

    info = ia64_template_info(0x0b);
    g_assert_true(info->stop_after_slot[0]);
    g_assert_false(info->stop_after_slot[1]);
    g_assert_true(info->stop_after_slot[2]);
}

static void test_reserved_template(void)
{
    uint8_t bundle[IA64_BUNDLE_SIZE];
    IA64DecodedBundle decoded;
    char text[160];

    make_bundle(bundle, 0x06, 1, 2, 3);

    g_assert_false(ia64_decode_bundle(bundle, &decoded));
    g_assert_false(decoded.valid);
    g_assert_cmpstr(decoded.info->name, ==, "reserved");
    g_assert_cmphex(decoded.slot[0], ==, 1);
    g_assert_cmphex(decoded.slot[1], ==, 2);
    g_assert_cmphex(decoded.slot[2], ==, 3);

    ia64_format_decoded_bundle(&decoded, text, sizeof(text));
    g_assert_cmpstr(text, ==,
                    "tmpl=06 reserved slots=?,?,? stops=--- long=no "
                    "raw=00000000001,00000000002,00000000003");
}

static void test_format_output_stable(void)
{
    uint8_t bundle[IA64_BUNDLE_SIZE] = { 0 };
    IA64DecodedBundle decoded;
    char text[160];

    g_assert_true(ia64_decode_bundle(bundle, &decoded));
    ia64_format_decoded_bundle(&decoded, text, sizeof(text));

    g_assert_cmpstr(text, ==,
                    "tmpl=00 MII slots=M,I,I stops=--- long=no "
                    "raw=00000000000,00000000000,00000000000");
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);

    g_test_add_func("/ia64-bundle/all-templates",
                    test_all_templates_classify);
    g_test_add_func("/ia64-bundle/slot-extraction-little-endian",
                    test_slot_extraction_little_endian);
    g_test_add_func("/ia64-bundle/stop-bits", test_stop_bits);
    g_test_add_func("/ia64-bundle/reserved-template",
                    test_reserved_template);
    g_test_add_func("/ia64-bundle/format-output-stable",
                    test_format_output_stable);

    return g_test_run();
}
