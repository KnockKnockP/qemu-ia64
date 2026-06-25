/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "bundle.h"

#define TEMPL(_name, _s0, _s1, _s2, _st0, _st1, _st2, _long) \
    {                                                        \
        .name = (_name),                                     \
        .slot_type = {                                       \
            IA64_SLOT_TYPE_##_s0,                            \
            IA64_SLOT_TYPE_##_s1,                            \
            IA64_SLOT_TYPE_##_s2,                            \
        },                                                   \
        .stop_after_slot = { (_st0), (_st1), (_st2) },       \
        .long_immediate = (_long),                           \
        .valid = true,                                       \
    }

#define RESERVED \
    { .name = "reserved" }

static const IA64TemplateInfo ia64_template_table[32] = {
    [0x00] = TEMPL("MII",  M, I, I, false, false, false, false),
    [0x01] = TEMPL("MII",  M, I, I, false, false, true,  false),
    [0x02] = TEMPL("MI_I", M, I, I, false, true,  false, false),
    [0x03] = TEMPL("MI_I", M, I, I, false, true,  true,  false),
    [0x04] = TEMPL("MLX",  M, L, X, false, false, false, true),
    [0x05] = TEMPL("MLX",  M, L, X, false, false, true,  true),
    [0x06] = RESERVED,
    [0x07] = RESERVED,
    [0x08] = TEMPL("MMI",  M, M, I, false, false, false, false),
    [0x09] = TEMPL("MMI",  M, M, I, false, false, true,  false),
    [0x0a] = TEMPL("M_MI", M, M, I, true,  false, false, false),
    [0x0b] = TEMPL("M_MI", M, M, I, true,  false, true,  false),
    [0x0c] = TEMPL("MFI",  M, F, I, false, false, false, false),
    [0x0d] = TEMPL("MFI",  M, F, I, false, false, true,  false),
    [0x0e] = TEMPL("MMF",  M, M, F, false, false, false, false),
    [0x0f] = TEMPL("MMF",  M, M, F, false, false, true,  false),
    [0x10] = TEMPL("MIB",  M, I, B, false, false, false, false),
    [0x11] = TEMPL("MIB",  M, I, B, false, false, true,  false),
    [0x12] = TEMPL("MBB",  M, B, B, false, false, false, false),
    [0x13] = TEMPL("MBB",  M, B, B, false, false, true,  false),
    [0x14] = RESERVED,
    [0x15] = RESERVED,
    [0x16] = TEMPL("BBB",  B, B, B, false, false, false, false),
    [0x17] = TEMPL("BBB",  B, B, B, false, false, true,  false),
    [0x18] = TEMPL("MMB",  M, M, B, false, false, false, false),
    [0x19] = TEMPL("MMB",  M, M, B, false, false, true,  false),
    [0x1a] = RESERVED,
    [0x1b] = RESERVED,
    [0x1c] = TEMPL("MFB",  M, F, B, false, false, false, false),
    [0x1d] = TEMPL("MFB",  M, F, B, false, false, true,  false),
    [0x1e] = RESERVED,
    [0x1f] = RESERVED,
};

static uint64_t ia64_load_le64(const uint8_t *p)
{
    uint64_t value = 0;

    for (int i = 7; i >= 0; i--) {
        value = (value << 8) | p[i];
    }

    return value;
}

const IA64TemplateInfo *ia64_template_info(uint8_t tmpl)
{
    return &ia64_template_table[tmpl & 0x1f];
}

const char *ia64_slot_type_name(IA64SlotType type)
{
    switch (type) {
    case IA64_SLOT_TYPE_M:
        return "M";
    case IA64_SLOT_TYPE_I:
        return "I";
    case IA64_SLOT_TYPE_F:
        return "F";
    case IA64_SLOT_TYPE_B:
        return "B";
    case IA64_SLOT_TYPE_L:
        return "L";
    case IA64_SLOT_TYPE_X:
        return "X";
    case IA64_SLOT_TYPE_INVALID:
    default:
        return "?";
    }
}

bool ia64_decode_bundle_words(uint64_t lo, uint64_t hi,
                              IA64DecodedBundle *decoded)
{
    uint8_t tmpl = lo & 0x1f;
    const IA64TemplateInfo *info = ia64_template_info(tmpl);

    memset(decoded, 0, sizeof(*decoded));
    decoded->tmpl = tmpl;
    decoded->slot[0] = (lo >> 5) & IA64_SLOT_MASK;
    decoded->slot[1] = ((lo >> 46) | (hi << 18)) & IA64_SLOT_MASK;
    decoded->slot[2] = (hi >> 23) & IA64_SLOT_MASK;
    decoded->info = info;
    decoded->valid = info->valid;

    return decoded->valid;
}

bool ia64_decode_bundle(const uint8_t bundle[IA64_BUNDLE_SIZE],
                        IA64DecodedBundle *decoded)
{
    uint64_t lo = ia64_load_le64(bundle);
    uint64_t hi = ia64_load_le64(bundle + 8);

    return ia64_decode_bundle_words(lo, hi, decoded);
}

void ia64_format_decoded_bundle(const IA64DecodedBundle *decoded,
                                char *buf, size_t buflen)
{
    const IA64TemplateInfo *info = decoded->info;
    char stops[IA64_SLOT_COUNT + 1];

    for (int i = 0; i < IA64_SLOT_COUNT; i++) {
        stops[i] = info->stop_after_slot[i] ? '0' + i : '-';
    }
    stops[IA64_SLOT_COUNT] = '\0';

    snprintf(buf, buflen,
             "tmpl=%02x %s slots=%s,%s,%s stops=%s long=%s "
             "raw=%011" PRIx64 ",%011" PRIx64 ",%011" PRIx64,
             decoded->tmpl, info->name,
             ia64_slot_type_name(info->slot_type[0]),
             ia64_slot_type_name(info->slot_type[1]),
             ia64_slot_type_name(info->slot_type[2]),
             stops, info->long_immediate ? "yes" : "no",
             decoded->slot[0], decoded->slot[1], decoded->slot[2]);
}
