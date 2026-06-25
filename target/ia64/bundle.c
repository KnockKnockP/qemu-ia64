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

#define OPCLASS(_family, _stem, _summary, _defined) \
    {                                               \
        .family = (_family),                        \
        .mnemonic_stem = (_stem),                   \
        .format_summary = (_summary),               \
        .defined = (_defined),                      \
    }

#define RESERVED_OP OPCLASS("reserved-or-ignored", "reserved", \
                            "reserved/ignored major opcode", false)

static const IA64OpcodeClass ia64_iunit_opcode_table[16] = {
    [0x0] = OPCLASS("misc-0", "misc0", "I18/I19/I20+", true),
    [0x1] = RESERVED_OP,
    [0x2] = RESERVED_OP,
    [0x3] = RESERVED_OP,
    [0x4] = OPCLASS("deposit", "deposit", "I15", true),
    [0x5] = OPCLASS("shift-test-bit", "shift", "I10-I17/I30", true),
    [0x6] = RESERVED_OP,
    [0x7] = OPCLASS("mm-multiply-shift", "mm", "I1-I9", true),
    [0x8] = OPCLASS("alu-mm-alu", "alu", "A1-A4/A9-A10", true),
    [0x9] = OPCLASS("add-imm22", "addl", "A5", true),
    [0xa] = RESERVED_OP,
    [0xb] = RESERVED_OP,
    [0xc] = OPCLASS("compare", "cmp", "A6-A8", true),
    [0xd] = OPCLASS("compare", "cmp", "A6-A8", true),
    [0xe] = OPCLASS("compare", "cmp", "A6-A8", true),
    [0xf] = RESERVED_OP,
};

static const IA64OpcodeClass ia64_munit_opcode_table[16] = {
    [0x0] = OPCLASS("sys-mem-mgmt-0", "sysmem0",
                    "M22-M28/M30/M37/M44/M48", true),
    [0x1] = OPCLASS("sys-mem-mgmt-1", "sysmem1",
                    "M20-M21/M29/M31-M36/M38-M43/M45-M47", true),
    [0x2] = RESERVED_OP,
    [0x3] = RESERVED_OP,
    [0x4] = OPCLASS("integer-load-register-getf", "ld",
                    "M1/M2/M4/M16/M17/M19", true),
    [0x5] = OPCLASS("integer-load-store-immediate", "ldst", "M3/M5", true),
    [0x6] = OPCLASS("fp-load-store-register-setf", "fldst",
                    "M6/M7/M9/M11-M13/M18", true),
    [0x7] = OPCLASS("fp-load-store-immediate", "fldst",
                    "M8/M10/M14/M15", true),
    [0x8] = OPCLASS("alu-mm-alu", "alu", "A1-A4/A9-A10", true),
    [0x9] = OPCLASS("add-imm22", "addl", "A5", true),
    [0xa] = RESERVED_OP,
    [0xb] = RESERVED_OP,
    [0xc] = OPCLASS("compare", "cmp", "A6-A8", true),
    [0xd] = OPCLASS("compare", "cmp", "A6-A8", true),
    [0xe] = OPCLASS("compare", "cmp", "A6-A8", true),
    [0xf] = RESERVED_OP,
};

static const IA64OpcodeClass ia64_funit_opcode_table[16] = {
    [0x0] = OPCLASS("fp-misc-0", "fpmisc0", "F6-F16", true),
    [0x1] = OPCLASS("fp-misc-1", "fpmisc1", "F6-F16", true),
    [0x2] = RESERVED_OP,
    [0x3] = RESERVED_OP,
    [0x4] = OPCLASS("fp-compare", "fcmp", "F4", true),
    [0x5] = OPCLASS("fp-class", "fclass", "F5", true),
    [0x6] = RESERVED_OP,
    [0x7] = RESERVED_OP,
    [0x8] = OPCLASS("fma", "fma", "F1", true),
    [0x9] = OPCLASS("fma", "fma", "F1", true),
    [0xa] = OPCLASS("fms", "fms", "F1", true),
    [0xb] = OPCLASS("fms", "fms", "F1", true),
    [0xc] = OPCLASS("fnma", "fnma", "F1", true),
    [0xd] = OPCLASS("fnma", "fnma", "F1", true),
    [0xe] = OPCLASS("fselect-xma", "fselect", "F2/F3", true),
    [0xf] = RESERVED_OP,
};

static const IA64OpcodeClass ia64_bunit_opcode_table[16] = {
    [0x0] = OPCLASS("misc-indirect-branch", "br", "B4/B8/B9", true),
    [0x1] = OPCLASS("indirect-call", "br.call", "B5", true),
    [0x2] = OPCLASS("indirect-predict-nop", "brp", "B7/B9", true),
    [0x3] = RESERVED_OP,
    [0x4] = OPCLASS("ip-relative-branch", "br", "B1/B2", true),
    [0x5] = OPCLASS("ip-relative-call", "br.call", "B3", true),
    [0x6] = RESERVED_OP,
    [0x7] = OPCLASS("ip-relative-predict", "brp", "B6", true),
    [0x8] = OPCLASS("extended-branch-8", "e8", "branch extension", true),
    [0x9] = OPCLASS("extended-branch-9", "e9", "branch extension", true),
    [0xa] = OPCLASS("extended-branch-a", "eA", "branch extension", true),
    [0xb] = OPCLASS("extended-branch-b", "eB", "branch extension", true),
    [0xc] = OPCLASS("extended-branch-c", "eC", "branch extension", true),
    [0xd] = OPCLASS("extended-branch-d", "eD", "branch extension", true),
    [0xe] = OPCLASS("extended-branch-e", "eE", "branch extension", true),
    [0xf] = OPCLASS("extended-branch-f", "eF", "branch extension", true),
};

static const IA64OpcodeClass ia64_lxunit_opcode_table[16] = {
    [0x0] = OPCLASS("extended-misc-0", "lx.misc0", "X1/X5", true),
    [0x1] = RESERVED_OP,
    [0x2] = RESERVED_OP,
    [0x3] = RESERVED_OP,
    [0x4] = RESERVED_OP,
    [0x5] = RESERVED_OP,
    [0x6] = OPCLASS("move-imm64", "movl", "X2", true),
    [0x7] = RESERVED_OP,
    [0x8] = RESERVED_OP,
    [0x9] = RESERVED_OP,
    [0xa] = RESERVED_OP,
    [0xb] = RESERVED_OP,
    [0xc] = OPCLASS("long-branch", "brl", "X3", true),
    [0xd] = OPCLASS("long-call", "brl.call", "X4", true),
    [0xe] = RESERVED_OP,
    [0xf] = RESERVED_OP,
};

static const IA64OpcodeClass ia64_xunit_opcode_class =
    OPCLASS("extended-continuation", "xdata",
            "second half of L+X instruction", true);

static const IA64OpcodeClass ia64_illegal_slot_opcode_class =
    OPCLASS("illegal-template-slot", "illegal", "reserved template", false);

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

uint8_t ia64_slot_predicate(uint64_t raw)
{
    return raw & 0x3f;
}

uint8_t ia64_slot_major_opcode(uint64_t raw)
{
    return (raw >> 37) & 0x0f;
}

const IA64OpcodeClass *ia64_opcode_class(IA64SlotType type,
                                         uint8_t major_opcode)
{
    major_opcode &= 0x0f;

    switch (type) {
    case IA64_SLOT_TYPE_M:
        return &ia64_munit_opcode_table[major_opcode];
    case IA64_SLOT_TYPE_I:
        return &ia64_iunit_opcode_table[major_opcode];
    case IA64_SLOT_TYPE_F:
        return &ia64_funit_opcode_table[major_opcode];
    case IA64_SLOT_TYPE_B:
        return &ia64_bunit_opcode_table[major_opcode];
    case IA64_SLOT_TYPE_L:
        return &ia64_lxunit_opcode_table[major_opcode];
    case IA64_SLOT_TYPE_X:
        return &ia64_xunit_opcode_class;
    case IA64_SLOT_TYPE_INVALID:
    default:
        return &ia64_illegal_slot_opcode_class;
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

void ia64_format_slot_class(const IA64DecodedBundle *decoded,
                            int slot,
                            char *buf,
                            size_t buflen)
{
    IA64SlotType type;
    uint64_t raw;
    uint8_t major;
    const IA64OpcodeClass *opclass;

    if (slot < 0 || slot >= IA64_SLOT_COUNT || buflen == 0) {
        if (buf && buflen) {
            buf[0] = '\0';
        }
        return;
    }

    type = decoded->valid ? decoded->info->slot_type[slot] :
           IA64_SLOT_TYPE_INVALID;
    raw = decoded->slot[slot];
    major = ia64_slot_major_opcode(raw);
    opclass = ia64_opcode_class(type, major);

    snprintf(buf, buflen,
             "slot=%d type=%s qp=p%u major=0x%x raw=0x%011" PRIx64
             " family=%s mnemonic=%s format=%s defined=%s",
             slot, ia64_slot_type_name(type), ia64_slot_predicate(raw), major,
             raw, opclass->family, opclass->mnemonic_stem,
             opclass->format_summary, opclass->defined ? "yes" : "no");
}
