/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IA64_BUNDLE_H
#define IA64_BUNDLE_H

#define IA64_BUNDLE_SIZE 16
#define IA64_SLOT_COUNT 3
#define IA64_SLOT_BITS 41
#define IA64_SLOT_MASK ((1ULL << IA64_SLOT_BITS) - 1)

typedef enum IA64SlotType {
    IA64_SLOT_TYPE_INVALID,
    IA64_SLOT_TYPE_M,
    IA64_SLOT_TYPE_I,
    IA64_SLOT_TYPE_F,
    IA64_SLOT_TYPE_B,
    IA64_SLOT_TYPE_L,
    IA64_SLOT_TYPE_X,
} IA64SlotType;

typedef struct IA64TemplateInfo {
    const char *name;
    IA64SlotType slot_type[IA64_SLOT_COUNT];
    bool stop_after_slot[IA64_SLOT_COUNT];
    bool long_immediate;
    bool valid;
} IA64TemplateInfo;

typedef struct IA64DecodedBundle {
    uint8_t tmpl;
    uint64_t slot[IA64_SLOT_COUNT];
    const IA64TemplateInfo *info;
    bool valid;
} IA64DecodedBundle;

const IA64TemplateInfo *ia64_template_info(uint8_t tmpl);
const char *ia64_slot_type_name(IA64SlotType type);

bool ia64_decode_bundle(const uint8_t bundle[IA64_BUNDLE_SIZE],
                        IA64DecodedBundle *decoded);
bool ia64_decode_bundle_words(uint64_t lo, uint64_t hi,
                              IA64DecodedBundle *decoded);
void ia64_format_decoded_bundle(const IA64DecodedBundle *decoded,
                                char *buf, size_t buflen);

#endif
