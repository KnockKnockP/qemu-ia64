/*
 * IA-64 typed-opcode ownership and architectural trait inventory.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "target/ia64/opcode-traits.h"

const IA64OpcodeFamilyTraits
ia64_opcode_family_traits[IA64_OPCODE_FAMILY_COUNT] = {
#define IA64_OPCODE_FAMILY(_id, _name, _sources, _destinations,       \
                           _predication, _nat, _faults, _tb)          \
    [IA64_OPCODE_FAMILY_##_id] = {                                   \
        .name = (_name),                                             \
        .sources = (_sources),                                       \
        .destinations = (_destinations),                             \
        .predication = (_predication),                               \
        .nat_rule = (_nat),                                          \
        .may_fault = (_faults),                                      \
        .tb_behavior = (_tb),                                        \
    },
#include "opcode-families.def"
#undef IA64_OPCODE_FAMILY
};

#define IA64_LIFECYCLE_ILLEGAL_ADMISSION IA64_OPCODE_ADMISSION_NOT_APPLICABLE
#define IA64_LIFECYCLE_DEAD_ALIAS_ADMISSION \
    IA64_OPCODE_ADMISSION_NOT_APPLICABLE
#define IA64_LIFECYCLE_OPEN_ADMISSION IA64_OPCODE_ADMISSION_NONE
#define IA64_LIFECYCLE_TYPED_ADMISSION IA64_OPCODE_ADMISSION_FULL
#define IA64_LIFECYCLE_TYPED_PARTIAL_ADMISSION IA64_OPCODE_ADMISSION_PARTIAL

#define IA64_LIFECYCLE_ILLEGAL_CLOSURE IA64_OPCODE_CLOSURE_NOT_APPLICABLE
#define IA64_LIFECYCLE_DEAD_ALIAS_CLOSURE \
    IA64_OPCODE_CLOSURE_ALIAS_CANONICALIZED
#define IA64_LIFECYCLE_OPEN_CLOSURE IA64_OPCODE_CLOSURE_OPEN
#define IA64_LIFECYCLE_TYPED_CLOSURE IA64_OPCODE_CLOSURE_CLOSED
#define IA64_LIFECYCLE_TYPED_PARTIAL_CLOSURE \
    IA64_OPCODE_CLOSURE_FOCUSED_VERIFIED

#define IA64_LIFECYCLE_ILLEGAL_DECODER_LIVE false
#define IA64_LIFECYCLE_DEAD_ALIAS_DECODER_LIVE false
#define IA64_LIFECYCLE_OPEN_DECODER_LIVE true
#define IA64_LIFECYCLE_TYPED_DECODER_LIVE true
#define IA64_LIFECYCLE_TYPED_PARTIAL_DECODER_LIVE true

#define IA64_LIFECYCLE_ILLEGAL_ORACLE false
#define IA64_LIFECYCLE_DEAD_ALIAS_ORACLE false
#define IA64_LIFECYCLE_OPEN_ORACLE true
#define IA64_LIFECYCLE_TYPED_ORACLE true
#define IA64_LIFECYCLE_TYPED_PARTIAL_ORACLE true

enum {
    IA64_OPCODE_TRAIT_ROW_COUNT = 0
#define IA64_OPCODE(_opcode, _family, _owner, _helper, _test,          \
                    _exception, _system, _lifecycle)                   \
        + 1
#include "opcode-traits.def"
#undef IA64_OPCODE
};

_Static_assert((int)IA64_OPCODE_TRAIT_ROW_COUNT == (int)IA64_OP_COUNT,
               "IA-64 opcode trait row count must match IA64_OP_COUNT");

const IA64OpcodeTraits ia64_opcode_traits[IA64_OP_COUNT] = {
#define IA64_OPCODE(_opcode, _family, _owner, _helper, _test,          \
                    _exception, _system, _lifecycle)                   \
    [_opcode] = {                                                      \
        .opcode = (_opcode),                                           \
        .name = #_opcode,                                              \
        .family = &ia64_opcode_family_traits[                          \
            IA64_OPCODE_FAMILY_##_family],                             \
        .lowering_owner = IA64_OPCODE_OWNER_##_owner,                  \
        .helper_whitelist = IA64_OPCODE_HELPER_##_helper,              \
        .test_owner = IA64_OPCODE_TEST_##_test,                        \
        .exception_evidence = IA64_OPCODE_EVIDENCE_##_exception,       \
        .system_evidence = IA64_OPCODE_EVIDENCE_##_system,             \
        .lifecycle = IA64_OPCODE_LIFECYCLE_##_lifecycle,               \
        .admission = IA64_LIFECYCLE_##_lifecycle##_ADMISSION,          \
        .closure = IA64_LIFECYCLE_##_lifecycle##_CLOSURE,              \
        .decoder_live = IA64_LIFECYCLE_##_lifecycle##_DECODER_LIVE,    \
        .legacy_oracle = IA64_LIFECYCLE_##_lifecycle##_ORACLE,         \
        .reference_tcg = IA64_LIFECYCLE_##_lifecycle##_ORACLE,         \
    },
#include "opcode-traits.def"
#undef IA64_OPCODE
};

const IA64OpcodeTraits *ia64_opcode_traits_for(IA64Opcode opcode)
{
    if ((unsigned)opcode >= IA64_OP_COUNT) {
        return NULL;
    }
    return &ia64_opcode_traits[opcode];
}
