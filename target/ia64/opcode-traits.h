/*
 * IA-64 typed-opcode ownership and architectural trait inventory.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef TARGET_IA64_OPCODE_TRAITS_H
#define TARGET_IA64_OPCODE_TRAITS_H

#include "target/ia64/decode.h"

typedef enum IA64OpcodeState {
    IA64_OPCODE_STATE_NONE        = 0,
    IA64_OPCODE_STATE_GR          = 1U << 0,
    IA64_OPCODE_STATE_PR          = 1U << 1,
    IA64_OPCODE_STATE_BR          = 1U << 2,
    IA64_OPCODE_STATE_AR          = 1U << 3,
    IA64_OPCODE_STATE_CR          = 1U << 4,
    IA64_OPCODE_STATE_FR          = 1U << 5,
    IA64_OPCODE_STATE_PSR         = 1U << 6,
    IA64_OPCODE_STATE_CFM         = 1U << 7,
    IA64_OPCODE_STATE_RSE         = 1U << 8,
    IA64_OPCODE_STATE_MEMORY      = 1U << 9,
    IA64_OPCODE_STATE_ALAT        = 1U << 10,
    IA64_OPCODE_STATE_TRANSLATION = 1U << 11,
    IA64_OPCODE_STATE_IP          = 1U << 12,
    IA64_OPCODE_STATE_INTERRUPT   = 1U << 13,
    IA64_OPCODE_STATE_CONTROL     = 1U << 14,
} IA64OpcodeState;

typedef enum IA64OpcodePredication {
    IA64_OPCODE_PREDICATION_NONE,
    IA64_OPCODE_PREDICATION_NORMAL,
    IA64_OPCODE_PREDICATION_SPECIAL,
} IA64OpcodePredication;

typedef enum IA64OpcodeNaTRule {
    IA64_OPCODE_NAT_NONE,
    IA64_OPCODE_NAT_PROPAGATE,
    IA64_OPCODE_NAT_CONSUME,
    IA64_OPCODE_NAT_MEMORY,
    IA64_OPCODE_NAT_SPECIAL,
} IA64OpcodeNaTRule;

typedef enum IA64OpcodeFault {
    IA64_OPCODE_FAULT_NONE       = 0,
    IA64_OPCODE_FAULT_EXPLICIT   = 1U << 0,
    IA64_OPCODE_FAULT_NAT        = 1U << 1,
    IA64_OPCODE_FAULT_MEMORY     = 1U << 2,
    IA64_OPCODE_FAULT_PRIVILEGED = 1U << 3,
    IA64_OPCODE_FAULT_FP         = 1U << 4,
    IA64_OPCODE_FAULT_RSE        = 1U << 5,
} IA64OpcodeFault;

typedef enum IA64OpcodeTbBehavior {
    IA64_OPCODE_TB_CONTINUE,
    IA64_OPCODE_TB_CONTROL_FLOW,
    IA64_OPCODE_TB_SERIALIZE,
    IA64_OPCODE_TB_INTERRUPTION_RETURN,
} IA64OpcodeTbBehavior;

typedef enum IA64OpcodeFamily {
#define IA64_OPCODE_FAMILY(_id, _name, _sources, _destinations,       \
                           _predication, _nat, _faults, _tb)          \
    IA64_OPCODE_FAMILY_##_id,
#include "opcode-families.def"
#undef IA64_OPCODE_FAMILY
    IA64_OPCODE_FAMILY_COUNT,
} IA64OpcodeFamily;

typedef struct IA64OpcodeFamilyTraits {
    const char *name;
    uint32_t sources;
    uint32_t destinations;
    IA64OpcodePredication predication;
    IA64OpcodeNaTRule nat_rule;
    uint32_t may_fault;
    IA64OpcodeTbBehavior tb_behavior;
} IA64OpcodeFamilyTraits;

typedef enum IA64OpcodeLoweringOwner {
    IA64_OPCODE_OWNER_ILLEGAL,
    IA64_OPCODE_OWNER_CANONICAL_ALIAS,
    IA64_OPCODE_OWNER_LEGACY_ORACLE,
    IA64_OPCODE_OWNER_DIRECT_TCG,
    IA64_OPCODE_OWNER_FOCUSED_HELPER,
} IA64OpcodeLoweringOwner;

typedef enum IA64OpcodeHelper {
    IA64_OPCODE_HELPER_NONE,
    IA64_OPCODE_HELPER_CALL_FRAME,
    IA64_OPCODE_HELPER_RETURN_FRAME,
    IA64_OPCODE_HELPER_RFI,
    IA64_OPCODE_HELPER_RSE_SPINE,
    IA64_OPCODE_HELPER_SPECIAL_LDST,
    IA64_OPCODE_HELPER_ATOMIC,
    IA64_OPCODE_HELPER_DATA_PLANE,
    IA64_OPCODE_HELPER_SYSTEM_PLANE,
} IA64OpcodeHelper;

typedef enum IA64OpcodeTestOwner {
    IA64_OPCODE_TEST_NONE,
    IA64_OPCODE_TEST_DECODE,
    IA64_OPCODE_TEST_FULL_TCG,
    IA64_OPCODE_TEST_RSE,
    IA64_OPCODE_TEST_DATA_PLANE,
} IA64OpcodeTestOwner;

typedef enum IA64OpcodeEvidence {
    IA64_OPCODE_EVIDENCE_NONE,
    IA64_OPCODE_EVIDENCE_DECODE,
    IA64_OPCODE_EVIDENCE_MEMORY,
    IA64_OPCODE_EVIDENCE_RSE,
    IA64_OPCODE_EVIDENCE_NO_OS,
    IA64_OPCODE_EVIDENCE_SNAPSHOT,
} IA64OpcodeEvidence;

typedef enum IA64OpcodeLifecycle {
    IA64_OPCODE_LIFECYCLE_ILLEGAL,
    IA64_OPCODE_LIFECYCLE_DEAD_ALIAS,
    IA64_OPCODE_LIFECYCLE_OPEN,
    IA64_OPCODE_LIFECYCLE_TYPED,
    IA64_OPCODE_LIFECYCLE_TYPED_PARTIAL,
} IA64OpcodeLifecycle;

typedef enum IA64OpcodeAdmission {
    IA64_OPCODE_ADMISSION_NOT_APPLICABLE,
    IA64_OPCODE_ADMISSION_NONE,
    IA64_OPCODE_ADMISSION_PARTIAL,
    IA64_OPCODE_ADMISSION_FULL,
} IA64OpcodeAdmission;

typedef enum IA64OpcodeClosure {
    IA64_OPCODE_CLOSURE_NOT_APPLICABLE,
    IA64_OPCODE_CLOSURE_ALIAS_CANONICALIZED,
    IA64_OPCODE_CLOSURE_OPEN,
    IA64_OPCODE_CLOSURE_FOCUSED_VERIFIED,
    IA64_OPCODE_CLOSURE_CLOSED,
} IA64OpcodeClosure;

typedef struct IA64OpcodeTraits {
    IA64Opcode opcode;
    const char *name;
    const IA64OpcodeFamilyTraits *family;
    IA64OpcodeLoweringOwner lowering_owner;
    IA64OpcodeHelper helper_whitelist;
    IA64OpcodeTestOwner test_owner;
    IA64OpcodeEvidence exception_evidence;
    IA64OpcodeEvidence system_evidence;
    IA64OpcodeLifecycle lifecycle;
    IA64OpcodeAdmission admission;
    IA64OpcodeClosure closure;
    bool decoder_live;
    bool legacy_oracle;
    bool reference_tcg;
} IA64OpcodeTraits;

extern const IA64OpcodeFamilyTraits
    ia64_opcode_family_traits[IA64_OPCODE_FAMILY_COUNT];
extern const IA64OpcodeTraits ia64_opcode_traits[IA64_OP_COUNT];

const IA64OpcodeTraits *ia64_opcode_traits_for(IA64Opcode opcode);

#endif /* TARGET_IA64_OPCODE_TRAITS_H */
