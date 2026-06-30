/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IA64_TCG_SKELETON_H
#define IA64_TCG_SKELETON_H

#include "bundle.h"

typedef enum IA64TcgTbBoundary {
    IA64_TCG_TB_BOUNDARY_NONE,
    IA64_TCG_TB_BOUNDARY_INVALID_TEMPLATE,
    IA64_TCG_TB_BOUNDARY_EFI_CALL_GATE,
    IA64_TCG_TB_BOUNDARY_BREAK,
    IA64_TCG_TB_BOUNDARY_SPECULATION_CHECK,
    IA64_TCG_TB_BOUNDARY_VIRTUAL_TRANSLATION,
    IA64_TCG_TB_BOUNDARY_BRANCH,
    IA64_TCG_TB_BOUNDARY_CPU_STATE,
    IA64_TCG_TB_BOUNDARY_TRANSLATION_STATE,
    IA64_TCG_TB_BOUNDARY_RSE_STATE,
} IA64TcgTbBoundary;

/*
 * P03 keeps IA-64 execution conservative: the translator decodes bundles into
 * real QEMU TBs, but still calls the correct bundle helper for semantics.  TBs
 * may contain multiple fall-through bundles only while the following state is
 * stable for already-translated code:
 *
 * - template, slot order, stop bits, and instruction-group boundaries;
 * - instruction fetch mapping and page boundary;
 * - PSR bits represented in TB flags, including IT/DT-sensitive state;
 * - precise exception bundle address plus PSR.ri slot position;
 * - branch, RSE, and translation-control state.
 *
 * Future TCG fast paths should use this module as the single boundary policy
 * before lowering individual slots.
 */
IA64TcgTbBoundary ia64_tcg_tb_boundary_for_bundle(
    const IA64DecodedBundle *bundle, uint64_t pc);
const char *ia64_tcg_tb_boundary_name(IA64TcgTbBoundary boundary);
bool ia64_tcg_tb_boundary_ends_tb(IA64TcgTbBoundary boundary);
bool ia64_tcg_pc_is_efi_call_gate(uint64_t pc);

typedef enum IA64TcgFallbackReason {
    IA64_TCG_FALLBACK_NONE,
    IA64_TCG_FALLBACK_INVALID_TEMPLATE,
    IA64_TCG_FALLBACK_BOUNDARY_EFI_CALL_GATE,
    IA64_TCG_FALLBACK_BOUNDARY_BREAK,
    IA64_TCG_FALLBACK_BOUNDARY_SPECULATION_CHECK,
    IA64_TCG_FALLBACK_BOUNDARY_VIRTUAL_TRANSLATION,
    IA64_TCG_FALLBACK_BOUNDARY_BRANCH,
    IA64_TCG_FALLBACK_BOUNDARY_CPU_STATE,
    IA64_TCG_FALLBACK_BOUNDARY_TRANSLATION_STATE,
    IA64_TCG_FALLBACK_BOUNDARY_RSE_STATE,
    IA64_TCG_FALLBACK_FAST_LONG_IMMEDIATE,
    IA64_TCG_FALLBACK_FAST_PREDICATED_SLOT,
    IA64_TCG_FALLBACK_FAST_STATIC_GR,
    IA64_TCG_FALLBACK_FAST_LDST_SLOT,
    IA64_TCG_FALLBACK_FAST_LDST_TRACE,
    IA64_TCG_FALLBACK_FAST_LDST_REGISTER_UPDATE,
    IA64_TCG_FALLBACK_FAST_LDST_MEMORY_CLASS,
    IA64_TCG_FALLBACK_FAST_LDST_DEPENDENCY,
    IA64_TCG_FALLBACK_FAST_LDST_TARGET,
    IA64_TCG_FALLBACK_FAST_UNSUPPORTED_SLOT,
    IA64_TCG_FALLBACK_RUNTIME_GUARD,
    IA64_TCG_FALLBACK_COUNT,
} IA64TcgFallbackReason;

IA64TcgFallbackReason ia64_tcg_fallback_reason_for_bundle(
    const IA64DecodedBundle *bundle, uint64_t pc);
const char *ia64_tcg_fallback_reason_name(IA64TcgFallbackReason reason);

typedef enum IA64TcgFastOp {
    IA64_TCG_FAST_OP_NOP,
    IA64_TCG_FAST_OP_ALU_ADD,
    IA64_TCG_FAST_OP_ALU_SUB,
    IA64_TCG_FAST_OP_ALU_LOGIC,
    IA64_TCG_FAST_OP_ALU_ADDP4,
    IA64_TCG_FAST_OP_ALU_SHLADD,
    IA64_TCG_FAST_OP_ADDL,
    IA64_TCG_FAST_OP_COMPARE,
    IA64_TCG_FAST_OP_EXTRACT,
    IA64_TCG_FAST_OP_DEPOSIT,
    IA64_TCG_FAST_OP_INTEGER_EXTEND,
    IA64_TCG_FAST_OP_PREDICATE_TEST,
    IA64_TCG_FAST_OP_BIT_COUNT,
    IA64_TCG_FAST_OP_VARIABLE_SHIFT,
    IA64_TCG_FAST_OP_LDST_LOAD,
    IA64_TCG_FAST_OP_LDST_STORE,
} IA64TcgFastOp;

typedef enum IA64TcgFastLogicOp {
    IA64_TCG_FAST_LOGIC_AND,
    IA64_TCG_FAST_LOGIC_ANDCM,
    IA64_TCG_FAST_LOGIC_OR,
    IA64_TCG_FAST_LOGIC_XOR,
} IA64TcgFastLogicOp;

typedef enum IA64TcgFastShiftKind {
    IA64_TCG_FAST_SHIFT_RIGHT_UNSIGNED,
    IA64_TCG_FAST_SHIFT_LEFT,
    IA64_TCG_FAST_SHIFT_RIGHT_SIGNED,
} IA64TcgFastShiftKind;

typedef struct IA64TcgFastSlot {
    IA64TcgFastOp op;
    IA64TcgFastLogicOp logic_op;
    uint8_t target;
    uint8_t source2;
    uint8_t source3;
    uint8_t qualifying_predicate;
    uint8_t base;
    uint8_t width;
    uint8_t slot_index;
    uint8_t predicate1;
    uint8_t predicate2;
    uint8_t compare_relation;
    uint8_t predicate_write_kind;
    uint8_t predicate_test_kind;
    uint8_t predicate_test_relation;
    uint8_t integer_extend_kind;
    uint8_t shift_kind;
    uint8_t position;
    uint8_t length;
    bool source2_immediate;
    bool base_update;
    bool sign_extend;
    bool deposit_zero;
    bool addp4;
    int64_t immediate;
    uint64_t source_nat_mask;
    uint64_t dest_mask;
} IA64TcgFastSlot;

typedef struct IA64TcgFastBundle {
    IA64TcgFastSlot slot[IA64_SLOT_COUNT];
    uint32_t slot_count;
    uint32_t op_counts;
    uint64_t source_nat_mask;
    uint64_t dest_mask;
} IA64TcgFastBundle;

bool ia64_tcg_build_fast_bundle(const IA64DecodedBundle *bundle,
                                IA64TcgFastBundle *fast);
bool ia64_tcg_bundle_has_ldst_immediate(const IA64DecodedBundle *bundle);

typedef enum IA64TcgFallbackPlanOp {
    IA64_TCG_FALLBACK_PLAN_GENERIC,
    IA64_TCG_FALLBACK_PLAN_ALLOC,
    IA64_TCG_FALLBACK_PLAN_MOV_FROM_BRANCH,
    IA64_TCG_FALLBACK_PLAN_MOV_TO_BRANCH,
    IA64_TCG_FALLBACK_PLAN_MOV_TO_APPLICATION,
    IA64_TCG_FALLBACK_PLAN_MOV_FROM_APPLICATION,
    IA64_TCG_FALLBACK_PLAN_MOV_TO_APPLICATION_IMM,
    IA64_TCG_FALLBACK_PLAN_EXTRACT,
    IA64_TCG_FALLBACK_PLAN_DEPOSIT,
    IA64_TCG_FALLBACK_PLAN_INTEGER_EXTEND,
    IA64_TCG_FALLBACK_PLAN_FLOATING_MEMORY,
    IA64_TCG_FALLBACK_PLAN_LDST_IMMEDIATE,
    IA64_TCG_FALLBACK_PLAN_COMPARE,
    IA64_TCG_FALLBACK_PLAN_PREDICATE_TEST,
    IA64_TCG_FALLBACK_PLAN_ALU_ADD,
    IA64_TCG_FALLBACK_PLAN_ALU_SUB,
    IA64_TCG_FALLBACK_PLAN_ALU_LOGIC,
    IA64_TCG_FALLBACK_PLAN_ALU_ADDP4,
    IA64_TCG_FALLBACK_PLAN_ALU_SHLADD,
    IA64_TCG_FALLBACK_PLAN_I_PACKED_I2,
    IA64_TCG_FALLBACK_PLAN_I_MUX,
    IA64_TCG_FALLBACK_PLAN_I_BIT_COUNT,
    IA64_TCG_FALLBACK_PLAN_I_VARIABLE_SHIFT,
    IA64_TCG_FALLBACK_PLAN_ADDL,
    IA64_TCG_FALLBACK_PLAN_BRANCH_RELATIVE,
    IA64_TCG_FALLBACK_PLAN_BRANCH_CALL_RELATIVE,
    IA64_TCG_FALLBACK_PLAN_BRANCH_INDIRECT,
    IA64_TCG_FALLBACK_PLAN_BRANCH_PREDICT_OR_NOP,
} IA64TcgFallbackPlanOp;

#define IA64_TCG_FALLBACK_PLAN_SLOT_BITS 8
#define IA64_TCG_FALLBACK_PLAN_SLOT_MASK 0xffu

static inline IA64TcgFallbackPlanOp ia64_tcg_fallback_plan_slot(
    uint32_t plan, unsigned slot)
{
    return (IA64TcgFallbackPlanOp)
        ((plan >> (slot * IA64_TCG_FALLBACK_PLAN_SLOT_BITS)) &
         IA64_TCG_FALLBACK_PLAN_SLOT_MASK);
}

uint32_t ia64_tcg_fallback_plan_for_bundle(const IA64DecodedBundle *bundle);

typedef struct IA64TcgDirectBranch {
    IA64TcgFastBundle prefix;
    uint64_t target_ip;
    uint64_t fallthrough_ip;
    uint8_t slot;
    uint8_t predicate;
    uint8_t nop_count;
    bool conditional;
} IA64TcgDirectBranch;

bool ia64_tcg_build_direct_branch(const IA64DecodedBundle *bundle,
                                  uint64_t pc,
                                  IA64TcgDirectBranch *branch);
bool ia64_tcg_bundle_has_direct_branch(const IA64DecodedBundle *bundle);
bool ia64_tcg_bundle_has_indirect_branch(const IA64DecodedBundle *bundle);

#endif
