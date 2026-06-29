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

typedef enum IA64TcgFastOp {
    IA64_TCG_FAST_OP_NOP,
    IA64_TCG_FAST_OP_ALU_ADD,
    IA64_TCG_FAST_OP_ALU_LOGIC,
    IA64_TCG_FAST_OP_ADDL,
    IA64_TCG_FAST_OP_LDST_LOAD,
    IA64_TCG_FAST_OP_LDST_STORE,
} IA64TcgFastOp;

typedef enum IA64TcgFastLogicOp {
    IA64_TCG_FAST_LOGIC_AND,
    IA64_TCG_FAST_LOGIC_ANDCM,
    IA64_TCG_FAST_LOGIC_OR,
    IA64_TCG_FAST_LOGIC_XOR,
} IA64TcgFastLogicOp;

typedef struct IA64TcgFastSlot {
    IA64TcgFastOp op;
    IA64TcgFastLogicOp logic_op;
    uint8_t target;
    uint8_t source2;
    uint8_t source3;
    uint8_t base;
    uint8_t width;
    uint8_t slot_index;
    bool source2_immediate;
    bool base_update;
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

typedef struct IA64TcgDirectBranch {
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
