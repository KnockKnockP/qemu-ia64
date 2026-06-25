/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IA64_EXEC_SMOKE_H
#define IA64_EXEC_SMOKE_H

#include "cpu.h"
#include "bundle.h"

#define IA64_SMOKE_NOP_RAW 0x08000000ULL

typedef enum IA64ExecSmokeStatus {
    IA64_EXEC_SMOKE_OK,
    IA64_EXEC_SMOKE_RESERVED_TEMPLATE,
    IA64_EXEC_SMOKE_UNSUPPORTED_SLOT,
} IA64ExecSmokeStatus;

typedef struct IA64ExecSmokeReport {
    IA64ExecSmokeStatus status;
    IA64DecodedBundle bundle;
    uint64_t ip_before;
    uint64_t ip_after;
    int failed_slot;
    char message[160];
} IA64ExecSmokeReport;

typedef enum IA64LdstImmediateKind {
    IA64_LDST_IMM_LOAD,
    IA64_LDST_IMM_STORE,
    IA64_LDST_IMM_PREFETCH,
} IA64LdstImmediateKind;

typedef struct IA64LdstImmediate {
    IA64LdstImmediateKind kind;
    uint8_t width;
    uint8_t target;
    uint8_t source;
    uint8_t base;
    uint8_t update_source;
    uint8_t memory_class;
    bool base_update;
    bool update_from_register;
    int64_t immediate;
} IA64LdstImmediate;

typedef enum IA64CompareRelation {
    IA64_CMP_EQ,
    IA64_CMP_NE,
    IA64_CMP_LT,
    IA64_CMP_LE,
    IA64_CMP_GT,
    IA64_CMP_GE,
    IA64_CMP_LTU,
    IA64_CMP_LEU,
    IA64_CMP_GTU,
    IA64_CMP_GEU,
} IA64CompareRelation;

typedef enum IA64PredicateWriteKind {
    IA64_PRED_WRITE_NORMAL,
    IA64_PRED_WRITE_UNCONDITIONAL,
    IA64_PRED_WRITE_AND,
    IA64_PRED_WRITE_OR,
    IA64_PRED_WRITE_OR_ANDCM,
} IA64PredicateWriteKind;

typedef struct IA64CompareInstruction {
    IA64CompareRelation relation;
    IA64PredicateWriteKind write_kind;
    uint8_t width;
    uint8_t p1;
    uint8_t p2;
    uint8_t source2;
    uint8_t source3;
    bool source_immediate;
    int64_t immediate;
} IA64CompareInstruction;

void ia64_cpu_reset_synthetic_itanium2(CPUIA64State *env);

const char *ia64_exec_smoke_status_name(IA64ExecSmokeStatus status);
bool ia64_exec_smoke_slot_supported(IA64SlotType type, uint64_t raw);
uint64_t ia64_make_cfm(uint32_t sof, uint32_t sol, uint32_t sor);
bool ia64_slot_is_m34_alloc(IA64SlotType type, uint64_t raw);
bool ia64_exec_m34_alloc(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_i_nop(IA64SlotType type, uint64_t raw);
bool ia64_slot_is_i_mov_ip(IA64SlotType type, uint64_t raw);
bool ia64_exec_i_mov_ip(CPUIA64State *env, uint64_t raw, uint64_t bundle_ip);
bool ia64_slot_is_i_mov_from_branch(IA64SlotType type, uint64_t raw);
bool ia64_exec_i_mov_from_branch(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_i_mov_to_branch(IA64SlotType type, uint64_t raw);
bool ia64_exec_i_mov_to_branch(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_i_mov_from_predicate(IA64SlotType type, uint64_t raw);
bool ia64_exec_i_mov_from_predicate(CPUIA64State *env, uint64_t raw);
bool ia64_slot_pair_is_lx_movl(uint64_t l_raw, uint64_t x_raw);
uint64_t ia64_lx_movl_imm64(uint64_t l_raw, uint64_t x_raw);
bool ia64_exec_lx_movl(CPUIA64State *env, uint64_t l_raw, uint64_t x_raw);
bool ia64_slot_is_alu_add(IA64SlotType type, uint64_t raw);
bool ia64_exec_alu_add(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_addl(IA64SlotType type, uint64_t raw);
int64_t ia64_addl_immediate(uint64_t raw);
bool ia64_exec_addl(CPUIA64State *env, uint64_t raw);
bool ia64_decode_ldst_immediate(IA64SlotType type, uint64_t raw,
                                IA64LdstImmediate *decoded);
bool ia64_decode_compare(IA64SlotType type, uint64_t raw,
                         IA64CompareInstruction *decoded);
bool ia64_exec_compare(CPUIA64State *env,
                       const IA64CompareInstruction *decoded);
bool ia64_slot_is_b_branch_relative(IA64SlotType type, uint64_t raw);
bool ia64_slot_is_b_call_relative(IA64SlotType type, uint64_t raw);
bool ia64_slot_is_b_indirect_branch(IA64SlotType type, uint64_t raw);
bool ia64_slot_is_b_predict_or_nop(IA64SlotType type, uint64_t raw);
int64_t ia64_branch_displacement(uint64_t raw);
bool ia64_exec_b_branch_relative(CPUIA64State *env,
                                 uint64_t raw,
                                 uint64_t bundle_ip,
                                 uint64_t *target_ip);
bool ia64_exec_b_call_relative(CPUIA64State *env,
                               uint64_t raw,
                               uint64_t bundle_ip,
                               uint64_t *target_ip);
bool ia64_exec_b_indirect_branch(CPUIA64State *env,
                                 uint64_t raw,
                                 uint64_t *target_ip);
IA64ExecSmokeStatus
ia64_exec_smoke_bundle(CPUIA64State *env,
                       const uint8_t bundle[IA64_BUNDLE_SIZE],
                       IA64ExecSmokeReport *report);

#endif
