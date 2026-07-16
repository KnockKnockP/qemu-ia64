/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IA64_INSN_H
#define IA64_INSN_H

/*
 * Architectural state transactions used by the typed IA-64 runtime.
 *
 * This interface deliberately contains no encoded-instruction fields, slot
 * predicates, legacy executors, or bundle-dispatch reports.
 */

#include "cpu.h"
#include "bundle.h"
#include "mem.h"

#define IA64_STACKED_GR_MASK (IA64_STACKED_GR_COUNT - 1)
#define IA64_RNAT_VALID_MASK (~(UINT64_C(1) << 63))
#define IA64_RSE_PHYS_STACKED_REGS 96

#ifndef IA64_PSR_DA_BIT
#define IA64_PSR_DA_BIT (UINT64_C(1) << 38)
#define IA64_PSR_DD_BIT (UINT64_C(1) << 39)
#endif

#if (IA64_STACKED_GR_COUNT & IA64_STACKED_GR_MASK) != 0
#error "IA64_STACKED_GR_COUNT must remain a power of two"
#endif

static inline uint32_t ia64_rse_wrap_slot(uint32_t slot)
{
    return slot & IA64_STACKED_GR_MASK;
}

typedef uint64_t (*IA64RSEReadRegisterFn)(CPUIA64State *env,
                                          uint64_t address,
                                          void *opaque);
typedef void (*IA64RSEWriteRegisterFn)(CPUIA64State *env, uint64_t address,
                                       uint64_t value, void *opaque);
typedef bool (*IA64RSEReadWordFn)(CPUIA64State *env, uint64_t address,
                                  uint64_t *value, void *opaque);
typedef bool (*IA64RSEInterruptionPendingFn)(CPUIA64State *env,
                                             void *opaque);

typedef enum IA64RSEStepResult {
    IA64_RSE_STEP_DONE,
    IA64_RSE_STEP_PROGRESS,
    IA64_RSE_STEP_FAULT,
    IA64_RSE_STEP_INTERRUPTION,
} IA64RSEStepResult;

typedef enum IA64RSEAllocValidation {
    IA64_RSE_ALLOC_VALID,
    IA64_RSE_ALLOC_ILLEGAL_OPERATION,
    IA64_RSE_ALLOC_RESERVED_REGISTER_FIELD,
} IA64RSEAllocValidation;

/* Normalized comparison relation used by typed integer lowering. */
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

/* Implemented by the restartable RSE helper layer. */
void ia64_rse_spill_for_alloc(CPUIA64State *env, uint32_t new_sof);
void ia64_rse_complete_frame_loads(CPUIA64State *env);
void ia64_exec_flushrs(CPUIA64State *env);
void ia64_exec_loadrs(CPUIA64State *env);

void ia64_cpu_init_synthetic_cpuid(CPUIA64State *env);

bool ia64_issue_group_preserve_ar_source(CPUIA64State *env, uint32_t reg,
                                         uint64_t entry_value);

uint64_t ia64_issue_group_select_ar_source(const CPUIA64State *env,
                                           uint32_t reg,
                                           uint64_t live_value);

void ia64_cpu_reset_synthetic_itanium2(CPUIA64State *env);

void ia64_deliver_break_interruption(CPUIA64State *env, uint64_t iim,
                                     uint64_t *next_ip, const char *detail);

bool ia64_try_platform_break(CPUIA64State *env, uint64_t iim);

void ia64_deliver_disabled_fp_interruption(CPUIA64State *env, bool high,
                                           uint64_t *next_ip);

bool ia64_pal_uses_stacked_calling_convention(uint64_t function_id);

uint64_t ia64_make_cfm(uint32_t sof, uint32_t sol, uint32_t sor);

void ia64_set_cfm(CPUIA64State *env, uint64_t cfm);

uint32_t ia64_rse_num_regs(uint64_t bspstore, uint64_t bsp);

uint64_t ia64_rse_skip_regs(uint64_t addr, int64_t num_regs);

uint32_t ia64_rse_wrap_physical(int32_t physical);

uint32_t ia64_rse_physical_to_storage(const CPUIA64State *env,
                                      uint32_t physical);

uint32_t ia64_rse_bof_offset_to_storage(const CPUIA64State *env,
                                        int32_t offset);

bool ia64_rse_partitions_valid(const CPUIA64State *env);

void ia64_rse_check_partitions(const CPUIA64State *env, const char *site);

bool ia64_rse_address_is_rnat_slot(uint64_t address);

uint32_t ia64_rse_nat_collection_bit(uint64_t address);

bool ia64_rse_mandatory_store_step(CPUIA64State *env,
                                   IA64RSEWriteRegisterFn write_word,
                                   void *opaque, bool *stored_register);

IA64RSEStepResult ia64_rse_spill_excess_dirty_interruptible(
    CPUIA64State *env, uint32_t new_sof,
    IA64RSEWriteRegisterFn write_register,
    IA64RSEInterruptionPendingFn interruption_pending, void *opaque,
    uint32_t *spilled_registers);

uint32_t ia64_rse_spill_excess_dirty(CPUIA64State *env, uint32_t new_sof,
                                     IA64RSEWriteRegisterFn write_register,
                                     void *opaque);

IA64RSEStepResult ia64_rse_flush_dirty_interruptible(
    CPUIA64State *env, IA64RSEWriteRegisterFn write_register,
    IA64RSEInterruptionPendingFn interruption_pending, void *opaque);

IA64RSEStepResult ia64_rse_mandatory_load_step(
    CPUIA64State *env, IA64RSEReadWordFn read_word, void *opaque);

IA64RSEStepResult ia64_rse_complete_mandatory_loads_interruptible(
    CPUIA64State *env, IA64RSEReadWordFn read_word,
    IA64RSEInterruptionPendingFn interruption_pending, void *opaque);

IA64RSEStepResult ia64_rse_complete_mandatory_loads(
    CPUIA64State *env, IA64RSEReadWordFn read_word, void *opaque);

void ia64_rse_reconstruct_partitions(CPUIA64State *env);

void ia64_rse_reconstruct_transients(CPUIA64State *env);

void ia64_rse_sync_logical_out(CPUIA64State *env);

void ia64_rse_sync_logical_in(CPUIA64State *env);

uint64_t ia64_read_gr(CPUIA64State *env, uint32_t reg);

void ia64_alat_set_valid(CPUIA64State *env, unsigned index, bool valid);

void ia64_alat_reconstruct_transients(CPUIA64State *env);

void ia64_alat_invalidate_all(CPUIA64State *env);

void ia64_alat_invalidate_gr(CPUIA64State *env, uint32_t reg);

void ia64_alat_invalidate_fr(CPUIA64State *env, uint32_t reg);

void ia64_alat_record_gr(CPUIA64State *env, uint32_t target,
                         uint64_t address, uint8_t width, bool physical);

void ia64_alat_record_fr(CPUIA64State *env, uint32_t target,
                         uint64_t address, uint8_t width, bool physical);

bool ia64_alat_check_gr(CPUIA64State *env, uint32_t reg, uint64_t address,
                        uint8_t width, bool physical, bool clear);

bool ia64_alat_check_fr(CPUIA64State *env, uint32_t reg, uint64_t address,
                        uint8_t width, bool physical, bool clear);

bool ia64_alat_test_gr(CPUIA64State *env, uint32_t reg, bool clear);

bool ia64_alat_test_fr(CPUIA64State *env, uint32_t reg, bool clear);

void ia64_write_gr(CPUIA64State *env, uint32_t reg, uint64_t value);

void ia64_preserve_fr_source(CPUIA64State *env, uint32_t reg);

const IA64FloatReg *ia64_read_fr_ordinary(CPUIA64State *env, uint32_t reg);

void ia64_note_fr_write(CPUIA64State *env, uint32_t reg);

/* Architectural floating-memory payload encodings shared by TCG and helpers. */
typedef enum IA64FloatingMemoryFormat {
    IA64_FLOAT_FMT_EXTENDED,
    IA64_FLOAT_FMT_SIGNIFICAND,
    IA64_FLOAT_FMT_SINGLE,
    IA64_FLOAT_FMT_DOUBLE,
    IA64_FLOAT_FMT_SPILL_FILL,
} IA64FloatingMemoryFormat;

void ia64_float_reg_to_spill(const IA64FloatReg *reg,
                             uint64_t *sign_exponent,
                             uint64_t *mantissa);

void ia64_float_reg_from_spill(uint64_t sign_exponent, uint64_t mantissa,
                               IA64FloatReg *reg);

void ia64_write_fr_natval(CPUIA64State *env, uint32_t reg);

void ia64_write_fr_from_single_bits(CPUIA64State *env, uint32_t reg,
                                    uint32_t bits);

void ia64_write_fr_from_double_bits(CPUIA64State *env, uint32_t reg,
                                    uint64_t bits);

uint32_t ia64_read_fr_as_single_bits(const IA64FloatReg *reg);

uint64_t ia64_read_fr_as_double_bits(const IA64FloatReg *reg);

IA64RSEAllocValidation ia64_rse_validate_alloc(
    const CPUIA64State *env, uint8_t r1, uint32_t sof, uint32_t sol,
    uint32_t sor, uint8_t qp);

uint64_t ia64_rse_commit_alloc(CPUIA64State *env, uint8_t r1,
                               uint32_t sof, uint32_t sol, uint32_t sor);

bool ia64_rse_loadrs_is_legal(const CPUIA64State *env);

IA64RSEStepResult ia64_rse_execute_loadrs_interruptible(
    CPUIA64State *env, IA64RSEReadWordFn read_word,
    IA64RSEInterruptionPendingFn interruption_pending, void *opaque);

uint64_t ia64_read_application_register(CPUIA64State *env, uint32_t reg);

void ia64_write_application_register(CPUIA64State *env, uint32_t reg,
                                     uint64_t value);

bool ia64_psr_user_mask_value_valid(uint64_t value);

uint64_t ia64_psr_write_user_mask_value(uint64_t old_psr, uint64_t value);

void ia64_itc_sync(CPUIA64State *env);

void ia64_itc_set(CPUIA64State *env, uint64_t value);

void ia64_itc_warp_to(CPUIA64State *env, uint64_t target);

void ia64_itc_timer_update(CPUIA64State *env);

bool ia64_itc_timer_poll(CPUIA64State *env);

bool ia64_timer_interrupt_due(CPUIA64State *env);

void ia64_latch_timer_interrupt(CPUIA64State *env);

bool ia64_queue_external_interrupt(CPUIA64State *env, uint64_t vector);

bool ia64_external_interrupt_pending(CPUIA64State *env);

bool ia64_external_interrupt_enabled(CPUIA64State *env);

void ia64_refresh_interrupt_delivery(CPUIA64State *env);

void ia64_reconcile_interrupt_state(CPUIA64State *env);

uint64_t ia64_read_control_register(CPUIA64State *env, uint32_t reg);

void ia64_write_control_register(CPUIA64State *env, uint32_t reg,
                                 uint64_t value);

bool ia64_rse_read_physical_nat(CPUIA64State *env, uint32_t slot);

void ia64_rse_write_physical_nat(CPUIA64State *env, uint32_t slot, bool nat);

void ia64_rse_sync_rnat(CPUIA64State *env);

void ia64_rse_write_rnat(CPUIA64State *env, uint64_t value);

void ia64_rse_clear_rnat(CPUIA64State *env);

bool ia64_read_gr_nat(CPUIA64State *env, uint32_t reg);

void ia64_write_gr_nat(CPUIA64State *env, uint32_t reg, bool nat);

void ia64_rotate_modulo_scheduled_registers(CPUIA64State *env);

void ia64_rse_cover_frame(CPUIA64State *env);

void ia64_rse_clear_rename_bases(CPUIA64State *env, bool predicate_only);

void ia64_enter_call_frame(CPUIA64State *env);

bool ia64_rse_return_frame_from_pfs(CPUIA64State *env, uint64_t pfs);

bool ia64_rse_return_frame_from_ifs(CPUIA64State *env, uint64_t ifs);

void ia64_rfi_restore_state(CPUIA64State *env, uint64_t source_ip);

bool ia64_return_from_call_frame(CPUIA64State *env, uint64_t target_ip);

void ia64_branch_call_effects(CPUIA64State *env, uint32_t b1,
                              uint64_t bundle_ip);

#endif
