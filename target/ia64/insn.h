/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IA64_INSN_H
#define IA64_INSN_H

#include "cpu.h"
#include "bundle.h"
#include "mem.h"

#define IA64_INSN_NOP_RAW 0x08000000ULL
#define IA64_STACKED_GR_MASK (IA64_STACKED_GR_COUNT - 1)
#define IA64_RNAT_VALID_MASK (~(UINT64_C(1) << 63))

#if (IA64_STACKED_GR_COUNT & IA64_STACKED_GR_MASK) != 0
#error "IA64_STACKED_GR_COUNT must remain a power of two"
#endif

static inline uint32_t ia64_rse_wrap_slot(uint32_t slot)
{
    return slot & IA64_STACKED_GR_MASK;
}

typedef enum IA64InsnStatus {
    IA64_INSN_OK,
    IA64_INSN_RESERVED_TEMPLATE,
    IA64_INSN_UNSUPPORTED_SLOT,
} IA64InsnStatus;

typedef enum IA64VirtualTranslationStatus {
    IA64_VIRTUAL_TRANSLATION_UNSUPPORTED,
    IA64_VIRTUAL_TRANSLATION_OK,
    IA64_VIRTUAL_TRANSLATION_FAULT,
} IA64VirtualTranslationStatus;

typedef enum IA64ProbeStatus {
    IA64_PROBE_UNSUPPORTED,
    IA64_PROBE_OK,
    IA64_PROBE_FAULT,
} IA64ProbeStatus;

typedef struct IA64InsnReport {
    IA64InsnStatus status;
    IA64DecodedBundle bundle;
    uint64_t ip_before;
    uint64_t ip_after;
    int failed_slot;
    char message[160];
} IA64InsnReport;

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

static inline bool ia64_ldst_immediate_is_fill(
    const IA64LdstImmediate *decoded)
{
    return decoded &&
           decoded->kind == IA64_LDST_IMM_LOAD &&
           decoded->memory_class == 6 &&
           decoded->width == 8;
}

static inline bool ia64_ldst_immediate_is_spill(
    const IA64LdstImmediate *decoded)
{
    return decoded &&
           decoded->kind == IA64_LDST_IMM_STORE &&
           decoded->memory_class == 0x0e &&
           decoded->width == 8;
}

typedef enum IA64AtomicKind {
    IA64_ATOMIC_CMPXCHG,
    IA64_ATOMIC_XCHG,
    IA64_ATOMIC_FETCHADD,
} IA64AtomicKind;

typedef struct IA64AtomicInstruction {
    IA64AtomicKind kind;
    uint8_t width;
    uint8_t target;
    uint8_t source;
    uint8_t base;
    bool release;
    int64_t immediate;
} IA64AtomicInstruction;

typedef struct IA64CountedStoreLoop {
    IA64LdstImmediate store;
    uint64_t fallthrough_ip;
} IA64CountedStoreLoop;

typedef enum IA64FloatingMemoryKind {
    IA64_FLOAT_MEM_LOAD,
    IA64_FLOAT_MEM_LOAD_PAIR,
    IA64_FLOAT_MEM_STORE,
    IA64_FLOAT_MEM_PREFETCH,
} IA64FloatingMemoryKind;

typedef enum IA64FloatingMemoryFormat {
    IA64_FLOAT_FMT_EXTENDED,
    IA64_FLOAT_FMT_SIGNIFICAND,
    IA64_FLOAT_FMT_SINGLE,
    IA64_FLOAT_FMT_DOUBLE,
    IA64_FLOAT_FMT_SPILL_FILL,
} IA64FloatingMemoryFormat;

typedef struct IA64FloatingMemoryInstruction {
    IA64FloatingMemoryKind kind;
    IA64FloatingMemoryFormat format;
    uint8_t width;
    uint8_t freg;
    uint8_t freg2;
    uint8_t base;
    uint8_t update_source;
    uint8_t memory_class;
    bool base_update;
    bool update_from_register;
    int64_t immediate;
} IA64FloatingMemoryInstruction;

typedef enum IA64FloatingCompareRelation {
    IA64_FLOAT_CMP_EQ,
    IA64_FLOAT_CMP_LT,
    IA64_FLOAT_CMP_LE,
    IA64_FLOAT_CMP_UNORD,
} IA64FloatingCompareRelation;

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

typedef enum IA64PredicateTestKind {
    IA64_PRED_TEST_BIT,
    IA64_PRED_TEST_NAT,
    IA64_PRED_TEST_FEATURE,
} IA64PredicateTestKind;

typedef enum IA64PredicateTestRelation {
    IA64_PRED_TEST_ZERO,
    IA64_PRED_TEST_NONZERO,
} IA64PredicateTestRelation;

typedef struct IA64PredicateTestInstruction {
    IA64PredicateTestKind kind;
    IA64PredicateTestRelation relation;
    IA64PredicateWriteKind write_kind;
    uint8_t p1;
    uint8_t p2;
    uint8_t source3;
    uint8_t immediate;
} IA64PredicateTestInstruction;

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

typedef struct IA64FloatingCompareInstruction {
    IA64FloatingCompareRelation relation;
    IA64PredicateWriteKind write_kind;
    uint8_t status_field;
    uint8_t p1;
    uint8_t p2;
    uint8_t source2;
    uint8_t source3;
} IA64FloatingCompareInstruction;

typedef struct IA64FloatingClassInstruction {
    IA64PredicateWriteKind write_kind;
    uint8_t p1;
    uint8_t p2;
    uint8_t source2;
    uint16_t mask;
} IA64FloatingClassInstruction;

typedef struct IA64ExtractInstruction {
    uint8_t target;
    uint8_t source3;
    uint8_t position;
    uint8_t length;
    bool sign_extend;
} IA64ExtractInstruction;

typedef struct IA64DepositInstruction {
    uint8_t target;
    uint8_t source2;
    uint8_t source3;
    uint8_t position;
    uint8_t length;
    bool deposit_zero;
    bool source_immediate;
    uint64_t immediate;
} IA64DepositInstruction;

typedef enum IA64IntegerExtendKind {
    IA64_EXT_ZXT,
    IA64_EXT_SXT,
    IA64_EXT_CZX_LEFT,
    IA64_EXT_CZX_RIGHT,
} IA64IntegerExtendKind;

typedef struct IA64IntegerExtendInstruction {
    IA64IntegerExtendKind kind;
    uint8_t target;
    uint8_t source3;
    uint8_t width;
} IA64IntegerExtendInstruction;

void ia64_cpu_reset_synthetic_itanium2(CPUIA64State *env);
void ia64_cpu_init_synthetic_cpuid(CPUIA64State *env);
void ia64_note_successful_instruction(CPUIA64State *env, uint64_t bundle_ip,
                                      uint64_t pre_instruction_psr);
void ia64_deliver_break_interruption(CPUIA64State *env, uint64_t iim,
                                     uint64_t *next_ip, const char *detail);
bool ia64_try_platform_break(CPUIA64State *env, uint64_t iim);
void ia64_deliver_disabled_fp_interruption(CPUIA64State *env, bool high,
                                           uint64_t *next_ip);
bool ia64_slot_raises_disabled_fp(CPUIA64State *env, IA64SlotType type,
                                  uint64_t raw, bool *high);
void ia64_note_fr_write(CPUIA64State *env, uint32_t reg);
bool ia64_pal_uses_stacked_calling_convention(uint64_t function_id);

const char *ia64_insn_status_name(IA64InsnStatus status);
bool ia64_insn_slot_supported(IA64SlotType type, uint64_t raw);
uint64_t ia64_make_cfm(uint32_t sof, uint32_t sol, uint32_t sor);
void ia64_set_cfm(CPUIA64State *env, uint64_t cfm);
uint32_t ia64_rse_num_regs(uint64_t bspstore, uint64_t bsp);
uint64_t ia64_rse_skip_regs(uint64_t addr, int64_t num_regs);
void ia64_rse_reconstruct_transients(CPUIA64State *env);
void ia64_rse_mark_dirty_partition(CPUIA64State *env, uint32_t count);
void ia64_rse_set_dirty_partition(CPUIA64State *env, uint64_t start,
                                  uint64_t end);
uint64_t ia64_rse_reg_address(uint64_t address);
bool ia64_rse_address_is_rnat_slot(uint64_t address);
uint64_t ia64_rse_rnat_address(uint64_t address);
uint32_t ia64_rse_nat_collection_bit(uint64_t address);
uint32_t ia64_rse_dirty_partition_first_slot(CPUIA64State *env,
                                             uint32_t count);
bool ia64_rse_read_physical_nat(CPUIA64State *env, uint32_t slot);
void ia64_rse_write_physical_nat(CPUIA64State *env, uint32_t slot, bool nat);
void ia64_rse_sync_rnat(CPUIA64State *env);
void ia64_rse_write_rnat(CPUIA64State *env, uint64_t value);
void ia64_rse_clear_rnat(CPUIA64State *env);
void ia64_rse_sync_logical_out(CPUIA64State *env);
void ia64_rse_sync_logical_in(CPUIA64State *env);
void ia64_rotate_modulo_scheduled_registers(CPUIA64State *env);
/* Physical stacked register file capacity (r32-r127 on real hardware). */
#define IA64_RSE_PHYS_STACKED_REGS 96
#ifndef IA64_PSR_DA_BIT
#define IA64_PSR_DA_BIT (UINT64_C(1) << 38)
#define IA64_PSR_DD_BIT (UINT64_C(1) << 39)
#endif

/*
 * The migration-compatible backing arrays are larger than the architectural
 * physical file.  These helpers are the only supported conversion between an
 * architectural physical-register number and its storage slot.
 */
uint32_t ia64_rse_wrap_physical(int32_t physical);
uint32_t ia64_rse_physical_to_storage(const CPUIA64State *env,
                                      uint32_t physical);
uint32_t ia64_rse_bof_offset_to_storage(const CPUIA64State *env,
                                        int32_t offset);

bool ia64_rse_partitions_valid(const CPUIA64State *env);
void ia64_rse_check_partitions(const CPUIA64State *env, const char *site);
void ia64_rse_reconstruct_partitions(CPUIA64State *env);

typedef uint64_t (*IA64RSEReadRegisterFn)(CPUIA64State *env,
                                          uint64_t address,
                                          void *opaque);
typedef void (*IA64RSEWriteRegisterFn)(CPUIA64State *env, uint64_t address,
                                       uint64_t value, void *opaque);
typedef bool (*IA64RSEReadWordFn)(CPUIA64State *env, uint64_t address,
                                  uint64_t *value, void *opaque);

typedef enum IA64RSEStepResult {
    IA64_RSE_STEP_DONE,
    IA64_RSE_STEP_PROGRESS,
    IA64_RSE_STEP_FAULT,
} IA64RSEStepResult;

IA64RSEStepResult ia64_rse_mandatory_load_step(
    CPUIA64State *env, IA64RSEReadWordFn read_word, void *opaque);
IA64RSEStepResult ia64_rse_complete_mandatory_loads(
    CPUIA64State *env, IA64RSEReadWordFn read_word, void *opaque);
bool ia64_rse_mandatory_store_step(CPUIA64State *env,
                                   IA64RSEWriteRegisterFn write_word,
                                   void *opaque, bool *stored_register);
uint32_t ia64_rse_spill_excess_dirty(CPUIA64State *env, uint32_t new_sof,
                                     IA64RSEWriteRegisterFn write_register,
                                     void *opaque);
void ia64_rse_load_dirty_partition(CPUIA64State *env, uint64_t load_start,
                                   uint64_t load_end,
                                   IA64RSEReadRegisterFn read_register,
                                   void *opaque);
uint32_t ia64_rse_load_restored_frame(CPUIA64State *env, uint32_t count,
                                      IA64RSEReadRegisterFn read_register,
                                      void *opaque);
uint64_t ia64_read_gr(CPUIA64State *env, uint32_t reg);
void ia64_write_gr(CPUIA64State *env, uint32_t reg, uint64_t value);
bool ia64_read_gr_nat(CPUIA64State *env, uint32_t reg);
void ia64_write_gr_nat(CPUIA64State *env, uint32_t reg, bool nat);
void ia64_ldst_apply_base_update(CPUIA64State *env,
                                 const IA64LdstImmediate *decoded,
                                 uint64_t address);
bool ia64_read_pr(CPUIA64State *env, uint32_t predicate);
void ia64_write_pr(CPUIA64State *env, uint32_t predicate, bool value);
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
void ia64_reconcile_interrupt_state(CPUIA64State *env);
uint64_t ia64_read_control_register(CPUIA64State *env, uint32_t reg);
void ia64_write_control_register(CPUIA64State *env, uint32_t reg,
                                 uint64_t value);
bool ia64_return_from_call_frame(CPUIA64State *env, uint64_t target_ip);
void ia64_enter_call_frame(CPUIA64State *env);
bool ia64_rse_return_frame_from_pfs(CPUIA64State *env, uint64_t pfs);
bool ia64_slot_is_m34_alloc(IA64SlotType type, uint64_t raw);
bool ia64_exec_m34_alloc(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_nop_or_hint(IA64SlotType type, uint64_t raw);
bool ia64_slot_is_i_nop(IA64SlotType type, uint64_t raw);
bool ia64_slot_is_i_break(IA64SlotType type, uint64_t raw);
uint64_t ia64_i_break_immediate(uint64_t raw);
bool ia64_slot_is_i_mov_ip(IA64SlotType type, uint64_t raw);
bool ia64_exec_i_mov_ip(CPUIA64State *env, uint64_t raw, uint64_t bundle_ip);
bool ia64_slot_is_i_mov_from_branch(IA64SlotType type, uint64_t raw);
bool ia64_exec_i_mov_from_branch(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_i_mov_to_branch(IA64SlotType type, uint64_t raw);
bool ia64_exec_i_mov_to_branch(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_i_mov_from_predicate(IA64SlotType type, uint64_t raw);
bool ia64_exec_i_mov_from_predicate(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_i_mov_to_predicate(IA64SlotType type, uint64_t raw);
bool ia64_exec_i_mov_to_predicate(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_i_mov_to_rotating_predicate_immediate(IA64SlotType type,
                                                        uint64_t raw);
bool ia64_exec_i_mov_to_rotating_predicate_immediate(CPUIA64State *env,
                                                     uint64_t raw);
bool ia64_slot_is_mov_to_application(IA64SlotType type, uint64_t raw);
bool ia64_exec_mov_to_application(CPUIA64State *env, IA64SlotType type,
                                  uint64_t raw);
bool ia64_slot_is_mov_from_application(IA64SlotType type, uint64_t raw);
bool ia64_exec_mov_from_application(CPUIA64State *env, IA64SlotType type,
                                    uint64_t raw);
bool ia64_slot_is_i_mov_to_application_immediate(IA64SlotType type,
                                                 uint64_t raw);
bool ia64_exec_i_mov_to_application_immediate(CPUIA64State *env,
                                              uint64_t raw);
bool ia64_slot_is_mov_to_application_immediate(IA64SlotType type,
                                               uint64_t raw);
bool ia64_exec_mov_to_application_immediate(CPUIA64State *env,
                                            IA64SlotType type,
                                            uint64_t raw);
bool ia64_slot_is_check_speculative(IA64SlotType type, uint64_t raw);
int64_t ia64_check_speculative_displacement(uint64_t raw);
bool ia64_exec_check_speculative(CPUIA64State *env, IA64SlotType type,
                                 uint64_t raw, uint64_t bundle_ip,
                                 uint64_t *target_ip, bool *branch_taken);
bool ia64_slot_is_m_check_advanced(IA64SlotType type, uint64_t raw);
bool ia64_exec_m_check_advanced(CPUIA64State *env, uint64_t raw,
                                uint64_t bundle_ip, uint64_t *target_ip,
                                bool *branch_taken);
bool ia64_slot_is_m_processor_mask(IA64SlotType type, uint64_t raw);
uint64_t ia64_processor_mask_immediate(uint64_t raw);
bool ia64_exec_m_processor_mask(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_m_mov_from_processor_status(IA64SlotType type,
                                              uint64_t raw);
bool ia64_exec_m_mov_from_processor_status(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_m_mov_to_processor_status(IA64SlotType type,
                                            uint64_t raw);
bool ia64_exec_m_mov_to_processor_status(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_m_break(IA64SlotType type, uint64_t raw);
uint64_t ia64_m_break_immediate(uint64_t raw);
bool ia64_slot_is_m_mov_to_region_register(IA64SlotType type, uint64_t raw);
bool ia64_exec_m_mov_to_region_register(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_m_mov_from_region_register(IA64SlotType type, uint64_t raw);
bool ia64_exec_m_mov_from_region_register(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_m_mov_to_control(IA64SlotType type, uint64_t raw);
bool ia64_exec_m_mov_to_control(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_m_mov_from_control(IA64SlotType type, uint64_t raw);
bool ia64_exec_m_mov_from_control(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_m_mov_from_processor_identifier(IA64SlotType type,
                                                  uint64_t raw);
bool ia64_exec_m_mov_from_processor_identifier(CPUIA64State *env,
                                               uint64_t raw);
bool ia64_slot_is_m_mov_to_indexed_system_register(IA64SlotType type,
                                                   uint64_t raw);
bool ia64_exec_m_mov_to_indexed_system_register(CPUIA64State *env,
                                                uint64_t raw);
bool ia64_slot_is_m_mov_from_indexed_system_register(IA64SlotType type,
                                                     uint64_t raw);
bool ia64_exec_m_mov_from_indexed_system_register(CPUIA64State *env,
                                                  uint64_t raw);
bool ia64_slot_is_m_insert_translation(IA64SlotType type, uint64_t raw);
bool ia64_exec_m_insert_translation(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_m_probe(IA64SlotType type, uint64_t raw);
IA64ProbeStatus ia64_exec_m_probe_checked(CPUIA64State *env, uint64_t raw,
                                          IA64TranslateResult *fault);
bool ia64_exec_m_probe(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_m_virtual_translation(IA64SlotType type, uint64_t raw);
IA64VirtualTranslationStatus
ia64_exec_m_virtual_translation_checked(CPUIA64State *env, uint64_t raw,
                                        IA64TranslateResult *fault);
bool ia64_exec_m_virtual_translation(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_m_purge_translation(IA64SlotType type, uint64_t raw);
bool ia64_exec_m_purge_translation(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_m_invala(IA64SlotType type, uint64_t raw);
bool ia64_exec_m_invala(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_m_flushrs(IA64SlotType type, uint64_t raw);
bool ia64_slot_is_m_loadrs(IA64SlotType type, uint64_t raw);
void ia64_alat_invalidate_gr(CPUIA64State *env, uint32_t reg);
void ia64_alat_set_valid(CPUIA64State *env, unsigned index, bool valid);
void ia64_alat_reconstruct_transients(CPUIA64State *env);
void ia64_alat_record_gr(CPUIA64State *env, uint32_t target,
                         uint64_t address, uint8_t width, bool physical);
bool ia64_alat_check_gr(CPUIA64State *env, uint32_t reg, uint64_t address,
                        uint8_t width, bool physical, bool clear);
bool ia64_slot_is_m_serialization(IA64SlotType type, uint64_t raw);
bool ia64_exec_m_serialization(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_m_system_noop(IA64SlotType type, uint64_t raw);
bool ia64_slot_pair_is_lx_movl(uint64_t l_raw, uint64_t x_raw);
uint64_t ia64_lx_movl_imm64(uint64_t l_raw, uint64_t x_raw);
bool ia64_exec_lx_movl(CPUIA64State *env, uint64_t l_raw, uint64_t x_raw);
bool ia64_slot_pair_is_lx_nop_or_hint(uint64_t l_raw, uint64_t x_raw);
bool ia64_exec_lx_nop_or_hint(CPUIA64State *env, uint64_t l_raw,
                              uint64_t x_raw);
bool ia64_slot_is_alu_add(IA64SlotType type, uint64_t raw);
bool ia64_exec_alu_add(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_alu_sub(IA64SlotType type, uint64_t raw);
bool ia64_exec_alu_sub(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_alu_logic(IA64SlotType type, uint64_t raw);
bool ia64_exec_alu_logic(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_alu_addp4(IA64SlotType type, uint64_t raw);
bool ia64_exec_alu_addp4(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_alu_shladd(IA64SlotType type, uint64_t raw);
bool ia64_exec_alu_shladd(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_i_packed_i2(IA64SlotType type, uint64_t raw);
bool ia64_exec_i_packed_i2(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_i_multiply_shift(IA64SlotType type, uint64_t raw);
bool ia64_exec_i_multiply_shift(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_packed_alu(IA64SlotType type, uint64_t raw);
bool ia64_exec_packed_alu(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_i_mux(IA64SlotType type, uint64_t raw);
bool ia64_exec_i_mux(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_i_bit_count(IA64SlotType type, uint64_t raw);
bool ia64_exec_i_bit_count(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_i_variable_shift(IA64SlotType type, uint64_t raw);
bool ia64_exec_i_variable_shift(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_addl(IA64SlotType type, uint64_t raw);
int64_t ia64_addl_immediate(uint64_t raw);
bool ia64_exec_addl(CPUIA64State *env, uint64_t raw);
bool ia64_decode_ldst_immediate(IA64SlotType type, uint64_t raw,
                                IA64LdstImmediate *decoded);
bool ia64_decode_counted_store_loop(const IA64DecodedBundle *bundle,
                                    uint64_t bundle_ip,
                                    IA64CountedStoreLoop *decoded);
bool ia64_slot_is_m_setf(IA64SlotType type, uint64_t raw);
bool ia64_exec_m_setf(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_m_getf(IA64SlotType type, uint64_t raw);
bool ia64_exec_m_getf(CPUIA64State *env, uint64_t raw);
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
bool ia64_decode_m_atomic(IA64SlotType type, uint64_t raw,
                          IA64AtomicInstruction *decoded);
bool ia64_decode_floating_memory(IA64SlotType type, uint64_t raw,
                                 IA64FloatingMemoryInstruction *decoded);
bool ia64_defer_floating_speculative_load(
    CPUIA64State *env, const IA64FloatingMemoryInstruction *decoded,
    vaddr address, bool base_nat);
bool ia64_decode_floating_compare(IA64SlotType type, uint64_t raw,
                                  IA64FloatingCompareInstruction *decoded);
bool ia64_exec_floating_compare_qualified(
    CPUIA64State *env,
    const IA64FloatingCompareInstruction *decoded,
    bool qualifying_predicate);
bool ia64_exec_floating_compare(
    CPUIA64State *env,
    const IA64FloatingCompareInstruction *decoded);
bool ia64_decode_floating_class(IA64SlotType type, uint64_t raw,
                                IA64FloatingClassInstruction *decoded);
bool ia64_exec_floating_class_qualified(
    CPUIA64State *env,
    const IA64FloatingClassInstruction *decoded,
    bool qualifying_predicate);
bool ia64_exec_floating_class(
    CPUIA64State *env,
    const IA64FloatingClassInstruction *decoded);
bool ia64_decode_extract(IA64SlotType type, uint64_t raw,
                         IA64ExtractInstruction *decoded);
bool ia64_exec_extract(CPUIA64State *env,
                       const IA64ExtractInstruction *decoded);
bool ia64_decode_deposit(IA64SlotType type, uint64_t raw,
                         IA64DepositInstruction *decoded);
bool ia64_exec_deposit(CPUIA64State *env,
                       const IA64DepositInstruction *decoded);
bool ia64_slot_is_i_shift_right_pair(IA64SlotType type, uint64_t raw);
bool ia64_exec_i_shift_right_pair(CPUIA64State *env, uint64_t raw);
bool ia64_decode_integer_extend(IA64SlotType type, uint64_t raw,
                                IA64IntegerExtendInstruction *decoded);
bool ia64_exec_integer_extend(CPUIA64State *env,
                              const IA64IntegerExtendInstruction *decoded);
bool ia64_slot_is_f_select_or_xma(IA64SlotType type, uint64_t raw);
bool ia64_exec_f_select_or_xma(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_f_multiply_add(IA64SlotType type, uint64_t raw);
bool ia64_exec_f_multiply_add(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_f_reciprocal_approx(IA64SlotType type, uint64_t raw);
bool ia64_exec_f_reciprocal_approx(CPUIA64State *env, uint64_t raw);
bool ia64_slot_is_f_misc(IA64SlotType type, uint64_t raw);
bool ia64_exec_f_misc(CPUIA64State *env, uint64_t raw);
bool ia64_decode_compare(IA64SlotType type, uint64_t raw,
                         IA64CompareInstruction *decoded);
bool ia64_exec_compare_qualified(CPUIA64State *env,
                                 const IA64CompareInstruction *decoded,
                                 bool qualifying_predicate);
bool ia64_exec_compare(CPUIA64State *env,
                       const IA64CompareInstruction *decoded);
bool ia64_decode_predicate_test(IA64SlotType type, uint64_t raw,
                                IA64PredicateTestInstruction *decoded);
bool ia64_exec_predicate_test_qualified(
    CPUIA64State *env,
    const IA64PredicateTestInstruction *decoded,
    bool qualifying_predicate);
bool ia64_exec_predicate_test(CPUIA64State *env,
                              const IA64PredicateTestInstruction *decoded);
bool ia64_slot_is_b_break(IA64SlotType type, uint64_t raw);
uint64_t ia64_b_break_immediate(uint64_t raw);
bool ia64_slot_is_b_branch_relative(IA64SlotType type, uint64_t raw);
bool ia64_slot_is_b_call_relative(IA64SlotType type, uint64_t raw);
bool ia64_slot_is_b_indirect_branch(IA64SlotType type, uint64_t raw);
bool ia64_slot_is_b_predict_or_nop(IA64SlotType type, uint64_t raw);
int64_t ia64_branch_displacement(uint64_t raw);
bool ia64_b_loop_branch_is_legal(IA64SlotType type, uint64_t raw,
                                 unsigned slot);
bool ia64_exec_b_branch_relative_decoded(CPUIA64State *env,
                                         uint8_t branch_type,
                                         uint8_t predicate,
                                         int64_t displacement,
                                         uint64_t raw,
                                         uint64_t bundle_ip,
                                         uint64_t *target_ip,
                                         bool *taken_out);
bool ia64_exec_b_branch_relative(CPUIA64State *env,
                                 uint64_t raw,
                                 uint64_t bundle_ip,
                                 uint64_t *target_ip,
                                 bool *taken_out);
void ia64_branch_call_effects(CPUIA64State *env, uint32_t b1,
                              uint64_t bundle_ip);
bool ia64_exec_b_call_relative_decoded(CPUIA64State *env,
                                       uint32_t branch_reg,
                                       int64_t displacement,
                                       uint64_t bundle_ip,
                                       uint64_t *target_ip);
bool ia64_exec_b_call_relative(CPUIA64State *env,
                               uint64_t raw,
                               uint64_t bundle_ip,
                               uint64_t *target_ip);
bool ia64_exec_b_indirect_branch_decoded(CPUIA64State *env,
                                         uint8_t major,
                                         uint8_t x6,
                                         uint32_t branch_reg,
                                         uint32_t target_reg,
                                         uint64_t bundle_ip,
                                         uint64_t *target_ip);
bool ia64_exec_b_indirect_branch(CPUIA64State *env,
                                 uint64_t raw,
                                 uint64_t bundle_ip,
                                 uint64_t *target_ip);
IA64InsnStatus
ia64_insn_exec_bundle(CPUIA64State *env,
                       const uint8_t bundle[IA64_BUNDLE_SIZE],
                       IA64InsnReport *report);

#endif
