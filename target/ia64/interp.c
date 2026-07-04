/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "accel/tcg/cpu-loop.h"
#include "accel/tcg/cpu-ldst.h"
#include "exec/cputlb.h"
#include "bundle.h"
#include "cpu.h"
#include "debug-trace.h"
#include "exception.h"
#include "exec/cpu-interrupt.h"
#include "firmware.h"
#include "insn.h"
#include "exec/helper-proto.h"
#include "hw/core/cpu.h"
#include "mem.h"
#include "perf.h"
#include "qemu/error-report.h"
#include "system/memory.h"
#include "tcg-classify.h"
#include "trace-target_ia64.h"

void HELPER(perf_tb_exec)(void)
{
    IA64_PERF_INC(IA64_PERF_TB_EXECUTED);
}

void HELPER(perf_direct_branch_fallback)(void)
{
    IA64_PERF_INC(IA64_PERF_TCG_BRANCH_DIRECT_FALLBACK);
}

void HELPER(perf_tcg_ldst_fallback)(void)
{
    IA64_PERF_INC(IA64_PERF_TCG_LDST_FALLBACK);
}

void HELPER(perf_tb_exit_main_loop)(void)
{
    IA64_PERF_INC(IA64_PERF_TB_EXIT_MAIN_LOOP);
}

void HELPER(perf_tb_exit_chained)(void)
{
    IA64_PERF_INC(IA64_PERF_TB_EXIT_CHAINED);
}

void HELPER(perf_tb_exit_lookup_ptr)(void)
{
    IA64_PERF_INC(IA64_PERF_TB_EXIT_LOOKUP_PTR);
}

void HELPER(firmware_call_gate)(CPUIA64State *env, uint64_t gate_ip)
{
    CPUState *cpu = env_cpu(env);

    IA64_PERF_INC(IA64_PERF_BUNDLE_EXECUTED);
    IA64_PERF_INC(IA64_PERF_TCG_FIRMWARE_CALL_GATE_FAST);

    /*
     * Firmware service helpers can legitimately perform guest memory and MMIO
     * accesses.  The full bundle interpreter used the same relaxed I/O mode.
     */
    cpu->neg.can_do_io = true;
    env->ip = gate_ip;
    env->cr[IA64_CR_IIP] = gate_ip;

    if (ia64_debug_hooks_active()) {
        ia64_progress_trace_bundle(env);
    }

    if (!ia64_firmware_dispatch_gate(env, gate_ip)) {
        IA64_PERF_INC(IA64_PERF_TCG_FIRMWARE_CALL_GATE_FALLBACK);
        cpu_abort(cpu,
                  "IA-64 firmware call-gate fast path missed "
                  "IP=0x%016" PRIx64 "\n",
                  gate_ip);
    }
}

#define IA64_LINUX_BREAK_SYSCALL UINT64_C(0x100000)
#define IA64_PSR_I_BIT UINT64_C(0x0000000000004000)
#define IA64_PSR_BN_BIT UINT64_C(0x0000100000000000)
#define IA64_PSR_CPL_SHIFT 32
#define IA64_PSR_CPL_MASK UINT64_C(0x0000000300000000)

static unsigned ia64_helper_psr_cpl(uint64_t psr)
{
    return (psr & IA64_PSR_CPL_MASK) >> IA64_PSR_CPL_SHIFT;
}

static void ia64_count_privilege_transition(uint64_t old_psr,
                                            uint64_t new_psr)
{
    unsigned old_cpl = ia64_helper_psr_cpl(old_psr);
    unsigned new_cpl = ia64_helper_psr_cpl(new_psr);

    if (old_cpl == new_cpl) {
        return;
    }

    IA64_PERF_INC(IA64_PERF_TRANSITION_PRIVILEGE_CHANGE);
    if (old_cpl == 3 && new_cpl < 3) {
        IA64_PERF_INC(IA64_PERF_TRANSITION_USER_TO_KERNEL);
    } else if (old_cpl < 3 && new_cpl == 3) {
        IA64_PERF_INC(IA64_PERF_TRANSITION_KERNEL_TO_USER);
    }
}

static void ia64_count_bank_transition(uint64_t old_psr, uint64_t new_psr)
{
    bool old_bank = (old_psr & IA64_PSR_BN_BIT) != 0;
    bool new_bank = (new_psr & IA64_PSR_BN_BIT) != 0;

    if (old_bank == new_bank) {
        return;
    }

    IA64_PERF_INC(IA64_PERF_TRANSITION_BANK_SWITCH);
    IA64_PERF_INC(new_bank ? IA64_PERF_TRANSITION_BANK_SWITCH_TO_BANK1 :
                             IA64_PERF_TRANSITION_BANK_SWITCH_TO_BANK0);
}

static void ia64_count_interrupt_unmask(uint64_t old_psr, uint64_t new_psr,
                                        CPUIA64State *env)
{
    if ((old_psr & IA64_PSR_I_BIT) == 0 &&
        (new_psr & IA64_PSR_I_BIT) != 0 &&
        ia64_external_interrupt_pending(env)) {
        IA64_PERF_INC(IA64_PERF_INTERRUPT_UNMASK_PENDING);
    }
}

static void ia64_count_psr_transition(CPUIA64State *env, uint64_t old_psr,
                                      uint64_t new_psr)
{
    ia64_count_privilege_transition(old_psr, new_psr);
    ia64_count_bank_transition(old_psr, new_psr);
    ia64_count_interrupt_unmask(old_psr, new_psr, env);
}

static void abort_unsupported_slot(CPUIA64State *env,
                                   const IA64DecodedBundle *decoded,
                                   int slot)
{
    char bundle_text[192];
    char slot_text[256];

    ia64_format_decoded_bundle(decoded, bundle_text, sizeof(bundle_text));
    ia64_format_slot_class(decoded, slot, slot_text, sizeof(slot_text));
    IA64_PERF_INC(IA64_PERF_UNSUPPORTED_ABORT);

    cpu_abort(env_cpu(env),
              "IA-64 execution frontier at IP=0x%016" PRIx64
              ": unsupported instruction %s; bundle %s\n",
              env->ip, slot_text, bundle_text);
}

static void abort_zero_branch(CPUIA64State *env,
                              const IA64DecodedBundle *decoded,
                              int slot)
{
    char bundle_text[192];
    char slot_text[256];

    ia64_format_decoded_bundle(decoded, bundle_text, sizeof(bundle_text));
    ia64_format_slot_class(decoded, slot, slot_text, sizeof(slot_text));
    IA64_PERF_INC(IA64_PERF_ZERO_BRANCH_ABORT);

    cpu_abort(env_cpu(env),
              "IA-64 execution frontier at IP=0x%016" PRIx64
              ": branch target became zero in %s; bundle %s\n",
              env->ip, slot_text, bundle_text);
}

static void ia64_deliver_break(CPUIA64State *env, const char *mnemonic,
                               uint64_t iim, uint64_t *next_ip)
{
    char detail[64];
    uint64_t old_psr = ia64_env_psr(env);
    uint64_t source_ip = env->ip;
    unsigned source_ri = ia64_env_ri(env);

    snprintf(detail, sizeof(detail), "%s iim=0x%" PRIx64, mnemonic, iim);
    IA64_PERF_INC(IA64_PERF_OP_BREAK);
    IA64_PERF_INC(IA64_PERF_TRANSITION_BREAK);
    if (iim == IA64_LINUX_BREAK_SYSCALL) {
        IA64_PERF_INC(IA64_PERF_TRANSITION_BREAK_SYSCALL);
    }
    ia64_trace_linux_syscall_break(env, mnemonic, iim, *next_ip);
    ia64_deliver_break_interruption(env, iim, next_ip, detail);
    ia64_count_psr_transition(env, old_psr, ia64_env_psr(env));
    ia64_progress_trace_event(env, mnemonic, iim, source_ip, source_ri,
                              *next_ip);
}

static void ia64_deliver_translation_fault(CPUIA64State *env,
                                           const IA64TranslateResult *result)
{
    ia64_deliver_exception(env, ia64_exception_for_translate_result(result),
                           result->vaddr, result->access_type,
                           result->message);
}

static G_NORETURN void ia64_exit_after_translation_fault(
    CPUIA64State *env, const IA64TranslateResult *result)
{
    CPUState *cpu = env_cpu(env);

    ia64_deliver_translation_fault(env, result);
    env->fault_exit_pending_tb_translate = true;
    IA64_PERF_INC(IA64_PERF_CPU_LOOP_EXIT);
    cpu_loop_exit(cpu);
}

static void ia64_finish_bundle(CPUIA64State *env, uint64_t next_ip,
                               unsigned next_ri)
{
    ia64_env_set_psr(env, ia64_psr_with_ri(ia64_env_psr(env), next_ri));
    env->ip = next_ip;
}

static void ia64_finish_tcg_ticks(CPUIA64State *env, uint32_t bundle_count)
{
    if (bundle_count == 0) {
        return;
    }

    /*
     * AR.ITC follows the QEMU virtual clock and the CR.ITM deadline timer
     * raises CPU_INTERRUPT_HARD from the main loop, so retired bundles no
     * longer advance guest time here.  Helpers can still make an external
     * interrupt deliverable while generated code has later bundle constants
     * queued in the same TB.  Leave the TB at the precise post-bundle IP and
     * let the cpu_exec_interrupt hook enter the IVT.
     */
    if (ia64_external_interrupt_enabled(env)) {
        IA64_PERF_INC(IA64_PERF_CPU_LOOP_EXIT);
        cpu_loop_exit(env_cpu(env));
    }
}

static void ia64_finish_interpreted_bundle(CPUIA64State *env, uint64_t next_ip,
                                           unsigned next_ri)
{
    ia64_finish_bundle(env, next_ip, next_ri);
    ia64_finish_tcg_ticks(env, 1);
}

static bool ia64_tcg_can_chain(CPUIA64State *env)
{
    CPUState *cpu = env_cpu(env);
    uint32_t interrupt_request = qatomic_read(&cpu->interrupt_request);

    if (qatomic_read(&cpu->exit_request)) {
        return false;
    }

    /*
     * HARD is also used as the timer kick.  Poll and latch the ITM compare
     * here on the vCPU thread, but do not let a masked IA-64 interrupt break
     * TB chaining until it can actually be delivered.
     */
    if ((interrupt_request & CPU_INTERRUPT_HARD) != 0 &&
        ia64_itc_timer_poll(env)) {
        ia64_latch_timer_interrupt(env);
    }

    if ((interrupt_request & ~CPU_INTERRUPT_HARD) != 0) {
        return false;
    }

    if (!ia64_external_interrupt_pending(env)) {
        if ((interrupt_request & CPU_INTERRUPT_HARD) != 0) {
            cpu_reset_interrupt(cpu, CPU_INTERRUPT_HARD);
        }
        return true;
    }

    if (!ia64_external_interrupt_enabled(env)) {
        IA64_PERF_INC(IA64_PERF_INTERRUPT_EXEC_PENDING_MASKED);
        return true;
    }

    return false;
}

static uint32_t ia64_lookup_ptr_chain_ok(CPUIA64State *env)
{
    bool chain_ok = ia64_tcg_can_chain(env);

    IA64_PERF_INC(chain_ok ? IA64_PERF_TB_EXIT_LOOKUP_PTR :
                             IA64_PERF_TB_EXIT_MAIN_LOOP);
    return chain_ok ? 1 : 0;
}

static void ia64_alat_invalidate_gr_mask(CPUIA64State *env, uint64_t dest_mask)
{
    dest_mask &= ~1ULL;
    if (dest_mask == 0 || env->alat.valid_mask == 0) {
        return;
    }

    while (dest_mask && env->alat.valid_mask != 0) {
        unsigned reg = ctz64(dest_mask);

        ia64_alat_invalidate_gr(env, reg);
        dest_mask &= dest_mask - 1;
    }
}

#include "interp-ldst.c"

#include "rse.c"

#include "fpu.c"

static bool exec_counted_store_loop(CPUIA64State *env,
                                    const IA64CountedStoreLoop *loop,
                                    uint64_t *next_ip)
{
    uint64_t loop_count = env->ar[IA64_AR_LC];
    uint64_t iterations;
    uint64_t address;
    uint64_t value;
    uint64_t update;

    if (!env || !loop || !next_ip || loop_count == UINT64_MAX) {
        return false;
    }

    IA64_PERF_INC(IA64_PERF_COUNTED_STORE_LOOP);
    iterations = loop_count + 1;
    address = ia64_read_gr(env, loop->store.base);
    value = ia64_read_gr(env, loop->store.source);
    update = (uint64_t)loop->store.immediate;

    for (uint64_t i = 0; i < iterations; i++) {
        ia64_ldst_write(env, address, loop->store.width, value);
        address += update;
    }

    ia64_write_gr(env, loop->store.base, address);
    env->ar[IA64_AR_LC] = 0;
    *next_ip = loop->fallthrough_ip;
    env->gr[0] = 0;
    return true;
}

static bool exec_false_predicated_side_effect(CPUIA64State *env,
                                              const IA64DecodedBundle *decoded,
                                              int slot)
{
    IA64SlotType type = decoded->info->slot_type[slot];
    uint64_t raw = decoded->slot[slot];
    IA64CompareInstruction cmp;
    IA64FloatingCompareInstruction fcmp;
    IA64PredicateTestInstruction pred_test;

    if (ia64_decode_compare(type, raw, &cmp) &&
        cmp.write_kind == IA64_PRED_WRITE_UNCONDITIONAL) {
        if (!ia64_exec_compare_qualified(env, &cmp, false)) {
            abort_unsupported_slot(env, decoded, slot);
        }
        return true;
    }

    if (ia64_decode_floating_compare(type, raw, &fcmp) &&
        fcmp.write_kind == IA64_PRED_WRITE_UNCONDITIONAL) {
        if (!ia64_exec_floating_compare_qualified(env, &fcmp, false)) {
            abort_unsupported_slot(env, decoded, slot);
        }
        return true;
    }

    if (ia64_decode_predicate_test(type, raw, &pred_test) &&
        pred_test.write_kind == IA64_PRED_WRITE_UNCONDITIONAL) {
        if (!ia64_exec_predicate_test_qualified(env, &pred_test, false)) {
            abort_unsupported_slot(env, decoded, slot);
        }
        return true;
    }

    return false;
}

static void ia64_count_fast_tcg_ops(uint32_t slot_count, uint32_t op_counts,
                                    bool count_bundle)
{
    if (count_bundle) {
        IA64_PERF_INC(IA64_PERF_TCG_FAST_BUNDLE);
    }
    IA64_PERF_ADD(IA64_PERF_TCG_FAST_SLOT, slot_count);
    IA64_PERF_ADD(IA64_PERF_TCG_FAST_NOP,
                  ia64_perf_fast_count(op_counts,
                                       IA64_PERF_FAST_COUNT_NOP_SHIFT));
    IA64_PERF_ADD(IA64_PERF_TCG_FAST_ALU_ADD,
                  ia64_perf_fast_count(op_counts,
                                       IA64_PERF_FAST_COUNT_ALU_ADD_SHIFT));
    IA64_PERF_ADD(IA64_PERF_TCG_FAST_ALU_LOGIC,
                  ia64_perf_fast_count(op_counts,
                                       IA64_PERF_FAST_COUNT_ALU_LOGIC_SHIFT));
    IA64_PERF_ADD(IA64_PERF_TCG_FAST_ADDL,
                  ia64_perf_fast_count(op_counts,
                                       IA64_PERF_FAST_COUNT_ADDL_SHIFT));
    IA64_PERF_ADD(IA64_PERF_TCG_FAST_COMPARE,
                  ia64_perf_fast_count(op_counts,
                                       IA64_PERF_FAST_COUNT_COMPARE_SHIFT));
    IA64_PERF_ADD(IA64_PERF_TCG_FAST_INTEGER_MISC,
                  ia64_perf_fast_count(op_counts,
                                       IA64_PERF_FAST_COUNT_INTEGER_MISC_SHIFT));
    IA64_PERF_ADD(IA64_PERF_TCG_LDST_LOAD,
                  ia64_perf_fast_count(op_counts,
                                       IA64_PERF_FAST_COUNT_LDST_LOAD_SHIFT));
    IA64_PERF_ADD(IA64_PERF_TCG_LDST_STORE,
                  ia64_perf_fast_count(op_counts,
                                       IA64_PERF_FAST_COUNT_LDST_STORE_SHIFT));
}

void HELPER(start_fast_bundle)(CPUIA64State *env, uint32_t slot_count,
                               uint32_t op_counts)
{
    CPUState *cpu = env_cpu(env);
    bool debug_hooks = ia64_debug_hooks_active();

    IA64_PERF_INC(IA64_PERF_BUNDLE_EXECUTED);
    ia64_count_fast_tcg_ops(slot_count, op_counts, true);

    cpu->neg.can_do_io = true;
    if (debug_hooks) {
        ia64_trace_execve(env);
        ia64_trace_epc_syscall(env);
        ia64_trace_syscall_return(env);
        ia64_trace_uevent_netlink(env);
        ia64_progress_trace_bundle(env);
        ia64_state_trace_bundle(env);
    }
    if (ia64_firmware_linux_cmdline_append_pending()) {
        ia64_firmware_maybe_apply_linux_cmdline_append(env);
    }
}

void HELPER(finish_fast_bundle)(CPUIA64State *env, uint64_t next_ip,
                                uint64_t dest_mask)
{
    ia64_alat_invalidate_gr_mask(env, dest_mask);
    env->gr[0] = 0;
    ia64_finish_bundle(env, next_ip, 0);
}

void HELPER(finish_fast_tb)(CPUIA64State *env, uint32_t bundle_count)
{
    ia64_finish_tcg_ticks(env, bundle_count);
}

uint64_t HELPER(fast_ldst_load)(CPUIA64State *env, uint64_t address,
                                uint32_t width, uint32_t slot)
{
    /*
     * Translated fast bundles carry one insn_start per bundle, so publish the
     * executing slot the same way the interpreter loop does: a fault below
     * must deliver PSR.ri/ISR.ei for this slot, not the bundle start.
     */
    ia64_env_set_ri(env, slot);
    return ia64_ldst_read(env, address, width);
}

void HELPER(fast_ldst_store)(CPUIA64State *env, uint64_t address,
                             uint64_t value, uint32_t width, uint32_t slot)
{
    ia64_env_set_ri(env, slot);
    ia64_ldst_write(env, address, width, value);
}

void HELPER(fast_ldst_alat_store)(CPUIA64State *env, uint64_t address,
                                  uint32_t width)
{
    /* Direct qemu_st lowering calls this only while ALAT entries are valid. */
    ia64_alat_invalidate_store(env, address, width);
}

static void ia64_flush_qemu_tlb_for_page(CPUState *cpu, vaddr address,
                                         uint8_t page_size)
{
    vaddr start;
    uint64_t len;

    /*
     * QEMU's softmmu TLB is keyed by virtual page and mmu_idx; IA-64 RIDs live
     * in target RR/TC state.  Any modeled TC/TR change for a VA can therefore
     * stale a direct qemu_ld/qemu_st mapping even when the new RID is distinct.
     */
    if (ia64_host_tlb_flush_span(address, page_size, &start, &len)) {
        tlb_flush_range_by_mmuidx(cpu, start, len, IA64_MMU_ALL_IDXMAP,
                                  TARGET_LONG_BITS);
        IA64_PERF_INC(IA64_PERF_QEMU_TLB_FLUSH_RANGE);
        return;
    }

    tlb_flush(cpu);
    IA64_PERF_INC(IA64_PERF_QEMU_TLB_FLUSH_FULL);
}

uint32_t HELPER(finish_direct_branch_bundle)(CPUIA64State *env,
                                             uint64_t next_ip,
                                             uint32_t branch_flags,
                                             uint32_t prefix_slot_count,
                                             uint32_t prefix_op_counts,
                                             uint64_t prefix_dest_mask)
{
    CPUState *cpu = env_cpu(env);
    /* bit 0 is branch-taken, upper bits are pending fast-path bundle ticks. */
    bool taken = branch_flags & 1;
    uint32_t pending_bundle_count = branch_flags >> 1;
    bool chain_ok;
    bool debug_hooks = ia64_debug_hooks_active();

    IA64_PERF_INC(IA64_PERF_BUNDLE_EXECUTED);
    IA64_PERF_INC(IA64_PERF_TCG_BRANCH_DIRECT_TRANSLATED);
    ia64_count_fast_tcg_ops(prefix_slot_count, prefix_op_counts, false);
    IA64_PERF_INC(IA64_PERF_OP_BRANCH_DIRECT);
    IA64_PERF_INC(taken ? IA64_PERF_BRANCH_TAKEN :
                           IA64_PERF_BRANCH_FALLTHROUGH);
    IA64_PERF_INC(IA64_PERF_TB_EXIT_DIRECT_BRANCH);

    cpu->neg.can_do_io = true;
    if (debug_hooks) {
        ia64_trace_execve(env);
        ia64_trace_uevent_netlink(env);
        ia64_progress_trace_bundle(env);
        ia64_state_trace_bundle(env);
    }
    if (ia64_firmware_linux_cmdline_append_pending()) {
        ia64_firmware_maybe_apply_linux_cmdline_append(env);
    }

    ia64_alat_invalidate_gr_mask(env, prefix_dest_mask);
    env->gr[0] = 0;
    ia64_finish_bundle(env, next_ip, 0);
    ia64_finish_tcg_ticks(env, pending_bundle_count + 1);

    chain_ok = ia64_tcg_can_chain(env);
    IA64_PERF_INC(chain_ok ? IA64_PERF_TB_EXIT_CHAINED :
                             IA64_PERF_TB_EXIT_MAIN_LOOP);
    return chain_ok ? 1 : 0;
}

typedef enum IA64PlannedSlotResult {
    IA64_PLANNED_SLOT_GENERIC,
    IA64_PLANNED_SLOT_CONTINUE,
    IA64_PLANNED_SLOT_BREAK,
} IA64PlannedSlotResult;

static IA64PlannedSlotResult exec_predecoded_slot(
    CPUIA64State *env, const IA64DecodedBundle *decoded, int slot,
    IA64SlotType type, uint64_t raw, IA64TcgFallbackPlanOp op,
    uint64_t *next_ip, unsigned *next_ri)
{
    switch (op) {
    case IA64_TCG_FALLBACK_PLAN_GENERIC:
        return IA64_PLANNED_SLOT_GENERIC;
    case IA64_TCG_FALLBACK_PLAN_ALLOC:
        IA64_PERF_INC(IA64_PERF_OP_ALLOC);
        ia64_exec_m34_alloc(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_MOV_FROM_BRANCH:
        IA64_PERF_INC(IA64_PERF_OP_BRANCH_REGISTER);
        ia64_exec_i_mov_from_branch(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_MOV_TO_BRANCH:
        IA64_PERF_INC(IA64_PERF_OP_BRANCH_REGISTER);
        ia64_exec_i_mov_to_branch(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_MOV_TO_APPLICATION:
        IA64_PERF_INC(IA64_PERF_OP_APPLICATION_REGISTER);
        ia64_exec_mov_to_application(env, type, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_MOV_FROM_APPLICATION:
        IA64_PERF_INC(IA64_PERF_OP_APPLICATION_REGISTER);
        ia64_exec_mov_from_application(env, type, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_MOV_TO_APPLICATION_IMM:
        IA64_PERF_INC(IA64_PERF_OP_APPLICATION_REGISTER);
        ia64_exec_mov_to_application_immediate(env, type, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_EXTRACT: {
        IA64ExtractInstruction extract;

        if (!ia64_decode_extract(type, raw, &extract) ||
            !ia64_exec_extract(env, &extract)) {
            return IA64_PLANNED_SLOT_GENERIC;
        }
        IA64_PERF_INC(IA64_PERF_OP_EXTRACT_DEPOSIT);
        return IA64_PLANNED_SLOT_CONTINUE;
    }
    case IA64_TCG_FALLBACK_PLAN_DEPOSIT: {
        IA64DepositInstruction deposit;

        if (!ia64_decode_deposit(type, raw, &deposit) ||
            !ia64_exec_deposit(env, &deposit)) {
            return IA64_PLANNED_SLOT_GENERIC;
        }
        IA64_PERF_INC(IA64_PERF_OP_EXTRACT_DEPOSIT);
        return IA64_PLANNED_SLOT_CONTINUE;
    }
    case IA64_TCG_FALLBACK_PLAN_INTEGER_EXTEND: {
        IA64IntegerExtendInstruction int_ext;

        if (!ia64_decode_integer_extend(type, raw, &int_ext) ||
            !ia64_exec_integer_extend(env, &int_ext)) {
            return IA64_PLANNED_SLOT_GENERIC;
        }
        IA64_PERF_INC(IA64_PERF_OP_SHIFT_EXTEND);
        return IA64_PLANNED_SLOT_CONTINUE;
    }
    case IA64_TCG_FALLBACK_PLAN_FLOATING_MEMORY: {
        IA64FloatingMemoryInstruction fldst;

        if (!ia64_decode_floating_memory(type, raw, &fldst) ||
            !exec_floating_memory(env, &fldst)) {
            return IA64_PLANNED_SLOT_GENERIC;
        }
        IA64_PERF_INC(IA64_PERF_OP_FLOAT_MEMORY);
        return IA64_PLANNED_SLOT_CONTINUE;
    }
    case IA64_TCG_FALLBACK_PLAN_FLOATING_COMPARE: {
        IA64FloatingCompareInstruction fcmp;

        if (!ia64_decode_floating_compare(type, raw, &fcmp) ||
            !ia64_exec_floating_compare(env, &fcmp)) {
            return IA64_PLANNED_SLOT_GENERIC;
        }
        IA64_PERF_INC(IA64_PERF_OP_FLOAT);
        return IA64_PLANNED_SLOT_CONTINUE;
    }
    case IA64_TCG_FALLBACK_PLAN_LDST_IMMEDIATE: {
        IA64LdstImmediate ldst;

        if (!ia64_decode_ldst_immediate(type, raw, &ldst) ||
            !exec_ldst_immediate(env, &ldst)) {
            return IA64_PLANNED_SLOT_GENERIC;
        }
        switch (ldst.kind) {
        case IA64_LDST_IMM_LOAD:
            IA64_PERF_INC(IA64_PERF_OP_LOAD);
            break;
        case IA64_LDST_IMM_STORE:
            IA64_PERF_INC(IA64_PERF_OP_STORE);
            break;
        case IA64_LDST_IMM_PREFETCH:
            IA64_PERF_INC(IA64_PERF_OP_PREFETCH);
            break;
        default:
            break;
        }
        return IA64_PLANNED_SLOT_CONTINUE;
    }
    case IA64_TCG_FALLBACK_PLAN_COMPARE: {
        IA64CompareInstruction cmp;

        if (!ia64_decode_compare(type, raw, &cmp) ||
            !ia64_exec_compare(env, &cmp)) {
            return IA64_PLANNED_SLOT_GENERIC;
        }
        IA64_PERF_INC(IA64_PERF_OP_COMPARE);
        return IA64_PLANNED_SLOT_CONTINUE;
    }
    case IA64_TCG_FALLBACK_PLAN_PREDICATE_TEST: {
        IA64PredicateTestInstruction pred_test;

        if (!ia64_decode_predicate_test(type, raw, &pred_test) ||
            !ia64_exec_predicate_test(env, &pred_test)) {
            return IA64_PLANNED_SLOT_GENERIC;
        }
        IA64_PERF_INC(IA64_PERF_OP_PREDICATE_TEST);
        if (pred_test.kind == IA64_PRED_TEST_NAT) {
            IA64_PERF_INC(IA64_PERF_OP_NAT_TEST);
        }
        return IA64_PLANNED_SLOT_CONTINUE;
    }
    case IA64_TCG_FALLBACK_PLAN_ALU_ADD:
        IA64_PERF_INC(IA64_PERF_OP_ALU);
        ia64_exec_alu_add(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_ALU_SUB:
        IA64_PERF_INC(IA64_PERF_OP_ALU);
        ia64_exec_alu_sub(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_ALU_LOGIC:
        IA64_PERF_INC(IA64_PERF_OP_ALU);
        ia64_exec_alu_logic(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_ALU_ADDP4:
        IA64_PERF_INC(IA64_PERF_OP_ALU);
        ia64_exec_alu_addp4(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_ALU_SHLADD:
        IA64_PERF_INC(IA64_PERF_OP_ALU);
        ia64_exec_alu_shladd(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_I_PACKED_I2:
        IA64_PERF_INC(IA64_PERF_OP_ALU);
        ia64_exec_i_packed_i2(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_I_MUX:
        IA64_PERF_INC(IA64_PERF_OP_ALU);
        ia64_exec_i_mux(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_I_BIT_COUNT:
        IA64_PERF_INC(IA64_PERF_OP_ALU);
        ia64_exec_i_bit_count(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_I_VARIABLE_SHIFT:
        IA64_PERF_INC(IA64_PERF_OP_ALU);
        ia64_exec_i_variable_shift(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_ADDL:
        IA64_PERF_INC(IA64_PERF_OP_ADDL);
        ia64_exec_addl(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_BRANCH_RELATIVE: {
        bool branch_taken = false;

        IA64_PERF_INC(IA64_PERF_OP_BRANCH_DIRECT);
        ia64_exec_b_branch_relative(env, raw, env->ip, next_ip,
                                    &branch_taken);
        if (*next_ip == 0) {
            abort_zero_branch(env, decoded, slot);
        }
        if (branch_taken || *next_ip != env->ip + IA64_BUNDLE_SIZE) {
            IA64_PERF_INC(IA64_PERF_BRANCH_TAKEN);
            return IA64_PLANNED_SLOT_BREAK;
        }
        IA64_PERF_INC(IA64_PERF_BRANCH_FALLTHROUGH);
        return IA64_PLANNED_SLOT_CONTINUE;
    }
    case IA64_TCG_FALLBACK_PLAN_BRANCH_CALL_RELATIVE:
        IA64_PERF_INC(IA64_PERF_OP_BRANCH_CALL);
        IA64_PERF_INC(IA64_PERF_BRANCH_TAKEN);
        ia64_exec_b_call_relative(env, raw, env->ip, next_ip);
        if (*next_ip == 0) {
            abort_zero_branch(env, decoded, slot);
        }
        return IA64_PLANNED_SLOT_BREAK;
    case IA64_TCG_FALLBACK_PLAN_BRANCH_INDIRECT: {
        uint8_t branch_major = ia64_slot_major_opcode(raw);
        uint8_t branch_x6 = (raw >> 27) & 0x3f;
        bool rfi = branch_major == 0x0 && branch_x6 == 0x08;
        bool rfi_valid_ifs =
            rfi && (env->cr[IA64_CR_IFS] & IA64_IFS_VALID_BIT) != 0;
        bool br_ret = branch_major == 0x0 && branch_x6 == 0x21;
        bool cover = branch_major == 0x0 && branch_x6 == 0x02;
        bool epc = branch_major == 0x0 && branch_x6 == 0x10;
        uint64_t old_psr = ia64_env_psr(env);

        IA64_PERF_INC(IA64_PERF_OP_BRANCH_INDIRECT);
        IA64_PERF_INC(IA64_PERF_BRANCH_TAKEN);
        if (cover) {
            IA64_PERF_INC(IA64_PERF_TRANSITION_COVER);
        }
        if (epc) {
            IA64_PERF_INC(IA64_PERF_TRANSITION_EPC);
        }
        if (br_ret) {
            ia64_rse_probe_restored_frame_fill(
                env, (env->ar[IA64_AR_PFS] >> 7) & 0x7f);
        }
        if (rfi_valid_ifs) {
            ia64_rse_probe_restored_frame_fill(
                env, env->cr[IA64_CR_IFS] & 0x7f);
        }
        ia64_exec_b_indirect_branch(env, raw, env->ip, next_ip);
        if (br_ret) {
            ia64_rse_maybe_fill_restored_frame(env,
                                               (env->cfm >> 7) & 0x7f);
        }
        if (rfi_valid_ifs) {
            IA64_PERF_INC(IA64_PERF_TRANSITION_RFI_VALID_IFS);
            ia64_rse_maybe_fill_restored_frame(env, env->rse.sof);
        }
        if (rfi) {
            IA64_PERF_INC(IA64_PERF_TRANSITION_RFI);
            IA64_PERF_INC(ia64_helper_psr_cpl(ia64_env_psr(env)) == 3 ?
                          IA64_PERF_TRANSITION_RFI_TO_USER :
                          IA64_PERF_TRANSITION_RFI_TO_KERNEL);
            *next_ri = ia64_env_ri(env);
        }
        ia64_count_psr_transition(env, old_psr, ia64_env_psr(env));
        if (*next_ip == 0) {
            abort_zero_branch(env, decoded, slot);
        }
        return IA64_PLANNED_SLOT_BREAK;
    }
    case IA64_TCG_FALLBACK_PLAN_BRANCH_PREDICT_OR_NOP:
        IA64_PERF_INC(IA64_PERF_OP_BRANCH_PREDICT);
        return IA64_PLANNED_SLOT_CONTINUE;
    default:
        return IA64_PLANNED_SLOT_GENERIC;
    }
}

static void ia64_exec_bundle_impl(CPUIA64State *env,
                                  uint32_t tmpl,
                                  uint64_t slot0,
                                  uint64_t slot1,
                                  uint64_t slot2,
                                  uint32_t fallback_plan)
{
    CPUState *cpu = env_cpu(env);
    IA64DecodedBundle decoded;
    uint64_t next_ip = env->ip + IA64_BUNDLE_SIZE;
    unsigned start_slot = ia64_env_ri(env);
    unsigned next_ri = 0;
    uint32_t planned_slot_count = 0;
    uint32_t planned_bailout_count = 0;
    bool debug_hooks = ia64_debug_hooks_active();

    IA64_PERF_INC(IA64_PERF_HELPER_EXEC_BUNDLE);
    IA64_PERF_INC(IA64_PERF_BUNDLE_EXECUTED);

    /*
     * This target still interprets complete IA-64 bundles inside one C helper.
     * Nested memory helpers therefore cannot hand QEMU a translated-code return
     * address for cpu_io_recompile().  Allow helper-owned I/O directly until the
     * translator grows per-instruction memory ops.
     */
    cpu->neg.can_do_io = true;

    if (debug_hooks) {
        ia64_trace_execve(env);
        ia64_trace_epc_syscall(env);
        ia64_trace_syscall_return(env);
        ia64_trace_uevent_netlink(env);
    }
    if (ia64_firmware_linux_cmdline_append_pending()) {
        ia64_firmware_maybe_apply_linux_cmdline_append(env);
    }

    decoded.tmpl = tmpl & 0x1f;
    decoded.slot[0] = slot0 & IA64_SLOT_MASK;
    decoded.slot[1] = slot1 & IA64_SLOT_MASK;
    decoded.slot[2] = slot2 & IA64_SLOT_MASK;
    decoded.info = ia64_template_info(decoded.tmpl);
    decoded.valid = decoded.info->valid;

    if (ia64_perf_enabled()) {
        ia64_perf_count_tcg_fallback_reason(
            ia64_tcg_fallback_reason_for_bundle(&decoded, env->ip));
    }

    if (!decoded.valid) {
        abort_unsupported_slot(env, &decoded, 0);
    }

    if (debug_hooks) {
        ia64_progress_trace_bundle(env);
        ia64_bundle_trace_decoded(env, &decoded, start_slot);
        ia64_state_trace_bundle(env);
    }

    {
        IA64CountedStoreLoop store_loop;

        if (start_slot == 0 &&
            ia64_decode_counted_store_loop(&decoded, env->ip, &store_loop) &&
            exec_counted_store_loop(env, &store_loop, &next_ip)) {
            IA64_PERF_INC(IA64_PERF_OP_STORE);
            ia64_finish_interpreted_bundle(env, next_ip, 0);
            return;
        }
    }

    if (start_slot >= IA64_SLOT_COUNT) {
        start_slot = 0;
    }

    for (int slot = start_slot; slot < IA64_SLOT_COUNT; slot++) {
        IA64SlotType type = decoded.info->slot_type[slot];
        uint64_t raw = decoded.slot[slot];
        uint8_t qp = ia64_slot_predicate(raw);
        IA64LdstImmediate ldst;
        IA64FloatingMemoryInstruction fldst;
        IA64FloatingCompareInstruction fcmp;
        IA64AtomicInstruction atomic;
        IA64CompareInstruction cmp;
        IA64PredicateTestInstruction pred_test;
        IA64ExtractInstruction extract;
        IA64DepositInstruction deposit;
        IA64IntegerExtendInstruction int_ext;

        ia64_env_set_ri(env, slot);
        IA64_PERF_INC(IA64_PERF_INTERP_SLOT_ITERATION);
        if (ia64_perf_enabled()) {
            ia64_perf_count_slot_type(type);
        }

        if (decoded.info->long_immediate && slot == 1) {
            uint8_t x_qp = ia64_slot_predicate(decoded.slot[2]);

            if (ia64_read_pr(env, x_qp)) {
                IA64_PERF_INC(IA64_PERF_INTERP_LONG_IMMEDIATE);
                if (!ia64_exec_lx_movl(env, decoded.slot[1],
                                       decoded.slot[2]) &&
                    !ia64_exec_lx_nop_or_hint(env, decoded.slot[1],
                                              decoded.slot[2])) {
                    abort_unsupported_slot(env, &decoded, 1);
                }
            }
            slot++;
            continue;
        }

        if (!ia64_read_pr(env, qp)) {
            IA64_PERF_INC(IA64_PERF_INTERP_PREDICATED_FALSE);
            if (exec_false_predicated_side_effect(env, &decoded, slot)) {
                IA64_PERF_INC(IA64_PERF_INTERP_FALSE_PRED_SIDE_EFFECT);
                continue;
            }
            if (!(type == IA64_SLOT_TYPE_B &&
                  ia64_slot_major_opcode(raw) == 0x4 &&
                  (((raw >> 6) & 0x7) == 2 || ((raw >> 6) & 0x7) == 3))) {
                continue;
            }
        }
        IA64_PERF_INC(IA64_PERF_INTERP_SLOT_EXECUTED);
        if (fallback_plan != 0) {
            IA64TcgFallbackPlanOp planned_op =
                ia64_tcg_fallback_plan_slot(fallback_plan, slot);

            if (planned_op != IA64_TCG_FALLBACK_PLAN_GENERIC) {
                IA64PlannedSlotResult planned =
                    exec_predecoded_slot(env, &decoded, slot, type, raw,
                                         planned_op, &next_ip, &next_ri);

                if (planned != IA64_PLANNED_SLOT_GENERIC) {
                    planned_slot_count++;
                    if (planned == IA64_PLANNED_SLOT_CONTINUE) {
                        continue;
                    }
                    break;
                }
                planned_bailout_count++;
            }
        }
        if (ia64_insn_slot_supported(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_INSN);
            continue;
        }
        if (ia64_slot_is_i_nop(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_NOP);
            continue;
        }
        if (ia64_slot_is_i_break(type, raw)) {
            uint64_t iim = ia64_i_break_immediate(raw);

            ia64_progress_trace_break_slot(env, &decoded, slot, "break.i",
                                           iim);
            ia64_deliver_break(env, "break.i", iim, &next_ip);
            break;
        }
        if (ia64_slot_is_m34_alloc(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_ALLOC);
            ia64_exec_m34_alloc(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mov_ip(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_MOV_IP);
            ia64_exec_i_mov_ip(env, raw, env->ip);
            continue;
        }
        if (ia64_slot_is_i_mov_from_branch(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_BRANCH_REGISTER);
            ia64_exec_i_mov_from_branch(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mov_to_branch(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_BRANCH_REGISTER);
            ia64_exec_i_mov_to_branch(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mov_from_predicate(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_PREDICATE_REGISTER);
            ia64_exec_i_mov_from_predicate(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mov_to_predicate(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_PREDICATE_REGISTER);
            ia64_exec_i_mov_to_predicate(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mov_to_rotating_predicate_immediate(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_PREDICATE_REGISTER);
            ia64_exec_i_mov_to_rotating_predicate_immediate(env, raw);
            continue;
        }
        if (ia64_slot_is_mov_to_application(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_APPLICATION_REGISTER);
            ia64_exec_mov_to_application(env, type, raw);
            continue;
        }
        if (ia64_slot_is_mov_from_application(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_APPLICATION_REGISTER);
            ia64_exec_mov_from_application(env, type, raw);
            continue;
        }
        if (ia64_slot_is_mov_to_application_immediate(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_APPLICATION_REGISTER);
            ia64_exec_mov_to_application_immediate(env, type, raw);
            continue;
        }
        if (ia64_slot_is_check_speculative(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_SPECULATION_CHECK);
            ia64_exec_check_speculative(env, type, raw, env->ip, &next_ip);
            if (next_ip == 0) {
                abort_zero_branch(env, &decoded, slot);
            }
            if (next_ip != env->ip + IA64_BUNDLE_SIZE) {
                break;
            }
            continue;
        }
        if (ia64_slot_is_m_check_advanced(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_SPECULATION_CHECK);
            ia64_exec_m_check_advanced(env, raw, env->ip, &next_ip);
            if (next_ip == 0) {
                abort_zero_branch(env, &decoded, slot);
            }
            if (next_ip != env->ip + IA64_BUNDLE_SIZE) {
                break;
            }
            continue;
        }
        if (ia64_slot_is_m_processor_mask(type, raw)) {
            uint64_t old_psr = ia64_env_psr(env);

            if (ia64_exec_m_processor_mask(env, raw)) {
                IA64_PERF_INC(IA64_PERF_OP_PROCESSOR_MASK);
                ia64_count_psr_transition(env, old_psr, ia64_env_psr(env));
                continue;
            }
        }
        if (ia64_slot_is_m_mov_from_processor_status(type, raw) &&
            ia64_exec_m_mov_from_processor_status(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_PROCESSOR_STATUS);
            continue;
        }
        if (ia64_slot_is_m_mov_to_processor_status(type, raw)) {
            uint64_t old_psr = ia64_env_psr(env);

            if (ia64_exec_m_mov_to_processor_status(env, raw)) {
                IA64_PERF_INC(IA64_PERF_OP_PROCESSOR_STATUS);
                ia64_count_psr_transition(env, old_psr, ia64_env_psr(env));
                continue;
            }
        }
        if (ia64_slot_is_m_break(type, raw)) {
            uint64_t iim = ia64_m_break_immediate(raw);

            ia64_progress_trace_break_slot(env, &decoded, slot, "break.m",
                                           iim);
            ia64_deliver_break(env, "break.m", iim, &next_ip);
            break;
        }
        if (ia64_slot_is_b_break(type, raw)) {
            uint64_t iim = ia64_b_break_immediate(raw);

            ia64_progress_trace_break_slot(env, &decoded, slot, "break.b",
                                           iim);
            ia64_deliver_break(env, "break.b", iim, &next_ip);
            break;
        }
        if (ia64_slot_is_m_mov_to_region_register(type, raw) &&
            ia64_exec_m_mov_to_region_register(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_REGION_REGISTER);
            /*
             * QEMU's host TLB is keyed by virtual page and mmu_idx, while
             * IA-64 RIDs live inside RR state used by target-side lookup.
             * Drop cached host translations when a region register changes.
             */
            tlb_flush(cpu);
            IA64_PERF_INC(IA64_PERF_QEMU_TLB_FLUSH_FULL);
            continue;
        }
        if (ia64_slot_is_m_mov_from_region_register(type, raw) &&
            ia64_exec_m_mov_from_region_register(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_REGION_REGISTER);
            continue;
        }
        if (ia64_slot_is_m_mov_to_control(type, raw) &&
            ia64_exec_m_mov_to_control(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_CONTROL_REGISTER);
            continue;
        }
        if (ia64_slot_is_m_mov_from_control(type, raw) &&
            ia64_exec_m_mov_from_control(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_CONTROL_REGISTER);
            continue;
        }
        if (ia64_slot_is_m_mov_from_processor_identifier(type, raw) &&
            ia64_exec_m_mov_from_processor_identifier(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_PROCESSOR_ID);
            continue;
        }
        if (ia64_slot_is_m_mov_to_indexed_system_register(type, raw) &&
            ia64_exec_m_mov_to_indexed_system_register(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_INDEXED_SYSTEM_REGISTER);
            continue;
        }
        if (ia64_slot_is_m_mov_from_indexed_system_register(type, raw) &&
            ia64_exec_m_mov_from_indexed_system_register(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_INDEXED_SYSTEM_REGISTER);
            continue;
        }
        if (ia64_slot_is_m_insert_translation(type, raw) &&
            ia64_exec_m_insert_translation(env, raw)) {
            uint8_t ps = (env->cr[IA64_CR_ITIR] >> 2) & 0x3f;

            IA64_PERF_INC(IA64_PERF_OP_INSERT_TRANSLATION);
            ia64_flush_qemu_tlb_for_page(cpu, env->cr[IA64_CR_IFA], ps);
            continue;
        }
        if (ia64_slot_is_m_probe(type, raw)) {
            IA64TranslateResult fault;
            IA64ProbeStatus status =
                ia64_exec_m_probe_checked(env, raw, &fault);

            if (status == IA64_PROBE_FAULT) {
                IA64_PERF_INC(IA64_PERF_OP_PROBE_TRANSLATION);
                ia64_exit_after_translation_fault(env, &fault);
            }
            if (status == IA64_PROBE_OK) {
                IA64_PERF_INC(IA64_PERF_OP_PROBE_TRANSLATION);
                continue;
            }
        }
        if (ia64_slot_is_m_virtual_translation(type, raw)) {
            IA64TranslateResult fault;
            IA64VirtualTranslationStatus status =
                ia64_exec_m_virtual_translation_checked(env, raw, &fault);

            if (status == IA64_VIRTUAL_TRANSLATION_FAULT) {
                IA64_PERF_INC(IA64_PERF_OP_VIRTUAL_TRANSLATION);
                ia64_exit_after_translation_fault(env, &fault);
            }
            if (status == IA64_VIRTUAL_TRANSLATION_OK) {
                IA64_PERF_INC(IA64_PERF_OP_VIRTUAL_TRANSLATION);
                continue;
            }
        }
        if (ia64_slot_is_m_purge_translation(type, raw) &&
            ia64_exec_m_purge_translation(env, raw)) {
            uint8_t px6 = (raw >> 27) & 0x3f;
            uint8_t ps = (ia64_read_gr(env, (raw >> 13) & 0x7f) >> 2) & 0x3f;

            IA64_PERF_INC(IA64_PERF_OP_PURGE_TRANSLATION);
            /*
             * The modeled translation-cache/register entries were invalidated;
             * drop the matching host softmmu TLB so stale cached pages re-fill.
             * Flush exactly the purged ia64 page range: ia64 pages can be larger
             * than TARGET_PAGE_SIZE, so a single host-page flush would leave
             * stale mappings whose physical page is later reused and corrupted
             * (seen as a slab free_block NULL deref). A range flush over just the
             * page -- rather than a full tlb_flush on every ptc.l -- also avoids
             * the re-fault storm during library mmap/mprotect that makes
             * userspace crawl. ptc.e and unusual page sizes fall back to a full
             * flush.
             */
            if (px6 != 0x34) {
                ia64_flush_qemu_tlb_for_page(
                    cpu, ia64_read_gr(env, (raw >> 20) & 0x7f), ps);
            } else {
                tlb_flush(cpu);
                IA64_PERF_INC(IA64_PERF_QEMU_TLB_FLUSH_FULL);
            }
            continue;
        }
        if (ia64_slot_is_m_invala(type, raw) &&
            ia64_exec_m_invala(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_INVALA);
            continue;
        }
        if (ia64_slot_is_m_flushrs(type, raw)) {
            ia64_exec_flushrs(env);
            continue;
        }
        if (ia64_slot_is_m_loadrs(type, raw)) {
            ia64_exec_loadrs(env);
            continue;
        }
        if (ia64_slot_is_m_system_noop(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_SYSTEM_NOOP);
            continue;
        }
        if (ia64_slot_is_m_setf(type, raw) && ia64_exec_m_setf(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_SETF_GETF);
            continue;
        }
        if (ia64_slot_is_m_getf(type, raw) && ia64_exec_m_getf(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_SETF_GETF);
            continue;
        }
        if (ia64_decode_m_atomic(type, raw, &atomic) &&
            exec_m_atomic(env, &atomic)) {
            IA64_PERF_INC(IA64_PERF_OP_ATOMIC);
            continue;
        }
        if (ia64_decode_extract(type, raw, &extract) &&
            ia64_exec_extract(env, &extract)) {
            IA64_PERF_INC(IA64_PERF_OP_EXTRACT_DEPOSIT);
            continue;
        }
        if (ia64_decode_deposit(type, raw, &deposit) &&
            ia64_exec_deposit(env, &deposit)) {
            IA64_PERF_INC(IA64_PERF_OP_EXTRACT_DEPOSIT);
            continue;
        }
        if (ia64_slot_is_i_shift_right_pair(type, raw) &&
            ia64_exec_i_shift_right_pair(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_SHIFT_EXTEND);
            continue;
        }
        if (ia64_decode_integer_extend(type, raw, &int_ext) &&
            ia64_exec_integer_extend(env, &int_ext)) {
            IA64_PERF_INC(IA64_PERF_OP_SHIFT_EXTEND);
            continue;
        }
        if (ia64_slot_is_f_reciprocal_approx(type, raw) &&
            ia64_exec_f_reciprocal_approx(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_FLOAT);
            continue;
        }
        if (ia64_slot_is_f_misc(type, raw) &&
            ia64_exec_f_misc(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_FLOAT);
            continue;
        }
        if (ia64_slot_is_f_multiply_add(type, raw) &&
            ia64_exec_f_multiply_add(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_FLOAT);
            continue;
        }
        if (ia64_slot_is_f_select_or_xma(type, raw) &&
            ia64_exec_f_select_or_xma(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_FLOAT);
            continue;
        }
        if (ia64_decode_floating_compare(type, raw, &fcmp) &&
            ia64_exec_floating_compare(env, &fcmp)) {
            IA64_PERF_INC(IA64_PERF_OP_FLOAT);
            continue;
        }
        if (ia64_decode_floating_memory(type, raw, &fldst) &&
            exec_floating_memory(env, &fldst)) {
            IA64_PERF_INC(IA64_PERF_OP_FLOAT_MEMORY);
            continue;
        }
        if (ia64_decode_ldst_immediate(type, raw, &ldst) &&
            exec_ldst_immediate(env, &ldst)) {
            switch (ldst.kind) {
            case IA64_LDST_IMM_LOAD:
                IA64_PERF_INC(IA64_PERF_OP_LOAD);
                break;
            case IA64_LDST_IMM_STORE:
                IA64_PERF_INC(IA64_PERF_OP_STORE);
                break;
            case IA64_LDST_IMM_PREFETCH:
                IA64_PERF_INC(IA64_PERF_OP_PREFETCH);
                break;
            default:
                break;
            }
            continue;
        }
        if (ia64_decode_compare(type, raw, &cmp) &&
            ia64_exec_compare(env, &cmp)) {
            IA64_PERF_INC(IA64_PERF_OP_COMPARE);
            continue;
        }
        if (ia64_decode_predicate_test(type, raw, &pred_test) &&
            ia64_exec_predicate_test(env, &pred_test)) {
            IA64_PERF_INC(IA64_PERF_OP_PREDICATE_TEST);
            if (pred_test.kind == IA64_PRED_TEST_NAT) {
                IA64_PERF_INC(IA64_PERF_OP_NAT_TEST);
            }
            continue;
        }
        if (ia64_slot_is_alu_add(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_ALU);
            ia64_exec_alu_add(env, raw);
            continue;
        }
        if (ia64_slot_is_alu_sub(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_ALU);
            ia64_exec_alu_sub(env, raw);
            continue;
        }
        if (ia64_slot_is_alu_logic(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_ALU);
            ia64_exec_alu_logic(env, raw);
            continue;
        }
        if (ia64_slot_is_alu_addp4(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_ALU);
            ia64_exec_alu_addp4(env, raw);
            continue;
        }
        if (ia64_slot_is_alu_shladd(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_ALU);
            ia64_exec_alu_shladd(env, raw);
            continue;
        }
        if (ia64_slot_is_i_packed_i2(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_ALU);
            ia64_exec_i_packed_i2(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mux(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_ALU);
            ia64_exec_i_mux(env, raw);
            continue;
        }
        if (ia64_slot_is_i_bit_count(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_ALU);
            ia64_exec_i_bit_count(env, raw);
            continue;
        }
        if (ia64_slot_is_i_variable_shift(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_ALU);
            ia64_exec_i_variable_shift(env, raw);
            continue;
        }
        if (ia64_slot_is_addl(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_ADDL);
            ia64_exec_addl(env, raw);
            continue;
        }
        if (ia64_slot_is_b_branch_relative(type, raw)) {
            bool branch_taken = false;

            IA64_PERF_INC(IA64_PERF_OP_BRANCH_DIRECT);
            ia64_exec_b_branch_relative(env, raw, env->ip, &next_ip,
                                        &branch_taken);
            if (next_ip == 0) {
                abort_zero_branch(env, &decoded, slot);
            }
            if (branch_taken || next_ip != env->ip + IA64_BUNDLE_SIZE) {
                IA64_PERF_INC(IA64_PERF_BRANCH_TAKEN);
                break;
            }
            IA64_PERF_INC(IA64_PERF_BRANCH_FALLTHROUGH);
            continue;
        }
        if (ia64_slot_is_b_call_relative(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_BRANCH_CALL);
            IA64_PERF_INC(IA64_PERF_BRANCH_TAKEN);
            ia64_exec_b_call_relative(env, raw, env->ip, &next_ip);
            if (next_ip == 0) {
                abort_zero_branch(env, &decoded, slot);
            }
            break;
        }
        if (ia64_slot_is_b_indirect_branch(type, raw)) {
            uint8_t branch_major = ia64_slot_major_opcode(raw);
            uint8_t branch_x6 = (raw >> 27) & 0x3f;
            bool rfi = branch_major == 0x0 && branch_x6 == 0x08;
            bool rfi_valid_ifs =
                rfi && (env->cr[IA64_CR_IFS] & IA64_IFS_VALID_BIT) != 0;
            bool br_ret = branch_major == 0x0 && branch_x6 == 0x21;
            bool cover = branch_major == 0x0 && branch_x6 == 0x02;
            bool epc = branch_major == 0x0 && branch_x6 == 0x10;
            uint64_t old_psr = ia64_env_psr(env);

            IA64_PERF_INC(IA64_PERF_OP_BRANCH_INDIRECT);
            IA64_PERF_INC(IA64_PERF_BRANCH_TAKEN);
            if (cover) {
                IA64_PERF_INC(IA64_PERF_TRANSITION_COVER);
            }
            if (epc) {
                IA64_PERF_INC(IA64_PERF_TRANSITION_EPC);
            }
            if (br_ret) {
                ia64_rse_probe_restored_frame_fill(
                    env, (env->ar[IA64_AR_PFS] >> 7) & 0x7f);
            }
            if (rfi_valid_ifs) {
                ia64_rse_probe_restored_frame_fill(
                    env, env->cr[IA64_CR_IFS] & 0x7f);
            }
            ia64_exec_b_indirect_branch(env, raw, env->ip, &next_ip);
            if (br_ret) {
                ia64_rse_maybe_fill_restored_frame(env,
                                                   (env->cfm >> 7) & 0x7f);
            }
            if (rfi_valid_ifs) {
                IA64_PERF_INC(IA64_PERF_TRANSITION_RFI_VALID_IFS);
                ia64_rse_maybe_fill_restored_frame(env, env->rse.sof);
            }
            if (rfi) {
                IA64_PERF_INC(IA64_PERF_TRANSITION_RFI);
                IA64_PERF_INC(ia64_helper_psr_cpl(ia64_env_psr(env)) == 3 ?
                              IA64_PERF_TRANSITION_RFI_TO_USER :
                              IA64_PERF_TRANSITION_RFI_TO_KERNEL);
                next_ri = ia64_env_ri(env);
            }
            ia64_count_psr_transition(env, old_psr, ia64_env_psr(env));
            if (next_ip == 0) {
                abort_zero_branch(env, &decoded, slot);
            }
            break;
        }
        if (ia64_slot_is_b_predict_or_nop(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_BRANCH_PREDICT);
            continue;
        }
        if (decoded.info->long_immediate && type == IA64_SLOT_TYPE_X) {
            abort_unsupported_slot(env, &decoded, 1);
        }

        abort_unsupported_slot(env, &decoded, slot);
    }

    IA64_PERF_ADD(IA64_PERF_TCG_FALLBACK_PLAN_SLOT, planned_slot_count);
    IA64_PERF_ADD(IA64_PERF_TCG_FALLBACK_PLAN_BAILOUT, planned_bailout_count);
    ia64_finish_interpreted_bundle(env, next_ip, next_ri);
}

void HELPER(exec_bundle)(CPUIA64State *env,
                         uint32_t tmpl,
                         uint64_t slot0,
                         uint64_t slot1,
                         uint64_t slot2,
                         uint32_t fallback_plan)
{
    ia64_exec_bundle_impl(env, tmpl, slot0, slot1, slot2, fallback_plan);
}

uint32_t HELPER(exec_bundle_lookup_ptr)(CPUIA64State *env,
                                        uint32_t tmpl,
                                        uint64_t slot0,
                                        uint64_t slot1,
                                        uint64_t slot2,
                                        uint32_t fallback_plan)
{
    ia64_exec_bundle_impl(env, tmpl, slot0, slot1, slot2, fallback_plan);
    return ia64_lookup_ptr_chain_ok(env);
}
