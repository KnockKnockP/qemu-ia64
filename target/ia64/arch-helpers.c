/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Architectural helper transactions used by the production translator.
 *
 * These helpers accept only normalized architectural inputs.  The optional
 * interpreter oracle has its own dispatcher and must not own symbols needed
 * by a full-TCG executable.
 */

#include "qemu/osdep.h"
#include "accel/tcg/cpu-loop.h"
#include "exec/cpu-interrupt.h"
#include "exec/cputlb.h"
#include "hw/core/cpu.h"
#include "cpu.h"
#include "exception.h"
#include "insn.h"
#include "mem.h"
#include "perf.h"
#include "exec/helper-proto.h"

#define IA64_PSR_I_BIT UINT64_C(0x0000000000004000)

static G_NORETURN void ia64_arch_raise_illegal(CPUIA64State *env)
{
    CPUState *cpu = env_cpu(env);

    ia64_deliver_illegal_operation_fast(env);
    env->fault_exit_pending_tb_translate = true;
    IA64_PERF_INC(IA64_PERF_CPU_LOOP_EXIT);
    cpu_loop_exit(cpu);
}

static G_NORETURN void ia64_arch_raise_reserved_register(
    CPUIA64State *env)
{
    CPUState *cpu = env_cpu(env);

    ia64_deliver_exception_fast(env, IA64_EXCEPTION_GENERAL_EXCEPTION,
                                env->ip, IA64_EXCEPTION_ACCESS_NONE, NULL);
    env->exception.isr_code = 0x30;
    env->cr[IA64_CR_ISR] = (env->cr[IA64_CR_ISR] & ~IA64_ISR_CODE_MASK) |
                           env->exception.isr_code;
    env->fault_exit_pending_tb_translate = true;
    IA64_PERF_INC(IA64_PERF_CPU_LOOP_EXIT);
    cpu_loop_exit(cpu);
}

static G_NORETURN void ia64_arch_raise_privileged(CPUIA64State *env)
{
    CPUState *cpu = env_cpu(env);

    ia64_deliver_exception_fast(env, IA64_EXCEPTION_GENERAL_EXCEPTION,
                                env->ip, IA64_EXCEPTION_ACCESS_NONE, NULL);
    env->exception.isr_code = 0x10;
    env->cr[IA64_CR_ISR] = (env->cr[IA64_CR_ISR] & ~IA64_ISR_CODE_MASK) |
                           env->exception.isr_code;
    env->fault_exit_pending_tb_translate = true;
    IA64_PERF_INC(IA64_PERF_CPU_LOOP_EXIT);
    cpu_loop_exit(cpu);
}

G_NORETURN void HELPER(raise_illegal_operation)(CPUIA64State *env)
{
    ia64_arch_raise_illegal(env);
}

G_NORETURN void HELPER(raise_privileged_operation)(CPUIA64State *env)
{
    ia64_arch_raise_privileged(env);
}

G_NORETURN void HELPER(raise_register_nat_consumption)(CPUIA64State *env,
                                                        uint64_t isr_extra)
{
    CPUState *cpu = env_cpu(env);

    ia64_deliver_exception_fast(env,
                                IA64_EXCEPTION_REGISTER_NAT_CONSUMPTION,
                                env->ip, IA64_EXCEPTION_ACCESS_NONE, NULL);
    env->exception.isr_code |= isr_extra;
    env->cr[IA64_CR_ISR] |= isr_extra;
    env->fault_exit_pending_tb_translate = true;
    IA64_PERF_INC(IA64_PERF_CPU_LOOP_EXIT);
    cpu_loop_exit(cpu);
}

void HELPER(clear_fault_suppression)(CPUIA64State *env, uint64_t entry_mask)
{
    uint64_t cleared = ia64_clear_fault_suppression_state(env, entry_mask);

    if (cleared & (IA64_PSR_DA_BIT | IA64_PSR_IA_BIT)) {
        tlb_flush(env_cpu(env));
    }
}

G_NORETURN void HELPER(raise_data_register_nat_consumption)(
    CPUIA64State *env, uint32_t access_type)
{
    ia64_raise_arch_register_nat_consumption(
        env, (MMUAccessType)access_type, NULL);
}

G_NORETURN void ia64_raise_arch_register_nat_consumption(
    CPUIA64State *env, MMUAccessType access_type, const char *detail)
{
    CPUState *cpu = env_cpu(env);

    ia64_deliver_exception_fast(
        env, IA64_EXCEPTION_REGISTER_NAT_CONSUMPTION, env->ip,
        access_type, detail);
    env->fault_exit_pending_tb_translate = true;
    IA64_PERF_INC(IA64_PERF_CPU_LOOP_EXIT);
    cpu_loop_exit(cpu);
}

G_NORETURN void ia64_raise_data_plane_exception(
    CPUIA64State *env, IA64ExceptionKind kind, vaddr address,
    int32_t access_type)
{
    CPUState *cpu = env_cpu(env);

    g_assert(kind == IA64_EXCEPTION_DATA_DEBUG ||
             kind == IA64_EXCEPTION_DATA_NAT_PAGE_CONSUMPTION ||
             kind == IA64_EXCEPTION_UNSUPPORTED_DATA_REFERENCE);
    ia64_deliver_exception_fast(env, kind, address, access_type, NULL);
    env->fault_exit_pending_tb_translate = true;
    IA64_PERF_INC(IA64_PERF_CPU_LOOP_EXIT);
    cpu_loop_exit(cpu);
}

G_NORETURN void HELPER(raise_unaligned_data_reference)(
    CPUIA64State *env, uint64_t address, uint32_t access_type)
{
    ia64_raise_arch_unaligned_data_reference(
        env, address, (MMUAccessType)access_type);
}

G_NORETURN void ia64_raise_arch_unaligned_data_reference(
    CPUIA64State *env, vaddr address, MMUAccessType access_type)
{
    CPUState *cpu = env_cpu(env);

    ia64_deliver_exception_fast(
        env, IA64_EXCEPTION_UNALIGNED_DATA_REFERENCE, address,
        access_type, "unaligned data reference");
    env->fault_exit_pending_tb_translate = true;
    IA64_PERF_INC(IA64_PERF_CPU_LOOP_EXIT);
    cpu_loop_exit(cpu);
}

G_NORETURN void ia64_raise_arch_translation_fault(
    CPUIA64State *env, const IA64TranslateResult *result)
{
    CPUState *cpu = env_cpu(env);

    ia64_deliver_exception_fast(
        env, ia64_exception_for_translate_result(result), result->vaddr,
        result->access_type, result->message);
    env->fault_exit_pending_tb_translate = true;
    IA64_PERF_INC(IA64_PERF_CPU_LOOP_EXIT);
    cpu_loop_exit(cpu);
}

void HELPER(perf_tb_exec)(void)
{
    IA64_PERF_INC(IA64_PERF_TB_EXECUTED);
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

void HELPER(memory_store_alat_invalidate)(CPUIA64State *env,
                                          uint64_t address,
                                          uint32_t width)
{
    IA64_PROFILE_HELPER(IA64_PROFILE_HELPER_NAT_ALAT);
    ia64_data_plane_alat_invalidate_store(env, address, width);
}

void HELPER(gr_alat_invalidate_mask)(CPUIA64State *env, uint64_t mask_lo,
                                     uint64_t mask_hi)
{
    uint32_t valid_mask;

    IA64_PROFILE_HELPER(IA64_PROFILE_HELPER_NAT_ALAT);
    mask_lo &= ~UINT64_C(1);
    mask_lo &= env->alat.gr_mask[0];
    mask_hi &= env->alat.gr_mask[1];
    if ((mask_lo | mask_hi) == 0) {
        return;
    }

    valid_mask = env->alat.valid_mask;
    while (valid_mask != 0) {
        unsigned index = ctz32(valid_mask);
        unsigned reg = env->alat.entries[index].target;
        uint64_t mask = reg < 64 ? mask_lo : mask_hi;

        valid_mask &= valid_mask - 1;
        if (mask & (UINT64_C(1) << (reg % 64))) {
            ia64_alat_set_valid(env, index, false);
        }
    }
}

void HELPER(retire_translated_bundles)(CPUIA64State *env,
                                       uint32_t bundle_count)
{
    IA64_PROFILE_HELPER(IA64_PROFILE_HELPER_OTHER);
    if (bundle_count == 0) {
        return;
    }

    ia64_benchmark_retire(env, bundle_count);
    if (ia64_external_interrupt_enabled(env)) {
        IA64_PERF_INC(IA64_PERF_CPU_LOOP_EXIT);
        cpu_loop_exit(env_cpu(env));
    }
}

static unsigned ia64_arch_psr_cpl(uint64_t psr)
{
    return (psr & IA64_PSR_CPL_MASK) >> IA64_PSR_CPL_SHIFT;
}

static void ia64_arch_count_psr_transition(CPUIA64State *env,
                                           uint64_t old_psr,
                                           uint64_t new_psr)
{
    unsigned old_cpl = ia64_arch_psr_cpl(old_psr);
    unsigned new_cpl = ia64_arch_psr_cpl(new_psr);
    bool old_bank = (old_psr & IA64_PSR_BN_BIT) != 0;
    bool new_bank = (new_psr & IA64_PSR_BN_BIT) != 0;

    if (old_cpl != new_cpl) {
        IA64_PERF_INC(IA64_PERF_TRANSITION_PRIVILEGE_CHANGE);
        if (old_cpl == 3 && new_cpl < 3) {
            IA64_PERF_INC(IA64_PERF_TRANSITION_USER_TO_KERNEL);
        } else if (old_cpl < 3 && new_cpl == 3) {
            IA64_PERF_INC(IA64_PERF_TRANSITION_KERNEL_TO_USER);
        }
    }
    if (old_bank != new_bank) {
        IA64_PERF_INC(IA64_PERF_TRANSITION_BANK_SWITCH);
        IA64_PERF_INC(new_bank ? IA64_PERF_TRANSITION_BANK_SWITCH_TO_BANK1 :
                                 IA64_PERF_TRANSITION_BANK_SWITCH_TO_BANK0);
    }
    if ((old_psr & IA64_PSR_I_BIT) == 0 &&
        (new_psr & IA64_PSR_I_BIT) != 0 &&
        ia64_external_interrupt_pending(env)) {
        IA64_PERF_INC(IA64_PERF_INTERRUPT_UNMASK_PENDING);
    }
}

static bool ia64_arch_can_chain(CPUIA64State *env)
{
    CPUState *cpu = env_cpu(env);
    uint32_t interrupt_request;

    if (qatomic_read(&cpu->exit_request)) {
        return false;
    }
    ia64_refresh_interrupt_delivery(env);
    interrupt_request = qatomic_read(&cpu->interrupt_request);
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

void HELPER(rotate_modulo_registers)(CPUIA64State *env)
{
    IA64_PROFILE_HELPER(IA64_PROFILE_HELPER_RSE);
    ia64_rotate_modulo_scheduled_registers(env);
}

void HELPER(enter_call_frame)(CPUIA64State *env)
{
    IA64_PROFILE_HELPER(IA64_PROFILE_HELPER_RSE);
    ia64_enter_call_frame(env);
}

uint32_t HELPER(return_frame_from_pfs)(CPUIA64State *env, uint64_t pfs)
{
    uint32_t old_cpl = ia64_arch_psr_cpl(ia64_env_psr(env));
    uint32_t new_cpl;

    IA64_PROFILE_HELPER(IA64_PROFILE_HELPER_RSE);
    ia64_rse_return_frame_from_pfs(env, pfs);
    new_cpl = ia64_arch_psr_cpl(ia64_env_psr(env));
    return new_cpl > old_cpl;
}

void HELPER(complete_rse_frame_loads)(CPUIA64State *env)
{
    IA64_PROFILE_HELPER(IA64_PROFILE_HELPER_RSE);
    ia64_rse_complete_frame_loads(env);
}

void HELPER(rfi)(CPUIA64State *env, uint64_t source_ip)
{
    uint64_t old_psr = ia64_env_psr(env);
    bool valid_ifs = (env->cr[IA64_CR_IFS] & IA64_IFS_VALID_BIT) != 0;

    IA64_PROFILE_HELPER(IA64_PROFILE_HELPER_RSE);
    IA64_PERF_INC(IA64_PERF_OP_BRANCH_INDIRECT);
    IA64_PERF_INC(IA64_PERF_BRANCH_TAKEN);
    ia64_rfi_restore_state(env, source_ip);
    if (valid_ifs) {
        IA64_PERF_INC(IA64_PERF_TRANSITION_RFI_VALID_IFS);
    }
    IA64_PERF_INC(IA64_PERF_TRANSITION_RFI);
    IA64_PERF_INC(ia64_arch_psr_cpl(ia64_env_psr(env)) == 3 ?
                  IA64_PERF_TRANSITION_RFI_TO_USER :
                  IA64_PERF_TRANSITION_RFI_TO_KERNEL);
    ia64_arch_count_psr_transition(env, old_psr, ia64_env_psr(env));
    ia64_refresh_interrupt_delivery(env);
    ia64_rse_complete_frame_loads(env);
    ia64_refresh_interrupt_delivery(env);
}

uint64_t HELPER(rse_alloc)(CPUIA64State *env, uint32_t packed)
{
    uint32_t sof = packed & 0x7f;
    uint32_t sol = (packed >> 7) & 0x7f;
    uint32_t sor = (packed >> 14) & 0x0f;
    uint8_t r1 = (packed >> 18) & 0x7f;
    IA64RSEAllocValidation validation =
        ia64_rse_validate_alloc(env, r1, sof, sol, sor, 0);

    IA64_PROFILE_HELPER(IA64_PROFILE_HELPER_RSE);
    IA64_PERF_INC(IA64_PERF_OP_ALLOC);
    if (validation == IA64_RSE_ALLOC_RESERVED_REGISTER_FIELD) {
        ia64_arch_raise_reserved_register(env);
    }
    g_assert(validation == IA64_RSE_ALLOC_VALID);
    ia64_rse_spill_for_alloc(env, sof);
    return ia64_rse_commit_alloc(env, r1, sof, sol, sor);
}

void HELPER(rse_cover)(CPUIA64State *env)
{
    IA64_PROFILE_HELPER(IA64_PROFILE_HELPER_RSE);
    IA64_PERF_INC(IA64_PERF_TRANSITION_COVER);
    ia64_rse_cover_frame(env);
}

void HELPER(rse_flushrs)(CPUIA64State *env)
{
    IA64_PROFILE_HELPER(IA64_PROFILE_HELPER_RSE);
    ia64_exec_flushrs(env);
}

void HELPER(rse_loadrs)(CPUIA64State *env)
{
    IA64_PROFILE_HELPER(IA64_PROFILE_HELPER_RSE);
    if (!ia64_rse_loadrs_is_legal(env)) {
        ia64_arch_raise_illegal(env);
    }
    ia64_exec_loadrs(env);
}

void HELPER(rse_clrrrb)(CPUIA64State *env, uint32_t predicate_only)
{
    IA64_PROFILE_HELPER(IA64_PROFILE_HELPER_RSE);
    ia64_rse_clear_rename_bases(env, predicate_only != 0);
}

uint32_t HELPER(return_chain_ok)(CPUIA64State *env)
{
    bool chain_ok = ia64_arch_can_chain(env);

    IA64_PERF_INC(chain_ok ? IA64_PERF_TB_EXIT_LOOKUP_PTR :
                             IA64_PERF_TB_EXIT_MAIN_LOOP);
    return chain_ok ? 1 : 0;
}

static G_NORETURN void ia64_arch_raise_branch_trap(CPUIA64State *env,
                                                    IA64ExceptionKind kind)
{
    CPUState *cpu = env_cpu(env);

    ia64_deliver_branch_trap(env, kind);
    env->fault_exit_pending_tb_translate = true;
    IA64_PERF_INC(IA64_PERF_CPU_LOOP_EXIT);
    cpu_loop_exit(cpu);
}

G_NORETURN void HELPER(raise_lower_privilege_transfer_trap)(
    CPUIA64State *env)
{
    ia64_arch_raise_branch_trap(env, IA64_EXCEPTION_LOWER_PRIVILEGE_TRANSFER);
}

G_NORETURN void HELPER(raise_taken_branch_trap)(CPUIA64State *env)
{
    ia64_arch_raise_branch_trap(env, IA64_EXCEPTION_TAKEN_BRANCH_TRAP);
}
