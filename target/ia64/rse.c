/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "accel/tcg/cpu-loop.h"
#include "accel/tcg/cpu-ldst.h"
#include "accel/tcg/getpc.h"
#include "accel/tcg/probe.h"
#include "cpu.h"
#include "exec/cputlb.h"
#include "exception.h"
#include "insn.h"
#include "mem.h"
#include "perf.h"

/*
 * A mandatory RSE reference uses RSC.pl for both translation and DBR PLM
 * matching.  A DBR match is lower priority than translation, protection-key,
 * access-right, A-bit, and D-bit faults, but it must be reported before any
 * RAM or MMIO callback.  probe_access() provides exactly that side-effect-free
 * ordering.  Keeping reference set across the probe also gives any
 * higher-priority fault, and the eventual Data Debug fault, ISR.rs=1.
 */
static void ia64_rse_data_debug_pre_access(CPUIA64State *env,
                                           vaddr address,
                                           MMUAccessType access_type,
                                           int mmu_idx,
                                           uintptr_t retaddr)
{
    unsigned debug_access = access_type == MMU_DATA_STORE ?
                            IA64_DEBUG_ACCESS_WRITE :
                            IA64_DEBUG_ACCESS_READ;

    g_assert(access_type == MMU_DATA_LOAD ||
             access_type == MMU_DATA_STORE);
    if (!ia64_rse_data_debug_match(env, address, 8, debug_access)) {
        return;
    }

    probe_access(env, address, 8, access_type, mmu_idx, retaddr);
    ia64_raise_data_plane_exception(env, IA64_EXCEPTION_DATA_DEBUG,
                                    address, access_type);
}

uint64_t ia64_rse_read_u64(CPUIA64State *env, vaddr address,
                           uintptr_t retaddr)
{
    uint64_t value;
    uint64_t suppression = env->psr &
                           (IA64_PSR_DA_BIT | IA64_PSR_DD_BIT);
    int mmu_idx = ia64_rse_mmu_index(ia64_env_psr(env), env->rse.rsc);

    env->rse.reference = true;
    ia64_rse_data_debug_pre_access(env, address, MMU_DATA_LOAD,
                                   mmu_idx, retaddr);
    if (env->rse.rsc & IA64_RSC_BE_BIT) {
        value = cpu_ldq_be_mmuidx_ra(env, address, mmu_idx, retaddr);
    } else {
        value = cpu_ldq_le_mmuidx_ra(env, address, mmu_idx, retaddr);
    }
    env->rse.reference = false;
    if (ia64_clear_fault_suppression_state(env, suppression) &
        IA64_PSR_DA_BIT) {
        tlb_flush(env_cpu(env));
    }
    return value;
}

void ia64_rse_write_u64(CPUIA64State *env, vaddr address, uint64_t value,
                        uintptr_t retaddr)
{
    uint64_t suppression = env->psr &
                           (IA64_PSR_DA_BIT | IA64_PSR_DD_BIT);
    int mmu_idx = ia64_rse_mmu_index(ia64_env_psr(env), env->rse.rsc);

    env->rse.reference = true;
    ia64_rse_data_debug_pre_access(env, address, MMU_DATA_STORE,
                                   mmu_idx, retaddr);
    if (env->rse.rsc & IA64_RSC_BE_BIT) {
        cpu_stq_be_mmuidx_ra(env, address, value, mmu_idx, retaddr);
    } else {
        cpu_stq_le_mmuidx_ra(env, address, value, mmu_idx, retaddr);
    }
    env->rse.reference = false;
    if (ia64_clear_fault_suppression_state(env, suppression) &
        IA64_PSR_DA_BIT) {
        tlb_flush(env_cpu(env));
    }
}

static void ia64_rse_write_backing_store_register(CPUIA64State *env,
                                                  uint64_t address,
                                                  uint64_t value,
                                                  void *opaque);
static bool ia64_rse_mandatory_word_interruption_pending(
    CPUIA64State *env, void *opaque);

static void ia64_rse_finish_mandatory_sequence(CPUIA64State *env,
                                               IA64RSEStepResult result)
{
    if (result == IA64_RSE_STEP_INTERRUPTION) {
        IA64_PERF_INC(IA64_PERF_CPU_LOOP_EXIT);
        cpu_loop_exit(env_cpu(env));
    }
    g_assert(result == IA64_RSE_STEP_DONE);
}

void ia64_exec_flushrs(CPUIA64State *env)
{
    IA64RSEStepResult result;

    IA64_PERF_INC(IA64_PERF_OP_RSE_FLUSHRS);
    result = ia64_rse_flush_dirty_interruptible(
        env, ia64_rse_write_backing_store_register,
        ia64_rse_mandatory_word_interruption_pending, NULL);
    ia64_rse_finish_mandatory_sequence(env, result);
}

static uint64_t ia64_rse_read_backing_store_register(CPUIA64State *env,
                                                     uint64_t address,
                                                     void *opaque)
{
    uint64_t value = ia64_rse_read_u64(env, address, GETPC());

    return value;
}

static void ia64_rse_write_backing_store_register(CPUIA64State *env,
                                                  uint64_t address,
                                                  uint64_t value,
                                                  void *opaque)
{
    ia64_rse_write_u64(env, address, value, GETPC());
}

static bool ia64_rse_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_RSE_TRACE") != NULL;
    }
    return enabled != 0;
}

/*
 * Enforce the physical stacked register file bound before alloc grows the
 * current frame: spill the oldest dirty registers to the backing store so
 * that dirty + sof never exceeds IA64_RSE_PHYS_STACKED_REGS, exactly like
 * hardware's mandatory RSE stores.  See ia64_rse_spill_excess_dirty for why
 * guests break without this.
 */
void ia64_rse_spill_for_alloc(CPUIA64State *env, uint32_t new_sof)
{
    uint64_t old_bspstore = env->rse.bspstore;
    IA64RSEStepResult result;
    uint32_t spilled = 0;

    result = ia64_rse_spill_excess_dirty_interruptible(
        env, new_sof, ia64_rse_write_backing_store_register,
        ia64_rse_mandatory_word_interruption_pending, NULL, &spilled);
    if (spilled != 0) {
        IA64_PERF_INC(IA64_PERF_OP_RSE_ALLOC_SPILL);
        IA64_PERF_ADD(IA64_PERF_OP_RSE_ALLOC_SPILL_REG, spilled);
    }
    if (spilled != 0 && ia64_rse_trace_enabled()) {
        fprintf(stderr,
                "[ia64-rse] ip=0x%016" PRIx64
                " alloc-spill sof=%u spilled=%u"
                " bspstore=0x%016" PRIx64 "->0x%016" PRIx64
                " bsp=0x%016" PRIx64 "\n",
                env->ip, new_sof, spilled, old_bspstore,
                env->rse.bspstore, env->rse.bsp);
    }
    ia64_rse_finish_mandatory_sequence(env, result);
}

static bool ia64_rse_read_mandatory_word(CPUIA64State *env,
                                         uint64_t address,
                                         uint64_t *value, void *opaque)
{
    /*
     * ra == 0 deliberately attributes a mandatory br.ret/rfi fill fault to
     * the already-committed target instruction.  reference remains set if
     * cpu_ldq exits through fault delivery, allowing ISR.rs/ir construction.
     */
    IA64_PERF_INC(IA64_PERF_LDST_READ);
    *value = ia64_rse_read_u64(env, address, 0);
    return true;
}

static bool ia64_rse_mandatory_word_interruption_pending(
    CPUIA64State *env, void *opaque)
{
    (void)opaque;
    ia64_refresh_interrupt_delivery(env);
    return ia64_external_interrupt_enabled(env);
}

void ia64_rse_complete_frame_loads(CPUIA64State *env)
{
    uint64_t old_bspstore = env->rse.bspstore;
    int32_t missing = -MIN(env->rse.dirty, 0);
    IA64RSEStepResult result;
    bool trace = ia64_rse_trace_enabled();

    IA64_PERF_INC(IA64_PERF_OP_RSE_FILL_RESTORED);
    if (env->rse.dirty >= 0 && env->rse.dirty_nat >= 0) {
        /*
         * An interrupt may win after the final mandatory word but before the
         * valid-frame check clears CFLE.  A migrated/rescheduled resume TB
         * must consume that completed boundary instead of remaining keyed as
         * an active completion forever.
         */
        env->rse.cfle = false;
        return;
    }

    result = ia64_rse_complete_mandatory_loads_interruptible(
        env, ia64_rse_read_mandatory_word,
        ia64_rse_mandatory_word_interruption_pending, NULL);
    if (result == IA64_RSE_STEP_INTERRUPTION) {
        /*
         * Return to cpu_exec before fetching the committed target.  CFLE is
         * intentionally still set, so the ordinary external-interruption
         * path records ISR.ir and interruption delivery then exposes the
         * incomplete frame to its handler.
         */
        IA64_PERF_INC(IA64_PERF_CPU_LOOP_EXIT);
        cpu_loop_exit(env_cpu(env));
    }
    g_assert(result == IA64_RSE_STEP_DONE);
    IA64_PERF_INC(IA64_PERF_OP_RSE_FILL_RESTORED_MEM);
    IA64_PERF_ADD(IA64_PERF_OP_RSE_FILL_RESTORED_REG, missing);

    if (trace) {
        fprintf(stderr,
                "[ia64-rse] ip=0x%016" PRIx64
                " fill-restored filled=%d"
                " bspstore=0x%016" PRIx64 "->0x%016" PRIx64
                " bsp=0x%016" PRIx64 "\n",
                env->ip, missing, old_bspstore, env->rse.bspstore,
                env->rse.bsp);
    }
}

static bool ia64_rse_read_loadrs_word(CPUIA64State *env, uint64_t address,
                                      uint64_t *value, void *opaque)
{
    (void)opaque;
    *value = ia64_rse_read_backing_store_register(env, address, NULL);
    return true;
}

void ia64_exec_loadrs(CPUIA64State *env)
{
    uint64_t bytes = ((env->rse.rsc >> 16) & 0x3fff) & ~7ULL;
    int32_t before = env->rse.dirty;
    IA64RSEStepResult result;

    IA64_PERF_INC(IA64_PERF_OP_RSE_LOADRS);
    result = ia64_rse_execute_loadrs_interruptible(
        env, ia64_rse_read_loadrs_word,
        ia64_rse_mandatory_word_interruption_pending, NULL);
    ia64_rse_finish_mandatory_sequence(env, result);
    if (ia64_rse_trace_enabled()) {
        fprintf(stderr,
                "[ia64-rse] ip=0x%016" PRIx64
                " loadrs bytes=0x%016" PRIx64
                " dirty-before=%d dirty-after=%d"
                " bspstore=0x%016" PRIx64 " bsp=0x%016" PRIx64 "\n",
                env->ip, bytes, before, env->rse.dirty,
                env->rse.bspstore, env->rse.bsp);
    }
}
