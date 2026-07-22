/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Architectural IA-64 state transactions shared by the typed TCG runtime.
 *
 * Raw instruction decoding and legacy slot execution live in
 * oracle-insn.c.  Keep this translation unit independent of raw slot bits so
 * a full-TCG executable cannot accidentally acquire a second instruction
 * engine by linking its architectural state support.
 */

#include "qemu/osdep.h"
#include "exception.h"
#include "flight-recorder.h"
#include "fpu/softfloat.h"
#include "insn.h"
#include "mem.h"
#include "perf.h"
#include "qemu/error-report.h"
#include "qemu/host-utils.h"
#include "qemu/timer.h"
#include "trace-target_ia64.h"

#define IA64_FR_EXPONENT_BIAS 0xffff
#define IA64_FR_INTEGER_EXPONENT 0x1003e
#define IA64_FR_SPECIAL_EXPONENT 0x1ffff
#define IA64_FR_NATVAL_EXPONENT 0x1fffe
#define IA64_FR_INTEGER_BIT UINT64_C(0x8000000000000000)
#define IA64_FR_QUIET_NAN_BIT UINT64_C(0x4000000000000000)
#define IA64_FPSR_STATUS_FIELD_SHIFT(sf) (6 + (13 * (sf)))
#define IA64_FPSR_STATUS_FIELD_MASK UINT64_C(0x1fff)
#define IA64_FPSR_STATUS_RC_SHIFT 4
#define IA64_FPSR_STATUS_RC_MASK 0x3
#define IA64_RR_IMPLEMENTED_MASK UINT64_C(0x00000000fffffffd)
#define IA64_PSR_I_BIT UINT64_C(0x0000000000004000)
#define IA64_PSR_BN_BIT UINT64_C(0x0000100000000000)
#define IA64_PSR_MFL_BIT UINT64_C(0x0000000000000010)
#define IA64_PSR_MFH_BIT UINT64_C(0x0000000000000020)
#define IA64_PSR_DFL_BIT UINT64_C(0x0000000000040000)
#define IA64_PSR_DFH_BIT UINT64_C(0x0000000000080000)
#define IA64_PSR_CPL_SHIFT 32
#define IA64_PSR_CPL_MASK UINT64_C(0x0000000300000000)
#define IA64_PFS_CFM_MASK UINT64_C(0x0000003fffffffff)
#define IA64_PFS_PEC_SHIFT 52
#define IA64_PFS_PEC_MASK UINT64_C(0x03f0000000000000)
#define IA64_PFS_PPL_SHIFT 62
#define IA64_PFS_PPL_MASK UINT64_C(0xc000000000000000)
#define IA64_INTERRUPT_VECTOR_MASK UINT64_C(0xff)
#define IA64_INTERRUPT_SPURIOUS_VECTOR UINT64_C(0x0f)
#define IA64_LOCAL_VECTOR_MASK_BIT UINT64_C(0x0000000000010000)
#define IA64_TPR_MIC_MASK UINT64_C(0xf0)
#define IA64_TPR_MMI_BIT UINT64_C(0x0000000000010000)
#define IA64_PSR_LOWER_MASK UINT64_C(0x00000000ffffffff)
#define IA64_PSR_MC_BIT UINT64_C(0x0000000800000000)
#define IA64_PSR_IT_BIT UINT64_C(0x0000001000000000)

static void ia64_alat_invalidate_rotating_frs(CPUIA64State *env);
static void ia64_rse_sync_ar(CPUIA64State *env);
static void ia64_rse_refresh_logical_slot(CPUIA64State *env, uint32_t slot);
static void ia64_alat_invalidate_stacked_gr_range(CPUIA64State *env,
                                                  uint32_t logical_count);
static bool ia64_interrupt_vector_pending(CPUIA64State *env,
                                          uint64_t vector);

static uint64_t ia64_default_region_register(unsigned index)
{
    return ((uint64_t)(index & 0x00ffffff) << 8) | (UINT64_C(12) << 2);
}

void ia64_cpu_init_synthetic_cpuid(CPUIA64State *env)
{
    if (!env) {
        return;
    }

    env->cpuid[0] = UINT64_C(0x49656e69756e6547);
    env->cpuid[1] = UINT64_C(0x000000006c65746e);
    env->cpuid[2] = 0;
    env->cpuid[3] = (UINT64_C(2) << 32) | (IA64_CPUID_COUNT - 1);
    env->cpuid[4] = IA64_CPUID_FEATURE_LB | IA64_CPUID_FEATURE_CZ |
                    IA64_CPUID_FEATURE_X2;
}

bool ia64_issue_group_preserve_ar_source(CPUIA64State *env, uint32_t reg,
                                         uint64_t entry_value)
{
    uint8_t count;

    if (env == NULL || reg >= IA64_AR_COUNT ||
        !env->issue_group.typed_active ||
        env->issue_group.saved_ar_count > IA64_ISSUE_GROUP_AR_CAPACITY) {
        return false;
    }

    count = env->issue_group.saved_ar_count;
    for (unsigned i = 0; i < count; i++) {
        if (env->issue_group.saved_ar_index[i] == reg) {
            /* WAW keeps the visibility-epoch entry image. */
            return true;
        }
    }
    if (count == IA64_ISSUE_GROUP_AR_CAPACITY) {
        return false;
    }

    env->issue_group.saved_ar_index[count] = reg;
    env->issue_group.saved_ar_value[count] = entry_value;
    env->issue_group.saved_ar_count = count + 1;
    return true;
}

uint64_t ia64_issue_group_select_ar_source(const CPUIA64State *env,
                                           uint32_t reg,
                                           uint64_t live_value)
{
    uint8_t count;

    if (env == NULL || reg >= IA64_AR_COUNT ||
        !env->issue_group.typed_active ||
        env->issue_group.saved_ar_count > IA64_ISSUE_GROUP_AR_CAPACITY) {
        return live_value;
    }

    count = env->issue_group.saved_ar_count;
    for (unsigned i = 0; i < count; i++) {
        if (env->issue_group.saved_ar_index[i] == reg) {
            return env->issue_group.saved_ar_value[i];
        }
    }
    return live_value;
}

void ia64_cpu_reset_synthetic_itanium2(CPUIA64State *env)
{
    memset(env, 0, offsetof(CPUIA64State, end_reset_fields));

    /*
     * Synthetic reset: enough for a stable placeholder CPU, not yet validated
     * against PAL/SAL-visible Itanium 2 reset state.
     */
    env->pr = 1;
    env->gr[0] = 0;
    env->ip = 0;
    env->rse.bol = 0;
    env->rse.dirty = 0;
    env->rse.dirty_nat = 0;
    env->rse.clean = 0;
    env->rse.clean_nat = 0;
    env->rse.invalid = IA64_RSE_PHYS_STACKED_REGS;
    env->rse.cfle = false;
    env->rse.reference = false;
    ia64_env_replace_psr(env, 0);
    ia64_env_begin_source_visibility_epoch(env);
    ia64_set_cfm(env, 0);
    /* Intel SDM Vol. 1, Table 5-2: FR0 is the exact register-format
     * positive-zero encoding, not the unsupported pseudo-infinity encoding.
     */
    env->fr[0].raw[1] = 0;
    env->fr[1].raw[0] = IA64_FR_INTEGER_BIT;
    env->fr[1].raw[1] = IA64_FR_EXPONENT_BIAS;

    env->ar[IA64_AR_RSC] = env->rse.rsc;
    env->ar[IA64_AR_BSP] = env->rse.bsp;
    env->ar[IA64_AR_BSPSTORE] = env->rse.bspstore;
    env->ar[IA64_AR_RNAT] = env->rse.rnat;
    env->ar[IA64_AR_UNAT] = env->nat.unat;
    env->ar[IA64_AR_PFS] = 0;
    env->ar[IA64_AR_FPSR] = IA64_FPSR_RESET_VALUE;

    for (unsigned i = 0; i < IA64_RR_COUNT; i++) {
        env->rr[i] = ia64_default_region_register(i);
    }
    ia64_cpu_init_synthetic_cpuid(env);

    env->cr[IA64_CR_IPSR] = env->psr;
    env->cr[IA64_CR_IIP] = env->ip;
    env->cr[IA64_CR_IFS] = env->cfm;
    /* Intel SDM Vol. 2 reset state: the local timer starts masked. */
    env->cr[IA64_CR_ITV] = IA64_LOCAL_VECTOR_MASK_BIT;
    env->cr[IA64_CR_IVR] = IA64_INTERRUPT_SPURIOUS_VECTOR;
    env->memory.identity_region0_only = true;
    ia64_clear_exception(env);
}

void ia64_deliver_break_interruption(CPUIA64State *env, uint64_t iim,
                                     uint64_t *next_ip, const char *detail)
{
    /* PSR.ic=0 suppresses interruption collection, including CR.IIM. */
    bool collect = (ia64_env_psr(env) & IA64_PSR_IC_BIT) != 0;

    ia64_deliver_exception(env, IA64_EXCEPTION_BREAK, env->ip,
                           MMU_INST_FETCH, detail);
    if (collect) {
        env->cr[IA64_CR_IIM] = iim;
    }
    *next_ip = env->ip;
}

bool ia64_try_platform_break(CPUIA64State *env, uint64_t iim)
{
    return env != NULL && env->platform_break_handler != NULL &&
           env->platform_break_handler(env, iim);
}

void ia64_deliver_disabled_fp_interruption(CPUIA64State *env, bool high,
                                           uint64_t *next_ip)
{
    ia64_deliver_exception(env,
                           high ? IA64_EXCEPTION_DISABLED_FP_HIGH
                                : IA64_EXCEPTION_DISABLED_FP_LOW,
                           env->ip, MMU_DATA_LOAD, "disabled fp-register");
    *next_ip = env->ip;
}

bool ia64_pal_uses_stacked_calling_convention(uint64_t function_id)
{
    switch (function_id) {
    case 257: /* PAL_HALT_INFO */
    case 259: /* PAL_CACHE_READ */
    case 260: /* PAL_CACHE_WRITE */
    case 261: /* PAL_VM_TR_READ */
    case 262: /* PAL_GET_PSTATE */
    case 263: /* PAL_SET_PSTATE */
    case 274: /* PAL_BRAND_INFO */
    case 276: /* PAL_MC_ERROR_INJECT */
        return true;
    default:
        return false;
    }
}

uint64_t ia64_make_cfm(uint32_t sof, uint32_t sol, uint32_t sor)
{
    return (sof & 0x7f) | ((uint64_t)(sol & 0x7f) << 7) |
           ((uint64_t)(sor & 0x0f) << 14);
}

static void ia64_assign_cfm(CPUIA64State *env, uint64_t cfm)
{
    uint32_t new_rrb_fr = (cfm >> 25) & 0x7f;

    if (env->rse.rrb_fr != new_rrb_fr) {
        ia64_alat_invalidate_rotating_frs(env);
    }
    env->cfm = cfm;
    env->rse.sof = cfm & 0x7f;
    env->rse.sol = (cfm >> 7) & 0x7f;
    env->rse.sor = (cfm >> 14) & 0x0f;
    env->rse.rrb_gr = (cfm >> 18) & 0x7f;
    env->rse.rrb_fr = new_rrb_fr;
    env->rse.rrb_pr = (cfm >> 32) & 0x3f;
}

void ia64_set_cfm(CPUIA64State *env, uint64_t cfm)
{
    bool pristine_partitions;

    if (!env) {
        return;
    }

    pristine_partitions = env->cfm == 0 && env->rse.dirty == 0 &&
        env->rse.dirty_nat == 0 && env->rse.clean == 0 &&
        env->rse.clean_nat == 0 &&
        (env->rse.invalid == 0 ||
         env->rse.invalid == IA64_RSE_PHYS_STACKED_REGS);
    ia64_assign_cfm(env, cfm);
    if (pristine_partitions &&
        env->rse.sof <= IA64_RSE_PHYS_STACKED_REGS) {
        /* Unit-created and legacy zero state; reset state already has 96. */
        env->rse.invalid = IA64_RSE_PHYS_STACKED_REGS - env->rse.sof;
    }
}

static uint32_t ia64_rse_slot_num(uint64_t addr)
{
    return (addr >> 3) & 0x3f;
}

uint32_t ia64_rse_num_regs(uint64_t bspstore, uint64_t bsp)
{
    uint64_t slots;

    if (bsp <= bspstore) {
        return 0;
    }

    slots = (bsp - bspstore) >> 3;
    return slots - (ia64_rse_slot_num(bspstore) + slots) / 0x40;
}

uint64_t ia64_rse_skip_regs(uint64_t addr, int64_t num_regs)
{
    int64_t delta = (int64_t)ia64_rse_slot_num(addr) + num_regs;

    if (num_regs < 0) {
        delta -= 0x3e;
    }

    return addr + (uint64_t)((num_regs + delta / 0x3f) * 8);
}

uint32_t ia64_rse_wrap_physical(int32_t physical)
{
    physical %= IA64_RSE_PHYS_STACKED_REGS;
    if (physical < 0) {
        physical += IA64_RSE_PHYS_STACKED_REGS;
    }
    return physical;
}

static uint32_t ia64_rse_storage_window_origin(const CPUIA64State *env)
{
    return ia64_rse_wrap_slot(env->rse.current_frame_base - env->rse.bol);
}

uint32_t ia64_rse_physical_to_storage(const CPUIA64State *env,
                                      uint32_t physical)
{
    uint32_t origin;

    if (!env) {
        return 0;
    }
    origin = ia64_rse_storage_window_origin(env);
    return ia64_rse_wrap_slot(
        origin + ia64_rse_wrap_physical((int32_t)physical));
}

uint32_t ia64_rse_bof_offset_to_storage(const CPUIA64State *env,
                                        int32_t offset)
{
    if (!env) {
        return 0;
    }
    return ia64_rse_physical_to_storage(
        env, ia64_rse_wrap_physical((int32_t)env->rse.bol + offset));
}

static int32_t ia64_rse_nat_words_grow(uint64_t address, uint32_t registers)
{
    return (ia64_rse_slot_num(address) + registers) / 63;
}

static int32_t ia64_rse_nat_words_shrink(uint64_t address,
                                         uint32_t registers)
{
    return (62 - ia64_rse_slot_num(address) + registers) / 63;
}

bool ia64_rse_partitions_valid(const CPUIA64State *env)
{
    int64_t total;
    int64_t dirty_words;
    uint64_t expected_bspstore;

    if (!env || env->rse.sof > IA64_RSE_PHYS_STACKED_REGS ||
        env->rse.bol >= IA64_RSE_PHYS_STACKED_REGS ||
        env->rse.clean < 0 || env->rse.clean_nat < 0 ||
        env->rse.invalid < 0) {
        return false;
    }
    if ((env->rse.bsp | env->rse.bspstore) & 7) {
        return false;
    }

    total = (int64_t)env->rse.sof + env->rse.dirty +
            env->rse.clean + env->rse.invalid;
    if (total != IA64_RSE_PHYS_STACKED_REGS) {
        return false;
    }

    dirty_words = (int64_t)env->rse.dirty + env->rse.dirty_nat;
    expected_bspstore = env->rse.bsp - dirty_words * 8;
    if (env->rse.bspstore != expected_bspstore) {
        return false;
    }

    if (env->rse.dirty < 0 || env->rse.dirty_nat < 0) {
        uint64_t span_slots;
        uint32_t missing_regs;
        uint32_t missing_nats;

        /*
         * An incomplete current frame is one contiguous unloaded backing-
         * store span.  A return consumes every clean word before making a
         * partition negative, so no clean partition can coexist with this
         * state.  Reject mixed signs as well: the next address could select
         * a word whose corresponding counter is already non-negative and
         * trip a late assertion after migration.
         */
        if (env->rse.dirty > 0 || env->rse.dirty_nat > 0 ||
            env->rse.clean != 0 || env->rse.clean_nat != 0 ||
            env->rse.bspstore <= env->rse.bsp) {
            return false;
        }
        span_slots = (env->rse.bspstore - env->rse.bsp) >> 3;
        missing_regs = ia64_rse_num_regs(env->rse.bsp,
                                         env->rse.bspstore);
        missing_nats = span_slots - missing_regs;
        if (env->rse.dirty != -(int32_t)missing_regs ||
            env->rse.dirty_nat != -(int32_t)missing_nats) {
            return false;
        }
    } else {
        int64_t expected_dirty_nat =
            (int64_t)(env->rse.bsp >> 9) -
            (int64_t)(env->rse.bspstore >> 9);
        uint64_t clean_start = env->rse.bspstore -
            ((int64_t)env->rse.clean + env->rse.clean_nat) * 8;
        int64_t expected_clean_nat =
            (int64_t)(env->rse.bspstore >> 9) -
            (int64_t)(clean_start >> 9);

        if (env->rse.dirty_nat != expected_dirty_nat) {
            return false;
        }
        if (env->rse.clean_nat != expected_clean_nat) {
            return false;
        }
    }
    return true;
}

void ia64_rse_check_partitions(const CPUIA64State *env, const char *site)
{
    if (ia64_rse_partitions_valid(env)) {
        return;
    }
    error_report("IA-64 RSE partition invariant failed at %s: "
                 "sof=%u bol=%u dirty=%d/%d clean=%d/%d invalid=%d "
                 "bsp=%016" PRIx64 " bspstore=%016" PRIx64,
                 site ? site : "unknown", env ? env->rse.sof : 0,
                 env ? env->rse.bol : 0, env ? env->rse.dirty : 0,
                 env ? env->rse.dirty_nat : 0,
                 env ? env->rse.clean : 0,
                 env ? env->rse.clean_nat : 0,
                 env ? env->rse.invalid : 0,
                 env ? env->rse.bsp : 0, env ? env->rse.bspstore : 0);
    g_assert_not_reached();
}

bool ia64_rse_address_is_rnat_slot(uint64_t address)
{
    return ia64_rse_slot_num(address) == 0x3f;
}

uint32_t ia64_rse_nat_collection_bit(uint64_t address)
{
    return ia64_rse_slot_num(address);
}

bool ia64_rse_mandatory_store_step(CPUIA64State *env,
                                   IA64RSEWriteRegisterFn write_word,
                                   void *opaque, bool *stored_register)
{
    uint64_t address;

    if (stored_register) {
        *stored_register = false;
    }
    if (!env || !write_word ||
        env->rse.dirty + env->rse.dirty_nat <= 0) {
        return false;
    }

    ia64_rse_check_partitions(env, "store-one-entry");
    address = env->rse.bspstore;
    if (ia64_rse_address_is_rnat_slot(address)) {
        uint64_t value = env->rse.rnat & IA64_RNAT_VALID_MASK;

        g_assert(env->rse.dirty_nat > 0);
        /* Commit no architectural state until the memory store succeeds. */
        write_word(env, address, value, opaque);
        env->psr &= ~(IA64_PSR_DA_BIT | IA64_PSR_DD_BIT);
        env->rse.rnat = 0;
        env->rse.dirty_nat--;
        env->rse.clean_nat++;
    } else {
        uint32_t slot = ia64_rse_bof_offset_to_storage(
            env, -env->rse.dirty);
        uint64_t value = env->rse.stacked_gr[slot];
        uint64_t bit = UINT64_C(1) << ia64_rse_nat_collection_bit(address);
        uint64_t next_rnat = env->rse.rnat;

        g_assert(env->rse.dirty > 0);
        if (ia64_rse_read_physical_nat(env, slot)) {
            next_rnat |= bit;
        } else {
            next_rnat &= ~bit;
        }
        write_word(env, address, value, opaque);
        env->psr &= ~(IA64_PSR_DA_BIT | IA64_PSR_DD_BIT);
        env->rse.rnat = next_rnat & IA64_RNAT_VALID_MASK;
        env->rse.dirty--;
        env->rse.clean++;
        if (stored_register) {
            *stored_register = true;
        }
    }

    env->rse.bspstore = address + 8;
    env->rse.bsp_load = env->rse.bspstore;
    env->rse.clean_count = env->rse.clean;
    ia64_rse_sync_ar(env);
    ia64_rse_check_partitions(env, "store-one-exit");
    return true;
}

IA64RSEStepResult ia64_rse_spill_excess_dirty_interruptible(
    CPUIA64State *env, uint32_t new_sof,
    IA64RSEWriteRegisterFn write_register,
    IA64RSEInterruptionPendingFn interruption_pending, void *opaque,
    uint32_t *spilled_registers)
{
    uint32_t excess;
    uint32_t spilled = 0;

    if (spilled_registers) {
        *spilled_registers = 0;
    }
    if (!env || !write_register || new_sof > IA64_RSE_PHYS_STACKED_REGS) {
        return IA64_RSE_STEP_FAULT;
    }

    ia64_rse_sync_logical_out(env);
    ia64_rse_check_partitions(env, "spill-entry");
    if (env->rse.dirty + (int32_t)new_sof <=
        IA64_RSE_PHYS_STACKED_REGS) {
        return IA64_RSE_STEP_DONE;
    }

    excess = env->rse.dirty + new_sof - IA64_RSE_PHYS_STACKED_REGS;
    if (interruption_pending && interruption_pending(env, opaque)) {
        return IA64_RSE_STEP_INTERRUPTION;
    }
    while (spilled < excess) {
        bool stored_register;

        g_assert(ia64_rse_mandatory_store_step(
            env, write_register, opaque, &stored_register));
        spilled += stored_register;
        if (spilled_registers) {
            *spilled_registers = spilled;
        }
        /* Every committed register or RNAT word is an interrupt boundary. */
        if (interruption_pending && interruption_pending(env, opaque)) {
            return IA64_RSE_STEP_INTERRUPTION;
        }
    }
    return IA64_RSE_STEP_DONE;
}

uint32_t ia64_rse_spill_excess_dirty(CPUIA64State *env, uint32_t new_sof,
                                     IA64RSEWriteRegisterFn write_register,
                                     void *opaque)
{
    uint32_t spilled = 0;
    IA64RSEStepResult result =
        ia64_rse_spill_excess_dirty_interruptible(
            env, new_sof, write_register, NULL, opaque, &spilled);

    g_assert(result == IA64_RSE_STEP_DONE || result == IA64_RSE_STEP_FAULT);
    return result == IA64_RSE_STEP_DONE ? spilled : 0;
}

IA64RSEStepResult ia64_rse_flush_dirty_interruptible(
    CPUIA64State *env, IA64RSEWriteRegisterFn write_register,
    IA64RSEInterruptionPendingFn interruption_pending, void *opaque)
{
    if (!env || !write_register) {
        return IA64_RSE_STEP_FAULT;
    }

    ia64_rse_sync_logical_out(env);
    if (env->rse.dirty + env->rse.dirty_nat <= 0) {
        return IA64_RSE_STEP_DONE;
    }
    if (interruption_pending && interruption_pending(env, opaque)) {
        return IA64_RSE_STEP_INTERRUPTION;
    }
    do {
        g_assert(ia64_rse_mandatory_store_step(
            env, write_register, opaque, NULL));
        if (interruption_pending && interruption_pending(env, opaque)) {
            return IA64_RSE_STEP_INTERRUPTION;
        }
    } while (env->rse.dirty + env->rse.dirty_nat > 0);
    return IA64_RSE_STEP_DONE;
}

IA64RSEStepResult ia64_rse_mandatory_load_step(
    CPUIA64State *env, IA64RSEReadWordFn read_word, void *opaque)
{
    int64_t live_words;
    uint64_t address;
    uint64_t value;

    if (!env || !read_word) {
        return IA64_RSE_STEP_FAULT;
    }
    if (env->rse.dirty >= 0 && env->rse.dirty_nat >= 0) {
        return IA64_RSE_STEP_DONE;
    }

    ia64_rse_check_partitions(env, "load-one-entry");
    live_words = (int64_t)env->rse.clean + env->rse.clean_nat +
                 env->rse.dirty + env->rse.dirty_nat;
    address = env->rse.bsp - (live_words + 1) * 8;
    if (!read_word(env, address, &value, opaque)) {
        return IA64_RSE_STEP_FAULT;
    }
    env->psr &= ~(IA64_PSR_DA_BIT | IA64_PSR_DD_BIT);

    if (ia64_rse_address_is_rnat_slot(address)) {
        g_assert(env->rse.dirty_nat < 0);
        env->rse.rnat = value & IA64_RNAT_VALID_MASK;
        env->rse.dirty_nat++;
    } else {
        uint32_t physical = ia64_rse_wrap_physical(
            (int32_t)env->rse.bol -
            (env->rse.clean + env->rse.dirty + 1));
        uint32_t slot = ia64_rse_physical_to_storage(env, physical);
        uint64_t bit = UINT64_C(1) << ia64_rse_nat_collection_bit(address);

        g_assert(env->rse.dirty < 0);
        g_assert(env->rse.invalid > 0);
        env->rse.stacked_gr[slot] = value;
        ia64_rse_write_physical_nat(env, slot,
                                    (env->rse.rnat & bit) != 0);
        env->rse.dirty++;
        env->rse.invalid--;
        ia64_rse_refresh_logical_slot(env, slot);
    }

    env->rse.bspstore -= 8;
    env->rse.bsp_load = env->rse.bspstore;
    env->rse.clean_count = env->rse.clean;
    ia64_rse_sync_ar(env);
    ia64_rse_check_partitions(env, "load-one-exit");
    return IA64_RSE_STEP_PROGRESS;
}

IA64RSEStepResult ia64_rse_complete_mandatory_loads_interruptible(
    CPUIA64State *env, IA64RSEReadWordFn read_word,
    IA64RSEInterruptionPendingFn interruption_pending, void *opaque)
{
    IA64RSEStepResult result;

    if (!env || !read_word) {
        return IA64_RSE_STEP_FAULT;
    }
    if (env->rse.dirty >= 0 && env->rse.dirty_nat >= 0) {
        env->rse.cfle = false;
        return IA64_RSE_STEP_DONE;
    }

    env->rse.cfle = true;
    for (;;) {
        /*
         * SDM Vol. 2 section 5.3 restarts interruption processing before
         * every mandatory current-frame load.  Leave CFLE set when an
         * enabled interruption wins so ISR.ir samples one and the already
         * committed prefix remains the sole resume authority.
         */
        if (interruption_pending && interruption_pending(env, opaque)) {
            return IA64_RSE_STEP_INTERRUPTION;
        }
        result = ia64_rse_mandatory_load_step(env, read_word, opaque);
        if (result != IA64_RSE_STEP_PROGRESS) {
            return result;
        }
        if (env->rse.dirty < 0 || env->rse.dirty_nat < 0) {
            continue;
        }
        /*
         * A final successful load also restarts at the interrupt-priority
         * check before the valid-frame check clears CFLE.
         */
        if (interruption_pending && interruption_pending(env, opaque)) {
            return IA64_RSE_STEP_INTERRUPTION;
        }
        break;
    }
    env->rse.cfle = false;
    return IA64_RSE_STEP_DONE;
}

IA64RSEStepResult ia64_rse_complete_mandatory_loads(
    CPUIA64State *env, IA64RSEReadWordFn read_word, void *opaque)
{
    return ia64_rse_complete_mandatory_loads_interruptible(
        env, read_word, NULL, opaque);
}

void ia64_rse_reconstruct_partitions(CPUIA64State *env)
{
    uint32_t dirty;
    uint32_t resident;

    if (!env) {
        return;
    }

    resident = env->rse.sof <= IA64_RSE_PHYS_STACKED_REGS
        ? IA64_RSE_PHYS_STACKED_REGS - env->rse.sof : 0;
    dirty = env->rse.bsp > env->rse.bspstore
        ? ia64_rse_num_regs(env->rse.bspstore, env->rse.bsp) : 0;
    dirty = MIN(dirty, resident);

    env->rse.bol %= IA64_RSE_PHYS_STACKED_REGS;
    env->rse.dirty = dirty;
    env->rse.dirty_nat = env->rse.bsp > env->rse.bspstore
        ? (int32_t)((env->rse.bsp - env->rse.bspstore) / 8) -
          (int32_t)dirty : 0;
    env->rse.clean = 0;
    env->rse.clean_nat = 0;
    env->rse.invalid = resident - dirty;
    env->rse.cfle = false;
    env->rse.reference = false;
    env->rse.bsp_load = env->rse.bspstore;
    env->rse.clean_count = 0;
}

void ia64_rse_reconstruct_transients(CPUIA64State *env)
{
    if (!env) {
        return;
    }
    if (!ia64_rse_partitions_valid(env)) {
        ia64_rse_reconstruct_partitions(env);
    }
    if (env->rse.bsp_load == 0) {
        env->rse.bsp_load = env->rse.bspstore;
    }
    env->rse.clean_count = env->rse.clean;
}

static void ia64_rse_sync_ar(CPUIA64State *env)
{
    env->ar[IA64_AR_BSP] = env->rse.bsp;
    env->ar[IA64_AR_BSPSTORE] = env->rse.bspstore;
    ia64_rse_sync_rnat(env);
}

static void ia64_rse_set_bol(CPUIA64State *env, int32_t bol)
{
    uint32_t origin = ia64_rse_storage_window_origin(env);

    env->rse.bol = ia64_rse_wrap_physical(bol);
    env->rse.current_frame_base =
        ia64_rse_wrap_slot(origin + env->rse.bol);
}

static void ia64_rse_preserve_frame(CPUIA64State *env, uint32_t preserved)
{
    int32_t nats;

    if (!env || preserved == 0) {
        return;
    }

    ia64_rse_check_partitions(env, "preserve-entry");
    if (env->rse.bsp == 0 && env->rse.bspstore != 0) {
        env->rse.bsp = env->rse.bspstore;
    }
    nats = ia64_rse_nat_words_grow(env->rse.bsp, preserved);
    ia64_rse_set_bol(env, (int32_t)env->rse.bol + preserved);
    env->rse.bsp += (uint64_t)(preserved + nats) * 8;
    env->rse.dirty += preserved;
    env->rse.dirty_nat += nats;
    env->rse.clean_count = env->rse.clean;
    ia64_rse_sync_ar(env);
}

static bool ia64_rse_restore_frame_partitions(CPUIA64State *env,
                                              uint32_t preserved,
                                              int32_t growth,
                                              uint32_t old_sof)
{
    int32_t preserved_nats;
    int32_t missing;
    int32_t missing_nats;

    preserved_nats = ia64_rse_nat_words_shrink(env->rse.bsp, preserved);
    env->rse.bsp -= (uint64_t)(preserved + preserved_nats) * 8;

    if (growth > env->rse.invalid + env->rse.clean) {
        /* SDM 6.5.5 bad-PFS path. */
        env->rse.invalid += preserved + old_sof;
        env->rse.dirty -= preserved;
        env->rse.dirty_nat -= preserved_nats;
        ia64_assign_cfm(env, 0);
        return true;
    }

    if (growth > env->rse.invalid) {
        env->rse.clean -= growth - env->rse.invalid;
        env->rse.clean_nat = ia64_rse_nat_words_shrink(
            env->rse.bsp, env->rse.clean + env->rse.dirty + 1) -
            env->rse.dirty_nat;
        env->rse.invalid = 0;
    } else {
        env->rse.invalid -= growth;
    }

    missing = (int32_t)preserved - env->rse.dirty;
    missing_nats = preserved_nats - env->rse.dirty_nat;
    if (missing <= 0) {
        env->rse.dirty -= preserved;
        env->rse.dirty_nat -= preserved_nats;
        return false;
    }

    if (missing <= env->rse.clean) {
        env->rse.clean -= missing;
        env->rse.clean_nat -= missing_nats;
        env->rse.dirty = 0;
        env->rse.dirty_nat = 0;
        env->rse.bspstore = env->rse.bsp;
        return false;
    }

    env->rse.dirty = -(missing - env->rse.clean);
    env->rse.dirty_nat = -(missing_nats - env->rse.clean_nat);
    env->rse.clean = 0;
    env->rse.clean_nat = 0;
    env->rse.bspstore = env->rse.bsp -
        ((int64_t)env->rse.dirty + env->rse.dirty_nat) * 8;
    return false;
}

static bool ia64_rse_return_to_frame(CPUIA64State *env, uint64_t pfm,
                                     uint32_t preserved)
{
    uint32_t old_sof = env->rse.sof;
    uint32_t new_sof = pfm & 0x7f;
    int32_t growth = (int32_t)new_sof - (int32_t)preserved -
                     (int32_t)old_sof;
    bool bad_pfs;

    ia64_rse_check_partitions(env, "return-entry");
    ia64_rse_sync_logical_out(env);
    /* The return path below performs the corresponding partition growth. */
    ia64_assign_cfm(env, pfm & IA64_PFS_CFM_MASK);
    ia64_rse_set_bol(env, (int32_t)env->rse.bol - preserved);
    bad_pfs = ia64_rse_restore_frame_partitions(
        env, preserved, growth, old_sof);
    /* RSE.CFLE is visible before branch-trap arbitration and memory fills. */
    env->rse.cfle = env->rse.dirty < 0 || env->rse.dirty_nat < 0;
    env->rse.bsp_load = env->rse.bspstore;
    env->rse.clean_count = env->rse.clean;
    ia64_rse_sync_ar(env);
    ia64_rse_sync_logical_in(env);
    ia64_alat_invalidate_stacked_gr_range(
        env, IA64_GR_COUNT - IA64_STATIC_GR_COUNT);
    ia64_rse_check_partitions(env, bad_pfs ? "return-bad-pfs" : "return");
    return bad_pfs;
}

static uint32_t ia64_stacked_gr_slot(CPUIA64State *env, uint32_t reg)
{
    uint32_t offset = reg - IA64_STATIC_GR_COUNT;
    uint32_t rotating_count = env->rse.sor * 8;
    uint32_t slot;

    if (rotating_count != 0 && offset < rotating_count) {
        offset = (offset + env->rse.rrb_gr) % rotating_count;
    }

    slot = ia64_rse_wrap_physical((int32_t)env->rse.bol + offset);
    return ia64_rse_physical_to_storage(env, slot);
}

static uint32_t ia64_stacked_gr_logical_from_slot(CPUIA64State *env,
                                                   uint32_t slot)
{
    uint32_t origin = ia64_rse_storage_window_origin(env);
    uint32_t physical = ia64_rse_wrap_slot(slot - origin);
    uint32_t offset;
    uint32_t rotating_count = env->rse.sor * 8;

    if (physical >= IA64_RSE_PHYS_STACKED_REGS) {
        return IA64_RSE_PHYS_STACKED_REGS;
    }
    offset = ia64_rse_wrap_physical(
        (int32_t)physical - (int32_t)env->rse.bol);

    if (rotating_count != 0 && offset < rotating_count) {
        uint32_t rrb = env->rse.rrb_gr % rotating_count;

        offset = (offset + rotating_count - rrb) % rotating_count;
    }
    return offset;
}

static bool ia64_rse_read_logical_nat(CPUIA64State *env, uint32_t logical)
{
    return (env->rse.logical_nat[logical / 64] &
            (UINT64_C(1) << (logical % 64))) != 0;
}

static void ia64_rse_write_logical_nat_raw(CPUIA64State *env,
                                            uint32_t logical, bool nat)
{
    uint64_t bit = UINT64_C(1) << (logical % 64);
    uint64_t *word = &env->rse.logical_nat[logical / 64];

    if (nat) {
        *word |= bit;
    } else {
        *word &= ~bit;
    }
    env->rse.logical_nat[1] &= UINT64_C(0xffffffff);
}

static void ia64_rse_refresh_logical_slot(CPUIA64State *env, uint32_t slot)
{
    uint32_t logical;
    uint64_t bit;

    slot = ia64_rse_wrap_slot(slot);
    logical = ia64_stacked_gr_logical_from_slot(env, slot);
    if (logical >= IA64_GR_COUNT - IA64_STATIC_GR_COUNT) {
        return;
    }

    env->gr[IA64_STATIC_GR_COUNT + logical] = env->rse.stacked_gr[slot];
    ia64_rse_write_logical_nat_raw(
        env, logical, ia64_rse_read_physical_nat(env, slot));
    bit = UINT64_C(1) << (logical % 64);
    env->rse.logical_dirty[logical / 64] &= ~bit;
    env->rse.logical_dirty[1] &= UINT64_C(0xffffffff);
}

void ia64_rse_sync_logical_out(CPUIA64State *env)
{
    uint64_t dirty[2];

    if (!env) {
        return;
    }

    dirty[0] = env->rse.logical_dirty[0];
    dirty[1] = env->rse.logical_dirty[1] & UINT64_C(0xffffffff);
    for (uint32_t word = 0; word < G_N_ELEMENTS(dirty); word++) {
        while (dirty[word] != 0) {
            uint32_t bit = ctz64(dirty[word]);
            uint32_t logical = word * 64 + bit;
            uint32_t reg = IA64_STATIC_GR_COUNT + logical;
            uint32_t slot = ia64_stacked_gr_slot(env, reg);

            dirty[word] &= dirty[word] - 1;
            env->rse.stacked_gr[slot] = env->gr[reg];
            ia64_rse_write_physical_nat(
                env, slot, ia64_rse_read_logical_nat(env, logical));
            env->rse.clean_count = MIN(env->rse.clean_count, slot);
        }
    }

    env->rse.logical_nat[1] &= UINT64_C(0xffffffff);
    env->rse.logical_dirty[0] = 0;
    env->rse.logical_dirty[1] = 0;
}

void ia64_rse_sync_logical_in(CPUIA64State *env)
{
    uint64_t logical_nat[2] = { 0, 0 };
    uint32_t live_logical;

    if (!env) {
        return;
    }

    /* Every legitimate mapping transition must first publish dirty names. */
    g_assert((env->rse.logical_dirty[0] |
              env->rse.logical_dirty[1]) == 0);

    /*
     * SOF is the exact architectural validity boundary for logical stacked
     * names.  Names outside the current frame are neither observable nor a
     * part of the resident logical image; the next frame transition that
     * makes one valid refreshes it from the physical backing image here.
     * Refreshing all 96 names on every call, return, alloc, cover, and RFI
     * turns a mapping transition into a blanket helper-wide state sync.
     */
    live_logical = env->rse.sof;
    g_assert(live_logical <= IA64_GR_COUNT - IA64_STATIC_GR_COUNT);
    for (uint32_t logical = 0; logical < live_logical; logical++) {
        uint32_t reg = IA64_STATIC_GR_COUNT + logical;
        uint32_t slot = ia64_stacked_gr_slot(env, reg);

        env->gr[reg] = env->rse.stacked_gr[slot];
        if (ia64_rse_read_physical_nat(env, slot)) {
            logical_nat[logical / 64] |=
                UINT64_C(1) << (logical % 64);
        }
    }

    env->rse.logical_nat[0] = logical_nat[0];
    env->rse.logical_nat[1] = logical_nat[1] & UINT64_C(0xffffffff);
    env->rse.logical_dirty[0] = 0;
    env->rse.logical_dirty[1] = 0;
}

uint64_t ia64_read_gr(CPUIA64State *env, uint32_t reg)
{
    if (!env || reg >= IA64_GR_COUNT || reg == 0) {
        return 0;
    }
    if (reg < IA64_STATIC_GR_COUNT) {
        if (reg >= 16 && reg < 32 &&
            (ia64_env_psr(env) & IA64_PSR_BN_BIT)) {
            return env->banked_gr[reg - 16];
        }
        return env->gr[reg];
    }
    return env->gr[reg];
}

static bool ia64_alat_target_is_valid(IA64AlatTargetType target_type,
                                      uint32_t reg)
{
    switch (target_type) {
    case IA64_ALAT_TARGET_GR:
        return reg > 0 && reg < IA64_GR_COUNT;
    case IA64_ALAT_TARGET_FR:
        return reg > 1 && reg < IA64_FR_COUNT;
    default:
        return false;
    }
}

static bool ia64_alat_width_is_valid(IA64AlatTargetType target_type,
                                     uint8_t width)
{
    if (target_type == IA64_ALAT_TARGET_GR) {
        return width == 1 || width == 2 || width == 4 || width == 8;
    }
    if (target_type == IA64_ALAT_TARGET_FR) {
        /*
         * Extended payloads occupy ten bytes but use a sixteen-byte access
         * span in the reference model; accept either representation so the
         * ALAT key can follow the lowering's chosen verification span.
         */
        return width == 4 || width == 8 || width == 10 || width == 16;
    }
    return false;
}

static int ia64_alat_find_target(CPUIA64State *env, uint32_t reg,
                                 IA64AlatTargetType target_type)
{
    uint32_t valid_mask;

    if (!env || !ia64_alat_target_is_valid(target_type, reg)) {
        return -1;
    }

    if (target_type == IA64_ALAT_TARGET_GR &&
        (env->alat.gr_mask[reg / 64] & (1ULL << (reg % 64))) == 0) {
        return -1;
    }

    valid_mask = env->alat.valid_mask;
    while (valid_mask != 0) {
        unsigned i = ctz32(valid_mask);

        if (env->alat.entries[i].target_type == target_type &&
            env->alat.entries[i].target == reg) {
            return i;
        }
        valid_mask &= valid_mask - 1;
    }

    return -1;
}

void ia64_alat_set_valid(CPUIA64State *env, unsigned index, bool valid)
{
    IA64AlatEntry *entry;
    unsigned target;
    bool was_active;

    if (!env || index >= IA64_ALAT_COUNT) {
        return;
    }

    entry = &env->alat.entries[index];
    if (entry->valid == valid) {
        return;
    }
    was_active = env->alat.valid_mask != 0;
    target = entry->target;
    entry->valid = valid;
    if (valid) {
        env->alat.valid_mask |= 1u << index;
        if (entry->target_type == IA64_ALAT_TARGET_GR && target > 0 &&
            target < IA64_GR_COUNT &&
            env->alat.gr_refcount[target]++ == 0) {
            env->alat.gr_mask[target / 64] |= 1ULL << (target % 64);
        }
    } else {
        env->alat.valid_mask &= ~(1u << index);
        if (entry->target_type == IA64_ALAT_TARGET_GR && target > 0 &&
            target < IA64_GR_COUNT && env->alat.gr_refcount[target] != 0 &&
            --env->alat.gr_refcount[target] == 0) {
            env->alat.gr_mask[target / 64] &= ~(1ULL << (target % 64));
        }
    }
    if (!was_active && env->alat.valid_mask != 0) {
        IA64_PERF_INC(IA64_PERF_ALAT_ACTIVE_ENTER);
    } else if (was_active && env->alat.valid_mask == 0) {
        IA64_PERF_INC(IA64_PERF_ALAT_ACTIVE_EXIT);
    }
}

void ia64_alat_reconstruct_transients(CPUIA64State *env)
{
    uint32_t valid_mask = 0;

    if (!env) {
        return;
    }

    memset(env->alat.gr_mask, 0, sizeof(env->alat.gr_mask));
    memset(env->alat.gr_refcount, 0, sizeof(env->alat.gr_refcount));
    for (unsigned i = 0; i < IA64_ALAT_COUNT; i++) {
        if (env->alat.entries[i].valid) {
            unsigned target = env->alat.entries[i].target;

            valid_mask |= 1u << i;
            if (env->alat.entries[i].target_type == IA64_ALAT_TARGET_GR &&
                target > 0 && target < IA64_GR_COUNT &&
                env->alat.gr_refcount[target]++ == 0) {
                env->alat.gr_mask[target / 64] |= 1ULL << (target % 64);
            }
        }
    }
    env->alat.valid_mask = valid_mask;
}

void ia64_alat_invalidate_all(CPUIA64State *env)
{
    uint32_t valid_mask;

    if (!env) {
        return;
    }

    valid_mask = env->alat.valid_mask;
    if (valid_mask == 0) {
        return;
    }
    IA64_PERF_INC(IA64_PERF_ALAT_INVALIDATE_ALL);
    IA64_PERF_INC(IA64_PERF_ALAT_ACTIVE_EXIT);

    env->alat.next = 0;
    env->alat.valid_mask = 0;
    memset(env->alat.gr_mask, 0, sizeof(env->alat.gr_mask));
    memset(env->alat.gr_refcount, 0, sizeof(env->alat.gr_refcount));
    for (unsigned i = 0; i < IA64_ALAT_COUNT; i++) {
        if (valid_mask & (1u << i)) {
            env->alat.entries[i].valid = false;
        }
    }
}

void ia64_alat_invalidate_gr(CPUIA64State *env, uint32_t reg)
{
    uint32_t valid_mask;

    if (!env || reg >= IA64_GR_COUNT) {
        return;
    }

    if ((env->alat.gr_mask[reg / 64] & (1ULL << (reg % 64))) == 0) {
        return;
    }
    IA64_PERF_INC(IA64_PERF_ALAT_INVALIDATE_GR);

    valid_mask = env->alat.valid_mask;
    while (valid_mask != 0) {
        unsigned i = ctz32(valid_mask);

        valid_mask &= valid_mask - 1;
        if (env->alat.entries[i].target_type == IA64_ALAT_TARGET_GR &&
            env->alat.entries[i].target == reg) {
            ia64_alat_set_valid(env, i, false);
        }
    }
}

void ia64_alat_invalidate_fr(CPUIA64State *env, uint32_t reg)
{
    uint32_t valid_mask;

    if (!env || !ia64_alat_target_is_valid(IA64_ALAT_TARGET_FR, reg)) {
        return;
    }

    valid_mask = env->alat.valid_mask;
    if (valid_mask != 0) {
        IA64_PERF_INC(IA64_PERF_ALAT_INVALIDATE_FR);
    }
    while (valid_mask != 0) {
        unsigned index = ctz32(valid_mask);

        valid_mask &= valid_mask - 1;
        if (env->alat.entries[index].target_type == IA64_ALAT_TARGET_FR &&
            env->alat.entries[index].target == reg) {
            ia64_alat_set_valid(env, index, false);
        }
    }
}

static void ia64_alat_invalidate_stacked_gr_range(CPUIA64State *env,
                                                   uint32_t stacked_count)
{
    uint32_t valid_mask;
    uint32_t stacked_end = IA64_STATIC_GR_COUNT + stacked_count;

    if (stacked_count == 0) {
        return;
    }

    /*
     * A stacked-name mapping transition changes the physical register denoted
     * by every name in this range.  Walk the active ALAT once so its masks and
     * refcounts continue to be maintained by the single validity authority.
     */
    valid_mask = env->alat.valid_mask;
    if (valid_mask != 0) {
        IA64_PERF_INC(IA64_PERF_ALAT_INVALIDATE_RSE);
    }
    while (valid_mask != 0) {
        unsigned index = ctz32(valid_mask);
        uint32_t target = env->alat.entries[index].target;

        valid_mask &= valid_mask - 1;
        if (env->alat.entries[index].target_type == IA64_ALAT_TARGET_GR &&
            target >= IA64_STATIC_GR_COUNT && target < stacked_end) {
            ia64_alat_set_valid(env, index, false);
        }
    }
}

static void ia64_alat_invalidate_rotating_grs(CPUIA64State *env,
                                               uint32_t rotating_count)
{
    ia64_alat_invalidate_stacked_gr_range(env, rotating_count);
}

static void ia64_alat_invalidate_rotating_frs(CPUIA64State *env)
{
    uint32_t valid_mask;

    if (!env) {
        return;
    }

    valid_mask = env->alat.valid_mask;
    while (valid_mask != 0) {
        unsigned index = ctz32(valid_mask);
        IA64AlatEntry *entry = &env->alat.entries[index];

        valid_mask &= valid_mask - 1;
        if (entry->target_type == IA64_ALAT_TARGET_FR &&
            entry->target >= 32) {
            ia64_alat_set_valid(env, index, false);
        }
    }
}

static void ia64_alat_record_target(CPUIA64State *env, uint32_t target,
                                    uint64_t address, uint8_t width,
                                    bool physical,
                                    IA64AlatTargetType target_type)
{
    IA64AlatEntry *entry;
    unsigned index;
    uint64_t started_ns = ia64_perf_clock_ns();

    IA64_PERF_INC(IA64_PERF_ALAT_HELPER_CALL);

    if (!env || !ia64_alat_target_is_valid(target_type, target) ||
        !ia64_alat_width_is_valid(target_type, width)) {
        IA64_PERF_ADD(IA64_PERF_ALAT_HELPER_HOST_NS,
                      ia64_perf_clock_ns() - started_ns);
        return;
    }

    if (target_type == IA64_ALAT_TARGET_GR) {
        ia64_alat_invalidate_gr(env, target);
    } else {
        ia64_alat_invalidate_fr(env, target);
    }
    index = env->alat.next % IA64_ALAT_COUNT;
    entry = &env->alat.entries[index];
    env->alat.next = (env->alat.next + 1) % IA64_ALAT_COUNT;

    ia64_alat_set_valid(env, index, false);
    memset(entry, 0, sizeof(*entry));
    entry->target = target;
    entry->target_type = target_type;
    entry->width = width;
    entry->physical = physical;
    entry->address = address;
    ia64_alat_set_valid(env, index, true);
    IA64_PERF_INC(IA64_PERF_ALAT_RECORD);
    IA64_PERF_ADD(IA64_PERF_ALAT_HELPER_HOST_NS,
                  ia64_perf_clock_ns() - started_ns);
}

void ia64_alat_record_gr(CPUIA64State *env, uint32_t target,
                         uint64_t address, uint8_t width, bool physical)
{
    ia64_alat_record_target(env, target, address, width, physical,
                            IA64_ALAT_TARGET_GR);
}

void ia64_alat_record_fr(CPUIA64State *env, uint32_t target,
                         uint64_t address, uint8_t width, bool physical)
{
    ia64_alat_record_target(env, target, address, width, physical,
                            IA64_ALAT_TARGET_FR);
}

static bool ia64_alat_check_target(CPUIA64State *env, uint32_t reg,
                                   uint64_t address, uint8_t width,
                                   bool physical, bool verify_address,
                                   bool clear,
                                   IA64AlatTargetType target_type)
{
    int index = ia64_alat_find_target(env, reg, target_type);
    IA64AlatEntry *entry;
    bool matches;
    uint64_t started_ns = ia64_perf_clock_ns();

    IA64_PERF_INC(IA64_PERF_ALAT_HELPER_CALL);

    if (index < 0) {
        IA64_PERF_INC(IA64_PERF_ALAT_CHECK_MISS);
        IA64_PERF_ADD(IA64_PERF_ALAT_HELPER_HOST_NS,
                      ia64_perf_clock_ns() - started_ns);
        return false;
    }

    entry = &env->alat.entries[index];
    matches = !verify_address ||
        (entry->physical == physical && entry->width == width &&
         entry->address == address);
    if (clear) {
        ia64_alat_set_valid(env, index, false);
    }
    IA64_PERF_INC(matches ? IA64_PERF_ALAT_CHECK_HIT :
                            IA64_PERF_ALAT_CHECK_MISS);
    IA64_PERF_ADD(IA64_PERF_ALAT_HELPER_HOST_NS,
                  ia64_perf_clock_ns() - started_ns);
    return matches;
}

bool ia64_alat_check_gr(CPUIA64State *env, uint32_t reg, uint64_t address,
                        uint8_t width, bool physical, bool clear)
{
    if (!ia64_alat_width_is_valid(IA64_ALAT_TARGET_GR, width)) {
        return false;
    }
    return ia64_alat_check_target(env, reg, address, width, physical, true,
                                  clear, IA64_ALAT_TARGET_GR);
}

bool ia64_alat_check_fr(CPUIA64State *env, uint32_t reg, uint64_t address,
                        uint8_t width, bool physical, bool clear)
{
    if (!ia64_alat_width_is_valid(IA64_ALAT_TARGET_FR, width)) {
        return false;
    }
    return ia64_alat_check_target(env, reg, address, width, physical, true,
                                  clear, IA64_ALAT_TARGET_FR);
}

bool ia64_alat_test_gr(CPUIA64State *env, uint32_t reg, bool clear)
{
    return ia64_alat_check_target(env, reg, 0, 0, false, false, clear,
                                  IA64_ALAT_TARGET_GR);
}

bool ia64_alat_test_fr(CPUIA64State *env, uint32_t reg, bool clear)
{
    return ia64_alat_check_target(env, reg, 0, 0, false, false, clear,
                                  IA64_ALAT_TARGET_FR);
}

void ia64_write_gr(CPUIA64State *env, uint32_t reg, uint64_t value)
{
    if (!env || reg >= IA64_GR_COUNT || reg == 0) {
        if (env) {
            env->gr[0] = 0;
            env->nat.gr_nat[0] &= ~1ULL;
        }
        return;
    }
    if (reg < IA64_STATIC_GR_COUNT) {
        if (reg >= 16 && reg < 32 &&
            (ia64_env_psr(env) & IA64_PSR_BN_BIT)) {
            env->banked_gr[reg - 16] = value;
        } else {
            env->gr[reg] = value;
        }
    } else {
        env->gr[reg] = value;
    }
    ia64_write_gr_nat(env, reg, false);
    ia64_alat_invalidate_gr(env, reg);
    env->gr[0] = 0;
}

static uint32_t ia64_map_fr(CPUIA64State *env, uint32_t reg)
{
    if (reg < 32) {
        return reg;
    }
    return 32 + ((reg - 32 + env->rse.rrb_fr) % (IA64_FR_COUNT - 32));
}

void ia64_preserve_fr_source(CPUIA64State *env, uint32_t reg)
{
    uint64_t bit;

    if (!env || reg < 2 || reg >= IA64_FR_COUNT ||
        !env->issue_group.typed_active) {
        return;
    }
    bit = UINT64_C(1) << (reg & 63);
    if ((env->issue_group.saved_fr_mask[reg >> 6] & bit) != 0) {
        return;
    }
    env->issue_group.saved_fr[reg] = env->fr[ia64_map_fr(env, reg)];
    env->issue_group.saved_fr_mask[reg >> 6] |= bit;
}

const IA64FloatReg *ia64_read_fr_ordinary(CPUIA64State *env, uint32_t reg)
{
    uint64_t bit;

    if (!env || reg >= IA64_FR_COUNT) {
        return NULL;
    }
    bit = UINT64_C(1) << (reg & 63);
    if (env->issue_group.typed_active &&
        (env->issue_group.saved_fr_mask[reg >> 6] & bit) != 0) {
        return &env->issue_group.saved_fr[reg];
    }
    return &env->fr[ia64_map_fr(env, reg)];
}

void ia64_note_fr_write(CPUIA64State *env, uint32_t reg)
{
    if (!env || reg < 2 || reg >= IA64_FR_COUNT) {
        return;
    }

    /*
     * The ALAT tag names the architectural FR before its current RRB.FR
     * mapping is applied to env->fr[].  Invalidate the old tag before the
     * write; an advanced-load completion records its replacement afterward.
     */
    ia64_alat_invalidate_fr(env, reg);
    /*
     * Writes to the FP register file set PSR.mfl/mfh; the OS uses the
     * modified bits to decide whether a partition must be saved on a
     * context switch (Linux gates the lazy f32-f127 save on PSR.mfh).
     */
    env->psr |= reg >= 32 ? IA64_PSR_MFH_BIT : IA64_PSR_MFL_BIT;
}

static void ia64_write_fr_parts(CPUIA64State *env, uint32_t reg,
                                bool sign, uint32_t exponent,
                                uint64_t significand)
{
    uint32_t mapped;

    if (!env || reg >= IA64_FR_COUNT || reg < 2) {
        return;
    }

    ia64_preserve_fr_source(env, reg);
    mapped = ia64_map_fr(env, reg);
    env->fr[mapped].raw[0] = significand;
    env->fr[mapped].raw[1] = (exponent & 0x1ffff) |
                             ((uint64_t)(sign ? 1 : 0) << 17);
    ia64_note_fr_write(env, reg);
}

static bool ia64_fr_sign(const IA64FloatReg *reg)
{
    return ((reg->raw[1] >> 17) & 1) != 0;
}

static uint32_t ia64_fr_exponent(const IA64FloatReg *reg)
{
    return reg->raw[1] & 0x1ffff;
}

static bool ia64_fr_is_natval(const IA64FloatReg *reg)
{
    return !ia64_fr_sign(reg) &&
           ia64_fr_exponent(reg) == IA64_FR_NATVAL_EXPONENT &&
           reg->raw[0] == 0;
}

static bool ia64_fr_is_zero(const IA64FloatReg *reg)
{
    return reg->raw[0] == 0 &&
           ia64_fr_exponent(reg) == 0;
}

void ia64_float_reg_to_spill(const IA64FloatReg *reg,
                             uint64_t *sign_exponent,
                             uint64_t *mantissa)
{
    /* Spill/fill is an exact 82-bit transfer.  In particular, exponent zero
     * plus a zero significand is zero, while exponent 0x1ffff plus a zero
     * significand is the distinct unsupported pseudo-infinity encoding.
     */
    *sign_exponent = reg->raw[1] & 0x3ffff;
    *mantissa = reg->raw[0];
}

void ia64_float_reg_from_spill(uint64_t sign_exponent, uint64_t mantissa,
                               IA64FloatReg *reg)
{
    reg->raw[0] = mantissa;
    reg->raw[1] = sign_exponent & 0x3ffff;
}

static bool ia64_fr_is_infinity(const IA64FloatReg *reg)
{
    return ia64_fr_exponent(reg) == IA64_FR_SPECIAL_EXPONENT &&
           reg->raw[0] == IA64_FR_INTEGER_BIT;
}

static bool ia64_fr_is_nan(const IA64FloatReg *reg)
{
    return ia64_fr_exponent(reg) == IA64_FR_SPECIAL_EXPONENT &&
           reg->raw[0] != 0 && reg->raw[0] != IA64_FR_INTEGER_BIT;
}

static bool ia64_fr_is_qnan(const IA64FloatReg *reg)
{
    return ia64_fr_is_nan(reg) &&
           (reg->raw[0] & IA64_FR_INTEGER_BIT) != 0 &&
           (reg->raw[0] & IA64_FR_QUIET_NAN_BIT) != 0;
}

static bool ia64_fr_is_snan(const IA64FloatReg *reg)
{
    return ia64_fr_is_nan(reg) &&
           (reg->raw[0] & IA64_FR_INTEGER_BIT) != 0 &&
           (reg->raw[0] & IA64_FR_QUIET_NAN_BIT) == 0;
}

static bool ia64_fr_is_unsupported_special(const IA64FloatReg *reg)
{
    return ia64_fr_exponent(reg) == IA64_FR_SPECIAL_EXPONENT &&
           !ia64_fr_is_zero(reg) &&
           !ia64_fr_is_infinity(reg) &&
           !ia64_fr_is_qnan(reg) &&
           !ia64_fr_is_snan(reg);
}

static void ia64_float_status_init(float_status *status)
{
    set_float_rounding_mode(float_round_nearest_even, status);
    set_float_2nan_prop_rule(float_2nan_prop_x87, status);
    set_float_default_nan_pattern(0b01000000, status);
    set_floatx80_rounding_precision(floatx80_precision_x, status);
}

static floatx80 ia64_fr_to_floatx80(const IA64FloatReg *reg)
{
    bool sign = ia64_fr_sign(reg);
    int32_t exponent = ia64_fr_exponent(reg);
    uint64_t significand = reg->raw[0];
    int32_t soft_exponent;
    uint16_t soft_sign = sign ? 0x8000 : 0;

    if (ia64_fr_is_natval(reg) || ia64_fr_is_nan(reg) ||
        ia64_fr_is_unsupported_special(reg)) {
        return make_floatx80(soft_sign | 0x7fff,
                             IA64_FR_INTEGER_BIT | 1);
    }
    if (ia64_fr_is_infinity(reg)) {
        return make_floatx80(soft_sign | 0x7fff, IA64_FR_INTEGER_BIT);
    }
    if (ia64_fr_is_zero(reg) || significand == 0) {
        return make_floatx80(soft_sign, 0);
    }

    while ((significand & IA64_FR_INTEGER_BIT) == 0) {
        significand <<= 1;
        exponent--;
    }
    soft_exponent = exponent - IA64_FR_EXPONENT_BIAS + 0x3fff;
    if (soft_exponent <= 0) {
        return make_floatx80(soft_sign, 0);
    }
    if (soft_exponent >= 0x7fff) {
        return make_floatx80(soft_sign | 0x7fff, IA64_FR_INTEGER_BIT);
    }

    return make_floatx80(soft_sign | (uint16_t)soft_exponent, significand);
}

void ia64_write_fr_natval(CPUIA64State *env, uint32_t reg)
{
    ia64_write_fr_parts(env, reg, false, IA64_FR_NATVAL_EXPONENT, 0);
}

static void ia64_write_fr_from_ieee_bits(CPUIA64State *env, uint32_t reg,
                                         bool sign, uint32_t exponent,
                                         uint32_t max_exponent,
                                         uint32_t exponent_bias,
                                         uint64_t fraction,
                                         unsigned fraction_bits)
{
    uint64_t significand;
    uint32_t register_exponent;

    if (exponent == 0) {
        if (fraction == 0) {
            ia64_write_fr_parts(env, reg, sign, 0, 0);
            return;
        }
        register_exponent = IA64_FR_EXPONENT_BIAS - exponent_bias + 1;
        significand = fraction << (63 - fraction_bits);
    } else if (exponent == max_exponent) {
        register_exponent = IA64_FR_SPECIAL_EXPONENT;
        significand = IA64_FR_INTEGER_BIT |
                      (fraction << (63 - fraction_bits));
    } else {
        register_exponent = IA64_FR_EXPONENT_BIAS + exponent - exponent_bias;
        significand = IA64_FR_INTEGER_BIT |
                      (fraction << (63 - fraction_bits));
    }

    ia64_write_fr_parts(env, reg, sign, register_exponent, significand);
}

void ia64_write_fr_from_single_bits(CPUIA64State *env, uint32_t reg,
                                    uint32_t bits)
{
    ia64_write_fr_from_ieee_bits(env, reg, (bits >> 31) != 0,
                                 (bits >> 23) & 0xff, 0xff, 127,
                                 bits & 0x7fffff, 23);
}

void ia64_write_fr_from_double_bits(CPUIA64State *env, uint32_t reg,
                                    uint64_t bits)
{
    ia64_write_fr_from_ieee_bits(env, reg, (bits >> 63) != 0,
                                 (bits >> 52) & 0x7ff, 0x7ff, 1023,
                                 bits & 0x000fffffffffffffULL, 52);
}

uint32_t ia64_read_fr_as_single_bits(const IA64FloatReg *reg)
{
    float_status status;
    float32 value;

    ia64_float_status_init(&status);
    value = floatx80_to_float32(ia64_fr_to_floatx80(reg), &status);
    return float32_val(value);
}

uint64_t ia64_read_fr_as_double_bits(const IA64FloatReg *reg)
{
    float_status status;
    float64 value;

    ia64_float_status_init(&status);
    value = floatx80_to_float64(ia64_fr_to_floatx80(reg), &status);
    return float64_val(value);
}

IA64RSEAllocValidation ia64_rse_validate_alloc(
    const CPUIA64State *env, uint8_t r1, uint32_t sof, uint32_t sol,
    uint32_t sor, uint8_t qp)
{
    /* check_target_register_sof() precedes every restartable RSE store. */
    if (!env || r1 == 0 ||
        (r1 >= IA64_STATIC_GR_COUNT &&
         r1 >= IA64_STATIC_GR_COUNT + sof) ||
        qp != 0 || sof > IA64_RSE_PHYS_STACKED_REGS ||
        sol > sof || sor * 8 > sof) {
        return IA64_RSE_ALLOC_ILLEGAL_OPERATION;
    }

    /*
     * SDM Vol. 1 section 4.5.1: changing the rotating-region size while any
     * rename base is non-zero raises Reserved Register/Field.  This check is
     * deliberately separate from the committing transition so a typed alloc
     * can perform it before the first restartable backing-store write.
     */
    if (sor != env->rse.sor &&
        (env->rse.rrb_gr != 0 || env->rse.rrb_fr != 0 ||
         env->rse.rrb_pr != 0)) {
        return IA64_RSE_ALLOC_RESERVED_REGISTER_FIELD;
    }
    return IA64_RSE_ALLOC_VALID;
}

uint64_t ia64_rse_commit_alloc(CPUIA64State *env, uint8_t r1,
                               uint32_t sof, uint32_t sol, uint32_t sor)
{
    const uint64_t frame_size_mask = (UINT64_C(1) << 18) - 1;
    uint64_t old_pfs;
    int32_t growth;

    g_assert(env != NULL);
    g_assert(ia64_rse_validate_alloc(env, r1, sof, sol, sor, 0) ==
             IA64_RSE_ALLOC_VALID);

    old_pfs = env->ar[IA64_AR_PFS];
    growth = (int32_t)sof - (int32_t)env->rse.sof;
    ia64_rse_sync_logical_out(env);
    if (growth <= env->rse.invalid) {
        env->rse.invalid -= growth;
    } else {
        growth -= env->rse.invalid;
        g_assert(growth <= env->rse.clean);
        env->rse.invalid = 0;
        env->rse.clean -= growth;
        env->rse.clean_nat = ia64_rse_nat_words_shrink(
            env->rse.bsp, env->rse.clean + env->rse.dirty + 1) -
            env->rse.dirty_nat;
    }
    ia64_alat_invalidate_stacked_gr_range(
        env, IA64_GR_COUNT - IA64_STATIC_GR_COUNT);
    /* alloc changes SOF/SOL/SOR but preserves all three rename bases. */
    ia64_assign_cfm(env, (env->cfm & ~frame_size_mask) |
                         ia64_make_cfm(sof, sol, sor));
    ia64_rse_sync_logical_in(env);
    env->rse.clean_count = env->rse.clean;
    ia64_rse_check_partitions(env, "alloc");
    return old_pfs;
}

bool ia64_rse_loadrs_is_legal(const CPUIA64State *env)
{
    uint64_t bytes;
    uint64_t address;
    uint32_t requested_registers = 0;

    if (!env) {
        return false;
    }
    bytes = ((env->rse.rsc >> IA64_RSC_LOADRS_SHIFT) &
             IA64_RSC_LOADRS_MASK) & ~UINT64_C(7);
    if ((env->rse.rsc & IA64_RSC_MODE_MASK) != 0 ||
        (env->rse.sof != 0 && bytes != 0)) {
        return false;
    }

    /* Count only register words; RNAT collection slots consume no GR. */
    address = env->rse.bsp - bytes;
    for (uint64_t offset = 0; offset < bytes; offset += 8) {
        if (!ia64_rse_address_is_rnat_slot(address + offset)) {
            requested_registers++;
        }
    }
    return requested_registers <= IA64_RSE_PHYS_STACKED_REGS;
}

static IA64RSEStepResult ia64_rse_loadrs_word_step(
    CPUIA64State *env, IA64RSEReadWordFn read_word, void *opaque)
{
    int64_t live_words = (int64_t)env->rse.clean + env->rse.clean_nat +
                         env->rse.dirty + env->rse.dirty_nat;
    uint64_t address = env->rse.bsp - (live_words + 1) * 8;
    uint64_t value;

    if (!read_word(env, address, &value, opaque)) {
        return IA64_RSE_STEP_FAULT;
    }
    env->psr &= ~(IA64_PSR_DA_BIT | IA64_PSR_DD_BIT);
    if (ia64_rse_address_is_rnat_slot(address)) {
        env->rse.rnat = value & IA64_RNAT_VALID_MASK;
        env->rse.dirty_nat++;
    } else {
        uint32_t physical;
        uint32_t storage;
        uint64_t bit;

        g_assert(env->rse.dirty < IA64_RSE_PHYS_STACKED_REGS);
        g_assert(env->rse.invalid > 0);
        physical = ia64_rse_wrap_physical(
            (int32_t)env->rse.bol -
            (env->rse.clean + env->rse.dirty + 1));
        storage = ia64_rse_physical_to_storage(env, physical);
        bit = UINT64_C(1) << ia64_rse_nat_collection_bit(address);
        env->rse.stacked_gr[storage] = value;
        ia64_rse_write_physical_nat(env, storage,
                                    (env->rse.rnat & bit) != 0);
        env->rse.dirty++;
        env->rse.invalid--;
    }
    env->rse.bspstore = env->rse.bsp -
        ((int64_t)env->rse.dirty + env->rse.dirty_nat) * 8;
    env->rse.bsp_load = env->rse.bspstore;
    env->rse.clean_count = env->rse.clean;
    ia64_rse_sync_ar(env);
    ia64_rse_check_partitions(env, "loadrs-word");
    return IA64_RSE_STEP_PROGRESS;
}

IA64RSEStepResult ia64_rse_execute_loadrs_interruptible(
    CPUIA64State *env, IA64RSEReadWordFn read_word,
    IA64RSEInterruptionPendingFn interruption_pending, void *opaque)
{
    uint64_t bytes;
    int32_t words;
    int32_t words_to_load;

    if (!env || !read_word || !ia64_rse_loadrs_is_legal(env)) {
        return IA64_RSE_STEP_FAULT;
    }
    bytes = ((env->rse.rsc >> IA64_RSC_LOADRS_SHIFT) &
             IA64_RSC_LOADRS_MASK) & ~UINT64_C(7);
    words = bytes >> 3;

    ia64_rse_sync_logical_out(env);
    ia64_rse_check_partitions(env, "loadrs-entry");
    words_to_load = words - (env->rse.clean + env->rse.clean_nat +
                             env->rse.dirty + env->rse.dirty_nat);
    if (words_to_load >= 0) {
        if (words_to_load > 0 && interruption_pending &&
            interruption_pending(env, opaque)) {
            return IA64_RSE_STEP_INTERRUPTION;
        }
        env->rse.dirty += env->rse.clean;
        env->rse.dirty_nat += env->rse.clean_nat;
        env->rse.clean = 0;
        env->rse.clean_nat = 0;
        env->rse.bspstore = env->rse.bsp -
            ((int64_t)env->rse.dirty + env->rse.dirty_nat) * 8;
        while (words_to_load-- > 0) {
            IA64RSEStepResult result =
                ia64_rse_loadrs_word_step(env, read_word, opaque);

            if (result != IA64_RSE_STEP_PROGRESS) {
                return result;
            }
            /* The final successful word is also an interrupt boundary. */
            if (interruption_pending && interruption_pending(env, opaque)) {
                return IA64_RSE_STEP_INTERRUPTION;
            }
        }
    } else {
        uint64_t tear = env->rse.bsp - bytes;

        env->rse.dirty_nat = (int32_t)((int64_t)(env->rse.bsp >> 9) -
                                       (int64_t)(tear >> 9));
        env->rse.dirty = words - env->rse.dirty_nat;
        g_assert(env->rse.dirty + env->rse.sof <=
                 IA64_RSE_PHYS_STACKED_REGS);
        env->rse.bspstore = env->rse.bsp -
            ((int64_t)env->rse.dirty + env->rse.dirty_nat) * 8;
        env->rse.clean = 0;
        env->rse.clean_nat = 0;
        env->rse.invalid = IA64_RSE_PHYS_STACKED_REGS -
                           env->rse.sof - env->rse.dirty;
    }

    env->rse.bsp_load = env->rse.bspstore;
    env->rse.clean_count = 0;
    ia64_rse_sync_ar(env);
    ia64_rse_clear_rnat(env);
    ia64_rse_check_partitions(env, "loadrs-exit");
    return IA64_RSE_STEP_DONE;
}

uint64_t ia64_read_application_register(CPUIA64State *env, uint32_t reg)
{
    if (!env || reg >= IA64_AR_COUNT) {
        return 0;
    }

    /* Architecturally ignored ARs always read as zero. */
    if ((reg >= 48 && reg <= 63) || reg >= 112) {
        return 0;
    }

    switch (reg) {
    case IA64_AR_RSC:
        return env->rse.rsc;
    case IA64_AR_BSP:
        return env->rse.bsp;
    case IA64_AR_BSPSTORE:
        return env->rse.bspstore;
    case IA64_AR_RNAT:
        return env->rse.rnat;
    case IA64_AR_UNAT:
        return env->nat.unat;
    case IA64_AR_ITC:
        ia64_itc_sync(env);
        return env->ar[IA64_AR_ITC];
    default:
        return env->ar[reg];
    }
}

static bool ia64_ar_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_AR_TRACE") != NULL;
    }
    return enabled != 0;
}

static int ia64_branch_trace_filter(void)
{
    static int filter = -2;

    if (filter == -2) {
        const char *value = g_getenv("VIBTANIUM_BRANCH_TRACE_REG");
        char *endptr = NULL;

        filter = -1;
        if (value && *value) {
            unsigned long parsed = strtoul(value, &endptr, 0);

            if (endptr != value && parsed < IA64_BR_COUNT) {
                filter = (int)parsed;
            }
        }
    }
    return filter;
}

static bool ia64_branch_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_BRANCH_TRACE") != NULL;
    }
    return enabled != 0;
}

static bool ia64_branch_trace_target_matches(uint64_t target)
{
    static int initialized;
    static bool has_filter;
    static uint64_t filter;

    if (!initialized) {
        const char *value = g_getenv("VIBTANIUM_BRANCH_TRACE_TARGET");

        if (value && *value) {
            char *endptr = NULL;
            uint64_t parsed = g_ascii_strtoull(value, &endptr, 0);

            if (endptr != value) {
                has_filter = true;
                filter = parsed;
            }
        }
        initialized = 1;
    }

    return !has_filter || target == filter;
}

static void ia64_trace_branch_write(CPUIA64State *env, const char *op,
                                    uint32_t reg, uint64_t value,
                                    uint64_t aux)
{
    int filter;

    if (!env || reg >= IA64_BR_COUNT || !ia64_branch_trace_enabled()) {
        return;
    }

    filter = ia64_branch_trace_filter();
    if (filter >= 0 && reg != (uint32_t)filter) {
        return;
    }
    if (!ia64_branch_trace_target_matches(value)) {
        return;
    }

    fprintf(stderr,
            "[ia64-br] ip=0x%016" PRIx64 " ri=%u %s b%u"
            " old=0x%016" PRIx64 " new=0x%016" PRIx64
            " aux=0x%016" PRIx64
            " cfm=0x%016" PRIx64 " pfs=0x%016" PRIx64
            " bsp=0x%016" PRIx64 " bspstore=0x%016" PRIx64 "\n",
            env->ip, ia64_env_ri(env), op, reg, env->br[reg],
            value, aux, env->cfm, env->ar[IA64_AR_PFS], env->rse.bsp,
            env->rse.bspstore);
}

void ia64_write_application_register(CPUIA64State *env, uint32_t reg,
                                     uint64_t value)
{
    if (!env || reg >= IA64_AR_COUNT) {
        return;
    }

    if (ia64_ar_trace_enabled() &&
        (reg == IA64_AR_LC || reg == IA64_AR_EC)) {
        fprintf(stderr, "[ia64-ar] ar[%u] <= 0x%016" PRIx64 "\n",
                reg, value);
    }

    /* Architecturally ignored ARs discard writes without side effects. */
    if ((reg >= 48 && reg <= 63) || reg >= 112) {
        return;
    }

    switch (reg) {
    case IA64_AR_ITC:
        ia64_itc_set(env, value);
        /*
         * An explicit ITC write starts a new comparison epoch.  It may
         * create an occurrence when the written value exactly equals ITM,
         * or arm a future equality, but writing beyond ITM must not replay a
         * comparison which has already been missed.
         */
        env->interrupt.timer_compare_latched = IA64_TIMER_COMPARE_IDLE;
        ia64_itc_timer_update(env);
        break;
    case IA64_AR_RSC:
    {
        uint64_t requested_pl =
            (value & IA64_RSC_PL_MASK) >> IA64_RSC_PL_SHIFT;
        uint64_t current_cpl =
            (ia64_env_psr(env) & IA64_PSR_CPL_MASK) >> IA64_PSR_CPL_SHIFT;
        uint64_t pl = MAX(requested_pl, current_cpl);

        uint64_t old_rsc = env->rse.rsc;

        value = (value & ~IA64_RSC_PL_MASK) |
                (pl << IA64_RSC_PL_SHIFT);
        env->ar[reg] = value;
        env->rse.rsc = value;
        env->rse.loadrs = (value >> 16) & 0x3fff;
        if ((old_rsc ^ value) & IA64_RSC_PL_MASK) {
            /* RSC.pl participates in every RSE backing-store TLB key. */
            ia64_cpu_tlb_flush(env);
        }
        break;
    }
    case IA64_AR_BSP:
        env->ar[reg] = value;
        env->rse.bsp = value;
        break;
    case IA64_AR_BSPSTORE:
    {
        int32_t dirty;

        ia64_rse_sync_logical_out(env);
        dirty = MAX(env->rse.dirty, 0);

        env->rse.bspstore = value & ~7ULL;
        env->rse.bsp_load = env->rse.bspstore;
        env->rse.dirty_nat = ia64_rse_nat_words_grow(
            env->rse.bspstore, dirty);
        env->rse.bsp = env->rse.bspstore +
            ((int64_t)dirty + env->rse.dirty_nat) * 8;
        env->rse.invalid += env->rse.clean;
        env->rse.clean = 0;
        env->rse.clean_nat = 0;
        env->rse.clean_count = 0;
        ia64_rse_sync_ar(env);
        ia64_rse_check_partitions(env, "mov-bspstore");
        break;
    }
    case IA64_AR_RNAT:
        ia64_rse_write_rnat(env, value);
        break;
    case IA64_AR_UNAT:
        env->ar[reg] = value;
        env->nat.unat = value;
        break;
    case IA64_AR_EC:
        env->ar[reg] = value & UINT64_C(0x3f);
        break;
    default:
        env->ar[reg] = value;
        break;
    }
}

static const char *ia64_cr_trace_name(uint32_t reg)
{
    switch (reg) {
    case IA64_CR_DCR:
        return "dcr";
    case IA64_CR_ITM:
        return "itm";
    case IA64_CR_IVA:
        return "iva";
    case IA64_CR_PTA:
        return "pta";
    case IA64_CR_IPSR:
        return "ipsr";
    case IA64_CR_ISR:
        return "isr";
    case IA64_CR_IIP:
        return "iip";
    case IA64_CR_IFA:
        return "ifa";
    case IA64_CR_ITIR:
        return "itir";
    case IA64_CR_IIPA:
        return "iipa";
    case IA64_CR_IFS:
        return "ifs";
    case IA64_CR_IIM:
        return "iim";
    case IA64_CR_IHA:
        return "iha";
    case IA64_CR_IIB0:
        return "iib0";
    case IA64_CR_IIB1:
        return "iib1";
    case IA64_CR_TPR:
        return "tpr";
    case IA64_CR_EOI:
        return "eoi";
    case IA64_CR_IRR0:
        return "irr0";
    case IA64_CR_IRR1:
        return "irr1";
    case IA64_CR_IRR2:
        return "irr2";
    case IA64_CR_IRR3:
        return "irr3";
    case IA64_CR_ITV:
        return "itv";
    case IA64_CR_IVR:
        return "ivr";
    default:
        return "cr";
    }
}

static int ia64_cr_trace_filter(void)
{
    static int initialized;
    static int filter;

    if (!initialized) {
        const char *value = g_getenv("VIBTANIUM_CR_TRACE_REG");
        char *endptr = NULL;

        filter = -1;
        if (value && *value) {
            unsigned long parsed = g_ascii_strtoull(value, &endptr, 0);

            if (endptr != value && parsed < IA64_CR_COUNT) {
                filter = (int)parsed;
            }
        }
        initialized = 1;
    }
    return filter;
}

static bool ia64_cr_trace_enabled(uint32_t reg)
{
    static int enabled = -1;
    int filter;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_CR_TRACE") != NULL;
    }
    if (!enabled) {
        return false;
    }
    filter = ia64_cr_trace_filter();
    return filter < 0 || filter == (int)reg;
}

static void ia64_trace_cr(CPUIA64State *env, const char *op, uint32_t reg,
                          uint64_t old_value, uint64_t new_value)
{
    if (!ia64_cr_trace_enabled(reg)) {
        return;
    }

    fprintf(stderr,
            "[ia64-cr] ip=0x%016" PRIx64 " op=%s cr%u.%s"
            " old=0x%016" PRIx64 " new=0x%016" PRIx64
            " psr=0x%016" PRIx64 " tpr=0x%016" PRIx64
            " ivr=0x%016" PRIx64 " irr3=0x%016" PRIx64
            " pending=%u vector=0x%016" PRIx64
            " isr=%016" PRIx64 ":%016" PRIx64
            ":%016" PRIx64 ":%016" PRIx64 "\n",
            env->ip, op, reg, ia64_cr_trace_name(reg), old_value, new_value,
            ia64_env_psr(env), env->cr[IA64_CR_TPR], env->cr[IA64_CR_IVR],
            env->cr[IA64_CR_IRR3], env->interrupt.pending,
            env->interrupt.pending_vector, env->interrupt.in_service[3],
            env->interrupt.in_service[2], env->interrupt.in_service[1],
            env->interrupt.in_service[0]);
}

bool ia64_psr_user_mask_value_valid(uint64_t value)
{
    return (value & ~IA64_PSR_UM_WRITABLE_MASK) == 0;
}

uint64_t ia64_psr_write_user_mask_value(uint64_t old_psr, uint64_t value)
{
    uint64_t write_mask = IA64_PSR_UM_WRITABLE_MASK;

    /* Secure performance monitoring makes PSR.up read-only. */
    if (old_psr & IA64_PSR_SP_BIT) {
        write_mask &= ~IA64_PSR_UP_BIT;
    }
    return (old_psr & ~write_mask) | (value & write_mask);
}

static bool ia64_time_after_eq(uint64_t lhs, uint64_t rhs)
{
    return (int64_t)(lhs - rhs) >= 0;
}

static uint64_t ia64_timer_vector(CPUIA64State *env)
{
    return env->cr[IA64_CR_ITV] & IA64_INTERRUPT_VECTOR_MASK;
}

static bool ia64_timer_vector_masked(CPUIA64State *env)
{
    return (env->cr[IA64_CR_ITV] & IA64_LOCAL_VECTOR_MASK_BIT) != 0;
}

static bool ia64_valid_external_interrupt_vector(uint64_t vector)
{
    /* Intel SDM Vol. 2, 5.8.3.6, Table 5-12 (ITV vector field). */
    return vector == 0 || vector == 2 ||
           (vector > IA64_INTERRUPT_SPURIOUS_VECTOR && vector <= 0xff);
}

static int ia64_external_interrupt_vector_priority(uint64_t vector)
{
    if (vector == 2) {
        return 257;
    }
    if (vector == 0) {
        return 256;
    }
    if (vector > IA64_INTERRUPT_SPURIOUS_VECTOR && vector <= 0xff) {
        return vector;
    }
    return -1;
}

static bool ia64_interrupt_vector_in_service(const CPUIA64State *env,
                                             uint64_t vector)
{
    return vector <= 0xff &&
           (env->interrupt.in_service[vector / 64] &
            (UINT64_C(1) << (vector & 63))) != 0;
}

static bool ia64_select_highest_in_service_external_interrupt(
    const CPUIA64State *env, uint64_t *vector_out)
{
    static const uint8_t special_priority[] = { 2, 0 };

    for (unsigned i = 0; i < ARRAY_SIZE(special_priority); i++) {
        uint64_t vector = special_priority[i];

        if (ia64_interrupt_vector_in_service(env, vector)) {
            *vector_out = vector;
            return true;
        }
    }
    for (int reg = 3; reg >= 0; reg--) {
        uint64_t active = env->interrupt.in_service[reg];

        while (active != 0) {
            unsigned bit = 63 - clz64(active);
            uint64_t vector = (uint64_t)reg * 64 + bit;

            if (vector != 0 && vector != 2 &&
                ia64_valid_external_interrupt_vector(vector)) {
                *vector_out = vector;
                return true;
            }
            active &= ~(UINT64_C(1) << bit);
        }
    }
    return false;
}

static bool ia64_external_interrupt_vector_masked_by_tpr(CPUIA64State *env,
                                                         uint64_t vector)
{
    uint64_t tpr = env->cr[IA64_CR_TPR];

    if (vector == 2) {
        return false;
    }
    if (tpr & IA64_TPR_MMI_BIT) {
        return true;
    }
    if (vector <= IA64_INTERRUPT_SPURIOUS_VECTOR) {
        return false;
    }
    return (vector >> 4) <= ((tpr & IA64_TPR_MIC_MASK) >> 4);
}

static bool ia64_external_interrupt_vector_masked(CPUIA64State *env,
                                                  uint64_t vector)
{
    uint64_t highest_in_service;

    if (ia64_select_highest_in_service_external_interrupt(
            env, &highest_in_service) &&
        ia64_external_interrupt_vector_priority(vector) <=
            ia64_external_interrupt_vector_priority(highest_in_service)) {
        return true;
    }
    return ia64_external_interrupt_vector_masked_by_tpr(env, vector);
}

static bool ia64_select_pending_external_interrupt(CPUIA64State *env,
                                                   bool honor_masks,
                                                   uint64_t *vector_out)
{
    static const uint8_t special_priority[] = { 2, 0 };

    for (unsigned i = 0; i < ARRAY_SIZE(special_priority); i++) {
        uint64_t vector = special_priority[i];

        if (ia64_interrupt_vector_pending(env, vector) &&
            (!honor_masks ||
             !ia64_external_interrupt_vector_masked(env, vector))) {
            *vector_out = vector;
            return true;
        }
    }
    for (int reg = IA64_CR_IRR3; reg >= IA64_CR_IRR0; reg--) {
        uint64_t pending = env->cr[reg];

        while (pending != 0) {
            unsigned bit = 63 - clz64(pending);
            uint64_t vector = (uint64_t)(reg - IA64_CR_IRR0) * 64 + bit;

            if (vector != 0 && vector != 2 &&
                ia64_valid_external_interrupt_vector(vector)) {
                if (!honor_masks ||
                    !ia64_external_interrupt_vector_masked(env, vector)) {
                    *vector_out = vector;
                    return true;
                }
            }
            pending &= ~(UINT64_C(1) << bit);
        }
    }

    return false;
}

static void ia64_refresh_pending_external_interrupt(CPUIA64State *env)
{
    uint64_t vector;

    if (ia64_select_pending_external_interrupt(env, false, &vector)) {
        env->interrupt.pending = true;
        env->interrupt.pending_vector = vector;
    } else {
        env->interrupt.pending = false;
        env->interrupt.pending_vector = 0;
    }
}

static void ia64_clear_pending_external_interrupt(CPUIA64State *env,
                                                  uint64_t vector)
{
    if (vector <= 0xff) {
        env->cr[IA64_CR_IRR0 + vector / 64] &= ~(UINT64_C(1) << (vector & 63));
    }
    ia64_refresh_pending_external_interrupt(env);
}

static bool ia64_interrupt_vector_pending(CPUIA64State *env, uint64_t vector)
{
    return vector <= 0xff &&
           (env->cr[IA64_CR_IRR0 + vector / 64] &
            (UINT64_C(1) << (vector & 63))) != 0;
}

static bool ia64_timer_compare_due(CPUIA64State *env)
{
    int64_t elapsed;
    uint64_t vector;

    if (!env || ia64_timer_vector_masked(env) ||
        env->interrupt.timer_compare_latched ==
            IA64_TIMER_COMPARE_CONSUMED) {
        return false;
    }

    vector = ia64_timer_vector(env);
    if (!ia64_valid_external_interrupt_vector(vector)) {
        return false;
    }

    elapsed = (int64_t)(env->ar[IA64_AR_ITC] - env->cr[IA64_CR_ITM]);
    if (elapsed == 0) {
        return true;
    }

    /*
     * Intel SDM Vol. 2, 10.5.5 defines the occurrence as ITC matching ITM;
     * 5.8.3.6 specifies that an occurrence while ITV.m is set is discarded.
     * The reference target's ia64_itm_update_pending() retains one additional
     * distinction which a host timer needs: whether a past match was armed.
     *
     * ITC > ITM is an occurrence only when this comparison was armed while
     * ITM was still in the future.  That is the late-host-callback case.  A
     * freshly programmed stale ITM, or an equality discarded while ITV was
     * masked, remains idle and cannot synthesize an interrupt on unmask.
     */
    return elapsed > 0 &&
           env->interrupt.timer_compare_latched == IA64_TIMER_COMPARE_ARMED;
}

static int64_t ia64_itc_clock_ticks(void)
{
    return qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL) / IA64_ITC_NS_PER_TICK;
}

void ia64_itc_sync(CPUIA64State *env)
{
    if (!env || !env->itc_clock_backed) {
        return;
    }

    env->ar[IA64_AR_ITC] = (uint64_t)(ia64_itc_clock_ticks() +
                                      env->itc_offset);
}

void ia64_itc_set(CPUIA64State *env, uint64_t value)
{
    if (!env) {
        return;
    }

    env->ar[IA64_AR_ITC] = value;
    if (env->itc_clock_backed) {
        env->itc_offset = (int64_t)value - ia64_itc_clock_ticks();
    }
}

void ia64_itc_warp_to(CPUIA64State *env, uint64_t target)
{
    if (!env) {
        return;
    }

    ia64_itc_sync(env);
    if (!ia64_time_after_eq(env->ar[IA64_AR_ITC], target)) {
        ia64_itc_set(env, target);
        ia64_itc_timer_update(env);
    }
}

static bool ia64_itm_timer_can_fire(CPUIA64State *env)
{
    uint64_t vector = ia64_timer_vector(env);

    return env->interrupt.timer_compare_latched !=
               IA64_TIMER_COMPARE_CONSUMED &&
           !ia64_timer_vector_masked(env) &&
           ia64_valid_external_interrupt_vector(vector);
}

void ia64_itc_timer_update(CPUIA64State *env)
{
    int64_t now_ns;
    int64_t delta_ticks;

    if (!env) {
        return;
    }
    ia64_itc_sync(env);
    if (!ia64_itm_timer_can_fire(env)) {
        if (env->interrupt.timer_compare_latched !=
            IA64_TIMER_COMPARE_CONSUMED) {
            env->interrupt.timer_compare_latched = IA64_TIMER_COMPARE_IDLE;
        }
        if (env->itm_timer) {
            timer_del(env->itm_timer);
        }
        return;
    }

    delta_ticks = (int64_t)(env->cr[IA64_CR_ITM] -
                            env->ar[IA64_AR_ITC]);
    if (delta_ticks < 0) {
        /* Preserve ARMED so a genuinely elapsed host deadline can fire. */
        if (env->itm_timer) {
            timer_del(env->itm_timer);
        }
        return;
    }

    /* Remember the equality even if vCPU polling happens one or more ticks late. */
    env->interrupt.timer_compare_latched = IA64_TIMER_COMPARE_ARMED;
    if (!env->itc_clock_backed || !env->itm_timer) {
        return;
    }

    now_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    if (delta_ticks == 0) {
        timer_mod(env->itm_timer, now_ns);
        return;
    }
    if (delta_ticks >= (INT64_MAX - now_ns) / IA64_ITC_NS_PER_TICK) {
        /*
         * The compare point lies beyond the virtual clock's range.  Every
         * ITM/ITV/ITC write re-evaluates the deadline, so treat it as
         * unreachable rather than arming an overflowed expiry.
         */
        timer_del(env->itm_timer);
        return;
    }
    timer_mod(env->itm_timer, now_ns + delta_ticks * IA64_ITC_NS_PER_TICK);
}

bool ia64_itc_timer_poll(CPUIA64State *env)
{
    ia64_itc_sync(env);
    return ia64_timer_interrupt_due(env);
}

bool ia64_timer_interrupt_due(CPUIA64State *env)
{
    uint64_t vector;

    IA64_PERF_INC(IA64_PERF_INTERRUPT_TIMER_CHECK);
    if (!ia64_timer_compare_due(env)) {
        IA64_PERF_INC(IA64_PERF_INTERRUPT_TIMER_FAST_NOT_DUE);
        return false;
    }

    vector = ia64_timer_vector(env);
    if (env->interrupt.timer_compare_latched ==
        IA64_TIMER_COMPARE_CONSUMED) {
        return false;
    }
    if (ia64_interrupt_vector_in_service(env, vector) ||
        ia64_interrupt_vector_pending(env, vector)) {
        return false;
    }

    IA64_PERF_INC(IA64_PERF_INTERRUPT_TIMER_DUE);
    return true;
}

void ia64_latch_timer_interrupt(CPUIA64State *env)
{
    IA64_PERF_INC(IA64_PERF_INTERRUPT_TIMER_LATCHED);
    if (ia64_queue_external_interrupt(env, ia64_timer_vector(env))) {
        env->interrupt.timer_compare_latched =
            IA64_TIMER_COMPARE_CONSUMED;
        ia64_itc_timer_update(env);
    }
}

bool ia64_queue_external_interrupt(CPUIA64State *env, uint64_t vector)
{
    if (!env || !ia64_valid_external_interrupt_vector(vector)) {
        return false;
    }

    env->cr[IA64_CR_IRR0 + vector / 64] |= UINT64_C(1) << (vector & 63);
    ia64_refresh_pending_external_interrupt(env);
    return true;
}

bool ia64_external_interrupt_pending(CPUIA64State *env)
{
    return env && env->interrupt.pending;
}

bool ia64_external_interrupt_enabled(CPUIA64State *env)
{
    uint64_t vector;

    return ia64_external_interrupt_pending(env) &&
           (ia64_env_psr(env) & IA64_PSR_I_BIT) != 0 &&
           ia64_select_pending_external_interrupt(env, true, &vector);
}

void ia64_refresh_interrupt_delivery(CPUIA64State *env)
{
    CPUState *cpu;

    if (!env) {
        return;
    }
    cpu = env_cpu(env);

    /*
     * This runs in serialized CPU-state context: normally the vCPU thread,
     * or while the CPU is stopped during post-load.  Re-arm the host deadline
     * first, then materialize an already-due ITM comparison in the
     * architectural IRR.  Keep HARD asserted even while the interrupt is
     * masked: a later PSR/TPR unmask must enter cpu_exec without relying on
     * another device edge or timer callback.
     */
    ia64_itc_timer_update(env);
    if (ia64_itc_timer_poll(env)) {
        ia64_latch_timer_interrupt(env);
    }
    if (ia64_external_interrupt_pending(env) &&
        (qatomic_read(&cpu->interrupt_request) & CPU_INTERRUPT_HARD) == 0) {
        /*
         * This path runs on the vCPU itself (or while it is stopped), outside
         * the BQL.  Arm the request without a redundant kick; the external
         * timer/device edge is responsible for waking a remote vCPU.
         */
        cpu_set_interrupt(cpu, CPU_INTERRUPT_HARD);
        IA64_PERF_INC(IA64_PERF_INTERRUPT_REQUEST);
    } else if (!ia64_external_interrupt_pending(env) &&
               (qatomic_read(&cpu->interrupt_request) &
                CPU_INTERRUPT_HARD) != 0) {
        /* HARD is derived from IRR, including after reset or VMState load. */
        cpu_reset_interrupt(cpu, CPU_INTERRUPT_HARD);
    }
}

void ia64_reconcile_interrupt_state(CPUIA64State *env)
{
    const uint64_t valid_word0 =
        (~UINT64_C(0) << 16) | UINT64_C(1) | (UINT64_C(1) << 2);
    uint64_t legacy_vector;

    if (!env) {
        return;
    }

    legacy_vector = env->cr[IA64_CR_IVR] & IA64_INTERRUPT_VECTOR_MASK;
    if (env->interrupt.legacy_pending_interruption &&
        ia64_valid_external_interrupt_vector(legacy_vector)) {
        env->interrupt.in_service[legacy_vector / 64] |=
            UINT64_C(1) << (legacy_vector & 63);
    }
    env->interrupt.legacy_pending_interruption = 0;
    env->interrupt.in_service[0] &= valid_word0;
    if (!ia64_valid_external_interrupt_vector(legacy_vector) &&
        legacy_vector != IA64_INTERRUPT_SPURIOUS_VECTOR) {
        env->cr[IA64_CR_IVR] = IA64_INTERRUPT_SPURIOUS_VECTOR;
    }

    ia64_refresh_pending_external_interrupt(env);
}

uint64_t ia64_read_control_register(CPUIA64State *env, uint32_t reg)
{
    uint64_t old;

    if (!env || reg >= IA64_CR_COUNT) {
        return 0;
    }

    old = env->cr[reg];
    switch (reg) {
    case IA64_CR_IVR:
    {
        uint64_t vector;

        if (ia64_select_pending_external_interrupt(env, true, &vector)) {
            ia64_clear_pending_external_interrupt(env, vector);
            env->interrupt.in_service[vector / 64] |=
                UINT64_C(1) << (vector & 63);
            env->cr[IA64_CR_IVR] = vector;
            ia64_trace_cr(env, "read", reg, old, vector);
            return vector;
        }
        env->cr[IA64_CR_IVR] = IA64_INTERRUPT_SPURIOUS_VECTOR;
        ia64_trace_cr(env, "read", reg, old, IA64_INTERRUPT_SPURIOUS_VECTOR);
        return IA64_INTERRUPT_SPURIOUS_VECTOR;
    }
    case IA64_CR_IRR0:
    case IA64_CR_IRR1:
    case IA64_CR_IRR2:
    case IA64_CR_IRR3:
        ia64_refresh_pending_external_interrupt(env);
        ia64_trace_cr(env, "read", reg, old, env->cr[reg]);
        return env->cr[reg];
    default:
        ia64_trace_cr(env, "read", reg, old, env->cr[reg]);
        return env->cr[reg];
    }
}

void ia64_write_control_register(CPUIA64State *env, uint32_t reg,
                                 uint64_t value)
{
    uint64_t old;

    if (!env || reg >= IA64_CR_COUNT) {
        return;
    }

    old = env->cr[reg];
    env->cr[reg] = value;
    switch (reg) {
    case IA64_CR_IVA:
        env->cr[reg] = value & ~UINT64_C(0x7fff);
        ia64_firmware_identity_tlb_set(env, false);
        ia64_cpu_tlb_flush(env);
        break;
    case IA64_CR_PTA:
        ia64_cpu_tlb_flush(env);
        break;
    case IA64_CR_IIPA:
        env->last_successful_bundle = value &
                                      ~(uint64_t)(IA64_BUNDLE_SIZE - 1);
        break;
    case IA64_CR_IVR:
        env->cr[reg] = old;
        break;
    case IA64_CR_TPR:
        ia64_refresh_pending_external_interrupt(env);
        break;
    case IA64_CR_EOI:
    {
        uint64_t vector;

        env->cr[reg] = 0;
        if (ia64_select_highest_in_service_external_interrupt(env, &vector)) {
            env->interrupt.in_service[vector / 64] &=
                ~(UINT64_C(1) << (vector & 63));
        }
        ia64_refresh_pending_external_interrupt(env);
        break;
    }
    case IA64_CR_ITM:
        env->interrupt.timer_compare_latched = IA64_TIMER_COMPARE_IDLE;
        ia64_itc_sync(env);
        if (!ia64_timer_compare_due(env)) {
            uint64_t vector = ia64_timer_vector(env);

            if (!ia64_interrupt_vector_in_service(env, vector)) {
                ia64_clear_pending_external_interrupt(env, vector);
            }
        }
        ia64_itc_timer_update(env);
        break;
    case IA64_CR_IRR0:
    case IA64_CR_IRR1:
    case IA64_CR_IRR2:
    case IA64_CR_IRR3:
        env->cr[reg] = old;
        break;
    case IA64_CR_ITV:
        /*
         * ITV selects and masks delivery; it does not create a new ITC/ITM
         * equality occurrence.  Only programming the comparison (or moving
         * ITC through a new comparison) may rearm a consumed match.
         */
        if (ia64_timer_vector_masked(env)) {
            ia64_clear_pending_external_interrupt(env,
                                                  value &
                                                  IA64_INTERRUPT_VECTOR_MASK);
        }
        ia64_itc_timer_update(env);
        break;
    default:
        break;
    }
    ia64_trace_cr(env, "write", reg, old, env->cr[reg]);
}

static uint32_t ia64_gr_nat_storage_index(uint32_t reg)
{
    return reg;
}

static int ia64_parse_nat_trace_filter(const char *name, uint32_t limit)
{
    const char *value = g_getenv(name);
    char *endptr = NULL;
    unsigned long parsed;

    if (!value || !*value) {
        return -1;
    }

    parsed = strtoul(value, &endptr, 0);
    if (endptr == value || parsed >= limit) {
        return -1;
    }

    return (int)parsed;
}

static bool ia64_gr_nat_trace_enabled(uint32_t reg)
{
    static int enabled = -1;
    static int filter = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_GR_NAT_TRACE") != NULL;
        filter = ia64_parse_nat_trace_filter("VIBTANIUM_GR_NAT_TRACE_REG",
                                             IA64_GR_COUNT);
    }

    return enabled && (filter < 0 || reg == (uint32_t)filter);
}

static bool ia64_gr_nat_trace_verbose(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_GR_NAT_TRACE_VERBOSE") != NULL;
    }

    return enabled;
}

static bool ia64_rse_nat_trace_enabled(uint32_t slot)
{
    static int enabled = -1;
    static int filter = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_RSE_NAT_TRACE") != NULL;
        filter = ia64_parse_nat_trace_filter("VIBTANIUM_RSE_NAT_TRACE_SLOT",
                                             IA64_STACKED_GR_COUNT);
    }

    return enabled && (filter < 0 || slot == (uint32_t)filter);
}

static bool ia64_rse_nat_trace_verbose(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_RSE_NAT_TRACE_VERBOSE") != NULL;
    }

    return enabled;
}

static void ia64_trace_gr_nat(CPUIA64State *env, const char *op,
                              uint32_t reg, uint32_t index,
                              bool old_nat, bool new_nat)
{
    uint32_t slot = reg >= IA64_STATIC_GR_COUNT
        ? ia64_stacked_gr_slot(env, reg)
        : UINT32_MAX;

    fprintf(stderr,
            "[ia64-gr-nat] op=%s ip=0x%016" PRIx64
            " reg=%u slot=%u index=%u old=%u new=%u"
            " cfm=0x%016" PRIx64 " pfs=0x%016" PRIx64
            " base=%u sof=%u sol=%u sor=%u rrb_gr=%u"
            " bsp=0x%016" PRIx64 " bspstore=0x%016" PRIx64
            " bspload=0x%016" PRIx64 " rnat=0x%016" PRIx64
            " gr=0x%016" PRIx64 "\n",
            op, env->ip, reg, slot, index, old_nat ? 1 : 0,
            new_nat ? 1 : 0, env->cfm, env->ar[IA64_AR_PFS],
            env->rse.current_frame_base, env->rse.sof, env->rse.sol,
            env->rse.sor, env->rse.rrb_gr, env->rse.bsp,
            env->rse.bspstore, env->rse.bsp_load, env->rse.rnat,
            ia64_read_gr(env, reg));
}

static void ia64_trace_rse_nat(CPUIA64State *env, const char *op,
                               uint32_t slot, uint32_t index,
                               bool old_nat, bool new_nat)
{
    fprintf(stderr,
            "[ia64-rse-nat] op=%s ip=0x%016" PRIx64
            " slot=%u index=%u old=%u new=%u"
            " cfm=0x%016" PRIx64 " pfs=0x%016" PRIx64
            " base=%u sof=%u sol=%u sor=%u rrb_gr=%u"
            " bsp=0x%016" PRIx64 " bspstore=0x%016" PRIx64
            " bspload=0x%016" PRIx64 " rnat=0x%016" PRIx64
            " value=0x%016" PRIx64 "\n",
            op, env->ip, slot, index, old_nat ? 1 : 0,
            new_nat ? 1 : 0, env->cfm, env->ar[IA64_AR_PFS],
            env->rse.current_frame_base, env->rse.sof, env->rse.sol,
            env->rse.sor, env->rse.rrb_gr, env->rse.bsp,
            env->rse.bspstore, env->rse.bsp_load, env->rse.rnat,
            env->rse.stacked_gr[ia64_rse_wrap_slot(slot)]);
}

bool ia64_rse_read_physical_nat(CPUIA64State *env, uint32_t slot)
{
    uint64_t word;

    if (!env) {
        return false;
    }

    slot = ia64_rse_wrap_slot(slot);
    word = env->rse.stacked_nat[slot / 64];
    return (word & (UINT64_C(1) << (slot % 64))) != 0;
}

void ia64_rse_write_physical_nat(CPUIA64State *env, uint32_t slot, bool nat)
{
    uint32_t index;
    uint64_t *word;
    uint64_t bit;
    bool old_nat;

    if (!env) {
        return;
    }

    slot = ia64_rse_wrap_slot(slot);
    index = IA64_STATIC_GR_COUNT + slot;
    word = &env->rse.stacked_nat[slot / 64];
    bit = UINT64_C(1) << (slot % 64);
    old_nat = (*word & bit) != 0;
    if (nat) {
        *word |= bit;
    } else {
        *word &= ~bit;
    }
    if (ia64_rse_nat_trace_enabled(slot) &&
        (old_nat != nat || nat || ia64_rse_nat_trace_verbose())) {
        ia64_trace_rse_nat(env, "write-phys", slot, index, old_nat, nat);
    }
}

void ia64_rse_sync_rnat(CPUIA64State *env)
{
    if (!env) {
        return;
    }

    env->rse.rnat &= IA64_RNAT_VALID_MASK;
    env->ar[IA64_AR_RNAT] = env->rse.rnat;
    env->nat.rnat = env->rse.rnat;
}

void ia64_rse_write_rnat(CPUIA64State *env, uint64_t value)
{
    if (!env) {
        return;
    }

    env->rse.rnat = value & IA64_RNAT_VALID_MASK;
    ia64_rse_sync_rnat(env);
}

void ia64_rse_clear_rnat(CPUIA64State *env)
{
    ia64_rse_write_rnat(env, 0);
}

bool ia64_read_gr_nat(CPUIA64State *env, uint32_t reg)
{
    uint32_t index;
    bool nat;

    if (!env || reg >= IA64_GR_COUNT) {
        return false;
    }

    index = ia64_gr_nat_storage_index(reg);
    if (reg < IA64_STATIC_GR_COUNT) {
        nat = (env->nat.gr_nat[0] & (UINT64_C(1) << reg)) != 0;
    } else {
        nat = ia64_rse_read_logical_nat(env,
                                        reg - IA64_STATIC_GR_COUNT);
    }
    if (ia64_gr_nat_trace_enabled(reg) &&
        (nat || ia64_gr_nat_trace_verbose())) {
        ia64_trace_gr_nat(env, "read", reg, index, nat, nat);
    }
    return nat;
}

void ia64_write_gr_nat(CPUIA64State *env, uint32_t reg, bool nat)
{
    uint32_t index;
    uint64_t bit;
    bool old_nat;

    if (!env || reg >= IA64_GR_COUNT) {
        return;
    }

    index = ia64_gr_nat_storage_index(reg);
    if (reg < IA64_STATIC_GR_COUNT) {
        bit = UINT64_C(1) << reg;
        old_nat = (env->nat.gr_nat[0] & bit) != 0;
        if (nat && reg != 0) {
            env->nat.gr_nat[0] |= bit;
        } else {
            env->nat.gr_nat[0] &= ~bit;
        }
    } else {
        uint32_t logical = reg - IA64_STATIC_GR_COUNT;

        bit = UINT64_C(1) << (logical % 64);
        old_nat = ia64_rse_read_logical_nat(env, logical);
        ia64_rse_write_logical_nat_raw(env, logical, nat);
        env->rse.logical_dirty[logical / 64] |= bit;
        env->rse.logical_dirty[1] &= UINT64_C(0xffffffff);
    }
    if (ia64_gr_nat_trace_enabled(reg) &&
        (old_nat != nat || nat || ia64_gr_nat_trace_verbose())) {
        ia64_trace_gr_nat(env, "write", reg, index, old_nat, nat && reg != 0);
    }
}

static bool ia64_exception_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_EXCEPTION_TRACE") != NULL;
    }
    return enabled != 0;
}

static bool ia64_user_rfi_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_USER_RFI_TRACE") != NULL;
    }
    return enabled != 0;
}

static uint64_t ia64_psr_cpl(uint64_t psr)
{
    return (psr & IA64_PSR_CPL_MASK) >> IA64_PSR_CPL_SHIFT;
}

static void ia64_trace_user_rfi(CPUIA64State *env, uint64_t bundle_ip,
                                uint64_t target)
{
    uint64_t ipsr;

    if (!ia64_user_rfi_trace_enabled()) {
        return;
    }

    ipsr = env->cr[IA64_CR_IPSR];
    if (ia64_psr_cpl(ipsr) != 3) {
        return;
    }

    fprintf(stderr,
            "[ia64-user-rfi] ip=0x%016" PRIx64
            " target=0x%016" PRIx64
            " ipsr=0x%016" PRIx64
            " ifs=0x%016" PRIx64
            " old_psr=0x%016" PRIx64
            " cfm=0x%016" PRIx64
            " pr=0x%016" PRIx64
            " r8=0x%016" PRIx64
            " r10=0x%016" PRIx64
            " r15=0x%016" PRIx64
            " r32=0x%016" PRIx64
            " r33=0x%016" PRIx64
            " r34=0x%016" PRIx64
            " r35=0x%016" PRIx64
            " r36=0x%016" PRIx64
            " r37=0x%016" PRIx64
            " r38=0x%016" PRIx64
            " r39=0x%016" PRIx64
            " b0=0x%016" PRIx64
            " b6=0x%016" PRIx64
            " b7=0x%016" PRIx64
            " bsp=0x%016" PRIx64
            " bspstore=0x%016" PRIx64
            " rsc=0x%016" PRIx64 "\n",
            bundle_ip, target, ipsr, env->cr[IA64_CR_IFS], env->psr,
            env->cfm, env->pr, ia64_read_gr(env, 8), ia64_read_gr(env, 10),
            ia64_read_gr(env, 15), ia64_read_gr(env, 32),
            ia64_read_gr(env, 33), ia64_read_gr(env, 34),
            ia64_read_gr(env, 35), ia64_read_gr(env, 36),
            ia64_read_gr(env, 37), ia64_read_gr(env, 38),
            ia64_read_gr(env, 39), env->br[0], env->br[6], env->br[7],
            env->ar[IA64_AR_BSP], env->ar[IA64_AR_BSPSTORE],
            env->ar[IA64_AR_RSC]);
}

static void ia64_update_cfm_rename_bases(CPUIA64State *env)
{
    env->cfm = (env->cfm & ~((((1ULL << 7) - 1) << 18) |
                             (((1ULL << 7) - 1) << 25) |
                             (((1ULL << 6) - 1) << 32))) |
               ((uint64_t)(env->rse.rrb_gr & 0x7f) << 18) |
               ((uint64_t)(env->rse.rrb_fr & 0x7f) << 25) |
               ((uint64_t)(env->rse.rrb_pr & 0x3f) << 32);
}

static void ia64_rotate_logical_nat_right(CPUIA64State *env,
                                          uint32_t rotating_count)
{
    uint64_t low = env->rse.logical_nat[0];
    uint64_t high = env->rse.logical_nat[1] & UINT64_C(0xffffffff);

    if (rotating_count <= 64) {
        uint64_t mask = rotating_count == 64 ? UINT64_MAX :
                        (UINT64_C(1) << rotating_count) - 1;
        uint64_t rotating = low & mask;

        rotating = ((rotating << 1) & mask) |
                   (rotating >> (rotating_count - 1));
        env->rse.logical_nat[0] = (low & ~mask) | rotating;
    } else {
        uint32_t high_count = rotating_count - 64;
        uint64_t high_mask = (UINT64_C(1) << high_count) - 1;
        uint64_t rotating_high = high & high_mask;
        uint64_t wrap = rotating_high >> (high_count - 1);

        env->rse.logical_nat[0] = (low << 1) | wrap;
        rotating_high = ((rotating_high << 1) & high_mask) | (low >> 63);
        env->rse.logical_nat[1] = (high & ~high_mask) | rotating_high;
    }
    env->rse.logical_nat[1] &= UINT64_C(0xffffffff);
}

static void ia64_rotate_issue_group_gr_right(CPUIA64State *env,
                                              uint32_t rotating_count)
{
    IA64IssueGroupState *group = &env->issue_group;
    uint64_t last_gr;
    uint64_t last_nat;
    uint64_t low;
    uint64_t high;

    if (!group->typed_active || rotating_count == 0) {
        return;
    }

    last_gr = group->saved_gr[IA64_STATIC_GR_COUNT + rotating_count - 1];
    last_nat = group->saved_nat[IA64_STATIC_GR_COUNT + rotating_count - 1];
    memmove(&group->saved_gr[IA64_STATIC_GR_COUNT + 1],
            &group->saved_gr[IA64_STATIC_GR_COUNT],
            (rotating_count - 1) * sizeof(group->saved_gr[0]));
    memmove(&group->saved_nat[IA64_STATIC_GR_COUNT + 1],
            &group->saved_nat[IA64_STATIC_GR_COUNT],
            (rotating_count - 1) * sizeof(group->saved_nat[0]));
    group->saved_gr[IA64_STATIC_GR_COUNT] = last_gr;
    group->saved_nat[IA64_STATIC_GR_COUNT] = last_nat;

    /* saved_gr_mask uses the same logical names, starting at bit 32. */
    low = group->saved_gr_mask[0];
    high = group->saved_gr_mask[1];
    if (rotating_count <= 32) {
        uint64_t mask = rotating_count == 32 ? UINT64_C(0xffffffff) :
                        (UINT64_C(1) << rotating_count) - 1;
        uint64_t rotating = (low >> IA64_STATIC_GR_COUNT) & mask;

        rotating = ((rotating << 1) & mask) |
                   (rotating >> (rotating_count - 1));
        group->saved_gr_mask[0] =
            (low & ~(mask << IA64_STATIC_GR_COUNT)) |
            (rotating << IA64_STATIC_GR_COUNT);
    } else {
        uint32_t high_count = rotating_count - 32;
        uint64_t high_mask = high_count == 64 ? UINT64_MAX :
                             (UINT64_C(1) << high_count) - 1;
        uint64_t rotating_low = low >> IA64_STATIC_GR_COUNT;
        uint64_t rotating_high = high & high_mask;
        uint64_t wrap = rotating_high >> (high_count - 1);

        group->saved_gr_mask[0] =
            (low & UINT64_C(0xffffffff)) |
            ((((rotating_low << 1) & UINT64_C(0xffffffff)) | wrap) <<
             IA64_STATIC_GR_COUNT);
        rotating_high = ((rotating_high << 1) & high_mask) |
                        (rotating_low >> 31);
        group->saved_gr_mask[1] = (high & ~high_mask) | rotating_high;
    }
}

void ia64_rotate_modulo_scheduled_registers(CPUIA64State *env)
{
    uint32_t rotating_gr_count;

    if (!env) {
        return;
    }

    rotating_gr_count = env->rse.sor * 8;
    /* Architecturally valid CFM limits SOR * 8 to 96 stacked names. */
    g_assert(rotating_gr_count <= IA64_GR_COUNT - IA64_STATIC_GR_COUNT);

    /* Publish only dirty names while the old RRB mapping still owns them. */
    ia64_rse_sync_logical_out(env);
    ia64_alat_invalidate_rotating_grs(env, rotating_gr_count);
    ia64_alat_invalidate_rotating_frs(env);
    if (rotating_gr_count != 0) {
        uint64_t last =
            env->gr[IA64_STATIC_GR_COUNT + rotating_gr_count - 1];

        /*
         * With RRB' = RRB - 1, slot'(i) is exactly slot(i - 1).  Rotating
         * the persistent logical mirror right therefore leaves the physical
         * backing file authoritative without a 96-register sync-in.
         */
        memmove(&env->gr[IA64_STATIC_GR_COUNT + 1],
                &env->gr[IA64_STATIC_GR_COUNT],
                (rotating_gr_count - 1) * sizeof(env->gr[0]));
        env->gr[IA64_STATIC_GR_COUNT] = last;
        ia64_rotate_logical_nat_right(env, rotating_gr_count);
        ia64_rotate_issue_group_gr_right(env, rotating_gr_count);
        env->rse.rrb_gr =
            (env->rse.rrb_gr + rotating_gr_count - 1) % rotating_gr_count;
    }
    env->rse.rrb_fr = (env->rse.rrb_fr + 95) % 96;
    env->rse.rrb_pr = (env->rse.rrb_pr + 47) % 48;
    ia64_update_cfm_rename_bases(env);
    g_assert((env->rse.logical_dirty[0] |
              env->rse.logical_dirty[1]) == 0);
}

void ia64_rse_cover_frame(CPUIA64State *env)
{
    uint64_t covered_cfm = env->cfm;
    uint32_t covered_sof = env->rse.sof;

    ia64_rse_sync_logical_out(env);
    ia64_rse_preserve_frame(env, covered_sof);
    ia64_set_cfm(env, 0);
    ia64_rse_sync_logical_in(env);
    ia64_alat_invalidate_stacked_gr_range(
        env, IA64_GR_COUNT - IA64_STATIC_GR_COUNT);
    ia64_rse_check_partitions(env, "cover");
    if ((env->psr & IA64_PSR_IC_BIT) == 0) {
        env->cr[IA64_CR_IFS] = covered_cfm | IA64_IFS_VALID_BIT;
    }
}

void ia64_rse_clear_rename_bases(CPUIA64State *env, bool predicate_only)
{
    if (!predicate_only) {
        ia64_rse_sync_logical_out(env);
        if (env->rse.rrb_fr != 0) {
            ia64_alat_invalidate_rotating_frs(env);
        }
        env->rse.rrb_gr = 0;
        env->rse.rrb_fr = 0;
    }
    env->rse.rrb_pr = 0;
    ia64_update_cfm_rename_bases(env);
    if (!predicate_only) {
        ia64_rse_sync_logical_in(env);
    }
    ia64_alat_invalidate_stacked_gr_range(
        env, IA64_GR_COUNT - IA64_STATIC_GR_COUNT);
}

static uint32_t ia64_cfm_sof(uint64_t cfm)
{
    return cfm & 0x7f;
}

static uint32_t ia64_cfm_sol(uint64_t cfm)
{
    return (cfm >> 7) & 0x7f;
}

void ia64_enter_call_frame(CPUIA64State *env)
{
    uint64_t caller_cfm;
    uint64_t caller_ec;
    uint64_t caller_cpl;
    uint32_t caller_sof;
    uint32_t caller_sol;
    uint32_t output_count;

    if (!env) {
        return;
    }

    caller_cfm = env->cfm;
    caller_ec = ia64_read_application_register(env, IA64_AR_EC) & 0x3f;
    caller_cpl =
        (ia64_env_psr(env) & IA64_PSR_CPL_MASK) >> IA64_PSR_CPL_SHIFT;
    caller_sof = ia64_cfm_sof(caller_cfm);
    caller_sol = ia64_cfm_sol(caller_cfm);
    g_assert(caller_sol <= caller_sof);
    output_count = caller_sof - caller_sol;

    ia64_rse_sync_logical_out(env);
    env->ar[IA64_AR_PFS] = (caller_cfm & IA64_PFS_CFM_MASK) |
                           (caller_ec << IA64_PFS_PEC_SHIFT) |
                           (caller_cpl << IA64_PFS_PPL_SHIFT);
    ia64_alat_invalidate_stacked_gr_range(
        env, IA64_GR_COUNT - IA64_STATIC_GR_COUNT);
    ia64_rse_preserve_frame(env, caller_sol);
    ia64_set_cfm(env, ia64_make_cfm(output_count, 0, 0));
    ia64_rse_sync_logical_in(env);
    env->rse.clean_count = env->rse.clean;
    ia64_rse_check_partitions(env, "call");
}

bool ia64_rse_return_frame_from_pfs(CPUIA64State *env, uint64_t pfs)
{
    uint64_t restored_cfm = pfs & IA64_PFS_CFM_MASK;
    uint64_t restored_ec =
        (pfs & IA64_PFS_PEC_MASK) >> IA64_PFS_PEC_SHIFT;
    uint64_t restored_cpl =
        (pfs & IA64_PFS_PPL_MASK) >> IA64_PFS_PPL_SHIFT;
    uint32_t restored_sol = ia64_cfm_sol(restored_cfm);
    uint64_t current_cpl;
    bool bad_pfs;

    if (!env) {
        return false;
    }
    bad_pfs = ia64_rse_return_to_frame(env, restored_cfm, restored_sol);
    ia64_write_application_register(env, IA64_AR_EC, restored_ec);
    current_cpl = (ia64_env_psr(env) & IA64_PSR_CPL_MASK) >>
                  IA64_PSR_CPL_SHIFT;
    if (current_cpl < restored_cpl) {
        ia64_env_set_psr(env, (ia64_env_psr(env) & ~IA64_PSR_CPL_MASK) |
                              (restored_cpl << IA64_PSR_CPL_SHIFT));
    }
    return bad_pfs;
}

bool ia64_rse_return_frame_from_ifs(CPUIA64State *env, uint64_t ifs)
{
    uint64_t restored_cfm;
    uint32_t restored_sof;

    if (!env || (ifs & IA64_IFS_VALID_BIT) == 0) {
        return false;
    }

    restored_cfm = ifs & IA64_CFM_MASK;
    restored_sof = ia64_cfm_sof(restored_cfm);
    return ia64_rse_return_to_frame(env, restored_cfm, restored_sof);
}

void ia64_rfi_restore_state(CPUIA64State *env, uint64_t source_ip)
{
    uint64_t target;
    uint64_t ifs;

    if (!env) {
        return;
    }

    target = env->cr[IA64_CR_IIP] & ~UINT64_C(0xf);
    ifs = env->cr[IA64_CR_IFS];
    trace_ia64_rfi(source_ip, target, env->cr[IA64_CR_IPSR], ifs,
                   env->psr, env->cfm);
    ia64_diag_record_rfi(env, source_ip, target);
    ia64_trace_user_rfi(env, source_ip, target);
    if (ia64_exception_trace_enabled()) {
        fprintf(stderr,
                "[ia64-rfi] ip=0x%016" PRIx64
                " target=0x%016" PRIx64 " ipsr=0x%016" PRIx64
                " ifs=0x%016" PRIx64 " psr=0x%016" PRIx64
                " cfm=0x%016" PRIx64 "\n",
                source_ip, target, env->cr[IA64_CR_IPSR], ifs,
                env->psr, env->cfm);
    }

    ia64_env_replace_psr(env, env->cr[IA64_CR_IPSR]);
    if (ifs & IA64_IFS_VALID_BIT) {
        ia64_rse_return_frame_from_ifs(env, ifs);
    }
    env->ip = target;
    ia64_env_begin_source_visibility_epoch(env);
}

bool ia64_return_from_call_frame(CPUIA64State *env, uint64_t target_ip)
{
    if (!env) {
        return false;
    }

    ia64_rse_return_frame_from_pfs(env, env->ar[IA64_AR_PFS]);
    env->ip = target_ip & ~0xfULL;
    env->cr[IA64_CR_IIP] = env->ip;
    ia64_env_begin_source_visibility_epoch(env);
    return true;
}

void ia64_branch_call_effects(CPUIA64State *env, uint32_t b1,
                              uint64_t bundle_ip)
{
    ia64_trace_branch_write(env, "br.call-relative", b1,
                            bundle_ip + IA64_BUNDLE_SIZE, bundle_ip);
    env->br[b1] = bundle_ip + IA64_BUNDLE_SIZE;
    ia64_enter_call_frame(env);
}
