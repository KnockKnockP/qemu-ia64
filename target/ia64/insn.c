/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "exception.h"
#include "flight-recorder.h"
#include "fpu/softfloat.h"
#include "insn.h"
#include "mem.h"
#include "perf.h"
#include "qemu/host-utils.h"
#include "qemu/timer.h"
#include "trace-target_ia64.h"

#define IA64_FR_EXPONENT_BIAS 0xffff
#define IA64_FR_INTEGER_EXPONENT 0x1003e
#define IA64_FR_SPECIAL_EXPONENT 0x1ffff
#define IA64_FR_NATVAL_EXPONENT 0x1fffe
#define IA64_FR_INTEGER_BIT UINT64_C(0x8000000000000000)
#define IA64_FR_QUIET_NAN_BIT UINT64_C(0x4000000000000000)
#define IA64_FCLASS_POSITIVE 0x001
#define IA64_FCLASS_NEGATIVE 0x002
#define IA64_FCLASS_ZERO 0x004
#define IA64_FCLASS_UNNORMALIZED 0x008
#define IA64_FCLASS_NORMALIZED 0x010
#define IA64_FCLASS_INFINITY 0x020
#define IA64_FCLASS_SNAN 0x040
#define IA64_FCLASS_QNAN 0x080
#define IA64_FCLASS_NATVAL 0x100
#define IA64_FPSR_STATUS_FIELD_SHIFT(sf) (6 + (13 * (sf)))
#define IA64_FPSR_STATUS_FIELD_MASK UINT64_C(0x1fff)
#define IA64_FPSR_STATUS_RC_SHIFT 4
#define IA64_FPSR_STATUS_RC_MASK 0x3
#define IA64_RR_IMPLEMENTED_MASK UINT64_C(0x00000000fffffffd)
#define IA64_PSR_I_BIT UINT64_C(0x0000000000004000)
#define IA64_PSR_IC_BIT UINT64_C(0x0000000000002000)
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
    env->cpuid[3] = (UINT64_C(2) << 32) | 4;
    env->cpuid[4] = (UINT64_C(1) << 32) | (UINT64_C(1) << 33);
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
    ia64_env_set_psr(env, 0);
    ia64_set_cfm(env, 0);
    env->fr[0].raw[1] = IA64_FR_SPECIAL_EXPONENT;
    env->fr[1].raw[0] = IA64_FR_INTEGER_BIT;
    env->fr[1].raw[1] = IA64_FR_EXPONENT_BIAS;

    env->ar[IA64_AR_RSC] = env->rse.rsc;
    env->ar[IA64_AR_BSP] = env->rse.bsp;
    env->ar[IA64_AR_BSPSTORE] = env->rse.bspstore;
    env->ar[IA64_AR_RNAT] = env->rse.rnat;
    env->ar[IA64_AR_UNAT] = env->nat.unat;
    env->ar[IA64_AR_PFS] = 0;
    env->ar[IA64_AR_FPSR] = 0;

    for (unsigned i = 0; i < IA64_RR_COUNT; i++) {
        env->rr[i] = ia64_default_region_register(i);
    }
    ia64_cpu_init_synthetic_cpuid(env);

    env->cr[IA64_CR_IPSR] = env->psr;
    env->cr[IA64_CR_IIP] = env->ip;
    env->cr[IA64_CR_IFS] = env->cfm;
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

static bool ia64_fp_regs_fault(CPUIA64State *env, const uint32_t *regs,
                               unsigned count, bool *high)
{
    uint64_t psr = ia64_env_psr(env);
    bool dfl = (psr & IA64_PSR_DFL_BIT) != 0;
    bool dfh = (psr & IA64_PSR_DFH_BIT) != 0;

    if (!dfl && !dfh) {
        return false;
    }
    for (unsigned i = 0; i < count; i++) {
        uint32_t reg = regs[i];

        if (reg >= 32 && reg < IA64_FR_COUNT && dfh) {
            *high = true;
            return true;
        }
        if (reg >= 2 && reg < 32 && dfl) {
            *high = false;
            return true;
        }
    }
    return false;
}

bool ia64_slot_raises_disabled_fp(CPUIA64State *env, IA64SlotType type,
                                  uint64_t raw, bool *high)
{
    uint64_t psr = ia64_env_psr(env);
    uint32_t regs[4];
    unsigned count = 0;
    IA64FloatingMemoryInstruction fldst;

    if ((psr & (IA64_PSR_DFL_BIT | IA64_PSR_DFH_BIT)) == 0) {
        return false;
    }

    if (type == IA64_SLOT_TYPE_F) {
        if (ia64_slot_is_f_multiply_add(type, raw) ||
            ia64_slot_is_f_select_or_xma(type, raw)) {
            regs[count++] = (raw >> 6) & 0x7f;
            regs[count++] = (raw >> 13) & 0x7f;
            regs[count++] = (raw >> 20) & 0x7f;
            regs[count++] = (raw >> 27) & 0x7f;
        } else if (ia64_slot_is_f_reciprocal_approx(type, raw)) {
            regs[count++] = (raw >> 6) & 0x7f;
            if (((raw >> 36) & 0x1) == 0) {
                regs[count++] = (raw >> 13) & 0x7f;
            }
            regs[count++] = (raw >> 20) & 0x7f;
        } else if (ia64_slot_is_f_misc(type, raw)) {
            uint8_t x6 = (raw >> 27) & 0x3f;

            if (x6 == 0x01 || x6 == 0x05) {
                return false;
            }
            regs[count++] = (raw >> 6) & 0x7f;
            regs[count++] = (raw >> 13) & 0x7f;
            if (x6 < 0x18 || x6 > 0x1c) {
                regs[count++] = (raw >> 20) & 0x7f;
            }
        } else if (ia64_slot_major_opcode(raw) == 0x4 ||
                   ia64_slot_major_opcode(raw) == 0x5) {
            /* fcmp (major 4) reads f2/f3; fclass (major 5) reads f2. */
            regs[count++] = (raw >> 13) & 0x7f;
            if (ia64_slot_major_opcode(raw) == 0x4) {
                regs[count++] = (raw >> 20) & 0x7f;
            }
        } else {
            return false;
        }
        return ia64_fp_regs_fault(env, regs, count, high);
    }

    if (type != IA64_SLOT_TYPE_M) {
        return false;
    }

    if (ia64_slot_is_m_setf(type, raw)) {
        regs[count++] = (raw >> 6) & 0x7f;
        return ia64_fp_regs_fault(env, regs, count, high);
    }
    if (ia64_slot_is_m_getf(type, raw)) {
        regs[count++] = (raw >> 13) & 0x7f;
        return ia64_fp_regs_fault(env, regs, count, high);
    }
    if (ia64_decode_floating_memory(type, raw, &fldst)) {
        if (fldst.kind == IA64_FLOAT_MEM_PREFETCH) {
            return false;
        }
        regs[count++] = fldst.freg;
        if (fldst.kind == IA64_FLOAT_MEM_LOAD_PAIR) {
            regs[count++] = fldst.freg2;
        }
        return ia64_fp_regs_fault(env, regs, count, high);
    }

    return false;
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

const char *ia64_insn_status_name(IA64InsnStatus status)
{
    switch (status) {
    case IA64_INSN_OK:
        return "ok";
    case IA64_INSN_RESERVED_TEMPLATE:
        return "reserved-template";
    case IA64_INSN_UNSUPPORTED_SLOT:
        return "unsupported-slot";
    default:
        return "unknown";
    }
}

bool ia64_insn_slot_supported(IA64SlotType type, uint64_t raw)
{
    return ia64_slot_is_nop_or_hint(type, raw);
}

uint64_t ia64_make_cfm(uint32_t sof, uint32_t sol, uint32_t sor)
{
    return (sof & 0x7f) | ((uint64_t)(sol & 0x7f) << 7) |
           ((uint64_t)(sor & 0x0f) << 14);
}

void ia64_set_cfm(CPUIA64State *env, uint64_t cfm)
{
    if (!env) {
        return;
    }

    env->cfm = cfm;
    env->rse.sof = cfm & 0x7f;
    env->rse.sol = (cfm >> 7) & 0x7f;
    env->rse.sor = (cfm >> 14) & 0x0f;
    env->rse.rrb_gr = (cfm >> 18) & 0x7f;
    env->rse.rrb_fr = (cfm >> 25) & 0x7f;
    env->rse.rrb_pr = (cfm >> 32) & 0x3f;
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

bool ia64_rse_address_is_rnat_slot(uint64_t address)
{
    return ia64_rse_slot_num(address) == 0x3f;
}

uint64_t ia64_rse_rnat_address(uint64_t address)
{
    return (address & ~UINT64_C(0x1ff)) | (UINT64_C(0x3f) << 3);
}

uint32_t ia64_rse_nat_collection_bit(uint64_t address)
{
    return ia64_rse_slot_num(address);
}

uint64_t ia64_rse_reg_address(uint64_t address)
{
    return ia64_rse_address_is_rnat_slot(address) ? address + 8 : address;
}

uint32_t ia64_rse_dirty_partition_first_slot(CPUIA64State *env,
                                             uint32_t count)
{
    if (!env) {
        return 0;
    }

    return ia64_rse_wrap_slot(env->rse.current_frame_base - count);
}

static void ia64_rse_sync_ar(CPUIA64State *env);

typedef struct IA64RSENatCache {
    uint64_t address;
    uint64_t value;
    bool valid;
} IA64RSENatCache;

static uint64_t ia64_rse_load_nat_collection(
    CPUIA64State *env, uint64_t address, uint64_t load_start,
    uint64_t load_end, uint64_t dirty_start, uint64_t dirty_end,
    IA64RSEReadRegisterFn read_register, void *opaque,
    IA64RSENatCache *cache)
{
    uint64_t rnat_address = ia64_rse_rnat_address(address);

    if (rnat_address >= dirty_start && rnat_address < dirty_end) {
        return env->rse.rnat;
    }
    if (rnat_address < load_start || rnat_address >= load_end) {
        return env->rse.rnat;
    }

    if (!cache->valid || cache->address != rnat_address) {
        cache->address = rnat_address;
        cache->value = read_register(env, rnat_address, opaque) &
                       IA64_RNAT_VALID_MASK;
        cache->valid = true;
    }
    return cache->value;
}

static void ia64_rse_load_register_nat(CPUIA64State *env, uint32_t slot,
                                       uint64_t address, uint64_t rnat)
{
    uint64_t bit = UINT64_C(1) << ia64_rse_nat_collection_bit(address);

    ia64_rse_write_physical_nat(env, slot, (rnat & bit) != 0);
}

static void ia64_rse_store_register_nat(CPUIA64State *env, uint32_t slot,
                                        uint64_t address)
{
    uint64_t bit = UINT64_C(1) << ia64_rse_nat_collection_bit(address);

    if (ia64_rse_read_physical_nat(env, slot)) {
        env->rse.rnat |= bit;
    } else {
        env->rse.rnat &= ~bit;
    }
    ia64_rse_sync_rnat(env);
}

void ia64_rse_load_dirty_partition(CPUIA64State *env, uint64_t load_start,
                                   uint64_t load_end,
                                   IA64RSEReadRegisterFn read_register,
                                   void *opaque)
{
    uint64_t dirty_start;
    uint64_t dirty_end;
    uint64_t address;
    uint32_t first_slot;
    uint32_t count;
    IA64RSENatCache nat_cache = { 0 };

    if (!env || !read_register || load_end <= load_start) {
        return;
    }

    count = ia64_rse_num_regs(load_start, load_end);
    if (count == 0) {
        return;
    }
    count = MIN(count, (uint32_t)IA64_STACKED_GR_COUNT);
    first_slot = ia64_rse_dirty_partition_first_slot(env, count);
    dirty_start = env->rse.bspstore;
    dirty_end = env->rse.bsp;
    address = ia64_rse_skip_regs(load_end, -(int64_t)count);
    for (uint32_t i = 0; i < count; i++) {
        uint32_t slot = ia64_rse_wrap_slot(first_slot + i);

        address = ia64_rse_reg_address(address);
        if (dirty_start == 0 || address < dirty_start || address >= dirty_end) {
            uint64_t rnat = ia64_rse_load_nat_collection(
                env, address, load_start, load_end, dirty_start, dirty_end,
                read_register, opaque, &nat_cache);

            env->rse.stacked_gr[slot] = read_register(env, address, opaque);
            ia64_rse_load_register_nat(env, slot, address, rnat);
        }
        address += 8;
    }
}

/*
 * Mandatory RSE spill.  Real hardware has only IA64_RSE_PHYS_STACKED_REGS
 * physical stacked registers, so the architecturally visible dirty partition
 * (AR.BSP - AR.BSPSTORE) can never exceed capacity minus the current frame:
 * when alloc grows the frame past that bound the RSE stalls and stores the
 * oldest dirty registers to the backing store, advancing AR.BSPSTORE.
 *
 * The emulated stacked file is larger than hardware's, but the bound must
 * still be enforced because guests rely on it: Linux computes the user
 * dirty-partition byte count at kernel entry and stashes it shifted into the
 * 14-bit RSC.loadrs field (minstate.h "shl r18=r18,16").  An unbounded dirty
 * partition eventually exceeds 0x3fff bytes, the shift silently truncates,
 * and the kernel-exit loadrs + AR.BSPSTORE rebase reconstruct a user AR.BSP
 * thousands of slots too low -- after which deep call-stack unwinds (perl was
 * the first guest program to hit this) walk the br.ret fill below the
 * backing-store bottom and the process dies with SIGSEGV.
 *
 * Spilled stores are idempotent (same values to the same addresses) and
 * AR.BSPSTORE is only advanced after the loop, so a page fault raised by
 * write_register mid-spill restarts the whole alloc cleanly.
 */
uint32_t ia64_rse_spill_excess_dirty(CPUIA64State *env, uint32_t new_sof,
                                     IA64RSEWriteRegisterFn write_register,
                                     void *opaque)
{
    uint32_t dirty;
    uint32_t excess;
    uint32_t first_slot;
    uint64_t address;

    if (!env || !write_register || env->rse.bspstore == 0) {
        return 0;
    }

    dirty = ia64_rse_num_regs(env->rse.bspstore, env->rse.bsp);
    if (dirty + new_sof <= IA64_RSE_PHYS_STACKED_REGS) {
        return 0;
    }

    excess = MIN(dirty + new_sof - IA64_RSE_PHYS_STACKED_REGS, dirty);
    first_slot = ia64_rse_dirty_partition_first_slot(env, dirty);
    address = env->rse.bspstore;
    for (uint32_t i = 0; i < excess;) {
        uint32_t slot;
        uint64_t value;

        if (ia64_rse_address_is_rnat_slot(address)) {
            write_register(env, address, env->rse.rnat, opaque);
            ia64_rse_clear_rnat(env);
            address += 8;
            continue;
        }

        slot = ia64_rse_wrap_slot(first_slot + i);
        value = env->rse.stacked_gr[slot];
        ia64_rse_store_register_nat(env, slot, address);
        write_register(env, address, value, opaque);
        address += 8;
        i++;
    }

    env->rse.bspstore = address;
    env->rse.bsp_load = address;
    env->ar[IA64_AR_BSPSTORE] = address;
    dirty = ia64_rse_num_regs(env->rse.bspstore, env->rse.bsp);
    env->rse.clean_count = dirty < env->rse.current_frame_base
        ? env->rse.current_frame_base - dirty
        : 0;
    ia64_rse_sync_ar(env);
    return excess;
}

uint32_t ia64_rse_load_restored_frame(CPUIA64State *env, uint32_t count,
                                      IA64RSEReadRegisterFn read_register,
                                      void *opaque)
{
    uint64_t frame_base;
    uint64_t frame_end;
    uint64_t load_end;
    uint64_t address;
    uint32_t filled = 0;
    IA64RSENatCache nat_cache = { 0 };

    if (!env || !read_register || count == 0 || env->rse.bsp == 0) {
        return 0;
    }

    count = MIN(count, (uint32_t)IA64_STACKED_GR_COUNT);
    frame_base = env->rse.bsp;
    frame_end = ia64_rse_skip_regs(frame_base, count);
    load_end = env->rse.bsp_load != 0 ? env->rse.bsp_load
                                      : env->rse.bspstore;

    if (load_end > frame_end) {
        load_end = frame_end;
    }
    if (load_end <= frame_base) {
        return 0;
    }

    address = frame_base;
    for (uint32_t i = 0; i < count; i++) {
        uint32_t slot = ia64_rse_wrap_slot(env->rse.current_frame_base + i);
        uint64_t rnat;

        address = ia64_rse_reg_address(address);
        if (address >= load_end) {
            break;
        }
        rnat = ia64_rse_load_nat_collection(
            env, address, frame_base, load_end, env->rse.bspstore,
            env->rse.bsp, read_register, opaque, &nat_cache);
        env->rse.stacked_gr[slot] = read_register(env, address, opaque);
        ia64_rse_load_register_nat(env, slot, address, rnat);
        filled++;
        address += 8;
    }

    if (filled == 0) {
        return 0;
    }

    env->rse.bspstore = frame_base;
    env->rse.bsp_load = frame_base;
    env->rse.clean_count = MIN(env->rse.clean_count,
                               env->rse.current_frame_base);
    ia64_rse_sync_ar(env);
    return filled;
}

void ia64_rse_reconstruct_transients(CPUIA64State *env)
{
    uint32_t dirty;

    if (!env) {
        return;
    }
    if (env->rse.bspstore == 0) {
        env->rse.bsp_load = 0;
        env->rse.clean_count = 0;
        return;
    }
    if (env->rse.bsp_load == 0) {
        env->rse.bsp_load = env->rse.bspstore;
    }

    dirty = ia64_rse_num_regs(env->rse.bspstore, env->rse.bsp);
    env->rse.clean_count = dirty < env->rse.current_frame_base
        ? env->rse.current_frame_base - dirty
        : 0;
}

void ia64_rse_mark_dirty_partition(CPUIA64State *env, uint32_t count)
{
    uint32_t dirty;

    if (!env || count == 0 || env->rse.bspstore == 0) {
        return;
    }

    dirty = ia64_rse_num_regs(env->rse.bspstore, env->rse.bsp);
    if (dirty < count) {
        env->rse.bsp = ia64_rse_skip_regs(env->rse.bspstore, count);
        dirty = count;
    }
    env->rse.clean_count = dirty < env->rse.current_frame_base
        ? env->rse.current_frame_base - dirty
        : 0;
    ia64_rse_sync_ar(env);
}

void ia64_rse_set_dirty_partition(CPUIA64State *env, uint64_t start,
                                  uint64_t end)
{
    uint32_t dirty;

    if (!env || end < start) {
        return;
    }

    env->rse.bspstore = start;
    env->rse.bsp = end;
    env->rse.bsp_load = start;
    dirty = ia64_rse_num_regs(start, end);
    env->rse.clean_count = dirty < env->rse.current_frame_base
        ? env->rse.current_frame_base - dirty
        : 0;
    ia64_rse_sync_ar(env);
}

static void ia64_rse_sync_ar(CPUIA64State *env)
{
    env->ar[IA64_AR_BSP] = env->rse.bsp;
    env->ar[IA64_AR_BSPSTORE] = env->rse.bspstore;
    ia64_rse_sync_rnat(env);
}

static void ia64_rse_preserve_frame(CPUIA64State *env, uint32_t preserved)
{
    if (!env || preserved == 0) {
        return;
    }

    if (env->rse.bsp == 0 && env->rse.bspstore != 0) {
        env->rse.bsp = env->rse.bspstore;
    }
    env->rse.clean_count = MIN(env->rse.clean_count,
                               env->rse.current_frame_base);
    env->rse.bsp = ia64_rse_skip_regs(env->rse.bsp, preserved);
    ia64_rse_sync_ar(env);
}

static void ia64_rse_restore_preserved_frame(CPUIA64State *env,
                                             uint32_t preserved)
{
    if (!env || preserved == 0) {
        return;
    }

    if (env->rse.bsp != 0 || env->rse.bspstore != 0) {
        if (env->rse.bsp == 0) {
            env->rse.bsp = env->rse.bspstore;
        }
        env->rse.bsp = ia64_rse_skip_regs(env->rse.bsp,
                                          -(int64_t)preserved);
        ia64_rse_sync_ar(env);
    }
}

static uint32_t ia64_stacked_gr_slot(CPUIA64State *env, uint32_t reg)
{
    uint32_t offset = reg - IA64_STATIC_GR_COUNT;
    uint32_t rotating_count = env->rse.sor * 8;
    uint32_t slot;

    if (rotating_count != 0 && offset < rotating_count) {
        offset = (offset + env->rse.rrb_gr) % rotating_count;
    }

    slot = env->rse.current_frame_base + offset;
    return ia64_rse_wrap_slot(slot);
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
    return env->rse.stacked_gr[ia64_stacked_gr_slot(env, reg)];
}

static int ia64_alat_find_gr(CPUIA64State *env, uint32_t reg)
{
    uint32_t valid_mask;

    if (!env || reg >= IA64_GR_COUNT) {
        return -1;
    }

    valid_mask = env->alat.valid_mask;
    if (valid_mask == 0) {
        return -1;
    }

    for (unsigned i = 0; i < IA64_ALAT_COUNT; i++) {
        if ((valid_mask & (1u << i)) != 0 &&
            env->alat.entries[i].target == reg) {
            return i;
        }
    }

    return -1;
}

void ia64_alat_set_valid(CPUIA64State *env, unsigned index, bool valid)
{
    if (!env || index >= IA64_ALAT_COUNT) {
        return;
    }

    env->alat.entries[index].valid = valid;
    if (valid) {
        env->alat.valid_mask |= 1u << index;
    } else {
        env->alat.valid_mask &= ~(1u << index);
    }
}

void ia64_alat_reconstruct_transients(CPUIA64State *env)
{
    uint32_t valid_mask = 0;

    if (!env) {
        return;
    }

    for (unsigned i = 0; i < IA64_ALAT_COUNT; i++) {
        if (env->alat.entries[i].valid) {
            valid_mask |= 1u << i;
        }
    }
    env->alat.valid_mask = valid_mask;
}

static void ia64_alat_invalidate_all(CPUIA64State *env)
{
    uint32_t valid_mask;

    if (!env) {
        return;
    }

    valid_mask = env->alat.valid_mask;
    if (valid_mask == 0) {
        return;
    }

    env->alat.next = 0;
    env->alat.valid_mask = 0;
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

    valid_mask = env->alat.valid_mask;
    if (valid_mask == 0) {
        return;
    }

    for (unsigned i = 0; i < IA64_ALAT_COUNT; i++) {
        if ((valid_mask & (1u << i)) != 0 &&
            env->alat.entries[i].target == reg) {
            ia64_alat_set_valid(env, i, false);
        }
    }
}

void ia64_alat_record_gr(CPUIA64State *env, uint32_t target,
                         uint64_t address, uint8_t width, bool physical)
{
    IA64AlatEntry *entry;
    unsigned index;

    if (!env || target == 0 || target >= IA64_GR_COUNT || width == 0) {
        return;
    }

    ia64_alat_invalidate_gr(env, target);
    index = env->alat.next % IA64_ALAT_COUNT;
    entry = &env->alat.entries[index];
    env->alat.next = (env->alat.next + 1) % IA64_ALAT_COUNT;

    memset(entry, 0, sizeof(*entry));
    entry->target = target;
    entry->width = width;
    entry->physical = physical;
    entry->address = address;
    ia64_alat_set_valid(env, index, true);
}

bool ia64_alat_check_gr(CPUIA64State *env, uint32_t reg, uint64_t address,
                        uint8_t width, bool physical, bool clear)
{
    uint32_t valid_mask;

    if (!env || reg >= IA64_GR_COUNT || width == 0) {
        return false;
    }

    valid_mask = env->alat.valid_mask;
    if (valid_mask == 0) {
        return false;
    }

    for (unsigned i = 0; i < IA64_ALAT_COUNT; i++) {
        IA64AlatEntry *entry = &env->alat.entries[i];

        if ((valid_mask & (1u << i)) == 0 || entry->target != reg) {
            continue;
        }

        if (clear) {
            ia64_alat_set_valid(env, i, false);
        }
        return entry->physical == physical && entry->width == width &&
               entry->address == address;
    }

    return false;
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
        uint32_t slot = ia64_stacked_gr_slot(env, reg);

        env->rse.stacked_gr[slot] = value;
        env->rse.clean_count = MIN(env->rse.clean_count, slot);
    }
    ia64_write_gr_nat(env, reg, false);
    ia64_alat_invalidate_gr(env, reg);
    env->gr[0] = 0;
}

void ia64_ldst_apply_base_update(CPUIA64State *env,
                                 const IA64LdstImmediate *decoded,
                                 uint64_t address)
{
    uint64_t update;

    if (!env || !decoded || !decoded->base_update) {
        return;
    }

    if (decoded->update_from_register &&
        ia64_read_gr_nat(env, decoded->update_source)) {
        ia64_write_gr_nat(env, decoded->base, true);
        return;
    }

    update = decoded->update_from_register
        ? ia64_read_gr(env, decoded->update_source)
        : (uint64_t)decoded->immediate;
    ia64_write_gr(env, decoded->base, address + update);
}

static uint32_t ia64_map_pr(CPUIA64State *env, uint32_t predicate)
{
    if (predicate < 16) {
        return predicate;
    }
    return 16 + ((predicate - 16 + env->rse.rrb_pr) % 48);
}

bool ia64_read_pr(CPUIA64State *env, uint32_t predicate)
{
    if (!env || predicate >= 64) {
        return false;
    }
    return predicate == 0 ||
           (env->pr & (1ULL << ia64_map_pr(env, predicate))) != 0;
}

void ia64_write_pr(CPUIA64State *env, uint32_t predicate, bool value)
{
    uint32_t mapped;

    if (!env || predicate >= 64) {
        return;
    }
    if (predicate == 0) {
        env->pr |= 1;
        return;
    }

    mapped = ia64_map_pr(env, predicate);
    if (value) {
        env->pr |= 1ULL << mapped;
    } else {
        env->pr &= ~(1ULL << mapped);
    }
    env->pr |= 1;
}

static int64_t ia64_sign_extend(uint64_t value, unsigned bits);

static void ia64_rse_invalidate(CPUIA64State *env, uint32_t first,
                                uint32_t last)
{
    uint32_t count;
    uint32_t tail_count;

    if (last < first) {
        last += IA64_STACKED_GR_COUNT;
    }
    count = MIN(last - first, (uint32_t)IA64_STACKED_GR_COUNT);
    if (count == 0) {
        return;
    }
    if (count == IA64_STACKED_GR_COUNT) {
        memset(env->rse.stacked_gr, 0, sizeof(env->rse.stacked_gr));
        env->nat.gr_nat[0] &= (UINT64_C(1) << IA64_STATIC_GR_COUNT) - 1;
        memset(env->rse.stacked_nat, 0, sizeof(env->rse.stacked_nat));
        return;
    }

    first = ia64_rse_wrap_slot(first);
    tail_count = MIN(count, (uint32_t)IA64_STACKED_GR_COUNT - first);
    memset(&env->rse.stacked_gr[first], 0,
           tail_count * sizeof(env->rse.stacked_gr[0]));
    for (uint32_t i = 0; i < tail_count; i++) {
        ia64_rse_write_physical_nat(env, first + i, false);
    }
    if (tail_count < count) {
        memset(env->rse.stacked_gr, 0,
               (count - tail_count) * sizeof(env->rse.stacked_gr[0]));
        for (uint32_t i = 0; i < count - tail_count; i++) {
            ia64_rse_write_physical_nat(env, i, false);
        }
    }
}

static uint32_t ia64_map_fr(CPUIA64State *env, uint32_t reg)
{
    if (reg < 32) {
        return reg;
    }
    return 32 + ((reg - 32 + env->rse.rrb_fr) % (IA64_FR_COUNT - 32));
}

void ia64_note_fr_write(CPUIA64State *env, uint32_t reg)
{
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
           ia64_fr_exponent(reg) == IA64_FR_SPECIAL_EXPONENT;
}

void ia64_float_reg_to_spill(const IA64FloatReg *reg,
                             uint64_t *sign_exponent,
                             uint64_t *mantissa)
{
    uint64_t sign = reg->raw[1] & (UINT64_C(1) << 17);

    if (ia64_fr_is_zero(reg)) {
        *sign_exponent = sign;
        *mantissa = 0;
        return;
    }

    *sign_exponent = reg->raw[1] & 0x3ffff;
    *mantissa = reg->raw[0];
}

void ia64_float_reg_from_spill(uint64_t sign_exponent, uint64_t mantissa,
                               IA64FloatReg *reg)
{
    sign_exponent &= 0x3ffff;
    if ((sign_exponent & 0x1ffff) == 0 && mantissa == 0) {
        reg->raw[0] = 0;
        reg->raw[1] = (sign_exponent & (UINT64_C(1) << 17)) |
                      IA64_FR_SPECIAL_EXPONENT;
        return;
    }

    reg->raw[0] = mantissa;
    reg->raw[1] = sign_exponent;
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

static bool ia64_fr_is_unnormalized(const IA64FloatReg *reg)
{
    return !ia64_fr_is_natval(reg) &&
           !ia64_fr_is_zero(reg) &&
           !ia64_fr_is_infinity(reg) &&
           !ia64_fr_is_qnan(reg) &&
           !ia64_fr_is_snan(reg) &&
           !ia64_fr_is_unsupported_special(reg) &&
           reg->raw[0] != 0 &&
           (reg->raw[0] & IA64_FR_INTEGER_BIT) == 0;
}

static bool ia64_fr_is_normalized(const IA64FloatReg *reg)
{
    return !ia64_fr_is_natval(reg) &&
           !ia64_fr_is_zero(reg) &&
           !ia64_fr_is_infinity(reg) &&
           !ia64_fr_is_qnan(reg) &&
           !ia64_fr_is_snan(reg) &&
           !ia64_fr_is_unsupported_special(reg) &&
           (reg->raw[0] & IA64_FR_INTEGER_BIT) != 0;
}

static bool ia64_fr_is_finite_nonzero(const IA64FloatReg *reg)
{
    return !ia64_fr_is_natval(reg) && !ia64_fr_is_zero(reg) &&
           !ia64_fr_is_infinity(reg) && !ia64_fr_is_nan(reg) &&
           reg->raw[0] != 0;
}

static bool ia64_fpu_trace_enabled(CPUIA64State *env)
{
    static int initialized;
    static bool enabled;
    static bool filtered;
    static uint64_t filter_start;
    static uint64_t filter_end;

    if (!initialized) {
        const char *trace = g_getenv("VIBTANIUM_FPU_TRACE");
        const char *addr = g_getenv("VIBTANIUM_FPU_TRACE_IP");
        const char *size = g_getenv("VIBTANIUM_FPU_TRACE_SIZE");

        enabled = trace != NULL && *trace != '\0';
        if (enabled && addr != NULL && *addr != '\0') {
            char *endptr = NULL;
            uint64_t parsed_size = IA64_BUNDLE_SIZE;

            filter_start = g_ascii_strtoull(addr, &endptr, 0);
            filtered = endptr != addr;
            if (size != NULL && *size != '\0') {
                endptr = NULL;
                parsed_size = g_ascii_strtoull(size, &endptr, 0);
                if (endptr == size || parsed_size == 0) {
                    parsed_size = IA64_BUNDLE_SIZE;
                }
            }
            filter_end = filter_start + parsed_size - 1;
        }
        initialized = 1;
    }

    return enabled && (!filtered ||
                       (env->ip >= filter_start && env->ip <= filter_end));
}

static void ia64_fpu_trace_fr(const char *tag, CPUIA64State *env,
                              uint64_t raw, uint32_t freg)
{
    const IA64FloatReg *reg = &env->fr[ia64_map_fr(env, freg)];

    fprintf(stderr,
            "[ia64-fpu] %s ip=0x%016" PRIx64
            " raw=0x%011" PRIx64 " f%u={raw0=0x%016" PRIx64
            " raw1=0x%016" PRIx64 "}\n",
            tag, env->ip, raw, freg, reg->raw[0], reg->raw[1]);
}

static void ia64_float_status_init(float_status *status)
{
    set_float_rounding_mode(float_round_nearest_even, status);
    set_float_2nan_prop_rule(float_2nan_prop_x87, status);
    set_float_default_nan_pattern(0b01000000, status);
    set_floatx80_rounding_precision(floatx80_precision_x, status);
}

static FloatRoundMode ia64_fpsr_rounding_mode(CPUIA64State *env, uint8_t sf)
{
    uint64_t field = (env->ar[IA64_AR_FPSR] >>
                      IA64_FPSR_STATUS_FIELD_SHIFT(sf & 0x3)) &
                     IA64_FPSR_STATUS_FIELD_MASK;

    switch ((field >> IA64_FPSR_STATUS_RC_SHIFT) &
            IA64_FPSR_STATUS_RC_MASK) {
    case 0:
        return float_round_nearest_even;
    case 1:
        return float_round_down;
    case 2:
        return float_round_up;
    case 3:
        return float_round_to_zero;
    default:
        g_assert_not_reached();
    }
}

static void ia64_float_status_init_for_sf(CPUIA64State *env,
                                          float_status *status,
                                          uint8_t sf)
{
    ia64_float_status_init(status);
    set_float_rounding_mode(ia64_fpsr_rounding_mode(env, sf), status);
}

static floatx80 ia64_fr_to_floatx80(const IA64FloatReg *reg)
{
    bool sign = ia64_fr_sign(reg);
    int32_t exponent = ia64_fr_exponent(reg);
    uint64_t significand = reg->raw[0];
    int32_t soft_exponent;
    uint16_t soft_sign = sign ? 0x8000 : 0;

    if (ia64_fr_is_natval(reg) || ia64_fr_is_nan(reg)) {
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

static void ia64_write_fr_from_floatx80(CPUIA64State *env, uint32_t reg,
                                        floatx80 value)
{
    bool sign = (value.high & 0x8000) != 0;
    uint32_t exponent = value.high & 0x7fff;

    if (!env || reg >= IA64_FR_COUNT || reg < 2) {
        return;
    }

    if (exponent == 0x7fff) {
        ia64_write_fr_parts(env, reg, sign, IA64_FR_SPECIAL_EXPONENT,
                            value.low);
        return;
    }
    if (exponent == 0 || value.low == 0) {
        ia64_write_fr_parts(env, reg, sign, IA64_FR_SPECIAL_EXPONENT, 0);
        return;
    }

    ia64_write_fr_parts(env, reg, sign,
                        exponent - 0x3fff + IA64_FR_EXPONENT_BIAS,
                        value.low);
}

static uint64_t ia64_read_fr_significand(CPUIA64State *env, uint32_t reg)
{
    if (!env || reg >= IA64_FR_COUNT) {
        return 0;
    }
    return env->fr[ia64_map_fr(env, reg)].raw[0];
}

static void ia64_write_fr_significand(CPUIA64State *env, uint32_t reg,
                                      uint64_t value)
{
    ia64_write_fr_parts(env, reg, false, IA64_FR_INTEGER_EXPONENT, value);
}

void ia64_write_fr_natval(CPUIA64State *env, uint32_t reg)
{
    ia64_write_fr_parts(env, reg, false, IA64_FR_NATVAL_EXPONENT, 0);
}

static uint32_t ia64_float_packed_high32(uint64_t value)
{
    return value >> 32;
}

static uint32_t ia64_float_packed_low32(uint64_t value)
{
    return value;
}

static uint64_t ia64_float_packed_pair(uint32_t high, uint32_t low)
{
    return ((uint64_t)high << 32) | low;
}

static uint32_t ia64_float_packed_negate_single(uint32_t value)
{
    return value ^ UINT32_C(0x80000000);
}

static uint32_t ia64_float_packed_extend_single_sign(uint32_t value)
{
    return (value & UINT32_C(0x80000000)) != 0 ? UINT32_MAX : 0;
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
            ia64_write_fr_parts(env, reg, sign, IA64_FR_SPECIAL_EXPONENT, 0);
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

static uint64_t ia64_round_shift_right_u64(uint64_t value, unsigned shift,
                                           bool truncate)
{
    uint64_t quotient;
    uint64_t remainder;
    uint64_t half;

    if (shift == 0) {
        return value;
    }
    if (shift >= 65) {
        return 0;
    }
    if (shift == 64) {
        quotient = 0;
        if (truncate || value < IA64_FR_INTEGER_BIT) {
            return 0;
        }
        return value > IA64_FR_INTEGER_BIT ? 1 : 0;
    }

    quotient = value >> shift;
    if (truncate) {
        return quotient;
    }

    remainder = value & ((UINT64_C(1) << shift) - 1);
    half = UINT64_C(1) << (shift - 1);
    if (remainder > half || (remainder == half && (quotient & 1) != 0)) {
        quotient++;
    }
    return quotient;
}

static uint64_t ia64_float_reg_to_fixed(const IA64FloatReg *reg,
                                        bool unsigned_form, bool truncate)
{
    uint32_t exponent;
    uint64_t magnitude;
    int shift;

    if (ia64_fr_is_natval(reg) || ia64_fr_is_nan(reg) ||
        ia64_fr_is_infinity(reg)) {
        return IA64_FR_INTEGER_BIT;
    }
    if (ia64_fr_is_zero(reg) || reg->raw[0] == 0) {
        return 0;
    }
    if (unsigned_form && ia64_fr_sign(reg)) {
        return IA64_FR_INTEGER_BIT;
    }

    exponent = ia64_fr_exponent(reg);
    shift = (int)exponent - IA64_FR_EXPONENT_BIAS - 63;
    if (shift >= 0) {
        unsigned __int128 widened;

        if (shift >= 64) {
            return IA64_FR_INTEGER_BIT;
        }
        widened = (unsigned __int128)reg->raw[0] << shift;
        if (widened > UINT64_MAX) {
            return IA64_FR_INTEGER_BIT;
        }
        magnitude = (uint64_t)widened;
    } else {
        magnitude = ia64_round_shift_right_u64(reg->raw[0], -shift,
                                               truncate);
    }

    if (unsigned_form) {
        return magnitude;
    }
    if (ia64_fr_sign(reg)) {
        if (magnitude > IA64_FR_INTEGER_BIT) {
            return IA64_FR_INTEGER_BIT;
        }
        return 0 - magnitude;
    }
    if (magnitude >= IA64_FR_INTEGER_BIT) {
        return IA64_FR_INTEGER_BIT;
    }
    return magnitude;
}

bool ia64_slot_is_m34_alloc(IA64SlotType type, uint64_t raw)
{
    uint8_t x3;

    if (type != IA64_SLOT_TYPE_M || ia64_slot_major_opcode(raw) != 0x1) {
        return false;
    }

    x3 = (raw >> 33) & 0x7;
    return x3 == 6;
}

bool ia64_exec_m34_alloc(CPUIA64State *env, uint64_t raw)
{
    uint32_t r1;
    uint32_t sof;
    uint32_t sol;
    uint32_t sor;
    uint64_t old_cfm;
    uint64_t old_pfs;

    if (!env || !ia64_slot_is_m34_alloc(IA64_SLOT_TYPE_M, raw)) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    sof = (raw >> 13) & 0x7f;
    sol = (raw >> 20) & 0x7f;
    sor = (raw >> 27) & 0x0f;
    old_cfm = env->cfm;
    old_pfs = env->ar[IA64_AR_PFS];

    if (sof < (old_cfm & 0x7f)) {
        ia64_rse_invalidate(env, env->rse.current_frame_base + sof,
                            env->rse.current_frame_base + (old_cfm & 0x7f));
    }
    ia64_set_cfm(env, ia64_make_cfm(sof, sol, sor));
    ia64_write_gr(env, r1, old_pfs);
    return true;
}

static bool ia64_slot_is_i_misc_x6(IA64SlotType type, uint64_t raw,
                                   uint8_t x6)
{
    if (type != IA64_SLOT_TYPE_I || ia64_slot_major_opcode(raw) != 0x0) {
        return false;
    }
    if (((raw >> 33) & 0x7) != 0) {
        return false;
    }
    return ((raw >> 27) & 0x3f) == x6;
}

static bool ia64_slot_is_m_system_x6(IA64SlotType type, uint64_t raw,
                                     uint8_t x6)
{
    if (type != IA64_SLOT_TYPE_M || ia64_slot_major_opcode(raw) != 0x1) {
        return false;
    }
    if (((raw >> 33) & 0x7) != 0) {
        return false;
    }
    return ((raw >> 27) & 0x3f) == x6;
}

static uint64_t ia64_read_ar(CPUIA64State *env, uint32_t reg)
{
    if (!env || reg >= IA64_AR_COUNT) {
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

static void ia64_trace_branch_return(CPUIA64State *env, const char *op,
                                     uint32_t reg, uint64_t target,
                                     uint64_t bundle_ip)
{
    int filter;

    if (!env || reg >= IA64_BR_COUNT || !ia64_branch_trace_enabled()) {
        return;
    }

    filter = ia64_branch_trace_filter();
    if (filter >= 0 && reg != (uint32_t)filter) {
        return;
    }
    if (!ia64_branch_trace_target_matches(target)) {
        return;
    }

    fprintf(stderr,
            "[ia64-br] ip=0x%016" PRIx64 " ri=%u %s b%u"
            " target=0x%016" PRIx64 " aux=0x%016" PRIx64
            " cfm=0x%016" PRIx64 " pfs=0x%016" PRIx64
            " bsp=0x%016" PRIx64 " bspstore=0x%016" PRIx64 "\n",
            env->ip, ia64_env_ri(env), op, reg, target, bundle_ip,
            env->cfm, env->ar[IA64_AR_PFS], env->rse.bsp,
            env->rse.bspstore);
}

static void ia64_write_ar(CPUIA64State *env, uint32_t reg, uint64_t value)
{
    if (!env || reg >= IA64_AR_COUNT) {
        return;
    }

    if (ia64_ar_trace_enabled() &&
        (reg == IA64_AR_LC || reg == IA64_AR_EC)) {
        fprintf(stderr, "[ia64-ar] ar[%u] <= 0x%016" PRIx64 "\n",
                reg, value);
    }

    switch (reg) {
    case IA64_AR_ITC:
        ia64_itc_set(env, value);
        env->interrupt.timer_compare_latched = 0;
        ia64_itc_timer_update(env);
        break;
    case IA64_AR_RSC:
        env->ar[reg] = value;
        env->rse.rsc = value;
        env->rse.loadrs = (value >> 16) & 0x3fff;
        break;
    case IA64_AR_BSP:
        env->ar[reg] = value;
        env->rse.bsp = value;
        break;
    case IA64_AR_BSPSTORE:
    {
        uint32_t dirty = ia64_rse_num_regs(env->rse.bspstore, env->rse.bsp);

        env->rse.bspstore = value & ~7ULL;
        env->rse.bsp_load = env->rse.bspstore;
        env->rse.bsp = ia64_rse_skip_regs(env->rse.bspstore, dirty);
        env->rse.clean_count = dirty == 0
            ? MIN(env->rse.clean_count, env->rse.current_frame_base)
            : 0;
        ia64_rse_clear_rnat(env);
        ia64_rse_sync_ar(env);
        break;
    }
    case IA64_AR_RNAT:
        ia64_rse_write_rnat(env, value);
        break;
    case IA64_AR_UNAT:
        env->ar[reg] = value;
        env->nat.unat = value;
        break;
    default:
        env->ar[reg] = value;
        break;
    }
}

bool ia64_slot_is_nop_or_hint(IA64SlotType type, uint64_t raw)
{
    uint8_t major = ia64_slot_major_opcode(raw);

    switch (type) {
    case IA64_SLOT_TYPE_I:
        return major == 0 && ((raw >> 33) & 0x7) == 0 &&
               ((raw >> 27) & 0x3f) == 1;
    case IA64_SLOT_TYPE_M:
        return major == 0 && ((raw >> 33) & 0x7) == 0 &&
               ((raw >> 31) & 0x3) == 0 &&
               ((raw >> 27) & 0xf) == 1;
    case IA64_SLOT_TYPE_F:
        return major == 0 && ((raw >> 33) & 0x1) == 0 &&
               ((raw >> 27) & 0x3f) == 1;
    case IA64_SLOT_TYPE_B:
        return major == 2 && ((raw >> 27) & 0x3f) <= 1;
    default:
        return false;
    }
}

bool ia64_slot_is_i_nop(IA64SlotType type, uint64_t raw)
{
    uint8_t y = (raw >> 26) & 0x1;

    return type == IA64_SLOT_TYPE_I &&
           ia64_slot_is_nop_or_hint(type, raw) && y == 0;
}

bool ia64_slot_is_i_break(IA64SlotType type, uint64_t raw)
{
    uint8_t y = (raw >> 26) & 0x1;

    return ia64_slot_is_i_misc_x6(type, raw, 0x0) && y == 0;
}

uint64_t ia64_i_break_immediate(uint64_t raw)
{
    return (((raw >> 36) & 0x1) << 20) | ((raw >> 6) & 0xfffff);
}

bool ia64_slot_is_i_mov_ip(IA64SlotType type, uint64_t raw)
{
    return ia64_slot_is_i_misc_x6(type, raw, 0x30);
}

bool ia64_exec_i_mov_ip(CPUIA64State *env, uint64_t raw, uint64_t bundle_ip)
{
    uint32_t r1;

    if (!env || !ia64_slot_is_i_mov_ip(IA64_SLOT_TYPE_I, raw)) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    ia64_write_gr(env, r1, bundle_ip);
    return true;
}

bool ia64_slot_is_i_mov_from_branch(IA64SlotType type, uint64_t raw)
{
    return ia64_slot_is_i_misc_x6(type, raw, 0x31);
}

bool ia64_exec_i_mov_from_branch(CPUIA64State *env, uint64_t raw)
{
    uint32_t r1;
    uint32_t b2;

    if (!env || !ia64_slot_is_i_mov_from_branch(IA64_SLOT_TYPE_I, raw)) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    b2 = (raw >> 13) & 0x7;
    ia64_write_gr(env, r1, env->br[b2]);
    return true;
}

bool ia64_slot_is_i_mov_to_branch(IA64SlotType type, uint64_t raw)
{
    return type == IA64_SLOT_TYPE_I && ia64_slot_major_opcode(raw) == 0x0 &&
           ((raw >> 33) & 0x7) == 7;
}

bool ia64_exec_i_mov_to_branch(CPUIA64State *env, uint64_t raw)
{
    uint32_t b1;
    uint32_t r2;

    if (!env || !ia64_slot_is_i_mov_to_branch(IA64_SLOT_TYPE_I, raw)) {
        return false;
    }

    b1 = (raw >> 6) & 0x7;
    r2 = (raw >> 13) & 0x7f;
    ia64_trace_branch_write(env, "mov-to-branch", b1,
                            ia64_read_gr(env, r2), r2);
    env->br[b1] = ia64_read_gr(env, r2);
    return true;
}

bool ia64_slot_is_i_mov_from_predicate(IA64SlotType type, uint64_t raw)
{
    return ia64_slot_is_i_misc_x6(type, raw, 0x33);
}

bool ia64_exec_i_mov_from_predicate(CPUIA64State *env, uint64_t raw)
{
    uint32_t r1;

    if (!env || !ia64_slot_is_i_mov_from_predicate(IA64_SLOT_TYPE_I, raw)) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    ia64_write_gr(env, r1, env->pr | 1);
    return true;
}

bool ia64_slot_is_i_mov_to_predicate(IA64SlotType type, uint64_t raw)
{
    return type == IA64_SLOT_TYPE_I && ia64_slot_major_opcode(raw) == 0x0 &&
           ((raw >> 33) & 0x7) == 3;
}

bool ia64_exec_i_mov_to_predicate(CPUIA64State *env, uint64_t raw)
{
    uint32_t r2;
    uint64_t value;
    uint64_t encoded_mask;
    uint64_t write_mask;

    if (!env || !ia64_slot_is_i_mov_to_predicate(IA64_SLOT_TYPE_I, raw)) {
        return false;
    }

    r2 = (raw >> 13) & 0x7f;
    value = ia64_read_gr(env, r2);
    encoded_mask = (((raw >> 36) & 0x1) << 16) |
                   (((raw >> 24) & 0xff) << 8) |
                   (((raw >> 6) & 0x7f) << 1);
    write_mask = (uint64_t)ia64_sign_extend(encoded_mask, 17);
    if (ia64_ar_trace_enabled()) {
        fprintf(stderr,
                "[ia64-pr] ip=0x%016" PRIx64
                " value=0x%016" PRIx64 " mask=0x%016" PRIx64 "\n",
                env->ip, value, write_mask);
    }
    env->pr = (env->pr & ~write_mask) | (value & write_mask) | 1;
    return true;
}

bool ia64_slot_is_i_mov_to_rotating_predicate_immediate(IA64SlotType type,
                                                        uint64_t raw)
{
    return type == IA64_SLOT_TYPE_I && ia64_slot_major_opcode(raw) == 0x0 &&
           ((raw >> 33) & 0x7) == 2;
}

bool ia64_exec_i_mov_to_rotating_predicate_immediate(CPUIA64State *env,
                                                     uint64_t raw)
{
    uint64_t imm44;

    if (!env ||
        !ia64_slot_is_i_mov_to_rotating_predicate_immediate(IA64_SLOT_TYPE_I,
                                                            raw)) {
        return false;
    }

    imm44 = (((raw >> 36) & 0x1) << 43) | (((raw >> 6) & 0x7ffffff) << 16);
    env->pr = (env->pr & ((1ULL << 16) - 1)) |
              ((uint64_t)ia64_sign_extend(imm44, 44) &
               ~((1ULL << 16) - 1)) | 1;
    return true;
}

bool ia64_slot_is_mov_to_application(IA64SlotType type, uint64_t raw)
{
    return ia64_slot_is_i_misc_x6(type, raw, 0x2a) ||
           ia64_slot_is_m_system_x6(type, raw, 0x2a);
}

bool ia64_exec_mov_to_application(CPUIA64State *env, IA64SlotType type,
                                  uint64_t raw)
{
    uint32_t ar3;
    uint32_t r2;

    if (!env || !ia64_slot_is_mov_to_application(type, raw)) {
        return false;
    }

    ar3 = (raw >> 20) & 0x7f;
    r2 = (raw >> 13) & 0x7f;
    if (ia64_ar_trace_enabled() &&
        (ar3 == IA64_AR_LC || ar3 == IA64_AR_EC)) {
        fprintf(stderr,
                "[ia64-ar-mov] ip=0x%016" PRIx64
                " ar[%u] <= r%u=0x%016" PRIx64 "\n",
                env->ip, ar3, r2, ia64_read_gr(env, r2));
    }
    ia64_write_ar(env, ar3, ia64_read_gr(env, r2));
    return true;
}

bool ia64_slot_is_mov_from_application(IA64SlotType type, uint64_t raw)
{
    return ia64_slot_is_i_misc_x6(type, raw, 0x32) ||
           ia64_slot_is_m_system_x6(type, raw, 0x22);
}

bool ia64_exec_mov_from_application(CPUIA64State *env, IA64SlotType type,
                                    uint64_t raw)
{
    uint32_t r1;
    uint32_t ar3;

    if (!env || !ia64_slot_is_mov_from_application(type, raw)) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    ar3 = (raw >> 20) & 0x7f;
    ia64_write_gr(env, r1, ia64_read_ar(env, ar3));
    return true;
}

bool ia64_slot_is_i_mov_to_application_immediate(IA64SlotType type,
                                                 uint64_t raw)
{
    return ia64_slot_is_i_misc_x6(type, raw, 0x0a);
}

bool ia64_slot_is_mov_to_application_immediate(IA64SlotType type,
                                               uint64_t raw)
{
    if (ia64_slot_is_i_mov_to_application_immediate(type, raw)) {
        return true;
    }

    return type == IA64_SLOT_TYPE_M &&
           ia64_slot_major_opcode(raw) == 0x0 &&
           ((raw >> 33) & 0x7) == 0 &&
           ((raw >> 31) & 0x3) == 2 &&
           ((raw >> 27) & 0xf) == 8;
}

bool ia64_exec_mov_to_application_immediate(CPUIA64State *env,
                                            IA64SlotType type,
                                            uint64_t raw)
{
    uint32_t ar3;
    int64_t imm8;

    if (!env || !ia64_slot_is_mov_to_application_immediate(type, raw)) {
        return false;
    }

    ar3 = (raw >> 20) & 0x7f;
    imm8 = ia64_sign_extend((((raw >> 36) & 0x1) << 7) |
                            ((raw >> 13) & 0x7f), 8);
    if (ia64_ar_trace_enabled() &&
        (ar3 == IA64_AR_LC || ar3 == IA64_AR_EC)) {
        fprintf(stderr,
                "[ia64-ar-mov] ip=0x%016" PRIx64
                " ar[%u] <= imm=0x%016" PRIx64 "\n",
                env->ip, ar3, (uint64_t)imm8);
    }
    ia64_write_ar(env, ar3, imm8);
    return true;
}

bool ia64_exec_i_mov_to_application_immediate(CPUIA64State *env,
                                              uint64_t raw)
{
    if (!env ||
        !ia64_slot_is_i_mov_to_application_immediate(IA64_SLOT_TYPE_I, raw)) {
        return false;
    }

    return ia64_exec_mov_to_application_immediate(env, IA64_SLOT_TYPE_I, raw);
}

bool ia64_slot_is_check_speculative(IA64SlotType type, uint64_t raw)
{
    uint8_t major = ia64_slot_major_opcode(raw);
    uint8_t x3 = (raw >> 33) & 0x7;

    if (type == IA64_SLOT_TYPE_I) {
        return major == 0x0 && x3 == 1;
    }

    if (type == IA64_SLOT_TYPE_M) {
        return major == 0x1 && (x3 == 1 || x3 == 3);
    }

    return false;
}

int64_t ia64_check_speculative_displacement(uint64_t raw)
{
    uint64_t encoded = (((raw >> 36) & 0x1) << 20) |
                       (((raw >> 20) & 0x1fff) << 7) |
                       ((raw >> 6) & 0x7f);

    return ia64_sign_extend(encoded, 21) << 4;
}

bool ia64_exec_check_speculative(CPUIA64State *env, IA64SlotType type,
                                 uint64_t raw, uint64_t bundle_ip,
                                 uint64_t *target_ip)
{
    uint8_t source;
    bool deferred;

    if (!env || !target_ip || !ia64_slot_is_check_speculative(type, raw)) {
        return false;
    }

    source = (raw >> 13) & 0x7f;
    if (type == IA64_SLOT_TYPE_M && ((raw >> 33) & 0x7) == 3) {
        deferred = ia64_fr_is_natval(&env->fr[ia64_map_fr(env, source)]);
    } else {
        deferred = ia64_read_gr_nat(env, source);
    }

    *target_ip = deferred
        ? bundle_ip + ia64_check_speculative_displacement(raw)
        : bundle_ip + IA64_BUNDLE_SIZE;
    return true;
}

bool ia64_slot_is_m_check_advanced(IA64SlotType type, uint64_t raw)
{
    uint8_t x3;

    if (type != IA64_SLOT_TYPE_M || ia64_slot_major_opcode(raw) != 0x0) {
        return false;
    }

    x3 = (raw >> 33) & 0x7;
    /*
     * Opcode 0 x3 (Table 4-42): 4=chk.a.nc int (M22), 5=chk.a.clr int (M22),
     * 6=chk.a.nc fp (M23), 7=chk.a.clr fp (M23).  All four share the same
     * imm20b/target25 branch layout and are handled together below.
     */
    return x3 >= 4 && x3 <= 7;
}

bool ia64_exec_m_check_advanced(CPUIA64State *env, uint64_t raw,
                                uint64_t bundle_ip, uint64_t *target_ip)
{
    uint8_t target;
    uint8_t x3;
    bool fp_form;
    bool clear;
    int alat_index;

    if (!env || !target_ip ||
        !ia64_slot_is_m_check_advanced(IA64_SLOT_TYPE_M, raw)) {
        return false;
    }

    x3 = (raw >> 33) & 0x7;
    fp_form = x3 >= 6;          /* 6/7 = chk.a fp (M23); 4/5 = chk.a int (M22) */
    clear = (x3 & 0x1) != 0;    /* odd x3 is the .clr variant */

    if (fp_form) {
        /*
         * Floating-point advanced loads (ldf.a/ldf.sa) are not tracked in the
         * ALAT model: the FP load classes and ldf.c always reperform the
         * access, so the FR half of the ALAT is permanently empty.  A missing
         * ALAT entry requires chk.a to branch to the compiler-provided
         * recovery code, which reloads the value.  This is architecturally
         * valid (the ALAT may drop entries at any time) and, crucially, avoids
         * aliasing an FR check against a same-numbered GR entry.
         */
        *target_ip = bundle_ip + ia64_branch_displacement(raw);
        return true;
    }

    target = (raw >> 6) & 0x7f;
    alat_index = ia64_alat_find_gr(env, target);
    if (alat_index >= 0) {
        if (clear) {
            ia64_alat_set_valid(env, alat_index, false);
        }
        *target_ip = bundle_ip + IA64_BUNDLE_SIZE;
    } else {
        *target_ip = bundle_ip + ia64_branch_displacement(raw);
    }
    return true;
}

bool ia64_slot_is_m_processor_mask(IA64SlotType type, uint64_t raw)
{
    uint8_t x4;

    if (type != IA64_SLOT_TYPE_M || ia64_slot_major_opcode(raw) != 0x0 ||
        ((raw >> 33) & 0x7) != 0) {
        return false;
    }

    x4 = (raw >> 27) & 0xf;
    return x4 >= 4 && x4 <= 7;
}

static bool ia64_psr_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_PSR_TRACE") != NULL;
    }
    return enabled != 0;
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
            " pending=%u active=%" PRIu64 " vector=0x%016" PRIx64 "\n",
            env->ip, op, reg, ia64_cr_trace_name(reg), old_value, new_value,
            ia64_env_psr(env), env->cr[IA64_CR_TPR], env->cr[IA64_CR_IVR],
            env->cr[IA64_CR_IRR3], env->interrupt.pending,
            env->interrupt.pending_interruption,
            env->interrupt.pending_vector);
}

uint64_t ia64_processor_mask_immediate(uint64_t raw)
{
    return (((raw >> 36) & 0x1) << 23) |
           (((raw >> 31) & 0x3) << 21) |
           ((raw >> 6) & 0x1fffff);
}

bool ia64_exec_m_processor_mask(CPUIA64State *env, uint64_t raw)
{
    uint8_t x4;
    uint64_t mask;
    uint64_t old_psr;

    if (!env || !ia64_slot_is_m_processor_mask(IA64_SLOT_TYPE_M, raw)) {
        return false;
    }

    x4 = (raw >> 27) & 0xf;
    mask = ia64_processor_mask_immediate(raw);
    mask &= x4 == 4 || x4 == 5 ? UINT64_C(0x3f) : UINT64_C(0x00ffffff);
    old_psr = ia64_env_psr(env);
    if (x4 == 4 || x4 == 6) {
        ia64_env_set_psr(env, old_psr | mask);
    } else {
        ia64_env_set_psr(env, old_psr & ~mask);
    }
    trace_ia64_processor_mask(env->ip, x4 == 4 || x4 == 6 ? "ssm" : "rsm",
                              mask, old_psr, ia64_env_psr(env));
    if (ia64_psr_trace_enabled()) {
        fprintf(stderr,
                "[ia64-psr-mask] ip=0x%016" PRIx64 " op=%s"
                " mask=0x%016" PRIx64 " old=0x%016" PRIx64
                " new=0x%016" PRIx64 "\n",
                env->ip, x4 == 4 || x4 == 6 ? "ssm" : "rsm",
                mask, old_psr, ia64_env_psr(env));
    }
    return true;
}

#define IA64_PSR_USER_MASK UINT64_C(0x000000000000003f)
#define IA64_PSR_LOWER_MASK UINT64_C(0x00000000ffffffff)
#define IA64_PSR_MC_BIT UINT64_C(0x0000000800000000)
#define IA64_PSR_IT_BIT UINT64_C(0x0000001000000000)

bool ia64_slot_is_m_mov_from_processor_status(IA64SlotType type,
                                              uint64_t raw)
{
    uint8_t x6;

    if (type != IA64_SLOT_TYPE_M || ia64_slot_major_opcode(raw) != 0x1 ||
        ((raw >> 33) & 0x7) != 0) {
        return false;
    }

    x6 = (raw >> 27) & 0x3f;
    return x6 == 0x21 || x6 == 0x25;
}

bool ia64_exec_m_mov_from_processor_status(CPUIA64State *env, uint64_t raw)
{
    uint8_t x6;
    uint32_t target;
    uint64_t value;

    if (!env ||
        !ia64_slot_is_m_mov_from_processor_status(IA64_SLOT_TYPE_M, raw)) {
        return false;
    }

    x6 = (raw >> 27) & 0x3f;
    target = (raw >> 6) & 0x7f;
    value = ia64_env_psr(env);
    value = x6 == 0x21
                ? (value & IA64_PSR_USER_MASK)
                : ((value & IA64_PSR_LOWER_MASK) |
                   (value & (IA64_PSR_MC_BIT | IA64_PSR_IT_BIT)));
    ia64_write_gr(env, target, value);
    return true;
}

bool ia64_slot_is_m_mov_to_processor_status(IA64SlotType type,
                                            uint64_t raw)
{
    uint8_t x6;

    if (type != IA64_SLOT_TYPE_M || ia64_slot_major_opcode(raw) != 0x1 ||
        ((raw >> 33) & 0x7) != 0) {
        return false;
    }

    x6 = (raw >> 27) & 0x3f;
    return x6 == 0x29 || x6 == 0x2d;
}

bool ia64_exec_m_mov_to_processor_status(CPUIA64State *env, uint64_t raw)
{
    uint8_t x6;
    uint32_t source;
    uint64_t write_mask;
    uint64_t value;

    if (!env ||
        !ia64_slot_is_m_mov_to_processor_status(IA64_SLOT_TYPE_M, raw)) {
        return false;
    }

    x6 = (raw >> 27) & 0x3f;
    source = (raw >> 13) & 0x7f;
    value = ia64_read_gr(env, source);
    write_mask = x6 == 0x29 ? IA64_PSR_USER_MASK : IA64_PSR_LOWER_MASK;
    if (ia64_psr_trace_enabled()) {
        fprintf(stderr,
                "[ia64-psr-mask] ip=0x%016" PRIx64 " op=mov-to-psr"
                " mask=0x%016" PRIx64 " old=0x%016" PRIx64
                " new=0x%016" PRIx64 "\n",
                env->ip, write_mask, ia64_env_psr(env),
                (ia64_env_psr(env) & ~write_mask) | (value & write_mask));
    }
    ia64_env_set_psr(env, (ia64_env_psr(env) & ~write_mask) |
                          (value & write_mask));
    return true;
}

bool ia64_slot_is_m_break(IA64SlotType type, uint64_t raw)
{
    if (type != IA64_SLOT_TYPE_M || ia64_slot_major_opcode(raw) != 0x0 ||
        ((raw >> 33) & 0x7) != 0) {
        return false;
    }

    return ((raw >> 31) & 0x3) == 0 && ((raw >> 27) & 0xf) == 0;
}

uint64_t ia64_m_break_immediate(uint64_t raw)
{
    return (((raw >> 36) & 0x1) << 20) | ((raw >> 6) & 0xfffff);
}

bool ia64_slot_is_m_mov_to_region_register(IA64SlotType type, uint64_t raw)
{
    return type == IA64_SLOT_TYPE_M &&
           ia64_slot_major_opcode(raw) == 0x1 &&
           ((raw >> 33) & 0x7) == 0 &&
           ((raw >> 27) & 0x3f) == 0x00;
}

bool ia64_exec_m_mov_to_region_register(CPUIA64State *env, uint64_t raw)
{
    uint32_t source;
    uint32_t selector_reg;
    uint64_t selector;
    unsigned region;

    if (!env ||
        !ia64_slot_is_m_mov_to_region_register(IA64_SLOT_TYPE_M, raw)) {
        return false;
    }

    source = (raw >> 13) & 0x7f;
    selector_reg = (raw >> 20) & 0x7f;
    selector = ia64_read_gr(env, selector_reg);
    region = (selector >> 61) & 0x7;
    env->rr[region] = ia64_read_gr(env, source) & IA64_RR_IMPLEMENTED_MASK;
    /*
     * Do NOT flush the translation lookup cache here. Linux reloads RR0-4 on
     * every switch_mm, so flushing on each region-register write defeats the
     * cache exactly during the fork/exec/exit churn where it matters most: the
     * kernel runs ~90% of the time in region 5 (a constant RR5-7 RID), so its
     * hot translations are needlessly re-walked after every context switch.
     *
     * The cache is keyed by RID (see ia64_entry_matches): a lookup with the new
     * RID simply misses any entry left from a previous RID and re-walks, so a
     * stale RID never produces a false hit. Cached entries for the *new* RID
     * remain valid because an RR write changes which context is current, not
     * the modeled TC/TR mappings of any context. The only way a RID is reused
     * for a different mapping is wrap_mmu_context(), which issues flush_tlb_all
     * (ptc.e) -- and the ptc purge path still flushes the lookup cache. Genuine
     * mapping changes (itc/itr/ptc/ptr) also still flush it.
     */
    return true;
}

bool ia64_slot_is_m_mov_from_region_register(IA64SlotType type, uint64_t raw)
{
    return type == IA64_SLOT_TYPE_M &&
           ia64_slot_major_opcode(raw) == 0x1 &&
           ((raw >> 33) & 0x7) == 0 &&
           ((raw >> 27) & 0x3f) == 0x10;
}

bool ia64_exec_m_mov_from_region_register(CPUIA64State *env, uint64_t raw)
{
    uint32_t target;
    uint32_t selector_reg;
    uint64_t selector;
    unsigned region;

    if (!env ||
        !ia64_slot_is_m_mov_from_region_register(IA64_SLOT_TYPE_M, raw)) {
        return false;
    }

    target = (raw >> 6) & 0x7f;
    selector_reg = (raw >> 20) & 0x7f;
    selector = ia64_read_gr(env, selector_reg);
    region = (selector >> 61) & 0x7;
    ia64_write_gr(env, target, env->rr[region] & IA64_RR_IMPLEMENTED_MASK);
    return true;
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
    return vector == 2 ||
           (vector > IA64_INTERRUPT_SPURIOUS_VECTOR && vector <= 0xff);
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
    /*
     * This local-SAPIC model tracks one in-service vector.  While it is
     * active, keep further external delivery masked until the guest writes EOI.
     */
    if (env->interrupt.pending_interruption) {
        return true;
    }
    return ia64_external_interrupt_vector_masked_by_tpr(env, vector);
}

static bool ia64_select_pending_external_interrupt(CPUIA64State *env,
                                                   bool honor_masks,
                                                   uint64_t *vector_out)
{
    for (int reg = IA64_CR_IRR3; reg >= IA64_CR_IRR0; reg--) {
        uint64_t pending = env->cr[reg];

        while (pending != 0) {
            unsigned bit = 63 - clz64(pending);
            uint64_t vector = (uint64_t)(reg - IA64_CR_IRR0) * 64 + bit;

            if (ia64_valid_external_interrupt_vector(vector)) {
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

static bool ia64_interrupt_vector_active(CPUIA64State *env, uint64_t vector)
{
    return env->interrupt.pending_interruption &&
           (env->cr[IA64_CR_IVR] & IA64_INTERRUPT_VECTOR_MASK) == vector;
}

static bool ia64_interrupt_vector_pending(CPUIA64State *env, uint64_t vector)
{
    return vector <= 0xff &&
           (env->cr[IA64_CR_IRR0 + vector / 64] &
            (UINT64_C(1) << (vector & 63))) != 0;
}

static bool ia64_timer_compare_due(CPUIA64State *env)
{
    uint64_t vector;

    if (!env ||
        !ia64_time_after_eq(env->ar[IA64_AR_ITC], env->cr[IA64_CR_ITM]) ||
        ia64_timer_vector_masked(env)) {
        return false;
    }

    vector = ia64_timer_vector(env);
    if (vector <= IA64_INTERRUPT_SPURIOUS_VECTOR ||
        !ia64_valid_external_interrupt_vector(vector)) {
        return false;
    }

    return true;
}

/*
 * AR.ITC is backed by the QEMU virtual clock at IA64_ITC_FREQUENCY_HZ so
 * guest time tracks real time regardless of emulation speed.  While
 * itc_clock_backed is false (bare resets in unit tests), the register stays
 * fully manual and every helper below degrades to plain
 * env->ar[IA64_AR_ITC] accesses.
 */
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

    return !env->interrupt.timer_compare_latched &&
           !ia64_timer_vector_masked(env) &&
           vector > IA64_INTERRUPT_SPURIOUS_VECTOR &&
           ia64_valid_external_interrupt_vector(vector);
}

void ia64_itc_timer_update(CPUIA64State *env)
{
    int64_t now_ns;
    int64_t delta_ticks;

    if (!env || !env->itc_clock_backed || !env->itm_timer) {
        return;
    }
    if (!ia64_itm_timer_can_fire(env)) {
        timer_del(env->itm_timer);
        return;
    }

    now_ns = qemu_clock_get_ns(QEMU_CLOCK_VIRTUAL);
    delta_ticks = (int64_t)(env->cr[IA64_CR_ITM] -
                            (uint64_t)(now_ns / IA64_ITC_NS_PER_TICK +
                                       env->itc_offset));
    if (delta_ticks <= 0) {
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
    if (env->interrupt.timer_compare_latched) {
        return false;
    }
    if (ia64_interrupt_vector_active(env, vector) ||
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
        env->interrupt.timer_compare_latched = 1;
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
           (ia64_env_psr(env) & (IA64_PSR_I_BIT | IA64_PSR_IC_BIT)) ==
           (IA64_PSR_I_BIT | IA64_PSR_IC_BIT) &&
           ia64_select_pending_external_interrupt(env, true, &vector);
}

void ia64_reconcile_interrupt_state(CPUIA64State *env)
{
    uint64_t active_vector;

    if (!env) {
        return;
    }

    active_vector = env->cr[IA64_CR_IVR] & IA64_INTERRUPT_VECTOR_MASK;
    if (env->interrupt.pending_interruption &&
        !ia64_valid_external_interrupt_vector(active_vector)) {
        env->interrupt.pending_interruption = 0;
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
            env->interrupt.pending_interruption = 1;
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
        break;
    case IA64_CR_EOI:
        env->interrupt.pending_interruption = 0;
        env->cr[IA64_CR_IVR] = IA64_INTERRUPT_SPURIOUS_VECTOR;
        break;
    case IA64_CR_ITM:
        env->interrupt.timer_compare_latched = 0;
        ia64_itc_sync(env);
        if (!ia64_timer_compare_due(env)) {
            uint64_t vector = ia64_timer_vector(env);

            if (!ia64_interrupt_vector_active(env, vector)) {
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
        env->interrupt.timer_compare_latched = 0;
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

bool ia64_slot_is_m_mov_to_control(IA64SlotType type, uint64_t raw)
{
    return type == IA64_SLOT_TYPE_M &&
           ia64_slot_major_opcode(raw) == 0x1 &&
           ((raw >> 33) & 0x7) == 0 &&
           ((raw >> 27) & 0x3f) == 0x2c;
}

bool ia64_exec_m_mov_to_control(CPUIA64State *env, uint64_t raw)
{
    uint32_t source;
    uint32_t control;

    if (!env || !ia64_slot_is_m_mov_to_control(IA64_SLOT_TYPE_M, raw)) {
        return false;
    }

    source = (raw >> 13) & 0x7f;
    control = (raw >> 20) & 0x7f;
    ia64_write_control_register(env, control, ia64_read_gr(env, source));
    return true;
}

bool ia64_slot_is_m_mov_from_control(IA64SlotType type, uint64_t raw)
{
    return type == IA64_SLOT_TYPE_M &&
           ia64_slot_major_opcode(raw) == 0x1 &&
           ((raw >> 33) & 0x7) == 0 &&
           ((raw >> 27) & 0x3f) == 0x24;
}

bool ia64_exec_m_mov_from_control(CPUIA64State *env, uint64_t raw)
{
    uint32_t target;
    uint32_t control;

    if (!env || !ia64_slot_is_m_mov_from_control(IA64_SLOT_TYPE_M, raw)) {
        return false;
    }

    target = (raw >> 6) & 0x7f;
    control = (raw >> 20) & 0x7f;
    ia64_write_gr(env, target, ia64_read_control_register(env, control));
    return true;
}

bool ia64_slot_is_m_mov_from_processor_identifier(IA64SlotType type,
                                                  uint64_t raw)
{
    return type == IA64_SLOT_TYPE_M &&
           ia64_slot_major_opcode(raw) == 0x1 &&
           ((raw >> 33) & 0x7) == 0 &&
           ((raw >> 27) & 0x3f) == 0x17;
}

bool ia64_exec_m_mov_from_processor_identifier(CPUIA64State *env,
                                               uint64_t raw)
{
    uint32_t target;
    uint32_t selector_reg;
    uint64_t selector;

    if (!env || !ia64_slot_is_m_mov_from_processor_identifier(
            IA64_SLOT_TYPE_M, raw)) {
        return false;
    }

    target = (raw >> 6) & 0x7f;
    selector_reg = (raw >> 20) & 0x7f;
    selector = ia64_read_gr(env, selector_reg);
    ia64_write_gr(env, target,
                  selector < IA64_CPUID_COUNT ? env->cpuid[selector] : 0);
    return true;
}

static uint64_t *ia64_indexed_system_register_bank(CPUIA64State *env,
                                                   uint8_t x6,
                                                   unsigned *count)
{
    switch (x6 & 0x0f) {
    case 0x01:
        *count = IA64_DBR_COUNT;
        return env->dbr;
    case 0x02:
        *count = IA64_IBR_COUNT;
        return env->ibr;
    case 0x03:
        *count = IA64_PKR_COUNT;
        return env->pkr;
    case 0x04:
        *count = IA64_PMC_COUNT;
        return env->pmc;
    case 0x05:
        *count = IA64_PMD_COUNT;
        return env->pmd;
    default:
        *count = 0;
        return NULL;
    }
}

bool ia64_slot_is_m_mov_to_indexed_system_register(IA64SlotType type,
                                                   uint64_t raw)
{
    uint8_t x6;

    if (type != IA64_SLOT_TYPE_M ||
        ia64_slot_major_opcode(raw) != 0x1 ||
        ((raw >> 33) & 0x7) != 0) {
        return false;
    }

    x6 = (raw >> 27) & 0x3f;
    return x6 >= 0x01 && x6 <= 0x05;
}

bool ia64_exec_m_mov_to_indexed_system_register(CPUIA64State *env,
                                                uint64_t raw)
{
    uint8_t x6;
    uint32_t source;
    uint32_t selector_reg;
    uint64_t selector;
    uint64_t *bank;
    unsigned count;

    if (!env || !ia64_slot_is_m_mov_to_indexed_system_register(
            IA64_SLOT_TYPE_M, raw)) {
        return false;
    }

    x6 = (raw >> 27) & 0x3f;
    source = (raw >> 13) & 0x7f;
    selector_reg = (raw >> 20) & 0x7f;
    selector = ia64_read_gr(env, selector_reg);
    bank = ia64_indexed_system_register_bank(env, x6, &count);
    if (bank != NULL && selector < count) {
        bank[selector] = ia64_read_gr(env, source);
    }
    return true;
}

bool ia64_slot_is_m_mov_from_indexed_system_register(IA64SlotType type,
                                                     uint64_t raw)
{
    uint8_t x6;

    if (type != IA64_SLOT_TYPE_M ||
        ia64_slot_major_opcode(raw) != 0x1 ||
        ((raw >> 33) & 0x7) != 0) {
        return false;
    }

    x6 = (raw >> 27) & 0x3f;
    return x6 >= 0x11 && x6 <= 0x15;
}

bool ia64_exec_m_mov_from_indexed_system_register(CPUIA64State *env,
                                                  uint64_t raw)
{
    uint8_t x6;
    uint32_t target;
    uint32_t selector_reg;
    uint64_t selector;
    uint64_t *bank;
    unsigned count;
    uint64_t value = 0;

    if (!env || !ia64_slot_is_m_mov_from_indexed_system_register(
            IA64_SLOT_TYPE_M, raw)) {
        return false;
    }

    x6 = (raw >> 27) & 0x3f;
    target = (raw >> 6) & 0x7f;
    selector_reg = (raw >> 20) & 0x7f;
    selector = ia64_read_gr(env, selector_reg);
    bank = ia64_indexed_system_register_bank(env, x6, &count);
    if (bank != NULL && selector < count) {
        value = bank[selector];
    }
    ia64_write_gr(env, target, value);
    return true;
}

bool ia64_slot_is_m_insert_translation(IA64SlotType type, uint64_t raw)
{
    uint8_t x6;

    if (type != IA64_SLOT_TYPE_M || ia64_slot_major_opcode(raw) != 0x1 ||
        ((raw >> 33) & 0x7) != 0) {
        return false;
    }

    x6 = (raw >> 27) & 0x3f;
    return x6 == 0x0e || x6 == 0x0f || x6 == 0x2e || x6 == 0x2f;
}

bool ia64_exec_m_insert_translation(CPUIA64State *env, uint64_t raw)
{
    uint8_t x6;
    uint32_t source;
    uint64_t translation;
    bool instruction;
    bool pinned;
    uint8_t slot = 0;

    if (!env || !ia64_slot_is_m_insert_translation(IA64_SLOT_TYPE_M, raw)) {
        return false;
    }

    x6 = (raw >> 27) & 0x3f;
    source = (raw >> 13) & 0x7f;
    translation = ia64_read_gr(env, source);
    instruction = x6 == 0x0f || x6 == 0x2f;
    pinned = x6 == 0x0e || x6 == 0x0f;

    if (pinned) {
        uint32_t slot_reg = (raw >> 20) & 0x7f;
        uint64_t slot_value = ia64_read_gr(env, slot_reg);

        if (slot_value >= IA64_ITR_COUNT) {
            return true;
        }
        slot = slot_value;
    }

    if (!ia64_install_translation(env, instruction, pinned, slot,
                                  env->cr[IA64_CR_IFA], translation,
                                  env->cr[IA64_CR_ITIR])) {
        return true;
    }

    if (pinned && instruction) {
        env->itr[slot] = translation;
    } else if (pinned) {
        env->dtr[slot] = translation;
    } else if (instruction) {
        env->itr[0] = translation;
    } else {
        env->dtr[0] = translation;
    }
    return true;
}

bool ia64_slot_is_m_purge_translation(IA64SlotType type, uint64_t raw)
{
    uint8_t x6;

    if (type != IA64_SLOT_TYPE_M || ia64_slot_major_opcode(raw) != 0x1 ||
        ((raw >> 33) & 0x7) != 0) {
        return false;
    }

    x6 = (raw >> 27) & 0x3f;
    /* ptc.l/g/ga (0x09/0x0a/0x0b), ptr.d/i (0x0c/0x0d), ptc.e (0x34). */
    return x6 == 0x09 || x6 == 0x0a || x6 == 0x0b ||
           x6 == 0x0c || x6 == 0x0d || x6 == 0x34;
}

bool ia64_exec_m_purge_translation(CPUIA64State *env, uint64_t raw)
{
    uint8_t x6;
    uint64_t address;
    uint8_t page_size;

    if (!env || !ia64_slot_is_m_purge_translation(IA64_SLOT_TYPE_M, raw)) {
        return false;
    }

    x6 = (raw >> 27) & 0x3f;
    address = ia64_read_gr(env, (raw >> 20) & 0x7f);

    if (x6 == 0x34) {
        /* ptc.e r3: purge the whole dynamic translation cache. */
        ia64_purge_all_translation_cache(env);
        return true;
    }

    /* ptc.* / ptr.* take the purge page size from r2{7:2}. */
    page_size = (ia64_read_gr(env, (raw >> 13) & 0x7f) >> 2) & 0x3f;
    switch (x6) {
    case 0x0c: /* ptr.d */
        ia64_purge_translation_register(env, false, address, page_size);
        break;
    case 0x0d: /* ptr.i */
        ia64_purge_translation_register(env, true, address, page_size);
        break;
    case 0x09: /* ptc.l */
        ia64_purge_translation_cache(env, address, page_size, false);
        break;
    default:   /* ptc.g / ptc.ga */
        /*
         * Architecturally these still identify a RID, but processors may
         * over-purge TC entries.  With one emulated CPU, all-RID purge is a
         * conservative shootdown for stale same-VA translations.
         */
        ia64_purge_translation_cache(env, address, page_size, true);
        break;
    }
    return true;
}

bool ia64_slot_is_m_probe(IA64SlotType type, uint64_t raw)
{
    uint8_t x6;

    if (type != IA64_SLOT_TYPE_M || ia64_slot_major_opcode(raw) != 0x1 ||
        ((raw >> 33) & 0x7) != 0) {
        return false;
    }

    x6 = (raw >> 27) & 0x3f;
    return x6 == 0x38 || x6 == 0x39 || x6 == 0x18 || x6 == 0x19 ||
           x6 == 0x31 || x6 == 0x32 || x6 == 0x33;
}

static bool ia64_probe_is_faulting(uint8_t x6)
{
    return x6 == 0x31 || x6 == 0x32 || x6 == 0x33;
}

static MMUAccessType ia64_probe_access_type(uint8_t x6)
{
    /*
     * The current AR model has no writable-but-unreadable translation, so a
     * store probe is the strict check for probe.rw.fault.
     */
    return x6 == 0x19 || x6 == 0x31 || x6 == 0x33 ? MMU_DATA_STORE
                                                   : MMU_DATA_LOAD;
}

IA64ProbeStatus ia64_exec_m_probe_checked(CPUIA64State *env, uint64_t raw,
                                          IA64TranslateResult *fault)
{
    IA64TranslateResult result;
    uint8_t x6;
    uint32_t target;
    uint32_t address_reg;
    uint64_t address;
    MMUAccessType access_type;
    bool faulting;
    int requested_cpl;
    int current_cpl;
    int effective_cpl;

    if (!env || !ia64_slot_is_m_probe(IA64_SLOT_TYPE_M, raw)) {
        return IA64_PROBE_UNSUPPORTED;
    }

    x6 = (raw >> 27) & 0x3f;
    faulting = ia64_probe_is_faulting(x6);
    access_type = ia64_probe_access_type(x6);
    target = (raw >> 6) & 0x7f;
    address_reg = (raw >> 20) & 0x7f;
    address = ia64_read_gr(env, address_reg);

    if (x6 == 0x38 || x6 == 0x39) {
        requested_cpl = ia64_read_gr(env, (raw >> 13) & 0x7f) & 0x3;
    } else {
        requested_cpl = (raw >> 13) & 0x3;
    }
    current_cpl = (ia64_env_psr(env) & IA64_PSR_CPL_MASK) >>
                  IA64_PSR_CPL_SHIFT;
    effective_cpl = requested_cpl < current_cpl ? current_cpl : requested_cpl;

    if (ia64_translate_address_with_cpl(env, address, access_type, 0,
                                        effective_cpl, true, &result)) {
        if (!faulting) {
            ia64_write_gr(env, target, 1);
        }
        return IA64_PROBE_OK;
    }

    if (!faulting &&
        (result.status == IA64_TRANSLATE_ACCESS_DENIED ||
         result.status == IA64_TRANSLATE_BAD_ADDRESS ||
         result.status == IA64_TRANSLATE_UNIMPLEMENTED)) {
        ia64_write_gr(env, target, 0);
        return IA64_PROBE_OK;
    }

    if (fault) {
        *fault = result;
    }
    return IA64_PROBE_FAULT;
}

bool ia64_exec_m_probe(CPUIA64State *env, uint64_t raw)
{
    return ia64_exec_m_probe_checked(env, raw, NULL) == IA64_PROBE_OK;
}

bool ia64_slot_is_m_virtual_translation(IA64SlotType type, uint64_t raw)
{
    uint8_t x6;

    if (type != IA64_SLOT_TYPE_M || ia64_slot_major_opcode(raw) != 0x1 ||
        ((raw >> 33) & 0x7) != 0) {
        return false;
    }

    x6 = (raw >> 27) & 0x3f;
    return x6 == 0x1a || x6 == 0x1b || x6 == 0x1e || x6 == 0x1f;
}

IA64VirtualTranslationStatus
ia64_exec_m_virtual_translation_checked(CPUIA64State *env, uint64_t raw,
                                        IA64TranslateResult *fault)
{
    uint8_t x6;
    uint32_t target;
    uint32_t source;
    uint64_t address;
    uint64_t value;

    if (!env || !ia64_slot_is_m_virtual_translation(IA64_SLOT_TYPE_M, raw)) {
        return IA64_VIRTUAL_TRANSLATION_UNSUPPORTED;
    }

    x6 = (raw >> 27) & 0x3f;
    target = (raw >> 6) & 0x7f;
    source = (raw >> 20) & 0x7f;
    address = ia64_read_gr(env, source);

    switch (x6) {
    case 0x1e: /* tpa */
    {
        IA64TranslateResult result;

        if (!ia64_translate_address(env, address, MMU_DATA_LOAD, 0, true,
                                    &result)) {
            if (fault) {
                *fault = result;
            }
            return IA64_VIRTUAL_TRANSLATION_FAULT;
        }
        value = result.paddr;
        break;
    }
    case 0x1f: /* tak */
        value = 0;
        break;
    case 0x1a: /* thash */
        value = ia64_vhpt_hash_address(env, address);
        break;
    case 0x1b: /* ttag */
        value = ia64_vhpt_tag(env, address);
        break;
    default:
        value = 0;
        break;
    }

    ia64_write_gr(env, target, value);
    return IA64_VIRTUAL_TRANSLATION_OK;
}

bool ia64_exec_m_virtual_translation(CPUIA64State *env, uint64_t raw)
{
    return ia64_exec_m_virtual_translation_checked(env, raw, NULL) ==
           IA64_VIRTUAL_TRANSLATION_OK;
}

bool ia64_slot_is_m_invala(IA64SlotType type, uint64_t raw)
{
    uint8_t x4;

    if (type != IA64_SLOT_TYPE_M ||
        ia64_slot_major_opcode(raw) != 0 ||
        ((raw >> 33) & 0x7) != 0 ||
        ((raw >> 31) & 0x3) != 1) {
        return false;
    }

    x4 = (raw >> 27) & 0xf;
    return x4 == 0 || x4 == 2 || x4 == 3;
}

bool ia64_exec_m_invala(CPUIA64State *env, uint64_t raw)
{
    uint8_t x4;

    if (!env || !ia64_slot_is_m_invala(IA64_SLOT_TYPE_M, raw)) {
        return false;
    }

    x4 = (raw >> 27) & 0xf;
    if (x4 == 0) {
        ia64_alat_invalidate_all(env);
    } else if (x4 == 2) {
        ia64_alat_invalidate_gr(env, (raw >> 6) & 0x7f);
    } else {
        /*
         * Floating-point advanced loads are not modeled yet, so there are no
         * FP-tagged ALAT entries to invalidate.  Still consume the instruction
         * architecturally instead of reporting an unsupported M27 encoding.
         */
    }
    return true;
}

bool ia64_slot_is_m_system_noop(IA64SlotType type, uint64_t raw)
{
    uint8_t major;
    uint8_t x2;
    uint8_t x4;

    if (type != IA64_SLOT_TYPE_M) {
        return false;
    }

    if (ia64_slot_is_nop_or_hint(type, raw)) {
        return true;
    }

    major = ia64_slot_major_opcode(raw);
    if (((raw >> 33) & 0x7) != 0) {
        return false;
    }
    if (major == 0x1) {
        /* fc/fc.i: the interpreter has coherent instruction/data memory. */
        return ((raw >> 27) & 0x3f) == 0x30;
    }
    if (major != 0x0) {
        return false;
    }

    x2 = (raw >> 31) & 0x3;
    x4 = (raw >> 27) & 0xf;

    /* invala has architectural ALAT side effects and is handled separately. */
    if (x2 == 2 && (x4 == 0 || x4 == 2 || x4 == 3)) {
        return true;
    }
    if (x2 == 3 && (x4 == 0 || x4 == 1 || x4 == 3)) {
        return true;
    }
    return false;
}

bool ia64_slot_is_m_flushrs(IA64SlotType type, uint64_t raw)
{
    return type == IA64_SLOT_TYPE_M &&
           ia64_slot_major_opcode(raw) == 0 &&
           ((raw >> 33) & 0x7) == 0 &&
           ((raw >> 31) & 0x3) == 0 &&
           ((raw >> 27) & 0xf) == 0x0c;
}

bool ia64_slot_is_m_loadrs(IA64SlotType type, uint64_t raw)
{
    return type == IA64_SLOT_TYPE_M &&
           ia64_slot_major_opcode(raw) == 0 &&
           ((raw >> 33) & 0x7) == 0 &&
           ((raw >> 31) & 0x3) == 0 &&
           ((raw >> 27) & 0xf) == 0x0a;
}

bool ia64_slot_pair_is_lx_movl(uint64_t l_raw, uint64_t x_raw)
{
    return ia64_slot_major_opcode(x_raw) == 0x6;
}

static bool ia64_movl_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_MOVL_TRACE") != NULL;
    }
    return enabled != 0;
}

uint64_t ia64_lx_movl_imm64(uint64_t l_raw, uint64_t x_raw)
{
    return (((x_raw >> 36) & 0x1) << 63) |
           ((l_raw & IA64_SLOT_MASK) << 22) |
           (((x_raw >> 21) & 0x1) << 21) |
           (((x_raw >> 22) & 0x1f) << 16) |
           (((x_raw >> 27) & 0x1ff) << 7) |
           ((x_raw >> 13) & 0x7f);
}

bool ia64_exec_lx_movl(CPUIA64State *env, uint64_t l_raw, uint64_t x_raw)
{
    uint32_t r1;
    uint64_t value;

    if (!env || !ia64_slot_pair_is_lx_movl(l_raw, x_raw)) {
        return false;
    }

    r1 = (x_raw >> 6) & 0x7f;
    value = ia64_lx_movl_imm64(l_raw, x_raw);
    trace_ia64_movl(env->ip, r1, value, l_raw, x_raw);
    if (ia64_movl_trace_enabled()) {
        fprintf(stderr,
                "[ia64-movl] ip=0x%016" PRIx64 " r%" PRIu32
                "=0x%016" PRIx64 " l_raw=0x%011" PRIx64
                " x_raw=0x%011" PRIx64 "\n",
                env->ip, r1, value, l_raw, x_raw);
    }
    ia64_write_gr(env, r1, value);
    return true;
}

bool ia64_slot_pair_is_lx_nop_or_hint(uint64_t l_raw, uint64_t x_raw)
{
    (void)l_raw;

    return ia64_slot_major_opcode(x_raw) == 0x0 &&
           ((x_raw >> 33) & 0x7) == 0 &&
           ((x_raw >> 27) & 0x3f) == 1;
}

bool ia64_exec_lx_nop_or_hint(CPUIA64State *env, uint64_t l_raw,
                              uint64_t x_raw)
{
    if (!env || !ia64_slot_pair_is_lx_nop_or_hint(l_raw, x_raw)) {
        return false;
    }

    return true;
}

static int64_t ia64_sign_extend(uint64_t value, unsigned bits)
{
    uint64_t sign = 1ULL << (bits - 1);
    uint64_t mask = (1ULL << bits) - 1;

    value &= mask;
    return (int64_t)((value ^ sign) - sign);
}

bool ia64_slot_is_alu_add(IA64SlotType type, uint64_t raw)
{
    uint8_t ve;
    uint8_t x2a;
    uint8_t x4;
    uint8_t x2b;

    if ((type != IA64_SLOT_TYPE_M && type != IA64_SLOT_TYPE_I) ||
        ia64_slot_major_opcode(raw) != 0x8) {
        return false;
    }

    ve = (raw >> 33) & 0x1;
    x2a = (raw >> 34) & 0x3;
    x4 = (raw >> 29) & 0xf;
    x2b = (raw >> 27) & 0x3;
    if (ve != 0) {
        return false;
    }
    if (x2a == 0) {
        return x4 == 0 && x2b <= 1;
    }
    return x2a == 2;
}

bool ia64_exec_alu_add(CPUIA64State *env, uint64_t raw)
{
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint8_t x2a;
    uint8_t immediate;

    if (!env || (!ia64_slot_is_alu_add(IA64_SLOT_TYPE_M, raw) &&
                 !ia64_slot_is_alu_add(IA64_SLOT_TYPE_I, raw))) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    x2a = (raw >> 34) & 0x3;
    r3 = (raw >> 20) & 0x7f;

    if (x2a == 2) {
        int64_t imm14 = ia64_sign_extend((((raw >> 36) & 0x1) << 13) |
                                         (((raw >> 27) & 0x3f) << 7) |
                                         ((raw >> 13) & 0x7f), 14);

        ia64_write_gr(env, r1, (uint64_t)imm14 + ia64_read_gr(env, r3));
    } else {
        r2 = (raw >> 13) & 0x7f;
        immediate = (raw >> 27) & 0x3;

        ia64_write_gr(env, r1,
                      ia64_read_gr(env, r2) + ia64_read_gr(env, r3) +
                      immediate);
    }
    env->gr[0] = 0;
    return true;
}

bool ia64_slot_is_alu_sub(IA64SlotType type, uint64_t raw)
{
    uint8_t ve;
    uint8_t x2a;
    uint8_t x4;
    uint8_t x2b;

    if ((type != IA64_SLOT_TYPE_M && type != IA64_SLOT_TYPE_I) ||
        ia64_slot_major_opcode(raw) != 0x8) {
        return false;
    }

    ve = (raw >> 33) & 0x1;
    x2a = (raw >> 34) & 0x3;
    x4 = (raw >> 29) & 0xf;
    x2b = (raw >> 27) & 0x3;

    return ve == 0 && x2a == 0 &&
           ((x4 == 1 && x2b <= 1) || (x4 == 9 && x2b == 1));
}

bool ia64_exec_alu_sub(CPUIA64State *env, uint64_t raw)
{
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint8_t x2b;
    uint8_t x4;
    uint8_t immediate;

    if (!env || (!ia64_slot_is_alu_sub(IA64_SLOT_TYPE_M, raw) &&
                 !ia64_slot_is_alu_sub(IA64_SLOT_TYPE_I, raw))) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    r2 = (raw >> 13) & 0x7f;
    r3 = (raw >> 20) & 0x7f;
    x2b = (raw >> 27) & 0x3;
    x4 = (raw >> 29) & 0xf;

    if (x4 == 9) {
        int64_t imm8 = ia64_sign_extend((((raw >> 36) & 0x1) << 7) |
                                        ((raw >> 13) & 0x7f), 8);

        ia64_write_gr(env, r1, (uint64_t)imm8 - ia64_read_gr(env, r3));
    } else {
        immediate = x2b == 0 ? 1 : 0;
        ia64_write_gr(env, r1,
                      ia64_read_gr(env, r2) - ia64_read_gr(env, r3) -
                      immediate);
    }
    env->gr[0] = 0;
    return true;
}

bool ia64_slot_is_alu_logic(IA64SlotType type, uint64_t raw)
{
    uint8_t ve;
    uint8_t x2a;
    uint8_t x4;

    if ((type != IA64_SLOT_TYPE_M && type != IA64_SLOT_TYPE_I) ||
        ia64_slot_major_opcode(raw) != 0x8) {
        return false;
    }

    ve = (raw >> 33) & 0x1;
    x2a = (raw >> 34) & 0x3;
    x4 = (raw >> 29) & 0xf;
    return ve == 0 && x2a == 0 && (x4 == 3 || x4 == 0xb);
}

bool ia64_exec_alu_logic(CPUIA64State *env, uint64_t raw)
{
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint8_t x2b;
    uint8_t x4;
    uint64_t source2;
    uint64_t source3;
    uint64_t result;

    if (!env || (!ia64_slot_is_alu_logic(IA64_SLOT_TYPE_M, raw) &&
                 !ia64_slot_is_alu_logic(IA64_SLOT_TYPE_I, raw))) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    r2 = (raw >> 13) & 0x7f;
    r3 = (raw >> 20) & 0x7f;
    x2b = (raw >> 27) & 0x3;
    x4 = (raw >> 29) & 0xf;
    source2 = x4 == 0xb
        ? (uint64_t)ia64_sign_extend((((raw >> 36) & 0x1) << 7) |
                                     ((raw >> 13) & 0x7f), 8)
        : ia64_read_gr(env, r2);
    source3 = ia64_read_gr(env, r3);

    switch (x2b) {
    case 0:
        result = source2 & source3;
        break;
    case 1:
        result = source2 & ~source3;
        break;
    case 2:
        result = source2 | source3;
        break;
    case 3:
        result = source2 ^ source3;
        break;
    default:
        g_assert_not_reached();
    }

    ia64_write_gr(env, r1, result);
    return true;
}

static uint64_t ia64_addp4(uint64_t left, uint64_t right)
{
    uint64_t low32 = (left + right) & UINT32_MAX;
    uint64_t region = ((right >> 30) & 0x3ULL) << 61;

    return region | low32;
}

bool ia64_slot_is_alu_addp4(IA64SlotType type, uint64_t raw)
{
    uint8_t ve;
    uint8_t x2a;
    uint8_t x4;
    uint8_t x2b;

    if ((type != IA64_SLOT_TYPE_M && type != IA64_SLOT_TYPE_I) ||
        ia64_slot_major_opcode(raw) != 0x8) {
        return false;
    }

    ve = (raw >> 33) & 0x1;
    x2a = (raw >> 34) & 0x3;
    x4 = (raw >> 29) & 0xf;
    x2b = (raw >> 27) & 0x3;
    return ve == 0 && ((x2a == 0 && x4 == 2 && x2b == 0) || x2a == 3);
}

bool ia64_exec_alu_addp4(CPUIA64State *env, uint64_t raw)
{
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint8_t x2a;
    uint64_t source2;
    uint64_t source3;

    if (!env || (!ia64_slot_is_alu_addp4(IA64_SLOT_TYPE_M, raw) &&
                 !ia64_slot_is_alu_addp4(IA64_SLOT_TYPE_I, raw))) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    r2 = (raw >> 13) & 0x7f;
    r3 = (raw >> 20) & 0x7f;
    x2a = (raw >> 34) & 0x3;
    source2 = x2a == 3
        ? (uint64_t)ia64_sign_extend((((raw >> 36) & 0x1) << 13) |
                                     (((raw >> 27) & 0x3f) << 7) |
                                     ((raw >> 13) & 0x7f), 14)
        : ia64_read_gr(env, r2);
    source3 = ia64_read_gr(env, r3);

    ia64_write_gr(env, r1, ia64_addp4(source2, source3));
    return true;
}

bool ia64_slot_is_alu_shladd(IA64SlotType type, uint64_t raw)
{
    uint8_t ve;
    uint8_t x2a;
    uint8_t x4;

    if ((type != IA64_SLOT_TYPE_M && type != IA64_SLOT_TYPE_I) ||
        ia64_slot_major_opcode(raw) != 0x8) {
        return false;
    }

    ve = (raw >> 33) & 0x1;
    x2a = (raw >> 34) & 0x3;
    x4 = (raw >> 29) & 0xf;
    return ve == 0 && x2a == 0 && (x4 == 4 || x4 == 6);
}

bool ia64_exec_alu_shladd(CPUIA64State *env, uint64_t raw)
{
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint8_t x2b;
    uint8_t x4;
    uint64_t shifted;
    uint64_t addend;

    if (!env || (!ia64_slot_is_alu_shladd(IA64_SLOT_TYPE_M, raw) &&
                 !ia64_slot_is_alu_shladd(IA64_SLOT_TYPE_I, raw))) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    r2 = (raw >> 13) & 0x7f;
    r3 = (raw >> 20) & 0x7f;
    x2b = (raw >> 27) & 0x3;
    x4 = (raw >> 29) & 0xf;
    shifted = ia64_read_gr(env, r2) << (x2b + 1);
    addend = ia64_read_gr(env, r3);

    ia64_write_gr(env, r1, x4 == 6
                  ? ia64_addp4(shifted, addend)
                  : shifted + addend);
    return true;
}

typedef enum IA64PackedI2Op {
    IA64_PACKED_I2_INVALID = 0,
    IA64_PACKED_I2_MIX1_R,
    IA64_PACKED_I2_MIX2_R,
    IA64_PACKED_I2_MIX4_R,
    IA64_PACKED_I2_MIX1_L,
    IA64_PACKED_I2_MIX2_L,
    IA64_PACKED_I2_MIX4_L,
    IA64_PACKED_I2_PACK2_USS,
    IA64_PACKED_I2_PACK2_SSS,
    IA64_PACKED_I2_PACK4_SSS,
    IA64_PACKED_I2_UNPACK1_H,
    IA64_PACKED_I2_UNPACK2_H,
    IA64_PACKED_I2_UNPACK4_H,
    IA64_PACKED_I2_UNPACK1_L,
    IA64_PACKED_I2_UNPACK2_L,
    IA64_PACKED_I2_UNPACK4_L,
    IA64_PACKED_I2_PMIN1_U,
    IA64_PACKED_I2_PMAX1_U,
    IA64_PACKED_I2_PMIN2,
    IA64_PACKED_I2_PMAX2,
    IA64_PACKED_I2_PMPY2_R,
    IA64_PACKED_I2_PMPY2_L,
    IA64_PACKED_I2_PSAD1,
} IA64PackedI2Op;

typedef enum IA64MultiplyShiftOp {
    IA64_MULTIPLY_SHIFT_INVALID = 0,
    IA64_MULTIPLY_SHIFT_PMPYSHR2_U,
    IA64_MULTIPLY_SHIFT_PMPYSHR2,
    IA64_MULTIPLY_SHIFT_MPY4,
    IA64_MULTIPLY_SHIFT_MPYSHL4,
} IA64MultiplyShiftOp;

static IA64MultiplyShiftOp ia64_decode_i_multiply_shift_op(
    IA64SlotType type, uint64_t raw)
{
    uint8_t za;
    uint8_t x2a;
    uint8_t zb;
    uint8_t ve;
    uint8_t x2b;
    uint8_t x2c;

    if (type != IA64_SLOT_TYPE_I || ia64_slot_major_opcode(raw) != 0x7) {
        return IA64_MULTIPLY_SHIFT_INVALID;
    }

    za = (raw >> 36) & 0x1;
    x2a = (raw >> 34) & 0x3;
    zb = (raw >> 33) & 0x1;
    ve = (raw >> 32) & 0x1;
    x2b = (raw >> 28) & 0x3;
    x2c = (raw >> 30) & 0x3;

    if (x2a != 0 || ve != 0) {
        return IA64_MULTIPLY_SHIFT_INVALID;
    }
    if (za == 0 && zb == 1) {
        if (x2b == 1) {
            return IA64_MULTIPLY_SHIFT_PMPYSHR2_U;
        }
        if (x2b == 3) {
            return IA64_MULTIPLY_SHIFT_PMPYSHR2;
        }
    }
    if (za == 1 && zb == 0 && x2c == 3) {
        if (x2b == 1) {
            return IA64_MULTIPLY_SHIFT_MPY4;
        }
        if (x2b == 3) {
            return IA64_MULTIPLY_SHIFT_MPYSHL4;
        }
    }
    return IA64_MULTIPLY_SHIFT_INVALID;
}

bool ia64_slot_is_i_multiply_shift(IA64SlotType type, uint64_t raw)
{
    return ia64_decode_i_multiply_shift_op(type, raw) !=
           IA64_MULTIPLY_SHIFT_INVALID;
}

#define IA64_PACKED_I2_KEY(za, zb, x2b, x2c) \
    ((((za) & 0x1) << 5) | (((zb) & 0x1) << 4) | \
     (((x2b) & 0x3) << 2) | ((x2c) & 0x3))

static IA64PackedI2Op ia64_decode_i_packed_i2_op(IA64SlotType type,
                                                  uint64_t raw)
{
    uint8_t za;
    uint8_t x2a;
    uint8_t zb;
    uint8_t ve;
    uint8_t x2b;
    uint8_t x2c;

    if (type != IA64_SLOT_TYPE_I || ia64_slot_major_opcode(raw) != 0x7) {
        return IA64_PACKED_I2_INVALID;
    }

    za = (raw >> 36) & 0x1;
    x2a = (raw >> 34) & 0x3;
    zb = (raw >> 33) & 0x1;
    ve = (raw >> 32) & 0x1;
    x2c = (raw >> 30) & 0x3;
    x2b = (raw >> 28) & 0x3;

    if (ve != 0 || x2a != 2) {
        return IA64_PACKED_I2_INVALID;
    }

    switch (IA64_PACKED_I2_KEY(za, zb, x2b, x2c)) {
    case IA64_PACKED_I2_KEY(0, 0, 0, 2):
        return IA64_PACKED_I2_MIX1_R;
    case IA64_PACKED_I2_KEY(0, 1, 0, 2):
        return IA64_PACKED_I2_MIX2_R;
    case IA64_PACKED_I2_KEY(1, 0, 0, 2):
        return IA64_PACKED_I2_MIX4_R;
    case IA64_PACKED_I2_KEY(0, 0, 2, 2):
        return IA64_PACKED_I2_MIX1_L;
    case IA64_PACKED_I2_KEY(0, 1, 2, 2):
        return IA64_PACKED_I2_MIX2_L;
    case IA64_PACKED_I2_KEY(1, 0, 2, 2):
        return IA64_PACKED_I2_MIX4_L;
    case IA64_PACKED_I2_KEY(0, 1, 0, 0):
        return IA64_PACKED_I2_PACK2_USS;
    case IA64_PACKED_I2_KEY(0, 1, 2, 0):
        return IA64_PACKED_I2_PACK2_SSS;
    case IA64_PACKED_I2_KEY(1, 0, 2, 0):
        return IA64_PACKED_I2_PACK4_SSS;
    case IA64_PACKED_I2_KEY(0, 0, 0, 1):
        return IA64_PACKED_I2_UNPACK1_H;
    case IA64_PACKED_I2_KEY(0, 1, 0, 1):
        return IA64_PACKED_I2_UNPACK2_H;
    case IA64_PACKED_I2_KEY(1, 0, 0, 1):
        return IA64_PACKED_I2_UNPACK4_H;
    case IA64_PACKED_I2_KEY(0, 0, 2, 1):
        return IA64_PACKED_I2_UNPACK1_L;
    case IA64_PACKED_I2_KEY(0, 1, 2, 1):
        return IA64_PACKED_I2_UNPACK2_L;
    case IA64_PACKED_I2_KEY(1, 0, 2, 1):
        return IA64_PACKED_I2_UNPACK4_L;
    case IA64_PACKED_I2_KEY(0, 0, 1, 0):
        return IA64_PACKED_I2_PMIN1_U;
    case IA64_PACKED_I2_KEY(0, 0, 1, 1):
        return IA64_PACKED_I2_PMAX1_U;
    case IA64_PACKED_I2_KEY(0, 1, 3, 0):
        return IA64_PACKED_I2_PMIN2;
    case IA64_PACKED_I2_KEY(0, 1, 3, 1):
        return IA64_PACKED_I2_PMAX2;
    case IA64_PACKED_I2_KEY(0, 1, 1, 3):
        return IA64_PACKED_I2_PMPY2_R;
    case IA64_PACKED_I2_KEY(0, 1, 3, 3):
        return IA64_PACKED_I2_PMPY2_L;
    case IA64_PACKED_I2_KEY(0, 0, 3, 2):
        return IA64_PACKED_I2_PSAD1;
    default:
        return IA64_PACKED_I2_INVALID;
    }
}

bool ia64_slot_is_i_packed_i2(IA64SlotType type, uint64_t raw)
{
    return ia64_decode_i_packed_i2_op(type, raw) != IA64_PACKED_I2_INVALID;
}

static uint8_t ia64_packed_u8(uint64_t value, unsigned lane)
{
    return (value >> (lane * 8)) & 0xff;
}

static uint16_t ia64_packed_u16(uint64_t value, unsigned lane)
{
    return (value >> (lane * 16)) & 0xffff;
}

static uint32_t ia64_packed_u32(uint64_t value, unsigned lane)
{
    return (value >> (lane * 32)) & 0xffffffffU;
}

static uint64_t ia64_packed_set_u8(uint64_t result, unsigned lane,
                                   uint8_t value)
{
    return result | ((uint64_t)value << (lane * 8));
}

static uint64_t ia64_packed_set_u16(uint64_t result, unsigned lane,
                                    uint16_t value)
{
    return result | ((uint64_t)value << (lane * 16));
}

static uint64_t ia64_packed_set_u32(uint64_t result, unsigned lane,
                                    uint32_t value)
{
    return result | ((uint64_t)value << (lane * 32));
}

bool ia64_exec_i_multiply_shift(CPUIA64State *env, uint64_t raw)
{
    static const uint8_t shift_count[4] = { 0, 7, 15, 16 };
    IA64MultiplyShiftOp op;
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint64_t source2;
    uint64_t source3;
    uint64_t result = 0;
    bool source_nat;

    if (!env) {
        return false;
    }

    op = ia64_decode_i_multiply_shift_op(IA64_SLOT_TYPE_I, raw);
    if (op == IA64_MULTIPLY_SHIFT_INVALID) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    r2 = (raw >> 13) & 0x7f;
    r3 = (raw >> 20) & 0x7f;
    source2 = ia64_read_gr(env, r2);
    source3 = ia64_read_gr(env, r3);
    source_nat = ia64_read_gr_nat(env, r2) || ia64_read_gr_nat(env, r3);

    if (op == IA64_MULTIPLY_SHIFT_PMPYSHR2_U ||
        op == IA64_MULTIPLY_SHIFT_PMPYSHR2) {
        unsigned count = shift_count[(raw >> 30) & 0x3];

        for (unsigned lane = 0; lane < 4; lane++) {
            uint16_t left = ia64_packed_u16(source2, lane);
            uint16_t right = ia64_packed_u16(source3, lane);
            uint32_t product = op == IA64_MULTIPLY_SHIFT_PMPYSHR2_U
                ? (uint32_t)left * (uint32_t)right
                : (uint32_t)((int32_t)(int16_t)left *
                             (int32_t)(int16_t)right);

            result = ia64_packed_set_u16(
                result, lane, (product >> count) & 0xffff);
        }
    } else if (op == IA64_MULTIPLY_SHIFT_MPY4) {
        result = (uint64_t)(uint32_t)source2 * (uint32_t)source3;
    } else {
        result = ((uint64_t)(uint32_t)(source2 >> 32) *
                  (uint32_t)source3) << 32;
    }

    ia64_write_gr(env, r1, result);
    ia64_write_gr_nat(env, r1, source_nat);
    return true;
}

static uint8_t ia64_saturate_signed_i8(int64_t value)
{
    if (value > 127) {
        return 0x7f;
    }
    if (value < -128) {
        return 0x80;
    }
    return (uint8_t)(int8_t)value;
}

static uint8_t ia64_saturate_unsigned_i8(int64_t value)
{
    if (value < 0) {
        return 0;
    }
    if (value > 255) {
        return 0xff;
    }
    return value;
}

static uint16_t ia64_saturate_signed_i16(int64_t value)
{
    if (value > 32767) {
        return 0x7fff;
    }
    if (value < -32768) {
        return 0x8000;
    }
    return (uint16_t)(int16_t)value;
}

bool ia64_exec_i_packed_i2(CPUIA64State *env, uint64_t raw)
{
    IA64PackedI2Op op;
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint64_t source2;
    uint64_t source3;
    uint64_t result = 0;

    if (!env) {
        return false;
    }

    op = ia64_decode_i_packed_i2_op(IA64_SLOT_TYPE_I, raw);
    if (op == IA64_PACKED_I2_INVALID) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    r2 = (raw >> 13) & 0x7f;
    r3 = (raw >> 20) & 0x7f;
    source2 = ia64_read_gr(env, r2);
    source3 = ia64_read_gr(env, r3);

    switch (op) {
    case IA64_PACKED_I2_MIX1_R:
    case IA64_PACKED_I2_MIX1_L: {
        unsigned first_lane = op == IA64_PACKED_I2_MIX1_R ? 0 : 1;

        for (unsigned pair = 0; pair < 4; pair++) {
            unsigned source_lane = first_lane + pair * 2;

            result = ia64_packed_set_u8(
                result, pair * 2, ia64_packed_u8(source3, source_lane));
            result = ia64_packed_set_u8(
                result, pair * 2 + 1, ia64_packed_u8(source2, source_lane));
        }
        break;
    }
    case IA64_PACKED_I2_MIX2_R:
    case IA64_PACKED_I2_MIX2_L: {
        unsigned first_lane = op == IA64_PACKED_I2_MIX2_R ? 0 : 1;

        for (unsigned pair = 0; pair < 2; pair++) {
            unsigned source_lane = first_lane + pair * 2;

            result = ia64_packed_set_u16(
                result, pair * 2, ia64_packed_u16(source3, source_lane));
            result = ia64_packed_set_u16(
                result, pair * 2 + 1,
                ia64_packed_u16(source2, source_lane));
        }
        break;
    }
    case IA64_PACKED_I2_MIX4_R:
    case IA64_PACKED_I2_MIX4_L: {
        unsigned source_lane = op == IA64_PACKED_I2_MIX4_R ? 0 : 1;

        result = ia64_packed_set_u32(
            result, 0, ia64_packed_u32(source3, source_lane));
        result = ia64_packed_set_u32(
            result, 1, ia64_packed_u32(source2, source_lane));
        break;
    }
    case IA64_PACKED_I2_PACK2_USS:
    case IA64_PACKED_I2_PACK2_SSS:
        for (unsigned lane = 0; lane < 4; lane++) {
            int16_t value = ia64_packed_u16(source2, lane);
            uint8_t packed = op == IA64_PACKED_I2_PACK2_USS
                ? ia64_saturate_unsigned_i8(value)
                : ia64_saturate_signed_i8(value);

            result = ia64_packed_set_u8(result, lane, packed);
        }
        for (unsigned lane = 0; lane < 4; lane++) {
            int16_t value = ia64_packed_u16(source3, lane);
            uint8_t packed = op == IA64_PACKED_I2_PACK2_USS
                ? ia64_saturate_unsigned_i8(value)
                : ia64_saturate_signed_i8(value);

            result = ia64_packed_set_u8(result, lane + 4, packed);
        }
        break;
    case IA64_PACKED_I2_PACK4_SSS:
        for (unsigned lane = 0; lane < 2; lane++) {
            int32_t value = ia64_packed_u32(source2, lane);

            result = ia64_packed_set_u16(
                result, lane, ia64_saturate_signed_i16(value));
        }
        for (unsigned lane = 0; lane < 2; lane++) {
            int32_t value = ia64_packed_u32(source3, lane);

            result = ia64_packed_set_u16(
                result, lane + 2, ia64_saturate_signed_i16(value));
        }
        break;
    case IA64_PACKED_I2_UNPACK1_H:
    case IA64_PACKED_I2_UNPACK1_L: {
        unsigned first_lane = op == IA64_PACKED_I2_UNPACK1_H ? 4 : 0;

        for (unsigned pair = 0; pair < 4; pair++) {
            unsigned source_lane = first_lane + pair;

            result = ia64_packed_set_u8(
                result, pair * 2, ia64_packed_u8(source3, source_lane));
            result = ia64_packed_set_u8(
                result, pair * 2 + 1, ia64_packed_u8(source2, source_lane));
        }
        break;
    }
    case IA64_PACKED_I2_UNPACK2_H:
    case IA64_PACKED_I2_UNPACK2_L: {
        unsigned first_lane = op == IA64_PACKED_I2_UNPACK2_H ? 2 : 0;

        for (unsigned pair = 0; pair < 2; pair++) {
            unsigned source_lane = first_lane + pair;

            result = ia64_packed_set_u16(
                result, pair * 2, ia64_packed_u16(source3, source_lane));
            result = ia64_packed_set_u16(
                result, pair * 2 + 1,
                ia64_packed_u16(source2, source_lane));
        }
        break;
    }
    case IA64_PACKED_I2_UNPACK4_H:
    case IA64_PACKED_I2_UNPACK4_L: {
        unsigned source_lane = op == IA64_PACKED_I2_UNPACK4_H ? 1 : 0;

        result = ia64_packed_set_u32(
            result, 0, ia64_packed_u32(source3, source_lane));
        result = ia64_packed_set_u32(
            result, 1, ia64_packed_u32(source2, source_lane));
        break;
    }
    case IA64_PACKED_I2_PMIN1_U:
    case IA64_PACKED_I2_PMAX1_U:
        for (unsigned lane = 0; lane < 8; lane++) {
            uint8_t left = ia64_packed_u8(source2, lane);
            uint8_t right = ia64_packed_u8(source3, lane);
            uint8_t chosen = op == IA64_PACKED_I2_PMIN1_U
                ? MIN(left, right)
                : MAX(left, right);

            result = ia64_packed_set_u8(result, lane, chosen);
        }
        break;
    case IA64_PACKED_I2_PMIN2:
    case IA64_PACKED_I2_PMAX2:
        for (unsigned lane = 0; lane < 4; lane++) {
            int16_t left = ia64_packed_u16(source2, lane);
            int16_t right = ia64_packed_u16(source3, lane);
            int16_t chosen = op == IA64_PACKED_I2_PMIN2
                ? MIN(left, right)
                : MAX(left, right);

            result = ia64_packed_set_u16(result, lane, chosen);
        }
        break;
    case IA64_PACKED_I2_PMPY2_R:
    case IA64_PACKED_I2_PMPY2_L: {
        unsigned first_lane = op == IA64_PACKED_I2_PMPY2_R ? 0 : 1;

        for (unsigned lane = 0; lane < 2; lane++) {
            unsigned source_lane = first_lane + lane * 2;
            int16_t left = ia64_packed_u16(source2, source_lane);
            int16_t right = ia64_packed_u16(source3, source_lane);

            result = ia64_packed_set_u32(
                result, lane, (uint32_t)((int32_t)left * (int32_t)right));
        }
        break;
    }
    case IA64_PACKED_I2_PSAD1:
        for (unsigned lane = 0; lane < 8; lane++) {
            int delta = ia64_packed_u8(source2, lane) -
                        ia64_packed_u8(source3, lane);

            result += delta < 0 ? -delta : delta;
        }
        break;
    default:
        return false;
    }

    {
        bool source_nat = ia64_read_gr_nat(env, r2) ||
                          ia64_read_gr_nat(env, r3);

        ia64_write_gr(env, r1, result);
        ia64_write_gr_nat(env, r1, source_nat);
    }
    return true;
}

/*
 * Parallel (multimedia) integer ALU, major opcode 0x8, x2a == 1.
 *
 * Covers the A9 arithmetic family (padd/psub with modulo and saturating
 * forms, pavg, pavgsub, pcmp) and the A10 shift-and-add family
 * (pshladd2/pshradd2).  Element width is selected by the za/zb pair:
 *   (za,zb) = (0,0) -> 1 byte, (0,1) -> 2 byte, (1,0) -> 4 byte.
 * These share the same major opcode and unit routing as the scalar ALU
 * ops (which all use x2a != 1), so the interpreter dispatches this family
 * on its own predicate.
 */
typedef enum IA64PackedAluOp {
    IA64_PACKED_ALU_INVALID = 0,
    IA64_PACKED_ALU_PADD,
    IA64_PACKED_ALU_PSUB,
    IA64_PACKED_ALU_PAVG,
    IA64_PACKED_ALU_PAVGSUB,
    IA64_PACKED_ALU_PCMP,
    IA64_PACKED_ALU_PSHLADD,
    IA64_PACKED_ALU_PSHRADD,
} IA64PackedAluOp;

static IA64PackedAluOp ia64_decode_packed_alu(uint64_t raw, unsigned *width_out,
                                              unsigned *mod_out)
{
    uint8_t za;
    uint8_t zb;
    uint8_t x4;
    uint8_t x2b;
    unsigned width;

    if (ia64_slot_major_opcode(raw) != 0x8 || ((raw >> 34) & 0x3) != 1) {
        return IA64_PACKED_ALU_INVALID;
    }

    za = (raw >> 36) & 0x1;
    zb = (raw >> 33) & 0x1;
    x4 = (raw >> 29) & 0xf;
    x2b = (raw >> 27) & 0x3;

    if (za == 0 && zb == 0) {
        width = 1;
    } else if (za == 0 && zb == 1) {
        width = 2;
    } else if (za == 1 && zb == 0) {
        width = 4;
    } else {
        return IA64_PACKED_ALU_INVALID;
    }

    *width_out = width;
    *mod_out = x2b;

    switch (x4) {
    case 0: /* padd: x2b 0=modulo 1=sss 2=uuu 3=uus */
    case 1: /* psub: same modifier layout */
        if (width == 4 && x2b != 0) {
            return IA64_PACKED_ALU_INVALID; /* no 4-byte saturating form */
        }
        return x4 == 0 ? IA64_PACKED_ALU_PADD : IA64_PACKED_ALU_PSUB;
    case 2: /* pavg: x2b 2=normal 3=raz */
        if (width == 4 || (x2b != 2 && x2b != 3)) {
            return IA64_PACKED_ALU_INVALID;
        }
        return IA64_PACKED_ALU_PAVG;
    case 3: /* pavgsub: x2b 2 only */
        if (width == 4 || x2b != 2) {
            return IA64_PACKED_ALU_INVALID;
        }
        return IA64_PACKED_ALU_PAVGSUB;
    case 4: /* pshladd2: 2-byte only, x2b = count2 */
        return width == 2 ? IA64_PACKED_ALU_PSHLADD : IA64_PACKED_ALU_INVALID;
    case 6: /* pshradd2: 2-byte only, x2b = count2 */
        return width == 2 ? IA64_PACKED_ALU_PSHRADD : IA64_PACKED_ALU_INVALID;
    case 9: /* pcmp: x2b 0=eq 1=gt */
        return x2b <= 1 ? IA64_PACKED_ALU_PCMP : IA64_PACKED_ALU_INVALID;
    default:
        return IA64_PACKED_ALU_INVALID;
    }
}

static uint64_t ia64_packed_mask(unsigned width)
{
    return width == 4 ? UINT32_MAX : ((UINT64_C(1) << (width * 8)) - 1);
}

static uint64_t ia64_packed_read_lane(uint64_t value, unsigned width,
                                      unsigned lane)
{
    switch (width) {
    case 1:
        return ia64_packed_u8(value, lane);
    case 2:
        return ia64_packed_u16(value, lane);
    default:
        return ia64_packed_u32(value, lane);
    }
}

static uint64_t ia64_packed_write_lane(uint64_t result, unsigned width,
                                       unsigned lane, uint64_t value)
{
    switch (width) {
    case 1:
        return ia64_packed_set_u8(result, lane, (uint8_t)value);
    case 2:
        return ia64_packed_set_u16(result, lane, (uint16_t)value);
    default:
        return ia64_packed_set_u32(result, lane, (uint32_t)value);
    }
}

static int64_t ia64_packed_sext(uint64_t lane, unsigned width)
{
    return ia64_sign_extend(lane, width * 8);
}

static uint16_t ia64_saturate_unsigned_i16(int64_t value)
{
    if (value < 0) {
        return 0;
    }
    if (value > 0xffff) {
        return 0xffff;
    }
    return value;
}

static uint64_t ia64_packed_saturate(int64_t value, unsigned width,
                                     bool result_signed)
{
    if (width == 1) {
        return result_signed ? ia64_saturate_signed_i8(value)
                             : ia64_saturate_unsigned_i8(value);
    }
    return result_signed ? ia64_saturate_signed_i16(value)
                         : ia64_saturate_unsigned_i16(value);
}

static uint64_t ia64_packed_addsub_lane(uint64_t x, uint64_t y, unsigned width,
                                        unsigned mod, bool subtract)
{
    int64_t left;
    int64_t right;
    int64_t temp;
    bool result_signed;

    if (mod == 0) { /* modulo form: truncate, sign is irrelevant */
        temp = subtract ? (int64_t)(x - y) : (int64_t)(x + y);
        return (uint64_t)temp & ia64_packed_mask(width);
    }

    switch (mod) {
    case 1: /* sss: signed result, signed sources */
        left = ia64_packed_sext(x, width);
        right = ia64_packed_sext(y, width);
        result_signed = true;
        break;
    case 3: /* uus: unsigned result, unsigned r2, signed r3 */
        left = (int64_t)x;
        right = ia64_packed_sext(y, width);
        result_signed = false;
        break;
    default: /* uuu: unsigned result, unsigned sources */
        left = (int64_t)x;
        right = (int64_t)y;
        result_signed = false;
        break;
    }

    temp = subtract ? left - right : left + right;
    return ia64_packed_saturate(temp, width, result_signed);
}

static uint64_t ia64_packed_avg_lane(uint64_t x, uint64_t y, unsigned width,
                                     bool raz)
{
    uint64_t sum = x + y; /* zero-extended sources, no overflow at 64 bits */

    if (raz) {
        return ((sum + 1) >> 1) & ia64_packed_mask(width);
    }
    return (((sum >> 1) | (sum & 1))) & ia64_packed_mask(width);
}

static uint64_t ia64_packed_avgsub_lane(uint64_t x, uint64_t y, unsigned width)
{
    uint64_t field_mask = (UINT64_C(1) << (width * 8 + 1)) - 1;
    uint64_t temp = (x - y) & field_mask; /* width+1 bit unsigned field */

    return (((temp >> 1) | (temp & 1))) & ia64_packed_mask(width);
}

static uint64_t ia64_packed_cmp_lane(uint64_t x, uint64_t y, unsigned width,
                                     bool greater_than)
{
    bool match = greater_than
        ? ia64_packed_sext(x, width) > ia64_packed_sext(y, width)
        : x == y;

    return match ? ia64_packed_mask(width) : 0;
}

static uint64_t ia64_packed_shladd2_lane(uint64_t x, uint64_t y, unsigned count)
{
    int64_t max = 0x7fff;
    int64_t min = -0x8000;
    int64_t temp = ia64_packed_sext(x, 2) << count;
    int64_t res;

    if (temp > max) {
        res = max;
    } else if (temp < min) {
        res = min;
    } else {
        res = temp + ia64_packed_sext(y, 2);
        if (res > max) {
            res = max;
        } else if (res < min) {
            res = min;
        }
    }
    return (uint64_t)res & 0xffff;
}

static uint64_t ia64_packed_shradd2_lane(uint64_t x, uint64_t y, unsigned count)
{
    int64_t max = 0x7fff;
    int64_t min = -0x8000;
    int64_t res = (ia64_packed_sext(x, 2) >> count) + ia64_packed_sext(y, 2);

    if (res > max) {
        res = max;
    } else if (res < min) {
        res = min;
    }
    return (uint64_t)res & 0xffff;
}

bool ia64_slot_is_packed_alu(IA64SlotType type, uint64_t raw)
{
    unsigned width;
    unsigned mod;

    if (type != IA64_SLOT_TYPE_M && type != IA64_SLOT_TYPE_I) {
        return false;
    }
    return ia64_decode_packed_alu(raw, &width, &mod) != IA64_PACKED_ALU_INVALID;
}

bool ia64_exec_packed_alu(CPUIA64State *env, uint64_t raw)
{
    IA64PackedAluOp op;
    unsigned width;
    unsigned mod;
    unsigned lanes;
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint64_t source2;
    uint64_t source3;
    uint64_t result = 0;

    if (!env) {
        return false;
    }

    op = ia64_decode_packed_alu(raw, &width, &mod);
    if (op == IA64_PACKED_ALU_INVALID) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    r2 = (raw >> 13) & 0x7f;
    r3 = (raw >> 20) & 0x7f;
    source2 = ia64_read_gr(env, r2);
    source3 = ia64_read_gr(env, r3);
    lanes = 8 / width;

    for (unsigned lane = 0; lane < lanes; lane++) {
        uint64_t x = ia64_packed_read_lane(source2, width, lane);
        uint64_t y = ia64_packed_read_lane(source3, width, lane);
        uint64_t out;

        switch (op) {
        case IA64_PACKED_ALU_PADD:
            out = ia64_packed_addsub_lane(x, y, width, mod, false);
            break;
        case IA64_PACKED_ALU_PSUB:
            out = ia64_packed_addsub_lane(x, y, width, mod, true);
            break;
        case IA64_PACKED_ALU_PAVG:
            out = ia64_packed_avg_lane(x, y, width, mod == 3);
            break;
        case IA64_PACKED_ALU_PAVGSUB:
            out = ia64_packed_avgsub_lane(x, y, width);
            break;
        case IA64_PACKED_ALU_PCMP:
            out = ia64_packed_cmp_lane(x, y, width, mod == 1);
            break;
        case IA64_PACKED_ALU_PSHLADD:
            out = ia64_packed_shladd2_lane(x, y, mod);
            break;
        case IA64_PACKED_ALU_PSHRADD:
            out = ia64_packed_shradd2_lane(x, y, mod);
            break;
        default:
            return false;
        }

        result = ia64_packed_write_lane(result, width, lane, out);
    }

    ia64_write_gr(env, r1, result);
    return true;
}

bool ia64_slot_is_i_mux(IA64SlotType type, uint64_t raw)
{
    uint8_t za;
    uint8_t zb;

    if (type != IA64_SLOT_TYPE_I || ia64_slot_major_opcode(raw) != 0x7) {
        return false;
    }
    if (((raw >> 32) & 0x1) != 0 || ((raw >> 34) & 0x3) != 3 ||
        ((raw >> 28) & 0x3) != 2 || ((raw >> 30) & 0x3) != 2) {
        return false;
    }

    za = (raw >> 36) & 0x1;
    zb = (raw >> 33) & 0x1;
    if (za != 0 || (zb != 0 && zb != 1)) {
        return false;
    }
    if (zb == 0) {
        uint8_t mbtype = (raw >> 20) & 0x0f;

        return mbtype == 0x0 || mbtype == 0x8 || mbtype == 0x9 ||
               mbtype == 0x0a || mbtype == 0x0b;
    }
    return true;
}

static uint64_t ia64_select_packed_elements(uint64_t source,
                                            const uint8_t *indexes,
                                            unsigned lanes,
                                            unsigned element_bits)
{
    uint64_t mask = (UINT64_C(1) << element_bits) - 1;
    uint64_t result = 0;

    for (unsigned lane = 0; lane < lanes; lane++) {
        uint64_t element = (source >> (indexes[lane] * element_bits)) & mask;
        result |= element << (lane * element_bits);
    }
    return result;
}

bool ia64_exec_i_mux(CPUIA64State *env, uint64_t raw)
{
    static const uint8_t mux1_0[] = { 0, 0, 0, 0, 0, 0, 0, 0 };
    static const uint8_t mux1_8[] = { 0, 4, 2, 6, 1, 5, 3, 7 };
    static const uint8_t mux1_9[] = { 0, 4, 1, 5, 2, 6, 3, 7 };
    static const uint8_t mux1_a[] = { 0, 2, 4, 6, 1, 3, 5, 7 };
    static const uint8_t mux1_b[] = { 7, 6, 5, 4, 3, 2, 1, 0 };
    uint32_t r1;
    uint32_t r2;
    uint8_t zb;
    uint64_t source;
    uint64_t result;

    if (!env || !ia64_slot_is_i_mux(IA64_SLOT_TYPE_I, raw)) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    r2 = (raw >> 13) & 0x7f;
    zb = (raw >> 33) & 0x1;
    source = ia64_read_gr(env, r2);

    if (zb == 0) {
        const uint8_t *indexes;

        switch ((raw >> 20) & 0x0f) {
        case 0x0:
            indexes = mux1_0;
            break;
        case 0x8:
            indexes = mux1_8;
            break;
        case 0x9:
            indexes = mux1_9;
            break;
        case 0x0a:
            indexes = mux1_a;
            break;
        case 0x0b:
            indexes = mux1_b;
            break;
        default:
            return false;
        }
        result = ia64_select_packed_elements(source, indexes, 8, 8);
    } else {
        uint8_t indexes[4];
        uint8_t immediate = (raw >> 20) & 0xff;

        for (unsigned lane = 0; lane < 4; lane++) {
            indexes[lane] = (immediate >> (lane * 2)) & 0x3;
        }
        result = ia64_select_packed_elements(source, indexes, 4, 16);
    }

    ia64_write_gr(env, r1, result);
    return true;
}

bool ia64_slot_is_i_bit_count(IA64SlotType type, uint64_t raw)
{
    uint8_t za;
    uint8_t x2a;
    uint8_t zb;
    uint8_t ve;
    uint8_t x2b;
    uint8_t x2c;

    if (type != IA64_SLOT_TYPE_I || ia64_slot_major_opcode(raw) != 0x7) {
        return false;
    }

    za = (raw >> 36) & 0x1;
    x2a = (raw >> 34) & 0x3;
    zb = (raw >> 33) & 0x1;
    ve = (raw >> 32) & 0x1;
    x2c = (raw >> 30) & 0x3;
    x2b = (raw >> 28) & 0x3;

    return za == 0 && x2a == 1 && zb == 1 && ve == 0 &&
           x2b == 1 && (x2c == 2 || x2c == 3);
}

bool ia64_exec_i_bit_count(CPUIA64State *env, uint64_t raw)
{
    uint32_t r1;
    uint32_t r3;
    uint8_t x2c;
    uint64_t value;
    uint64_t result;

    if (!env || !ia64_slot_is_i_bit_count(IA64_SLOT_TYPE_I, raw)) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    r3 = (raw >> 20) & 0x7f;
    x2c = (raw >> 30) & 0x3;
    value = ia64_read_gr(env, r3);
    result = x2c == 2 ? ctpop64(value) : clz64(value);
    ia64_write_gr(env, r1, result);
    return true;
}

bool ia64_slot_is_i_variable_shift(IA64SlotType type, uint64_t raw)
{
    uint8_t za;
    uint8_t x2a;
    uint8_t zb;
    uint8_t ve;
    uint8_t x2b;
    uint8_t x2c;

    if (type != IA64_SLOT_TYPE_I || ia64_slot_major_opcode(raw) != 0x7) {
        return false;
    }

    za = (raw >> 36) & 0x1;
    x2a = (raw >> 34) & 0x3;
    zb = (raw >> 33) & 0x1;
    ve = (raw >> 32) & 0x1;
    x2c = (raw >> 30) & 0x3;
    x2b = (raw >> 28) & 0x3;

    if (za != 1 || x2a != 0 || zb != 1 || ve != 0) {
        return false;
    }

    return (x2b == 0 && x2c == 0) ||
           (x2b == 0 && x2c == 1) ||
           (x2b == 2 && x2c == 0);
}

bool ia64_exec_i_variable_shift(CPUIA64State *env, uint64_t raw)
{
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint8_t x2b;
    uint8_t x2c;
    uint64_t count;
    uint64_t value;
    uint64_t result;

    if (!env || !ia64_slot_is_i_variable_shift(IA64_SLOT_TYPE_I, raw)) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    r2 = (raw >> 13) & 0x7f;
    r3 = (raw >> 20) & 0x7f;
    x2c = (raw >> 30) & 0x3;
    x2b = (raw >> 28) & 0x3;

    if (x2b == 0 && x2c == 1) {
        value = ia64_read_gr(env, r2);
        count = ia64_read_gr(env, r3);
        result = count >= 64 ? 0 : value << count;
    } else {
        value = ia64_read_gr(env, r3);
        count = ia64_read_gr(env, r2);
        if (x2b == 0 && x2c == 0) {
            result = count >= 64 ? 0 : value >> count;
        } else {
            result = count >= 64
                ? (uint64_t)((int64_t)value >> 63)
                : (uint64_t)((int64_t)value >> count);
        }
    }

    ia64_write_gr(env, r1, result);
    return true;
}

bool ia64_slot_is_addl(IA64SlotType type, uint64_t raw)
{
    return (type == IA64_SLOT_TYPE_M || type == IA64_SLOT_TYPE_I) &&
           ia64_slot_major_opcode(raw) == 0x9;
}

int64_t ia64_addl_immediate(uint64_t raw)
{
    uint64_t encoded = (((raw >> 36) & 0x1) << 21) |
                       (((raw >> 22) & 0x1f) << 16) |
                       (((raw >> 27) & 0x1ff) << 7) |
                       ((raw >> 13) & 0x7f);

    return ia64_sign_extend(encoded, 22);
}

bool ia64_exec_addl(CPUIA64State *env, uint64_t raw)
{
    uint32_t r1;
    uint32_t r3;

    if (!env || (!ia64_slot_is_addl(IA64_SLOT_TYPE_M, raw) &&
                 !ia64_slot_is_addl(IA64_SLOT_TYPE_I, raw))) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    r3 = (raw >> 20) & 0x3;
    ia64_write_gr(env, r1,
                  (uint64_t)ia64_addl_immediate(raw) +
                  ia64_read_gr(env, r3));
    env->gr[0] = 0;
    return true;
}

bool ia64_slot_is_m_setf(IA64SlotType type, uint64_t raw)
{
    uint8_t x6;
    uint8_t memory_class;

    if (type != IA64_SLOT_TYPE_M || ia64_slot_major_opcode(raw) != 0x6) {
        return false;
    }
    if (((raw >> 27) & 0x1) == 0 || ((raw >> 36) & 0x1) != 0) {
        return false;
    }

    x6 = (raw >> 30) & 0x3f;
    memory_class = x6 >> 2;
    return memory_class == 7;
}

bool ia64_exec_m_setf(CPUIA64State *env, uint64_t raw)
{
    uint8_t x6;
    uint8_t format;
    uint32_t f1;
    uint32_t r2;
    uint64_t value;

    if (!env || !ia64_slot_is_m_setf(IA64_SLOT_TYPE_M, raw)) {
        return false;
    }

    x6 = (raw >> 30) & 0x3f;
    format = x6 & 0x3;
    f1 = (raw >> 6) & 0x7f;
    r2 = (raw >> 13) & 0x7f;
    value = ia64_read_gr(env, r2);

    if (ia64_read_gr_nat(env, r2)) {
        ia64_write_fr_natval(env, f1);
        return true;
    }

    switch (format) {
    case 0:
        ia64_write_fr_parts(env, f1, false, IA64_FR_INTEGER_EXPONENT, value);
        if (ia64_fpu_trace_enabled(env)) {
            fprintf(stderr,
                    "[ia64-fpu] setf.sig ip=0x%016" PRIx64
                    " raw=0x%011" PRIx64 " f%u=r%u"
                    " value=0x%016" PRIx64 "\n",
                    env->ip, raw, f1, r2, value);
            ia64_fpu_trace_fr("setf.sig.result", env, raw, f1);
        }
        return true;
    case 1:
        ia64_write_fr_parts(env, f1, (value & (UINT64_C(1) << 17)) != 0,
                            value & 0x1ffff, IA64_FR_INTEGER_BIT);
        return true;
    case 2:
        ia64_write_fr_from_single_bits(env, f1, (uint32_t)value);
        return true;
    case 3:
        ia64_write_fr_from_double_bits(env, f1, value);
        return true;
    default:
        return false;
    }
}

bool ia64_slot_is_m_getf(IA64SlotType type, uint64_t raw)
{
    uint8_t x6;

    if (type != IA64_SLOT_TYPE_M || ia64_slot_major_opcode(raw) != 0x4) {
        return false;
    }
    if (((raw >> 27) & 0x1) == 0) {
        return false;
    }

    x6 = (raw >> 30) & 0x3f;
    return x6 >= 0x1c && x6 <= 0x1f;
}

bool ia64_exec_m_getf(CPUIA64State *env, uint64_t raw)
{
    uint8_t x6;
    uint8_t format;
    uint32_t r1;
    uint32_t f2;
    uint32_t mapped;
    uint64_t value;
    const char *mnemonic;

    if (!env || !ia64_slot_is_m_getf(IA64_SLOT_TYPE_M, raw)) {
        return false;
    }

    x6 = (raw >> 30) & 0x3f;
    format = x6 & 0x3;
    r1 = (raw >> 6) & 0x7f;
    f2 = (raw >> 13) & 0x7f;
    mapped = ia64_map_fr(env, f2);

    switch (format) {
    case 0:
        value = env->fr[mapped].raw[0];
        mnemonic = "getf.sig";
        break;
    case 1:
        value = env->fr[mapped].raw[1] & 0x3ffff;
        mnemonic = "getf.exp";
        break;
    case 2:
        value = ia64_read_fr_as_single_bits(&env->fr[mapped]);
        mnemonic = "getf.s";
        break;
    case 3:
        value = ia64_read_fr_as_double_bits(&env->fr[mapped]);
        mnemonic = "getf.d";
        break;
    default:
        return false;
    }

    ia64_write_gr(env, r1, value);
    if (ia64_fpu_trace_enabled(env)) {
        ia64_fpu_trace_fr("getf.source", env, raw, f2);
        fprintf(stderr,
                "[ia64-fpu] %s ip=0x%016" PRIx64
                " raw=0x%011" PRIx64 " r%u=f%u"
                " value=0x%016" PRIx64 "\n",
                mnemonic, env->ip, raw, r1, f2, value);
    }
    return true;
}

static int64_t ia64_fetchadd_increment(uint8_t encoded)
{
    int64_t magnitude;

    switch (encoded & 0x3) {
    case 0:
        magnitude = 16;
        break;
    case 1:
        magnitude = 8;
        break;
    case 2:
        magnitude = 4;
        break;
    case 3:
        magnitude = 1;
        break;
    default:
        g_assert_not_reached();
    }

    return (encoded & 0x4) == 0 ? magnitude : -magnitude;
}

bool ia64_decode_m_atomic(IA64SlotType type, uint64_t raw,
                          IA64AtomicInstruction *decoded)
{
    uint8_t x6;

    if (!decoded || type != IA64_SLOT_TYPE_M ||
        ia64_slot_major_opcode(raw) != 0x4 ||
        ((raw >> 27) & 0x1) == 0) {
        return false;
    }

    memset(decoded, 0, sizeof(*decoded));
    x6 = (raw >> 30) & 0x3f;
    decoded->target = (raw >> 6) & 0x7f;
    decoded->source = (raw >> 13) & 0x7f;
    decoded->base = (raw >> 20) & 0x7f;

    if (x6 <= 0x07) {
        decoded->kind = IA64_ATOMIC_CMPXCHG;
        decoded->width = 1u << (x6 & 0x3);
        decoded->release = (x6 & 0x4) != 0;
        return true;
    }

    if (x6 >= 0x08 && x6 <= 0x0b) {
        decoded->kind = IA64_ATOMIC_XCHG;
        decoded->width = 1u << (x6 - 0x08);
        return true;
    }

    if (x6 == 0x12 || x6 == 0x13 || x6 == 0x16 || x6 == 0x17) {
        decoded->kind = IA64_ATOMIC_FETCHADD;
        decoded->width = (x6 & 0x1) == 0 ? 4 : 8;
        decoded->release = (x6 & 0x4) != 0;
        decoded->immediate = ia64_fetchadd_increment((raw >> 13) & 0x7);
        return true;
    }

    return false;
}

static bool ia64_floating_memory_format(uint8_t size_code,
                                        uint8_t memory_class,
                                        IA64FloatingMemoryFormat *format,
                                        uint8_t *width)
{
    if (memory_class == 6 || memory_class == 0x0e) {
        *format = IA64_FLOAT_FMT_SPILL_FILL;
        *width = 16;
        return true;
    }

    switch (size_code) {
    case 0:
        *format = IA64_FLOAT_FMT_EXTENDED;
        *width = 16;
        return true;
    case 1:
        *format = IA64_FLOAT_FMT_SIGNIFICAND;
        *width = 8;
        return true;
    case 2:
        *format = IA64_FLOAT_FMT_SINGLE;
        *width = 4;
        return true;
    case 3:
        *format = IA64_FLOAT_FMT_DOUBLE;
        *width = 8;
        return true;
    default:
        return false;
    }
}

static bool ia64_floating_load_pair_format(uint8_t size_code,
                                           IA64FloatingMemoryFormat *format,
                                           uint8_t *width)
{
    switch (size_code) {
    case 1:
        *format = IA64_FLOAT_FMT_SIGNIFICAND;
        *width = 8;
        return true;
    case 2:
        *format = IA64_FLOAT_FMT_SINGLE;
        *width = 4;
        return true;
    case 3:
        *format = IA64_FLOAT_FMT_DOUBLE;
        *width = 8;
        return true;
    default:
        return false;
    }
}

static bool ia64_floating_load_pair_class(uint8_t memory_class)
{
    switch (memory_class) {
    case 0:
    case 1:
    case 2:
    case 3:
    case 8:
    case 9:
        return true;
    default:
        return false;
    }
}

bool ia64_decode_floating_memory(IA64SlotType type, uint64_t raw,
                                 IA64FloatingMemoryInstruction *decoded)
{
    uint8_t major;
    uint8_t x6;
    uint8_t memory_class;
    uint8_t size_code;
    uint8_t width;
    IA64FloatingMemoryFormat format;
    bool base_update_with_register;
    bool base_update_with_immediate;

    if (!decoded || type != IA64_SLOT_TYPE_M) {
        return false;
    }

    major = ia64_slot_major_opcode(raw);
    if (major != 0x6 && major != 0x7) {
        return false;
    }

    x6 = (raw >> 30) & 0x3f;
    memory_class = x6 >> 2;
    size_code = x6 & 0x3;

    if (major == 0x6 && ((raw >> 27) & 0x1) != 0) {
        if (memory_class == 7 ||
            !ia64_floating_load_pair_class(memory_class) ||
            !ia64_floating_load_pair_format(size_code, &format, &width)) {
            return false;
        }

        memset(decoded, 0, sizeof(*decoded));
        decoded->kind = IA64_FLOAT_MEM_LOAD_PAIR;
        decoded->format = format;
        decoded->width = width;
        decoded->freg = (raw >> 6) & 0x7f;
        decoded->freg2 = (raw >> 13) & 0x7f;
        decoded->base = (raw >> 20) & 0x7f;
        decoded->memory_class = memory_class;
        decoded->base_update = ((raw >> 36) & 0x1) != 0;
        decoded->immediate = decoded->width * 2;
        return true;
    }

    if (!ia64_floating_memory_format(size_code, memory_class,
                                     &format, &width)) {
        return false;
    }

    base_update_with_register = major == 0x6 && ((raw >> 36) & 0x1) != 0;
    base_update_with_immediate = major == 0x7;
    memset(decoded, 0, sizeof(*decoded));
    decoded->format = format;
    decoded->width = width;
    decoded->base = (raw >> 20) & 0x7f;
    decoded->memory_class = memory_class;
    decoded->base_update =
        base_update_with_register || base_update_with_immediate;
    decoded->update_from_register = base_update_with_register;

    if (base_update_with_immediate) {
        decoded->immediate = ia64_sign_extend(
            (((raw >> 36) & 0x1) << 8) |
            (((raw >> 27) & 0x1) << 7) |
            ((raw >> 13) & 0x7f),
            9);
    } else {
        decoded->update_source = (raw >> 13) & 0x7f;
    }

    if (memory_class == 0x0b) {
        decoded->kind = IA64_FLOAT_MEM_PREFETCH;
        decoded->freg = (raw >> 6) & 0x7f;
    } else if (memory_class == 0x0c || memory_class == 0x0e) {
        decoded->kind = IA64_FLOAT_MEM_STORE;
        decoded->freg = (raw >> 13) & 0x7f;
        if (base_update_with_immediate) {
            decoded->immediate = ia64_sign_extend(
                (((raw >> 36) & 0x1) << 8) |
                (((raw >> 27) & 0x1) << 7) |
                ((raw >> 6) & 0x7f),
                9);
        }
    } else if (memory_class == 0 || memory_class == 1 ||
               memory_class == 2 || memory_class == 3 ||
               memory_class == 6 || memory_class == 8 ||
               memory_class == 9) {
        decoded->kind = IA64_FLOAT_MEM_LOAD;
        decoded->freg = (raw >> 6) & 0x7f;
    } else {
        return false;
    }

    return true;
}

bool ia64_defer_floating_speculative_load(
    CPUIA64State *env, const IA64FloatingMemoryInstruction *decoded,
    vaddr address, bool base_nat)
{
    if (!env || !decoded ||
        (decoded->kind != IA64_FLOAT_MEM_LOAD &&
         decoded->kind != IA64_FLOAT_MEM_LOAD_PAIR)) {
        return false;
    }

    if (!ia64_control_speculative_load_defer(
            env, decoded->memory_class, base_nat, address,
            decoded->kind == IA64_FLOAT_MEM_LOAD_PAIR ? decoded->width * 2
                                                       : decoded->width,
            NULL)) {
        return false;
    }

    ia64_write_fr_natval(env, decoded->freg);
    if (decoded->kind == IA64_FLOAT_MEM_LOAD_PAIR) {
        ia64_write_fr_natval(env, decoded->freg2);
    }
    return true;
}

static uint64_t ia64_bit_mask(unsigned bits)
{
    return bits >= 64 ? UINT64_MAX : ((1ULL << bits) - 1);
}

bool ia64_decode_extract(IA64SlotType type, uint64_t raw,
                         IA64ExtractInstruction *decoded)
{
    uint8_t x2;
    uint8_t x;

    if (!decoded || type != IA64_SLOT_TYPE_I ||
        ia64_slot_major_opcode(raw) != 0x5) {
        return false;
    }

    x2 = (raw >> 34) & 0x3;
    x = (raw >> 33) & 0x1;
    if (x2 != 1 || x != 0) {
        return false;
    }

    memset(decoded, 0, sizeof(*decoded));
    decoded->target = (raw >> 6) & 0x7f;
    decoded->source3 = (raw >> 20) & 0x7f;
    decoded->position = (raw >> 14) & 0x3f;
    decoded->length = ((raw >> 27) & 0x3f) + 1;
    decoded->sign_extend = ((raw >> 13) & 0x1) != 0;
    return true;
}

bool ia64_exec_extract(CPUIA64State *env,
                       const IA64ExtractInstruction *decoded)
{
    uint8_t length;
    uint64_t value;
    uint64_t result;

    if (!env || !decoded || decoded->position >= 64) {
        return false;
    }

    length = MIN((uint8_t)(64 - decoded->position), decoded->length);
    value = ia64_read_gr(env, decoded->source3) >> decoded->position;
    result = value & ia64_bit_mask(length);
    if (decoded->sign_extend && length != 0 &&
        (result & (1ULL << (length - 1))) != 0) {
        result |= ~ia64_bit_mask(length);
    }

    ia64_write_gr(env, decoded->target, result);
    return true;
}

static uint8_t ia64_complemented_bit_position(uint64_t raw, unsigned offset)
{
    return 63 - ((raw >> offset) & 0x3f);
}

bool ia64_decode_deposit(IA64SlotType type, uint64_t raw,
                         IA64DepositInstruction *decoded)
{
    uint8_t major;
    uint8_t x2;
    uint8_t x;

    if (!decoded || type != IA64_SLOT_TYPE_I) {
        return false;
    }

    major = ia64_slot_major_opcode(raw);
    memset(decoded, 0, sizeof(*decoded));

    if (major == 0x4) {
        decoded->target = (raw >> 6) & 0x7f;
        decoded->source2 = (raw >> 13) & 0x7f;
        decoded->source3 = (raw >> 20) & 0x7f;
        decoded->position = ia64_complemented_bit_position(raw, 31);
        decoded->length = ((raw >> 27) & 0x0f) + 1;
        return true;
    }

    if (major != 0x5) {
        return false;
    }

    x2 = (raw >> 34) & 0x3;
    x = (raw >> 33) & 0x1;
    if (x2 == 1 && x == 1) {
        decoded->target = (raw >> 6) & 0x7f;
        decoded->source2 = (raw >> 13) & 0x7f;
        decoded->position = ia64_complemented_bit_position(raw, 20);
        decoded->length = ((raw >> 27) & 0x3f) + 1;
        decoded->deposit_zero = true;
        decoded->source_immediate = ((raw >> 26) & 0x1) != 0;
        if (decoded->source_immediate) {
            decoded->immediate = (uint64_t)ia64_sign_extend(
                (((raw >> 36) & 0x1) << 7) | decoded->source2, 8);
            decoded->source2 = 0;
        }
        return true;
    }

    if (x2 == 3 && x == 1) {
        decoded->target = (raw >> 6) & 0x7f;
        decoded->source3 = (raw >> 20) & 0x7f;
        decoded->position = ia64_complemented_bit_position(raw, 14);
        decoded->length = ((raw >> 27) & 0x3f) + 1;
        decoded->source_immediate = true;
        decoded->immediate = (uint64_t)ia64_sign_extend((raw >> 36) & 0x1,
                                                        1);
        return true;
    }

    return false;
}

bool ia64_exec_deposit(CPUIA64State *env,
                       const IA64DepositInstruction *decoded)
{
    uint8_t length;
    uint64_t source;
    uint64_t base;
    uint64_t mask;
    uint64_t field;

    if (!env || !decoded || decoded->position >= 64) {
        return false;
    }

    length = MIN((uint8_t)(64 - decoded->position), decoded->length);
    source = decoded->source_immediate
        ? decoded->immediate
        : ia64_read_gr(env, decoded->source2);
    base = decoded->deposit_zero ? 0 : ia64_read_gr(env, decoded->source3);
    mask = ia64_bit_mask(length) << decoded->position;
    field = (source & ia64_bit_mask(length)) << decoded->position;

    ia64_write_gr(env, decoded->target, (base & ~mask) | field);
    return true;
}

bool ia64_slot_is_i_shift_right_pair(IA64SlotType type, uint64_t raw)
{
    if (type != IA64_SLOT_TYPE_I || ia64_slot_major_opcode(raw) != 0x5) {
        return false;
    }

    return ((raw >> 34) & 0x3) == 3 &&
           ((raw >> 33) & 0x1) == 0;
}

bool ia64_exec_i_shift_right_pair(CPUIA64State *env, uint64_t raw)
{
    uint32_t r1;
    uint32_t r2;
    uint32_t r3;
    uint8_t count;
    uint64_t high;
    uint64_t low;
    uint64_t result;

    if (!env || !ia64_slot_is_i_shift_right_pair(IA64_SLOT_TYPE_I, raw)) {
        return false;
    }

    r1 = (raw >> 6) & 0x7f;
    r2 = (raw >> 13) & 0x7f;
    r3 = (raw >> 20) & 0x7f;
    count = (raw >> 27) & 0x3f;
    high = ia64_read_gr(env, r2);
    low = ia64_read_gr(env, r3);
    result = count == 0 ? low : (low >> count) | (high << (64 - count));

    ia64_write_gr(env, r1, result);
    return true;
}

bool ia64_decode_integer_extend(IA64SlotType type, uint64_t raw,
                                IA64IntegerExtendInstruction *decoded)
{
    uint8_t x6;

    if (!decoded || type != IA64_SLOT_TYPE_I ||
        ia64_slot_major_opcode(raw) != 0x0 ||
        ((raw >> 33) & 0x7) != 0) {
        return false;
    }

    x6 = (raw >> 27) & 0x3f;
    memset(decoded, 0, sizeof(*decoded));
    decoded->target = (raw >> 6) & 0x7f;
    decoded->source3 = (raw >> 20) & 0x7f;

    switch (x6) {
    case 0x10:
    case 0x11:
    case 0x12:
        decoded->kind = IA64_EXT_ZXT;
        decoded->width = x6 == 0x10 ? 1 : x6 == 0x11 ? 2 : 4;
        return true;
    case 0x14:
    case 0x15:
    case 0x16:
        decoded->kind = IA64_EXT_SXT;
        decoded->width = x6 == 0x14 ? 1 : x6 == 0x15 ? 2 : 4;
        return true;
    case 0x18:
    case 0x19:
        decoded->kind = IA64_EXT_CZX_LEFT;
        decoded->width = x6 == 0x18 ? 1 : 2;
        return true;
    case 0x1c:
    case 0x1d:
        decoded->kind = IA64_EXT_CZX_RIGHT;
        decoded->width = x6 == 0x1c ? 1 : 2;
        return true;
    default:
        return false;
    }
}

static uint64_t ia64_compute_zero_index(uint64_t value, uint8_t width,
                                        bool from_left)
{
    unsigned element_bits = width * 8;
    unsigned elements = 8 / width;
    uint64_t mask = ia64_bit_mask(element_bits);

    for (unsigned index = 0; index < elements; index++) {
        unsigned lane = from_left ? elements - index - 1 : index;
        if (((value >> (lane * element_bits)) & mask) == 0) {
            return index;
        }
    }

    return elements;
}

bool ia64_exec_integer_extend(CPUIA64State *env,
                              const IA64IntegerExtendInstruction *decoded)
{
    uint64_t value;
    uint64_t result;

    if (!env || !decoded || decoded->width == 0) {
        return false;
    }

    value = ia64_read_gr(env, decoded->source3);
    switch (decoded->kind) {
    case IA64_EXT_ZXT:
        result = value & ia64_bit_mask(decoded->width * 8);
        break;
    case IA64_EXT_SXT:
        result = (uint64_t)ia64_sign_extend(value, decoded->width * 8);
        break;
    case IA64_EXT_CZX_LEFT:
        result = ia64_compute_zero_index(value, decoded->width, true);
        break;
    case IA64_EXT_CZX_RIGHT:
        result = ia64_compute_zero_index(value, decoded->width, false);
        break;
    default:
        return false;
    }

    ia64_write_gr(env, decoded->target, result);
    return true;
}

bool ia64_slot_is_f_select_or_xma(IA64SlotType type, uint64_t raw)
{
    uint8_t x;
    uint8_t x2;

    if (type != IA64_SLOT_TYPE_F || ia64_slot_major_opcode(raw) != 0xe) {
        return false;
    }

    x = (raw >> 36) & 0x1;
    x2 = (raw >> 34) & 0x3;
    return x == 0 || x2 == 0 || x2 == 2 || x2 == 3;
}

bool ia64_slot_is_f_multiply_add(IA64SlotType type, uint64_t raw)
{
    uint8_t major = ia64_slot_major_opcode(raw);

    return type == IA64_SLOT_TYPE_F && major >= 0x8 && major <= 0xd;
}

typedef enum IA64FmaPrecisionCompleter {
    IA64_FMA_PC_DYNAMIC,
    IA64_FMA_PC_SINGLE,
    IA64_FMA_PC_DOUBLE,
} IA64FmaPrecisionCompleter;

static bool ia64_fma_scalar_precision(uint64_t raw,
                                      IA64FmaPrecisionCompleter *pc)
{
    uint8_t major = ia64_slot_major_opcode(raw);
    bool x = ((raw >> 36) & 0x1) != 0;

    if (major < 0x8 || major > 0xd) {
        return false;
    }

    if ((major & 0x1) != 0) {
        if (x) {
            return false;
        }
        *pc = IA64_FMA_PC_DOUBLE;
    } else {
        *pc = x ? IA64_FMA_PC_SINGLE : IA64_FMA_PC_DYNAMIC;
    }
    return true;
}

static void ia64_write_fr_from_fma_result(CPUIA64State *env, uint32_t reg,
                                          floatx80 value,
                                          IA64FmaPrecisionCompleter pc,
                                          uint8_t sf)
{
    float_status status = { 0 };

    ia64_float_status_init_for_sf(env, &status, sf);

    switch (pc) {
    case IA64_FMA_PC_SINGLE:
        ia64_write_fr_from_single_bits(env, reg,
                                       float32_val(
                                           floatx80_to_float32(value,
                                                               &status)));
        return;
    case IA64_FMA_PC_DOUBLE:
        ia64_write_fr_from_double_bits(env, reg,
                                       float64_val(
                                           floatx80_to_float64(value,
                                                               &status)));
        return;
    case IA64_FMA_PC_DYNAMIC:
        ia64_write_fr_from_floatx80(env, reg, value);
        return;
    default:
        g_assert_not_reached();
    }
}

bool ia64_exec_f_multiply_add(CPUIA64State *env, uint64_t raw)
{
    uint8_t major;
    uint8_t sf;
    uint32_t f1;
    uint32_t f2;
    uint32_t f3;
    uint32_t f4;
    IA64FmaPrecisionCompleter pc;
    float_status status = { 0 };
    floatx80 addend;
    floatx80 multiplicand;
    floatx80 multiplier;
    floatx80 product;
    floatx80 result;

    if (!env || !ia64_slot_is_f_multiply_add(IA64_SLOT_TYPE_F, raw) ||
        !ia64_fma_scalar_precision(raw, &pc)) {
        return false;
    }

    major = ia64_slot_major_opcode(raw);
    sf = (raw >> 34) & 0x3;
    f1 = (raw >> 6) & 0x7f;
    f2 = (raw >> 13) & 0x7f;
    f3 = (raw >> 20) & 0x7f;
    f4 = (raw >> 27) & 0x7f;
    ia64_float_status_init_for_sf(env, &status, sf);

    addend = ia64_fr_to_floatx80(&env->fr[ia64_map_fr(env, f2)]);
    multiplicand = ia64_fr_to_floatx80(&env->fr[ia64_map_fr(env, f3)]);
    multiplier = ia64_fr_to_floatx80(&env->fr[ia64_map_fr(env, f4)]);
    product = floatx80_mul(multiplicand, multiplier, &status);

    switch (major) {
    case 0x8:
    case 0x9:
        result = floatx80_add(product, addend, &status);
        break;
    case 0x0a:
    case 0x0b:
        result = floatx80_sub(product, addend, &status);
        break;
    case 0x0c:
    case 0x0d:
        result = floatx80_sub(addend, product, &status);
        break;
    default:
        return false;
    }

    ia64_write_fr_from_fma_result(env, f1, result, pc, sf);
    if (ia64_fpu_trace_enabled(env)) {
        fprintf(stderr,
                "[ia64-fpu] fma-family ip=0x%016" PRIx64
                " raw=0x%011" PRIx64 " f%u=f%u,f%u,f%u"
                " pc=%u sf=%u"
                " addend=0x%04x:%016" PRIx64
                " multiplicand=0x%04x:%016" PRIx64
                " multiplier=0x%04x:%016" PRIx64
                " result=0x%04x:%016" PRIx64
                " pr=0x%016" PRIx64 "\n",
                env->ip, raw, f1, f2, f3, f4, pc, sf,
                addend.high, addend.low,
                multiplicand.high, multiplicand.low, multiplier.high,
                multiplier.low, result.high, result.low, env->pr);
        ia64_fpu_trace_fr("fma-family.result", env, raw, f1);
    }
    return true;
}

bool ia64_slot_is_f_reciprocal_approx(IA64SlotType type, uint64_t raw)
{
    uint8_t major = ia64_slot_major_opcode(raw);

    if (type != IA64_SLOT_TYPE_F || (major != 0x0 && major != 0x1)) {
        return false;
    }

    return ((raw >> 33) & 0x1) != 0;
}

bool ia64_exec_f_reciprocal_approx(CPUIA64State *env, uint64_t raw)
{
    uint32_t f1;
    uint32_t f2;
    uint32_t f3;
    uint8_t p2;
    bool q;
    IA64FloatReg numerator = { 0 };
    IA64FloatReg denominator;
    float_status status = { 0 };
    floatx80 numerator80;
    floatx80 denominator80;
    floatx80 result;
    bool predicate;

    if (!env || !ia64_slot_is_f_reciprocal_approx(IA64_SLOT_TYPE_F, raw)) {
        return false;
    }
    ia64_float_status_init(&status);

    f1 = (raw >> 6) & 0x7f;
    q = ((raw >> 36) & 0x1) != 0;
    f2 = q ? 0 : (raw >> 13) & 0x7f;
    f3 = (raw >> 20) & 0x7f;
    p2 = (raw >> 27) & 0x3f;

    denominator = env->fr[ia64_map_fr(env, f3)];
    if (ia64_fr_is_natval(&denominator)) {
        ia64_write_fr_natval(env, f1);
        ia64_write_pr(env, p2, false);
        return true;
    }
    denominator80 = ia64_fr_to_floatx80(&denominator);

    if (q) {
        predicate = ia64_fr_is_finite_nonzero(&denominator) &&
                    !ia64_fr_sign(&denominator);
        result = floatx80_div(floatx80_one,
                              floatx80_sqrt(denominator80, &status),
                              &status);
    } else {
        numerator = env->fr[ia64_map_fr(env, f2)];
        if (ia64_fr_is_natval(&numerator)) {
            ia64_write_fr_natval(env, f1);
            ia64_write_pr(env, p2, false);
            return true;
        }
        numerator80 = ia64_fr_to_floatx80(&numerator);

        predicate = ia64_fr_is_finite_nonzero(&numerator) &&
                    ia64_fr_is_finite_nonzero(&denominator);
        result = predicate
            ? floatx80_div(floatx80_one, denominator80, &status)
            : floatx80_div(numerator80, denominator80, &status);
    }

    ia64_write_fr_from_floatx80(env, f1, result);
    ia64_write_pr(env, p2, predicate);
    if (ia64_fpu_trace_enabled(env)) {
        fprintf(stderr,
                "[ia64-fpu] frcpa ip=0x%016" PRIx64
                " raw=0x%011" PRIx64 " f%u,p%u=f%u,f%u"
                " numerator=0x%016" PRIx64 ":%05" PRIx64
                " denominator=0x%016" PRIx64 ":%05" PRIx64
                " result=0x%04x:%016" PRIx64
                " predicate=%u pr=0x%016" PRIx64 "\n",
                env->ip, raw, f1, p2, f2, f3, numerator.raw[0],
                numerator.raw[1], denominator.raw[0], denominator.raw[1],
                result.high, result.low, predicate, env->pr);
        ia64_fpu_trace_fr("frcpa.result", env, raw, f1);
    }
    return true;
}

bool ia64_slot_is_f_misc(IA64SlotType type, uint64_t raw)
{
    uint8_t major = ia64_slot_major_opcode(raw);
    uint8_t x;
    uint8_t x6;

    if (type != IA64_SLOT_TYPE_F || major != 0x0) {
        return false;
    }

    x = (raw >> 33) & 0x1;
    x6 = (raw >> 27) & 0x3f;
    if (x != 0) {
        return false;
    }

    return x6 == 0x01 || x6 == 0x05 ||
           (x6 >= 0x10 && x6 <= 0x12) ||
           (x6 >= 0x14 && x6 <= 0x17) ||
           (x6 >= 0x18 && x6 <= 0x1c) ||
           x6 == 0x28 ||
           (x6 >= 0x2c && x6 <= 0x2f) ||
           (x6 >= 0x34 && x6 <= 0x36) ||
           (x6 >= 0x39 && x6 <= 0x3d);
}

static const IA64FloatReg *ia64_f_minmax_select(const IA64FloatReg *source2,
                                                const IA64FloatReg *source3,
                                                uint8_t x6,
                                                float_status *status)
{
    bool maximum = x6 == 0x15 || x6 == 0x17;
    bool absolute = x6 == 0x16 || x6 == 0x17;
    floatx80 left;
    floatx80 right;

    if (ia64_fr_is_nan(source2) || ia64_fr_is_nan(source3)) {
        return source3;
    }

    left = ia64_fr_to_floatx80(source2);
    right = ia64_fr_to_floatx80(source3);
    if (absolute) {
        left = floatx80_abs(left);
        right = floatx80_abs(right);
    }

    if (maximum) {
        return floatx80_compare_quiet(right, left, status) ==
               float_relation_less ? source2 : source3;
    }
    return floatx80_compare_quiet(left, right, status) ==
           float_relation_less ? source2 : source3;
}

bool ia64_exec_f_misc(CPUIA64State *env, uint64_t raw)
{
    uint8_t x6;
    uint8_t sf;
    uint32_t f1;
    uint32_t f2;
    uint32_t f3;
    uint32_t target;
    uint32_t source2;
    uint32_t source3;
    bool sign;
    uint64_t exponent;

    if (!env || !ia64_slot_is_f_misc(IA64_SLOT_TYPE_F, raw)) {
        return false;
    }

    x6 = (raw >> 27) & 0x3f;
    sf = (raw >> 34) & 0x3;
    f1 = (raw >> 6) & 0x7f;
    f2 = (raw >> 13) & 0x7f;
    f3 = (raw >> 20) & 0x7f;

    if (x6 == 0x01) {
        return true;
    }

    if (x6 == 0x05) {
        const uint64_t flags_mask =
            UINT64_C(0x3f) <<
            (IA64_FPSR_STATUS_FIELD_SHIFT(sf) + 7);
        uint64_t old_fpsr = env->ar[IA64_AR_FPSR];

        env->ar[IA64_AR_FPSR] &= ~flags_mask;
        if (ia64_fpu_trace_enabled(env)) {
            fprintf(stderr,
                    "[ia64-fpu] fclrf ip=0x%016" PRIx64
                    " raw=0x%011" PRIx64 " sf=%u"
                    " old-fpsr=0x%016" PRIx64
                    " new-fpsr=0x%016" PRIx64 "\n",
                    env->ip, raw, sf, old_fpsr,
                    env->ar[IA64_AR_FPSR]);
        }
        return true;
    }

    if (x6 >= 0x14 && x6 <= 0x17) {
        const IA64FloatReg *source2_reg;
        const IA64FloatReg *source3_reg;
        const IA64FloatReg *selected;
        float_status status = { 0 };

        if (f1 >= IA64_FR_COUNT || f1 < 2 ||
            f2 >= IA64_FR_COUNT || f3 >= IA64_FR_COUNT) {
            return true;
        }

        source2_reg = &env->fr[ia64_map_fr(env, f2)];
        source3_reg = &env->fr[ia64_map_fr(env, f3)];
        if (ia64_fr_is_natval(source2_reg) ||
            ia64_fr_is_natval(source3_reg)) {
            ia64_write_fr_natval(env, f1);
            return true;
        }

        ia64_float_status_init_for_sf(env, &status, sf);
        selected = ia64_f_minmax_select(source2_reg, source3_reg, x6,
                                        &status);
        env->fr[ia64_map_fr(env, f1)] = *selected;
        ia64_note_fr_write(env, f1);
        if (ia64_fpu_trace_enabled(env)) {
            fprintf(stderr,
                    "[ia64-fpu] minmax ip=0x%016" PRIx64
                    " raw=0x%011" PRIx64 " x6=0x%02x f%u=f%u,f%u"
                    " selected=f%u result=0x%016" PRIx64 ":%05" PRIx64
                    "\n",
                    env->ip, raw, x6, f1, f2, f3,
                    selected == source2_reg ? f2 : f3,
                    selected->raw[0], selected->raw[1]);
            ia64_fpu_trace_fr("minmax.result", env, raw, f1);
        }
        return true;
    }

    if (x6 == 0x28 ||
        (x6 >= 0x2c && x6 <= 0x2f) ||
        (x6 >= 0x34 && x6 <= 0x36) ||
        (x6 >= 0x39 && x6 <= 0x3d)) {
        const IA64FloatReg *source2_reg;
        const IA64FloatReg *source3_reg;
        uint64_t source2_sig;
        uint64_t source3_sig;
        uint64_t result;

        if (f1 >= IA64_FR_COUNT || f1 < 2 ||
            f2 >= IA64_FR_COUNT || f3 >= IA64_FR_COUNT) {
            return true;
        }

        source2_reg = &env->fr[ia64_map_fr(env, f2)];
        source3_reg = &env->fr[ia64_map_fr(env, f3)];
        if (ia64_fr_is_natval(source2_reg) ||
            ia64_fr_is_natval(source3_reg)) {
            ia64_write_fr_natval(env, f1);
            return true;
        }

        source2_sig = source2_reg->raw[0];
        source3_sig = source3_reg->raw[0];
        switch (x6) {
        case 0x28:
            result = ia64_float_packed_pair(
                ia64_read_fr_as_single_bits(source2_reg),
                ia64_read_fr_as_single_bits(source3_reg));
            break;
        case 0x2c:
            result = source2_sig & source3_sig;
            break;
        case 0x2d:
            result = source2_sig & ~source3_sig;
            break;
        case 0x2e:
            result = source2_sig | source3_sig;
            break;
        case 0x2f:
            result = source2_sig ^ source3_sig;
            break;
        case 0x34:
            result = ia64_float_packed_pair(
                ia64_float_packed_low32(source3_sig),
                ia64_float_packed_high32(source2_sig));
            break;
        case 0x35:
            result = ia64_float_packed_pair(
                ia64_float_packed_negate_single(
                    ia64_float_packed_low32(source3_sig)),
                ia64_float_packed_high32(source2_sig));
            break;
        case 0x36:
            result = ia64_float_packed_pair(
                ia64_float_packed_low32(source3_sig),
                ia64_float_packed_negate_single(
                    ia64_float_packed_high32(source2_sig)));
            break;
        case 0x39:
            result = ia64_float_packed_pair(
                ia64_float_packed_high32(source2_sig),
                ia64_float_packed_low32(source3_sig));
            break;
        case 0x3a:
            result = ia64_float_packed_pair(
                ia64_float_packed_low32(source2_sig),
                ia64_float_packed_low32(source3_sig));
            break;
        case 0x3b:
            result = ia64_float_packed_pair(
                ia64_float_packed_high32(source2_sig),
                ia64_float_packed_high32(source3_sig));
            break;
        case 0x3c:
            result = ia64_float_packed_pair(
                ia64_float_packed_extend_single_sign(
                    ia64_float_packed_low32(source2_sig)),
                ia64_float_packed_low32(source3_sig));
            break;
        case 0x3d:
            result = ia64_float_packed_pair(
                ia64_float_packed_extend_single_sign(
                    ia64_float_packed_high32(source2_sig)),
                ia64_float_packed_high32(source3_sig));
            break;
        default:
            return false;
        }

        ia64_write_fr_significand(env, f1, result);
        if (ia64_fpu_trace_enabled(env)) {
            fprintf(stderr,
                    "[ia64-fpu] packed-misc ip=0x%016" PRIx64
                    " raw=0x%011" PRIx64 " x6=0x%02x f%u=f%u,f%u"
                    " source2=0x%016" PRIx64 " source3=0x%016" PRIx64
                    " result=0x%016" PRIx64 "\n",
                    env->ip, raw, x6, f1, f2, f3, source2_sig,
                    source3_sig, result);
            ia64_fpu_trace_fr("packed-misc.result", env, raw, f1);
        }
        return true;
    }

    if (x6 >= 0x18 && x6 <= 0x1c) {
        const IA64FloatReg *source = &env->fr[ia64_map_fr(env, f2)];
        bool unsigned_form = x6 == 0x19 || x6 == 0x1b;
        bool truncate = x6 == 0x1a || x6 == 0x1b;

        if (ia64_fr_is_natval(source)) {
            ia64_write_fr_natval(env, f1);
        } else if (x6 == 0x1c) {
            float_status status = { 0 };

            ia64_float_status_init(&status);
            ia64_write_fr_from_floatx80(
                env, f1, int64_to_floatx80((int64_t)source->raw[0],
                                            &status));
        } else {
            uint64_t fixed = ia64_float_reg_to_fixed(source, unsigned_form,
                                                     truncate);

            ia64_write_fr_significand(
                env, f1, fixed);
            if (ia64_fpu_trace_enabled(env)) {
                fprintf(stderr,
                        "[ia64-fpu] fcvt.fixed ip=0x%016" PRIx64
                        " raw=0x%011" PRIx64 " f%u=f%u"
                        " unsigned=%u trunc=%u source=0x%016" PRIx64
                        ":%05" PRIx64
                        " fixed=0x%016" PRIx64 "\n",
                        env->ip, raw, f1, f2, unsigned_form, truncate,
                        source->raw[0], source->raw[1], fixed);
                ia64_fpu_trace_fr("fcvt.fixed.result", env, raw, f1);
            }
        }
        return true;
    }

    if (f1 >= IA64_FR_COUNT || f1 < 2 ||
        f2 >= IA64_FR_COUNT || f3 >= IA64_FR_COUNT) {
        return true;
    }

    target = ia64_map_fr(env, f1);
    source2 = ia64_map_fr(env, f2);
    source3 = ia64_map_fr(env, f3);
    sign = (env->fr[source2].raw[1] >> 17) & 1;
    if (x6 == 0x11) {
        sign = !sign;
    }
    exponent = x6 == 0x12
        ? env->fr[source2].raw[1] & 0x1ffff
        : env->fr[source3].raw[1] & 0x1ffff;

    env->fr[target].raw[0] = env->fr[source3].raw[0];
    env->fr[target].raw[1] = exponent | ((uint64_t)sign << 17);
    ia64_note_fr_write(env, f1);
    return true;
}

bool ia64_exec_f_select_or_xma(CPUIA64State *env, uint64_t raw)
{
    uint8_t x;
    uint8_t x2;
    uint32_t f1;
    uint32_t f2;
    uint32_t f3;
    uint32_t f4;
    uint64_t source2;
    uint64_t source3;
    uint64_t source4;
    uint64_t result;

    if (!env || !ia64_slot_is_f_select_or_xma(IA64_SLOT_TYPE_F, raw)) {
        return false;
    }

    x = (raw >> 36) & 0x1;
    x2 = (raw >> 34) & 0x3;
    f1 = (raw >> 6) & 0x7f;
    f2 = (raw >> 13) & 0x7f;
    f3 = (raw >> 20) & 0x7f;
    f4 = (raw >> 27) & 0x7f;
    source2 = ia64_read_fr_significand(env, f2);
    source3 = ia64_read_fr_significand(env, f3);
    source4 = ia64_read_fr_significand(env, f4);

    if (x == 0) {
        result = (source3 & source2) | (source4 & ~source2);
    } else if (x2 == 0) {
        __int128 product =
            (__int128)(int64_t)source3 * (__int128)(int64_t)source4;
        result = (uint64_t)(product + source2);
    } else if (x2 == 2) {
        unsigned __int128 product =
            (unsigned __int128)source3 * (unsigned __int128)source4;
        result = (uint64_t)((product + source2) >> 64);
    } else {
        __int128 product =
            (__int128)(int64_t)source3 * (__int128)(int64_t)source4;
        result = (uint64_t)((product + source2) >> 64);
    }

    ia64_write_fr_significand(env, f1, result);
    if (ia64_fpu_trace_enabled(env)) {
        fprintf(stderr,
                "[ia64-fpu] select-xma ip=0x%016" PRIx64
                " raw=0x%011" PRIx64 " f%u=f%u,f%u,f%u"
                " x=%u x2=%u source2=0x%016" PRIx64
                " source3=0x%016" PRIx64 " source4=0x%016" PRIx64
                " result=0x%016" PRIx64 "\n",
                env->ip, raw, f1, f2, f3, f4, x, x2, source2,
                source3, source4, result);
        ia64_fpu_trace_fr("select-xma.result", env, raw, f1);
    }
    return true;
}

bool ia64_decode_ldst_immediate(IA64SlotType type, uint64_t raw,
                                IA64LdstImmediate *decoded)
{
    uint8_t major = ia64_slot_major_opcode(raw);
    uint8_t x6;
    uint8_t memory_class;
    uint8_t size_code;
    bool update_from_register;
    bool update_from_immediate;
    bool load_like;
    bool store_like;

    if (!decoded || type != IA64_SLOT_TYPE_M ||
        (major != 0x4 && major != 0x5)) {
        return false;
    }
    if (major == 0x4 && ((raw >> 27) & 0x1) != 0) {
        return false;
    }

    memset(decoded, 0, sizeof(*decoded));
    x6 = (raw >> 30) & 0x3f;
    memory_class = x6 >> 2;
    size_code = x6 & 0x3;
    update_from_register = major == 0x4 && ((raw >> 36) & 0x1) != 0;
    update_from_immediate = major == 0x5;
    load_like = memory_class == 0 || memory_class == 1 ||
                memory_class == 2 || memory_class == 3 ||
                memory_class == 4 || memory_class == 5 ||
                (memory_class == 6 && size_code == 3) ||
                memory_class == 8 || memory_class == 9 ||
                memory_class == 0x0a;
    store_like = memory_class == 0x0c || memory_class == 0x0d ||
                 (memory_class == 0x0e && size_code == 3);

    decoded->width = 1u << size_code;
    decoded->target = (raw >> 6) & 0x7f;
    decoded->source = (raw >> 13) & 0x7f;
    decoded->base = (raw >> 20) & 0x7f;
    decoded->update_source = decoded->source;
    decoded->memory_class = memory_class;
    decoded->base_update = update_from_register || update_from_immediate;
    decoded->update_from_register = update_from_register;

    if (update_from_immediate) {
        decoded->immediate = ia64_sign_extend((((raw >> 36) & 0x1) << 8) |
                                              (((raw >> 27) & 0x1) << 7) |
                                              ((raw >> 13) & 0x7f), 9);
    }

    if (memory_class == 0x0b) {
        decoded->kind = IA64_LDST_IMM_PREFETCH;
        return true;
    }
    if (load_like) {
        decoded->kind = IA64_LDST_IMM_LOAD;
        return true;
    }
    if (store_like) {
        if (update_from_register) {
            return false;
        }
        decoded->kind = IA64_LDST_IMM_STORE;
        if (update_from_immediate) {
            decoded->immediate =
                ia64_sign_extend((((raw >> 36) & 0x1) << 8) |
                                 (((raw >> 27) & 0x1) << 7) |
                                 ((raw >> 6) & 0x7f), 9);
        }
        return true;
    }

    return false;
}

bool ia64_decode_counted_store_loop(const IA64DecodedBundle *bundle,
                                    uint64_t bundle_ip,
                                    IA64CountedStoreLoop *decoded)
{
    IA64LdstImmediate store;
    uint64_t branch_raw;

    if (!bundle || !decoded || !bundle->valid ||
        bundle->info->slot_type[0] != IA64_SLOT_TYPE_M ||
        bundle->info->slot_type[1] != IA64_SLOT_TYPE_I ||
        bundle->info->slot_type[2] != IA64_SLOT_TYPE_B) {
        return false;
    }

    if (ia64_slot_predicate(bundle->slot[0]) != 0 ||
        ia64_slot_predicate(bundle->slot[1]) != 0 ||
        ia64_slot_predicate(bundle->slot[2]) != 0 ||
        bundle->slot[1] != IA64_INSN_NOP_RAW) {
        return false;
    }

    if (!ia64_decode_ldst_immediate(IA64_SLOT_TYPE_M, bundle->slot[0],
                                    &store) ||
        store.kind != IA64_LDST_IMM_STORE ||
        !store.base_update ||
        store.update_from_register ||
        store.source == store.base) {
        return false;
    }

    branch_raw = bundle->slot[2];
    if (!ia64_slot_is_b_branch_relative(IA64_SLOT_TYPE_B, branch_raw) ||
        ((branch_raw >> 6) & 0x7) != 5 ||
        ia64_branch_displacement(branch_raw) != 0) {
        return false;
    }

    memset(decoded, 0, sizeof(*decoded));
    decoded->store = store;
    decoded->fallthrough_ip = bundle_ip + IA64_BUNDLE_SIZE;
    return true;
}

static IA64CompareRelation ia64_normal_compare_relation(uint8_t major)
{
    switch (major) {
    case 0xc:
        return IA64_CMP_LT;
    case 0xd:
        return IA64_CMP_LTU;
    case 0xe:
        return IA64_CMP_EQ;
    default:
        g_assert_not_reached();
    }
}

static IA64PredicateWriteKind ia64_parallel_compare_write_kind(uint8_t major)
{
    switch (major) {
    case 0xc:
        return IA64_PRED_WRITE_AND;
    case 0xd:
        return IA64_PRED_WRITE_OR;
    case 0xe:
        return IA64_PRED_WRITE_OR_ANDCM;
    default:
        g_assert_not_reached();
    }
}

static IA64CompareRelation ia64_compare_to_zero_relation(uint8_t ta, uint8_t c)
{
    if (ta == 0 && c == 0) {
        return IA64_CMP_GT;
    }
    if (ta == 0 && c == 1) {
        return IA64_CMP_LE;
    }
    if (ta == 1 && c == 0) {
        return IA64_CMP_GE;
    }
    return IA64_CMP_LT;
}

static bool ia64_decode_predicate_write_kind(uint8_t ta, uint8_t tb,
                                             uint8_t c,
                                             IA64PredicateWriteKind *write_kind,
                                             IA64PredicateTestRelation *relation)
{
    if (!write_kind || !relation) {
        return false;
    }

    if (ta == 0 && tb == 0) {
        *write_kind = c == 0 ? IA64_PRED_WRITE_NORMAL
                             : IA64_PRED_WRITE_UNCONDITIONAL;
    } else if (ta == 0 && tb == 1) {
        *write_kind = IA64_PRED_WRITE_AND;
    } else if (ta == 1 && tb == 0) {
        *write_kind = IA64_PRED_WRITE_OR;
    } else {
        *write_kind = IA64_PRED_WRITE_OR_ANDCM;
    }

    *relation = (*write_kind == IA64_PRED_WRITE_NORMAL ||
                 *write_kind == IA64_PRED_WRITE_UNCONDITIONAL ||
                 c == 0)
        ? IA64_PRED_TEST_ZERO
        : IA64_PRED_TEST_NONZERO;
    return true;
}

bool ia64_decode_predicate_test(IA64SlotType type, uint64_t raw,
                                IA64PredicateTestInstruction *decoded)
{
    uint8_t major = ia64_slot_major_opcode(raw);
    uint8_t x2;
    uint8_t ta;
    uint8_t tb;
    uint8_t c;
    uint8_t y;
    uint8_t x;
    uint8_t position;
    uint8_t r3;

    if (!decoded || type != IA64_SLOT_TYPE_I || major != 0x5) {
        return false;
    }

    x2 = (raw >> 34) & 0x3;
    if (x2 != 0) {
        return false;
    }

    memset(decoded, 0, sizeof(*decoded));
    ta = (raw >> 33) & 0x1;
    tb = (raw >> 36) & 0x1;
    c = (raw >> 12) & 0x1;
    y = (raw >> 13) & 0x1;
    x = (raw >> 19) & 0x1;
    position = (raw >> 14) & 0x3f;
    r3 = (raw >> 20) & 0x7f;

    if (!ia64_decode_predicate_write_kind(ta, tb, c,
                                          &decoded->write_kind,
                                          &decoded->relation)) {
        return false;
    }

    decoded->p1 = (raw >> 6) & 0x3f;
    decoded->p2 = (raw >> 27) & 0x3f;
    decoded->source3 = r3;

    if (y == 0) {
        decoded->kind = IA64_PRED_TEST_BIT;
        decoded->immediate = position;
        return true;
    }
    if (x == 0 && ((raw >> 14) & 0x1f) == 0) {
        decoded->kind = IA64_PRED_TEST_NAT;
        decoded->immediate = 0;
        return true;
    }
    if (x == 1 && r3 == 0) {
        decoded->kind = IA64_PRED_TEST_FEATURE;
        decoded->immediate = 32 + ((raw >> 14) & 0x1f);
        return true;
    }

    return false;
}

bool ia64_decode_compare(IA64SlotType type, uint64_t raw,
                         IA64CompareInstruction *decoded)
{
    uint8_t major = ia64_slot_major_opcode(raw);
    uint8_t x2;
    uint8_t tb;
    uint8_t ta;
    uint8_t c;
    uint8_t r2;

    if (!decoded || (type != IA64_SLOT_TYPE_M && type != IA64_SLOT_TYPE_I) ||
        (major < 0xc || major > 0xe)) {
        return false;
    }

    memset(decoded, 0, sizeof(*decoded));
    x2 = (raw >> 34) & 0x3;
    tb = (raw >> 36) & 0x1;
    ta = (raw >> 33) & 0x1;
    c = (raw >> 12) & 0x1;
    r2 = (raw >> 13) & 0x7f;

    decoded->p1 = (raw >> 6) & 0x3f;
    decoded->p2 = (raw >> 27) & 0x3f;
    decoded->source2 = r2;
    decoded->source3 = (raw >> 20) & 0x7f;

    if (x2 == 0 || x2 == 1) {
        decoded->width = x2 == 1 ? 4 : 8;
        if (tb == 0 && ta == 0) {
            decoded->write_kind = c == 0 ? IA64_PRED_WRITE_NORMAL
                                         : IA64_PRED_WRITE_UNCONDITIONAL;
            decoded->relation = ia64_normal_compare_relation(major);
            return true;
        }
        if (tb == 0 && ta == 1) {
            decoded->write_kind = ia64_parallel_compare_write_kind(major);
            decoded->relation = c == 0 ? IA64_CMP_EQ : IA64_CMP_NE;
            return true;
        }
        if (tb == 1 && r2 == 0) {
            decoded->write_kind = ia64_parallel_compare_write_kind(major);
            decoded->relation = ia64_compare_to_zero_relation(ta, c);
            return true;
        }
        return false;
    }

    decoded->width = x2 == 3 ? 4 : 8;
    decoded->source_immediate = true;
    decoded->immediate = ia64_sign_extend(((uint64_t)tb << 7) | r2, 8);
    if (ta == 0) {
        decoded->write_kind = c == 0 ? IA64_PRED_WRITE_NORMAL
                                     : IA64_PRED_WRITE_UNCONDITIONAL;
        decoded->relation = ia64_normal_compare_relation(major);
        return true;
    }
    decoded->write_kind = ia64_parallel_compare_write_kind(major);
    decoded->relation = c == 0 ? IA64_CMP_EQ : IA64_CMP_NE;
    return true;
}

bool ia64_decode_floating_compare(IA64SlotType type, uint64_t raw,
                                  IA64FloatingCompareInstruction *decoded)
{
    uint8_t major = ia64_slot_major_opcode(raw);
    uint8_t ra;
    uint8_t rb;

    if (!decoded || type != IA64_SLOT_TYPE_F || major != 0x4) {
        return false;
    }

    memset(decoded, 0, sizeof(*decoded));
    ra = (raw >> 33) & 0x1;
    rb = (raw >> 36) & 0x1;

    if (ra == 0 && rb == 0) {
        decoded->relation = IA64_FLOAT_CMP_EQ;
    } else if (ra == 0 && rb == 1) {
        decoded->relation = IA64_FLOAT_CMP_LT;
    } else if (ra == 1 && rb == 0) {
        decoded->relation = IA64_FLOAT_CMP_LE;
    } else {
        decoded->relation = IA64_FLOAT_CMP_UNORD;
    }

    decoded->write_kind = ((raw >> 12) & 0x1) == 0
        ? IA64_PRED_WRITE_NORMAL
        : IA64_PRED_WRITE_UNCONDITIONAL;
    decoded->status_field = (raw >> 34) & 0x3;
    decoded->p1 = (raw >> 6) & 0x3f;
    decoded->p2 = (raw >> 27) & 0x3f;
    decoded->source2 = (raw >> 13) & 0x7f;
    decoded->source3 = (raw >> 20) & 0x7f;
    return true;
}

bool ia64_decode_floating_class(IA64SlotType type, uint64_t raw,
                                IA64FloatingClassInstruction *decoded)
{
    uint8_t major = ia64_slot_major_opcode(raw);

    if (!decoded || type != IA64_SLOT_TYPE_F || major != 0x5) {
        return false;
    }

    memset(decoded, 0, sizeof(*decoded));
    decoded->write_kind = ((raw >> 12) & 0x1) == 0
        ? IA64_PRED_WRITE_NORMAL
        : IA64_PRED_WRITE_UNCONDITIONAL;
    decoded->p1 = (raw >> 6) & 0x3f;
    decoded->p2 = (raw >> 27) & 0x3f;
    decoded->source2 = (raw >> 13) & 0x7f;
    decoded->mask = ((((raw >> 20) & 0x7f) << 2) |
                     ((raw >> 35) & 0x3)) & 0x1ff;
    return true;
}

static uint64_t ia64_compare_left_operand(CPUIA64State *env,
                                          const IA64CompareInstruction *decoded)
{
    if (decoded->source_immediate) {
        return (uint64_t)decoded->immediate;
    }
    return ia64_read_gr(env, decoded->source2);
}

static bool ia64_compare_matches(uint64_t left, uint64_t right,
                                 uint8_t width,
                                 IA64CompareRelation relation)
{
    if (width == 4) {
        left = (uint32_t)left;
        right = (uint32_t)right;
    }

    switch (relation) {
    case IA64_CMP_EQ:
        return left == right;
    case IA64_CMP_NE:
        return left != right;
    case IA64_CMP_LT:
        return width == 4 ? (int32_t)left < (int32_t)right
                          : (int64_t)left < (int64_t)right;
    case IA64_CMP_LE:
        return width == 4 ? (int32_t)left <= (int32_t)right
                          : (int64_t)left <= (int64_t)right;
    case IA64_CMP_GT:
        return width == 4 ? (int32_t)left > (int32_t)right
                          : (int64_t)left > (int64_t)right;
    case IA64_CMP_GE:
        return width == 4 ? (int32_t)left >= (int32_t)right
                          : (int64_t)left >= (int64_t)right;
    case IA64_CMP_LTU:
        return left < right;
    case IA64_CMP_LEU:
        return left <= right;
    case IA64_CMP_GTU:
        return left > right;
    case IA64_CMP_GEU:
        return left >= right;
    default:
        g_assert_not_reached();
    }
}

static uint32_t ia64_gr_nat_storage_index(CPUIA64State *env, uint32_t reg)
{
    if (reg < IA64_STATIC_GR_COUNT) {
        return reg;
    }
    return IA64_STATIC_GR_COUNT + ia64_stacked_gr_slot(env, reg);
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

    index = ia64_gr_nat_storage_index(env, reg);
    if (reg < IA64_STATIC_GR_COUNT) {
        nat = (env->nat.gr_nat[0] & (UINT64_C(1) << reg)) != 0;
    } else {
        nat = ia64_rse_read_physical_nat(env, index - IA64_STATIC_GR_COUNT);
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

    index = ia64_gr_nat_storage_index(env, reg);
    if (reg < IA64_STATIC_GR_COUNT) {
        bit = UINT64_C(1) << reg;
        old_nat = (env->nat.gr_nat[0] & bit) != 0;
        if (nat && reg != 0) {
            env->nat.gr_nat[0] |= bit;
        } else {
            env->nat.gr_nat[0] &= ~bit;
        }
    } else {
        old_nat = ia64_rse_read_physical_nat(
            env, index - IA64_STATIC_GR_COUNT);
        ia64_rse_write_physical_nat(env, index - IA64_STATIC_GR_COUNT, nat);
    }
    if (ia64_gr_nat_trace_enabled(reg) &&
        (old_nat != nat || nat || ia64_gr_nat_trace_verbose())) {
        ia64_trace_gr_nat(env, "write", reg, index, old_nat, nat && reg != 0);
    }
}

static void ia64_apply_predicate_pair_write(CPUIA64State *env,
                                            IA64PredicateWriteKind write_kind,
                                            uint8_t p1, uint8_t p2,
                                            bool result,
                                            bool source_unavailable)
{
    switch (write_kind) {
    case IA64_PRED_WRITE_AND:
        if (source_unavailable || !result) {
            ia64_write_pr(env, p1, false);
            ia64_write_pr(env, p2, false);
        }
        break;
    case IA64_PRED_WRITE_OR:
        if (!source_unavailable && result) {
            ia64_write_pr(env, p1, true);
            ia64_write_pr(env, p2, true);
        }
        break;
    case IA64_PRED_WRITE_OR_ANDCM:
        if (!source_unavailable && result) {
            ia64_write_pr(env, p1, true);
            ia64_write_pr(env, p2, false);
        }
        break;
    case IA64_PRED_WRITE_UNCONDITIONAL:
    case IA64_PRED_WRITE_NORMAL:
        ia64_write_pr(env, p1, source_unavailable ? false : result);
        ia64_write_pr(env, p2, source_unavailable ? false : !result);
        break;
    default:
        g_assert_not_reached();
    }
}

static bool ia64_floating_compare_matches(const IA64FloatReg *left_reg,
                                          const IA64FloatReg *right_reg,
                                          IA64FloatingCompareRelation relation,
                                          bool *source_unavailable)
{
    float_status status = { 0 };
    FloatRelation compare;

    if (ia64_fr_is_natval(left_reg) || ia64_fr_is_natval(right_reg)) {
        *source_unavailable = true;
        return false;
    }

    ia64_float_status_init(&status);
    compare = floatx80_compare_quiet(ia64_fr_to_floatx80(left_reg),
                                     ia64_fr_to_floatx80(right_reg),
                                     &status);

    switch (relation) {
    case IA64_FLOAT_CMP_EQ:
        return compare == float_relation_equal;
    case IA64_FLOAT_CMP_LT:
        return compare == float_relation_less;
    case IA64_FLOAT_CMP_LE:
        return compare == float_relation_less ||
               compare == float_relation_equal;
    case IA64_FLOAT_CMP_UNORD:
        return compare == float_relation_unordered;
    default:
        g_assert_not_reached();
    }
}

static bool ia64_floating_class_matches(const IA64FloatReg *reg,
                                        uint16_t mask)
{
    if (ia64_fr_is_natval(reg)) {
        return (mask & IA64_FCLASS_NATVAL) != 0;
    }
    if (ia64_fr_is_qnan(reg)) {
        return (mask & IA64_FCLASS_QNAN) != 0;
    }
    if (ia64_fr_is_snan(reg)) {
        return (mask & IA64_FCLASS_SNAN) != 0;
    }
    if (ia64_fr_sign(reg)) {
        if ((mask & IA64_FCLASS_NEGATIVE) == 0) {
            return false;
        }
    } else if ((mask & IA64_FCLASS_POSITIVE) == 0) {
        return false;
    }

    if (ia64_fr_is_zero(reg)) {
        return (mask & IA64_FCLASS_ZERO) != 0;
    }
    if (ia64_fr_is_infinity(reg)) {
        return (mask & IA64_FCLASS_INFINITY) != 0;
    }
    if (ia64_fr_is_unnormalized(reg)) {
        return (mask & IA64_FCLASS_UNNORMALIZED) != 0;
    }
    if (ia64_fr_is_normalized(reg)) {
        return (mask & IA64_FCLASS_NORMALIZED) != 0;
    }
    return false;
}

bool ia64_exec_floating_compare_qualified(
    CPUIA64State *env,
    const IA64FloatingCompareInstruction *decoded,
    bool qualifying_predicate)
{
    const IA64FloatReg *left_reg;
    const IA64FloatReg *right_reg;
    bool source_unavailable = false;
    bool result;

    if (!env || !decoded || decoded->p1 == decoded->p2) {
        return false;
    }

    if (!qualifying_predicate) {
        if (decoded->write_kind == IA64_PRED_WRITE_UNCONDITIONAL) {
            ia64_write_pr(env, decoded->p1, false);
            ia64_write_pr(env, decoded->p2, false);
        }
        return true;
    }

    left_reg = &env->fr[ia64_map_fr(env, decoded->source2)];
    right_reg = &env->fr[ia64_map_fr(env, decoded->source3)];
    result = ia64_floating_compare_matches(left_reg, right_reg,
                                           decoded->relation,
                                           &source_unavailable);

    ia64_apply_predicate_pair_write(env, decoded->write_kind,
                                    decoded->p1, decoded->p2,
                                    result, source_unavailable);
    return true;
}

bool ia64_exec_floating_compare(
    CPUIA64State *env,
    const IA64FloatingCompareInstruction *decoded)
{
    return ia64_exec_floating_compare_qualified(env, decoded, true);
}

bool ia64_exec_floating_class_qualified(
    CPUIA64State *env,
    const IA64FloatingClassInstruction *decoded,
    bool qualifying_predicate)
{
    const IA64FloatReg *reg;
    bool source_unavailable;
    bool result;

    if (!env || !decoded || decoded->p1 == decoded->p2) {
        return false;
    }

    if (!qualifying_predicate) {
        if (decoded->write_kind == IA64_PRED_WRITE_UNCONDITIONAL) {
            ia64_write_pr(env, decoded->p1, false);
            ia64_write_pr(env, decoded->p2, false);
        }
        return true;
    }

    reg = &env->fr[ia64_map_fr(env, decoded->source2)];
    source_unavailable = ia64_fr_is_natval(reg) &&
                         (decoded->mask & IA64_FCLASS_NATVAL) == 0;
    result = ia64_floating_class_matches(reg, decoded->mask);

    ia64_apply_predicate_pair_write(env, decoded->write_kind,
                                    decoded->p1, decoded->p2,
                                    result, source_unavailable);
    return true;
}

bool ia64_exec_floating_class(
    CPUIA64State *env,
    const IA64FloatingClassInstruction *decoded)
{
    return ia64_exec_floating_class_qualified(env, decoded, true);
}

bool ia64_exec_predicate_test_qualified(
    CPUIA64State *env,
    const IA64PredicateTestInstruction *decoded,
    bool qualifying_predicate)
{
    bool source_unavailable = false;
    bool result = false;

    if (!env || !decoded || decoded->p1 == decoded->p2 ||
        decoded->immediate >= 64) {
        return false;
    }

    if (!qualifying_predicate) {
        if (decoded->write_kind == IA64_PRED_WRITE_UNCONDITIONAL) {
            ia64_write_pr(env, decoded->p1, false);
            ia64_write_pr(env, decoded->p2, false);
        }
        return true;
    }

    if (decoded->kind == IA64_PRED_TEST_BIT &&
        ia64_read_gr_nat(env, decoded->source3)) {
        source_unavailable = true;
    } else {
        switch (decoded->kind) {
        case IA64_PRED_TEST_BIT:
            result = ((ia64_read_gr(env, decoded->source3) >>
                       decoded->immediate) & 1) != 0;
            break;
        case IA64_PRED_TEST_NAT:
            result = ia64_read_gr_nat(env, decoded->source3);
            break;
        case IA64_PRED_TEST_FEATURE:
            /*
             * The synthetic CPU has not grown processor-identifier registers
             * yet, so no optional test-feature bits are advertised.
             */
            result = false;
            break;
        default:
            g_assert_not_reached();
        }
        if (decoded->relation == IA64_PRED_TEST_ZERO) {
            result = !result;
        }
    }

    ia64_apply_predicate_pair_write(env, decoded->write_kind,
                                    decoded->p1, decoded->p2,
                                    result, source_unavailable);
    return true;
}

bool ia64_exec_predicate_test(CPUIA64State *env,
                              const IA64PredicateTestInstruction *decoded)
{
    return ia64_exec_predicate_test_qualified(env, decoded, true);
}

bool ia64_exec_compare_qualified(CPUIA64State *env,
                                 const IA64CompareInstruction *decoded,
                                 bool qualifying_predicate)
{
    uint64_t left;
    uint64_t right;
    bool result;

    if (!env || !decoded || decoded->p1 == decoded->p2) {
        return false;
    }

    if (!qualifying_predicate) {
        if (decoded->write_kind == IA64_PRED_WRITE_UNCONDITIONAL) {
            ia64_write_pr(env, decoded->p1, false);
            ia64_write_pr(env, decoded->p2, false);
        }
        return true;
    }

    left = ia64_compare_left_operand(env, decoded);
    right = ia64_read_gr(env, decoded->source3);
    result = ia64_compare_matches(left, right, decoded->width,
                                  decoded->relation);

    ia64_apply_predicate_pair_write(env, decoded->write_kind,
                                    decoded->p1, decoded->p2,
                                    result, false);
    return true;
}

bool ia64_exec_compare(CPUIA64State *env,
                       const IA64CompareInstruction *decoded)
{
    return ia64_exec_compare_qualified(env, decoded, true);
}

bool ia64_slot_is_b_break(IA64SlotType type, uint64_t raw)
{
    return type == IA64_SLOT_TYPE_B &&
           ia64_slot_major_opcode(raw) == 0x0 &&
           ((raw >> 27) & 0x3f) == 0x00;
}

uint64_t ia64_b_break_immediate(uint64_t raw)
{
    return (((raw >> 36) & 0x1) << 20) | ((raw >> 6) & 0xfffff);
}

bool ia64_slot_is_b_branch_relative(IA64SlotType type, uint64_t raw)
{
    return type == IA64_SLOT_TYPE_B && ia64_slot_major_opcode(raw) == 0x4;
}

bool ia64_slot_is_b_call_relative(IA64SlotType type, uint64_t raw)
{
    return type == IA64_SLOT_TYPE_B && ia64_slot_major_opcode(raw) == 0x5;
}

bool ia64_slot_is_b_indirect_branch(IA64SlotType type, uint64_t raw)
{
    uint8_t major = ia64_slot_major_opcode(raw);
    uint8_t x6 = (raw >> 27) & 0x3f;

    return type == IA64_SLOT_TYPE_B &&
           (major == 0x1 ||
            (major == 0x0 && (x6 == 0x02 || x6 == 0x04 || x6 == 0x05 ||
                              x6 == 0x08 || x6 == 0x0c || x6 == 0x0d ||
                              x6 == 0x10 || x6 == 0x20 || x6 == 0x21)));
}

bool ia64_slot_is_b_predict_or_nop(IA64SlotType type, uint64_t raw)
{
    uint8_t major = ia64_slot_major_opcode(raw);

    return type == IA64_SLOT_TYPE_B && (major == 0x2 || major == 0x7);
}

static bool ia64_loop_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_LOOP_TRACE") != NULL;
    }
    return enabled != 0;
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

int64_t ia64_branch_displacement(uint64_t raw)
{
    uint64_t encoded = (((raw >> 36) & 0x1) << 20) |
                       ((raw >> 13) & ((1ULL << 20) - 1));

    return ia64_sign_extend(encoded, 21) << 4;
}

static void ia64_set_loop_predicate_63(CPUIA64State *env, bool value)
{
    ia64_write_pr(env, 63, value);
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

static void ia64_rotate_modulo_scheduled_registers(CPUIA64State *env)
{
    uint32_t rotating_gr_count = env->rse.sor * 8;

    if (rotating_gr_count != 0) {
        env->rse.rrb_gr =
            (env->rse.rrb_gr + rotating_gr_count - 1) % rotating_gr_count;
    }
    env->rse.rrb_fr = (env->rse.rrb_fr + 95) % 96;
    env->rse.rrb_pr = (env->rse.rrb_pr + 47) % 48;
    ia64_update_cfm_rename_bases(env);
}

static void ia64_cover_stack_frame(CPUIA64State *env)
{
    uint64_t covered_cfm = env->cfm;
    uint32_t covered_sof = env->rse.sof;

    env->rse.current_frame_base =
        ia64_rse_wrap_slot(env->rse.current_frame_base + covered_sof);
    ia64_rse_preserve_frame(env, covered_sof);
    ia64_set_cfm(env, 0);
    if ((env->psr & IA64_PSR_IC_BIT) == 0) {
        env->cr[IA64_CR_IFS] = covered_cfm | IA64_IFS_VALID_BIT;
    }
}

static void ia64_uncover_stack_frame(CPUIA64State *env, uint64_t restored_cfm)
{
    uint32_t restored_sof = restored_cfm & 0x7f;

    env->rse.current_frame_base =
        ia64_rse_wrap_slot(env->rse.current_frame_base - restored_sof);
    ia64_rse_restore_preserved_frame(env, restored_sof);
    env->rse.clean_count = MIN(env->rse.clean_count,
                               env->rse.current_frame_base);
    ia64_set_cfm(env, restored_cfm);
}

static void ia64_clear_register_rename_bases(CPUIA64State *env,
                                             bool predicate_only)
{
    if (!predicate_only) {
        env->rse.rrb_gr = 0;
        env->rse.rrb_fr = 0;
    }
    env->rse.rrb_pr = 0;
    ia64_update_cfm_rename_bases(env);
}

bool ia64_exec_b_branch_relative_decoded(CPUIA64State *env,
                                         uint8_t btype,
                                         uint8_t predicate,
                                         int64_t displacement,
                                         uint64_t raw,
                                         uint64_t bundle_ip,
                                         uint64_t *target_ip,
                                         bool *taken_out)
{
    bool taken = true;

    if (taken_out) {
        *taken_out = false;
    }

    if (!env || !target_ip || btype > 7 || predicate >= IA64_PR_COUNT) {
        return false;
    }

    switch (btype) {
    case 2:
    case 3:
    {
        bool qualifying_predicate = ia64_read_pr(env, predicate);
        uint64_t epilog_count = ia64_read_ar(env, IA64_AR_EC);
        bool continue_loop;

        if (qualifying_predicate) {
            ia64_set_loop_predicate_63(env, false);
            ia64_rotate_modulo_scheduled_registers(env);
        } else if (epilog_count != 0) {
            ia64_write_ar(env, IA64_AR_EC, epilog_count - 1);
            ia64_set_loop_predicate_63(env, false);
            ia64_rotate_modulo_scheduled_registers(env);
        } else {
            ia64_set_loop_predicate_63(env, false);
        }

        continue_loop = qualifying_predicate || epilog_count > 1;
        taken = btype == 3 ? continue_loop : !continue_loop;
        break;
    }
    case 5:
    {
        uint64_t loop_count = ia64_read_ar(env, IA64_AR_LC);

        taken = loop_count != 0;
        if (taken) {
            ia64_write_ar(env, IA64_AR_LC, loop_count - 1);
        }
        break;
    }
    case 6:
    case 7:
    {
        uint64_t loop_count = ia64_read_ar(env, IA64_AR_LC);
        uint64_t epilog_count = ia64_read_ar(env, IA64_AR_EC);
        bool active = loop_count != 0 || epilog_count > 1;

        if (loop_count != 0) {
            ia64_write_ar(env, IA64_AR_LC, loop_count - 1);
            ia64_set_loop_predicate_63(env, true);
            ia64_rotate_modulo_scheduled_registers(env);
        } else if (epilog_count != 0) {
            ia64_write_ar(env, IA64_AR_EC, epilog_count - 1);
            ia64_set_loop_predicate_63(env, false);
            ia64_rotate_modulo_scheduled_registers(env);
        } else {
            ia64_set_loop_predicate_63(env, false);
        }

        taken = btype == 7 ? active : !active;
        break;
    }
    default:
        break;
    }

    if (taken) {
        *target_ip = bundle_ip + displacement;
    } else {
        *target_ip = bundle_ip + IA64_BUNDLE_SIZE;
    }
    if (taken_out) {
        *taken_out = taken;
    }
    if (ia64_loop_trace_enabled() && (btype == 2 || btype == 3 ||
                                      btype == 5 || btype == 6 ||
                                      btype == 7)) {
        fprintf(stderr,
                "[ia64-loop] ip=0x%016" PRIx64 " raw=0x%011" PRIx64
                " btype=%u lc=0x%016" PRIx64 " ec=0x%016" PRIx64
                " taken=%u target=0x%016" PRIx64
                " rrb-gr=%u rrb-fr=%u rrb-pr=%u\n",
                bundle_ip, raw, btype, ia64_read_ar(env, IA64_AR_LC),
                ia64_read_ar(env, IA64_AR_EC), taken ? 1 : 0, *target_ip,
                env->rse.rrb_gr, env->rse.rrb_fr, env->rse.rrb_pr);
    }
    return true;
}

bool ia64_exec_b_branch_relative(CPUIA64State *env,
                                 uint64_t raw,
                                 uint64_t bundle_ip,
                                 uint64_t *target_ip,
                                 bool *taken_out)
{
    if (!ia64_slot_is_b_branch_relative(IA64_SLOT_TYPE_B, raw)) {
        return false;
    }
    return ia64_exec_b_branch_relative_decoded(
        env, (raw >> 6) & 0x7, ia64_slot_predicate(raw),
        ia64_branch_displacement(raw), raw, bundle_ip, target_ip, taken_out);
}

static uint32_t ia64_cfm_sof(uint64_t cfm)
{
    return cfm & 0x7f;
}

static uint32_t ia64_cfm_sol(uint64_t cfm)
{
    return (cfm >> 7) & 0x7f;
}

static void ia64_enter_call_frame(CPUIA64State *env)
{
    uint64_t caller_cfm = env->cfm;
    uint64_t caller_ec = ia64_read_ar(env, IA64_AR_EC) & 0x3f;
    uint64_t caller_cpl =
        (ia64_env_psr(env) & IA64_PSR_CPL_MASK) >> IA64_PSR_CPL_SHIFT;
    uint32_t caller_sof = ia64_cfm_sof(caller_cfm);
    uint32_t caller_sol = ia64_cfm_sol(caller_cfm);
    uint32_t output_count = caller_sof >= caller_sol
        ? caller_sof - caller_sol
        : 0;

    env->ar[IA64_AR_PFS] = (caller_cfm & IA64_PFS_CFM_MASK) |
                           (caller_ec << IA64_PFS_PEC_SHIFT) |
                           (caller_cpl << IA64_PFS_PPL_SHIFT);
    env->rse.current_frame_base =
        ia64_rse_wrap_slot(env->rse.current_frame_base + caller_sol);
    ia64_rse_preserve_frame(env, caller_sol);
    ia64_set_cfm(env, ia64_make_cfm(output_count, 0, 0));
}

static void ia64_restore_frame_from_pfs(CPUIA64State *env)
{
    uint64_t pfs = env->ar[IA64_AR_PFS];
    uint64_t restored_cfm = pfs & IA64_PFS_CFM_MASK;
    uint64_t restored_ec =
        (pfs & IA64_PFS_PEC_MASK) >> IA64_PFS_PEC_SHIFT;
    uint64_t restored_cpl =
        (pfs & IA64_PFS_PPL_MASK) >> IA64_PFS_PPL_SHIFT;
    uint32_t restored_sof = ia64_cfm_sof(restored_cfm);
    uint32_t restored_sol = ia64_cfm_sol(restored_cfm);
    uint32_t caller_base =
        ia64_rse_wrap_slot(env->rse.current_frame_base - restored_sol);

    ia64_rse_invalidate(env, caller_base + restored_sof,
                        env->rse.current_frame_base + 96);
    env->rse.current_frame_base = caller_base;
    ia64_rse_restore_preserved_frame(env, restored_sol);
    env->rse.clean_count = MIN(env->rse.clean_count,
                               env->rse.current_frame_base);
    ia64_set_cfm(env, restored_cfm);
    ia64_write_ar(env, IA64_AR_EC, restored_ec);
    ia64_env_set_psr(env, (ia64_env_psr(env) & ~IA64_PSR_CPL_MASK) |
                          (restored_cpl << IA64_PSR_CPL_SHIFT));
}

bool ia64_return_from_call_frame(CPUIA64State *env, uint64_t target_ip)
{
    if (!env) {
        return false;
    }

    ia64_restore_frame_from_pfs(env);
    env->ip = target_ip & ~0xfULL;
    env->cr[IA64_CR_IIP] = env->ip;
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

bool ia64_exec_b_call_relative_decoded(CPUIA64State *env,
                                       uint32_t b1,
                                       int64_t displacement,
                                       uint64_t bundle_ip,
                                       uint64_t *target_ip)
{
    if (!env || !target_ip || b1 >= IA64_BR_COUNT) {
        return false;
    }

    ia64_branch_call_effects(env, b1, bundle_ip);
    *target_ip = bundle_ip + displacement;
    return true;
}

bool ia64_exec_b_call_relative(CPUIA64State *env,
                               uint64_t raw,
                               uint64_t bundle_ip,
                               uint64_t *target_ip)
{
    if (!ia64_slot_is_b_call_relative(IA64_SLOT_TYPE_B, raw)) {
        return false;
    }
    return ia64_exec_b_call_relative_decoded(
        env, (raw >> 6) & 0x7, ia64_branch_displacement(raw), bundle_ip,
        target_ip);
}

bool ia64_exec_b_indirect_branch_decoded(CPUIA64State *env,
                                         uint8_t major,
                                         uint8_t x6,
                                         uint32_t b1,
                                         uint32_t b2,
                                         uint64_t bundle_ip,
                                         uint64_t *target_ip)
{
    if (!env || !target_ip || b1 >= IA64_BR_COUNT || b2 >= IA64_BR_COUNT) {
        return false;
    }

    if (major == 0x0) {
        switch (x6) {
        case 0x02: /* cover */
            ia64_cover_stack_frame(env);
            *target_ip = bundle_ip + IA64_BUNDLE_SIZE;
            return true;
        case 0x04: /* clrrrb */
        case 0x05: /* clrrrb.pr */
            ia64_clear_register_rename_bases(env, x6 == 0x05);
            *target_ip = bundle_ip + IA64_BUNDLE_SIZE;
            return true;
        case 0x0c: /* bsw.0 */
            ia64_env_set_psr(env, ia64_env_psr(env) & ~IA64_PSR_BN_BIT);
            *target_ip = bundle_ip + IA64_BUNDLE_SIZE;
            return true;
        case 0x0d: /* bsw.1 */
            ia64_env_set_psr(env, ia64_env_psr(env) | IA64_PSR_BN_BIT);
            *target_ip = bundle_ip + IA64_BUNDLE_SIZE;
            return true;
        case 0x10: /* epc */
            ia64_env_set_psr(env, ia64_env_psr(env) & ~IA64_PSR_CPL_MASK);
            *target_ip = bundle_ip + IA64_BUNDLE_SIZE;
            return true;
        default:
            break;
        }
    }
    if (major == 0x0 && x6 == 0x08) {
        uint64_t target = env->cr[IA64_CR_IIP] & ~0xfULL;

        trace_ia64_rfi(bundle_ip, target, env->cr[IA64_CR_IPSR],
                       env->cr[IA64_CR_IFS], env->psr, env->cfm);
        ia64_diag_record_rfi(env, bundle_ip, target);
        ia64_trace_user_rfi(env, bundle_ip, target);
        if (ia64_exception_trace_enabled()) {
            fprintf(stderr,
                    "[ia64-rfi] ip=0x%016" PRIx64
                    " target=0x%016" PRIx64 " ipsr=0x%016" PRIx64
                    " ifs=0x%016" PRIx64 " psr=0x%016" PRIx64
                    " cfm=0x%016" PRIx64 "\n",
                    bundle_ip, target, env->cr[IA64_CR_IPSR],
                    env->cr[IA64_CR_IFS], env->psr, env->cfm);
        }
        ia64_env_set_psr(env, env->cr[IA64_CR_IPSR]);
        if (env->cr[IA64_CR_IFS] & IA64_IFS_VALID_BIT) {
            ia64_uncover_stack_frame(env,
                                     env->cr[IA64_CR_IFS] & IA64_CFM_MASK);
        }
        *target_ip = target;
        return true;
    }

    *target_ip = env->br[b2] & ~0xfULL;
    if (major == 0x1) {
        ia64_trace_branch_write(env, "br.call-indirect", b1,
                                bundle_ip + IA64_BUNDLE_SIZE, env->br[b2]);
        env->br[b1] = bundle_ip + IA64_BUNDLE_SIZE;
        ia64_enter_call_frame(env);
    } else if (x6 == 0x21) {
        ia64_trace_branch_return(env, "br.ret", b2, *target_ip, bundle_ip);
        ia64_restore_frame_from_pfs(env);
    }
    return true;
}

bool ia64_exec_b_indirect_branch(CPUIA64State *env,
                                 uint64_t raw,
                                 uint64_t bundle_ip,
                                 uint64_t *target_ip)
{
    if (!ia64_slot_is_b_indirect_branch(IA64_SLOT_TYPE_B, raw)) {
        return false;
    }
    return ia64_exec_b_indirect_branch_decoded(
        env, ia64_slot_major_opcode(raw), (raw >> 27) & 0x3f,
        (raw >> 6) & 0x7, (raw >> 13) & 0x7, bundle_ip, target_ip);
}

static void ia64_insn_set_message(IA64InsnReport *report,
                                        const char *fmt, ...)
    G_GNUC_PRINTF(2, 3);

static void ia64_insn_set_message(IA64InsnReport *report,
                                        const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(report->message, sizeof(report->message), fmt, ap);
    va_end(ap);
}

IA64InsnStatus
ia64_insn_exec_bundle(CPUIA64State *env,
                       const uint8_t bundle[IA64_BUNDLE_SIZE],
                       IA64InsnReport *report)
{
    memset(report, 0, sizeof(*report));
    report->failed_slot = -1;
    report->ip_before = env->ip;
    report->ip_after = env->ip;

    ia64_decode_bundle(bundle, &report->bundle);

    if (!report->bundle.valid) {
        report->status = IA64_INSN_RESERVED_TEMPLATE;
        ia64_insn_set_message(
            report,
            "reserved IA-64 template 0x%02x at ip=0x%016" PRIx64,
            report->bundle.tmpl, report->ip_before);
        return report->status;
    }

    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        IA64SlotType type = report->bundle.info->slot_type[slot];
        uint64_t raw = report->bundle.slot[slot];

        if (!ia64_insn_slot_supported(type, raw)) {
            report->status = IA64_INSN_UNSUPPORTED_SLOT;
            report->failed_slot = slot;
            ia64_insn_set_message(
                report,
                "unsupported IA-64 instruction at ip=0x%016" PRIx64
                " slot=%d type=%s raw=0x%011" PRIx64
                " template=0x%02x %s",
                report->ip_before, slot, ia64_slot_type_name(type), raw,
                report->bundle.tmpl, report->bundle.info->name);
            return report->status;
        }
    }

    env->ip += IA64_BUNDLE_SIZE;
    report->status = IA64_INSN_OK;
    report->ip_after = env->ip;
    ia64_insn_set_message(
        report,
        "executed IA-64 NOP bundle at ip=0x%016" PRIx64
        " next=0x%016" PRIx64,
        report->ip_before, report->ip_after);

    return report->status;
}
