/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "accel/tcg/cpu-loop.h"
#include "accel/tcg/cpu-ldst.h"
#include "accel/tcg/getpc.h"
#include "accel/tcg/probe.h"
#include "cpu.h"
#include "exec/target_page.h"
#include "exec/translation-block.h"
#include "decode.h"
#include "exception.h"
#include "exec/helper-proto.h"
#include "fpu/softfloat.h"
#include "insn.h"
#include "mem.h"
#include "perf.h"
#include "qemu/host-utils.h"

enum {
    IA64_DATA_PLANE_LOAD_CONTINUE = 0,
    IA64_DATA_PLANE_LOAD_ALAT_HIT = 1,
    IA64_DATA_PLANE_LOAD_DEFER = 2,
    IA64_DATA_PLANE_LOAD_ADVANCED_ZERO = 3,
};

static uint32_t ia64_data_plane_map_fr(CPUIA64State *env, uint32_t reg)
{
    if (reg < 32) {
        return reg;
    }
    return 32 + ((reg - 32 + env->rse.rrb_fr) % (IA64_FR_COUNT - 32));
}

static void ia64_data_plane_write_fr_raw(CPUIA64State *env, uint32_t reg,
                                         uint64_t low, uint64_t high)
{
    uint32_t mapped;

    if (reg >= IA64_FR_COUNT || reg < 2) {
        return;
    }
    ia64_preserve_fr_source(env, reg);
    mapped = ia64_data_plane_map_fr(env, reg);
    env->fr[mapped].raw[0] = low;
    env->fr[mapped].raw[1] = high;
    ia64_note_fr_write(env, reg);
}

static bool ia64_data_plane_probe_speculation(
    CPUIA64State *env, uint64_t address, IA64TranslateResult *result)
{
    /* This is a non-raising decision probe, but it is not a debug lookup:
       A-bit and permission failures must flow to the real access rather than
       being mistaken for a successfully classified mapping. */
    return ia64_translate_address_no_detail(
        env, address, MMU_DATA_LOAD, 0, false, result);
}

static void ia64_data_probe_range(CPUIA64State *env,
                                  uint64_t address,
                                  uint32_t size,
                                  MMUAccessType access_type,
                                  int mmu_idx,
                                  uintptr_t retaddr)
{
    uint32_t remaining = size;

    while (remaining != 0) {
        uint32_t page_remaining =
            TARGET_PAGE_SIZE - (address & ~TARGET_PAGE_MASK);
        uint32_t chunk = MIN(remaining, page_remaining);

        probe_access(env, address, chunk, access_type, mmu_idx, retaddr);
        address += chunk;
        remaining -= chunk;
    }
}

/*
 * A SoftMMU host-TLB hit otherwise bypasses the target translation code, so
 * architectural DBRs need a focused pre-access seam.  First test the DBRs
 * without side effects; a non-matching access keeps the normal zero-overhead
 * fault path.  For a match, probe every page and every required permission
 * before delivering Data Debug.  probe_access() performs no RAM/MMIO device
 * callback, preserving the required translation/protection/A/D-before-debug
 * and debug-before-device ordering.
 */
void HELPER(data_debug_pre_access)(CPUIA64State *env, uint64_t address,
                                   uint32_t size, uint32_t access,
                                   uint32_t mmu_idx)
{
    uintptr_t retaddr;
    int32_t exception_access;

    if (size == 0 || !ia64_data_debug_match(env, address, size, access)) {
        return;
    }

    retaddr = GETPC();
    if (access & IA64_DEBUG_ACCESS_READ) {
        ia64_data_probe_range(env, address, size, MMU_DATA_LOAD,
                              mmu_idx, retaddr);
    }
    if (access & IA64_DEBUG_ACCESS_WRITE) {
        ia64_data_probe_range(env, address, size, MMU_DATA_STORE,
                              mmu_idx, retaddr);
    }

    exception_access =
        (access & IA64_DEBUG_ACCESS_READ) &&
        (access & IA64_DEBUG_ACCESS_WRITE) ?
            IA64_EXCEPTION_ACCESS_SEMAPHORE :
        (access & IA64_DEBUG_ACCESS_WRITE) ? MMU_DATA_STORE : MMU_DATA_LOAD;
    ia64_deliver_exception_fast(env, IA64_EXCEPTION_DATA_DEBUG, address,
                                exception_access,
                                "data breakpoint match before access");
    env->fault_exit_pending_tb_translate = true;
    cpu_loop_exit(env_cpu(env));
}

/*
 * An architecturally faulting unaligned reference is lower priority than its
 * translation, protection-key, access-bit, and dirty-bit checks.  The normal
 * qemu_ld/st cannot provide that ordering because it must not perform the
 * memory or MMIO access once Unaligned is selected.  Probe only the dynamic
 * fault arm, after precise slot state has been published, then let the caller
 * deliver Unaligned if every required page and permission is valid.
 */
void HELPER(data_unaligned_pre_access)(CPUIA64State *env, uint64_t address,
                                       uint32_t size, uint32_t access_type,
                                       uint32_t mmu_idx)
{
    uintptr_t retaddr = GETPC();

    g_assert(size != 0);
    if (access_type == MMU_DATA_LOAD ||
        access_type == IA64_EXCEPTION_ACCESS_SEMAPHORE) {
        ia64_data_probe_range(env, address, size, MMU_DATA_LOAD,
                              mmu_idx, retaddr);
    }
    if (access_type == MMU_DATA_STORE ||
        access_type == IA64_EXCEPTION_ACCESS_SEMAPHORE) {
        ia64_data_probe_range(env, address, size, MMU_DATA_STORE,
                              mmu_idx, retaddr);
    }
}

uint32_t HELPER(data_plane_integer_load_prepare)(CPUIA64State *env,
                                                  uint64_t address,
                                                  uint32_t target,
                                                  uint32_t width,
                                                  uint32_t memory_class)
{
    if (memory_class == 8 || memory_class == 9) {
        uint64_t resolved;
        bool physical;

        ia64_data_plane_alat_resolve_address(
            env, address, MMU_DATA_LOAD, &resolved, &physical);
        if (ia64_alat_check_gr(env, target, resolved, width, physical,
                               memory_class == 8)) {
            return IA64_DATA_PLANE_LOAD_ALAT_HIT;
        }
    }
    if (memory_class == 2) {
        IA64TranslateResult result;

        if (ia64_data_plane_probe_speculation(env, address, &result)) {
            /* Plain advanced loads are not control-speculative.  A NaTPage
               must reach the real access and raise Data NaT Page; only .s
               and .sa may turn it into deferred NaT state. */
            if (result.memory_attribute == 7) {
                return IA64_DATA_PLANE_LOAD_CONTINUE;
            }
            if (result.speculation_class == IA64_MEMORY_SPECULATION_NON) {
                ia64_alat_invalidate_gr(env, target);
                return IA64_DATA_PLANE_LOAD_ADVANCED_ZERO;
            }
        }
    }
    if (memory_class == 1 || memory_class == 3) {
        IA64ControlSpeculativeLoadAction action =
            ia64_control_speculative_load_action(
                env, memory_class, false, address, width, NULL);

        if (action == IA64_CONTROL_SPECULATIVE_LOAD_DATA_DEBUG) {
            ia64_raise_data_plane_exception(
                env, IA64_EXCEPTION_DATA_DEBUG, address, MMU_DATA_LOAD);
        }
        if (action == IA64_CONTROL_SPECULATIVE_LOAD_UNALIGNED) {
            ia64_raise_arch_unaligned_data_reference(
                env, address, MMU_DATA_LOAD);
        }
        if (action == IA64_CONTROL_SPECULATIVE_LOAD_DEFER) {
            ia64_alat_invalidate_gr(env, target);
            return IA64_DATA_PLANE_LOAD_DEFER;
        }
    }
    return IA64_DATA_PLANE_LOAD_CONTINUE;
}

uint32_t HELPER(data_plane_integer_load_prepare_nat)(CPUIA64State *env,
                                                      uint32_t target,
                                                      uint32_t memory_class)
{
    if (memory_class != 1 && memory_class != 3) {
        return IA64_DATA_PLANE_LOAD_CONTINUE;
    }
    ia64_alat_invalidate_gr(env, target);
    return IA64_DATA_PLANE_LOAD_DEFER;
}

void HELPER(data_plane_integer_load_complete)(CPUIA64State *env,
                                               uint64_t address,
                                               uint32_t target,
                                               uint32_t width,
                                               uint32_t memory_class)
{
    (void)address;
    (void)width;
    (void)memory_class;
    ia64_alat_invalidate_gr(env, target);
}

void HELPER(data_plane_alat_record)(CPUIA64State *env, uint64_t address,
                                    uint32_t target, uint32_t width,
                                    uint32_t target_type,
                                    uint32_t memory_class)
{
    IA64TranslateResult result;
    uint64_t resolved = address;
    bool physical = false;

    if (ia64_data_plane_probe_speculation(env, address, &result)) {
        if (result.memory_attribute == 7 ||
            result.speculation_class == IA64_MEMORY_SPECULATION_NON ||
            (memory_class == 3 &&
             result.speculation_class != IA64_MEMORY_SPECULATION_SPEC)) {
            return;
        }
        resolved = result.paddr;
        physical = true;
    }
    if (target_type == IA64_ALAT_TARGET_GR) {
        ia64_alat_record_gr(env, target, resolved, width, physical);
    } else if (target_type == IA64_ALAT_TARGET_FR) {
        ia64_alat_record_fr(env, target, resolved, width, physical);
    }
}

void HELPER(data_plane_semaphore_probe)(CPUIA64State *env, uint64_t address,
                                        uint32_t allow_uce)
{
    IA64TranslateResult load_result;
    IA64TranslateResult store_result;

    /* Every semaphore is both a read and a write, including a failing
       compare.  Probe both permissions before the RMW and retag any
       interruption with the architectural R|W access class. */
    if (!ia64_translate_address(env, address, MMU_DATA_LOAD, 0, false,
                                &load_result)) {
        load_result.access_type =
            (MMUAccessType)IA64_EXCEPTION_ACCESS_SEMAPHORE;
        ia64_raise_arch_translation_fault(env, &load_result);
    }
    if (!ia64_translate_address(env, address, MMU_DATA_STORE, 0, false,
                                &store_result)) {
        store_result.access_type =
            (MMUAccessType)IA64_EXCEPTION_ACCESS_SEMAPHORE;
        ia64_raise_arch_translation_fault(env, &store_result);
    }

    if (load_result.memory_attribute == 7) {
        ia64_raise_data_plane_exception(
            env, IA64_EXCEPTION_DATA_NAT_PAGE_CONSUMPTION, address,
            IA64_EXCEPTION_ACCESS_SEMAPHORE);
    }
    if (load_result.memory_attribute != 0 &&
        !(allow_uce && load_result.memory_attribute == 5)) {
        ia64_raise_data_plane_exception(
            env, IA64_EXCEPTION_UNSUPPORTED_DATA_REFERENCE, address,
            IA64_EXCEPTION_ACCESS_SEMAPHORE);
    }
}

/* LD16/ST16 and the ten-byte extended FP forms require a WB transaction.
   Their translated emitters perform the architectural NaT/disabled/alignment
   gates first, then enter here before any direct memory operation. */
void HELPER(data_plane_wb_only_probe)(CPUIA64State *env, uint64_t address,
                                      uint32_t is_store)
{
    MMUAccessType access_type = is_store ? MMU_DATA_STORE : MMU_DATA_LOAD;
    IA64TranslateResult result;

    if (!ia64_translate_address(env, address, access_type, 0, false,
                                &result)) {
        ia64_raise_arch_translation_fault(env, &result);
    }
    if (result.memory_attribute == 7) {
        ia64_raise_data_plane_exception(
            env, IA64_EXCEPTION_DATA_NAT_PAGE_CONSUMPTION, address,
            access_type);
    }
    if (result.memory_attribute != 0) {
        ia64_raise_data_plane_exception(
            env, IA64_EXCEPTION_UNSUPPORTED_DATA_REFERENCE, address,
            access_type);
    }
}

void HELPER(data_plane_ar_preserve)(CPUIA64State *env, uint32_t reg,
                                    uint64_t entry_value)
{
    ia64_issue_group_preserve_ar_source(env, reg, entry_value);
}

uint64_t HELPER(data_plane_ar_select)(CPUIA64State *env, uint32_t reg,
                                      uint64_t live_value)
{
    return ia64_issue_group_select_ar_source(env, reg, live_value);
}

static bool ia64_data_plane_big_endian(CPUIA64State *env)
{
    return (ia64_env_psr(env) & IA64_TB_PSR_BE_BIT) != 0;
}

static MemOp ia64_data_plane_memop(uint32_t width, bool big_endian)
{
    MemOp memop;

    switch (width) {
    case 1:
        memop = MO_UB;
        break;
    case 2:
        memop = MO_UW;
        break;
    case 4:
        memop = MO_UL;
        break;
    case 8:
        memop = MO_UQ;
        break;
    default:
        g_assert_not_reached();
    }
    return memop | (big_endian ? MO_BE : MO_LE);
}

static uint64_t ia64_data_plane_load_scalar(CPUIA64State *env,
                                             uint64_t address,
                                             uint32_t width,
                                             bool big_endian)
{
    uintptr_t ra = GETPC();

    switch (width) {
    case 1:
        return cpu_ldub_data_ra(env, address, ra);
    case 2:
        return big_endian ? cpu_lduw_be_data_ra(env, address, ra) :
                            cpu_lduw_le_data_ra(env, address, ra);
    case 4:
        return big_endian ? cpu_ldl_be_data_ra(env, address, ra) :
                            cpu_ldl_le_data_ra(env, address, ra);
    case 8:
        return big_endian ? cpu_ldq_be_data_ra(env, address, ra) :
                            cpu_ldq_le_data_ra(env, address, ra);
    default:
        g_assert_not_reached();
    }
}

uint64_t HELPER(data_plane_cmpxchg)(CPUIA64State *env, uint64_t address,
                                    uint64_t compare, uint64_t value,
                                    uint32_t width)
{
    uintptr_t ra = GETPC();
    bool big_endian = ia64_data_plane_big_endian(env);
    uint64_t mask = width == 8 ? UINT64_MAX :
                    (UINT64_C(1) << (width * 8)) - 1;
    bool representable = (compare & mask) == compare;
    int mmu_idx = cpu_mmu_index(env_cpu(env), false);
    MemOpIdx oi = make_memop_idx(
        ia64_data_plane_memop(width, big_endian), mmu_idx);
    uint64_t old;

    if (!representable) {
        return ia64_data_plane_load_scalar(env, address, width, big_endian);
    }

    switch (width) {
    case 1:
        old = cpu_atomic_cmpxchgb_mmu(env, address, compare, value,
                                      oi, ra);
        break;
    case 2:
        old = big_endian ?
              cpu_atomic_cmpxchgw_be_mmu(env, address, compare, value,
                                          oi, ra) :
              cpu_atomic_cmpxchgw_le_mmu(env, address, compare, value,
                                          oi, ra);
        break;
    case 4:
        old = big_endian ?
              cpu_atomic_cmpxchgl_be_mmu(env, address, compare, value,
                                          oi, ra) :
              cpu_atomic_cmpxchgl_le_mmu(env, address, compare, value,
                                          oi, ra);
        break;
    case 8:
        old = big_endian ?
              cpu_atomic_cmpxchgq_be_mmu(env, address, compare, value,
                                          oi, ra) :
              cpu_atomic_cmpxchgq_le_mmu(env, address, compare, value,
                                          oi, ra);
        break;
    default:
        g_assert_not_reached();
    }
    if (old == compare) {
        ia64_data_plane_alat_invalidate_store(env, address, width);
    }
    return old;
}

static MemOpIdx ia64_data_plane_wide_oi(CPUIA64State *env)
{
    return make_memop_idx(MO_128 |
                          (ia64_data_plane_big_endian(env) ? MO_BE : MO_LE),
                          cpu_mmu_index(env_cpu(env), false));
}

static Int128 ia64_data_plane_wide_value(CPUIA64State *env,
                                         uint64_t low_address,
                                         uint64_t high_address)
{
    return ia64_data_plane_big_endian(env)
        ? int128_make128(high_address, low_address)
        : int128_make128(low_address, high_address);
}

static uint64_t ia64_data_plane_wide_selected(CPUIA64State *env,
                                              Int128 value,
                                              uint64_t address)
{
    bool upper_address = (address & 8) != 0;

    if (ia64_data_plane_big_endian(env)) {
        return upper_address ? int128_getlo(value) :
                               (uint64_t)int128_gethi(value);
    }
    return upper_address ? (uint64_t)int128_gethi(value) :
                           int128_getlo(value);
}

uint64_t HELPER(data_plane_cmp8xchg16)(CPUIA64State *env,
                                       uint64_t address,
                                       uint64_t compare,
                                       uint64_t low_address,
                                       uint64_t high_address)
{
    uint64_t block = address & ~UINT64_C(0xf);
    Int128 desired = ia64_data_plane_wide_value(
        env, low_address, high_address);
    Int128 observed;
    MemOpIdx oi = ia64_data_plane_wide_oi(env);
    bool big_endian = ia64_data_plane_big_endian(env);
    uint64_t initial;

    /* A failed comparison reads only the selected eight-byte operand: do
       not turn the unselected half into an observable device/watchpoint
       access.  Once it matches, take one atomic full-block snapshot for the
       compare-exchange retry loop, without issuing a spurious write. */
    initial = ia64_data_plane_load_scalar(env, address, 8, big_endian);
    if (initial != compare) {
        return initial;
    }
    observed = cpu_ld16_mmu(env, block, oi, GETPC());
    for (;;) {
        uint64_t selected = ia64_data_plane_wide_selected(
            env, observed, address);
        Int128 previous;

        if (selected != compare) {
            return selected;
        }
        previous = big_endian
            ? cpu_atomic_cmpxchgo_be_mmu(
                  env, block, observed, desired, oi, GETPC())
            : cpu_atomic_cmpxchgo_le_mmu(
                  env, block, observed, desired, oi, GETPC());
        if (int128_eq(previous, observed)) {
            ia64_data_plane_alat_invalidate_store(env, block, 16);
            return selected;
        }
        observed = previous;
    }
}

#define IA64_DP_PSR_MFL UINT64_C(0x10)
#define IA64_DP_PSR_MFH UINT64_C(0x20)
#define IA64_DP_PSR_DFL UINT64_C(0x0000000000040000)
#define IA64_DP_PSR_DFH UINT64_C(0x0000000000080000)
#define IA64_DP_FR_NATVAL_EXPONENT UINT64_C(0x1fffe)
#define IA64_DP_FR_INTEGER_EXPONENT UINT64_C(0x1003e)
#define IA64_DP_FR_SPECIAL_EXPONENT UINT64_C(0x1ffff)

enum {
    IA64_DP_FP_LOAD_CONTINUE = 0,
    IA64_DP_FP_LOAD_ALAT_HIT = 1,
    IA64_DP_FP_LOAD_DEFER_NATVAL = 2,
    IA64_DP_FP_LOAD_ADVANCED_ZERO = 3,
    IA64_DP_FP_LOAD_BASE_NAT = 4,
};

enum {
    IA64_DP_FP_STORE_CONTINUE = 0,
    IA64_DP_FP_STORE_BASE_NAT = 1,
    IA64_DP_FP_STORE_VALUE_NAT = 2,
};

#define IA64_DP_FP_TARGET1(_targets) ((_targets) & 0xff)
#define IA64_DP_FP_TARGET2(_targets) (((_targets) >> 8) & 0xff)
#define IA64_DP_FP_PAIR(_targets) (((_targets) >> 16) & 1)
#define IA64_DP_FP_FORMAT(_info) ((_info) & 0xff)
#define IA64_DP_FP_WIDTH(_info) (((_info) >> 8) & 0xff)
#define IA64_DP_FP_CLASS(_info) (((_info) >> 16) & 0xff)

static void ia64_data_plane_fp_note_modified(CPUIA64State *env,
                                              uint32_t reg)
{
    if (reg >= 2 && reg < IA64_FR_COUNT) {
        env->psr |= reg >= 32 ? IA64_DP_PSR_MFH : IA64_DP_PSR_MFL;
    }
}

static bool ia64_data_plane_fp_disabled(CPUIA64State *env, uint32_t reg,
                                        bool *high)
{
    uint64_t psr = ia64_env_psr(env);

    if (reg >= 32 && reg < IA64_FR_COUNT &&
        (psr & IA64_DP_PSR_DFH) != 0) {
        *high = true;
        return true;
    }
    if (reg >= 2 && reg < 32 &&
        (psr & IA64_DP_PSR_DFL) != 0) {
        *high = false;
        return true;
    }
    return false;
}

static G_NORETURN void ia64_data_plane_raise_disabled_fp(
    CPUIA64State *env, bool high)
{
    uint64_t next_ip;

    ia64_deliver_disabled_fp_interruption(env, high, &next_ip);
    env->fault_exit_pending_tb_translate = true;
    cpu_loop_exit(env_cpu(env));
}

static void ia64_data_plane_fp_check_disabled(CPUIA64State *env,
                                               uint32_t reg)
{
    bool high;

    if (ia64_data_plane_fp_disabled(env, reg, &high)) {
        ia64_data_plane_raise_disabled_fp(env, high);
    }
}

void HELPER(data_plane_fp_check_disabled_set)(CPUIA64State *env,
                                               uint64_t packed_regs)
{
    unsigned count = packed_regs & 0xff;

    /* Destination first, followed by normalized f2/f3/f4 operands. */
    g_assert(count <= 4);
    for (unsigned i = 0; i < count; i++) {
        ia64_data_plane_fp_check_disabled(
            env, (packed_regs >> ((i + 1) * 8)) & 0x7f);
    }
}

static void ia64_data_plane_fp_write_extended(CPUIA64State *env,
                                               uint32_t reg,
                                               uint64_t mantissa,
                                               uint16_t external)
{
    uint32_t exponent = external & 0x7fff;
    uint64_t sign_exponent = (external & 0x8000) != 0 ?
                             UINT64_C(1) << 17 : 0;
    IA64FloatReg value;

    if (exponent == 0x7fff) {
        exponent = IA64_DP_FR_SPECIAL_EXPONENT;
    } else if (exponent != 0) {
        exponent += 0xc000;
    }
    sign_exponent |= exponent;
    ia64_float_reg_from_spill(sign_exponent, mantissa, &value);
    ia64_data_plane_write_fr_raw(env, reg, value.raw[0], value.raw[1]);
}

static void ia64_data_plane_fp_write_one(CPUIA64State *env, uint32_t reg,
                                         uint32_t format, uint64_t low,
                                         uint64_t high)
{
    IA64FloatReg value;

    switch ((IA64FloatingMemoryFormat)format) {
    case IA64_FLOAT_FMT_SINGLE:
        ia64_write_fr_from_single_bits(env, reg, low);
        break;
    case IA64_FLOAT_FMT_DOUBLE:
        ia64_write_fr_from_double_bits(env, reg, low);
        break;
    case IA64_FLOAT_FMT_SIGNIFICAND:
        ia64_data_plane_write_fr_raw(env, reg, low,
                                     IA64_DP_FR_INTEGER_EXPONENT);
        break;
    case IA64_FLOAT_FMT_EXTENDED:
        ia64_data_plane_fp_write_extended(env, reg, low, high);
        break;
    case IA64_FLOAT_FMT_SPILL_FILL:
        ia64_float_reg_from_spill(high, low, &value);
        ia64_data_plane_write_fr_raw(env, reg,
                                     value.raw[0], value.raw[1]);
        break;
    default:
        g_assert_not_reached();
    }
}

static void ia64_data_plane_fp_write_natval_targets(CPUIA64State *env,
                                                     uint32_t targets)
{
    ia64_preserve_fr_source(env, IA64_DP_FP_TARGET1(targets));
    if (IA64_DP_FP_PAIR(targets)) {
        ia64_preserve_fr_source(env, IA64_DP_FP_TARGET2(targets));
    }
    ia64_write_fr_natval(env, IA64_DP_FP_TARGET1(targets));
    if (IA64_DP_FP_PAIR(targets)) {
        ia64_write_fr_natval(env, IA64_DP_FP_TARGET2(targets));
    }
}

static void ia64_data_plane_fp_write_zero_targets(CPUIA64State *env,
                                                   uint32_t targets,
                                                   uint32_t format)
{
    uint64_t exponent = format == IA64_FLOAT_FMT_SIGNIFICAND ?
                        IA64_DP_FR_INTEGER_EXPONENT : 0;
    uint32_t first = IA64_DP_FP_TARGET1(targets);

    ia64_preserve_fr_source(env, first);
    if (IA64_DP_FP_PAIR(targets)) {
        ia64_preserve_fr_source(env, IA64_DP_FP_TARGET2(targets));
    }
    /* An advanced-load zero is an exact architectural register encoding.
     * Real formats use exp=0,sig=0; integer/parallel format uses 0x1003e.
     * Never use exp=0x1ffff here: with sig=0 that is pseudo-infinity.
     */
    ia64_data_plane_write_fr_raw(env, first, 0, exponent);
    if (IA64_DP_FP_PAIR(targets)) {
        uint32_t second = IA64_DP_FP_TARGET2(targets);

        ia64_data_plane_write_fr_raw(env, second, 0, exponent);
    }
}

uint32_t HELPER(data_plane_fp_pair_legal)(CPUIA64State *env,
                                          uint32_t first,
                                          uint32_t second)
{
    return ((ia64_data_plane_map_fr(env, first) ^
             ia64_data_plane_map_fr(env, second)) & 1)
           != 0;
}

uint32_t HELPER(data_plane_fp_load_prepare)(CPUIA64State *env,
                                             uint64_t address,
                                             uint64_t base_nat,
                                             uint32_t targets,
                                             uint32_t info)
{
    uint32_t first = IA64_DP_FP_TARGET1(targets);
    uint32_t second = IA64_DP_FP_TARGET2(targets);
    uint32_t format = IA64_DP_FP_FORMAT(info);
    uint32_t width = IA64_DP_FP_WIDTH(info);
    uint32_t memory_class = IA64_DP_FP_CLASS(info);
    bool speculative = memory_class == 1 || memory_class == 3;

    ia64_data_plane_fp_check_disabled(env, first);
    if (IA64_DP_FP_PAIR(targets)) {
        ia64_data_plane_fp_check_disabled(env, second);
    }

    if (base_nat != 0) {
        if (!speculative) {
            return IA64_DP_FP_LOAD_BASE_NAT;
        }
        ia64_data_plane_fp_write_natval_targets(env, targets);
        return IA64_DP_FP_LOAD_DEFER_NATVAL;
    }

    if (memory_class == 8 || memory_class == 9) {
        uint64_t resolved;
        bool physical;

        ia64_data_plane_alat_resolve_address(
            env, address, MMU_DATA_LOAD, &resolved, &physical);
        if (ia64_alat_check_fr(env, first, resolved, width, physical,
                               memory_class == 8)) {
            ia64_data_plane_fp_note_modified(env, first);
            if (IA64_DP_FP_PAIR(targets)) {
                ia64_data_plane_fp_note_modified(env, second);
            }
            return IA64_DP_FP_LOAD_ALAT_HIT;
        }
    }

    if (speculative) {
        IA64ControlSpeculativeLoadAction action =
            ia64_control_speculative_load_action(
                env, memory_class, false, address, width, NULL);

        if (action == IA64_CONTROL_SPECULATIVE_LOAD_DATA_DEBUG) {
            ia64_raise_data_plane_exception(
                env, IA64_EXCEPTION_DATA_DEBUG, address, MMU_DATA_LOAD);
        }
        if (action == IA64_CONTROL_SPECULATIVE_LOAD_UNALIGNED) {
            ia64_raise_arch_unaligned_data_reference(
                env, address, MMU_DATA_LOAD);
        }
        if (action == IA64_CONTROL_SPECULATIVE_LOAD_DEFER) {
            ia64_data_plane_fp_write_natval_targets(env, targets);
            return IA64_DP_FP_LOAD_DEFER_NATVAL;
        }
    }
    if (memory_class == 2) {
        IA64TranslateResult result;

        if (ia64_data_plane_probe_speculation(env, address, &result)) {
            /* .a is not control-speculative: NaTPage is a real fault.  The
               extended format additionally requires WB, so every non-WB
               attribute must continue to its WB-only probe rather than
               taking the generic advanced-zero path. */
            if (result.memory_attribute == 7) {
                return IA64_DP_FP_LOAD_CONTINUE;
            }
            if (format == IA64_FLOAT_FMT_EXTENDED &&
                result.memory_attribute != 0) {
                return IA64_DP_FP_LOAD_CONTINUE;
            }
            if (result.speculation_class == IA64_MEMORY_SPECULATION_NON) {
                ia64_data_plane_fp_write_zero_targets(env, targets, format);
                return IA64_DP_FP_LOAD_ADVANCED_ZERO;
            }
        }
    }
    return IA64_DP_FP_LOAD_CONTINUE;
}

void HELPER(data_plane_fp_load_complete)(CPUIA64State *env,
                                          uint64_t address,
                                          uint64_t low,
                                          uint64_t high,
                                          uint32_t targets,
                                          uint32_t info)
{
    uint32_t format = IA64_DP_FP_FORMAT(info);

    (void)address;
    ia64_preserve_fr_source(env, IA64_DP_FP_TARGET1(targets));
    if (IA64_DP_FP_PAIR(targets)) {
        ia64_preserve_fr_source(env, IA64_DP_FP_TARGET2(targets));
    }
    ia64_data_plane_fp_write_one(
        env, IA64_DP_FP_TARGET1(targets), format, low, high);
    if (IA64_DP_FP_PAIR(targets)) {
        ia64_data_plane_fp_write_one(
            env, IA64_DP_FP_TARGET2(targets), format, high, 0);
    }
}

static bool ia64_data_plane_fp_is_natval(const IA64FloatReg *reg)
{
    return reg->raw[0] == 0 &&
           (reg->raw[1] & UINT64_C(0x3ffff)) ==
           IA64_DP_FR_NATVAL_EXPONENT;
}

uint32_t HELPER(data_plane_fp_store_prepare)(CPUIA64State *env,
                                              uint64_t base_nat,
                                              uint32_t source,
                                              uint32_t format)
{
    const IA64FloatReg *value;

    ia64_data_plane_fp_check_disabled(env, source);
    if (base_nat != 0) {
        return IA64_DP_FP_STORE_BASE_NAT;
    }
    value = ia64_read_fr_ordinary(env, source);
    if (format != IA64_FLOAT_FMT_SPILL_FILL &&
        ia64_data_plane_fp_is_natval(value)) {
        return IA64_DP_FP_STORE_VALUE_NAT;
    }
    return IA64_DP_FP_STORE_CONTINUE;
}

uint64_t HELPER(data_plane_fp_store_value)(CPUIA64State *env,
                                            uint32_t source,
                                            uint32_t format,
                                            uint32_t part)
{
    const IA64FloatReg *reg = ia64_read_fr_ordinary(env, source);
    uint64_t sign_exponent;
    uint64_t mantissa;

    switch ((IA64FloatingMemoryFormat)format) {
    case IA64_FLOAT_FMT_SINGLE:
        return ia64_read_fr_as_single_bits(reg);
    case IA64_FLOAT_FMT_DOUBLE:
        return ia64_read_fr_as_double_bits(reg);
    case IA64_FLOAT_FMT_SIGNIFICAND:
        return reg->raw[0];
    case IA64_FLOAT_FMT_EXTENDED:
        ia64_float_reg_to_spill(reg, &sign_exponent, &mantissa);
        if (part == 0) {
            return mantissa;
        }
        {
            uint32_t internal = sign_exponent & 0x1ffff;
            uint32_t external;

            if (internal == IA64_DP_FR_SPECIAL_EXPONENT) {
                external = 0x7fff;
            } else if (internal > 0xc000) {
                external = internal - 0xc000;
            } else {
                external = 0;
            }
            return ((sign_exponent >> 17) & 1) << 15 |
                   (external & 0x7fff);
        }
    case IA64_FLOAT_FMT_SPILL_FILL:
        ia64_float_reg_to_spill(reg, &sign_exponent, &mantissa);
        return part == 0 ? mantissa : sign_exponent;
    default:
        g_assert_not_reached();
    }
}

/*
 * Double-extended transfers have an architectural ten-byte footprint but
 * QEMU has no ten-byte MemOp.  Validate the entire footprint, including all
 * pages and watchpoints, before either of the two component accesses runs.
 * This also performs any write-side notdirty/code invalidation before STFE
 * can publish its first byte, so a retry can never observe a partial store
 * merely because the second component needed translation or recompilation.
 * Alignment=16 with a ten-byte payload makes a 4-KiB translation-page split
 * architecturally unreachable.  This prototype does not, however, claim a
 * transaction across the two callbacks of a split extended-format MMIO
 * device: its second callback may still exit or reject after the first one.
 */
void HELPER(data_plane_fp_extended_preflight)(CPUIA64State *env,
                                               uint64_t address,
                                               uint32_t mmu_idx,
                                               uint32_t is_store)
{
    const MMUAccessType access_type = is_store ? MMU_DATA_STORE :
                                                  MMU_DATA_LOAD;
    uintptr_t retaddr = GETPC();
    unsigned int remaining = 10;

    while (remaining != 0) {
        unsigned int page_remaining =
            TARGET_PAGE_SIZE - (address & ~TARGET_PAGE_MASK);
        unsigned int chunk = MIN(remaining, page_remaining);

        probe_access(env, address, chunk, access_type, mmu_idx, retaddr);
        address += chunk;
        remaining -= chunk;
    }
}

#undef IA64_DP_FP_TARGET1
#undef IA64_DP_FP_TARGET2
#undef IA64_DP_FP_PAIR
#undef IA64_DP_FP_FORMAT
#undef IA64_DP_FP_WIDTH
#undef IA64_DP_FP_CLASS

void HELPER(data_plane_alat_invalidate_all)(CPUIA64State *env)
{
    ia64_alat_invalidate_all(env);
}

void HELPER(data_plane_alat_invalidate_one)(CPUIA64State *env,
                                             uint32_t reg,
                                             uint32_t target_type)
{
    if (target_type == IA64_ALAT_TARGET_FR) {
        ia64_alat_invalidate_fr(env, reg);
    } else {
        g_assert(target_type == IA64_ALAT_TARGET_GR);
        ia64_alat_invalidate_gr(env, reg);
    }
}

uint32_t HELPER(data_plane_chk_s_fr)(CPUIA64State *env, uint32_t reg)
{
    const IA64FloatReg *value;

    ia64_data_plane_fp_check_disabled(env, reg);
    value = ia64_read_fr_ordinary(env, reg);
    return ia64_data_plane_fp_is_natval(value);
}

uint32_t HELPER(data_plane_chk_a)(CPUIA64State *env, uint32_t reg,
                                   uint32_t target_type, uint32_t clear)
{
    if (target_type == IA64_ALAT_TARGET_FR) {
        return ia64_alat_test_fr(env, reg, clear != 0);
    }
    g_assert(target_type == IA64_ALAT_TARGET_GR);
    return ia64_alat_test_gr(env, reg, clear != 0);
}

static G_NORETURN void ia64_data_plane_exit_non_access_translation_fault(
    CPUIA64State *env, IA64TranslateResult *result, int32_t access_type)
{
    result->access_type = (MMUAccessType)access_type;
    ia64_raise_arch_translation_fault(env, result);
}

static G_NORETURN void ia64_data_plane_raise_non_access_nat_page(
    CPUIA64State *env, uint64_t address, int32_t access_type)
{
    ia64_raise_data_plane_exception(
        env, IA64_EXCEPTION_DATA_NAT_PAGE_CONSUMPTION, address,
        access_type);
}

static void ia64_data_plane_probe_non_access_read(CPUIA64State *env,
                                                  uint64_t address,
                                                  IA64TranslateResult *result,
                                                  int32_t access_type,
                                                  bool skip_accessed)
{
    /*
     * FC is a non-access lookup: it does not set/check A and does not consult
     * protection keys.  A debug-form lookup supplies exactly that distinction
     * while retaining the architectural read-AR check for nonzero CPL.  At
     * CPL0 every readable translation AR is accepted, as required.  Faulting
     * lfetch remains an ordinary read-rights/A-bit probe.
     */
    if (!ia64_translate_address(env, address, MMU_DATA_LOAD, 0,
                                skip_accessed,
                                result)) {
        ia64_data_plane_exit_non_access_translation_fault(
            env, result, access_type);
    }
    if (result->memory_attribute == 7) {
        ia64_data_plane_raise_non_access_nat_page(
            env, address, access_type);
    }
}

void HELPER(data_plane_fc)(CPUIA64State *env, uint64_t address)
{
    IA64TranslateResult result;
    hwaddr start;
    hwaddr last;

    ia64_data_plane_probe_non_access_read(
        env, address, &result,
        IA64_EXCEPTION_ACCESS_FC_READ_NON_ACCESS, true);
    start = result.paddr & ~(hwaddr)31;
    last = start > (hwaddr)-1 - 31 ? (hwaddr)-1 : start + 31;
    tb_invalidate_phys_range(env_cpu(env), start, last);
}

void HELPER(data_plane_lfetch_fault)(CPUIA64State *env, uint64_t address)
{
    IA64TranslateResult result;

    /* Translation/protection is the operation: no guest byte is read. */
    ia64_data_plane_probe_non_access_read(
        env, address, &result,
        IA64_EXCEPTION_ACCESS_LFETCH_FAULT_READ_NON_ACCESS, false);
    if (ia64_data_debug_match(env, address, 1, IA64_DEBUG_ACCESS_READ)) {
        ia64_raise_data_plane_exception(
            env, IA64_EXCEPTION_DATA_DEBUG, address,
            IA64_EXCEPTION_ACCESS_LFETCH_FAULT_READ_NON_ACCESS);
    }
}

/*
 * Decoded floating-point compute seam.
 *
 * The translator supplies only normalized fields.  All source FR reads use
 * ia64_read_fr_ordinary(), so a consumer in the same issue group observes
 * the entry image even after an earlier typed writer.  Results remain local
 * until the single finalizer has classified V/D/Z versus O/U/I.
 */
#define IA64_FP_FR_BIAS              0xffffU
#define IA64_FP_FR_INTEGER_EXP       0x1003eU
#define IA64_FP_FR_SPECIAL_EXP       0x1ffffU
#define IA64_FP_FR_NAT_EXP           0x1fffeU
#define IA64_FP_FR_INTEGER_BIT       UINT64_C(0x8000000000000000)
#define IA64_FP_FR_QUIET_BIT         UINT64_C(0x4000000000000000)
#define IA64_FP_FPSR_TRAPS           UINT64_C(0x3f)
#define IA64_FP_SF_SHIFT(_sf)        (6U + 13U * ((_sf) & 3U))
#define IA64_FP_SF_FLAGS_SHIFT       7U
#define IA64_FP_SF_TD                (1U << 6)
#define IA64_FP_CTL_SF(_c)           ((uint32_t)(_c) & 3U)
#define IA64_FP_CTL_PREC(_c)         (((uint32_t)(_c) >> 2) & 3U)
#define IA64_FP_CTL_IMM(_c)          (((uint32_t)(_c) >> 4) & 0xffU)
#define IA64_FP_CTL_P1(_c)           (((uint32_t)(_c) >> 12) & 0x3fU)
#define IA64_FP_CTL_P2(_c)           (((uint32_t)(_c) >> 18) & 0x3fU)

typedef struct IA64FpTransaction {
    float_status status;
    IA64FloatReg result;
    uint32_t opcode;
    uint32_t sf;
    bool write_fr;
    bool record_exceptions;
    bool allow_traps;
    bool paired;
    int hi_soft;
    int lo_soft;
    uint64_t forced_fault;
} IA64FpTransaction;

static bool ia64_fp_fr_sign(const IA64FloatReg *reg)
{
    return (reg->raw[1] >> 17) & 1;
}

static uint32_t ia64_fp_fr_exp(const IA64FloatReg *reg)
{
    return reg->raw[1] & 0x1ffff;
}

static bool ia64_fp_fr_nat(const IA64FloatReg *reg)
{
    return !ia64_fp_fr_sign(reg) &&
           ia64_fp_fr_exp(reg) == IA64_FP_FR_NAT_EXP && reg->raw[0] == 0;
}

static bool ia64_fp_fr_zero(const IA64FloatReg *reg)
{
    return ia64_fp_fr_exp(reg) == 0 && reg->raw[0] == 0;
}

static bool ia64_fp_fr_inf(const IA64FloatReg *reg)
{
    return ia64_fp_fr_exp(reg) == IA64_FP_FR_SPECIAL_EXP &&
           reg->raw[0] == IA64_FP_FR_INTEGER_BIT;
}

static bool ia64_fp_fr_nan(const IA64FloatReg *reg)
{
    return ia64_fp_fr_exp(reg) == IA64_FP_FR_SPECIAL_EXP &&
           reg->raw[0] != 0 && reg->raw[0] != IA64_FP_FR_INTEGER_BIT;
}

static IA64FloatReg ia64_fp_natval(void)
{
    IA64FloatReg value = { .raw = { 0, IA64_FP_FR_NAT_EXP } };

    return value;
}

static IA64FloatReg ia64_fp_significand(uint64_t value)
{
    IA64FloatReg result = {
        .raw = { value, IA64_FP_FR_INTEGER_EXP },
    };

    return result;
}

static floatx80 ia64_fp_to_x80(const IA64FloatReg *reg)
{
    uint16_t sign = ia64_fp_fr_sign(reg) ? 0x8000 : 0;
    int32_t exponent = ia64_fp_fr_exp(reg);
    uint64_t mantissa = reg->raw[0];
    int32_t soft_exp;

    if (ia64_fp_fr_nat(reg) || ia64_fp_fr_nan(reg)) {
        return make_floatx80(sign | 0x7fff,
                             IA64_FP_FR_INTEGER_BIT | IA64_FP_FR_QUIET_BIT);
    }
    if (ia64_fp_fr_inf(reg)) {
        return make_floatx80(sign | 0x7fff, IA64_FP_FR_INTEGER_BIT);
    }
    if (mantissa == 0) {
        return make_floatx80(sign, 0);
    }
    while ((mantissa & IA64_FP_FR_INTEGER_BIT) == 0) {
        mantissa <<= 1;
        exponent--;
    }
    soft_exp = exponent - (int32_t)IA64_FP_FR_BIAS + 0x3fff;
    if (soft_exp <= 0) {
        return make_floatx80(sign, 0);
    }
    if (soft_exp >= 0x7fff) {
        return make_floatx80(sign | 0x7fff, IA64_FP_FR_INTEGER_BIT);
    }
    return make_floatx80(sign | soft_exp, mantissa);
}

static IA64FloatReg ia64_fp_from_x80(floatx80 value)
{
    bool sign = (value.high & 0x8000) != 0;
    uint32_t exponent = value.high & 0x7fff;
    IA64FloatReg result;

    result.raw[0] = value.low;
    if (exponent == 0x7fff) {
        result.raw[1] = IA64_FP_FR_SPECIAL_EXP;
    } else if (exponent == 0 || value.low == 0) {
        result.raw[0] = 0;
        result.raw[1] = 0;
    } else {
        result.raw[1] = exponent - 0x3fff + IA64_FP_FR_BIAS;
    }
    result.raw[1] |= (uint64_t)sign << 17;
    return result;
}

static IA64FloatReg ia64_fp_from_ieee(uint64_t bits, bool single)
{
    unsigned frac_bits = single ? 23 : 52;
    uint32_t max_exp = single ? 0xff : 0x7ff;
    uint32_t bias = single ? 127 : 1023;
    uint32_t exponent = single ? (bits >> 23) & 0xff :
                                 (bits >> 52) & 0x7ff;
    uint64_t fraction = single ? bits & 0x7fffff :
                                 bits & UINT64_C(0x000fffffffffffff);
    bool sign = single ? (bits >> 31) & 1 : (bits >> 63) & 1;
    IA64FloatReg result = { 0 };

    if (exponent == 0) {
        if (fraction != 0) {
            result.raw[0] = fraction << (63 - frac_bits);
            result.raw[1] = IA64_FP_FR_BIAS - bias + 1;
        }
    } else if (exponent == max_exp) {
        result.raw[0] = IA64_FP_FR_INTEGER_BIT |
                        (fraction << (63 - frac_bits));
        result.raw[1] = IA64_FP_FR_SPECIAL_EXP;
    } else {
        result.raw[0] = IA64_FP_FR_INTEGER_BIT |
                        (fraction << (63 - frac_bits));
        result.raw[1] = IA64_FP_FR_BIAS + exponent - bias;
    }
    result.raw[1] |= (uint64_t)sign << 17;
    return result;
}

static uint64_t ia64_fp_sf_controls(const CPUIA64State *env, uint32_t sf)
{
    return (env->ar[IA64_AR_FPSR] >> IA64_FP_SF_SHIFT(sf)) & 0x7f;
}

static uint64_t ia64_fp_active_traps(const CPUIA64State *env, uint32_t sf)
{
    uint64_t controls = ia64_fp_sf_controls(env, sf);

    return (controls & IA64_FP_SF_TD) ? IA64_FP_FPSR_TRAPS :
                                       env->ar[IA64_AR_FPSR] &
                                       IA64_FP_FPSR_TRAPS;
}

static uint64_t ia64_fp_soft_flags(int soft)
{
    uint64_t flags = 0;

    flags |= (soft & float_flag_invalid) ? 1U << 0 : 0;
    flags |= (soft & (float_flag_input_denormal_flushed |
                      float_flag_input_denormal_used)) ? 1U << 1 : 0;
    flags |= (soft & float_flag_divbyzero) ? 1U << 2 : 0;
    flags |= (soft & float_flag_overflow) ? 1U << 3 : 0;
    flags |= (soft & (float_flag_underflow |
                      float_flag_output_denormal_flushed)) ? 1U << 4 : 0;
    flags |= (soft & float_flag_inexact) ? 1U << 5 : 0;
    return flags;
}

static void ia64_fp_transaction_begin(IA64FpTransaction *tx,
                                      CPUIA64State *env, uint32_t opcode,
                                      uint64_t controls)
{
    static const FloatRoundMode rounding[4] = {
        float_round_nearest_even, float_round_down,
        float_round_up, float_round_to_zero,
    };
    uint64_t sf_controls;
    uint32_t precision;
    uint32_t pc;

    memset(tx, 0, sizeof(*tx));
    tx->opcode = opcode;
    tx->sf = IA64_FP_CTL_SF(controls);
    tx->record_exceptions = true;
    tx->allow_traps = true;
    sf_controls = ia64_fp_sf_controls(env, tx->sf);
    set_float_rounding_mode(rounding[(sf_controls >> 4) & 3], &tx->status);
    set_float_2nan_prop_rule(float_2nan_prop_x87, &tx->status);
    set_float_default_nan_pattern(0b01000000, &tx->status);
    precision = IA64_FP_CTL_PREC(controls);
    pc = (sf_controls >> 2) & 3;
    if (precision == 1 || (precision == 0 && pc == 0)) {
        set_floatx80_rounding_precision(floatx80_precision_s, &tx->status);
    } else if (precision == 2 || (precision == 0 && pc == 2)) {
        set_floatx80_rounding_precision(floatx80_precision_d, &tx->status);
    } else {
        set_floatx80_rounding_precision(floatx80_precision_x, &tx->status);
    }
    set_flush_to_zero(sf_controls & 1, &tx->status);
    set_flush_inputs_to_zero(false, &tx->status);
    set_float_exception_flags(0, &tx->status);
}

static G_NORETURN void ia64_fp_raise(CPUIA64State *env,
                                     IA64ExceptionKind kind,
                                     uint64_t isr_code)
{
    ia64_deliver_exception_fast(env, kind, env->ip,
                                IA64_EXCEPTION_ACCESS_NONE, NULL);
    env->exception.isr_code |= isr_code;
    env->cr[IA64_CR_ISR] |= isr_code;
    env->fault_exit_pending_tb_translate = true;
    cpu_loop_exit(env_cpu(env));
}

static void ia64_fp_transaction_commit(IA64FpTransaction *tx,
                                       CPUIA64State *env, uint32_t f1,
                                       uint64_t flags)
{
    if (tx->write_fr) {
        ia64_data_plane_write_fr_raw(env, f1,
                                     tx->result.raw[0], tx->result.raw[1]);
    }
    if (tx->record_exceptions && flags != 0) {
        env->ar[IA64_AR_FPSR] |=
            flags << (IA64_FP_SF_SHIFT(tx->sf) + IA64_FP_SF_FLAGS_SHIFT);
    }
}

static void ia64_fp_transaction_finish(IA64FpTransaction *tx,
                                       CPUIA64State *env, uint32_t f1)
{
    int soft = get_float_exception_flags(&tx->status);
    uint64_t hi_flags;
    uint64_t lo_flags;
    uint64_t flags;
    uint64_t traps;
    uint64_t enabled;
    uint64_t fault_isr = tx->forced_fault;
    uint64_t trap_isr = 0;

    if (tx->paired) {
        hi_flags = ia64_fp_soft_flags(tx->hi_soft);
        lo_flags = ia64_fp_soft_flags(tx->lo_soft);
        flags = hi_flags | lo_flags;
    } else {
        hi_flags = ia64_fp_soft_flags(soft);
        lo_flags = 0;
        flags = hi_flags;
    }
    if (!tx->record_exceptions) {
        flags = hi_flags = lo_flags = 0;
    }
    traps = ia64_fp_active_traps(env, tx->sf);
    if (tx->paired) {
        uint64_t hi_enabled = hi_flags & ~traps;
        uint64_t lo_enabled = lo_flags & ~traps;

        /* Intel ISR lane orientation: high lane occupies the low fault
         * nibble; low lane occupies the high fault nibble. */
        fault_isr |= (hi_enabled & 7) | ((lo_enabled & 7) << 4);
        if (tx->allow_traps && (hi_enabled & 0x38)) {
            trap_isr |= ((hi_enabled & 0x38) << 8) | (1U << 14);
        }
        if (tx->allow_traps && (lo_enabled & 0x38)) {
            trap_isr |= ((lo_enabled & 0x38) << 4) | (1U << 10);
        }
        enabled = hi_enabled | lo_enabled;
    } else {
        enabled = flags & ~traps;
        fault_isr |= enabled & 7;
        if (tx->allow_traps && (enabled & 0x38)) {
            trap_isr = ((enabled & 0x38) << 8) | 1;
        }
    }
    if (fault_isr != 0) {
        ia64_fp_raise(env, IA64_EXCEPTION_FP_FAULT, fault_isr);
    }

    ia64_fp_transaction_commit(tx, env, f1, flags);
    if (trap_isr != 0) {
        unsigned slot = ia64_psr_ri(env->psr);

        if (slot < 2) {
            env->psr = ia64_psr_with_ri(env->psr, slot + 1);
        } else {
            env->ip += 16;
            env->psr = ia64_psr_with_ri(env->psr, 0);
        }
        ia64_fp_raise(env, IA64_EXCEPTION_FP_TRAP, trap_isr);
    }
}

typedef struct IA64FpFormat {
    bool sign;
    uint32_t exp;
    uint64_t mant;
} IA64FpFormat;

static IA64FpFormat ia64_fp_format(const IA64FloatReg *reg)
{
    IA64FpFormat fmt = {
        .sign = ia64_fp_fr_sign(reg),
        .exp = ia64_fp_fr_exp(reg),
        .mant = reg->raw[0],
    };

    if (fmt.exp != 0 && fmt.exp != IA64_FP_FR_SPECIAL_EXP && fmt.mant != 0) {
        unsigned shift = clz64(fmt.mant);

        fmt.mant <<= shift;
        fmt.exp = fmt.exp > shift ? fmt.exp - shift : 0;
    }
    return fmt;
}

static bool ia64_fp_format_normal(const IA64FpFormat *fmt)
{
    return fmt->exp != 0 && fmt->exp != IA64_FP_FR_SPECIAL_EXP &&
           fmt->mant != 0 && (fmt->mant & IA64_FP_FR_INTEGER_BIT);
}

static uint32_t ia64_fp_recip_exp(uint32_t exp)
{
    int32_t result = (int32_t)(2 * IA64_FP_FR_BIAS - 1) - (int32_t)exp;

    return result > 0 ? result : 0;
}

static uint32_t ia64_fp_rsqrt_exp(uint32_t exp)
{
    int32_t unbiased = (int32_t)exp - IA64_FP_FR_BIAS;

    return ((IA64_FP_FR_BIAS - 1) - (unbiased >> 1)) & 0x1ffff;
}

static uint16_t ia64_fp_recip_entry(uint64_t mant)
{
    uint32_t index = (mant >> 55) & 0xff;
    uint32_t denominator = 513 + index * 2;

    /* Midpoint reciprocal table, rounded to the architected 11-bit entry. */
    return MIN(0x7fcU, (UINT32_C(1048576) + denominator / 2) /
                            denominator);
}

static uint16_t ia64_fp_rsqrt_entry(const IA64FpFormat *fmt)
{
    uint32_t index = (fmt->mant >> 56) & 0x7f;
    uint32_t denominator = (257 + 2 * index) *
                           ((fmt->exp & 1) ? 1 : 2);
    uint32_t low = 0;
    uint32_t high = 2048;
    uint32_t entry;

    /* Integer form of round(32768 / sqrt(denominator)). */
    while (low < high) {
        uint32_t mid = (low + high + 1) / 2;

        if ((uint64_t)mid * mid * denominator <= (UINT64_C(1) << 30)) {
            low = mid;
        } else {
            high = mid - 1;
        }
    }
    entry = low;
    if ((uint64_t)denominator *
        (4 * (uint64_t)entry * entry + 4 * entry + 1) <=
        (UINT64_C(1) << 32)) {
        entry++;
    }

    return MIN(entry, 0x7fcU);
}

static IA64FloatReg ia64_fp_approx_value(bool sign, uint32_t exp,
                                         uint16_t entry)
{
    IA64FloatReg result = {
        .raw = { (uint64_t)entry << 53,
                 exp | ((uint64_t)sign << 17) },
    };

    return result;
}

static floatx80 ia64_fp_muladd(floatx80 a, floatx80 b, floatx80 c,
                               int flags, float_status *status)
{
    float128 result = float128_muladd(floatx80_to_float128(a, status),
                                      floatx80_to_float128(b, status),
                                      floatx80_to_float128(c, status),
                                      flags, status);

    return float128_to_floatx80(result, status);
}

static bool ia64_fp_any_nat2(const IA64FloatReg *a, const IA64FloatReg *b)
{
    return ia64_fp_fr_nat(a) || ia64_fp_fr_nat(b);
}

static bool ia64_fp_any_nat3(const IA64FloatReg *a, const IA64FloatReg *b,
                             const IA64FloatReg *c)
{
    return ia64_fp_fr_nat(a) || ia64_fp_fr_nat(b) || ia64_fp_fr_nat(c);
}

static void ia64_fp_set_x80_result(IA64FpTransaction *tx, floatx80 result)
{
    tx->result = ia64_fp_from_x80(result);
    tx->write_fr = true;
}

static void ia64_fp_set_nat_result(IA64FpTransaction *tx)
{
    tx->result = ia64_fp_natval();
    tx->write_fr = true;
}

static void ia64_fp_scalar_binary(IA64FpTransaction *tx, uint32_t opcode,
                                  const IA64FloatReg *a,
                                  const IA64FloatReg *b)
{
    floatx80 result;

    if (ia64_fp_any_nat2(a, b)) {
        ia64_fp_set_nat_result(tx);
        return;
    }
    switch (opcode) {
    case IA64_OP_FADD:
        result = floatx80_add(ia64_fp_to_x80(a), ia64_fp_to_x80(b),
                              &tx->status);
        break;
    case IA64_OP_FSUB:
        result = floatx80_sub(ia64_fp_to_x80(a), ia64_fp_to_x80(b),
                              &tx->status);
        break;
    case IA64_OP_FMPY:
        result = floatx80_mul(ia64_fp_to_x80(a), ia64_fp_to_x80(b),
                              &tx->status);
        break;
    default:
        g_assert_not_reached();
    }
    ia64_fp_set_x80_result(tx, result);
}

static void ia64_fp_scalar_fma(IA64FpTransaction *tx, uint32_t opcode,
                               const IA64FloatReg *addend,
                               const IA64FloatReg *multiplicand,
                               const IA64FloatReg *multiplier)
{
    int flags = opcode == IA64_OP_FMS ? float_muladd_negate_c :
                opcode == IA64_OP_FNMA ? float_muladd_negate_product : 0;

    if (ia64_fp_any_nat3(addend, multiplicand, multiplier)) {
        ia64_fp_set_nat_result(tx);
        return;
    }
    ia64_fp_set_x80_result(
        tx, ia64_fp_muladd(ia64_fp_to_x80(multiplicand),
                           ia64_fp_to_x80(multiplier),
                           ia64_fp_to_x80(addend), flags, &tx->status));
}

static uint64_t ia64_fp_scalar_compare(IA64FpTransaction *tx,
                                       const IA64FloatReg *left,
                                       const IA64FloatReg *right,
                                       uint32_t relation)
{
    FloatRelation rel;
    bool condition;

    if (ia64_fp_any_nat2(left, right)) {
        return 0;
    }
    rel = floatx80_compare(ia64_fp_to_x80(left), ia64_fp_to_x80(right),
                           &tx->status);
    switch (relation & 3) {
    case 0: condition = rel == float_relation_equal; break;
    case 1: condition = rel == float_relation_less; break;
    case 2: condition = rel == float_relation_less ||
                        rel == float_relation_equal; break;
    default: condition = rel == float_relation_unordered; break;
    }
    return (condition ? 1 : 0) | (condition ? 0 : 2);
}

static void ia64_fp_scalar_minmax(IA64FpTransaction *tx, uint32_t opcode,
                                  const IA64FloatReg *left,
                                  const IA64FloatReg *right)
{
    bool maximum = opcode == IA64_OP_FMAX || opcode == IA64_OP_FAMAX;
    bool absolute = opcode == IA64_OP_FAMIN || opcode == IA64_OP_FAMAX;
    floatx80 a;
    floatx80 b;
    FloatRelation rel;

    if (ia64_fp_any_nat2(left, right)) {
        ia64_fp_set_nat_result(tx);
        return;
    }
    if (ia64_fp_fr_nan(left) || ia64_fp_fr_nan(right)) {
        float_raise(float_flag_invalid, &tx->status);
        tx->result = *right;
        tx->write_fr = true;
        return;
    }
    a = ia64_fp_to_x80(left);
    b = ia64_fp_to_x80(right);
    rel = floatx80_compare(absolute ? floatx80_abs(a) : a,
                           absolute ? floatx80_abs(b) : b, &tx->status);
    tx->result = (maximum ? rel == float_relation_greater :
                            rel == float_relation_less) ? *left : *right;
    tx->write_fr = true;
}

static uint64_t ia64_fp_to_fixed(IA64FpTransaction *tx,
                                 const IA64FloatReg *source,
                                 bool is_unsigned, bool truncate)
{
    floatx80 value = ia64_fp_to_x80(source);

    if (is_unsigned) {
        float128 wide = floatx80_to_float128(value, &tx->status);

        return truncate ? float128_to_uint64_round_to_zero(wide,
                                                           &tx->status) :
                          float128_to_uint64(wide, &tx->status);
    }
    return truncate ? (uint64_t)floatx80_to_int64_round_to_zero(
                          value, &tx->status) :
                      (uint64_t)floatx80_to_int64(value, &tx->status);
}

static bool ia64_fp_finite_nonzero(const IA64FloatReg *reg)
{
    return !ia64_fp_fr_zero(reg) && !ia64_fp_fr_inf(reg) &&
           !ia64_fp_fr_nan(reg) && !ia64_fp_fr_nat(reg) && reg->raw[0] != 0;
}

static bool ia64_fp_frcpa(IA64FpTransaction *tx, const IA64FloatReg *num,
                          const IA64FloatReg *den)
{
    IA64FpFormat num_fmt;
    IA64FpFormat den_fmt;
    bool predicate;

    if (ia64_fp_any_nat2(num, den)) {
        ia64_fp_set_nat_result(tx);
        return false;
    }
    num_fmt = ia64_fp_format(num);
    den_fmt = ia64_fp_format(den);
    predicate = ia64_fp_finite_nonzero(num) &&
                ia64_fp_finite_nonzero(den);
    if (predicate && ia64_fp_format_normal(&den_fmt)) {
        int32_t est_exp = (int32_t)num_fmt.exp - (int32_t)den_fmt.exp;

        if (den_fmt.exp == 0 || den_fmt.exp >= 2 * IA64_FP_FR_BIAS - 2 ||
            est_exp <= 2 - (int32_t)IA64_FP_FR_BIAS ||
            est_exp >= (int32_t)IA64_FP_FR_BIAS || num_fmt.exp <= 64) {
            tx->forced_fault = 8; /* software-assist */
        }
        tx->result = ia64_fp_approx_value(
            den_fmt.sign, ia64_fp_recip_exp(den_fmt.exp),
            ia64_fp_recip_entry(den_fmt.mant));
        tx->write_fr = true;
    } else {
        floatx80 numerator = predicate ?
            make_floatx80(0x3fff, IA64_FP_FR_INTEGER_BIT) :
            ia64_fp_to_x80(num);

        ia64_fp_set_x80_result(
            tx, floatx80_div(numerator, ia64_fp_to_x80(den), &tx->status));
    }
    return predicate;
}

static bool ia64_fp_frsqrta(IA64FpTransaction *tx,
                            const IA64FloatReg *source)
{
    IA64FpFormat fmt;
    floatx80 value;
    bool predicate;

    if (ia64_fp_fr_nat(source)) {
        ia64_fp_set_nat_result(tx);
        return false;
    }
    fmt = ia64_fp_format(source);
    value = ia64_fp_to_x80(source);
    if (floatx80_is_zero(value) ||
        (!floatx80_is_neg(value) && floatx80_is_infinity(value,
                                                         &tx->status))) {
        tx->result = *source;
        tx->write_fr = true;
        return false;
    }
    predicate = !floatx80_is_neg(value) && !floatx80_is_any_nan(value) &&
                !floatx80_is_infinity(value, &tx->status);
    if (predicate && ia64_fp_format_normal(&fmt)) {
        if (fmt.exp <= 64) {
            tx->forced_fault = 8;
        }
        tx->result = ia64_fp_approx_value(
            false, ia64_fp_rsqrt_exp(fmt.exp), ia64_fp_rsqrt_entry(&fmt));
        tx->write_fr = true;
    } else {
        floatx80 root = floatx80_sqrt(value, &tx->status);
        floatx80 one = make_floatx80(0x3fff, IA64_FP_FR_INTEGER_BIT);

        ia64_fp_set_x80_result(tx,
                               floatx80_div(one, root, &tx->status));
    }
    return predicate;
}

static bool ia64_fp_float32_normal(uint32_t bits, IA64FpFormat *fmt)
{
    uint32_t exponent = (bits >> 23) & 0xff;
    uint32_t fraction = bits & 0x7fffff;

    if (exponent == 0 || exponent == 0xff) {
        return false;
    }
    fmt->sign = bits >> 31;
    fmt->exp = exponent + IA64_FP_FR_BIAS - 127;
    fmt->mant = IA64_FP_FR_INTEGER_BIT | ((uint64_t)fraction << 40);
    return true;
}

static uint32_t ia64_fp_approx_to_f32(IA64FloatReg value,
                                      const float_status *base)
{
    float_status status = *base;

    set_float_exception_flags(0, &status);
    return float32_val(floatx80_to_float32(ia64_fp_to_x80(&value), &status));
}

static uint32_t ia64_fp_rcpa_lane(uint32_t num_bits, uint32_t den_bits,
                                  const float_status *base, bool *predicate,
                                  int *soft)
{
    float32 num = make_float32(num_bits);
    float32 den = make_float32(den_bits);
    IA64FpFormat den_fmt = { 0 };
    float_status status = *base;
    bool normal = ia64_fp_float32_normal(den_bits, &den_fmt);
    float32 result;

    set_float_exception_flags(0, &status);
    *predicate = !float32_is_zero(num) && !float32_is_infinity(num) &&
                 !float32_is_any_nan(num) && !float32_is_zero(den) &&
                 !float32_is_infinity(den) && !float32_is_any_nan(den) &&
                 normal;
    if (*predicate) {
        IA64FloatReg approx = ia64_fp_approx_value(
            den_fmt.sign, ia64_fp_recip_exp(den_fmt.exp),
            ia64_fp_recip_entry(den_fmt.mant));

        result = make_float32(ia64_fp_approx_to_f32(approx, base));
    } else {
        result = float32_div(num, den, &status);
    }
    *soft = get_float_exception_flags(&status);
    return float32_val(result);
}

static uint32_t ia64_fp_rsqrta_lane(uint32_t bits,
                                    const float_status *base,
                                    bool *predicate, int *soft)
{
    float32 value = make_float32(bits);
    IA64FpFormat fmt = { 0 };
    float_status status = *base;
    bool normal = ia64_fp_float32_normal(bits, &fmt);
    float32 result;

    set_float_exception_flags(0, &status);
    *predicate = !float32_is_zero(value) && !float32_is_neg(value) &&
                 !float32_is_infinity(value) && !float32_is_any_nan(value) &&
                 normal;
    if (*predicate) {
        IA64FloatReg approx = ia64_fp_approx_value(
            false, ia64_fp_rsqrt_exp(fmt.exp), ia64_fp_rsqrt_entry(&fmt));

        result = make_float32(ia64_fp_approx_to_f32(approx, base));
    } else {
        float32 root = float32_sqrt(value, &status);

        result = float32_div(float32_one, root, &status);
    }
    *soft = get_float_exception_flags(&status);
    return float32_val(result);
}

static bool ia64_fp_paired_approx(IA64FpTransaction *tx, uint32_t opcode,
                                  const IA64FloatReg *left,
                                  const IA64FloatReg *right)
{
    uint64_t a = left ? left->raw[0] : 0;
    uint64_t b = right->raw[0];
    uint32_t hi;
    uint32_t lo;
    bool hi_pred;
    bool lo_pred;

    tx->paired = true;
    if (ia64_fp_fr_nat(right) || (left && ia64_fp_fr_nat(left))) {
        ia64_fp_set_nat_result(tx);
        return false;
    }
    if (opcode == IA64_OP_FPRCPA) {
        hi = ia64_fp_rcpa_lane(a >> 32, b >> 32, &tx->status,
                               &hi_pred, &tx->hi_soft);
        lo = ia64_fp_rcpa_lane(a, b, &tx->status,
                               &lo_pred, &tx->lo_soft);
    } else {
        hi = ia64_fp_rsqrta_lane(b >> 32, &tx->status,
                                 &hi_pred, &tx->hi_soft);
        lo = ia64_fp_rsqrta_lane(b, &tx->status,
                                 &lo_pred, &tx->lo_soft);
    }
    tx->result = ia64_fp_significand(((uint64_t)hi << 32) | lo);
    tx->write_fr = true;
    return hi_pred && lo_pred;
}

static uint32_t ia64_fp_minmax_lane(uint32_t a_bits, uint32_t b_bits,
                                    bool maximum, bool absolute,
                                    float_status *status)
{
    float32 a = make_float32(a_bits);
    float32 b = make_float32(b_bits);
    FloatRelation rel;

    if (float32_is_any_nan(a) || float32_is_any_nan(b)) {
        float_raise(float_flag_invalid, status);
        return b_bits;
    }
    rel = float32_compare(absolute ? float32_abs(a) : a,
                          absolute ? float32_abs(b) : b, status);
    return (maximum ? rel == float_relation_greater :
                      rel == float_relation_less) ? a_bits : b_bits;
}

static bool ia64_fp_compare_lane(uint32_t a, uint32_t b, uint32_t relation,
                                 float_status *status)
{
    FloatRelation rel = float32_compare(make_float32(a), make_float32(b),
                                        status);

    switch (relation & 7) {
    case 0: return rel == float_relation_equal;
    case 1: return rel == float_relation_less;
    case 2: return rel == float_relation_less || rel == float_relation_equal;
    case 3: return rel == float_relation_unordered;
    case 4: return rel != float_relation_equal;
    case 5: return rel != float_relation_less;
    case 6: return rel != float_relation_less && rel != float_relation_equal;
    default: return rel != float_relation_unordered;
    }
}

static void ia64_fp_paired_binary(IA64FpTransaction *tx, uint32_t opcode,
                                  const IA64FloatReg *left,
                                  const IA64FloatReg *right,
                                  uint32_t relation)
{
    float_status hi_status = tx->status;
    float_status lo_status = tx->status;
    uint32_t hi;
    uint32_t lo;

    tx->paired = true;
    set_float_exception_flags(0, &hi_status);
    set_float_exception_flags(0, &lo_status);
    if (ia64_fp_any_nat2(left, right)) {
        ia64_fp_set_nat_result(tx);
        return;
    }
    if (opcode == IA64_OP_FPCMP) {
        hi = ia64_fp_compare_lane(left->raw[0] >> 32, right->raw[0] >> 32,
                                  relation, &hi_status) ? UINT32_MAX : 0;
        lo = ia64_fp_compare_lane(left->raw[0], right->raw[0], relation,
                                  &lo_status) ? UINT32_MAX : 0;
    } else {
        bool maximum = opcode == IA64_OP_FPMAX || opcode == IA64_OP_FPAMAX;
        bool absolute = opcode == IA64_OP_FPAMIN ||
                        opcode == IA64_OP_FPAMAX;

        hi = ia64_fp_minmax_lane(left->raw[0] >> 32,
                                 right->raw[0] >> 32, maximum, absolute,
                                 &hi_status);
        lo = ia64_fp_minmax_lane(left->raw[0], right->raw[0], maximum,
                                 absolute, &lo_status);
    }
    tx->hi_soft = get_float_exception_flags(&hi_status);
    tx->lo_soft = get_float_exception_flags(&lo_status);
    tx->result = ia64_fp_significand(((uint64_t)hi << 32) | lo);
    tx->write_fr = true;
}

static uint32_t ia64_fp_convert_lane(uint32_t bits, bool is_unsigned,
                                     bool truncate, float_status *status)
{
    float32 value = make_float32(bits);

    if (is_unsigned) {
        return truncate ? float32_to_uint32_round_to_zero(value, status) :
                          float32_to_uint32(value, status);
    }
    return truncate ? (uint32_t)float32_to_int32_round_to_zero(value,
                                                                status) :
                      (uint32_t)float32_to_int32(value, status);
}

static void ia64_fp_paired_convert(IA64FpTransaction *tx,
                                   const IA64FloatReg *source,
                                   bool is_unsigned, bool truncate)
{
    float_status hi_status = tx->status;
    float_status lo_status = tx->status;
    uint32_t hi;
    uint32_t lo;

    tx->paired = true;
    if (ia64_fp_fr_nat(source)) {
        ia64_fp_set_nat_result(tx);
        return;
    }
    set_float_exception_flags(0, &hi_status);
    set_float_exception_flags(0, &lo_status);
    hi = ia64_fp_convert_lane(source->raw[0] >> 32, is_unsigned, truncate,
                              &hi_status);
    lo = ia64_fp_convert_lane(source->raw[0], is_unsigned, truncate,
                              &lo_status);
    tx->hi_soft = get_float_exception_flags(&hi_status);
    tx->lo_soft = get_float_exception_flags(&lo_status);
    tx->result = ia64_fp_significand(((uint64_t)hi << 32) | lo);
    tx->write_fr = true;
}

static uint32_t ia64_fp_muladd_lane(uint32_t addend, uint32_t a, uint32_t b,
                                    uint32_t form, float_status *status)
{
    float32 c = make_float32(addend);
    float32 left = make_float32(a);

    if (form == 1) {
        c = float32_chs(c);
    } else if (form == 2) {
        left = float32_chs(left);
    }
    return float32_val(float32_muladd(left, make_float32(b), c, 0, status));
}

static void ia64_fp_paired_fma(IA64FpTransaction *tx, uint32_t opcode,
                               const IA64FloatReg *addend,
                               const IA64FloatReg *left,
                               const IA64FloatReg *right)
{
    float_status hi_status = tx->status;
    float_status lo_status = tx->status;
    uint32_t form = opcode == IA64_OP_FPMS ? 1 :
                    opcode == IA64_OP_FPNMA ? 2 : 0;
    uint32_t hi;
    uint32_t lo;

    tx->paired = true;
    if (ia64_fp_any_nat3(addend, left, right)) {
        ia64_fp_set_nat_result(tx);
        return;
    }
    set_float_exception_flags(0, &hi_status);
    set_float_exception_flags(0, &lo_status);
    hi = ia64_fp_muladd_lane(addend->raw[0] >> 32, left->raw[0] >> 32,
                             right->raw[0] >> 32, form, &hi_status);
    lo = ia64_fp_muladd_lane(addend->raw[0], left->raw[0], right->raw[0],
                             form, &lo_status);
    tx->hi_soft = get_float_exception_flags(&hi_status);
    tx->lo_soft = get_float_exception_flags(&lo_status);
    tx->result = ia64_fp_significand(((uint64_t)hi << 32) | lo);
    tx->write_fr = true;
}

uint64_t HELPER(fp_compute)(CPUIA64State *env, uint32_t opcode,
                            uint32_t f1, uint32_t f2, uint32_t f3,
                            uint32_t f4, uint64_t controls)
{
    IA64FpTransaction transaction;
    const IA64FloatReg *source2 = NULL;
    const IA64FloatReg *source3 = NULL;
    const IA64FloatReg *source4 = NULL;
    uint32_t immediate = IA64_FP_CTL_IMM(controls);
    uint64_t result = 0;

    ia64_fp_transaction_begin(&transaction, env, opcode, controls);
    switch ((IA64Opcode)opcode) {
    case IA64_OP_FADD:
    case IA64_OP_FSUB:
    case IA64_OP_FMPY:
        source2 = ia64_read_fr_ordinary(env, f2);
        source3 = ia64_read_fr_ordinary(env, f3);
        ia64_fp_scalar_binary(&transaction, opcode, source2, source3);
        break;
    case IA64_OP_FMA:
    case IA64_OP_FMS:
    case IA64_OP_FNMA:
        source2 = ia64_read_fr_ordinary(env, f2);
        source3 = ia64_read_fr_ordinary(env, f3);
        source4 = ia64_read_fr_ordinary(env, f4);
        ia64_fp_scalar_fma(&transaction, opcode, source2, source3, source4);
        break;
    case IA64_OP_FNORM:
        source3 = ia64_read_fr_ordinary(env, f3);
        if (ia64_fp_fr_nat(source3)) {
            ia64_fp_set_nat_result(&transaction);
        } else {
            ia64_fp_set_x80_result(
                &transaction,
                floatx80_round(ia64_fp_to_x80(source3),
                               &transaction.status));
        }
        break;
    case IA64_OP_FCMP:
        transaction.allow_traps = false;
        source2 = ia64_read_fr_ordinary(env, f2);
        source3 = ia64_read_fr_ordinary(env, f3);
        result = ia64_fp_scalar_compare(&transaction, source2, source3,
                                        immediate);
        break;
    case IA64_OP_FMIN:
    case IA64_OP_FMAX:
    case IA64_OP_FAMIN:
    case IA64_OP_FAMAX:
        transaction.allow_traps = false;
        source2 = ia64_read_fr_ordinary(env, f2);
        source3 = ia64_read_fr_ordinary(env, f3);
        ia64_fp_scalar_minmax(&transaction, opcode, source2, source3);
        break;
    case IA64_OP_FRCPA:
        transaction.allow_traps = false;
        source2 = ia64_read_fr_ordinary(env, f2);
        source3 = ia64_read_fr_ordinary(env, f3);
        result = ia64_fp_frcpa(&transaction, source2, source3);
        break;
    case IA64_OP_FPRCPA:
        transaction.allow_traps = false;
        source2 = ia64_read_fr_ordinary(env, f2);
        source3 = ia64_read_fr_ordinary(env, f3);
        result = ia64_fp_paired_approx(&transaction, opcode,
                                       source2, source3);
        break;
    case IA64_OP_FPRSQRTA:
        transaction.allow_traps = false;
        source3 = ia64_read_fr_ordinary(env, f3);
        result = ia64_fp_paired_approx(&transaction, opcode,
                                       NULL, source3);
        break;
    case IA64_OP_FRSQRTA:
        transaction.allow_traps = false;
        source3 = ia64_read_fr_ordinary(env, f3);
        result = ia64_fp_frsqrta(&transaction, source3);
        break;
    case IA64_OP_FCVT_FX:
    case IA64_OP_FCVT_FXU:
        source2 = ia64_read_fr_ordinary(env, f2);
        if (ia64_fp_fr_nat(source2)) {
            ia64_fp_set_nat_result(&transaction);
        } else {
            transaction.result = ia64_fp_significand(
                ia64_fp_to_fixed(&transaction, source2,
                                 opcode == IA64_OP_FCVT_FXU,
                                 (immediate & 2) != 0));
            transaction.write_fr = true;
        }
        break;
    case IA64_OP_GETF_D:
    case IA64_OP_GETF_S:
        transaction.record_exceptions = false;
        transaction.allow_traps = false;
        source2 = ia64_read_fr_ordinary(env, f2);
        if (!ia64_fp_fr_nat(source2)) {
            result = opcode == IA64_OP_GETF_D ?
                     ia64_read_fr_as_double_bits(source2) :
                     ia64_read_fr_as_single_bits(source2);
        }
        break;
    case IA64_OP_SETF_D:
    case IA64_OP_SETF_S:
        transaction.record_exceptions = false;
        transaction.allow_traps = false;
        if (ia64_read_gr_nat(env, f2)) {
            ia64_fp_set_nat_result(&transaction);
        } else {
            transaction.result = ia64_fp_from_ieee(
                ia64_read_gr(env, f2), opcode == IA64_OP_SETF_S);
            transaction.write_fr = true;
        }
        break;
    case IA64_OP_FPACK:
    {
        float_status high_status = transaction.status;
        float_status low_status = transaction.status;
        float32 high;
        float32 low;

        transaction.record_exceptions = false;
        transaction.allow_traps = false;
        source2 = ia64_read_fr_ordinary(env, f2);
        source3 = ia64_read_fr_ordinary(env, f3);
        if (ia64_fp_any_nat2(source2, source3)) {
            ia64_fp_set_nat_result(&transaction);
        } else {
            high = floatx80_to_float32(ia64_fp_to_x80(source2),
                                       &high_status);
            low = floatx80_to_float32(ia64_fp_to_x80(source3),
                                      &low_status);
            transaction.result = ia64_fp_significand(
                ((uint64_t)float32_val(high) << 32) | float32_val(low));
            transaction.write_fr = true;
        }
        break;
    }
    case IA64_OP_FPMIN:
    case IA64_OP_FPMAX:
    case IA64_OP_FPAMIN:
    case IA64_OP_FPAMAX:
    case IA64_OP_FPCMP:
        transaction.allow_traps = false;
        source2 = ia64_read_fr_ordinary(env, f2);
        source3 = ia64_read_fr_ordinary(env, f3);
        ia64_fp_paired_binary(&transaction, opcode, source2, source3,
                              immediate);
        break;
    case IA64_OP_FPCVT:
        source2 = ia64_read_fr_ordinary(env, f2);
        ia64_fp_paired_convert(&transaction, source2,
                               (immediate & 1) != 0,
                               (immediate & 2) != 0);
        break;
    case IA64_OP_FPMA:
    case IA64_OP_FPMS:
    case IA64_OP_FPNMA:
        source2 = ia64_read_fr_ordinary(env, f2);
        source3 = ia64_read_fr_ordinary(env, f3);
        source4 = ia64_read_fr_ordinary(env, f4);
        ia64_fp_paired_fma(&transaction, opcode, source2, source3, source4);
        break;
    default:
        g_assert_not_reached();
    }

    /* Payload-bearing rows are non-trapping; a no-return post-result trap
     * therefore cannot bypass a GR/PR result staged by the translator. */
    g_assert(!transaction.allow_traps || result == 0);
    ia64_fp_transaction_finish(&transaction, env, f1);
    return result;
}

#undef IA64_FP_CTL_P2
#undef IA64_FP_CTL_P1
#undef IA64_FP_CTL_IMM
#undef IA64_FP_CTL_PREC
#undef IA64_FP_CTL_SF
#undef IA64_FP_SF_TD
#undef IA64_FP_SF_FLAGS_SHIFT
#undef IA64_FP_SF_SHIFT
#undef IA64_FP_FPSR_TRAPS
#undef IA64_FP_FR_QUIET_BIT
#undef IA64_FP_FR_INTEGER_BIT
#undef IA64_FP_FR_NAT_EXP
#undef IA64_FP_FR_SPECIAL_EXP
#undef IA64_FP_FR_INTEGER_EXP
#undef IA64_FP_FR_BIAS
