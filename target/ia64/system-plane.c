/*
 * IA-64 normalized system/control transactions.
 *
 * This module is part of the production typed engine.  Its helper entry takes
 * an enum opcode and decoded operands only; it never receives an instruction
 * slot or performs a second decode.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "accel/tcg/cpu-loop.h"
#include "exec/cputlb.h"
#include "hw/core/cpu.h"
#include "cpu.h"
#include "decode.h"
#include "exception.h"
#include "insn.h"
#include "mem.h"
#include "system-plane.h"
#include "exec/helper-proto.h"

#define IA64_RR_IMPLEMENTED_MASK UINT64_C(0x00000000fffffffd)
#define IA64_PSR_LOWER_WRITABLE_MASK UINT64_C(0x000000000fffe03e)
#define IA64_PSR_MC_BIT UINT64_C(0x0000000800000000)
#define IA64_PSR_IS_BIT UINT64_C(0x0000000400000000)
#define IA64_DEBUG_DBR_IGNORED_MASK (UINT64_C(3) << 60)
#define IA64_DEBUG_IBR_IGNORED_MASK (UINT64_C(7) << 60)

static G_NORETURN void ia64_system_raise_general(CPUIA64State *env,
                                                  uint16_t code);
static G_NORETURN void ia64_system_raise_illegal(CPUIA64State *env);

static bool ia64_system_reserved_pfs(uint64_t value)
{
    uint32_t sof = value & 0x7f;
    uint32_t sol = (value >> 7) & 0x7f;
    uint32_t sor = ((value >> 14) & 0xf) << 3;
    uint32_t rrb_gr = (value >> 18) & 0x7f;
    uint32_t rrb_fr = (value >> 25) & 0x7f;
    uint32_t rrb_pr = (value >> 32) & 0x3f;

    if ((value & (UINT64_C(0xf) << 58)) ||
        (value & (UINT64_C(0x3fff) << 38))) {
        return true;
    }
    return sof > IA64_RSE_PHYS_STACKED_REGS || sol > sof || sor > sof ||
           (sor ? rrb_gr >= sor : rrb_gr != 0) ||
           rrb_fr >= 96 || rrb_pr >= 48;
}

static bool ia64_system_reserved_rsc(uint64_t value)
{
    const uint64_t implemented = UINT64_C(0x1f) |
                                 (UINT64_C(0x3fff) <<
                                  IA64_RSC_LOADRS_SHIFT);

    return (value & ~implemented) != 0;
}

static bool ia64_system_reserved_fpsr(uint64_t value)
{
    return (value >> 58) != 0 || ((value >> 12) & 1) != 0 ||
           ((value >> 47) & 3) == 1 || ((value >> 34) & 3) == 1 ||
           ((value >> 21) & 3) == 1 || ((value >> 8) & 3) == 1;
}

static bool ia64_system_reserved_cr_value(uint32_t reg, uint64_t value)
{
    switch (reg) {
    case IA64_CR_DCR:
        return (value >> 15) != 0 ||
               (value & (UINT64_C(0x1f) << 3)) != 0;
    case IA64_CR_PTA:
    {
        uint8_t ps = (value >> 2) & 0x3f;

        return (value & (UINT64_C(0x3f) << 9)) != 0 ||
               (value & UINT64_C(2)) != 0 || ps < 15;
    }
    case IA64_CR_IPSR:
        return (value >> 46) != 0 || ((value >> 41) & 3) == 3 ||
               ((value >> 28) & 0xf) != 0 ||
               ((value >> 16) & 1) != 0 ||
               ((value >> 6) & 0x7f) != 0 || (value & 1) != 0;
    case IA64_CR_ISR:
        return (value >> 44) != 0 || ((value >> 41) & 3) == 3 ||
               ((value >> 24) & 0xff) != 0;
    case IA64_CR_IFS:
        return (value & (UINT64_C(0x1ffffff) << 38)) != 0 ||
               ((value >> 63) && ia64_system_reserved_pfs(value));
    case IA64_CR_LID:
        return (value & UINT64_C(0xffff)) != 0;
    case IA64_CR_IVR:
        return (value & UINT64_C(0xff)) != 0;
    case IA64_CR_TPR:
        return (value & UINT64_C(0xff00)) != 0;
    case IA64_CR_ITV:
    case IA64_CR_PMV:
    case IA64_CR_CMCV:
        return (value & (UINT64_C(7) << 13)) != 0 ||
               (value & (UINT64_C(0xf) << 8)) != 0;
    case IA64_CR_LRR0:
    case IA64_CR_LRR1:
    {
        uint8_t delivery_mode = (value >> 8) & 7;

        return (value & (UINT64_C(1) << 14)) != 0 ||
               (value & (UINT64_C(1) << 11)) != 0 ||
               delivery_mode == 1 || delivery_mode == 3 ||
               delivery_mode == 6;
    }
    default:
        return false;
    }
}

static uint64_t ia64_system_normalize_cr_value(uint32_t reg, uint64_t value)
{
    switch (reg) {
    case IA64_CR_IVA:
        return value & ~UINT64_C(0x7fff);
    case IA64_CR_IHA:
        return value & ~UINT64_C(3);
    case IA64_CR_LID:
        return value & UINT64_C(0x00000000ffff0000);
    case IA64_CR_TPR:
        return value & UINT64_C(0x100f0);
    case IA64_CR_EOI:
        return 0;
    case IA64_CR_ITV:
    case IA64_CR_PMV:
    case IA64_CR_CMCV:
        return value & UINT64_C(0x100ff);
    case IA64_CR_LRR0:
    case IA64_CR_LRR1:
        return value & UINT64_C(0x1a7ff);
    default:
        return value;
    }
}

static uint64_t ia64_system_validate_cr_access(CPUIA64State *env,
                                                uint32_t reg,
                                                bool write,
                                                uint64_t value)
{
    if ((env->psr & IA64_PSR_IC_BIT) &&
        reg >= IA64_CR_IPSR && reg <= IA64_CR_IIB1) {
        ia64_system_raise_illegal(env);
    }
    if (write && (reg == IA64_CR_IVR ||
                  (reg >= IA64_CR_IRR0 && reg <= IA64_CR_IRR3))) {
        ia64_system_raise_illegal(env);
    }
    if (write && ia64_system_reserved_cr_value(reg, value)) {
        ia64_system_raise_general(env, 0x30);
    }
    return write ? ia64_system_normalize_cr_value(reg, value) : value;
}

static void ia64_system_validate_cr_legality(CPUIA64State *env,
                                              uint32_t reg, bool write)
{
    if ((env->psr & IA64_PSR_IC_BIT) &&
        reg >= IA64_CR_IPSR && reg <= IA64_CR_IIB1) {
        ia64_system_raise_illegal(env);
    }
    if (write && (reg == IA64_CR_IVR ||
                  (reg >= IA64_CR_IRR0 && reg <= IA64_CR_IRR3))) {
        ia64_system_raise_illegal(env);
    }
}

static G_NORETURN void ia64_system_exit(CPUIA64State *env)
{
    env->fault_exit_pending_tb_translate = true;
    cpu_loop_exit(env_cpu(env));
}

static G_NORETURN void ia64_system_raise_general_isr(CPUIA64State *env,
                                                      uint16_t code,
                                                      uint64_t isr_extra)
{
    ia64_deliver_exception_fast(env, IA64_EXCEPTION_GENERAL_EXCEPTION,
                                env->ip, IA64_EXCEPTION_ACCESS_NONE, NULL);
    env->exception.isr_code = code;
    env->cr[IA64_CR_ISR] = (env->cr[IA64_CR_ISR] & ~IA64_ISR_CODE_MASK) |
                           code | isr_extra;
    ia64_system_exit(env);
}

static G_NORETURN void ia64_system_raise_general(CPUIA64State *env,
                                                  uint16_t code)
{
    ia64_system_raise_general_isr(env, code, 0);
}

static G_NORETURN void ia64_system_raise_illegal(CPUIA64State *env)
{
    ia64_deliver_illegal_operation_fast(env);
    ia64_system_exit(env);
}

static G_NORETURN void ia64_system_raise_non_access_translation(
    CPUIA64State *env, IA64ExceptionKind kind, uint64_t address,
    const char *message, bool read, bool write, uint16_t code)
{
    int access = read && write ? IA64_EXCEPTION_ACCESS_SEMAPHORE_NON_ACCESS :
                 (read ? IA64_EXCEPTION_ACCESS_READ_NON_ACCESS :
                  (write ? IA64_EXCEPTION_ACCESS_WRITE_NON_ACCESS :
                           IA64_EXCEPTION_ACCESS_NONE));

    ia64_deliver_exception(env, kind, address, access, message);
    env->exception.isr_code = code;
    env->cr[IA64_CR_ISR] =
        (env->cr[IA64_CR_ISR] & ~IA64_ISR_CODE_MASK) |
        (UINT64_C(1) << IA64_ISR_NA_BIT) | code;
    ia64_system_exit(env);
}

static G_NORETURN void ia64_system_raise_probe_translation(
    CPUIA64State *env, const IA64TranslateResult *result,
    bool read, bool write, uint16_t non_access_code)
{
    int access = read && write ? IA64_EXCEPTION_ACCESS_SEMAPHORE_NON_ACCESS :
                 (write ? IA64_EXCEPTION_ACCESS_WRITE_NON_ACCESS :
                          IA64_EXCEPTION_ACCESS_READ_NON_ACCESS);

    ia64_deliver_exception(env, ia64_exception_for_translate_result(result),
                           result->vaddr, access, result->message);
    env->exception.isr_code = non_access_code;
    env->cr[IA64_CR_ISR] =
        (env->cr[IA64_CR_ISR] & ~IA64_ISR_CODE_MASK) | non_access_code;
    ia64_system_exit(env);
}

static G_NORETURN void ia64_system_raise_probe_debug(
    CPUIA64State *env, uint64_t address, bool read, bool write)
{
    int access = read && write ? IA64_EXCEPTION_ACCESS_SEMAPHORE_NON_ACCESS :
                 (write ? IA64_EXCEPTION_ACCESS_WRITE_NON_ACCESS :
                          IA64_EXCEPTION_ACCESS_READ_NON_ACCESS);

    ia64_deliver_exception(env, IA64_EXCEPTION_DATA_DEBUG, address, access,
                           "fault-form probe data debug match");
    env->exception.isr_code = 5;
    env->cr[IA64_CR_ISR] =
        (env->cr[IA64_CR_ISR] & ~IA64_ISR_CODE_MASK) | UINT64_C(5);
    ia64_system_exit(env);
}

static G_NORETURN void ia64_system_raise_unimplemented_non_access(
    CPUIA64State *env, uint64_t address)
{
    ia64_deliver_exception(env, IA64_EXCEPTION_UNSUPPORTED_DATA_REFERENCE,
                           address, IA64_EXCEPTION_ACCESS_NONE,
                           "unimplemented non-access virtual address");
    env->exception.isr_code = 43;
    env->cr[IA64_CR_ISR] =
        (env->cr[IA64_CR_ISR] & ~IA64_ISR_CODE_MASK) |
        (UINT64_C(1) << IA64_ISR_NA_BIT) | UINT64_C(43);
    ia64_system_exit(env);
}

static unsigned ia64_system_cpl(const CPUIA64State *env)
{
    return (env->psr & IA64_PSR_CPL_MASK) >> IA64_PSR_CPL_SHIFT;
}

static bool ia64_system_always_privileged(IA64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_MOV_CRGR:
    case IA64_OP_MOV_GRCR:
    case IA64_OP_SSM:
    case IA64_OP_RSM:
    case IA64_OP_ITR_D:
    case IA64_OP_ITR_I:
    case IA64_OP_PTR_D:
    case IA64_OP_PTR_I:
    case IA64_OP_PTC_L:
    case IA64_OP_PTC_G:
    case IA64_OP_TPA:
    case IA64_OP_TAK:
    case IA64_OP_PTC_E:
    case IA64_OP_ITC_D:
    case IA64_OP_ITC_I:
    case IA64_OP_PTC_GA:
    case IA64_OP_MOV_PSRGR:
    case IA64_OP_MOV_GRPSR:
    case IA64_OP_MOV_RRGR:
    case IA64_OP_MOV_GRRR:
    case IA64_OP_BSW0:
    case IA64_OP_BSW1:
    case IA64_OP_MOV_PKRGR_INDEXED:
    case IA64_OP_MOV_GRPKR_INDEXED:
    case IA64_OP_MOV_IBRGR_INDEXED:
    case IA64_OP_MOV_GRIBR_INDEXED:
    case IA64_OP_MOV_DBRGR_INDEXED:
    case IA64_OP_MOV_GRDBR_INDEXED:
    case IA64_OP_MOV_PMCGR_INDEXED:
    case IA64_OP_MOV_GRPMC_INDEXED:
    case IA64_OP_MOV_GRPMD_INDEXED:
    case IA64_OP_MOV_DAHRGR_INDEXED:
    case IA64_OP_MOV_MSRGR:
    case IA64_OP_MOV_GRMSR:
        return true;
    default:
        return false;
    }
}

static bool ia64_system_translation_insert_requires_ic_clear(
    IA64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_ITC_D:
    case IA64_OP_ITC_I:
    case IA64_OP_ITR_D:
    case IA64_OP_ITR_I:
        return true;
    default:
        return false;
    }
}

static void ia64_system_validate_privilege(CPUIA64State *env,
                                           IA64Opcode opcode,
                                           uint32_t selector)
{
    unsigned cpl = ia64_system_cpl(env);

    if (ia64_system_always_privileged(opcode) && cpl != 0) {
        uint64_t extra = UINT64_C(0);

        if (opcode == IA64_OP_TAK) {
            extra = (UINT64_C(1) << IA64_ISR_NA_BIT) | UINT64_C(3);
        } else if (opcode == IA64_OP_TPA) {
            extra = UINT64_C(1) << IA64_ISR_NA_BIT;
        }
        ia64_system_raise_general_isr(env, 0x10, extra);
    }
    (void)selector;
}

static void ia64_system_validate_ar_legality(CPUIA64State *env,
                                              uint32_t reg, bool write)
{
    if (reg >= IA64_AR_COUNT) {
        ia64_system_raise_illegal(env);
    }
    if (write && reg == IA64_AR_BSP) {
        /* AR.BSP is the read-only view of the current RSE stack top. */
        ia64_system_raise_illegal(env);
    }
    if ((reg == IA64_AR_BSPSTORE || reg == IA64_AR_RNAT) &&
        (env->rse.rsc & IA64_RSC_MODE_MASK) != 0) {
        ia64_system_raise_illegal(env);
    }
}

static void ia64_system_validate_ar_privilege(CPUIA64State *env,
                                               uint32_t reg, bool write)
{
    unsigned cpl = ia64_system_cpl(env);

    if (write) {
        if ((reg <= 7 || reg == IA64_AR_ITC || reg == IA64_AR_RUC) &&
            cpl != 0) {
            ia64_system_raise_general(env, 0x20);
        }
    } else if ((reg == IA64_AR_ITC || reg == IA64_AR_RUC) &&
               (env->psr & IA64_PSR_SI_BIT) != 0 && cpl != 0) {
        ia64_system_raise_general(env, 0x20);
    }
}

static void ia64_system_validate_ar_preflight(CPUIA64State *env,
                                               uint32_t reg, bool write)
{
    ia64_system_validate_ar_legality(env, reg, write);
    ia64_system_validate_ar_privilege(env, reg, write);
}

static bool ia64_system_ar_write_value_valid(uint32_t reg, uint64_t value)
{
    return !((reg == IA64_AR_RSC && ia64_system_reserved_rsc(value)) ||
             (reg == IA64_AR_FPSR && ia64_system_reserved_fpsr(value)) ||
             (reg == IA64_AR_PFS && ia64_system_reserved_pfs(value)));
}

static void ia64_system_validate_ar_write_value(CPUIA64State *env,
                                                 uint32_t reg,
                                                 uint64_t value)
{
    if (!ia64_system_ar_write_value_valid(reg, value)) {
        ia64_system_raise_general(env, 0x30);
    }
}

static void ia64_system_flush_page(CPUIA64State *env, uint64_t address,
                                   uint8_t page_size)
{
    CPUState *cpu = env_cpu(env);
    vaddr start;
    uint64_t len;

    if (ia64_host_tlb_flush_span(address, page_size, &start, &len)) {
        tlb_flush_range_by_mmuidx(cpu, start, len, IA64_MMU_ALL_IDXMAP,
                                  TARGET_LONG_BITS);
    } else {
        tlb_flush(cpu);
    }
}

static void ia64_system_validate_index(CPUIA64State *env,
                                       uint64_t index, uint64_t count)
{
    if (index >= count) {
        ia64_system_raise_general(env, 0x30);
    }
}

static uint64_t ia64_system_indexed_read(CPUIA64State *env,
                                         IA64Opcode opcode,
                                         uint64_t index)
{
    if (opcode != IA64_OP_MOV_MSRGR) {
        index &= UINT64_C(0xff);
    }
    switch (opcode) {
    case IA64_OP_MOV_PKRGR_INDEXED:
        ia64_system_validate_index(env, index, IA64_PKR_COUNT);
        return env->pkr[index];
    case IA64_OP_MOV_IBRGR_INDEXED:
        ia64_system_validate_index(env, index, IA64_IBR_COUNT);
        return env->ibr[index];
    case IA64_OP_MOV_DBRGR_INDEXED:
        ia64_system_validate_index(env, index, IA64_DBR_COUNT);
        return env->dbr[index];
    case IA64_OP_MOV_PMCGR_INDEXED:
        ia64_system_validate_index(env, index, IA64_PMC_COUNT);
        return env->pmc[index];
    case IA64_OP_MOV_PMDGR_INDEXED:
        ia64_system_validate_index(env, index, IA64_PMD_COUNT);
        /*
         * PMD reads never raise Privileged Register.  At non-zero CPL the
         * secured-monitor policy returns zero; PMC.pm applies only to the
         * generic counters above PMD3.
         */
        if (ia64_system_cpl(env) != 0 &&
            ((env->psr & IA64_PSR_SP_BIT) ||
             (index > 3 && (env->pmc[index] & (UINT64_C(1) << 6))))) {
            return 0;
        }
        return env->pmd[index];
    case IA64_OP_MOV_CPUID_INDEXED:
        ia64_system_validate_index(env, index, IA64_CPUID_COUNT);
        return env->cpuid[index];
    case IA64_OP_MOV_DAHRGR_INDEXED:
        index &= UINT64_C(7);
        return env->dahr[index] & UINT64_C(0x7ff);
    case IA64_OP_MOV_MSRGR:
        return index < IA64_MSR_COUNT ? env->msr[index] : 0;
    default:
        ia64_system_raise_illegal(env);
    }
}

static void ia64_system_indexed_write(CPUIA64State *env,
                                      IA64Opcode opcode, uint64_t value,
                                      uint64_t index)
{
    if (opcode != IA64_OP_MOV_GRMSR) {
        index &= UINT64_C(0xff);
    }
    switch (opcode) {
    case IA64_OP_MOV_GRPKR_INDEXED:
        ia64_system_validate_index(env, index, IA64_PKR_COUNT);
        if (!ia64_pkr_value_valid(value)) {
            ia64_system_raise_general(env, 0x30);
        }
        ia64_pkr_write_state(env, index, value);
        tlb_flush(env_cpu(env));
        return;
    case IA64_OP_MOV_GRIBR_INDEXED:
        ia64_system_validate_index(env, index, IA64_IBR_COUNT);
        if (index & 1) {
            value &= ~IA64_DEBUG_IBR_IGNORED_MASK;
        }
        env->ibr[index] = value;
        return;
    case IA64_OP_MOV_GRDBR_INDEXED:
        ia64_system_validate_index(env, index, IA64_DBR_COUNT);
        if (index & 1) {
            value &= ~IA64_DEBUG_DBR_IGNORED_MASK;
        }
        env->dbr[index] = value;
        return;
    case IA64_OP_MOV_GRPMC_INDEXED:
        ia64_system_validate_index(env, index, IA64_PMC_COUNT);
        env->pmc[index] = value;
        return;
    case IA64_OP_MOV_GRPMD_INDEXED:
        ia64_system_validate_index(env, index, IA64_PMD_COUNT);
        env->pmd[index] = value;
        return;
    case IA64_OP_MOV_GRMSR:
        if (index < IA64_MSR_COUNT) {
            env->msr[index] = value;
        }
        return;
    default:
        ia64_system_raise_illegal(env);
    }
}

static bool ia64_system_probe_translate(CPUIA64State *env,
                                        uint64_t address,
                                        MMUAccessType access,
                                        int effective_cpl,
                                        bool regular_form,
                                        bool *vhpt_fault,
                                        IA64TranslateResult *result)
{
    *vhpt_fault = false;
    if (ia64_translate_probe_address(env, address, access, effective_cpl,
                                     regular_form, result)) {
        return true;
    }
    if (result->status == IA64_TRANSLATE_TLB_MISS &&
        (env->psr & IA64_PSR_DT_BIT) && result->vhpt_enabled) {
        IA64VHPTWalkStatus walk = ia64_try_vhpt_walk(
            env, env_cpu(env)->as, address, access);

        if (walk == IA64_VHPT_WALK_INSTALLED) {
            return ia64_translate_probe_address(
                env, address, access, effective_cpl, regular_form, result);
        }
        *vhpt_fault = walk == IA64_VHPT_WALK_FAULT;
    }
    return false;
}

static uint64_t ia64_system_probe(CPUIA64State *env, IA64Opcode opcode,
                                  uint32_t flags, uint64_t address,
                                  uint64_t level)
{
    IA64TranslateResult result;
    bool fault_form = (flags & IA64_SYSTEM_PLANE_PROBE_FAULT) != 0;
    bool read = opcode != IA64_OP_PROBE_W;
    bool write = opcode != IA64_OP_PROBE_R;
    bool vhpt_fault;
    int current_cpl = ia64_system_cpl(env);
    int effective_cpl = MAX(current_cpl, (int)(level & 3));

    if (read && !ia64_system_probe_translate(
                    env, address, MMU_DATA_LOAD, effective_cpl,
                    !fault_form, &vhpt_fault, &result)) {
        if (vhpt_fault) {
            ia64_system_raise_non_access_translation(
                env, IA64_EXCEPTION_VHPT_TRANSLATION, address,
                "probe VHPT data fault", read, write,
                fault_form ? 5 : 2);
        }
        if (!fault_form &&
            (result.status == IA64_TRANSLATE_ACCESS_DENIED ||
             result.status == IA64_TRANSLATE_KEY_PERMISSION ||
             result.status == IA64_TRANSLATE_ACCESS_BIT ||
             result.status == IA64_TRANSLATE_DIRTY_BIT ||
             result.status == IA64_TRANSLATE_BAD_ADDRESS ||
             result.status == IA64_TRANSLATE_UNIMPLEMENTED)) {
            return 0;
        }
        ia64_system_raise_probe_translation(
            env, &result, read, write, fault_form ? 5 : 2);
    }
    if (write && !ia64_system_probe_translate(
                     env, address, MMU_DATA_STORE, effective_cpl,
                     !fault_form, &vhpt_fault, &result)) {
        if (vhpt_fault) {
            ia64_system_raise_non_access_translation(
                env, IA64_EXCEPTION_VHPT_TRANSLATION, address,
                "probe VHPT data fault", read, write,
                fault_form ? 5 : 2);
        }
        if (!fault_form &&
            (result.status == IA64_TRANSLATE_ACCESS_DENIED ||
             result.status == IA64_TRANSLATE_KEY_PERMISSION ||
             result.status == IA64_TRANSLATE_ACCESS_BIT ||
             result.status == IA64_TRANSLATE_DIRTY_BIT ||
             result.status == IA64_TRANSLATE_BAD_ADDRESS ||
             result.status == IA64_TRANSLATE_UNIMPLEMENTED)) {
            return 0;
        }
        ia64_system_raise_probe_translation(
            env, &result, read, write, fault_form ? 5 : 2);
    }
    if (fault_form && ia64_data_debug_match_at_cpl(
            env, address, 1,
            (read ? IA64_DEBUG_ACCESS_READ : 0) |
            (write ? IA64_DEBUG_ACCESS_WRITE : 0), effective_cpl)) {
        ia64_system_raise_probe_debug(env, address, read, write);
    }
    return 1;
}

static uint64_t ia64_system_virtual(CPUIA64State *env,
                                    IA64Opcode opcode, uint64_t address)
{
    switch (opcode) {
    case IA64_OP_TPA:
    {
        IA64TranslateResult result;

        if (!ia64_translate_data_non_access_checked(env, address, true,
                                                    &result)) {
            if (result.status == IA64_TRANSLATE_TLB_MISS &&
                (env->psr & IA64_PSR_DT_BIT) && result.vhpt_enabled) {
                IA64VHPTWalkStatus walk = ia64_try_vhpt_walk(
                    env, env_cpu(env)->as, address, MMU_DATA_LOAD);

                if (walk == IA64_VHPT_WALK_INSTALLED &&
                    ia64_translate_data_non_access_checked(
                        env, address, true, &result)) {
                    return result.paddr;
                }
                if (walk == IA64_VHPT_WALK_FAULT) {
                    ia64_system_raise_non_access_translation(
                        env, IA64_EXCEPTION_VHPT_TRANSLATION, address,
                        "tpa VHPT data fault", false, false, 0);
                }
            }
            ia64_system_raise_non_access_translation(
                env, ia64_exception_for_translate_result(&result),
                address, result.message, false, false, 0);
        }
        return result.paddr;
    }
    case IA64_OP_TAK:
    {
        uint64_t key = ia64_translation_access_key(env, address);

        if (key == 1 && (env->psr & IA64_PSR_DT_BIT)) {
            IA64VHPTWalkStatus walk = ia64_try_vhpt_walk(
                env, env_cpu(env)->as, address, MMU_DATA_LOAD);

            if (walk == IA64_VHPT_WALK_INSTALLED) {
                key = ia64_translation_access_key(env, address);
            }
        }
        return key;
    }
    case IA64_OP_THASH:
        return ia64_vhpt_hash_address(env, address);
    case IA64_OP_TTAG:
        return ia64_vhpt_tag(env, address);
    default:
        ia64_system_raise_illegal(env);
    }
}

static void ia64_system_insert_translation(CPUIA64State *env,
                                           IA64Opcode opcode,
                                           uint64_t translation,
                                           uint64_t slot_value)
{
    bool instruction = opcode == IA64_OP_ITR_I || opcode == IA64_OP_ITC_I;
    bool pinned = opcode == IA64_OP_ITR_D || opcode == IA64_OP_ITR_I;
    uint8_t slot = 0;
    uint8_t ps = (env->cr[IA64_CR_ITIR] >> 2) & 0x3f;

    if (pinned) {
        slot_value &= UINT64_C(0xff);
        ia64_system_validate_index(env, slot_value, IA64_ITR_COUNT);
        slot = slot_value;
    }
    if (!ia64_translation_insert_fields_valid(
            translation, env->cr[IA64_CR_ITIR])) {
        ia64_system_raise_general(env, 0x30);
    }
    if (!ia64_virtual_address_implemented(env->cr[IA64_CR_IFA])) {
        ia64_system_raise_unimplemented_non_access(
            env, env->cr[IA64_CR_IFA]);
    }
    if (!ia64_translation_insert_has_permission(translation)) {
        return;
    }
    if (!ia64_install_translation(env, instruction, pinned, slot,
                                  env->cr[IA64_CR_IFA], translation,
                                  env->cr[IA64_CR_ITIR])) {
        ia64_system_raise_general(env, 0x30);
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
    ia64_system_flush_page(env, env->cr[IA64_CR_IFA], ps);
}

static void ia64_system_purge_translation(CPUIA64State *env,
                                          IA64Opcode opcode,
                                          uint64_t address,
                                          uint64_t size_value)
{
    uint8_t ps;

    if (opcode == IA64_OP_PTC_E) {
        ia64_purge_all_translation_cache(env);
        tlb_flush(env_cpu(env));
        return;
    }
    ps = (size_value >> 2) & 0x3f;
    if (!ia64_page_size_supported(ps)) {
        ia64_system_raise_general(env, 0x30);
    }
    switch (opcode) {
    case IA64_OP_PTR_D:
        ia64_purge_translation_register(env, false, address, ps);
        break;
    case IA64_OP_PTR_I:
        ia64_purge_translation_register(env, true, address, ps);
        break;
    case IA64_OP_PTC_L:
        ia64_purge_translation_cache(env, address, ps, false);
        break;
    case IA64_OP_PTC_G:
    case IA64_OP_PTC_GA:
        ia64_purge_translation_cache(env, address, ps, true);
        break;
    default:
        ia64_system_raise_illegal(env);
    }
    ia64_system_flush_page(env, address, ps);
}

static void ia64_system_break(CPUIA64State *env, uint64_t iim)
{
    uint64_t next_ip = env->ip + IA64_BUNDLE_SIZE;

    if (ia64_try_platform_break(env, iim)) {
        return;
    }
    ia64_deliver_break_interruption(env, iim, &next_ip, "typed break");
    ia64_system_exit(env);
}

static void ia64_system_br_ia(CPUIA64State *env, uint64_t target)
{
    uint64_t psr = ia64_env_psr(env);

    /* Dirty backing-store state is an Illegal Operation before PSR.di. */
    if (env->rse.dirty != 0 || env->rse.dirty_nat != 0) {
        ia64_system_raise_illegal(env);
    }
    if (psr & IA64_PSR_DI_BIT) {
        ia64_system_raise_general(env, 0x40);
    }

    /*
     * IC/DT/IT/MC are software preconditions whose violation is undefined,
     * not an architected br.ia fault.  The reference helper therefore does
     * not invent a competing exception after the dirty/DI priority checks.
     */

    psr |= IA64_PSR_IS_BIT;
    psr &= ~(IA64_PSR_DA_BIT | IA64_PSR_IA_BIT | IA64_PSR_DD_BIT |
             IA64_PSR_ED_BIT | IA64_PSR_RI_MASK);
    ia64_env_write_psr_guest(env, psr);
    ia64_set_cfm(env, 0);
    env->rse.sof = 0;
    env->rse.sol = 0;
    env->rse.sor = 0;
    env->rse.rrb_gr = 0;
    env->rse.rrb_fr = 0;
    env->rse.rrb_pr = 0;
    env->rse.clean = 0;
    env->rse.clean_nat = 0;
    env->rse.invalid = IA64_RSE_PHYS_STACKED_REGS;
    env->ip = (uint32_t)target;
    ia64_alat_invalidate_all(env);
    cpu_abort(env_cpu(env),
              "IA-64 br.ia entered IA-32 mode at 0x%08x; "
              "IA-32 execution is not implemented\n", (uint32_t)target);
}

uint32_t HELPER(instruction_debug_match)(CPUIA64State *env,
                                         uint64_t address)
{
    return ia64_instruction_debug_match(env, address);
}

G_NORETURN void HELPER(raise_instruction_debug)(CPUIA64State *env)
{
    ia64_deliver_exception_fast(env, IA64_EXCEPTION_INSTRUCTION_DEBUG,
                                env->ip, MMU_INST_FETCH,
                                "instruction breakpoint match");
    ia64_system_exit(env);
}

void HELPER(system_preflight)(CPUIA64State *env, uint32_t opcode_value,
                              uint32_t selector)
{
    IA64Opcode opcode = opcode_value;

    if ((unsigned)opcode >= IA64_OP_COUNT) {
        ia64_system_raise_illegal(env);
    }
    /* VMSW is an absent optional feature; feature failure precedes CPL. */
    if (opcode == IA64_OP_VMSW) {
        ia64_system_raise_illegal(env);
    }
    /* PSR.ic legality precedes CPL, operand NaT and insert-field checks. */
    if (ia64_system_translation_insert_requires_ic_clear(opcode) &&
        (env->psr & IA64_PSR_IC_BIT) != 0) {
        ia64_system_raise_illegal(env);
    }
    if (opcode == IA64_OP_MOV_CRGR || opcode == IA64_OP_MOV_GRCR) {
        ia64_system_validate_cr_legality(
            env, selector, opcode == IA64_OP_MOV_GRCR);
    }
    if (opcode == IA64_OP_MOV_IMMAR) {
        /* Reserved value and privilege follow the immediate in the writer. */
        ia64_system_validate_ar_legality(env, selector, true);
    }
    ia64_system_validate_privilege(env, opcode, selector);
}

void HELPER(application_register_preflight)(CPUIA64State *env,
                                             uint32_t selector,
                                             uint32_t write)
{
    ia64_system_validate_ar_preflight(env, selector, write != 0);
}

void HELPER(application_register_write_legality)(CPUIA64State *env,
                                                  uint32_t selector)
{
    ia64_system_validate_ar_legality(env, selector, true);
}

enum {
    IA64_APPLICATION_REGISTER_OK,
    IA64_APPLICATION_REGISTER_ILLEGAL,
    IA64_APPLICATION_REGISTER_PRIVILEGED,
};

uint32_t HELPER(application_register_legality_status)(CPUIA64State *env,
                                                       uint32_t selector,
                                                       uint32_t write)
{
    if (selector >= IA64_AR_COUNT || (write && selector == IA64_AR_BSP) ||
        ((selector == IA64_AR_BSPSTORE || selector == IA64_AR_RNAT) &&
         (env->rse.rsc & IA64_RSC_MODE_MASK) != 0)) {
        return IA64_APPLICATION_REGISTER_ILLEGAL;
    }
    return IA64_APPLICATION_REGISTER_OK;
}

uint32_t HELPER(application_register_privilege_status)(CPUIA64State *env,
                                                        uint32_t selector,
                                                        uint32_t write)
{
    unsigned cpl = ia64_system_cpl(env);

    if ((write && (selector <= 7 || selector == IA64_AR_ITC ||
                   selector == IA64_AR_RUC) && cpl != 0) ||
        (!write && (selector == IA64_AR_ITC || selector == IA64_AR_RUC) &&
         (env->psr & IA64_PSR_SI_BIT) != 0 && cpl != 0)) {
        return IA64_APPLICATION_REGISTER_PRIVILEGED;
    }
    return IA64_APPLICATION_REGISTER_OK;
}

G_NORETURN void HELPER(raise_application_register_fault)(CPUIA64State *env,
                                                          uint32_t status)
{
    if (status == IA64_APPLICATION_REGISTER_ILLEGAL) {
        ia64_system_raise_illegal(env);
    }
    ia64_system_raise_general(env, 0x20);
}

uint64_t HELPER(application_register_read)(CPUIA64State *env,
                                           uint32_t selector)
{
    uint64_t value = ia64_read_application_register(env, selector);

    return ia64_issue_group_select_ar_source(env, selector, value);
}

uint32_t HELPER(application_register_write_value_valid)(uint32_t selector,
                                                         uint64_t value)
{
    return ia64_system_ar_write_value_valid(selector, value);
}

static void ia64_system_preserve_ar_write_sources(CPUIA64State *env,
                                                   uint32_t selector)
{
    ia64_issue_group_preserve_ar_source(
        env, selector, ia64_read_application_register(env, selector));

    if (selector == IA64_AR_BSPSTORE) {
        /*
         * A BSPSTORE write also rebases BSP and makes RNAT undefined.  Keep
         * every architectural AR side effect in the same typed visibility
         * epoch, including a fault/restart or snapshot taken before its stop.
         */
        ia64_issue_group_preserve_ar_source(
            env, IA64_AR_BSP,
            ia64_read_application_register(env, IA64_AR_BSP));
        ia64_issue_group_preserve_ar_source(
            env, IA64_AR_RNAT,
            ia64_read_application_register(env, IA64_AR_RNAT));
    }
}

void HELPER(application_register_write)(CPUIA64State *env,
                                         uint32_t selector,
                                         uint64_t value)
{
    ia64_system_validate_ar_write_value(env, selector, value);
    ia64_system_validate_ar_privilege(env, selector, true);
    ia64_system_preserve_ar_write_sources(env, selector);
    ia64_write_application_register(env, selector, value);
}

void HELPER(application_register_write_committed)(CPUIA64State *env,
                                                   uint32_t selector,
                                                   uint64_t value)
{
    /* Translator callers have already handled legality, privilege and value
     * faults in explicit cold arms.  This returning helper cannot fault. */
    ia64_system_preserve_ar_write_sources(env, selector);
    ia64_write_application_register(env, selector, value);
}

uint64_t HELPER(system_plane)(CPUIA64State *env, uint32_t opcode_value,
                              uint32_t selector, uint32_t flags,
                              uint64_t arg0, uint64_t arg1)
{
    IA64Opcode opcode = opcode_value;
    uint64_t psr;

    switch (opcode) {
    case IA64_OP_BREAK:
        ia64_system_break(env, arg0);
        return 0;
    case IA64_OP_BR_IA:
        ia64_system_br_ia(env, arg0);
        return 0;
    case IA64_OP_MOV_IMMAR:
        HELPER(application_register_write)(env, selector, arg0);
        return 0;
    case IA64_OP_MOV_CRGR:
        ia64_system_validate_cr_access(env, selector, false, 0);
        return ia64_read_control_register(env, selector);
    case IA64_OP_MOV_GRCR:
        arg0 = ia64_system_validate_cr_access(env, selector, true, arg0);
        ia64_write_control_register(env, selector, arg0);
        return 0;
    case IA64_OP_SSM:
        ia64_env_write_psr_guest(env, ia64_env_psr(env) | arg0);
        return 0;
    case IA64_OP_RSM:
        ia64_env_write_psr_guest(env, ia64_env_psr(env) & ~arg0);
        return 0;
    case IA64_OP_RUM:
        psr = ia64_env_psr(env);
        ia64_env_write_psr_guest(env,
            ia64_psr_write_user_mask_value(psr, psr & ~arg0));
        return 0;
    case IA64_OP_SUM_UM:
        psr = ia64_env_psr(env);
        ia64_env_write_psr_guest(env,
            ia64_psr_write_user_mask_value(psr, psr | arg0));
        return 0;
    case IA64_OP_ITR_D:
    case IA64_OP_ITR_I:
    case IA64_OP_ITC_D:
    case IA64_OP_ITC_I:
        ia64_system_insert_translation(env, opcode, arg0, arg1);
        return 0;
    case IA64_OP_PTR_D:
    case IA64_OP_PTR_I:
    case IA64_OP_PTC_L:
    case IA64_OP_PTC_G:
    case IA64_OP_PTC_GA:
    case IA64_OP_PTC_E:
        ia64_system_purge_translation(env, opcode, arg0, arg1);
        return 0;
    case IA64_OP_TPA:
    case IA64_OP_TAK:
    case IA64_OP_THASH:
    case IA64_OP_TTAG:
        return ia64_system_virtual(env, opcode, arg0);
    case IA64_OP_PROBE_R:
    case IA64_OP_PROBE_W:
    case IA64_OP_PROBE_RW:
        return ia64_system_probe(env, opcode, flags, arg0, arg1);
    case IA64_OP_SYNC_I:
        return 0;
    case IA64_OP_SRLZ:
    case IA64_OP_SRLZ_D:
        ia64_env_serialize_psr_ic(env);
        return 0;
    case IA64_OP_MF:
    case IA64_OP_MF_A:
    case IA64_OP_BRP:
        return 0;
    case IA64_OP_MOV_PSRGR:
        /*
         * Keep the reference platform's firmware-visible PSR image.  RI is
         * an internal restart selector once execution resumes, so expose its
         * chosen architecturally-undefined value of zero while retaining BN
         * and the other live status bits needed by the SAL loader handoff.
         */
        return ia64_env_psr(env) & ~IA64_PSR_RI_MASK;
    case IA64_OP_MOV_GRPSR:
        /*
         * M35 is ``mov psr.l = r2``: only GR bits 31:0 participate in the
         * operation.  The upper half commonly contains a complete PSR image
         * saved by an interruption handler (Linux does exactly this while
         * installing its boot-time identity ITRs), and must be ignored rather
         * than diagnosed as a reserved-field fault.
         */
        arg0 &= UINT64_C(0xffffffff);
        if (arg0 & ~IA64_PSR_LOWER_WRITABLE_MASK) {
            ia64_system_raise_general(env, 0x30);
        }
        psr = ia64_env_psr(env);
        ia64_env_write_psr_guest(
            env, (psr & ~UINT64_C(0xffffffff)) | arg0);
        return 0;
    case IA64_OP_MOV_RRGR:
        return env->rr[(arg0 >> 61) & 7] & IA64_RR_IMPLEMENTED_MASK;
    case IA64_OP_MOV_GRRR:
    {
        uint8_t ps = (arg0 >> 2) & 0x3f;
        unsigned region = (arg1 >> 61) & 7;

        if ((arg0 & ~IA64_RR_IMPLEMENTED_MASK) ||
            !ia64_page_size_supported(ps)) {
            ia64_system_raise_general(env, 0x30);
        }
        env->rr[region] = arg0 & IA64_RR_IMPLEMENTED_MASK;
        tlb_flush(env_cpu(env));
        return 0;
    }
    case IA64_OP_BSW0:
        ia64_env_write_psr_guest(env, ia64_env_psr(env) & ~IA64_PSR_BN_BIT);
        return 0;
    case IA64_OP_BSW1:
        ia64_env_write_psr_guest(env, ia64_env_psr(env) | IA64_PSR_BN_BIT);
        return 0;
    case IA64_OP_EPC:
    {
        unsigned current_cpl = ia64_system_cpl(env);
        unsigned pfs_ppl = (arg0 >> 62) & 3;
        unsigned target_cpl = current_cpl;
        uint8_t gate_pl;

        if (pfs_ppl < current_cpl) {
            ia64_system_raise_illegal(env);
        }
        if ((ia64_env_psr(env) & IA64_PSR_IT_BIT) == 0) {
            target_cpl = 0;
        } else if (ia64_instruction_epc_gate(env, env->ip, &gate_pl) &&
                   gate_pl < current_cpl) {
            target_cpl = gate_pl;
        }
        if (target_cpl != current_cpl) {
            ia64_env_write_psr_guest(
                env, (ia64_env_psr(env) & ~IA64_PSR_CPL_MASK) |
                     ((uint64_t)target_cpl << IA64_PSR_CPL_SHIFT));
            tlb_flush(env_cpu(env));
        }
        return 0;
    }
    case IA64_OP_MOV_PKRGR_INDEXED:
    case IA64_OP_MOV_IBRGR_INDEXED:
    case IA64_OP_MOV_DBRGR_INDEXED:
    case IA64_OP_MOV_PMCGR_INDEXED:
    case IA64_OP_MOV_PMDGR_INDEXED:
    case IA64_OP_MOV_CPUID_INDEXED:
    case IA64_OP_MOV_DAHRGR_INDEXED:
    case IA64_OP_MOV_MSRGR:
        return ia64_system_indexed_read(env, opcode, arg0);
    case IA64_OP_MOV_GRPKR_INDEXED:
    case IA64_OP_MOV_GRIBR_INDEXED:
    case IA64_OP_MOV_GRDBR_INDEXED:
    case IA64_OP_MOV_GRPMC_INDEXED:
    case IA64_OP_MOV_GRPMD_INDEXED:
    case IA64_OP_MOV_GRMSR:
        ia64_system_indexed_write(env, opcode, arg0, arg1);
        return 0;
    case IA64_OP_MOV_UMGR:
        return ia64_env_psr(env) & IA64_PSR_UM_MASK;
    case IA64_OP_MOV_GRUM:
        if (!ia64_psr_user_mask_value_valid(arg0)) {
            ia64_system_raise_general(env, 0x30);
        }
        psr = ia64_env_psr(env);
        ia64_env_write_psr_guest(
            env, ia64_psr_write_user_mask_value(psr, arg0));
        return 0;
    case IA64_OP_MOV_CURRENT_IP:
        return arg0;
    default:
        ia64_system_raise_illegal(env);
    }
}

G_NORETURN void HELPER(raise_reserved_register_field)(CPUIA64State *env)
{
    ia64_system_raise_general(env, 0x30);
}
