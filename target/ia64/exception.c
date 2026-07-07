/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "exception.h"
#include "insn.h"
#include "mem.h"
#include "perf.h"
#include "trace-target_ia64.h"

#define IA64_DCR_PP_BIT  UINT64_C(0x0000000000000001)
#define IA64_DCR_BE_BIT  UINT64_C(0x0000000000000002)
#define IA64_PSR_BE_BIT  UINT64_C(0x0000000000000002)
#define IA64_PSR_UP_BIT  UINT64_C(0x0000000000000004)
#define IA64_PSR_MFL_BIT UINT64_C(0x0000000000000010)
#define IA64_PSR_MFH_BIT UINT64_C(0x0000000000000020)
#define IA64_PSR_IC_BIT  UINT64_C(0x0000000000002000)
#define IA64_PSR_I_BIT   UINT64_C(0x0000000000004000)
#define IA64_PSR_PK_BIT  UINT64_C(0x0000000000008000)
#define IA64_PSR_DT_BIT  UINT64_C(0x0000000000020000)
#define IA64_PSR_PP_BIT  UINT64_C(0x0000000000200000)
#define IA64_PSR_RT_BIT  UINT64_C(0x0000000008000000)
#define IA64_PSR_CPL_MASK UINT64_C(0x0000000300000000)
#define IA64_PSR_MC_BIT  UINT64_C(0x0000000800000000)
#define IA64_PSR_IT_BIT  UINT64_C(0x0000001000000000)
#define IA64_PSR_BN_BIT  UINT64_C(0x0000100000000000)

#define IA64_PSR_INTERRUPTION_PRESERVED_MASK \
    (IA64_PSR_UP_BIT | IA64_PSR_MFL_BIT | IA64_PSR_MFH_BIT | \
     IA64_PSR_PK_BIT | IA64_PSR_DT_BIT | IA64_PSR_RT_BIT | \
     IA64_PSR_MC_BIT | IA64_PSR_IT_BIT)

static bool ia64_exception_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_EXCEPTION_TRACE") != NULL;
    }
    return enabled != 0;
}

static bool ia64_user_exception_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_USER_EXCEPTION_TRACE") != NULL;
    }
    return enabled != 0;
}

static bool ia64_exception_from_user(uint64_t psr)
{
    return (psr & IA64_PSR_CPL_MASK) == IA64_PSR_CPL_MASK;
}

static uint64_t ia64_psr_for_interruption_delivery(CPUIA64State *env)
{
    uint64_t psr = ia64_env_psr(env) & IA64_PSR_INTERRUPTION_PRESERVED_MASK;

    /*
     * IVA-based interruption delivery preserves only a small set of PSR bits.
     * DCR.be and DCR.pp supply the replacement values for PSR.be and PSR.pp.
     */
    if (env->cr[IA64_CR_DCR] & IA64_DCR_BE_BIT) {
        psr |= IA64_PSR_BE_BIT;
    }
    if (env->cr[IA64_CR_DCR] & IA64_DCR_PP_BIT) {
        psr |= IA64_PSR_PP_BIT;
    }
    return psr;
}

static uint64_t ia64_interruption_isr(uint64_t psr,
                                      MMUAccessType access_type)
{
    uint64_t isr = ((uint64_t)ia64_psr_ri(psr) << IA64_ISR_EI_SHIFT) &
                   IA64_ISR_EI_MASK;

    switch (access_type) {
    case MMU_INST_FETCH:
        isr |= UINT64_C(1) << IA64_ISR_X_BIT;
        break;
    case MMU_DATA_STORE:
        isr |= UINT64_C(1) << IA64_ISR_W_BIT;
        break;
    case MMU_DATA_LOAD:
    default:
        isr |= UINT64_C(1) << IA64_ISR_R_BIT;
        break;
    }
    if ((psr & IA64_PSR_IC_BIT) == 0) {
        isr |= UINT64_C(1) << IA64_ISR_NI_BIT;
    }

    return isr;
}

const char *ia64_exception_name(IA64ExceptionKind kind)
{
    switch (kind) {
    case IA64_EXCEPTION_NONE:
        return "none";
    case IA64_EXCEPTION_VHPT_TRANSLATION:
        return "vhpt-translation";
    case IA64_EXCEPTION_INSTRUCTION_TLB_MISS:
        return "instruction-tlb-miss";
    case IA64_EXCEPTION_DATA_TLB_MISS:
        return "data-tlb-miss";
    case IA64_EXCEPTION_ALTERNATE_INSTRUCTION_TLB_MISS:
        return "alternate-instruction-tlb-miss";
    case IA64_EXCEPTION_ALTERNATE_DATA_TLB_MISS:
        return "alternate-data-tlb-miss";
    case IA64_EXCEPTION_DATA_NESTED_TLB:
        return "data-nested-tlb";
    case IA64_EXCEPTION_DIRTY_BIT:
        return "dirty-bit";
    case IA64_EXCEPTION_INSTRUCTION_ACCESS_BIT:
        return "instruction-access-bit";
    case IA64_EXCEPTION_DATA_ACCESS_BIT:
        return "data-access-bit";
    case IA64_EXCEPTION_INSTRUCTION_ACCESS_RIGHTS:
        return "instruction-access-rights";
    case IA64_EXCEPTION_DATA_ACCESS_RIGHTS:
        return "data-access-rights";
    case IA64_EXCEPTION_ILLEGAL_OPERATION:
        return "illegal-operation";
    case IA64_EXCEPTION_PAGE_FAULT:
        return "page-fault";
    case IA64_EXCEPTION_GENERAL_EXCEPTION:
        return "general-exception";
    case IA64_EXCEPTION_BREAK:
        return "break";
    case IA64_EXCEPTION_EXTERNAL_INTERRUPT:
        return "external-interrupt";
    case IA64_EXCEPTION_DISABLED_FP_LOW:
        return "disabled-fp-register-low";
    case IA64_EXCEPTION_DISABLED_FP_HIGH:
        return "disabled-fp-register-high";
    default:
        return "unknown";
    }
}

IA64ExceptionKind
ia64_exception_for_translate_result(const IA64TranslateResult *result)
{
    if (!result) {
        return IA64_EXCEPTION_PAGE_FAULT;
    }

    switch (result->status) {
    case IA64_TRANSLATE_TLB_MISS:
        if (result->access_type == MMU_INST_FETCH) {
            return result->vhpt_enabled ?
                   IA64_EXCEPTION_INSTRUCTION_TLB_MISS :
                   IA64_EXCEPTION_ALTERNATE_INSTRUCTION_TLB_MISS;
        }
        return result->vhpt_enabled ? IA64_EXCEPTION_DATA_TLB_MISS :
                                      IA64_EXCEPTION_ALTERNATE_DATA_TLB_MISS;
    case IA64_TRANSLATE_DIRTY_BIT:
        return IA64_EXCEPTION_DIRTY_BIT;
    case IA64_TRANSLATE_ACCESS_BIT:
        return result->access_type == MMU_INST_FETCH ?
               IA64_EXCEPTION_INSTRUCTION_ACCESS_BIT :
               IA64_EXCEPTION_DATA_ACCESS_BIT;
    case IA64_TRANSLATE_ACCESS_DENIED:
        return result->access_type == MMU_INST_FETCH ?
               IA64_EXCEPTION_INSTRUCTION_ACCESS_RIGHTS :
               IA64_EXCEPTION_DATA_ACCESS_RIGHTS;
    default:
        return IA64_EXCEPTION_PAGE_FAULT;
    }
}

void ia64_clear_exception(CPUIA64State *env)
{
    memset(&env->exception, 0, sizeof(env->exception));
}

static void ia64_record_exception_common(CPUIA64State *env,
                                         IA64ExceptionKind kind,
                                         vaddr address,
                                         MMUAccessType access_type,
                                         const char *detail,
                                         bool format_detail)
{
    IA64ExceptionRecord *record = &env->exception;

    ia64_env_sync_psr_ri(env);
    memset(record, 0, sizeof(*record));
    record->kind = kind;
    record->ip = env->ip;
    record->address = address;
    record->access_type = access_type;
    record->pending = kind != IA64_EXCEPTION_NONE;

    switch (kind) {
    case IA64_EXCEPTION_VHPT_TRANSLATION:
        record->vector = 0x0000;
        break;
    case IA64_EXCEPTION_INSTRUCTION_TLB_MISS:
        record->vector = 0x0400;
        break;
    case IA64_EXCEPTION_DATA_TLB_MISS:
        record->vector = 0x0800;
        break;
    case IA64_EXCEPTION_ALTERNATE_INSTRUCTION_TLB_MISS:
        record->vector = 0x0c00;
        break;
    case IA64_EXCEPTION_ALTERNATE_DATA_TLB_MISS:
        record->vector = 0x1000;
        break;
    case IA64_EXCEPTION_DATA_NESTED_TLB:
        record->vector = 0x1400;
        break;
    case IA64_EXCEPTION_DIRTY_BIT:
        record->vector = 0x2000;
        break;
    case IA64_EXCEPTION_INSTRUCTION_ACCESS_BIT:
        record->vector = 0x2400;
        break;
    case IA64_EXCEPTION_DATA_ACCESS_BIT:
        record->vector = 0x2800;
        break;
    case IA64_EXCEPTION_INSTRUCTION_ACCESS_RIGHTS:
        record->vector = 0x5200;
        break;
    case IA64_EXCEPTION_DATA_ACCESS_RIGHTS:
        record->vector = 0x5300;
        break;
    case IA64_EXCEPTION_ILLEGAL_OPERATION:
        record->vector = 0x5400;
        break;
    case IA64_EXCEPTION_PAGE_FAULT:
        record->vector = 0x5000;
        break;
    case IA64_EXCEPTION_GENERAL_EXCEPTION:
        record->vector = 0x5400;
        break;
    case IA64_EXCEPTION_BREAK:
        record->vector = 0x2c00;
        break;
    case IA64_EXCEPTION_EXTERNAL_INTERRUPT:
        record->vector = 0x3000;
        break;
    case IA64_EXCEPTION_DISABLED_FP_LOW:
        record->vector = 0x5500;
        record->isr_code = 1;
        break;
    case IA64_EXCEPTION_DISABLED_FP_HIGH:
        record->vector = 0x5500;
        record->isr_code = 2;
        break;
    case IA64_EXCEPTION_NONE:
    default:
        record->vector = 0;
        break;
    }

    if (format_detail) {
        IA64_PERF_INC(IA64_PERF_EXCEPTION_RECORD_FORMATTED);
        snprintf((char *)record->message, sizeof(record->message),
                 "%s at ip=0x%016" VADDR_PRIx " address=0x%016" VADDR_PRIx
                 " access=%d%s%s",
                 ia64_exception_name(kind), record->ip, record->address,
                 access_type, detail ? " " : "", detail ? detail : "");
    } else {
        IA64_PERF_INC(IA64_PERF_EXCEPTION_RECORD_FAST);
        record->message[0] = '\0';
    }

    env->cr[IA64_CR_IIP] = env->ip;
    env->cr[IA64_CR_IFA] = address;
    env->cr[IA64_CR_IIPA] = address;
    env->cr[IA64_CR_ISR] = ia64_interruption_isr(ia64_env_psr(env),
                                                 access_type) |
                           env->exception.isr_code;
}

void ia64_record_exception(CPUIA64State *env, IA64ExceptionKind kind,
                           vaddr address, MMUAccessType access_type,
                           const char *detail)
{
    ia64_record_exception_common(env, kind, address, access_type, detail,
                                 true);
}

static void ia64_deliver_exception_common(CPUIA64State *env,
                                          IA64ExceptionKind kind,
                                          vaddr address,
                                          MMUAccessType access_type,
                                          const char *detail,
                                          bool format_detail)
{
    uint64_t source_ip;
    uint64_t old_psr;
    uint64_t saved_ipsr;
    uint64_t saved_iip;
    uint64_t saved_iipa;
    uint64_t saved_ifs;
    uint64_t saved_isr;
    uint64_t saved_ifa;
    uint64_t saved_itir;
    uint64_t saved_iha;
    uint64_t vhpt_iha;
    uint64_t rr;
    bool collection_disabled;
    bool data_nested_tlb;
    bool trace_enabled;
    bool user_trace_enabled;

    ia64_env_sync_psr_ri(env);

    source_ip = env->ip;
    old_psr = ia64_env_psr(env);
    saved_ipsr = env->cr[IA64_CR_IPSR];
    saved_iip = env->cr[IA64_CR_IIP];
    saved_iipa = env->cr[IA64_CR_IIPA];
    saved_ifs = env->cr[IA64_CR_IFS];
    saved_isr = env->cr[IA64_CR_ISR];
    saved_ifa = env->cr[IA64_CR_IFA];
    saved_itir = env->cr[IA64_CR_ITIR];
    saved_iha = env->cr[IA64_CR_IHA];
    vhpt_iha = ia64_vhpt_hash_address(env, address);
    rr = env->rr[ia64_va_region(address)];
    /*
     * PSR.ic=0 suppresses interruption-resource collection.  Keep the
     * original collected state for resources that are only updated with
     * collection enabled; ISR is still written for non-Data-Nested
     * interruptions and records ISR.ni for the nested-delivery condition.
     */
    collection_disabled = (old_psr & IA64_PSR_IC_BIT) == 0;
    data_nested_tlb = collection_disabled &&
                      (kind == IA64_EXCEPTION_DATA_TLB_MISS ||
                       kind == IA64_EXCEPTION_ALTERNATE_DATA_TLB_MISS);
    trace_enabled = ia64_exception_trace_enabled();
    user_trace_enabled = ia64_user_exception_trace_enabled();

    if (data_nested_tlb) {
        kind = IA64_EXCEPTION_DATA_NESTED_TLB;
    }

    IA64_PERF_INC(IA64_PERF_EXCEPTION_DELIVERED);
    if (ia64_perf_enabled()) {
        ia64_perf_count_exception_kind(kind);
    }

    ia64_record_exception_common(env, kind, address, access_type, detail,
                                 format_detail || trace_enabled ||
                                 user_trace_enabled);

    if (collection_disabled) {
        env->cr[IA64_CR_IPSR] = saved_ipsr;
        env->cr[IA64_CR_IIP] = saved_iip;
        env->cr[IA64_CR_IIPA] = saved_iipa;
        env->cr[IA64_CR_IFS] = saved_ifs;
        env->cr[IA64_CR_IFA] = saved_ifa;
        env->cr[IA64_CR_ITIR] = saved_itir;
        env->cr[IA64_CR_IHA] = saved_iha;
        if (data_nested_tlb) {
            env->cr[IA64_CR_ISR] = saved_isr;
        }
        ia64_env_set_psr(env, ia64_psr_for_interruption_delivery(env));
        env->ip = (env->cr[IA64_CR_IVA] & ~0x7fffULL) +
                  env->exception.vector;
        goto trace;
    }

    env->cr[IA64_CR_IPSR] = ia64_env_psr(env);
    if (old_psr & IA64_PSR_IC_BIT) {
        env->cr[IA64_CR_IFS] = 0;
    }
    env->cr[IA64_CR_IIP] = access_type == MMU_INST_FETCH ?
                           (address & ~0xfULL) : env->ip;
    env->cr[IA64_CR_IFA] = address;
    env->cr[IA64_CR_ISR] = ia64_interruption_isr(ia64_env_psr(env),
                                                 access_type) |
                           env->exception.isr_code;
    if (kind == IA64_EXCEPTION_INSTRUCTION_TLB_MISS ||
        kind == IA64_EXCEPTION_DATA_TLB_MISS ||
        kind == IA64_EXCEPTION_VHPT_TRANSLATION ||
        kind == IA64_EXCEPTION_ALTERNATE_INSTRUCTION_TLB_MISS ||
        kind == IA64_EXCEPTION_ALTERNATE_DATA_TLB_MISS ||
        kind == IA64_EXCEPTION_DIRTY_BIT ||
        kind == IA64_EXCEPTION_INSTRUCTION_ACCESS_BIT ||
        kind == IA64_EXCEPTION_DATA_ACCESS_BIT ||
        kind == IA64_EXCEPTION_INSTRUCTION_ACCESS_RIGHTS ||
        kind == IA64_EXCEPTION_DATA_ACCESS_RIGHTS ||
        kind == IA64_EXCEPTION_PAGE_FAULT) {
        env->cr[IA64_CR_ITIR] =
            kind == IA64_EXCEPTION_VHPT_TRANSLATION ?
            ia64_default_itir(env, vhpt_iha) :
            ia64_default_itir(env, address);
    }
    if (kind == IA64_EXCEPTION_VHPT_TRANSLATION) {
        env->cr[IA64_CR_IHA] = vhpt_iha;
    } else if (kind == IA64_EXCEPTION_INSTRUCTION_TLB_MISS ||
        kind == IA64_EXCEPTION_DATA_TLB_MISS) {
        env->cr[IA64_CR_IHA] = vhpt_iha;
    }

    ia64_env_set_psr(env, ia64_psr_for_interruption_delivery(env));
    env->ip = (env->cr[IA64_CR_IVA] & ~0x7fffULL) + env->exception.vector;
    env->cr[IA64_CR_IIP] &= ~0xfULL;

trace:
    trace_ia64_exception_deliver(ia64_exception_name(kind), source_ip,
                                 address, env->exception.vector, env->ip,
                                 env->cr[IA64_CR_IPSR],
                                 env->cr[IA64_CR_IIP],
                                 env->cr[IA64_CR_IFA],
                                 env->cr[IA64_CR_ISR], env->psr);
    trace_ia64_exception_mmu(ia64_exception_name(kind), address,
                             env->cr[IA64_CR_ITIR], env->cr[IA64_CR_IHA],
                             env->cr[IA64_CR_PTA], rr);
    if (trace_enabled) {
        fprintf(stderr,
                "[ia64-exception] kind=%s ip=0x%016" PRIx64
                " address=0x%016" PRIx64 " vector=0x%04" PRIx64
                " target=0x%016" PRIx64 " ipsr=0x%016" PRIx64
                " iip=0x%016" PRIx64 " ifa=0x%016" PRIx64
                " isr=0x%016" PRIx64 " psr=0x%016" PRIx64
                " itir=0x%016" PRIx64 " iha=0x%016" PRIx64
                " pta=0x%016" PRIx64 " rr=0x%016" PRIx64 "\n",
                ia64_exception_name(kind), source_ip, address,
                env->exception.vector, env->ip, env->cr[IA64_CR_IPSR],
                env->cr[IA64_CR_IIP], env->cr[IA64_CR_IFA],
                env->cr[IA64_CR_ISR], env->psr, env->cr[IA64_CR_ITIR],
                env->cr[IA64_CR_IHA], env->cr[IA64_CR_PTA], rr);
    }
    if (user_trace_enabled && ia64_exception_from_user(old_psr) &&
        kind != IA64_EXCEPTION_BREAK &&
        kind != IA64_EXCEPTION_EXTERNAL_INTERRUPT) {
        fprintf(stderr,
                "[ia64-user-exception] kind=%s ip=0x%016" PRIx64
                " address=0x%016" PRIx64 " access=%d"
                " vector=0x%04" PRIx64 " target=0x%016" PRIx64
                " old_psr=0x%016" PRIx64 " psr=0x%016" PRIx64
                " ipsr=0x%016" PRIx64 " iip=0x%016" PRIx64
                " ifa=0x%016" PRIx64 " isr=0x%016" PRIx64
                " itir=0x%016" PRIx64 " iha=0x%016" PRIx64
                " cfm=0x%016" PRIx64 " pr=0x%016" PRIx64
                " r8=0x%016" PRIx64 " r10=0x%016" PRIx64
                " r15=0x%016" PRIx64 " r32=0x%016" PRIx64
                " r33=0x%016" PRIx64 " r34=0x%016" PRIx64
                " r35=0x%016" PRIx64 " b0=0x%016" PRIx64
                " b6=0x%016" PRIx64 " b7=0x%016" PRIx64
                " bsp=0x%016" PRIx64 " bspstore=0x%016" PRIx64
                " rsc=0x%016" PRIx64 "\n",
                ia64_exception_name(kind), source_ip, address, access_type,
                env->exception.vector, env->ip, old_psr, env->psr,
                env->cr[IA64_CR_IPSR], env->cr[IA64_CR_IIP],
                env->cr[IA64_CR_IFA], env->cr[IA64_CR_ISR],
                env->cr[IA64_CR_ITIR], env->cr[IA64_CR_IHA],
                env->cfm, env->pr, ia64_read_gr(env, 8),
                ia64_read_gr(env, 10), ia64_read_gr(env, 15),
                ia64_read_gr(env, 32), ia64_read_gr(env, 33),
                ia64_read_gr(env, 34), ia64_read_gr(env, 35),
                env->br[0], env->br[6], env->br[7], env->ar[IA64_AR_BSP],
                env->ar[IA64_AR_BSPSTORE], env->ar[IA64_AR_RSC]);
    }
}

void ia64_deliver_exception(CPUIA64State *env, IA64ExceptionKind kind,
                            vaddr address, MMUAccessType access_type,
                            const char *detail)
{
    ia64_deliver_exception_common(env, kind, address, access_type, detail,
                                  true);
}

void ia64_deliver_exception_fast(CPUIA64State *env, IA64ExceptionKind kind,
                                 vaddr address, MMUAccessType access_type,
                                 const char *detail)
{
    ia64_deliver_exception_common(env, kind, address, access_type, detail,
                                  false);
}

void ia64_format_exception(const IA64ExceptionRecord *record,
                           char *buf, size_t buflen)
{
    snprintf(buf, buflen,
             "kind=%s vector=0x%02" PRIx64 " ip=0x%016" VADDR_PRIx
             " address=0x%016" VADDR_PRIx " access=%d pending=%s"
             " message=\"%s\"",
             ia64_exception_name(record->kind), record->vector,
             record->ip, record->address, record->access_type,
             record->pending ? "yes" : "no",
             (const char *)record->message);
}
