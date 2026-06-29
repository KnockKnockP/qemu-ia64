/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "exception.h"
#include "exec-smoke.h"
#include "mem.h"
#include "perf.h"
#include "trace-target_ia64.h"

#define IA64_PSR_IC_BIT UINT64_C(0x0000000000002000)
#define IA64_PSR_I_BIT  UINT64_C(0x0000000000004000)
#define IA64_PSR_CPL_MASK UINT64_C(0x0000000300000000)
#define IA64_PSR_BN_BIT   UINT64_C(0x0000100000000000)

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

static uint64_t ia64_psr_clear_interruption_delivery_bits(uint64_t psr)
{
    return psr & ~(IA64_PSR_I_BIT | IA64_PSR_IC_BIT |
                   IA64_PSR_BN_BIT | IA64_PSR_RI_MASK |
                   IA64_PSR_CPL_MASK);
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

    return isr;
}

const char *ia64_exception_name(IA64ExceptionKind kind)
{
    switch (kind) {
    case IA64_EXCEPTION_NONE:
        return "none";
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
    default:
        return "unknown";
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

    memset(record, 0, sizeof(*record));
    record->kind = kind;
    record->ip = env->ip;
    record->address = address;
    record->access_type = access_type;
    record->pending = kind != IA64_EXCEPTION_NONE;

    switch (kind) {
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
    env->cr[IA64_CR_ISR] = ia64_interruption_isr(env->psr, access_type);
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
    uint64_t source_ip = env->ip;
    uint64_t old_psr = env->psr;
    uint64_t saved_ipsr = env->cr[IA64_CR_IPSR];
    uint64_t saved_iip = env->cr[IA64_CR_IIP];
    uint64_t saved_iipa = env->cr[IA64_CR_IIPA];
    uint64_t saved_ifs = env->cr[IA64_CR_IFS];
    uint64_t saved_isr = env->cr[IA64_CR_ISR];
    uint64_t saved_ifa = env->cr[IA64_CR_IFA];
    uint64_t saved_itir = env->cr[IA64_CR_ITIR];
    uint64_t saved_iha = env->cr[IA64_CR_IHA];
    uint64_t rr = env->rr[ia64_va_region(address)];
    bool nested_data_tlb =
        (kind == IA64_EXCEPTION_DATA_TLB_MISS ||
         kind == IA64_EXCEPTION_ALTERNATE_DATA_TLB_MISS) &&
        (old_psr & IA64_PSR_IC_BIT) == 0;
    bool trace_enabled = ia64_exception_trace_enabled();
    bool user_trace_enabled = ia64_user_exception_trace_enabled();

    if (nested_data_tlb) {
        kind = IA64_EXCEPTION_DATA_NESTED_TLB;
    }

    IA64_PERF_INC(IA64_PERF_EXCEPTION_DELIVERED);
    if (ia64_perf_enabled()) {
        ia64_perf_count_exception_kind(kind);
    }

    ia64_record_exception_common(env, kind, address, access_type, detail,
                                 format_detail || trace_enabled ||
                                 user_trace_enabled);

    if (nested_data_tlb) {
        env->cr[IA64_CR_IPSR] = saved_ipsr;
        env->cr[IA64_CR_IIP] = saved_iip;
        env->cr[IA64_CR_IIPA] = saved_iipa;
        env->cr[IA64_CR_IFS] = saved_ifs;
        env->cr[IA64_CR_ISR] = saved_isr;
        env->cr[IA64_CR_IFA] = saved_ifa;
        env->cr[IA64_CR_ITIR] = saved_itir;
        env->cr[IA64_CR_IHA] = saved_iha;
        env->psr = ia64_psr_clear_interruption_delivery_bits(env->psr);
        env->ip = (env->cr[IA64_CR_IVA] & ~0x7fffULL) +
                  env->exception.vector;
        goto trace;
    }

    env->cr[IA64_CR_IPSR] = env->psr;
    if (old_psr & IA64_PSR_IC_BIT) {
        env->cr[IA64_CR_IFS] = 0;
    }
    env->cr[IA64_CR_IIP] = access_type == MMU_INST_FETCH ?
                           (address & ~0xfULL) : env->ip;
    env->cr[IA64_CR_IFA] = address;
    env->cr[IA64_CR_ISR] = ia64_interruption_isr(env->psr, access_type);
    if (kind == IA64_EXCEPTION_INSTRUCTION_TLB_MISS ||
        kind == IA64_EXCEPTION_DATA_TLB_MISS ||
        kind == IA64_EXCEPTION_ALTERNATE_INSTRUCTION_TLB_MISS ||
        kind == IA64_EXCEPTION_ALTERNATE_DATA_TLB_MISS ||
        kind == IA64_EXCEPTION_PAGE_FAULT) {
        env->cr[IA64_CR_ITIR] = ia64_default_itir(env, address);
    }
    if (kind == IA64_EXCEPTION_INSTRUCTION_TLB_MISS ||
        kind == IA64_EXCEPTION_DATA_TLB_MISS) {
        env->cr[IA64_CR_IHA] = ia64_vhpt_hash_address(env, address);
    }

    env->psr = ia64_psr_clear_interruption_delivery_bits(env->psr);
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
