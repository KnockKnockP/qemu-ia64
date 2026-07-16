/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "flight-recorder.h"

#if VIBTANIUM_DIAGNOSTICS

#include "insn.h"

#define IA64_FLIGHT_RING_SIZE 128
#define IA64_KERNEL_REGION 5
#define IA64_LOW_STACK_DEFAULT_MAX UINT64_C(0x20000000)

typedef struct IA64FlightEntry {
    uint64_t seq;
    char event[32];
    char detail[96];
    uint64_t ip;
    uint64_t psr;
    uint64_t cfm;
    uint64_t pr;
    uint64_t r1;
    uint64_t r12;
    uint64_t r13;
    uint64_t bsp;
    uint64_t bspstore;
    uint64_t rsc;
    uint64_t ipsr;
    uint64_t iip;
    uint64_t ifa;
    uint64_t isr;
    uint64_t a;
    uint64_t b;
    uint64_t c;
    uint64_t d;
} IA64FlightEntry;

static IA64FlightEntry ia64_flight_ring[IA64_FLIGHT_RING_SIZE];
static uint64_t ia64_flight_seq;

static bool ia64_diag_env_enabled(const char *name)
{
    const char *value = g_getenv(name);

    return value != NULL && *value != '\0' &&
           g_ascii_strcasecmp(value, "0") != 0 &&
           g_ascii_strcasecmp(value, "false") != 0 &&
           g_ascii_strcasecmp(value, "off") != 0;
}

static uint64_t ia64_diag_env_u64(const char *name, uint64_t fallback)
{
    const char *value = g_getenv(name);
    char *endptr = NULL;
    uint64_t parsed;

    if (!value || !*value) {
        return fallback;
    }

    parsed = g_ascii_strtoull(value, &endptr, 0);
    return endptr != value ? parsed : fallback;
}

bool ia64_diag_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = ia64_diag_env_enabled("VIBTANIUM_FLIGHT_RECORDER") ||
                  ia64_diag_env_enabled("VIBTANIUM_FLIGHT_ECHO") ||
                  ia64_diag_env_enabled("VIBTANIUM_INVARIANTS");
    }
    return enabled != 0;
}

bool ia64_diag_invariants_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = ia64_diag_env_enabled("VIBTANIUM_INVARIANTS");
    }
    return enabled != 0;
}

static bool ia64_diag_echo_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = ia64_diag_env_enabled("VIBTANIUM_FLIGHT_ECHO");
    }
    return enabled != 0;
}

static uint64_t ia64_diag_low_stack_max(void)
{
    static bool initialized;
    static uint64_t threshold;

    if (!initialized) {
        threshold = ia64_diag_env_u64("VIBTANIUM_INVARIANT_LOW_STACK_MAX",
                                      IA64_LOW_STACK_DEFAULT_MAX);
        initialized = true;
    }
    return threshold;
}

static unsigned ia64_diag_dump_limit(void)
{
    static bool initialized;
    static unsigned limit;

    if (!initialized) {
        limit = ia64_diag_env_u64("VIBTANIUM_INVARIANT_DUMP_LIMIT", 4);
        initialized = true;
    }
    return limit;
}

static void ia64_diag_print_entry(const IA64FlightEntry *entry)
{
    fprintf(stderr,
            "[ia64-flight] seq=%" PRIu64 " event=%s"
            " ip=0x%016" PRIx64 " psr=0x%016" PRIx64
            " cfm=0x%016" PRIx64 " pr=0x%016" PRIx64
            " r1=0x%016" PRIx64 " r12=0x%016" PRIx64
            " r13=0x%016" PRIx64 " bsp=0x%016" PRIx64
            " bspstore=0x%016" PRIx64 " rsc=0x%016" PRIx64
            " ipsr=0x%016" PRIx64 " iip=0x%016" PRIx64
            " ifa=0x%016" PRIx64 " isr=0x%016" PRIx64
            " a=0x%016" PRIx64 " b=0x%016" PRIx64
            " c=0x%016" PRIx64 " d=0x%016" PRIx64
            " detail=%s\n",
            entry->seq, entry->event, entry->ip, entry->psr, entry->cfm,
            entry->pr, entry->r1, entry->r12, entry->r13, entry->bsp,
            entry->bspstore, entry->rsc, entry->ipsr, entry->iip,
            entry->ifa, entry->isr, entry->a, entry->b, entry->c,
            entry->d, entry->detail);
}

static void ia64_diag_record_state(CPUIA64State *env, const char *event,
                                   uint64_t a, uint64_t b,
                                   uint64_t c, uint64_t d,
                                   const char *detail)
{
    IA64FlightEntry *entry;

    if (!ia64_diag_enabled()) {
        return;
    }

    entry = &ia64_flight_ring[ia64_flight_seq % IA64_FLIGHT_RING_SIZE];
    memset(entry, 0, sizeof(*entry));
    entry->seq = ++ia64_flight_seq;
    g_strlcpy(entry->event, event ? event : "unknown", sizeof(entry->event));
    g_strlcpy(entry->detail, detail ? detail : "", sizeof(entry->detail));
    entry->a = a;
    entry->b = b;
    entry->c = c;
    entry->d = d;

    if (env) {
        entry->ip = env->ip;
        entry->psr = ia64_env_psr(env);
        entry->cfm = env->cfm;
        entry->pr = env->pr;
        entry->r1 = ia64_read_gr(env, 1);
        entry->r12 = ia64_read_gr(env, 12);
        entry->r13 = ia64_read_gr(env, 13);
        entry->bsp = env->ar[IA64_AR_BSP];
        entry->bspstore = env->ar[IA64_AR_BSPSTORE];
        entry->rsc = env->ar[IA64_AR_RSC];
        entry->ipsr = env->cr[IA64_CR_IPSR];
        entry->iip = env->cr[IA64_CR_IIP];
        entry->ifa = env->cr[IA64_CR_IFA];
        entry->isr = env->cr[IA64_CR_ISR];
    }

    if (ia64_diag_echo_enabled()) {
        ia64_diag_print_entry(entry);
    }
}

void ia64_diag_dump(const char *reason)
{
    uint64_t count;
    uint64_t first;

    if (!ia64_diag_enabled()) {
        return;
    }

    count = MIN(ia64_flight_seq, (uint64_t)IA64_FLIGHT_RING_SIZE);
    first = ia64_flight_seq >= count ? ia64_flight_seq - count + 1 : 1;
    fprintf(stderr, "[ia64-flight-dump] reason=%s count=%" PRIu64 "\n",
            reason ? reason : "manual", count);
    for (uint64_t seq = first; seq <= ia64_flight_seq; seq++) {
        const IA64FlightEntry *entry =
            &ia64_flight_ring[(seq - 1) % IA64_FLIGHT_RING_SIZE];

        if (entry->seq == seq) {
            ia64_diag_print_entry(entry);
        }
    }
    fflush(stderr);
}

static void ia64_diag_report_invariant(CPUIA64State *env,
                                       const char *name,
                                       uint64_t a, uint64_t b,
                                       uint64_t c, uint64_t d,
                                       const char *detail)
{
    static unsigned dumps;

    ia64_diag_record_state(env, name, a, b, c, d, detail);
    if (dumps < ia64_diag_dump_limit()) {
        dumps++;
        ia64_diag_dump(name);
    }
}

void ia64_diag_check_kernel_low_stack(CPUIA64State *env, const char *where)
{
    uint64_t sp;
    uint64_t bspstore;
    uint64_t threshold;
    bool kernel_ip;
    bool low_sp;
    bool low_bspstore;

    if (!env || !ia64_diag_invariants_enabled()) {
        return;
    }

    kernel_ip = (env->ip >> 61) == IA64_KERNEL_REGION;
    if (!kernel_ip) {
        return;
    }

    threshold = ia64_diag_low_stack_max();
    sp = ia64_read_gr(env, 12);
    bspstore = env->ar[IA64_AR_BSPSTORE];
    low_sp = sp != 0 && sp < threshold;
    low_bspstore = bspstore != 0 && bspstore < threshold;
    if (!low_sp && !low_bspstore) {
        return;
    }

    ia64_diag_report_invariant(env, "invariant.kernel-low-stack",
                               sp, bspstore, threshold, 0, where);
}

void ia64_diag_record_efi_commit(CPUIA64State *env, const char *state,
                                 const char *image, uint64_t load_base,
                                 uint64_t size)
{
    ia64_diag_record_state(env, "efi.commit", load_base, size, 0, 0,
                           state ? state : image);
}

void ia64_diag_record_efi_handoff(CPUIA64State *env, const char *image,
                                  uint64_t entry, uint64_t global_pointer)
{
    ia64_diag_record_state(env, "efi.handoff", entry, global_pointer, 0, 0,
                           image);
}

void ia64_diag_record_firmware_write(CPUIA64State *env, const char *name,
                                     uint64_t address, uint64_t size,
                                     uint64_t clear_size, bool live_cpu)
{
    ia64_diag_record_state(env, "efi.write", address, size, clear_size,
                           live_cpu ? 1 : 0, name);
    if (live_cpu && ia64_diag_invariants_enabled()) {
        ia64_diag_report_invariant(env, "invariant.efi-write-live-cpu",
                                   address, size, clear_size, 0, name);
    }
}

void ia64_diag_record_exception(CPUIA64State *env, const char *kind,
                                uint64_t source_ip, uint64_t address,
                                uint64_t vector, uint64_t old_psr)
{
    ia64_diag_record_state(env, "exception", source_ip, address, vector,
                           old_psr, kind);
}

void ia64_diag_record_external_interrupt(CPUIA64State *env,
                                         uint64_t interrupt_request)
{
    ia64_diag_record_state(env, "interrupt.external",
                           interrupt_request,
                           env ? env->interrupt.pending_vector : 0,
                           env ? env->interrupt.in_service[0] : 0,
                           env ? env->interrupt.in_service[3] : 0,
                           "external-interrupt");
}

void ia64_diag_record_rfi(CPUIA64State *env, uint64_t bundle_ip,
                          uint64_t target)
{
    ia64_diag_record_state(env, "rfi", bundle_ip, target,
                           env ? env->cr[IA64_CR_IPSR] : 0,
                           env ? env->cr[IA64_CR_IFS] : 0, "rfi");
}

#endif
