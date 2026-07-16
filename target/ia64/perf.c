/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "cpu.h"
#include "mem.h"
#include "perf.h"
#include "tcg/tcg.h"

#ifdef CONFIG_IA64_OBSERVABILITY

int ia64_perf_enabled_cached = -1;

static uint64_t ia64_perf_counters[IA64_PERF_COUNTER_COUNT];
static int64_t ia64_perf_start_us;
static bool ia64_perf_registered;
static int ia64_tb_stats_only_cached = -1;

typedef struct IA64PerfTBRecord {
    uint64_t executions;
    uint32_t host_bytes;
} IA64PerfTBRecord;

static GArray *ia64_perf_tb_records;
static uint32_t ia64_perf_last_tb_id;

static const char * const ia64_perf_counter_names[IA64_PERF_COUNTER_COUNT] = {
    [IA64_PERF_TB_TRANSLATED] = "tb.translated",
    [IA64_PERF_TB_EXECUTED] = "tb.executed",
    [IA64_PERF_TB_LOOKUP] = "tb.lookup",
    [IA64_PERF_TB_LOOKUP_HIT] = "tb.lookup.hit",
    [IA64_PERF_TB_LOOKUP_MISS] = "tb.lookup.miss",
    [IA64_PERF_TB_INVALIDATED] = "tb.invalidated",
    [IA64_PERF_TB_FLUSH] = "tb.flush",
    [IA64_PERF_TB_TRANSLATED_AFTER_FAULT] = "tb.translated.after_fault",
    [IA64_PERF_TB_GENERATED_REGION0] = "tb.generated.region0",
    [IA64_PERF_TB_GENERATED_REGION1] = "tb.generated.region1",
    [IA64_PERF_TB_GENERATED_REGION2] = "tb.generated.region2",
    [IA64_PERF_TB_GENERATED_REGION3] = "tb.generated.region3",
    [IA64_PERF_TB_GENERATED_REGION4] = "tb.generated.region4",
    [IA64_PERF_TB_GENERATED_REGION5] = "tb.generated.region5",
    [IA64_PERF_TB_GENERATED_REGION6] = "tb.generated.region6",
    [IA64_PERF_TB_GENERATED_REGION7] = "tb.generated.region7",
    [IA64_PERF_BUNDLE_DECODED] = "bundle.decoded",
    [IA64_PERF_BUNDLE_DECODE_INVALID] = "bundle.decode_invalid",
    [IA64_PERF_TB_EXIT_CHAINED] = "tb.exit.chained",
    [IA64_PERF_TB_EXIT_LOOKUP_PTR] = "tb.exit.lookup_ptr",
    [IA64_PERF_TB_EXIT_MAIN_LOOP] = "tb.exit.main_loop",
    [IA64_PERF_OP_ALLOC] = "op.alloc",
    [IA64_PERF_OP_RSE_FLUSHRS] = "op.rse.flushrs",
    [IA64_PERF_OP_RSE_LOADRS] = "op.rse.loadrs",
    [IA64_PERF_OP_RSE_FILL_RESTORED] = "op.rse.fill_restored",
    [IA64_PERF_OP_RSE_FILL_RESTORED_MEM] = "op.rse.fill_restored.mem",
    [IA64_PERF_OP_RSE_FILL_RESTORED_REG] = "op.rse.fill_restored.reg",
    [IA64_PERF_OP_RSE_ALLOC_SPILL] = "op.rse.alloc_spill",
    [IA64_PERF_OP_RSE_ALLOC_SPILL_REG] = "op.rse.alloc_spill.reg",
    [IA64_PERF_OP_BRANCH_INDIRECT] = "op.branch.indirect",
    [IA64_PERF_BRANCH_TAKEN] = "branch.taken",
    [IA64_PERF_LDST_READ] = "ldst.read_helper",
    [IA64_PERF_LDST_MMIO_LOAD] = "ldst.mmio_load",
    [IA64_PERF_LDST_MMIO_STORE] = "ldst.mmio_store",
    [IA64_PERF_LDST_LOAD_FAULT] = "ldst.load_fault",
    [IA64_PERF_LDST_STORE_FAULT] = "ldst.store_fault",
    [IA64_PERF_ALAT_RESOLVE] = "alat.resolve",
    [IA64_PERF_ALAT_INVALIDATE_STORE] = "alat.invalidate_store",
    [IA64_PERF_TARGET_TRANSLATE] = "mmu.target_translate",
    [IA64_PERF_TARGET_TRANSLATE_INST] = "mmu.target_translate.inst",
    [IA64_PERF_TARGET_TRANSLATE_LOAD] = "mmu.target_translate.load",
    [IA64_PERF_TARGET_TRANSLATE_STORE] = "mmu.target_translate.store",
    [IA64_PERF_TARGET_TRANSLATE_DEBUG] = "mmu.target_translate.debug",
    [IA64_PERF_TARGET_TRANSLATE_NO_DETAIL] = "mmu.target_translate.no_detail",
    [IA64_PERF_TARGET_TRANSLATE_PHYSICAL] = "mmu.target_translate.physical",
    [IA64_PERF_TARGET_TRANSLATE_LOOKUP] = "mmu.target_translate.lookup",
    [IA64_PERF_TARGET_TRANSLATE_LOOKUP_CACHE_HIT] =
        "mmu.target_translate.lookup_cache.hit",
    [IA64_PERF_TARGET_TRANSLATE_LOOKUP_CACHE_MISS] =
        "mmu.target_translate.lookup_cache.miss",
    [IA64_PERF_VHPT_WALK] = "mmu.vhpt.walk",
    [IA64_PERF_VHPT_WALK_SHORT] = "mmu.vhpt.walk.short",
    [IA64_PERF_VHPT_WALK_LONG_UNSUPPORTED] =
        "mmu.vhpt.walk.long_unsupported",
    [IA64_PERF_VHPT_WALK_VADDR_MISS] = "mmu.vhpt.walk.vaddr_miss",
    [IA64_PERF_VHPT_WALK_FAULT] = "mmu.vhpt.walk.fault",
    [IA64_PERF_VHPT_WALK_READ_FAIL] = "mmu.vhpt.walk.read_fail",
    [IA64_PERF_VHPT_WALK_INVALID] = "mmu.vhpt.walk.invalid",
    [IA64_PERF_VHPT_WALK_INSTALL_FAIL] = "mmu.vhpt.walk.install_fail",
    [IA64_PERF_VHPT_WALK_HIT] = "mmu.vhpt.walk.hit",
    [IA64_PERF_TARGET_TRANSLATE_OK] = "mmu.target_translate.ok",
    [IA64_PERF_TARGET_TRANSLATE_TLB_MISS] = "mmu.target_translate.tlb_miss",
    [IA64_PERF_TARGET_TRANSLATE_NOT_PRESENT] = "mmu.target_translate.not_present",
    [IA64_PERF_TARGET_TRANSLATE_ACCESS_DENIED] = "mmu.target_translate.access_denied",
    [IA64_PERF_TARGET_TRANSLATE_OTHER_FAIL] = "mmu.target_translate.other_fail",
    [IA64_PERF_TARGET_TRANSLATION_INSTALL] = "mmu.translation_install",
    [IA64_PERF_TARGET_TRANSLATION_INSTALL_INST] = "mmu.translation_install.inst",
    [IA64_PERF_TARGET_TRANSLATION_INSTALL_DATA] = "mmu.translation_install.data",
    [IA64_PERF_TARGET_TRANSLATION_PURGE_CACHE] = "mmu.translation_purge.cache",
    [IA64_PERF_TARGET_TRANSLATION_PURGE_REGISTER] = "mmu.translation_purge.register",
    [IA64_PERF_TARGET_TRANSLATION_PURGE_ALL] = "mmu.translation_purge.all",
    [IA64_PERF_QEMU_TLB_FILL] = "qemu_tlb.fill",
    [IA64_PERF_QEMU_TLB_FILL_INST] = "qemu_tlb.fill.inst",
    [IA64_PERF_QEMU_TLB_FILL_LOAD] = "qemu_tlb.fill.load",
    [IA64_PERF_QEMU_TLB_FILL_STORE] = "qemu_tlb.fill.store",
    [IA64_PERF_QEMU_TLB_FILL_SUCCESS] = "qemu_tlb.fill.success",
    [IA64_PERF_QEMU_TLB_FILL_PROBE_FAIL] = "qemu_tlb.fill.probe_fail",
    [IA64_PERF_QEMU_TLB_FILL_EXCEPTION] = "qemu_tlb.fill.exception",
    [IA64_PERF_QEMU_TLB_FILL_EXCEPTION_INST] = "qemu_tlb.fill.exception.inst",
    [IA64_PERF_QEMU_TLB_FILL_EXCEPTION_LOAD] = "qemu_tlb.fill.exception.load",
    [IA64_PERF_QEMU_TLB_FILL_EXCEPTION_STORE] = "qemu_tlb.fill.exception.store",
    [IA64_PERF_CPU_LOOP_EXIT] = "cpu_loop.exit",
    [IA64_PERF_EXIT_REQUEST_OBSERVED] = "exit_request.observed",
    [IA64_PERF_INTERRUPT_TIMER_CHECK] = "interrupt.timer_check",
    [IA64_PERF_INTERRUPT_TIMER_FAST_NOT_DUE] = "interrupt.timer_fast_not_due",
    [IA64_PERF_INTERRUPT_TIMER_DUE] = "interrupt.timer_due",
    [IA64_PERF_INTERRUPT_TIMER_LATCHED] = "interrupt.timer_latched",
    [IA64_PERF_INTERRUPT_TIMER_CALLBACK] = "interrupt.timer_callback",
    [IA64_PERF_INTERRUPT_REQUEST] = "interrupt.request",
    [IA64_PERF_INTERRUPT_EXEC_CHECK] = "interrupt.exec_check",
    [IA64_PERF_INTERRUPT_EXEC_PENDING_MASKED] = "interrupt.exec_pending_masked",
    [IA64_PERF_INTERRUPT_UNMASK_PENDING] = "interrupt.unmask_pending",
    [IA64_PERF_INTERRUPT_DELIVERED] = "interrupt.delivered",
    [IA64_PERF_INTERRUPT_MASKED_INTERVAL] = "interrupt.masked_interval",
    [IA64_PERF_INTERRUPT_MASKED_INTERVAL_END] =
        "interrupt.masked_interval_end",
    [IA64_PERF_EXCEPTION_DELIVERED] = "exception.delivered",
    [IA64_PERF_EXCEPTION_TLB_MISS] = "exception.tlb_miss",
    [IA64_PERF_EXCEPTION_PAGE_FAULT] = "exception.page_fault",
    [IA64_PERF_EXCEPTION_BREAK] = "exception.break",
    [IA64_PERF_EXCEPTION_EXTERNAL_INTERRUPT] = "exception.external_interrupt",
    [IA64_PERF_EXCEPTION_OTHER] = "exception.other",
    [IA64_PERF_EXCEPTION_RECORD_FORMATTED] = "exception.record.formatted",
    [IA64_PERF_EXCEPTION_RECORD_FAST] = "exception.record.fast",
    [IA64_PERF_TRANSITION_COVER] = "transition.cover",
    [IA64_PERF_TRANSITION_RFI] = "transition.rfi",
    [IA64_PERF_TRANSITION_RFI_VALID_IFS] = "transition.rfi.valid_ifs",
    [IA64_PERF_TRANSITION_RFI_TO_USER] = "transition.rfi.to_user",
    [IA64_PERF_TRANSITION_RFI_TO_KERNEL] = "transition.rfi.to_kernel",
    [IA64_PERF_TRANSITION_PRIVILEGE_CHANGE] = "transition.privilege_change",
    [IA64_PERF_TRANSITION_USER_TO_KERNEL] = "transition.user_to_kernel",
    [IA64_PERF_TRANSITION_KERNEL_TO_USER] = "transition.kernel_to_user",
    [IA64_PERF_TRANSITION_BANK_SWITCH] = "transition.bank_switch",
    [IA64_PERF_TRANSITION_BANK_SWITCH_TO_BANK0] = "transition.bank_switch.to_bank0",
    [IA64_PERF_TRANSITION_BANK_SWITCH_TO_BANK1] = "transition.bank_switch.to_bank1",
    [IA64_PERF_FIRMWARE_PAL] = "firmware.pal",
    [IA64_PERF_FIRMWARE_PAL_HALT] = "firmware.pal.halt",
    [IA64_PERF_FIRMWARE_PAL_HALT_LIGHT] = "firmware.pal.halt_light",
    [IA64_PERF_FIRMWARE_PAL_CACHE_MAINT] = "firmware.pal.cache_maint",
    [IA64_PERF_FIRMWARE_PAL_CACHE_INFO] = "firmware.pal.cache_info",
    [IA64_PERF_FIRMWARE_PAL_MEMORY_ATTRIBUTES] = "firmware.pal.memory_attributes",
    [IA64_PERF_FIRMWARE_PAL_PTCE_INFO] = "firmware.pal.ptce_info",
    [IA64_PERF_FIRMWARE_PAL_RSE_INFO] = "firmware.pal.rse_info",
    [IA64_PERF_FIRMWARE_PAL_VM_PAGE_SIZE] = "firmware.pal.vm_page_size",
    [IA64_PERF_FIRMWARE_PAL_FEATURES] = "firmware.pal.features",
    [IA64_PERF_FIRMWARE_PAL_DEBUG] = "firmware.pal.debug",
    [IA64_PERF_FIRMWARE_PAL_FREQUENCY] = "firmware.pal.frequency",
    [IA64_PERF_FIRMWARE_PAL_PERF_MONITOR] = "firmware.pal.perf_monitor",
    [IA64_PERF_FIRMWARE_PAL_FIXED_PLATFORM] = "firmware.pal.fixed_platform",
    [IA64_PERF_FIRMWARE_PAL_VERSION] = "firmware.pal.version",
    [IA64_PERF_FIRMWARE_PAL_REGISTER_INFO] = "firmware.pal.register_info",
    [IA64_PERF_FIRMWARE_PAL_PREFETCH] = "firmware.pal.prefetch",
    [IA64_PERF_FIRMWARE_PAL_LOGICAL_TO_PHYSICAL] = "firmware.pal.logical_to_physical",
    [IA64_PERF_FIRMWARE_PAL_CACHE_SHARED] = "firmware.pal.cache_shared",
    [IA64_PERF_FIRMWARE_PAL_SHUTDOWN] = "firmware.pal.shutdown",
    [IA64_PERF_FIRMWARE_PAL_HALT_INFO] = "firmware.pal.halt_info",
    [IA64_PERF_FIRMWARE_PAL_BRAND] = "firmware.pal.brand",
    [IA64_PERF_FIRMWARE_PAL_MACHINE_CHECK] = "firmware.pal.machine_check",
    [IA64_PERF_FIRMWARE_PAL_OTHER] = "firmware.pal.other",
    [IA64_PERF_FIRMWARE_SAL] = "firmware.sal",
    [IA64_PERF_FIRMWARE_EFI] = "firmware.efi",
    [IA64_PERF_TRANSLATE_HOST_NS] = "host_ns.translate",
    [IA64_PERF_DECODE_HOST_NS] = "host_ns.decode",
    [IA64_PERF_PREFLIGHT_HOST_NS] = "host_ns.preflight",
    [IA64_PERF_PLAN_ALLOC_HOST_NS] = "host_ns.plan_alloc",
    [IA64_PERF_TCG_EMISSION_HOST_NS] = "host_ns.tcg_emission",
    [IA64_PERF_TCG_OPTIMIZE_HOST_NS] = "host_ns.tcg_optimize",
    [IA64_PERF_HOST_CODEGEN_NS] = "host_ns.host_codegen",
    [IA64_PERF_GENERATED_EXECUTION_HOST_NS] = "host_ns.generated_execution",
    [IA64_PERF_GENERATED_EXECUTION_RETURNS] = "generated_execution.returns",
    [IA64_PERF_EVENT_OBSERVATION_LATENCY_NS_MAX] =
        "event.observation_latency_ns_max",
    [IA64_PERF_TCG_OP_GENERATED] = "tcg.op.generated",
    [IA64_PERF_TCG_OP_OPTIMIZED] = "tcg.op.optimized",
    [IA64_PERF_TCG_ENV_LOAD_GENERATED] = "tcg.env_load.generated",
    [IA64_PERF_TCG_ENV_LOAD_OPTIMIZED] = "tcg.env_load.optimized",
    [IA64_PERF_TCG_ENV_STORE_GENERATED] = "tcg.env_store.generated",
    [IA64_PERF_TCG_ENV_STORE_OPTIMIZED] = "tcg.env_store.optimized",
    [IA64_PERF_TCG_BRANCH_GENERATED] = "tcg.branch.generated",
    [IA64_PERF_TCG_BRANCH_OPTIMIZED] = "tcg.branch.optimized",
    [IA64_PERF_TCG_HELPER_GENERATED] = "tcg.helper.generated",
    [IA64_PERF_TCG_HELPER_OPTIMIZED] = "tcg.helper.optimized",
    [IA64_PERF_TCG_QEMU_LOAD_GENERATED] = "tcg.qemu_load.generated",
    [IA64_PERF_TCG_QEMU_LOAD_OPTIMIZED] = "tcg.qemu_load.optimized",
    [IA64_PERF_TCG_QEMU_STORE_GENERATED] = "tcg.qemu_store.generated",
    [IA64_PERF_TCG_QEMU_STORE_OPTIMIZED] = "tcg.qemu_store.optimized",
    [IA64_PERF_HOST_CODE_BYTES] = "host_code.bytes",
    [IA64_PERF_TB_CODEGEN_BUFFER_OVERFLOW] = "tb.codegen.buffer_overflow",
    [IA64_PERF_TB_CODEGEN_TOO_LARGE] = "tb.codegen.too_large",
    [IA64_PERF_TB_CODEGEN_PAGE_RELOCK] = "tb.codegen.page_relock",
    [IA64_PERF_PLAN_CAPACITY] = "plan.capacity",
    [IA64_PERF_PLAN_USE] = "plan.use",
    [IA64_PERF_PLAN_CAPACITY_MAX] = "plan.capacity.max",
    [IA64_PERF_PLAN_USE_MAX] = "plan.use.max",
    [IA64_PERF_PLAN_ALLOCATION] = "plan.allocation",
    [IA64_PERF_PLAN_ALLOCATION_BYTES] = "plan.allocation_bytes",
    [IA64_PERF_PLAN_PREFLIGHT_SUCCESS] = "plan.preflight.success",
    [IA64_PERF_PLAN_PREFLIGHT_REJECT] = "plan.preflight.reject",
    [IA64_PERF_PLAN_SHORTEN_TB_LIMIT] = "plan.shorten.tb_limit",
    [IA64_PERF_PLAN_SHORTEN_OP_BUDGET] = "plan.shorten.op_budget",
    [IA64_PERF_PLAN_SHORTEN_PLUGIN] = "plan.shorten.plugin",
    [IA64_PERF_PLAN_END_MEMORY] = "plan.end.memory",
    [IA64_PERF_PLAN_END_BRANCH] = "plan.end.branch",
    [IA64_PERF_PLAN_END_PAGE] = "plan.end.page",
    [IA64_PERF_PLAN_END_HELPER] = "plan.end.helper",
    [IA64_PERF_PLAN_END_OTHER] = "plan.end.other",
    [IA64_PERF_NAT_KNOWN_CLEAR] = "nat.known_clear",
    [IA64_PERF_NAT_KNOWN_SET] = "nat.known_set",
    [IA64_PERF_NAT_UNKNOWN] = "nat.unknown",
    [IA64_PERF_NAT_DYNAMIC_LOAD] = "nat.dynamic_load",
    [IA64_PERF_NAT_DYNAMIC_BRANCH] = "nat.dynamic_branch",
    [IA64_PERF_NAT_FAULT] = "nat.fault",
    [IA64_PERF_NAT_LATTICE_INVALIDATE] = "nat.lattice_invalidate",
    [IA64_PERF_NAT_RSE_UNKNOWN] = "nat.rse_unknown",
    [IA64_PERF_ALAT_ACTIVE_ENTER] = "alat.active.enter",
    [IA64_PERF_ALAT_ACTIVE_EXIT] = "alat.active.exit",
    [IA64_PERF_ALAT_RECORD] = "alat.record",
    [IA64_PERF_ALAT_CHECK_HIT] = "alat.check.hit",
    [IA64_PERF_ALAT_CHECK_MISS] = "alat.check.miss",
    [IA64_PERF_ALAT_INVALIDATE_GR] = "alat.invalidate.gr",
    [IA64_PERF_ALAT_INVALIDATE_FR] = "alat.invalidate.fr",
    [IA64_PERF_ALAT_INVALIDATE_RSE] = "alat.invalidate.rse",
    [IA64_PERF_ALAT_INVALIDATE_ALL] = "alat.invalidate.all",
    [IA64_PERF_ALAT_HELPER_CALL] = "alat.helper.call",
    [IA64_PERF_ALAT_HELPER_HOST_NS] = "alat.helper.host_ns",
};

static void ia64_perf_dump(void)
{
    int64_t elapsed_us = g_get_monotonic_time() - ia64_perf_start_us;
    uint64_t never_executed = 0;
    uint64_t one_use = 0;
    uint64_t reused = 0;

    if (ia64_perf_enabled_cached == 0) {
        return;
    }

    fprintf(stderr, "[ia64-perf] enabled=1\n");
    fprintf(stderr, "[ia64-perf] elapsed_us=%" PRId64 "\n", elapsed_us);
    for (unsigned i = 0; i < IA64_PERF_COUNTER_COUNT; i++) {
        g_assert(ia64_perf_counter_names[i] != NULL);
        fprintf(stderr, "[ia64-perf] %s=%" PRIu64 "\n",
                ia64_perf_counter_names[i], ia64_perf_counters[i]);
    }
    if (ia64_perf_tb_records != NULL) {
        for (unsigned i = 0; i < ia64_perf_tb_records->len; i++) {
            const IA64PerfTBRecord *record =
                &g_array_index(ia64_perf_tb_records, IA64PerfTBRecord, i);

            if (record->executions == 0) {
                never_executed++;
            } else if (record->executions == 1) {
                one_use++;
            } else {
                reused++;
            }
        }
    }
    fprintf(stderr, "[ia64-perf] tb.never_executed=%" PRIu64 "\n",
            never_executed);
    fprintf(stderr, "[ia64-perf] tb.one_use=%" PRIu64 "\n", one_use);
    fprintf(stderr, "[ia64-perf] tb.reused=%" PRIu64 "\n", reused);
}

static bool ia64_perf_env_enabled(const char *name)
{
    const char *value = g_getenv(name);

    return value != NULL && *value != '\0' && strcmp(value, "0") != 0 &&
           g_ascii_strcasecmp(value, "off") != 0 &&
           g_ascii_strcasecmp(value, "false") != 0;
}

bool ia64_perf_init_enabled(void)
{
    ia64_perf_enabled_cached = ia64_perf_env_enabled("VIBTANIUM_IA64_PERF");
    if (ia64_perf_enabled_cached && !ia64_perf_registered) {
        ia64_perf_start_us = g_get_monotonic_time();
        ia64_perf_tb_records = g_array_new(false, true,
                                           sizeof(IA64PerfTBRecord));
        atexit(ia64_perf_dump);
        ia64_perf_registered = true;
    }

    return ia64_perf_enabled_cached != 0;
}

bool ia64_perf_tb_stats_only_enabled(void)
{
    if (ia64_tb_stats_only_cached < 0) {
        ia64_tb_stats_only_cached =
            ia64_perf_env_enabled("VIBTANIUM_IA64_TB_STATS_ONLY");
    }
    return ia64_tb_stats_only_cached != 0;
}

void ia64_perf_count(IA64PerfCounter counter)
{
    if (counter < IA64_PERF_COUNTER_COUNT) {
        ia64_perf_counters[counter]++;
    }
}

void ia64_perf_add(IA64PerfCounter counter, uint64_t value)
{
    if (counter < IA64_PERF_COUNTER_COUNT) {
        ia64_perf_counters[counter] += value;
    }
}

void ia64_perf_max(IA64PerfCounter counter, uint64_t value)
{
    if (counter < IA64_PERF_COUNTER_COUNT &&
        ia64_perf_counters[counter] < value) {
        ia64_perf_counters[counter] = value;
    }
}

uint32_t ia64_perf_register_tb(void)
{
    IA64PerfTBRecord record = { 0 };

    if (!ia64_perf_enabled() || ia64_perf_tb_records == NULL) {
        return 0;
    }
    g_array_append_val(ia64_perf_tb_records, record);
    ia64_perf_last_tb_id = ia64_perf_tb_records->len;
    return ia64_perf_last_tb_id;
}

void ia64_perf_tb_exec(uint32_t id)
{
    if (id != 0 && ia64_perf_tb_records != NULL &&
        id <= ia64_perf_tb_records->len) {
        IA64PerfTBRecord *record =
            &g_array_index(ia64_perf_tb_records, IA64PerfTBRecord, id - 1);

        record->executions++;
    }
    ia64_perf_count(IA64_PERF_TB_EXECUTED);
}

void ia64_perf_record_codegen(const TCGCodegenStats *stats)
{
    if (!ia64_perf_enabled() || stats == NULL) {
        return;
    }
    ia64_perf_add(IA64_PERF_TRANSLATE_HOST_NS, stats->translate_ns);
    ia64_perf_add(IA64_PERF_TCG_OPTIMIZE_HOST_NS, stats->optimize_ns);
    ia64_perf_add(IA64_PERF_HOST_CODEGEN_NS, stats->host_codegen_ns);
    ia64_perf_add(IA64_PERF_TCG_OP_GENERATED, stats->generated.total);
    ia64_perf_add(IA64_PERF_TCG_OP_OPTIMIZED, stats->optimized.total);
    ia64_perf_add(IA64_PERF_TCG_ENV_LOAD_GENERATED,
                  stats->generated.env_load);
    ia64_perf_add(IA64_PERF_TCG_ENV_LOAD_OPTIMIZED,
                  stats->optimized.env_load);
    ia64_perf_add(IA64_PERF_TCG_ENV_STORE_GENERATED,
                  stats->generated.env_store);
    ia64_perf_add(IA64_PERF_TCG_ENV_STORE_OPTIMIZED,
                  stats->optimized.env_store);
    ia64_perf_add(IA64_PERF_TCG_BRANCH_GENERATED,
                  stats->generated.conditional_branch);
    ia64_perf_add(IA64_PERF_TCG_BRANCH_OPTIMIZED,
                  stats->optimized.conditional_branch);
    ia64_perf_add(IA64_PERF_TCG_HELPER_GENERATED,
                  stats->generated.helper_call);
    ia64_perf_add(IA64_PERF_TCG_HELPER_OPTIMIZED,
                  stats->optimized.helper_call);
    ia64_perf_add(IA64_PERF_TCG_QEMU_LOAD_GENERATED,
                  stats->generated.qemu_load);
    ia64_perf_add(IA64_PERF_TCG_QEMU_LOAD_OPTIMIZED,
                  stats->optimized.qemu_load);
    ia64_perf_add(IA64_PERF_TCG_QEMU_STORE_GENERATED,
                  stats->generated.qemu_store);
    ia64_perf_add(IA64_PERF_TCG_QEMU_STORE_OPTIMIZED,
                  stats->optimized.qemu_store);
    ia64_perf_add(IA64_PERF_HOST_CODE_BYTES, stats->host_bytes);
    if (ia64_perf_last_tb_id != 0 && ia64_perf_tb_records != NULL &&
        ia64_perf_last_tb_id <= ia64_perf_tb_records->len) {
        IA64PerfTBRecord *record = &g_array_index(
            ia64_perf_tb_records, IA64PerfTBRecord,
            ia64_perf_last_tb_id - 1);

        record->host_bytes = stats->host_bytes;
    }
}

void ia64_perf_record_codegen_failure(int reason)
{
    switch (reason) {
    case -1:
        ia64_perf_count(IA64_PERF_TB_CODEGEN_BUFFER_OVERFLOW);
        break;
    case -2:
        ia64_perf_count(IA64_PERF_TB_CODEGEN_TOO_LARGE);
        break;
    case -3:
        ia64_perf_count(IA64_PERF_TB_CODEGEN_PAGE_RELOCK);
        break;
    default:
        break;
    }
}

void ia64_perf_record_exec_time(uint64_t elapsed_ns)
{
    if (ia64_perf_enabled()) {
        ia64_perf_add(IA64_PERF_GENERATED_EXECUTION_HOST_NS, elapsed_ns);
        ia64_perf_count(IA64_PERF_GENERATED_EXECUTION_RETURNS);
        ia64_perf_max(IA64_PERF_EVENT_OBSERVATION_LATENCY_NS_MAX, elapsed_ns);
    }
}

uint64_t ia64_perf_clock_ns(void)
{
    return ia64_perf_enabled() ? g_get_monotonic_time() * 1000 : 0;
}

void ia64_perf_count_access_type(int access_type)
{
    switch (access_type) {
    case MMU_INST_FETCH:
        ia64_perf_count(IA64_PERF_TARGET_TRANSLATE_INST);
        break;
    case MMU_DATA_LOAD:
        ia64_perf_count(IA64_PERF_TARGET_TRANSLATE_LOAD);
        break;
    case MMU_DATA_STORE:
        ia64_perf_count(IA64_PERF_TARGET_TRANSLATE_STORE);
        break;
    default:
        break;
    }
}

void ia64_perf_count_translate_status(unsigned status)
{
    switch (status) {
    case IA64_TRANSLATE_OK:
        ia64_perf_count(IA64_PERF_TARGET_TRANSLATE_OK);
        break;
    case IA64_TRANSLATE_TLB_MISS:
        ia64_perf_count(IA64_PERF_TARGET_TRANSLATE_TLB_MISS);
        break;
    case IA64_TRANSLATE_NOT_PRESENT:
        ia64_perf_count(IA64_PERF_TARGET_TRANSLATE_NOT_PRESENT);
        break;
    case IA64_TRANSLATE_ACCESS_DENIED:
        ia64_perf_count(IA64_PERF_TARGET_TRANSLATE_ACCESS_DENIED);
        break;
    default:
        ia64_perf_count(IA64_PERF_TARGET_TRANSLATE_OTHER_FAIL);
        break;
    }
}

void ia64_perf_count_exception_kind(unsigned kind)
{
    if (kind == IA64_EXCEPTION_REGISTER_NAT_CONSUMPTION ||
        kind == IA64_EXCEPTION_DATA_NAT_PAGE_CONSUMPTION ||
        kind == IA64_EXCEPTION_INSTRUCTION_NAT_PAGE_CONSUMPTION) {
        ia64_perf_count(IA64_PERF_NAT_FAULT);
    }
    switch (kind) {
    case IA64_EXCEPTION_VHPT_TRANSLATION:
    case IA64_EXCEPTION_INSTRUCTION_TLB_MISS:
    case IA64_EXCEPTION_DATA_TLB_MISS:
    case IA64_EXCEPTION_ALTERNATE_INSTRUCTION_TLB_MISS:
    case IA64_EXCEPTION_ALTERNATE_DATA_TLB_MISS:
    case IA64_EXCEPTION_DATA_NESTED_TLB:
        ia64_perf_count(IA64_PERF_EXCEPTION_TLB_MISS);
        break;
    case IA64_EXCEPTION_DIRTY_BIT:
    case IA64_EXCEPTION_INSTRUCTION_ACCESS_BIT:
    case IA64_EXCEPTION_DATA_ACCESS_BIT:
    case IA64_EXCEPTION_INSTRUCTION_ACCESS_RIGHTS:
    case IA64_EXCEPTION_DATA_ACCESS_RIGHTS:
    case IA64_EXCEPTION_PAGE_FAULT:
        ia64_perf_count(IA64_PERF_EXCEPTION_PAGE_FAULT);
        break;
    case IA64_EXCEPTION_BREAK:
        ia64_perf_count(IA64_PERF_EXCEPTION_BREAK);
        break;
    case IA64_EXCEPTION_EXTERNAL_INTERRUPT:
        ia64_perf_count(IA64_PERF_EXCEPTION_EXTERNAL_INTERRUPT);
        break;
    default:
        ia64_perf_count(IA64_PERF_EXCEPTION_OTHER);
        break;
    }
}

#endif /* CONFIG_IA64_OBSERVABILITY */
