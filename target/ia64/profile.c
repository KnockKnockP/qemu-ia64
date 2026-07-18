/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qemu/cutils.h"
#include "cpu.h"
#include "profile.h"
#include "exec/translation-block.h"
#include "tcg/tcg.h"

#ifdef CONFIG_IA64_OBSERVABILITY

#define IA64_PROFILE_SAMPLE_QUANTUM_NS INT64_C(10000)
#define IA64_PROFILE_INITIAL_DELAY_NS INT64_C(100000000)

int ia64_profile_enabled_cached = -1;

static unsigned ia64_profile_shift = 11;
static bool ia64_profile_registered;
static GPtrArray *ia64_profile_cpus;

typedef struct IA64ProfileShapeRecord {
    uint64_t pc;
    uint32_t flags;
    uint32_t counter[IA64_PROFILE_COUNTER_COUNT];
    uint32_t group_length[IA64_PROFILE_GROUP_HIST_COUNT];
    uint32_t group_destination[IA64_PROFILE_GROUP_HIST_COUNT];
    TCGCodegenOpStats generated;
    TCGCodegenOpStats optimized;
    uint32_t exact_helper[IA64_PROFILE_EXACT_HELPERS];
    uint32_t host_bytes;
    uint32_t dirty;
    uint8_t exit;
    uint8_t end_reason;
} IA64ProfileShapeRecord;

typedef struct IA64ProfileCodeRecord {
    uint64_t pc;
    uint32_t flags;
    TCGCodegenStats stats;
} IA64ProfileCodeRecord;

static IA64ProfileShapeRecord
    ia64_profile_shapes[IA64_PROFILE_SHAPE_SLOTS];
static unsigned ia64_profile_shape_count;
static const char *ia64_profile_exact_helper_names[IA64_PROFILE_EXACT_HELPERS];
static unsigned ia64_profile_exact_helper_count;
static GArray *ia64_profile_normal_code;
G_LOCK_DEFINE_STATIC(ia64_profile_shape_map);

static int ia64_profile_exact_helper_id(const char *name);

static const char * const ia64_profile_counter_names[] = {
    [IA64_PROFILE_TB_EXECUTED] = "tb.executed",
    [IA64_PROFILE_BUNDLE_EXECUTED] = "bundle.executed",
    [IA64_PROFILE_SLOT_EXECUTED] = "slot.executed",
    [IA64_PROFILE_BUNDLE_ZERO_HELPER] = "bundle.zero_helper",
    [IA64_PROFILE_BRANCH_INLINE_DIRECT] = "branch.inline.direct",
    [IA64_PROFILE_BRANCH_INLINE_INDIRECT] = "branch.inline.indirect",
    [IA64_PROFILE_EXIT_DIRECT_CHAIN] = "tb.exit.direct_chain",
    [IA64_PROFILE_EXIT_LOOKUP_PTR] = "tb.exit.lookup_ptr",
    [IA64_PROFILE_EXIT_MAIN_LOOP] = "tb.exit.main_loop",
    [IA64_PROFILE_STATE_CACHE_ACTIVE_BUNDLE] =
        "state_cache.active_bundle",
    [IA64_PROFILE_STATE_CACHE_HIT] = "state_cache.hit",
    [IA64_PROFILE_STATE_CACHE_DIRTY_WRITEBACK] =
        "state_cache.dirty_writeback",
    [IA64_PROFILE_SHAPE_A_GROUP] = "shape.a.group",
    [IA64_PROFILE_SHAPE_A_SLOT] = "shape.a.slot",
    [IA64_PROFILE_SHAPE_B_GROUP] = "shape.b.group",
    [IA64_PROFILE_SHAPE_B_SLOT] = "shape.b.slot",
    [IA64_PROFILE_SHAPE_C_GROUP] = "shape.c.group",
    [IA64_PROFILE_SHAPE_C_SLOT] = "shape.c.slot",
    [IA64_PROFILE_SHAPE_C_RSE_GROUP] = "shape.c.reason.rse.group",
    [IA64_PROFILE_SHAPE_C_RSE_SLOT] = "shape.c.reason.rse.slot",
    [IA64_PROFILE_SHAPE_C_RFI_GROUP] = "shape.c.reason.rfi.group",
    [IA64_PROFILE_SHAPE_C_RFI_SLOT] = "shape.c.reason.rfi.slot",
    [IA64_PROFILE_SHAPE_C_SYSTEM_GROUP] = "shape.c.reason.system.group",
    [IA64_PROFILE_SHAPE_C_SYSTEM_SLOT] = "shape.c.reason.system.slot",
    [IA64_PROFILE_SHAPE_C_DATA_MEMORY_GROUP] =
        "shape.c.reason.data_memory.group",
    [IA64_PROFILE_SHAPE_C_DATA_MEMORY_SLOT] =
        "shape.c.reason.data_memory.slot",
    [IA64_PROFILE_SHAPE_C_DATA_NONMEMORY_GROUP] =
        "shape.c.reason.data_nonmemory.group",
    [IA64_PROFILE_SHAPE_C_DATA_NONMEMORY_SLOT] =
        "shape.c.reason.data_nonmemory.slot",
    [IA64_PROFILE_SHAPE_C_FLOATING_GROUP] =
        "shape.c.reason.floating.group",
    [IA64_PROFILE_SHAPE_C_FLOATING_SLOT] =
        "shape.c.reason.floating.slot",
    [IA64_PROFILE_SHAPE_C_PLUGIN_GROUP] = "shape.c.reason.plugin.group",
    [IA64_PROFILE_SHAPE_C_PLUGIN_SLOT] = "shape.c.reason.plugin.slot",
    [IA64_PROFILE_SHAPE_C_INSN_DEBUG_GROUP] =
        "shape.c.reason.instruction_debug.group",
    [IA64_PROFILE_SHAPE_C_INSN_DEBUG_SLOT] =
        "shape.c.reason.instruction_debug.slot",
    [IA64_PROFILE_SHAPE_C_DATA_DEBUG_GROUP] =
        "shape.c.reason.data_debug.group",
    [IA64_PROFILE_SHAPE_C_DATA_DEBUG_SLOT] =
        "shape.c.reason.data_debug.slot",
    [IA64_PROFILE_SHAPE_C_DURABLE_OPEN_GROUP] =
        "shape.c.reason.durable_open_group.group",
    [IA64_PROFILE_SHAPE_C_DURABLE_OPEN_SLOT] =
        "shape.c.reason.durable_open_group.slot",
    [IA64_PROFILE_SHAPE_C_UNSUPPORTED_TRAITS_GROUP] =
        "shape.c.reason.unsupported_traits.group",
    [IA64_PROFILE_SHAPE_C_UNSUPPORTED_TRAITS_SLOT] =
        "shape.c.reason.unsupported_traits.slot",
    [IA64_PROFILE_SHAPE_C_UNKNOWN_GROUP] = "shape.c.reason.unknown.group",
    [IA64_PROFILE_SHAPE_C_UNKNOWN_SLOT] = "shape.c.reason.unknown.slot",
    [IA64_PROFILE_ORDINARY_NONMEMORY_SLOT] =
        "ordinary_nonmemory.slot.total",
    [IA64_PROFILE_ORDINARY_NONMEMORY_SHAPE_A_SLOT] =
        "ordinary_nonmemory.shape.a.slot",
    [IA64_PROFILE_ORDINARY_NONMEMORY_SHAPE_B_SLOT] =
        "ordinary_nonmemory.shape.b.slot",
    [IA64_PROFILE_ORDINARY_NONMEMORY_SHAPE_C_SLOT] =
        "ordinary_nonmemory.shape.c.slot",
    [IA64_PROFILE_ORDINARY_NONMEMORY_SHAPE_C_RSE_SLOT] =
        "ordinary_nonmemory.shape.c.reason.rse.slot",
    [IA64_PROFILE_ORDINARY_NONMEMORY_SHAPE_C_RFI_SLOT] =
        "ordinary_nonmemory.shape.c.reason.rfi.slot",
    [IA64_PROFILE_ORDINARY_NONMEMORY_SHAPE_C_SYSTEM_SLOT] =
        "ordinary_nonmemory.shape.c.reason.system.slot",
    [IA64_PROFILE_ORDINARY_NONMEMORY_SHAPE_C_DATA_MEMORY_SLOT] =
        "ordinary_nonmemory.shape.c.reason.data_memory.slot",
    [IA64_PROFILE_ORDINARY_NONMEMORY_SHAPE_C_DATA_NONMEMORY_SLOT] =
        "ordinary_nonmemory.shape.c.reason.data_nonmemory.slot",
    [IA64_PROFILE_ORDINARY_NONMEMORY_SHAPE_C_FLOATING_SLOT] =
        "ordinary_nonmemory.shape.c.reason.floating.slot",
    [IA64_PROFILE_ORDINARY_NONMEMORY_SHAPE_C_PLUGIN_SLOT] =
        "ordinary_nonmemory.shape.c.reason.plugin.slot",
    [IA64_PROFILE_ORDINARY_NONMEMORY_SHAPE_C_INSN_DEBUG_SLOT] =
        "ordinary_nonmemory.shape.c.reason.instruction_debug.slot",
    [IA64_PROFILE_ORDINARY_NONMEMORY_SHAPE_C_DATA_DEBUG_SLOT] =
        "ordinary_nonmemory.shape.c.reason.data_debug.slot",
    [IA64_PROFILE_ORDINARY_NONMEMORY_SHAPE_C_DURABLE_OPEN_SLOT] =
        "ordinary_nonmemory.shape.c.reason.durable_open_group.slot",
    [IA64_PROFILE_ORDINARY_NONMEMORY_SHAPE_C_UNSUPPORTED_TRAITS_SLOT] =
        "ordinary_nonmemory.shape.c.reason.unsupported_traits.slot",
    [IA64_PROFILE_ORDINARY_NONMEMORY_SHAPE_C_UNKNOWN_SLOT] =
        "ordinary_nonmemory.shape.c.reason.unknown.slot",
    [IA64_PROFILE_GROUP_TB_CROSSING] = "group.crossing.tb",
    [IA64_PROFILE_GROUP_PAGE_CROSSING] = "group.crossing.page",
    [IA64_PROFILE_GROUP_SAFEPOINT] = "group.safepoint",
    [IA64_PROFILE_OVERLAY_SAVE_GR] = "overlay.save.gr",
    [IA64_PROFILE_OVERLAY_SAVE_NAT] = "overlay.save.nat",
    [IA64_PROFILE_OVERLAY_SAVE_PR] = "overlay.save.pr",
    [IA64_PROFILE_OVERLAY_SAVE_BR] = "overlay.save.br",
    [IA64_PROFILE_OVERLAY_SAVE_PFS] = "overlay.save.pfs",
    [IA64_PROFILE_OVERLAY_SAVE_AR] = "overlay.save.ar",
    [IA64_PROFILE_OVERLAY_SAVE_FR] = "overlay.save.fr",
    [IA64_PROFILE_OVERLAY_VALIDITY_LOAD] = "overlay.validity.load",
    [IA64_PROFILE_OVERLAY_VALIDITY_BRANCH] = "overlay.validity.branch",
    [IA64_PROFILE_OVERLAY_CLEAR] = "overlay.clear",
    [IA64_PROFILE_STAGED_WRITE] = "state.staged_write",
    [IA64_PROFILE_FINAL_COMMIT] = "state.final_commit",
    [IA64_PROFILE_DURABLE_MATERIALIZATION] = "state.durable_materialization",
    [IA64_PROFILE_DURABLE_BYTES] = "state.durable_bytes",
    [IA64_PROFILE_ARCH_LOAD] = "state.arch_load",
    [IA64_PROFILE_ARCH_STORE] = "state.arch_store",
    [IA64_PROFILE_SYNC_HELPER] = "state.sync.helper",
    [IA64_PROFILE_SYNC_FAULT] = "state.sync.fault",
    [IA64_PROFILE_SYNC_EXIT] = "state.sync.exit",
    [IA64_PROFILE_RESIDENT_LOAD] = "resident.load",
    [IA64_PROFILE_RESIDENT_HIT] = "resident.hit",
    [IA64_PROFILE_RESIDENT_SPILL] = "resident.spill",
    [IA64_PROFILE_RESIDENT_WRITEBACK] = "resident.writeback",
    [IA64_PROFILE_RESIDENT_SYNC] = "resident.sync",
    [IA64_PROFILE_NAT_KNOWN_CLEAR] = "nat.known_clear",
    [IA64_PROFILE_NAT_KNOWN_SET] = "nat.known_set",
    [IA64_PROFILE_NAT_UNKNOWN] = "nat.unknown",
    [IA64_PROFILE_NAT_DYNAMIC_LOAD] = "nat.dynamic_load",
    [IA64_PROFILE_NAT_DYNAMIC_BRANCH] = "nat.dynamic_branch",
    [IA64_PROFILE_NAT_FAULT] = "nat.direct_known_set_fault",
    [IA64_PROFILE_NAT_LATTICE_INVALIDATE] = "nat.lattice_invalidate",
    [IA64_PROFILE_NAT_RSE_UNKNOWN] = "nat.rse_unknown",
    [IA64_PROFILE_ALAT_EMPTY_TB] = "alat.empty.tb",
    [IA64_PROFILE_ALAT_EMPTY_BUNDLE] = "alat.empty.bundle",
    [IA64_PROFILE_ALAT_ACTIVE_TB] = "alat.active.tb",
    [IA64_PROFILE_ALAT_ACTIVE_BUNDLE] = "alat.active.bundle",
    [IA64_PROFILE_COMMON_INTEGER_SLOT] = "common.integer.slot",
    [IA64_PROFILE_COMMON_PREDICATE_SLOT] = "common.predicate.slot",
    [IA64_PROFILE_COMMON_BRANCH_SLOT] = "common.branch.slot",
    [IA64_PROFILE_COMMON_MEMORY_SLOT] = "common.memory.slot",
    [IA64_PROFILE_COMMON_LOOP_SLOT] = "common.loop.slot",
    [IA64_PROFILE_LOOP_RECOGNIZED] = "loop.recognized",
    [IA64_PROFILE_LOOP_REJECT_NOT_SELF] = "loop.reject.not_self",
    [IA64_PROFILE_LOOP_REJECT_OBSERVATION] = "loop.reject.observation",
    [IA64_PROFILE_LOOP_REJECT_BODY] = "loop.reject.body",
    [IA64_PROFILE_LOOP_INTERNAL_ITERATION] = "loop.internal_iteration",
    [IA64_PROFILE_LOOP_BUDGET_EXIT] = "loop.budget_exit",
    [IA64_PROFILE_LOOP_ASYNC_EXIT] = "loop.async_exit",
    [IA64_PROFILE_LOOP_ZERO_STORE] = "loop.zero_store",
    [IA64_PROFILE_LOOP_BULK_ZERO_BYTES] = "loop.bulk_zero_bytes",
    [IA64_PROFILE_LOOP_SLOW_FALLBACK] = "loop.slow_fallback",
};

static const char * const ia64_profile_tb_end_names[] = {
    [IA64_PROFILE_TB_END_MEMORY] = "memory",
    [IA64_PROFILE_TB_END_BRANCH] = "branch",
    [IA64_PROFILE_TB_END_PAGE] = "page",
    [IA64_PROFILE_TB_END_OP_BUDGET] = "op_budget",
    [IA64_PROFILE_TB_END_HELPER] = "helper",
    [IA64_PROFILE_TB_END_EVENT] = "event",
    [IA64_PROFILE_TB_END_OTHER] = "other",
};

static const char * const ia64_profile_helper_names[] = {
    [IA64_PROFILE_HELPER_RSE] = "helper.rse",
    [IA64_PROFILE_HELPER_NAT_ALAT] = "helper.nat_alat",
    [IA64_PROFILE_HELPER_OTHER] = "helper.other",
};

static uint64_t ia64_profile_scaled(uint64_t value, long double weight)
{
    if (weight <= 0.0 || value == 0) {
        return 0;
    }
    if ((long double)value > (long double)UINT64_MAX / weight) {
        return UINT64_MAX;
    }
    return (uint64_t)((long double)value * weight + 0.5);
}

static void ia64_profile_sample_on_cpu(CPUState *cs, run_on_cpu_data data)
{
    IA64CPU *cpu = IA64_CPU(cs);
    IA64ProductionProfile *profile = &cpu->production_profile;

    (void)data;
    if (profile->active && !qatomic_read(&profile->collecting)) {
        qatomic_set(&profile->collecting, 1);
        qatomic_inc(&profile->sample_windows);
    }
}

static void ia64_profile_sample_timer(void *opaque)
{
    IA64CPU *cpu = opaque;
    IA64ProductionProfile *profile = &cpu->production_profile;
    uint64_t period = UINT64_C(1) << ia64_profile_shift;

    if (!profile->active) {
        return;
    }
    async_run_on_cpu(CPU(cpu), ia64_profile_sample_on_cpu, RUN_ON_CPU_NULL);
    timer_mod_ns(profile->sample_timer,
                 qemu_clock_get_ns(QEMU_CLOCK_REALTIME) +
                 IA64_PROFILE_SAMPLE_QUANTUM_NS * period);
}

static void ia64_profile_print_rate(const char *name, uint64_t value,
                                    uint64_t bundles)
{
    double rate = bundles == 0 ? 0.0 :
                  (double)value * 1000000.0 / (double)bundles;

    fprintf(stderr, "[ia64-profile] %s=%" PRIu64 "\n", name, value);
    fprintf(stderr, "[ia64-profile] %s.per_million_bundles=%.3f\n",
            name, rate);
}

typedef struct IA64ProfileCodegenTotal {
    uint64_t generated[10];
    uint64_t optimized[10];
    uint64_t host_bytes;
    uint64_t group_length[IA64_PROFILE_GROUP_HIST_COUNT];
    uint64_t group_destination[IA64_PROFILE_GROUP_HIST_COUNT];
    uint64_t end_reason[IA64_PROFILE_TB_END_COUNT];
    uint64_t exact_helper[IA64_PROFILE_EXACT_HELPERS];
} IA64ProfileCodegenTotal;

static void ia64_profile_add_codegen_ops(uint64_t total[10],
                                         const TCGCodegenOpStats *ops,
                                         uint64_t weight)
{
    const uint32_t value[10] = {
        ops->total, ops->env_load, ops->env_store,
        ops->conditional_branch, ops->helper_call, ops->qemu_load,
        ops->qemu_store, ops->goto_tb, ops->goto_ptr, ops->exit_tb,
    };

    for (unsigned i = 0; i < ARRAY_SIZE(value); i++) {
        total[i] += ia64_profile_scaled(value[i], weight);
    }
}

static void ia64_profile_print_density(const char *name, uint64_t value,
                                       uint64_t bundles, uint64_t slots)
{
    double per_bundle = bundles == 0 ? 0.0 :
                        (double)value / (double)bundles;
    double per_slot = slots == 0 ? 0.0 : (double)value / (double)slots;

    fprintf(stderr, "[ia64-profile] %s=%" PRIu64 "\n", name, value);
    fprintf(stderr, "[ia64-profile] %s.per_bundle=%.6f\n",
            name, per_bundle);
    fprintf(stderr, "[ia64-profile] %s.per_slot=%.6f\n", name, per_slot);
}

static void ia64_profile_print_percentiles(
    const char *name, const uint64_t histogram[IA64_PROFILE_GROUP_HIST_COUNT])
{
    static const unsigned percentile[] = { 50, 90, 95, 99 };
    uint64_t total = 0;

    for (unsigned i = 0; i < IA64_PROFILE_GROUP_HIST_COUNT; i++) {
        total += histogram[i];
    }
    for (unsigned p = 0; p < ARRAY_SIZE(percentile); p++) {
        uint64_t threshold = (total * percentile[p] + 99) / 100;
        uint64_t cumulative = 0;
        unsigned bucket = 0;

        for (; bucket < IA64_PROFILE_GROUP_HIST_COUNT; bucket++) {
            cumulative += histogram[bucket];
            if (cumulative >= threshold) {
                break;
            }
        }
        fprintf(stderr, "[ia64-profile] %s.p%u=%u%s\n", name,
                percentile[p], MIN(bucket, IA64_PROFILE_GROUP_HIST_MAX),
                bucket >= IA64_PROFILE_GROUP_HIST_MAX ? ".plus" : "");
    }
}

static void ia64_profile_dump(void)
{
    IA64ProductionProfile total = { 0 };
    IA64ProfileCodegenTotal codegen = { 0 };
    uint64_t elapsed_ns = 0;
    uint64_t shape_overflow = 0;
    uint64_t bundles;
    int64_t now = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);

    if (!ia64_profile_enabled_cached || ia64_profile_cpus == NULL) {
        return;
    }

    for (unsigned cpu_index = 0; cpu_index < ia64_profile_cpus->len;
         cpu_index++) {
        IA64CPU *cpu = g_ptr_array_index(ia64_profile_cpus, cpu_index);
        IA64ProductionProfile *profile = &cpu->production_profile;
        uint64_t cpu_elapsed_ns;
        long double weight = UINT64_C(1) << ia64_profile_shift;

        cpu_elapsed_ns = profile->wall_start_ns == 0 ? 0 :
                         now - profile->wall_start_ns;
        elapsed_ns += cpu_elapsed_ns;
        total.sample_windows += profile->sample_windows;

        for (unsigned i = 0; i < IA64_PROFILE_HELPER_COUNT; i++) {
            total.helper[i] +=
                ia64_profile_scaled(profile->helper[i], weight);
        }
        for (unsigned shape_slot = 0;
             shape_slot < ia64_profile_shape_count; shape_slot++) {
            const IA64ProfileShapeRecord *shape =
                &ia64_profile_shapes[shape_slot];
            uint64_t executions = profile->shape_exec[shape_slot];
            uint64_t weighted;
            unsigned bundles_in_tb;
            IA64ProfileCounter exit_counter;

            if (executions == 0) {
                continue;
            }
            if (shape_slot == IA64_PROFILE_SHAPE_OVERFLOW_SLOT) {
                shape_overflow += executions;
                continue;
            }
            total.sample_clock += executions;
            weighted = ia64_profile_scaled(executions, weight);
            total.counter[IA64_PROFILE_TB_EXECUTED] += weighted;
            exit_counter = shape->exit == IA64_PROFILE_EXIT_DIRECT ?
                               IA64_PROFILE_EXIT_DIRECT_CHAIN :
                           shape->exit == IA64_PROFILE_EXIT_LOOKUP ?
                               IA64_PROFILE_EXIT_LOOKUP_PTR :
                               IA64_PROFILE_EXIT_MAIN_LOOP;
            total.counter[exit_counter] += weighted;
            bundles_in_tb = MIN(
                shape->counter[IA64_PROFILE_BUNDLE_EXECUTED],
                IA64_PROFILE_MAX_TB_BUNDLES);
            total.tb_length[bundles_in_tb] += weighted;
            for (unsigned i = IA64_PROFILE_BUNDLE_EXECUTED;
                 i < IA64_PROFILE_COUNTER_COUNT; i++) {
                total.counter[i] +=
                    ia64_profile_scaled(shape->counter[i], weighted);
            }
            total.counter[IA64_PROFILE_STATE_CACHE_DIRTY_WRITEBACK] +=
                ia64_profile_scaled(shape->dirty, weighted);
            for (unsigned i = 0; i < IA64_PROFILE_GROUP_HIST_COUNT; i++) {
                codegen.group_length[i] +=
                    ia64_profile_scaled(shape->group_length[i], weighted);
                codegen.group_destination[i] += ia64_profile_scaled(
                    shape->group_destination[i], weighted);
            }
            if (shape->end_reason < IA64_PROFILE_TB_END_COUNT) {
                codegen.end_reason[shape->end_reason] += weighted;
            }
            ia64_profile_add_codegen_ops(codegen.generated,
                                         &shape->generated, weighted);
            ia64_profile_add_codegen_ops(codegen.optimized,
                                         &shape->optimized, weighted);
            codegen.host_bytes +=
                ia64_profile_scaled(shape->host_bytes, weighted);
            for (unsigned i = 0; i < ia64_profile_exact_helper_count; i++) {
                codegen.exact_helper[i] += ia64_profile_scaled(
                    shape->exact_helper[i], weighted);
            }
        }
    }

    bundles = total.counter[IA64_PROFILE_BUNDLE_EXECUTED];
    fprintf(stderr, "[ia64-profile] enabled=1\n");
    fprintf(stderr, "[ia64-profile] sample_shift=%u\n", ia64_profile_shift);
    fprintf(stderr, "[ia64-profile] sample_period=%" PRIu64 "\n",
            UINT64_C(1) << ia64_profile_shift);
    fprintf(stderr, "[ia64-profile] sample_interval_ns=%" PRIu64 "\n",
            IA64_PROFILE_SAMPLE_QUANTUM_NS << ia64_profile_shift);
    fprintf(stderr, "[ia64-profile] elapsed_ns=%" PRIu64 "\n", elapsed_ns);
    fprintf(stderr, "[ia64-profile] sample_tbs_per_window=1\n");
    fprintf(stderr, "[ia64-profile] sample_windows=%" PRIu64 "\n",
            total.sample_windows);
    fprintf(stderr, "[ia64-profile] effective_weight=%" PRIu64 "\n",
            UINT64_C(1) << ia64_profile_shift);
    fprintf(stderr, "[ia64-profile] tb.observed=%" PRIu64 "\n",
            total.sample_clock);
    if (shape_overflow != 0) {
        fprintf(stderr, "[ia64-profile] shape.overflow=%" PRIu64 "\n",
                shape_overflow);
    }
    for (unsigned i = 0; i < IA64_PROFILE_COUNTER_COUNT; i++) {
        g_assert(ia64_profile_counter_names[i] != NULL);
        ia64_profile_print_rate(ia64_profile_counter_names[i],
                                total.counter[i], bundles);
    }
    {
        uint64_t ordinary =
            total.counter[IA64_PROFILE_ORDINARY_NONMEMORY_SLOT];
        uint64_t fast =
            total.counter[IA64_PROFILE_ORDINARY_NONMEMORY_SHAPE_A_SLOT] +
            total.counter[IA64_PROFILE_ORDINARY_NONMEMORY_SHAPE_B_SLOT];

        fprintf(stderr,
                "[ia64-profile] ordinary_nonmemory.shape_ab.percent=%.6f\n",
                ordinary == 0 ? 0.0 : 100.0 * fast / ordinary);
    }
    for (unsigned i = 1; i < IA64_PROFILE_TB_LENGTH_COUNT; i++) {
        if (total.tb_length[i] != 0) {
            fprintf(stderr,
                    "[ia64-profile] tb.length.%u=%" PRIu64 "\n",
                    i, total.tb_length[i]);
        }
    }
    for (unsigned i = 0; i < IA64_PROFILE_GROUP_HIST_COUNT; i++) {
        if (codegen.group_length[i] != 0) {
            fprintf(stderr, "[ia64-profile] group.length.%u%s=%" PRIu64
                    "\n", i, i == IA64_PROFILE_GROUP_HIST_MAX ?
                    ".plus" : "", codegen.group_length[i]);
        }
        if (codegen.group_destination[i] != 0) {
            fprintf(stderr, "[ia64-profile] group.destinations.%u%s=%" PRIu64
                    "\n", i, i == IA64_PROFILE_GROUP_HIST_MAX ?
                    ".plus" : "", codegen.group_destination[i]);
        }
    }
    ia64_profile_print_percentiles("group.length", codegen.group_length);
    ia64_profile_print_percentiles("group.destinations",
                                   codegen.group_destination);
    for (unsigned i = 0; i < IA64_PROFILE_TB_END_COUNT; i++) {
        fprintf(stderr, "[ia64-profile] tb.end.%s=%" PRIu64 "\n",
                ia64_profile_tb_end_names[i], codegen.end_reason[i]);
    }
    {
        static const char * const generated_names[10] = {
            "codegen.generated.ops", "codegen.generated.env_load",
            "codegen.generated.env_store", "codegen.generated.branch",
            "codegen.generated.helper", "codegen.generated.qemu_load",
            "codegen.generated.qemu_store", "codegen.generated.goto_tb",
            "codegen.generated.goto_ptr", "codegen.generated.exit_tb",
        };
        static const char * const optimized_names[10] = {
            "codegen.optimized.ops", "codegen.optimized.env_load",
            "codegen.optimized.env_store", "codegen.optimized.branch",
            "codegen.optimized.helper", "codegen.optimized.qemu_load",
            "codegen.optimized.qemu_store", "codegen.optimized.goto_tb",
            "codegen.optimized.goto_ptr", "codegen.optimized.exit_tb",
        };
        uint64_t slots = total.counter[IA64_PROFILE_SLOT_EXECUTED];

        for (unsigned i = 0; i < ARRAY_SIZE(generated_names); i++) {
            ia64_profile_print_density(generated_names[i],
                                       codegen.generated[i], bundles, slots);
            ia64_profile_print_density(optimized_names[i],
                                       codegen.optimized[i], bundles, slots);
        }
        ia64_profile_print_density("codegen.host_bytes", codegen.host_bytes,
                                   bundles, slots);
    }
    for (unsigned i = 0; i < IA64_PROFILE_HELPER_COUNT; i++) {
        uint64_t value = total.helper[i];

        if (value != 0) {
            ia64_profile_print_rate(ia64_profile_helper_names[i], value,
                                    bundles);
        }
    }
    for (unsigned i = 0; i < ia64_profile_exact_helper_count; i++) {
        char *name = g_strdup_printf("helper.exact.%s",
                                     ia64_profile_exact_helper_names[i]);

        ia64_profile_print_rate(name, codegen.exact_helper[i], bundles);
        g_free(name);
    }
    /*
     * Preserve concrete high-density shapes, rather than only aggregate
     * means.  These are translation records weighted by sampled executions;
     * the source PC is diagnostic data, never an admission key.
     */
    {
        unsigned printed[32];

        for (unsigned rank = 0; rank < ARRAY_SIZE(printed); rank++) {
            uint64_t best_exec = 0;
            unsigned best_slot = IA64_PROFILE_SHAPE_OVERFLOW_SLOT;

            for (unsigned slot = 0; slot < ia64_profile_shape_count &&
                 slot < IA64_PROFILE_SHAPE_OVERFLOW_SLOT; slot++) {
                uint64_t executions = 0;
                bool already_printed = false;

                for (unsigned cpu_index = 0;
                     cpu_index < ia64_profile_cpus->len; cpu_index++) {
                    IA64CPU *cpu =
                        g_ptr_array_index(ia64_profile_cpus, cpu_index);

                    executions += cpu->production_profile.shape_exec[slot];
                }
                for (unsigned earlier = 0; earlier < rank; earlier++) {
                    if (printed[earlier] == slot) {
                        already_printed = true;
                        break;
                    }
                }
                if (!already_printed && executions > best_exec) {
                    best_exec = executions;
                    best_slot = slot;
                }
            }
            if (best_slot == IA64_PROFILE_SHAPE_OVERFLOW_SLOT ||
                best_exec == 0) {
                break;
            }
            printed[rank] = best_slot;
            {
                const IA64ProfileShapeRecord *shape =
                    &ia64_profile_shapes[best_slot];
                uint64_t weighted = ia64_profile_scaled(
                    best_exec, UINT64_C(1) << ia64_profile_shift);
                uint32_t overlay_save =
                    shape->counter[IA64_PROFILE_OVERLAY_SAVE_GR] +
                    shape->counter[IA64_PROFILE_OVERLAY_SAVE_NAT] +
                    shape->counter[IA64_PROFILE_OVERLAY_SAVE_PR] +
                    shape->counter[IA64_PROFILE_OVERLAY_SAVE_BR] +
                    shape->counter[IA64_PROFILE_OVERLAY_SAVE_PFS] +
                    shape->counter[IA64_PROFILE_OVERLAY_SAVE_AR] +
                    shape->counter[IA64_PROFILE_OVERLAY_SAVE_FR];

                fprintf(stderr,
                    "[ia64-profile] top.%u=pc:0x%016" PRIx64
                    ",flags:0x%08x,executions:%" PRIu64
                    ",bundles:%u,slots:%u,"
                    "generated:%u,optimized:%u,host_bytes:%u,"
                    "generated_env_load:%u,generated_env_store:%u,"
                    "generated_branch:%u,generated_helper:%u,"
                    "generated_qemu_load:%u,generated_qemu_store:%u,"
                    "env_load:%u,env_store:%u,branch:%u,helper:%u,"
                    "qemu_load:%u,qemu_store:%u,"
                    "arch_load:%u,arch_store:%u,overlay_save:%u,"
                    "overlay_validity:%u,overlay_clear:%u,"
                    "durable_materialization:%u,durable_bytes:%u,"
                    "integer:%u,predicate:%u,"
                    "branch_slots:%u,memory:%u,loop:%u,end:%s\n",
                    rank + 1, shape->pc, shape->flags, weighted,
                    shape->counter[IA64_PROFILE_BUNDLE_EXECUTED],
                    shape->counter[IA64_PROFILE_SLOT_EXECUTED],
                    shape->generated.total, shape->optimized.total,
                    shape->host_bytes,
                    shape->generated.env_load, shape->generated.env_store,
                    shape->generated.conditional_branch,
                    shape->generated.helper_call,
                    shape->generated.qemu_load,
                    shape->generated.qemu_store,
                    shape->optimized.env_load,
                    shape->optimized.env_store,
                    shape->optimized.conditional_branch,
                    shape->optimized.helper_call, shape->optimized.qemu_load,
                    shape->optimized.qemu_store,
                    shape->counter[IA64_PROFILE_ARCH_LOAD],
                    shape->counter[IA64_PROFILE_ARCH_STORE], overlay_save,
                    shape->counter[IA64_PROFILE_OVERLAY_VALIDITY_LOAD] +
                        shape->counter[IA64_PROFILE_OVERLAY_VALIDITY_BRANCH],
                    shape->counter[IA64_PROFILE_OVERLAY_CLEAR],
                    shape->counter[IA64_PROFILE_DURABLE_MATERIALIZATION],
                    shape->counter[IA64_PROFILE_DURABLE_BYTES],
                    shape->counter[IA64_PROFILE_COMMON_INTEGER_SLOT],
                    shape->counter[IA64_PROFILE_COMMON_PREDICATE_SLOT],
                    shape->counter[IA64_PROFILE_COMMON_BRANCH_SLOT],
                    shape->counter[IA64_PROFILE_COMMON_MEMORY_SLOT],
                    shape->counter[IA64_PROFILE_COMMON_LOOP_SLOT],
                        shape->end_reason < IA64_PROFILE_TB_END_COUNT ?
                            ia64_profile_tb_end_names[shape->end_reason] :
                            "invalid");
                for (unsigned helper = 0;
                     helper < ia64_profile_exact_helper_count; helper++) {
                    if (shape->exact_helper[helper] != 0) {
                        fprintf(stderr,
                                "[ia64-profile] top.%u.helper.%s=%u\n",
                                rank + 1,
                                ia64_profile_exact_helper_names[helper],
                                shape->exact_helper[helper]);
                    }
                }
            }
        }
    }
}

bool ia64_profile_init_enabled(void)
{
    const char *value = g_getenv("VIBTANIUM_IA64_PROD_PROFILE");
    const char *shift_value;
    const char *end = NULL;
    unsigned long parsed = 11;

    ia64_profile_enabled_cached = value != NULL && *value != '\0' &&
        strcmp(value, "0") != 0 &&
        g_ascii_strcasecmp(value, "off") != 0 &&
        g_ascii_strcasecmp(value, "false") != 0;
    if (!ia64_profile_enabled_cached) {
        return false;
    }

    shift_value = g_getenv("VIBTANIUM_IA64_PROFILE_SAMPLE_SHIFT");
    if (shift_value != NULL &&
        qemu_strtoul(shift_value, &end, 0, &parsed) == 0 && *end == '\0') {
        ia64_profile_shift = MIN(parsed, 20ul);
    }
    if (!ia64_profile_registered) {
        ia64_profile_cpus = g_ptr_array_new();
        ia64_profile_normal_code = g_array_new(
            false, true, sizeof(IA64ProfileCodeRecord));
        atexit(ia64_profile_dump);
        ia64_profile_registered = true;
    }
    return true;
}

unsigned ia64_profile_sample_shift(void)
{
    ia64_profile_init_enabled();
    return ia64_profile_shift;
}

void ia64_profile_register_cpu(struct ArchCPU *cpu)
{
    if (ia64_profile_enabled()) {
        IA64ProductionProfile *profile = &cpu->production_profile;
        const char *autostart;
        bool start;

        g_ptr_array_add(ia64_profile_cpus, cpu);
        profile->sample_timer = timer_new_ns(QEMU_CLOCK_REALTIME,
                                             ia64_profile_sample_timer, cpu);
        autostart = g_getenv("VIBTANIUM_IA64_PROFILE_AUTOSTART");
        start = autostart == NULL ||
                (*autostart != '\0' && strcmp(autostart, "0") != 0 &&
                 g_ascii_strcasecmp(autostart, "off") != 0 &&
                 g_ascii_strcasecmp(autostart, "false") != 0);
        if (start) {
            ia64_profile_set_active(cpu, true);
        }
    }
}

bool ia64_profile_get_active(struct ArchCPU *cpu)
{
    return cpu->production_profile.active;
}

void ia64_profile_set_active(struct ArchCPU *cpu, bool active)
{
    IA64ProductionProfile *profile = &cpu->production_profile;

    profile->requested = active;
    if (!ia64_profile_enabled() || profile->active == active) {
        return;
    }
    if (!active) {
        profile->active = false;
        qatomic_set(&profile->collecting, 0);
        timer_del(profile->sample_timer);
        return;
    }

    profile->sample_clock = 0;
    memset(profile->counter, 0, sizeof(profile->counter));
    memset(profile->tb_length, 0, sizeof(profile->tb_length));
    memset(profile->helper, 0, sizeof(profile->helper));
    memset(profile->shape_exec, 0, sizeof(profile->shape_exec));
    profile->sample_windows = 0;
    profile->wall_start_ns = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
    profile->active = true;
    if (ia64_profile_sample_shift() == 0) {
        qatomic_set(&profile->collecting, 1);
    } else {
        qatomic_set(&profile->collecting, 0);
        timer_mod_ns(profile->sample_timer,
                     profile->wall_start_ns + IA64_PROFILE_INITIAL_DELAY_NS);
    }
}

unsigned ia64_profile_register_tb_shape(
    uint64_t pc, uint32_t flags,
    const uint32_t *counter, const uint32_t *group_length,
    const uint32_t *group_destination, uint32_t dirty,
    IA64ProfileExit exit, IA64ProfileTbEnd end_reason)
{
    IA64ProfileShapeRecord *shape;
    unsigned shape_slot;

    G_LOCK(ia64_profile_shape_map);
    if (ia64_profile_shape_count >= IA64_PROFILE_SHAPE_OVERFLOW_SLOT) {
        ia64_profile_shape_count = IA64_PROFILE_SHAPE_SLOTS;
        G_UNLOCK(ia64_profile_shape_map);
        return IA64_PROFILE_SHAPE_OVERFLOW_SLOT;
    }
    shape_slot = ia64_profile_shape_count++;
    shape = &ia64_profile_shapes[shape_slot];
    shape->pc = pc;
    shape->flags = flags & ~IA64_TB_FLAG_PROFILE;
    memcpy(shape->counter, counter, sizeof(shape->counter));
    memcpy(shape->group_length, group_length, sizeof(shape->group_length));
    memcpy(shape->group_destination, group_destination,
           sizeof(shape->group_destination));
    shape->dirty = dirty;
    shape->exit = exit;
    shape->end_reason = end_reason;
    for (unsigned i = 0;
         ia64_profile_normal_code != NULL &&
         i < ia64_profile_normal_code->len; i++) {
        const IA64ProfileCodeRecord *code = &g_array_index(
            ia64_profile_normal_code, IA64ProfileCodeRecord, i);

        if (code->pc == shape->pc && code->flags == shape->flags) {
            shape->generated = code->stats.generated;
            shape->optimized = code->stats.optimized;
            shape->host_bytes = code->stats.host_bytes;
            for (unsigned helper = 0; helper < code->stats.helper_count;
                 helper++) {
                int id = ia64_profile_exact_helper_id(
                    code->stats.helper[helper].name);

                if (id >= 0) {
                    shape->exact_helper[id] +=
                        code->stats.helper[helper].calls;
                }
            }
            break;
        }
    }
    G_UNLOCK(ia64_profile_shape_map);
    return shape_slot;
}

static int ia64_profile_exact_helper_id(const char *name)
{
    for (unsigned i = 0; i < ia64_profile_exact_helper_count; i++) {
        if (ia64_profile_exact_helper_names[i] == name ||
            strcmp(ia64_profile_exact_helper_names[i], name) == 0) {
            return i;
        }
    }
    if (ia64_profile_exact_helper_count >= IA64_PROFILE_EXACT_HELPERS) {
        return -1;
    }
    ia64_profile_exact_helper_names[ia64_profile_exact_helper_count] = name;
    return ia64_profile_exact_helper_count++;
}

void ia64_profile_codegen_complete(const TranslationBlock *tb,
                                   const TCGCodegenStats *stats)
{
    IA64ProfileCodeRecord *code = NULL;
    uint32_t flags;

    if (stats == NULL || tb == NULL ||
        (tb->flags & IA64_TB_FLAG_PROFILE) != 0) {
        return;
    }

    flags = tb->flags & ~IA64_TB_FLAG_PROFILE;
    G_LOCK(ia64_profile_shape_map);
    for (unsigned i = 0;
         ia64_profile_normal_code != NULL &&
         i < ia64_profile_normal_code->len; i++) {
        IA64ProfileCodeRecord *candidate = &g_array_index(
            ia64_profile_normal_code, IA64ProfileCodeRecord, i);

        if (candidate->pc == tb->pc && candidate->flags == flags) {
            code = candidate;
            break;
        }
    }
    if (code == NULL && ia64_profile_normal_code != NULL &&
        ia64_profile_normal_code->len < IA64_PROFILE_SHAPE_SLOTS) {
        IA64ProfileCodeRecord new_code = { 0 };

        g_array_append_val(ia64_profile_normal_code, new_code);
        code = &g_array_index(ia64_profile_normal_code,
                              IA64ProfileCodeRecord,
                              ia64_profile_normal_code->len - 1);
        code->pc = tb->pc;
        code->flags = flags;
    }
    if (code != NULL) {
        code->stats = *stats;
    }
    for (unsigned slot = 0; slot < ia64_profile_shape_count &&
         slot < IA64_PROFILE_SHAPE_OVERFLOW_SLOT; slot++) {
        IA64ProfileShapeRecord *shape = &ia64_profile_shapes[slot];

        if (shape->pc != tb->pc || shape->flags != flags) {
            continue;
        }
        shape->generated = stats->generated;
        shape->optimized = stats->optimized;
        shape->host_bytes = stats->host_bytes;
        memset(shape->exact_helper, 0, sizeof(shape->exact_helper));
        for (unsigned i = 0; i < stats->helper_count; i++) {
            int id = ia64_profile_exact_helper_id(stats->helper[i].name);

            if (id >= 0) {
                shape->exact_helper[id] += stats->helper[i].calls;
            }
        }
    }
    G_UNLOCK(ia64_profile_shape_map);
}

void ia64_profile_count_helper(CPUIA64State *env,
                               IA64ProfileHelperFamily family)
{
    IA64ProductionProfile *profile = &env_archcpu(env)->production_profile;

    if (qatomic_read(&profile->collecting) &&
        family < IA64_PROFILE_HELPER_COUNT) {
        qatomic_inc(&profile->helper[family]);
    }
}

#endif /* CONFIG_IA64_OBSERVABILITY */
