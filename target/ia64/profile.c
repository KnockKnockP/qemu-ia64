/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "qemu/atomic.h"
#include "qemu/cutils.h"
#include "cpu.h"
#include "profile.h"

#define IA64_PROFILE_SAMPLE_QUANTUM_NS INT64_C(10000)
#define IA64_PROFILE_INITIAL_DELAY_NS INT64_C(100000000)

int ia64_profile_enabled_cached = -1;

static unsigned ia64_profile_shift = 11;
static bool ia64_profile_registered;
static GPtrArray *ia64_profile_cpus;

typedef struct IA64ProfileShapeRecord {
    uint32_t counter[IA64_PROFILE_COUNTER_COUNT];
    uint32_t dirty;
    uint8_t exit;
} IA64ProfileShapeRecord;

static IA64ProfileShapeRecord
    ia64_profile_shapes[IA64_PROFILE_SHAPE_SLOTS];
static unsigned ia64_profile_shape_count;
G_LOCK_DEFINE_STATIC(ia64_profile_shape_map);

static const char * const ia64_profile_counter_names[] = {
    [IA64_PROFILE_TB_EXECUTED] = "tb.executed",
    [IA64_PROFILE_BUNDLE_EXECUTED] = "bundle.executed",
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

static void ia64_profile_dump(void)
{
    IA64ProductionProfile total = { 0 };
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
                total.counter[i] += ia64_profile_scaled(
                    executions * shape->counter[i], weight);
            }
            total.counter[IA64_PROFILE_STATE_CACHE_DIRTY_WRITEBACK] +=
                ia64_profile_scaled(executions * shape->dirty, weight);
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
        if (total.counter[i] != 0) {
            ia64_profile_print_rate(ia64_profile_counter_names[i],
                                    total.counter[i], bundles);
        }
    }
    for (unsigned i = 1; i < IA64_PROFILE_TB_LENGTH_COUNT; i++) {
        if (total.tb_length[i] != 0) {
            fprintf(stderr,
                    "[ia64-profile] tb.length.%u=%" PRIu64 "\n",
                    i, total.tb_length[i]);
        }
    }
    for (unsigned i = 0; i < IA64_PROFILE_HELPER_COUNT; i++) {
        uint64_t value = total.helper[i];

        if (value != 0) {
            ia64_profile_print_rate(ia64_profile_helper_names[i], value,
                                    bundles);
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
    const uint32_t *counter, uint32_t dirty, IA64ProfileExit exit)
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
    memcpy(shape->counter, counter, sizeof(shape->counter));
    shape->dirty = dirty;
    shape->exit = exit;
    G_UNLOCK(ia64_profile_shape_map);
    return shape_slot;
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
