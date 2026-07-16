/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IA64_PROFILE_H
#define IA64_PROFILE_H

#include "qemu/timer.h"

#define IA64_PROFILE_MAX_TB_BUNDLES 256
#define IA64_PROFILE_TB_LENGTH_COUNT (IA64_PROFILE_MAX_TB_BUNDLES + 1)
#define IA64_PROFILE_SHAPE_SLOTS 16384
#define IA64_PROFILE_SHAPE_OVERFLOW_SLOT (IA64_PROFILE_SHAPE_SLOTS - 1)

typedef enum IA64ProfileCounter {
    IA64_PROFILE_TB_EXECUTED,
    IA64_PROFILE_BUNDLE_EXECUTED,
    IA64_PROFILE_BUNDLE_ZERO_HELPER,
    IA64_PROFILE_BRANCH_INLINE_DIRECT,
    IA64_PROFILE_BRANCH_INLINE_INDIRECT,
    IA64_PROFILE_EXIT_DIRECT_CHAIN,
    IA64_PROFILE_EXIT_LOOKUP_PTR,
    IA64_PROFILE_EXIT_MAIN_LOOP,
    IA64_PROFILE_STATE_CACHE_ACTIVE_BUNDLE,
    IA64_PROFILE_STATE_CACHE_HIT,
    IA64_PROFILE_STATE_CACHE_DIRTY_WRITEBACK,
    IA64_PROFILE_COUNTER_COUNT,
} IA64ProfileCounter;

typedef enum IA64ProfileExit {
    IA64_PROFILE_EXIT_DIRECT,
    IA64_PROFILE_EXIT_LOOKUP,
    IA64_PROFILE_EXIT_MAIN,
} IA64ProfileExit;

typedef enum IA64ProfileHelperFamily {
    IA64_PROFILE_HELPER_RSE,
    IA64_PROFILE_HELPER_NAT_ALAT,
    IA64_PROFILE_HELPER_OTHER,
    IA64_PROFILE_HELPER_COUNT,
} IA64ProfileHelperFamily;

typedef struct IA64ProductionProfile {
    uint64_t sample_clock;
    uint64_t counter[IA64_PROFILE_COUNTER_COUNT];
    uint64_t tb_length[IA64_PROFILE_TB_LENGTH_COUNT];
    uint64_t helper[IA64_PROFILE_HELPER_COUNT];
    uint64_t shape_exec[IA64_PROFILE_SHAPE_SLOTS];
    QEMUTimer *sample_timer;
    int64_t wall_start_ns;
    uint64_t sample_windows;
    bool requested;
    bool active;
    uint8_t collecting;
} IA64ProductionProfile;

extern int ia64_profile_enabled_cached;

bool ia64_profile_init_enabled(void);
unsigned ia64_profile_sample_shift(void);
void ia64_profile_register_cpu(struct ArchCPU *cpu);
bool ia64_profile_get_active(struct ArchCPU *cpu);
void ia64_profile_set_active(struct ArchCPU *cpu, bool active);
unsigned ia64_profile_register_tb_shape(
    const uint32_t *counter, uint32_t dirty, IA64ProfileExit exit);
void ia64_profile_count_helper(struct CPUArchState *env,
                               IA64ProfileHelperFamily family);

static inline bool ia64_profile_enabled(void)
{
    if (ia64_profile_enabled_cached < 0) {
        return ia64_profile_init_enabled();
    }
    return ia64_profile_enabled_cached != 0;
}

#define IA64_PROFILE_HELPER(family) \
    do { \
        if (unlikely(ia64_profile_enabled())) { \
            ia64_profile_count_helper(env, family); \
        } \
    } while (0)

#endif
