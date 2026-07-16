/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IA64_PROFILE_H
#define IA64_PROFILE_H

#include "qemu/timer.h"

#define IA64_PROFILE_MAX_TB_BUNDLES 256
#define IA64_PROFILE_TB_LENGTH_COUNT (IA64_PROFILE_MAX_TB_BUNDLES + 1)
#define IA64_PROFILE_SHAPE_SLOTS 16384
#define IA64_PROFILE_SHAPE_OVERFLOW_SLOT (IA64_PROFILE_SHAPE_SLOTS - 1)
#define IA64_PROFILE_GROUP_HIST_MAX 64
#define IA64_PROFILE_GROUP_HIST_COUNT (IA64_PROFILE_GROUP_HIST_MAX + 1)
#define IA64_PROFILE_EXACT_HELPERS 256

typedef enum IA64ProfileCounter {
    IA64_PROFILE_TB_EXECUTED,
    IA64_PROFILE_BUNDLE_EXECUTED,
    IA64_PROFILE_SLOT_EXECUTED,
    IA64_PROFILE_BUNDLE_ZERO_HELPER,
    IA64_PROFILE_BRANCH_INLINE_DIRECT,
    IA64_PROFILE_BRANCH_INLINE_INDIRECT,
    IA64_PROFILE_EXIT_DIRECT_CHAIN,
    IA64_PROFILE_EXIT_LOOKUP_PTR,
    IA64_PROFILE_EXIT_MAIN_LOOP,
    IA64_PROFILE_STATE_CACHE_ACTIVE_BUNDLE,
    IA64_PROFILE_STATE_CACHE_HIT,
    IA64_PROFILE_STATE_CACHE_DIRTY_WRITEBACK,
    IA64_PROFILE_SHAPE_A_GROUP,
    IA64_PROFILE_SHAPE_A_SLOT,
    IA64_PROFILE_SHAPE_B_GROUP,
    IA64_PROFILE_SHAPE_B_SLOT,
    IA64_PROFILE_SHAPE_C_GROUP,
    IA64_PROFILE_SHAPE_C_SLOT,
    IA64_PROFILE_SHAPE_C_OPEN_TB,
    IA64_PROFILE_SHAPE_C_PAGE,
    IA64_PROFILE_SHAPE_C_RSE,
    IA64_PROFILE_SHAPE_C_SYSTEM,
    IA64_PROFILE_SHAPE_C_OBSERVATION,
    IA64_PROFILE_SHAPE_C_OTHER,
    IA64_PROFILE_GROUP_TB_CROSSING,
    IA64_PROFILE_GROUP_PAGE_CROSSING,
    IA64_PROFILE_GROUP_SAFEPOINT,
    IA64_PROFILE_OVERLAY_SAVE_GR,
    IA64_PROFILE_OVERLAY_SAVE_NAT,
    IA64_PROFILE_OVERLAY_SAVE_PR,
    IA64_PROFILE_OVERLAY_SAVE_BR,
    IA64_PROFILE_OVERLAY_SAVE_PFS,
    IA64_PROFILE_OVERLAY_SAVE_AR,
    IA64_PROFILE_OVERLAY_SAVE_FR,
    IA64_PROFILE_OVERLAY_VALIDITY_LOAD,
    IA64_PROFILE_OVERLAY_VALIDITY_BRANCH,
    IA64_PROFILE_OVERLAY_CLEAR,
    IA64_PROFILE_STAGED_WRITE,
    IA64_PROFILE_FINAL_COMMIT,
    IA64_PROFILE_DURABLE_MATERIALIZATION,
    IA64_PROFILE_DURABLE_BYTES,
    IA64_PROFILE_ARCH_LOAD,
    IA64_PROFILE_ARCH_STORE,
    IA64_PROFILE_SYNC_HELPER,
    IA64_PROFILE_SYNC_FAULT,
    IA64_PROFILE_SYNC_EXIT,
    IA64_PROFILE_RESIDENT_LOAD,
    IA64_PROFILE_RESIDENT_HIT,
    IA64_PROFILE_RESIDENT_SPILL,
    IA64_PROFILE_RESIDENT_WRITEBACK,
    IA64_PROFILE_RESIDENT_SYNC,
    IA64_PROFILE_NAT_KNOWN_CLEAR,
    IA64_PROFILE_NAT_KNOWN_SET,
    IA64_PROFILE_NAT_UNKNOWN,
    IA64_PROFILE_NAT_DYNAMIC_LOAD,
    IA64_PROFILE_NAT_DYNAMIC_BRANCH,
    IA64_PROFILE_NAT_FAULT,
    IA64_PROFILE_NAT_LATTICE_INVALIDATE,
    IA64_PROFILE_NAT_RSE_UNKNOWN,
    IA64_PROFILE_ALAT_EMPTY_TB,
    IA64_PROFILE_ALAT_EMPTY_BUNDLE,
    IA64_PROFILE_ALAT_ACTIVE_TB,
    IA64_PROFILE_ALAT_ACTIVE_BUNDLE,
    IA64_PROFILE_COMMON_INTEGER_SLOT,
    IA64_PROFILE_COMMON_PREDICATE_SLOT,
    IA64_PROFILE_COMMON_BRANCH_SLOT,
    IA64_PROFILE_COMMON_MEMORY_SLOT,
    IA64_PROFILE_COMMON_LOOP_SLOT,
    IA64_PROFILE_LOOP_RECOGNIZED,
    IA64_PROFILE_LOOP_REJECT_NOT_SELF,
    IA64_PROFILE_LOOP_REJECT_OBSERVATION,
    IA64_PROFILE_LOOP_REJECT_BODY,
    IA64_PROFILE_LOOP_INTERNAL_ITERATION,
    IA64_PROFILE_LOOP_BUDGET_EXIT,
    IA64_PROFILE_LOOP_ASYNC_EXIT,
    IA64_PROFILE_LOOP_ZERO_STORE,
    IA64_PROFILE_LOOP_BULK_ZERO_BYTES,
    IA64_PROFILE_LOOP_SLOW_FALLBACK,
    IA64_PROFILE_COUNTER_COUNT,
} IA64ProfileCounter;

typedef enum IA64ProfileExit {
    IA64_PROFILE_EXIT_DIRECT,
    IA64_PROFILE_EXIT_LOOKUP,
    IA64_PROFILE_EXIT_MAIN,
} IA64ProfileExit;

typedef enum IA64ProfileTbEnd {
    IA64_PROFILE_TB_END_MEMORY,
    IA64_PROFILE_TB_END_BRANCH,
    IA64_PROFILE_TB_END_PAGE,
    IA64_PROFILE_TB_END_OP_BUDGET,
    IA64_PROFILE_TB_END_HELPER,
    IA64_PROFILE_TB_END_EVENT,
    IA64_PROFILE_TB_END_OTHER,
    IA64_PROFILE_TB_END_COUNT,
} IA64ProfileTbEnd;

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

typedef struct TCGCodegenStats TCGCodegenStats;
typedef struct TranslationBlock TranslationBlock;

#ifdef CONFIG_IA64_OBSERVABILITY
extern int ia64_profile_enabled_cached;
bool ia64_profile_init_enabled(void);
unsigned ia64_profile_sample_shift(void);
void ia64_profile_register_cpu(struct ArchCPU *cpu);
bool ia64_profile_get_active(struct ArchCPU *cpu);
void ia64_profile_set_active(struct ArchCPU *cpu, bool active);
unsigned ia64_profile_register_tb_shape(
    uint64_t pc, uint32_t flags,
    const uint32_t *counter, const uint32_t *group_length,
    const uint32_t *group_destination, uint32_t dirty,
    IA64ProfileExit exit, IA64ProfileTbEnd end_reason);
void ia64_profile_codegen_complete(const TranslationBlock *tb,
                                   const TCGCodegenStats *stats);
void ia64_profile_count_helper(struct CPUArchState *env,
                               IA64ProfileHelperFamily family);

static inline bool ia64_profile_enabled(void)
{
    if (ia64_profile_enabled_cached < 0) {
        return ia64_profile_init_enabled();
    }
    return ia64_profile_enabled_cached != 0;
}
#else
static inline bool ia64_profile_init_enabled(void)
{
    return false;
}
static inline unsigned ia64_profile_sample_shift(void)
{
    return 0;
}
static inline void ia64_profile_register_cpu(struct ArchCPU *cpu)
{
    (void)cpu;
}
static inline bool ia64_profile_get_active(struct ArchCPU *cpu)
{
    (void)cpu;
    return false;
}
static inline void ia64_profile_set_active(struct ArchCPU *cpu, bool active)
{
    (void)cpu;
    (void)active;
}
static inline unsigned ia64_profile_register_tb_shape(
    uint64_t pc, uint32_t flags,
    const uint32_t *counter, const uint32_t *group_length,
    const uint32_t *group_destination, uint32_t dirty,
    IA64ProfileExit exit, IA64ProfileTbEnd end_reason)
{
    (void)pc;
    (void)flags;
    (void)counter;
    (void)group_length;
    (void)group_destination;
    (void)dirty;
    (void)exit;
    (void)end_reason;
    return 0;
}
static inline void ia64_profile_codegen_complete(const TranslationBlock *tb,
                                                 const TCGCodegenStats *stats)
{
    (void)tb;
    (void)stats;
}
static inline void ia64_profile_count_helper(struct CPUArchState *env,
                                             IA64ProfileHelperFamily family)
{
    (void)env;
    (void)family;
}
static inline bool ia64_profile_enabled(void)
{
    return false;
}
#endif

#ifdef CONFIG_IA64_OBSERVABILITY
#define IA64_PROFILE_HELPER(family) \
    do { \
        if (unlikely(ia64_profile_enabled())) { \
            ia64_profile_count_helper(env, family); \
        } \
    } while (0)
#else
#define IA64_PROFILE_HELPER(family) do { (void)(family); } while (0)
#endif

#endif
