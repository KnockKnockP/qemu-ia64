/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "cpu.h"
#include "bundle.h"
#include "debug-trace.h"
#include "insn.h"
#include "exec/helper-proto.h"
#include "exec/helper-gen.h"
#include "exec/memop.h"
#include "exec/target_page.h"
#include "exec/translation-block.h"
#include "exec/translator.h"
#include "firmware.h"
#include "hw/core/cpu.h"
#include "mem.h"
#include "perf.h"
#include "tcg-classify.h"
#include "tcg/tcg-op.h"
#include "trace-target_ia64.h"

#define HELPER_H "helper.h"
#include "exec/helper-info.c.inc"
#undef HELPER_H

typedef struct IA64ProfileTbShape {
    uint32_t counter[IA64_PROFILE_COUNTER_COUNT];
    IA64ProfileShapeFamily family[IA64_PROFILE_MAX_SHAPE_FAMILIES];
    uint8_t family_count;
} IA64ProfileTbShape;

typedef struct DisasContext {
    DisasContextBase base;
    CPUIA64State *env;
    TCGv_i32 fast_bundle_ticks;
    TCGv_i32 stacked_frame_base;
    TCGv_ptr stacked_gr_base;
    TCGv_ptr stacked_nat_base;
    TCGv_i64 static_gr[IA64_STATIC_GR_COUNT];
    TCGv_i64 br[IA64_BR_COUNT];
    TCGv_i64 ar[IA64_AR_COUNT];
    TCGv_i64 pr;
    TCGv_i64 gr_nat;
    uint32_t static_gr_selected;
    uint32_t static_gr_valid;
    uint32_t static_gr_dirty;
    uint8_t br_valid;
    uint8_t br_dirty;
    uint64_t ar_valid[2];
    uint64_t ar_dirty[2];
    uint8_t static_gr_selected_count;
    bool stacked_frame_base_loaded;
    bool fast_bundle_ticks_used;
    bool inline_gr_nat_clear;
    bool state_cache_available;
    bool state_cache_active;
    bool pr_valid;
    bool pr_dirty;
    bool gr_nat_valid;
    bool gr_nat_dirty;
    bool profile_enabled;
    uint8_t region_branch_count;
    IA64ProfileTbShape profile_shape;
} DisasContext;

typedef struct IA64TrStateCacheDirty {
    uint32_t static_gr;
    uint8_t br;
    uint64_t ar[2];
    bool pr;
    bool gr_nat;
} IA64TrStateCacheDirty;

#define DISAS_EXIT DISAS_TARGET_0

#define IA64_CPU_STATE_OFFSET(field) \
    ((intptr_t)offsetof(IA64CPU, parent_obj) + \
     (intptr_t)offsetof(CPUState, field) - \
     (intptr_t)offsetof(IA64CPU, env))
#define IA64_CPU_OFFSET(field) \
    ((intptr_t)offsetof(IA64CPU, field) - \
     (intptr_t)offsetof(IA64CPU, env))

#define IA64_TR_PFS_CFM_MASK UINT64_C(0x0000003fffffffff)
#define IA64_TR_PFS_PEC_SHIFT 52
#define IA64_TR_PFS_PPL_SHIFT 62

static TCGv_i64 cpu_ip;

static bool ia64_tr_use_zero_helper_path(void);

static void ia64_tr_profile_add(DisasContext *ctx,
                                IA64ProfileCounter counter,
                                uint32_t value)
{
    if (ctx->profile_enabled) {
        ctx->profile_shape.counter[counter] += value;
    }
}

static void ia64_tr_profile_add_family(DisasContext *ctx,
                                       IA64ProfileFamilyKind kind,
                                       IA64SlotType type, uint64_t raw)
{
    IA64ProfileTbShape *shape = &ctx->profile_shape;
    uint16_t key;

    if (!ctx->profile_enabled) {
        return;
    }
    key = ia64_profile_family_key(type, raw);
    for (unsigned i = 0; i < shape->family_count; i++) {
        if (shape->family[i].kind == kind && shape->family[i].key == key) {
            shape->family[i].count++;
            return;
        }
    }
    if (shape->family_count < IA64_PROFILE_MAX_SHAPE_FAMILIES) {
        IA64ProfileShapeFamily *family =
            &shape->family[shape->family_count++];

        family->kind = kind;
        family->key = key;
        family->count = 1;
    }
}

static uint32_t ia64_tr_profile_dirty_count(DisasContext *ctx)
{
    return ctpop32(ctx->static_gr_dirty) + ctpop32(ctx->br_dirty) +
           ctpop64(ctx->ar_dirty[0]) + ctpop64(ctx->ar_dirty[1]) +
           ctx->pr_dirty + ctx->gr_nat_dirty;
}

static void ia64_tr_profile_add_runtime_counter(intptr_t offset,
                                                uint64_t value)
{
    TCGv_i64 counter = tcg_temp_new_i64();

    tcg_gen_ld_i64(counter, tcg_env, offset);
    tcg_gen_addi_i64(counter, counter, value);
    tcg_gen_st_i64(counter, tcg_env, offset);
}

static void ia64_tr_profile_emit(DisasContext *ctx, IA64ProfileExit exit)
{
    IA64ProfileTbShape *shape = &ctx->profile_shape;
    unsigned shape_slot;

    if (!ctx->profile_enabled) {
        return;
    }
    shape_slot = ia64_profile_register_tb_shape(
        shape->counter, shape->family, shape->family_count,
        ia64_tr_profile_dirty_count(ctx), exit);
    ia64_tr_profile_add_runtime_counter(
        IA64_CPU_OFFSET(production_profile.shape_exec[shape_slot]), 1);
    if (ia64_profile_sample_shift() != 0) {
        tcg_gen_st8_i32(
            tcg_constant_i32(0), tcg_env,
            IA64_CPU_OFFSET(production_profile.collecting));
        tcg_gen_exit_tb(NULL, 0);
    }
}

static IA64ProfileCounter ia64_tr_profile_branch_reject_counter(
    IA64TcgBranchReject reject)
{
    static const IA64ProfileCounter counters[] = {
        [IA64_TCG_BRANCH_REJECT_NOT_SLOT2] =
            IA64_PROFILE_BRANCH_REJECT_NOT_SLOT2,
        [IA64_TCG_BRANCH_REJECT_UNSUPPORTED_TYPE] =
            IA64_PROFILE_BRANCH_REJECT_UNSUPPORTED_TYPE,
        [IA64_TCG_BRANCH_REJECT_PREFIX_UNSUPPORTED] =
            IA64_PROFILE_BRANCH_REJECT_PREFIX_UNSUPPORTED,
        [IA64_TCG_BRANCH_REJECT_PREFIX_LDST_DEPENDENCY] =
            IA64_PROFILE_BRANCH_REJECT_PREFIX_LDST_DEPENDENCY,
        [IA64_TCG_BRANCH_REJECT_CROSS_PAGE] =
            IA64_PROFILE_BRANCH_REJECT_CROSS_PAGE,
        [IA64_TCG_BRANCH_REJECT_ROTATING_PREDICATE] =
            IA64_PROFILE_BRANCH_REJECT_ROTATING_PREDICATE,
        [IA64_TCG_BRANCH_REJECT_INDIRECT_UNSUPPORTED] =
            IA64_PROFILE_BRANCH_REJECT_INDIRECT_UNSUPPORTED,
        [IA64_TCG_BRANCH_REJECT_MULTIPLE_BRANCH] =
            IA64_PROFILE_BRANCH_REJECT_MULTIPLE_BRANCH,
    };

    if (reject <= IA64_TCG_BRANCH_REJECT_NONE ||
        reject >= IA64_TCG_BRANCH_REJECT_COUNT) {
        return IA64_PROFILE_BRANCH_REJECT_UNSUPPORTED_TYPE;
    }
    return counters[reject];
}

static bool ia64_tr_state_cache_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        const char *value = g_getenv("VIBTANIUM_TCG_STATE_CACHE");

        enabled = value != NULL &&
                  !(strcmp(value, "0") == 0 ||
                    g_ascii_strcasecmp(value, "off") == 0 ||
                    g_ascii_strcasecmp(value, "false") == 0);
    }
    return enabled;
}

static unsigned ia64_tr_state_cache_gr_limit(void)
{
    static int limit = -1;

    if (limit < 0) {
        const char *value = g_getenv("VIBTANIUM_TCG_STATE_CACHE_GRS");
        const char *end = NULL;
        unsigned long parsed = 4;

        limit = value != NULL &&
                qemu_strtoul(value, &end, 0, &parsed) == 0 && *end == '\0'
            ? MIN(parsed, IA64_STATIC_GR_COUNT - 1)
            : 4;
    }
    return limit;
}

static unsigned ia64_tr_state_cache_min_bundles(void)
{
    static int minimum = -1;

    if (minimum < 0) {
        const char *value = g_getenv("VIBTANIUM_TCG_STATE_CACHE_MIN_BUNDLES");
        const char *end = NULL;
        unsigned long parsed = 12;

        minimum = value != NULL &&
                  qemu_strtoul(value, &end, 0, &parsed) == 0 && *end == '\0'
            ? MIN(parsed, (unsigned long)TCG_MAX_INSNS)
            : 12;
    }
    return minimum;
}

void ia64_translate_init(void)
{
    cpu_ip = tcg_global_mem_new_i64(tcg_env,
                                    offsetof(CPUIA64State, ip),
                                    "ip");
}

static void ia64_tr_init_disas_context(DisasContextBase *dcbase,
                                       CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    int bound;

    ctx->base.is_jmp = DISAS_NEXT;
    ctx->env = cpu_env(cs);
    ctx->fast_bundle_ticks = NULL;
    ctx->stacked_frame_base = NULL;
    ctx->stacked_gr_base = NULL;
    ctx->stacked_nat_base = NULL;
    memset(ctx->static_gr, 0, sizeof(ctx->static_gr));
    memset(ctx->br, 0, sizeof(ctx->br));
    memset(ctx->ar, 0, sizeof(ctx->ar));
    ctx->pr = NULL;
    ctx->gr_nat = NULL;
    ctx->static_gr_selected = 0;
    ctx->static_gr_valid = 0;
    ctx->static_gr_dirty = 0;
    ctx->br_valid = 0;
    ctx->br_dirty = 0;
    memset(ctx->ar_valid, 0, sizeof(ctx->ar_valid));
    memset(ctx->ar_dirty, 0, sizeof(ctx->ar_dirty));
    ctx->static_gr_selected_count = 0;
    ctx->stacked_frame_base_loaded = false;
    ctx->fast_bundle_ticks_used = false;
    ctx->inline_gr_nat_clear = false;
    ctx->state_cache_available = false;
    ctx->state_cache_active = false;
    ctx->pr_valid = false;
    ctx->pr_dirty = false;
    ctx->gr_nat_valid = false;
    ctx->gr_nat_dirty = false;
    ctx->profile_enabled =
        (ctx->base.tb->flags & IA64_TB_FLAG_PROFILE) != 0;
    ctx->region_branch_count = 0;
    memset(&ctx->profile_shape, 0, sizeof(ctx->profile_shape));

    /*
     * Instruction fetch exceptions raised while translating a later bundle in
     * a TB must not skip earlier, already translated-but-not-executed bundles.
     * Keep each TB inside the starting TARGET_PAGE_SIZE page so the next page
     * is fetched only after the current page's bundles have retired.
     */
    bound = -(ctx->base.pc_first | TARGET_PAGE_MASK) / IA64_BUNDLE_SIZE;
    ctx->base.max_insns = MIN(ctx->base.max_insns, bound);
}

static void ia64_tr_tb_start(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);

    if ((ctx->base.tb->flags & IA64_TB_FLAG_BENCHMARK) != 0 ||
        !ia64_tr_use_zero_helper_path()) {
        ctx->fast_bundle_ticks = tcg_temp_new_i32();
        tcg_gen_movi_i32(ctx->fast_bundle_ticks, 0);
    }
    ctx->stacked_frame_base = tcg_temp_new_i32();
    ctx->stacked_gr_base = tcg_temp_new_ptr();
    tcg_gen_addi_ptr(ctx->stacked_gr_base, tcg_env,
                     offsetof(CPUIA64State, rse.stacked_gr));
    ctx->stacked_nat_base = tcg_temp_new_ptr();
    tcg_gen_addi_ptr(ctx->stacked_nat_base, tcg_env,
                     offsetof(CPUIA64State, rse.stacked_nat));
    ctx->state_cache_available = ia64_tr_use_zero_helper_path() &&
                                 ia64_tr_state_cache_enabled();
    ctx->state_cache_active = false;
    if (ia64_perf_enabled()) {
        gen_helper_perf_tb_exec();
    }
}

static void ia64_tr_note_fast_bundle(DisasContext *ctx)
{
    if (ctx->fast_bundle_ticks == NULL) {
        return;
    }
    ctx->fast_bundle_ticks_used = true;
    tcg_gen_addi_i32(ctx->fast_bundle_ticks, ctx->fast_bundle_ticks, 1);
}

static bool ia64_tr_zero_helper_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        const char *value = g_getenv("VIBTANIUM_TCG_ZERO_HELPER");

        enabled = value == NULL ||
                  !(strcmp(value, "0") == 0 ||
                    g_ascii_strcasecmp(value, "off") == 0 ||
                    g_ascii_strcasecmp(value, "false") == 0);
    }
    return enabled;
}

static bool ia64_tr_use_zero_helper_path(void)
{
    return ia64_tr_zero_helper_enabled() && !ia64_perf_enabled() &&
           !ia64_debug_hooks_active() &&
           !ia64_firmware_linux_cmdline_append_pending();
}

static bool ia64_tr_region_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        const char *value = g_getenv("VIBTANIUM_TCG_REGION");

        enabled = value != NULL &&
                  !(strcmp(value, "0") == 0 ||
                    g_ascii_strcasecmp(value, "off") == 0 ||
                    g_ascii_strcasecmp(value, "false") == 0);
    }
    return enabled;
}

static bool ia64_tr_conditional_region_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        const char *value = g_getenv("VIBTANIUM_TCG_CONDITIONAL_REGION");

        enabled = value != NULL &&
                  !(strcmp(value, "0") == 0 ||
                    g_ascii_strcasecmp(value, "off") == 0 ||
                    g_ascii_strcasecmp(value, "false") == 0);
    }
    return enabled;
}

static bool ia64_tr_inline_call_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        const char *value = g_getenv("VIBTANIUM_TCG_INLINE_CALL");

        enabled = value != NULL &&
                  !(strcmp(value, "0") == 0 ||
                    g_ascii_strcasecmp(value, "off") == 0 ||
                    g_ascii_strcasecmp(value, "false") == 0);
    }
    return enabled;
}

static bool ia64_tr_spec_check_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        const char *value = g_getenv("VIBTANIUM_TCG_SPEC_CHECK");

        enabled = value == NULL ||
                  !(strcmp(value, "0") == 0 ||
                    g_ascii_strcasecmp(value, "off") == 0 ||
                    g_ascii_strcasecmp(value, "false") == 0);
    }
    return enabled;
}

static size_t ia64_tr_static_gr_offset(DisasContext *ctx, uint8_t reg)
{
    if (reg >= 16 && reg < IA64_STATIC_GR_COUNT &&
        (ctx->base.tb->flags & IA64_TB_FLAG_BN) != 0) {
        return offsetof(CPUIA64State, banked_gr) +
               (reg - 16) * sizeof(uint64_t);
    }
    return offsetof(CPUIA64State, gr) + reg * sizeof(uint64_t);
}

static bool ia64_tr_select_static_gr(DisasContext *ctx, uint8_t reg)
{
    uint32_t bit = UINT32_C(1) << reg;

    if ((ctx->static_gr_selected & bit) != 0) {
        return true;
    }
    if (ctx->static_gr_selected_count >= ia64_tr_state_cache_gr_limit()) {
        return false;
    }
    ctx->static_gr_selected |= bit;
    ctx->static_gr_selected_count++;
    return true;
}

static TCGv_i64 ia64_tr_ensure_static_gr(DisasContext *ctx, uint8_t reg)
{
    uint32_t bit = UINT32_C(1) << reg;

    g_assert(ctx->state_cache_active && reg > 0 &&
             reg < IA64_STATIC_GR_COUNT);
    if (!ia64_tr_select_static_gr(ctx, reg)) {
        return NULL;
    }
    if (ctx->static_gr[reg] == NULL) {
        ctx->static_gr[reg] = tcg_temp_new_i64();
    }
    if ((ctx->static_gr_valid & bit) == 0) {
        tcg_gen_ld_i64(ctx->static_gr[reg], tcg_env,
                       ia64_tr_static_gr_offset(ctx, reg));
        ctx->static_gr_valid |= bit;
    } else {
        ia64_tr_profile_add(ctx, IA64_PROFILE_STATE_CACHE_HIT, 1);
    }
    return ctx->static_gr[reg];
}

static TCGv_i64 ia64_tr_ensure_br(DisasContext *ctx, uint8_t reg)
{
    uint8_t bit = 1u << reg;

    g_assert(ctx->state_cache_active && reg < IA64_BR_COUNT);
    if (ctx->br[reg] == NULL) {
        ctx->br[reg] = tcg_temp_new_i64();
    }
    if ((ctx->br_valid & bit) == 0) {
        tcg_gen_ld_i64(ctx->br[reg], tcg_env,
                       offsetof(CPUIA64State, br) +
                       reg * sizeof(uint64_t));
        ctx->br_valid |= bit;
    } else {
        ia64_tr_profile_add(ctx, IA64_PROFILE_STATE_CACHE_HIT, 1);
    }
    return ctx->br[reg];
}

static TCGv_i64 ia64_tr_ensure_ar(DisasContext *ctx, uint8_t reg)
{
    unsigned word = reg >> 6;
    uint64_t bit = UINT64_C(1) << (reg & 63);

    g_assert(ctx->state_cache_active && reg < IA64_AR_COUNT);
    if (ctx->ar[reg] == NULL) {
        ctx->ar[reg] = tcg_temp_new_i64();
    }
    if ((ctx->ar_valid[word] & bit) == 0) {
        tcg_gen_ld_i64(ctx->ar[reg], tcg_env,
                       offsetof(CPUIA64State, ar) +
                       reg * sizeof(uint64_t));
        ctx->ar_valid[word] |= bit;
    } else {
        ia64_tr_profile_add(ctx, IA64_PROFILE_STATE_CACHE_HIT, 1);
    }
    return ctx->ar[reg];
}

static TCGv_i64 ia64_tr_ensure_pr(DisasContext *ctx)
{
    g_assert(ctx->state_cache_active);
    if (ctx->pr == NULL) {
        ctx->pr = tcg_temp_new_i64();
    }
    if (!ctx->pr_valid) {
        tcg_gen_ld_i64(ctx->pr, tcg_env, offsetof(CPUIA64State, pr));
        ctx->pr_valid = true;
    } else {
        ia64_tr_profile_add(ctx, IA64_PROFILE_STATE_CACHE_HIT, 1);
    }
    return ctx->pr;
}

static TCGv_i64 ia64_tr_ensure_gr_nat(DisasContext *ctx)
{
    g_assert(ctx->state_cache_active);
    if (ctx->gr_nat == NULL) {
        ctx->gr_nat = tcg_temp_new_i64();
    }
    if (!ctx->gr_nat_valid) {
        tcg_gen_ld_i64(ctx->gr_nat, tcg_env,
                       offsetof(CPUIA64State, nat.gr_nat));
        ctx->gr_nat_valid = true;
    } else {
        ia64_tr_profile_add(ctx, IA64_PROFILE_STATE_CACHE_HIT, 1);
    }
    return ctx->gr_nat;
}

/*
 * Exit paths can branch in TCG control flow after translation-time cache
 * metadata has been computed.  Keep dirty bits intact while emitting an exit
 * writeback so every arm gets the same stores.  A barrier additionally drops
 * the metadata before translation continues past a helper or fault boundary.
 */
static void ia64_tr_capture_state_cache_dirty(
    DisasContext *ctx, IA64TrStateCacheDirty *dirty)
{
    dirty->static_gr = ctx->static_gr_dirty;
    dirty->br = ctx->br_dirty;
    dirty->ar[0] = ctx->ar_dirty[0];
    dirty->ar[1] = ctx->ar_dirty[1];
    dirty->pr = ctx->pr_dirty;
    dirty->gr_nat = ctx->gr_nat_dirty;
}

static void ia64_tr_sync_state_cache_dirty(
    DisasContext *ctx, const IA64TrStateCacheDirty *dirty)
{
    uint32_t gr = dirty->static_gr;
    uint8_t br = dirty->br;

    while (gr != 0) {
        unsigned reg = ctz32(gr);

        tcg_gen_st_i64(ctx->static_gr[reg], tcg_env,
                       ia64_tr_static_gr_offset(ctx, reg));
        gr &= gr - 1;
    }
    while (br != 0) {
        unsigned reg = ctz32(br);

        tcg_gen_st_i64(ctx->br[reg], tcg_env,
                       offsetof(CPUIA64State, br) +
                       reg * sizeof(uint64_t));
        br &= br - 1;
    }
    for (unsigned word = 0; word < ARRAY_SIZE(dirty->ar); word++) {
        uint64_t ar = dirty->ar[word];

        while (ar != 0) {
            unsigned reg = word * 64 + ctz64(ar);

            tcg_gen_st_i64(ctx->ar[reg], tcg_env,
                           offsetof(CPUIA64State, ar) +
                           reg * sizeof(uint64_t));
            ar &= ar - 1;
        }
    }
    if (dirty->pr) {
        tcg_gen_st_i64(ctx->pr, tcg_env, offsetof(CPUIA64State, pr));
    }
    if (dirty->gr_nat) {
        tcg_gen_st_i64(ctx->gr_nat, tcg_env,
                       offsetof(CPUIA64State, nat.gr_nat));
    }
}

static void ia64_tr_sync_state_cache(DisasContext *ctx)
{
    IA64TrStateCacheDirty dirty;

    ia64_tr_capture_state_cache_dirty(ctx, &dirty);
    ia64_tr_sync_state_cache_dirty(ctx, &dirty);
}

static void ia64_tr_reload_state_cache(DisasContext *ctx)
{
    uint32_t gr = ctx->static_gr_valid;
    uint8_t br = ctx->br_valid;

    while (gr != 0) {
        unsigned reg = ctz32(gr);

        tcg_gen_ld_i64(ctx->static_gr[reg], tcg_env,
                       ia64_tr_static_gr_offset(ctx, reg));
        gr &= gr - 1;
    }
    while (br != 0) {
        unsigned reg = ctz32(br);

        tcg_gen_ld_i64(ctx->br[reg], tcg_env,
                       offsetof(CPUIA64State, br) +
                       reg * sizeof(uint64_t));
        br &= br - 1;
    }
    for (unsigned word = 0; word < ARRAY_SIZE(ctx->ar_valid); word++) {
        uint64_t ar = ctx->ar_valid[word];

        while (ar != 0) {
            unsigned reg = word * 64 + ctz64(ar);

            tcg_gen_ld_i64(ctx->ar[reg], tcg_env,
                           offsetof(CPUIA64State, ar) +
                           reg * sizeof(uint64_t));
            ar &= ar - 1;
        }
    }
    if (ctx->pr_valid) {
        tcg_gen_ld_i64(ctx->pr, tcg_env, offsetof(CPUIA64State, pr));
    }
    if (ctx->gr_nat_valid) {
        tcg_gen_ld_i64(ctx->gr_nat, tcg_env,
                       offsetof(CPUIA64State, nat.gr_nat));
    }
    if (ctx->stacked_frame_base_loaded) {
        tcg_gen_ld_i32(ctx->stacked_frame_base, tcg_env,
                       offsetof(CPUIA64State, rse.current_frame_base));
    }
}

static void ia64_tr_invalidate_state_cache(DisasContext *ctx)
{
    ctx->static_gr_valid = 0;
    ctx->static_gr_dirty = 0;
    ctx->br_valid = 0;
    ctx->br_dirty = 0;
    memset(ctx->ar_valid, 0, sizeof(ctx->ar_valid));
    memset(ctx->ar_dirty, 0, sizeof(ctx->ar_dirty));
    ctx->pr_valid = false;
    ctx->pr_dirty = false;
    ctx->gr_nat_valid = false;
    ctx->gr_nat_dirty = false;
    ctx->stacked_frame_base_loaded = false;
}

static void ia64_tr_state_cache_barrier(DisasContext *ctx)
{
    if (ctx->state_cache_active) {
        ia64_tr_profile_add(ctx, IA64_PROFILE_STATE_CACHE_BARRIER, 1);
    }
    ia64_tr_sync_state_cache(ctx);
    ia64_tr_invalidate_state_cache(ctx);
}

static bool ia64_tr_suspend_state_cache(DisasContext *ctx)
{
    bool active = ctx->state_cache_active;

    if (active) {
        ia64_tr_profile_add(ctx, IA64_PROFILE_STATE_CACHE_SUSPEND, 1);
        ia64_tr_state_cache_barrier(ctx);
        ctx->state_cache_active = false;
    }
    return active;
}

static void ia64_tr_resume_state_cache(DisasContext *ctx, bool active)
{
    if (active) {
        g_assert(ctx->static_gr_valid == 0 && ctx->static_gr_dirty == 0 &&
                 ctx->br_valid == 0 && ctx->br_dirty == 0 &&
                 ctx->ar_valid[0] == 0 && ctx->ar_valid[1] == 0 &&
                 ctx->ar_dirty[0] == 0 && ctx->ar_dirty[1] == 0 &&
                 !ctx->pr_valid && !ctx->pr_dirty &&
                 !ctx->gr_nat_valid && !ctx->gr_nat_dirty);
        ctx->state_cache_active = true;
    }
}

static void ia64_tr_emit_benchmark_retire(TCGv_i32 bundle_count)
{
    TCGv_i64 count = tcg_temp_new_i64();
    TCGv_i64 retired = tcg_temp_new_i64();

    tcg_gen_ld_i64(retired, tcg_env,
                   IA64_CPU_OFFSET(benchmark_retired_bundles));
    tcg_gen_extu_i32_i64(count, bundle_count);
    tcg_gen_add_i64(retired, retired, count);
    tcg_gen_st_i64(retired, tcg_env,
                   IA64_CPU_OFFSET(benchmark_retired_bundles));
}

static void ia64_tr_flush_fast_bundle_ticks(DisasContext *ctx)
{
    if (!ctx->fast_bundle_ticks_used) {
        return;
    }

    if (ia64_tr_use_zero_helper_path()) {
        g_assert((ctx->base.tb->flags & IA64_TB_FLAG_BENCHMARK) != 0);
        ia64_tr_emit_benchmark_retire(ctx->fast_bundle_ticks);
    } else {
        gen_helper_finish_fast_tb(tcg_env, ctx->fast_bundle_ticks);
    }
    tcg_gen_movi_i32(ctx->fast_bundle_ticks, 0);
}

static void ia64_tr_commit_ip(uint64_t ip)
{
    tcg_gen_movi_i64(cpu_ip, ip);
    tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                    offsetof(CPUIA64State, ri));
    tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                    offsetof(CPUIA64State, ri_dirty));
}

static void ia64_tr_commit_ip_value(TCGv_i64 ip)
{
    tcg_gen_mov_i64(cpu_ip, ip);
    tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                    offsetof(CPUIA64State, ri));
    tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                    offsetof(CPUIA64State, ri_dirty));
}

static void ia64_tr_prepare_helper_ip(uint64_t ip)
{
    if (ia64_tr_use_zero_helper_path()) {
        ia64_tr_commit_ip(ip);
    } else {
        tcg_gen_movi_i64(cpu_ip, ip);
    }
}

static void ia64_tr_emit_can_do_io(void)
{
    tcg_gen_st8_i32(tcg_constant_i32(true), tcg_env,
                    IA64_CPU_STATE_OFFSET(neg.can_do_io));
}

static void ia64_tr_insn_start(DisasContextBase *dcbase, CPUState *cs)
{
    tcg_gen_insn_start(dcbase->pc_next,
                       ia64_tcg_tb_flags_ri(dcbase->tb->flags), 0);
}

static void ia64_tr_emit_exec_bundle(DisasContext *ctx,
                                     const IA64DecodedBundle *bundle,
                                     uint64_t pc)
{
    IA64TcgFallbackPlan fallback_plan =
        ia64_tcg_fallback_plan_for_bundle(bundle);
    IA64TcgFallbackArgs fallback_args = ia64_tcg_fallback_args(
        bundle, &fallback_plan, IA64_TCG_FALLBACK_FULL_BUNDLE);

    ia64_tr_state_cache_barrier(ctx);
    ia64_tr_flush_fast_bundle_ticks(ctx);
    ia64_tr_prepare_helper_ip(pc);
    gen_helper_exec_bundle(
        tcg_env,
        tcg_constant_i64(fallback_args.header),
        tcg_constant_i64(fallback_args.slot1),
        tcg_constant_i64(fallback_args.slot2),
        tcg_constant_i64(fallback_args.desc01),
        tcg_constant_i64(fallback_args.desc2));
}

static void ia64_tr_emit_exec_bundle_lookup_ptr(DisasContext *ctx,
                                                const IA64DecodedBundle *bundle,
                                                uint64_t pc)
{
    IA64TcgFallbackPlan fallback_plan =
        ia64_tcg_fallback_plan_for_bundle(bundle);
    IA64TcgFallbackArgs fallback_args = ia64_tcg_fallback_args(
        bundle, &fallback_plan, IA64_TCG_FALLBACK_FULL_BUNDLE);
    TCGLabel *main_loop_exit = gen_new_label();
    TCGv_i32 chain_ok = tcg_temp_new_i32();

    ia64_tr_state_cache_barrier(ctx);
    ia64_tr_flush_fast_bundle_ticks(ctx);
    ia64_tr_prepare_helper_ip(pc);
    gen_helper_exec_bundle_lookup_ptr(
        chain_ok, tcg_env,
        tcg_constant_i64(fallback_args.header),
        tcg_constant_i64(fallback_args.slot1),
        tcg_constant_i64(fallback_args.slot2),
        tcg_constant_i64(fallback_args.desc01),
        tcg_constant_i64(fallback_args.desc2));
    tcg_gen_brcondi_i32(TCG_COND_EQ, chain_ok, 0, main_loop_exit);
    ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_LOOKUP);
    tcg_gen_lookup_and_goto_ptr();

    gen_set_label(main_loop_exit);
    ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_MAIN);
    tcg_gen_exit_tb(NULL, 0);
}

static void ia64_tr_emit_exec_bundle_cached_fallback(
    DisasContext *ctx, const IA64DecodedBundle *bundle, uint64_t pc,
    const IA64TrStateCacheDirty *dirty_before)
{
    IA64TcgFallbackPlan fallback_plan =
        ia64_tcg_fallback_plan_for_bundle(bundle);
    IA64TcgFallbackArgs fallback_args = ia64_tcg_fallback_args(
        bundle, &fallback_plan, IA64_TCG_FALLBACK_FULL_BUNDLE);

    /*
     * The guard bypasses this bundle's fast writes, so publish only state
     * dirtied by earlier bundles before invoking the correctness oracle.
     */
    ia64_tr_sync_state_cache_dirty(ctx, dirty_before);
    ia64_tr_flush_fast_bundle_ticks(ctx);
    ia64_tr_prepare_helper_ip(pc);
    gen_helper_exec_bundle(
        tcg_env,
        tcg_constant_i64(fallback_args.header),
        tcg_constant_i64(fallback_args.slot1),
        tcg_constant_i64(fallback_args.slot2),
        tcg_constant_i64(fallback_args.desc01),
        tcg_constant_i64(fallback_args.desc2));

    /* Make both runtime arms define every translation-time-valid cache temp. */
    ia64_tr_reload_state_cache(ctx);
}

static void ia64_tr_emit_exec_bundle_lookup_ptr_cached_fallback(
    DisasContext *ctx, const IA64DecodedBundle *bundle, uint64_t pc,
    const IA64TrStateCacheDirty *dirty_before)
{
    IA64TcgFallbackPlan fallback_plan =
        ia64_tcg_fallback_plan_for_bundle(bundle);
    IA64TcgFallbackArgs fallback_args = ia64_tcg_fallback_args(
        bundle, &fallback_plan, IA64_TCG_FALLBACK_FULL_BUNDLE);
    TCGLabel *main_loop_exit = gen_new_label();
    TCGv_i32 chain_ok = tcg_temp_new_i32();

    ia64_tr_sync_state_cache_dirty(ctx, dirty_before);
    ia64_tr_flush_fast_bundle_ticks(ctx);
    ia64_tr_prepare_helper_ip(pc);
    gen_helper_exec_bundle_lookup_ptr(
        chain_ok, tcg_env,
        tcg_constant_i64(fallback_args.header),
        tcg_constant_i64(fallback_args.slot1),
        tcg_constant_i64(fallback_args.slot2),
        tcg_constant_i64(fallback_args.desc01),
        tcg_constant_i64(fallback_args.desc2));
    tcg_gen_brcondi_i32(TCG_COND_EQ, chain_ok, 0, main_loop_exit);
    ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_LOOKUP);
    tcg_gen_lookup_and_goto_ptr();

    gen_set_label(main_loop_exit);
    ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_MAIN);
    tcg_gen_exit_tb(NULL, 0);
}

static void ia64_tr_emit_firmware_call_gate(DisasContext *ctx, uint64_t pc,
                                            uint64_t dispatch_ip)
{
    ia64_tr_state_cache_barrier(ctx);
    ia64_tr_flush_fast_bundle_ticks(ctx);
    ia64_tr_prepare_helper_ip(pc);
    gen_helper_firmware_call_gate(tcg_env, tcg_constant_i64(pc),
                                  tcg_constant_i64(dispatch_ip));
}

static bool ia64_tr_instruction_physical_address(DisasContext *ctx,
                                                 uint64_t pc,
                                                 uint64_t *physical_pc)
{
    IA64TranslateResult result;
    int mmu_idx = ia64_tcg_mmu_index_for_psr(ctx->env->psr, true);

    if (!ia64_translate_address_no_detail(ctx->env, pc, MMU_INST_FETCH,
                                          mmu_idx, false, &result)) {
        return false;
    }
    *physical_pc = result.paddr;
    return true;
}

static bool ia64_tr_gr_is_stacked(uint8_t reg)
{
    return reg >= IA64_STATIC_GR_COUNT;
}

static void ia64_tr_ensure_stacked_frame_base(DisasContext *ctx)
{
    if (!ctx->stacked_frame_base_loaded) {
        tcg_gen_ld_i32(ctx->stacked_frame_base, tcg_env,
                       offsetof(CPUIA64State, rse.current_frame_base));
        ctx->stacked_frame_base_loaded = true;
    } else {
        ia64_tr_profile_add(ctx, IA64_PROFILE_STATE_CACHE_HIT, 1);
    }
}

static void ia64_tr_stacked_gr_slot(DisasContext *ctx, TCGv_i64 slot,
                                    uint8_t reg)
{
    ia64_tr_ensure_stacked_frame_base(ctx);
    tcg_gen_extu_i32_i64(slot, ctx->stacked_frame_base);
    tcg_gen_addi_i64(slot, slot, reg - IA64_STATIC_GR_COUNT);
    tcg_gen_andi_i64(slot, slot, IA64_STACKED_GR_MASK);
}

static void ia64_tr_stacked_gr_address(DisasContext *ctx, TCGv_ptr ptr,
                                       TCGv_i64 slot, uint8_t reg)
{
    TCGv_i64 byte_offset = tcg_temp_new_i64();

    ia64_tr_stacked_gr_slot(ctx, slot, reg);
    tcg_gen_shli_i64(byte_offset, slot, 3);
    tcg_gen_trunc_i64_ptr(ptr, byte_offset);
    tcg_gen_add_ptr(ptr, ctx->stacked_gr_base, ptr);
}

static void ia64_tr_mark_stacked_gr_dirty(TCGv_i64 slot)
{
    TCGv_i32 clean_count = tcg_temp_new_i32();
    TCGv_i32 slot32 = tcg_temp_new_i32();

    tcg_gen_ld_i32(clean_count, tcg_env,
                   offsetof(CPUIA64State, rse.clean_count));
    tcg_gen_extrl_i64_i32(slot32, slot);
    tcg_gen_movcond_i32(TCG_COND_LTU, clean_count, clean_count, slot32,
                        clean_count, slot32);
    tcg_gen_st_i32(clean_count, tcg_env,
                   offsetof(CPUIA64State, rse.clean_count));
}

static void ia64_tr_stacked_nat_address(DisasContext *ctx, TCGv_ptr ptr,
                                        TCGv_i64 bit, uint8_t reg)
{
    TCGv_i64 slot = tcg_temp_new_i64();
    TCGv_i64 shift = tcg_temp_new_i64();
    TCGv_i64 byte_offset = tcg_temp_new_i64();

    ia64_tr_stacked_gr_slot(ctx, slot, reg);
    tcg_gen_andi_i64(shift, slot, 63);
    tcg_gen_shl_i64(bit, tcg_constant_i64(1), shift);
    tcg_gen_shri_i64(byte_offset, slot, 6);
    tcg_gen_shli_i64(byte_offset, byte_offset, 3);
    tcg_gen_trunc_i64_ptr(ptr, byte_offset);
    tcg_gen_add_ptr(ptr, ctx->stacked_nat_base, ptr);
}

static void ia64_tr_clear_gr_nat(DisasContext *ctx, uint8_t reg)
{
    if (ia64_tr_gr_is_stacked(reg)) {
        TCGv_ptr ptr = tcg_temp_new_ptr();
        TCGv_i64 bit = tcg_temp_new_i64();
        TCGv_i64 nat = tcg_temp_new_i64();

        ia64_tr_stacked_nat_address(ctx, ptr, bit, reg);
        tcg_gen_ld_i64(nat, ptr, 0);
        tcg_gen_andc_i64(nat, nat, bit);
        tcg_gen_st_i64(nat, ptr, 0);
        return;
    }

    if (ctx->state_cache_active) {
        TCGv_i64 nat = ia64_tr_ensure_gr_nat(ctx);

        tcg_gen_andi_i64(nat, nat, ~(UINT64_C(1) << reg));
        ctx->gr_nat_dirty = true;
    } else {
        TCGv_i64 nat = tcg_temp_new_i64();

        tcg_gen_ld_i64(nat, tcg_env, offsetof(CPUIA64State, nat.gr_nat));
        tcg_gen_andi_i64(nat, nat, ~(UINT64_C(1) << reg));
        tcg_gen_st_i64(nat, tcg_env, offsetof(CPUIA64State, nat.gr_nat));
    }
}

static void ia64_tr_load_static_gr(DisasContext *ctx, TCGv_i64 dest,
                                   uint8_t reg)
{
    if (ia64_tr_gr_is_stacked(reg)) {
        TCGv_ptr ptr = tcg_temp_new_ptr();
        TCGv_i64 slot = tcg_temp_new_i64();

        ia64_tr_stacked_gr_address(ctx, ptr, slot, reg);
        tcg_gen_ld_i64(dest, ptr, 0);
        return;
    }

    if (reg == 0) {
        tcg_gen_movi_i64(dest, 0);
        return;
    }

    if (ctx->state_cache_active) {
        TCGv_i64 cached = ia64_tr_ensure_static_gr(ctx, reg);

        if (cached != NULL) {
            tcg_gen_mov_i64(dest, cached);
            return;
        }
    }

    tcg_gen_ld_i64(dest, tcg_env, ia64_tr_static_gr_offset(ctx, reg));
}

static void ia64_tr_store_static_gr(DisasContext *ctx, uint8_t reg,
                                    TCGv_i64 value)
{
    if (ia64_tr_gr_is_stacked(reg)) {
        TCGv_ptr ptr = tcg_temp_new_ptr();
        TCGv_i64 slot = tcg_temp_new_i64();

        ia64_tr_stacked_gr_address(ctx, ptr, slot, reg);
        tcg_gen_st_i64(value, ptr, 0);
        ia64_tr_mark_stacked_gr_dirty(slot);
        if (ctx->inline_gr_nat_clear) {
            ia64_tr_clear_gr_nat(ctx, reg);
        }
        return;
    }

    if (reg == 0) {
        return;
    }

    if (ctx->state_cache_active && ia64_tr_select_static_gr(ctx, reg)) {
        uint32_t bit = UINT32_C(1) << reg;

        if (ctx->static_gr[reg] == NULL) {
            ctx->static_gr[reg] = tcg_temp_new_i64();
        }
        tcg_gen_mov_i64(ctx->static_gr[reg], value);
        ctx->static_gr_valid |= bit;
        ctx->static_gr_dirty |= bit;
        if (ctx->inline_gr_nat_clear) {
            ia64_tr_clear_gr_nat(ctx, reg);
        }
        return;
    }

    tcg_gen_st_i64(value, tcg_env, ia64_tr_static_gr_offset(ctx, reg));
    if (ctx->inline_gr_nat_clear) {
        ia64_tr_clear_gr_nat(ctx, reg);
    }
}

static TCGCond ia64_tr_compare_cond(uint8_t relation)
{
    switch (relation) {
    case IA64_CMP_EQ:
        return TCG_COND_EQ;
    case IA64_CMP_NE:
        return TCG_COND_NE;
    case IA64_CMP_LT:
        return TCG_COND_LT;
    case IA64_CMP_LE:
        return TCG_COND_LE;
    case IA64_CMP_GT:
        return TCG_COND_GT;
    case IA64_CMP_GE:
        return TCG_COND_GE;
    case IA64_CMP_LTU:
        return TCG_COND_LTU;
    case IA64_CMP_LEU:
        return TCG_COND_LEU;
    case IA64_CMP_GTU:
        return TCG_COND_GTU;
    case IA64_CMP_GEU:
        return TCG_COND_GEU;
    default:
        g_assert_not_reached();
    }
}

static bool ia64_tr_compare_relation_is_signed(uint8_t relation)
{
    return relation == IA64_CMP_LT || relation == IA64_CMP_LE ||
           relation == IA64_CMP_GT || relation == IA64_CMP_GE;
}

static void ia64_tr_predicate_bit(TCGv_i64 bit, uint8_t predicate)
{
    if (predicate < 16) {
        tcg_gen_movi_i64(bit, UINT64_C(1) << predicate);
        return;
    }

    TCGv_i32 rrb32 = tcg_temp_new_i32();
    TCGv_i64 mapped = tcg_temp_new_i64();
    TCGv_i64 wrapped = tcg_temp_new_i64();

    tcg_gen_ld_i32(rrb32, tcg_env,
                   offsetof(CPUIA64State, rse.rrb_pr));
    tcg_gen_extu_i32_i64(mapped, rrb32);
    tcg_gen_addi_i64(mapped, mapped, predicate);
    tcg_gen_subi_i64(wrapped, mapped, 48);
    tcg_gen_movcond_i64(TCG_COND_GEU, mapped, mapped,
                        tcg_constant_i64(64), wrapped, mapped);
    tcg_gen_subi_i64(wrapped, mapped, 48);
    tcg_gen_movcond_i64(TCG_COND_GEU, mapped, mapped,
                        tcg_constant_i64(64), wrapped, mapped);
    tcg_gen_shl_i64(bit, tcg_constant_i64(1), mapped);
}

static void ia64_tr_load_predicate(DisasContext *ctx, TCGv_i64 value,
                                   uint8_t predicate)
{
    TCGv_i64 pr = tcg_temp_new_i64();
    TCGv_i64 bit = tcg_temp_new_i64();

    ia64_tr_predicate_bit(bit, predicate);
    if (ctx->state_cache_active) {
        tcg_gen_mov_i64(pr, ia64_tr_ensure_pr(ctx));
    } else {
        tcg_gen_ld_i64(pr, tcg_env, offsetof(CPUIA64State, pr));
    }
    tcg_gen_and_i64(value, pr, bit);
}

static void ia64_tr_write_pr_const(DisasContext *ctx, uint8_t predicate,
                                   bool value)
{
    TCGv_i64 pr;
    TCGv_i64 bit;

    if (predicate == 0) {
        pr = ctx->state_cache_active ? ia64_tr_ensure_pr(ctx) :
                                      tcg_temp_new_i64();
        if (!ctx->state_cache_active) {
            tcg_gen_ld_i64(pr, tcg_env, offsetof(CPUIA64State, pr));
        }
        tcg_gen_ori_i64(pr, pr, 1);
        if (ctx->state_cache_active) {
            ctx->pr_dirty = true;
        } else {
            tcg_gen_st_i64(pr, tcg_env, offsetof(CPUIA64State, pr));
        }
        return;
    }

    pr = ctx->state_cache_active ? ia64_tr_ensure_pr(ctx) :
                                  tcg_temp_new_i64();
    bit = tcg_temp_new_i64();
    ia64_tr_predicate_bit(bit, predicate);
    if (!ctx->state_cache_active) {
        tcg_gen_ld_i64(pr, tcg_env, offsetof(CPUIA64State, pr));
    }
    if (value) {
        tcg_gen_or_i64(pr, pr, bit);
    } else {
        tcg_gen_andc_i64(pr, pr, bit);
    }
    tcg_gen_ori_i64(pr, pr, 1);
    if (ctx->state_cache_active) {
        ctx->pr_dirty = true;
    } else {
        tcg_gen_st_i64(pr, tcg_env, offsetof(CPUIA64State, pr));
    }
}

static void ia64_tr_write_pr_bool(DisasContext *ctx, uint8_t predicate,
                                  TCGv_i64 value)
{
    TCGv_i64 pr;
    TCGv_i64 bit;
    TCGv_i64 selected;

    if (predicate == 0) {
        ia64_tr_write_pr_const(ctx, predicate, true);
        return;
    }

    pr = ctx->state_cache_active ? ia64_tr_ensure_pr(ctx) :
                                  tcg_temp_new_i64();
    bit = tcg_temp_new_i64();
    selected = tcg_temp_new_i64();
    ia64_tr_predicate_bit(bit, predicate);
    if (!ctx->state_cache_active) {
        tcg_gen_ld_i64(pr, tcg_env, offsetof(CPUIA64State, pr));
    }
    tcg_gen_andc_i64(pr, pr, bit);
    tcg_gen_neg_i64(selected, value);
    tcg_gen_and_i64(selected, selected, bit);
    tcg_gen_or_i64(pr, pr, selected);
    tcg_gen_ori_i64(pr, pr, 1);
    if (ctx->state_cache_active) {
        ctx->pr_dirty = true;
    } else {
        tcg_gen_st_i64(pr, tcg_env, offsetof(CPUIA64State, pr));
    }
}

static void ia64_tr_emit_predicate_pair_write(DisasContext *ctx,
                                              const IA64TcgFastSlot *slot,
                                              TCGv_i64 result)
{
    TCGv_i64 inverted;
    TCGLabel *done;

    if (ctx->state_cache_active) {
        ia64_tr_ensure_pr(ctx);
    }
    switch (slot->predicate_write_kind) {
    case IA64_PRED_WRITE_UNCONDITIONAL:
    case IA64_PRED_WRITE_NORMAL:
        ia64_tr_write_pr_bool(ctx, slot->predicate1, result);
        inverted = tcg_temp_new_i64();
        tcg_gen_xori_i64(inverted, result, 1);
        ia64_tr_write_pr_bool(ctx, slot->predicate2, inverted);
        break;
    case IA64_PRED_WRITE_AND:
        done = gen_new_label();
        tcg_gen_brcondi_i64(TCG_COND_NE, result, 0, done);
        ia64_tr_write_pr_const(ctx, slot->predicate1, false);
        ia64_tr_write_pr_const(ctx, slot->predicate2, false);
        gen_set_label(done);
        break;
    case IA64_PRED_WRITE_OR:
        done = gen_new_label();
        tcg_gen_brcondi_i64(TCG_COND_EQ, result, 0, done);
        ia64_tr_write_pr_const(ctx, slot->predicate1, true);
        ia64_tr_write_pr_const(ctx, slot->predicate2, true);
        gen_set_label(done);
        break;
    case IA64_PRED_WRITE_OR_ANDCM:
        done = gen_new_label();
        tcg_gen_brcondi_i64(TCG_COND_EQ, result, 0, done);
        ia64_tr_write_pr_const(ctx, slot->predicate1, true);
        ia64_tr_write_pr_const(ctx, slot->predicate2, false);
        gen_set_label(done);
        break;
    default:
        g_assert_not_reached();
    }
}

static void ia64_tr_emit_addp4(TCGv_i64 dest, TCGv_i64 left, TCGv_i64 right)
{
    TCGv_i64 low32 = tcg_temp_new_i64();
    TCGv_i64 region = tcg_temp_new_i64();

    tcg_gen_add_i64(low32, left, right);
    tcg_gen_ext32u_i64(low32, low32);
    tcg_gen_shri_i64(region, right, 30);
    tcg_gen_andi_i64(region, region, 3);
    tcg_gen_shli_i64(region, region, 61);
    tcg_gen_or_i64(dest, region, low32);
}

static void ia64_tr_read_static_gr_nat(DisasContext *ctx, TCGv_i64 dest,
                                       uint8_t reg)
{
    if (ia64_tr_gr_is_stacked(reg)) {
        TCGv_ptr ptr = tcg_temp_new_ptr();
        TCGv_i64 bit = tcg_temp_new_i64();

        ia64_tr_stacked_nat_address(ctx, ptr, bit, reg);
        tcg_gen_ld_i64(dest, ptr, 0);
        tcg_gen_and_i64(dest, dest, bit);
        tcg_gen_setcondi_i64(TCG_COND_NE, dest, dest, 0);
        return;
    }

    if (ctx->state_cache_active) {
        tcg_gen_mov_i64(dest, ia64_tr_ensure_gr_nat(ctx));
    } else {
        tcg_gen_ld_i64(dest, tcg_env,
                       offsetof(CPUIA64State, nat.gr_nat));
    }
    tcg_gen_shri_i64(dest, dest, reg % 64);
    tcg_gen_andi_i64(dest, dest, 1);
}

static void ia64_tr_write_gr_nat(DisasContext *ctx, uint8_t reg,
                                 TCGv_i64 value)
{
    TCGv_i64 nat = tcg_temp_new_i64();
    TCGv_i64 bit = tcg_temp_new_i64();
    TCGv_i64 selected = tcg_temp_new_i64();

    if (ia64_tr_gr_is_stacked(reg)) {
        TCGv_ptr ptr = tcg_temp_new_ptr();

        ia64_tr_stacked_nat_address(ctx, ptr, bit, reg);
        tcg_gen_ld_i64(nat, ptr, 0);
        tcg_gen_andc_i64(nat, nat, bit);
        tcg_gen_neg_i64(selected, value);
        tcg_gen_and_i64(selected, selected, bit);
        tcg_gen_or_i64(nat, nat, selected);
        tcg_gen_st_i64(nat, ptr, 0);
        return;
    }

    tcg_gen_movi_i64(bit, UINT64_C(1) << reg);
    if (ctx->state_cache_active) {
        tcg_gen_mov_i64(nat, ia64_tr_ensure_gr_nat(ctx));
    } else {
        tcg_gen_ld_i64(nat, tcg_env,
                       offsetof(CPUIA64State, nat.gr_nat));
    }
    tcg_gen_andc_i64(nat, nat, bit);
    tcg_gen_neg_i64(selected, value);
    tcg_gen_and_i64(selected, selected, bit);
    tcg_gen_or_i64(nat, nat, selected);
    if (ctx->state_cache_active) {
        tcg_gen_mov_i64(ctx->gr_nat, nat);
        ctx->gr_nat_dirty = true;
    } else {
        tcg_gen_st_i64(nat, tcg_env,
                       offsetof(CPUIA64State, nat.gr_nat));
    }
}

static void ia64_tr_emit_fill_nat(DisasContext *ctx,
                                  const IA64TcgFastSlot *slot,
                                  TCGv_i64 address)
{
    TCGv_i64 shift = tcg_temp_new_i64();
    TCGv_i64 bit = tcg_temp_new_i64();
    TCGv_i64 unat = tcg_temp_new_i64();

    tcg_gen_shri_i64(shift, address, 3);
    tcg_gen_andi_i64(shift, shift, 0x3f);
    tcg_gen_shl_i64(bit, tcg_constant_i64(1), shift);
    tcg_gen_ld_i64(unat, tcg_env, offsetof(CPUIA64State, nat.unat));
    tcg_gen_and_i64(unat, unat, bit);
    tcg_gen_setcondi_i64(TCG_COND_NE, unat, unat, 0);
    ia64_tr_write_gr_nat(ctx, slot->target, unat);
}

static void ia64_tr_emit_spill_unat(DisasContext *ctx,
                                    const IA64TcgFastSlot *slot,
                                    TCGv_i64 address)
{
    TCGv_i64 source_nat = tcg_temp_new_i64();
    TCGv_i64 shift = tcg_temp_new_i64();
    TCGv_i64 bit = tcg_temp_new_i64();
    TCGv_i64 selected = tcg_temp_new_i64();
    TCGv_i64 unat = tcg_temp_new_i64();

    ia64_tr_read_static_gr_nat(ctx, source_nat, slot->source2);
    tcg_gen_shri_i64(shift, address, 3);
    tcg_gen_andi_i64(shift, shift, 0x3f);
    tcg_gen_shl_i64(bit, tcg_constant_i64(1), shift);
    tcg_gen_ld_i64(unat, tcg_env, offsetof(CPUIA64State, nat.unat));
    tcg_gen_andc_i64(unat, unat, bit);
    tcg_gen_neg_i64(selected, source_nat);
    tcg_gen_and_i64(selected, selected, bit);
    tcg_gen_or_i64(unat, unat, selected);
    tcg_gen_st_i64(unat, tcg_env, offsetof(CPUIA64State, nat.unat));
    tcg_gen_st_i64(unat, tcg_env,
                   offsetof(CPUIA64State, ar) +
                   IA64_AR_UNAT * sizeof(uint64_t));
}

static void ia64_tr_emit_integer_extend(const IA64TcgFastSlot *slot,
                                        TCGv_i64 dest, TCGv_i64 source)
{
    switch (slot->integer_extend_kind) {
    case IA64_EXT_ZXT:
        switch (slot->width) {
        case 1:
            tcg_gen_ext8u_i64(dest, source);
            break;
        case 2:
            tcg_gen_ext16u_i64(dest, source);
            break;
        case 4:
            tcg_gen_ext32u_i64(dest, source);
            break;
        default:
            g_assert_not_reached();
        }
        break;
    case IA64_EXT_SXT:
        switch (slot->width) {
        case 1:
            tcg_gen_ext8s_i64(dest, source);
            break;
        case 2:
            tcg_gen_ext16s_i64(dest, source);
            break;
        case 4:
            tcg_gen_ext32s_i64(dest, source);
            break;
        default:
            g_assert_not_reached();
        }
        break;
    default:
        g_assert_not_reached();
    }
}

static void ia64_tr_emit_predicate_test(DisasContext *ctx,
                                        const IA64TcgFastSlot *slot,
                                        TCGv_i64 result, TCGv_i64 source3)
{
    switch (slot->predicate_test_kind) {
    case IA64_PRED_TEST_BIT:
        ia64_tr_load_static_gr(ctx, source3, slot->source3);
        tcg_gen_shri_i64(result, source3, slot->immediate);
        tcg_gen_andi_i64(result, result, 1);
        break;
    case IA64_PRED_TEST_NAT:
        ia64_tr_read_static_gr_nat(ctx, result, slot->source3);
        break;
    case IA64_PRED_TEST_FEATURE:
        tcg_gen_movi_i64(result, 0);
        break;
    default:
        g_assert_not_reached();
    }

    if (slot->predicate_test_relation == IA64_PRED_TEST_ZERO) {
        tcg_gen_xori_i64(result, result, 1);
    }
    ia64_tr_emit_predicate_pair_write(ctx, slot, result);
}

static void ia64_tr_emit_variable_shift(DisasContext *ctx,
                                        const IA64TcgFastSlot *slot,
                                        TCGv_i64 result,
                                        TCGv_i64 source2,
                                        TCGv_i64 source3)
{
    TCGLabel *done = gen_new_label();

    switch (slot->shift_kind) {
    case IA64_TCG_FAST_SHIFT_LEFT:
        ia64_tr_load_static_gr(ctx, source2, slot->source2);
        ia64_tr_load_static_gr(ctx, source3, slot->source3);
        tcg_gen_movi_i64(result, 0);
        tcg_gen_brcondi_i64(TCG_COND_GEU, source3, 64, done);
        tcg_gen_shl_i64(result, source2, source3);
        break;
    case IA64_TCG_FAST_SHIFT_RIGHT_UNSIGNED:
        ia64_tr_load_static_gr(ctx, source2, slot->source2);
        ia64_tr_load_static_gr(ctx, source3, slot->source3);
        tcg_gen_movi_i64(result, 0);
        tcg_gen_brcondi_i64(TCG_COND_GEU, source2, 64, done);
        tcg_gen_shr_i64(result, source3, source2);
        break;
    case IA64_TCG_FAST_SHIFT_RIGHT_SIGNED:
        ia64_tr_load_static_gr(ctx, source2, slot->source2);
        ia64_tr_load_static_gr(ctx, source3, slot->source3);
        tcg_gen_sari_i64(result, source3, 63);
        tcg_gen_brcondi_i64(TCG_COND_GEU, source2, 64, done);
        tcg_gen_sar_i64(result, source3, source2);
        break;
    default:
        g_assert_not_reached();
    }

    gen_set_label(done);
}

static void ia64_tr_load_fast_source2(DisasContext *ctx, TCGv_i64 dest,
                                      const IA64TcgFastSlot *slot)
{
    if (slot->source2_immediate) {
        tcg_gen_movi_i64(dest, slot->immediate);
    } else {
        ia64_tr_load_static_gr(ctx, dest, slot->source2);
    }
}

static MemOp ia64_tr_ldst_memop(uint8_t width)
{
    /* IA-64 permits unaligned data access; the interpreter path assembles
       unaligned values bytewise, which matches unaligned SoftMMU ops. */
    switch (width) {
    case 1:
        return MO_UB;
    case 2:
        return MO_LEUW;
    case 4:
        return MO_LEUL;
    case 8:
        return MO_LEUQ;
    default:
        g_assert_not_reached();
    }
}

static int ia64_tr_data_mmu_index(DisasContext *ctx)
{
    return ia64_tcg_data_mmu_index_for_tb_flags(ctx->base.tb->flags);
}

static void ia64_tr_publish_memory_slot(DisasContext *ctx,
                                        const IA64TcgFastSlot *slot)
{
    uint64_t pc = ctx->base.pc_next - IA64_BUNDLE_SIZE;

    /*
     * The bundle has a single insn_start, so a fault inside the memory op
     * must find the executing slot in env->ri (see ia64_env_restore_ri).
     * Publish the decoded slot as well: data-fault delivery uses it to set
     * ISR.sp/ed for speculative loads.  The bundle-finish helper republishes
     * PSR.ri and clears the flag.
     */
    tcg_gen_st8_i32(tcg_constant_i32(slot->slot_index), tcg_env,
                    offsetof(CPUIA64State, ri));
    tcg_gen_st8_i32(tcg_constant_i32(1), tcg_env,
                    offsetof(CPUIA64State, ri_dirty));
    tcg_gen_st8_i32(tcg_constant_i32(1), tcg_env,
                    offsetof(CPUIA64State, current_slot_valid));
    tcg_gen_st8_i32(tcg_constant_i32(slot->slot_index), tcg_env,
                    offsetof(CPUIA64State, current_slot_ri));
    tcg_gen_st8_i32(tcg_constant_i32(slot->slot_type), tcg_env,
                    offsetof(CPUIA64State, current_slot_type));
    tcg_gen_st_i64(tcg_constant_i64(pc), tcg_env,
                   offsetof(CPUIA64State, current_slot_ip));
    tcg_gen_st_i64(tcg_constant_i64(slot->raw), tcg_env,
                   offsetof(CPUIA64State, current_slot_raw));
}

static void ia64_tr_emit_ldst_alat_invalidate(const IA64TcgFastSlot *slot,
                                              TCGv_i64 address)
{
    TCGLabel *skip = gen_new_label();
    TCGv_i32 valid = tcg_temp_new_i32();

    tcg_gen_ld_i32(valid, tcg_env,
                   offsetof(CPUIA64State, alat.valid_mask));
    tcg_gen_brcondi_i32(TCG_COND_EQ, valid, 0, skip);
    gen_helper_fast_ldst_alat_store(tcg_env, address,
                                    tcg_constant_i32(slot->width));
    gen_set_label(skip);
}

static void ia64_tr_emit_ldst_base_update(DisasContext *ctx,
                                          const IA64TcgFastSlot *slot,
                                          TCGv_i64 address)
{
    TCGv_i64 updated;

    if (!slot->base_update) {
        return;
    }

    updated = tcg_temp_new_i64();
    if (slot->update_from_register) {
        TCGv_i64 update = tcg_temp_new_i64();

        ia64_tr_load_static_gr(ctx, update, slot->update_source);
        tcg_gen_add_i64(updated, address, update);
    } else {
        tcg_gen_addi_i64(updated, address, slot->immediate);
    }
    ia64_tr_store_static_gr(ctx, slot->base, updated);
}

static void ia64_tr_load_br(DisasContext *ctx, TCGv_i64 value, uint8_t reg)
{
    if (ctx->state_cache_active) {
        tcg_gen_mov_i64(value, ia64_tr_ensure_br(ctx, reg));
    } else {
        tcg_gen_ld_i64(value, tcg_env,
                       offsetof(CPUIA64State, br) +
                       reg * sizeof(uint64_t));
    }
}

static void ia64_tr_store_br(DisasContext *ctx, uint8_t reg, TCGv_i64 value)
{
    if (ctx->state_cache_active) {
        uint8_t bit = 1u << reg;

        if (ctx->br[reg] == NULL) {
            ctx->br[reg] = tcg_temp_new_i64();
        }
        tcg_gen_mov_i64(ctx->br[reg], value);
        ctx->br_valid |= bit;
        ctx->br_dirty |= bit;
    } else {
        tcg_gen_st_i64(value, tcg_env,
                       offsetof(CPUIA64State, br) +
                       reg * sizeof(uint64_t));
    }
}

static void ia64_tr_load_ar(DisasContext *ctx, TCGv_i64 value, uint8_t reg)
{
    if (ctx->state_cache_active) {
        tcg_gen_mov_i64(value, ia64_tr_ensure_ar(ctx, reg));
    } else {
        tcg_gen_ld_i64(value, tcg_env,
                       offsetof(CPUIA64State, ar) +
                       reg * sizeof(uint64_t));
    }
}

static void ia64_tr_store_ar(DisasContext *ctx, uint8_t reg, TCGv_i64 value)
{
    if (ctx->state_cache_active) {
        unsigned word = reg >> 6;
        uint64_t bit = UINT64_C(1) << (reg & 63);

        if (ctx->ar[reg] == NULL) {
            ctx->ar[reg] = tcg_temp_new_i64();
        }
        tcg_gen_mov_i64(ctx->ar[reg], value);
        ctx->ar_valid[word] |= bit;
        ctx->ar_dirty[word] |= bit;
    } else {
        tcg_gen_st_i64(value, tcg_env,
                       offsetof(CPUIA64State, ar) +
                       reg * sizeof(uint64_t));
    }
}

static void ia64_tr_prime_predicated_slot_state(
    DisasContext *ctx, const IA64TcgFastSlot *slot)
{
    uint64_t gr_mask;
    uint64_t nat_mask;

    if (!ctx->state_cache_active || slot->qualifying_predicate == 0) {
        return;
    }

    /* Loads must execute before the predicate branch on both runtime arms. */
    ia64_tr_ensure_pr(ctx);
    gr_mask = (slot->source_nat_mask | slot->dest_mask) & UINT32_MAX &
              ~UINT64_C(1);
    while (gr_mask != 0) {
        unsigned reg = ctz64(gr_mask);

        ia64_tr_ensure_static_gr(ctx, reg);
        gr_mask &= gr_mask - 1;
    }

    nat_mask = slot->source_nat_mask & UINT32_MAX & ~UINT64_C(1);
    if (ctx->inline_gr_nat_clear) {
        nat_mask |= slot->dest_mask & UINT32_MAX & ~UINT64_C(1);
    }
    if (nat_mask != 0) {
        ia64_tr_ensure_gr_nat(ctx);
    }

    switch (slot->op) {
    case IA64_TCG_FAST_OP_MOV_FROM_BR:
    case IA64_TCG_FAST_OP_MOV_TO_BR:
        ia64_tr_ensure_br(ctx, slot->system_reg);
        break;
    case IA64_TCG_FAST_OP_MOV_FROM_AR:
    case IA64_TCG_FAST_OP_MOV_TO_AR:
        ia64_tr_ensure_ar(ctx, slot->system_reg);
        break;
    default:
        break;
    }
}

static TCGLabel *ia64_tr_emit_fast_slot_predicate_guard(
    DisasContext *ctx, const IA64TcgFastSlot *slot)
{
    TCGLabel *skip;
    TCGv_i64 pr;

    if (slot->qualifying_predicate == 0 || slot->op == IA64_TCG_FAST_OP_NOP) {
        return NULL;
    }

    skip = gen_new_label();
    pr = tcg_temp_new_i64();
    ia64_tr_load_predicate(ctx, pr, slot->qualifying_predicate);
    tcg_gen_brcondi_i64(TCG_COND_EQ, pr, 0, skip);
    return skip;
}

static void ia64_tr_finish_fast_slot_predicate_guard(TCGLabel *skip)
{
    if (skip != NULL) {
        gen_set_label(skip);
    }
}

static void ia64_tr_note_runtime_dest(const IA64TcgFastSlot *slot,
                                      TCGv_i64 runtime_dest_mask,
                                      TCGv_i64 runtime_dest_mask_hi)
{
    if (runtime_dest_mask != NULL && slot->finalize_mask != 0) {
        tcg_gen_ori_i64(runtime_dest_mask, runtime_dest_mask,
                        slot->finalize_mask);
    }
    if (runtime_dest_mask_hi != NULL && slot->finalize_mask_hi != 0) {
        tcg_gen_ori_i64(runtime_dest_mask_hi, runtime_dest_mask_hi,
                        slot->finalize_mask_hi);
    }
}

static void ia64_tr_emit_fast_alloc(DisasContext *ctx,
                                    const IA64TcgFastSlot *slot,
                                    TCGv_i64 runtime_dest_mask,
                                    TCGv_i64 runtime_dest_mask_hi)
{
    uint64_t raw = (uint64_t)slot->immediate;
    uint32_t sof = (raw >> 13) & 0x7f;
    uint32_t sol = (raw >> 20) & 0x7f;
    uint32_t sor = (raw >> 27) & 0x0f;
    uint64_t cfm = ia64_make_cfm(sof, sol, sor);
    TCGLabel *fast = gen_new_label();
    TCGLabel *done = gen_new_label();
    TCGv_i64 bspstore = tcg_temp_new_i64();
    TCGv_i64 bsp = tcg_temp_new_i64();
    TCGv_i64 slots = tcg_temp_new_i64();
    TCGv_i64 dirty = tcg_temp_new_i64();
    TCGv_i64 tmp = tcg_temp_new_i64();
    TCGv_i64 old_pfs = tcg_temp_new_i64();

    tcg_gen_ld_i64(bspstore, tcg_env,
                   offsetof(CPUIA64State, rse.bspstore));
    tcg_gen_brcondi_i64(TCG_COND_EQ, bspstore, 0, fast);
    tcg_gen_ld_i64(bsp, tcg_env, offsetof(CPUIA64State, rse.bsp));
    tcg_gen_brcond_i64(TCG_COND_LEU, bsp, bspstore, fast);
    tcg_gen_sub_i64(slots, bsp, bspstore);
    tcg_gen_shri_i64(slots, slots, 3);
    tcg_gen_shri_i64(tmp, bspstore, 3);
    tcg_gen_andi_i64(tmp, tmp, 0x3f);
    tcg_gen_add_i64(tmp, tmp, slots);
    tcg_gen_shri_i64(tmp, tmp, 6);
    tcg_gen_sub_i64(dirty, slots, tmp);
    tcg_gen_addi_i64(dirty, dirty, sof);
    tcg_gen_brcondi_i64(TCG_COND_LEU, dirty,
                        IA64_RSE_PHYS_STACKED_REGS, fast);

    ia64_tr_commit_ip(ctx->base.pc_next - IA64_BUNDLE_SIZE);
    gen_helper_fast_alloc(tcg_env, tcg_constant_i64(raw));
    tcg_gen_br(done);

    gen_set_label(fast);
    tcg_gen_ld_i64(old_pfs, tcg_env,
                   offsetof(CPUIA64State, ar) +
                   IA64_AR_PFS * sizeof(uint64_t));
    tcg_gen_st_i64(tcg_constant_i64(cfm), tcg_env,
                   offsetof(CPUIA64State, cfm));
    tcg_gen_st_i32(tcg_constant_i32(sof), tcg_env,
                   offsetof(CPUIA64State, rse.sof));
    tcg_gen_st_i32(tcg_constant_i32(sol), tcg_env,
                   offsetof(CPUIA64State, rse.sol));
    tcg_gen_st_i32(tcg_constant_i32(sor), tcg_env,
                   offsetof(CPUIA64State, rse.sor));
    tcg_gen_st_i32(tcg_constant_i32(0), tcg_env,
                   offsetof(CPUIA64State, rse.rrb_gr));
    tcg_gen_st_i32(tcg_constant_i32(0), tcg_env,
                   offsetof(CPUIA64State, rse.rrb_fr));
    tcg_gen_st_i32(tcg_constant_i32(0), tcg_env,
                   offsetof(CPUIA64State, rse.rrb_pr));
    ia64_tr_store_static_gr(ctx, slot->target, old_pfs);

    gen_set_label(done);
    ia64_tr_note_runtime_dest(slot, runtime_dest_mask,
                              runtime_dest_mask_hi);
}

static void ia64_tr_emit_fast_slot(DisasContext *ctx,
                                   const IA64TcgFastSlot *slot,
                                   TCGv_i64 ldst_address,
                                   TCGv_i64 runtime_dest_mask,
                                   TCGv_i64 runtime_dest_mask_hi)
{
    TCGLabel *skip;
    TCGv_i64 result;
    TCGv_i64 source2;
    TCGv_i64 source3;

    if (slot->op == IA64_TCG_FAST_OP_NOP) {
        return;
    }

    ia64_tr_prime_predicated_slot_state(ctx, slot);
    skip = ia64_tr_emit_fast_slot_predicate_guard(ctx, slot);
    result = tcg_temp_new_i64();
    source2 = tcg_temp_new_i64();
    source3 = tcg_temp_new_i64();

    switch (slot->op) {
    case IA64_TCG_FAST_OP_ALU_ADD:
        ia64_tr_load_static_gr(ctx, source3, slot->source3);
        if (slot->source2_immediate) {
            tcg_gen_addi_i64(result, source3, slot->immediate);
        } else {
            ia64_tr_load_static_gr(ctx, source2, slot->source2);
            tcg_gen_add_i64(result, source2, source3);
            if (slot->immediate != 0) {
                tcg_gen_addi_i64(result, result, slot->immediate);
            }
        }
        break;
    case IA64_TCG_FAST_OP_ALU_SUB:
        ia64_tr_load_static_gr(ctx, source3, slot->source3);
        if (slot->source2_immediate) {
            tcg_gen_movi_i64(source2, slot->immediate);
        } else {
            ia64_tr_load_static_gr(ctx, source2, slot->source2);
        }
        tcg_gen_sub_i64(result, source2, source3);
        if (!slot->source2_immediate && slot->immediate != 0) {
            tcg_gen_subi_i64(result, result, slot->immediate);
        }
        break;
    case IA64_TCG_FAST_OP_ALU_LOGIC:
        ia64_tr_load_static_gr(ctx, source3, slot->source3);
        ia64_tr_load_fast_source2(ctx, source2, slot);
        switch (slot->logic_op) {
        case IA64_TCG_FAST_LOGIC_AND:
            tcg_gen_and_i64(result, source2, source3);
            break;
        case IA64_TCG_FAST_LOGIC_ANDCM:
            tcg_gen_andc_i64(result, source2, source3);
            break;
        case IA64_TCG_FAST_LOGIC_OR:
            tcg_gen_or_i64(result, source2, source3);
            break;
        case IA64_TCG_FAST_LOGIC_XOR:
            tcg_gen_xor_i64(result, source2, source3);
            break;
        default:
            g_assert_not_reached();
        }
        break;
    case IA64_TCG_FAST_OP_ALU_ADDP4:
        ia64_tr_load_static_gr(ctx, source3, slot->source3);
        ia64_tr_load_fast_source2(ctx, source2, slot);
        ia64_tr_emit_addp4(result, source2, source3);
        break;
    case IA64_TCG_FAST_OP_ALU_SHLADD:
        ia64_tr_load_static_gr(ctx, source2, slot->source2);
        ia64_tr_load_static_gr(ctx, source3, slot->source3);
        tcg_gen_shli_i64(source2, source2, slot->immediate);
        if (slot->addp4) {
            ia64_tr_emit_addp4(result, source2, source3);
        } else {
            tcg_gen_add_i64(result, source2, source3);
        }
        break;
    case IA64_TCG_FAST_OP_ADDL:
        ia64_tr_load_static_gr(ctx, source3, slot->source3);
        tcg_gen_addi_i64(result, source3, slot->immediate);
        break;
    case IA64_TCG_FAST_OP_COMPARE:
        if (slot->source2_immediate) {
            tcg_gen_movi_i64(source2, slot->immediate);
        } else {
            ia64_tr_load_static_gr(ctx, source2, slot->source2);
        }
        ia64_tr_load_static_gr(ctx, source3, slot->source3);
        if (slot->width == 4) {
            if (ia64_tr_compare_relation_is_signed(slot->compare_relation)) {
                tcg_gen_ext32s_i64(source2, source2);
                tcg_gen_ext32s_i64(source3, source3);
            } else {
                tcg_gen_ext32u_i64(source2, source2);
                tcg_gen_ext32u_i64(source3, source3);
            }
        }
        tcg_gen_setcond_i64(ia64_tr_compare_cond(slot->compare_relation),
                            result, source2, source3);
        ia64_tr_emit_predicate_pair_write(ctx, slot, result);
        ia64_tr_finish_fast_slot_predicate_guard(skip);
        return;
    case IA64_TCG_FAST_OP_EXTRACT:
        ia64_tr_load_static_gr(ctx, source3, slot->source3);
        if (slot->sign_extend) {
            tcg_gen_sextract_i64(result, source3,
                                 slot->position, slot->length);
        } else {
            tcg_gen_extract_i64(result, source3,
                                slot->position, slot->length);
        }
        break;
    case IA64_TCG_FAST_OP_DEPOSIT:
        ia64_tr_load_fast_source2(ctx, source2, slot);
        if (slot->deposit_zero) {
            tcg_gen_deposit_z_i64(result, source2,
                                  slot->position, slot->length);
        } else {
            ia64_tr_load_static_gr(ctx, source3, slot->source3);
            tcg_gen_deposit_i64(result, source3, source2,
                                slot->position, slot->length);
        }
        break;
    case IA64_TCG_FAST_OP_INTEGER_EXTEND:
        ia64_tr_load_static_gr(ctx, source3, slot->source3);
        ia64_tr_emit_integer_extend(slot, result, source3);
        break;
    case IA64_TCG_FAST_OP_PREDICATE_TEST:
        ia64_tr_emit_predicate_test(ctx, slot, result, source3);
        ia64_tr_finish_fast_slot_predicate_guard(skip);
        return;
    case IA64_TCG_FAST_OP_BIT_COUNT:
        ia64_tr_load_static_gr(ctx, source3, slot->source3);
        if (slot->shift_kind == 2) {
            tcg_gen_ctpop_i64(result, source3);
        } else {
            tcg_gen_clzi_i64(result, source3, 64);
        }
        break;
    case IA64_TCG_FAST_OP_VARIABLE_SHIFT:
        ia64_tr_emit_variable_shift(ctx, slot, result, source2, source3);
        break;
    case IA64_TCG_FAST_OP_MOV_FROM_BR:
        ia64_tr_load_br(ctx, result, slot->system_reg);
        break;
    case IA64_TCG_FAST_OP_MOV_TO_BR:
        ia64_tr_load_static_gr(ctx, source2, slot->source2);
        ia64_tr_store_br(ctx, slot->system_reg, source2);
        ia64_tr_finish_fast_slot_predicate_guard(skip);
        return;
    case IA64_TCG_FAST_OP_MOV_FROM_AR:
        ia64_tr_load_ar(ctx, result, slot->system_reg);
        break;
    case IA64_TCG_FAST_OP_MOV_TO_AR:
        ia64_tr_load_fast_source2(ctx, source2, slot);
        ia64_tr_store_ar(ctx, slot->system_reg, source2);
        ia64_tr_finish_fast_slot_predicate_guard(skip);
        return;
    case IA64_TCG_FAST_OP_ALLOC:
        ia64_tr_emit_fast_alloc(ctx, slot, runtime_dest_mask,
                                runtime_dest_mask_hi);
        ia64_tr_finish_fast_slot_predicate_guard(skip);
        return;
    case IA64_TCG_FAST_OP_MOVL:
        tcg_gen_movi_i64(result, (uint64_t)slot->immediate);
        break;
    case IA64_TCG_FAST_OP_FP_SLOT:
        gen_helper_fast_fp_slot(tcg_env,
                                tcg_constant_i32(slot->slot_type),
                                tcg_constant_i64(slot->raw),
                                tcg_constant_i32(slot->slot_index));
        ia64_tr_note_runtime_dest(slot, runtime_dest_mask,
                                  runtime_dest_mask_hi);
        ia64_tr_finish_fast_slot_predicate_guard(skip);
        return;
    case IA64_TCG_FAST_OP_LDST_LOAD:
    {
        bool prepare = slot->memory_class == 1 ||
                       slot->memory_class == 3 ||
                       slot->memory_class == 8 ||
                       slot->memory_class == 9 ||
                       slot->memory_class == 0x0a;
        bool special = slot->memory_class != 0 &&
                       slot->memory_class != 4 &&
                       slot->memory_class != 5;
        TCGLabel *memory_done = special ? gen_new_label() : NULL;

        g_assert(ldst_address != NULL);
        if (prepare) {
            TCGv_i32 deferred = tcg_temp_new_i32();

            gen_helper_fast_ldst_prepare(
                deferred, tcg_env, ldst_address,
                tcg_constant_i32(slot->target),
                tcg_constant_i32(slot->width),
                tcg_constant_i32(slot->memory_class));
            tcg_gen_brcondi_i32(TCG_COND_NE, deferred, 0, memory_done);
        }
        if (ia64_tcg_fast_ldst_mode() == IA64_TCG_FAST_LDST_DIRECT) {
            ia64_tr_publish_memory_slot(ctx, slot);
            tcg_gen_qemu_ld_i64(result, ldst_address,
                                ia64_tr_data_mmu_index(ctx),
                                ia64_tr_ldst_memop(slot->width));
        } else {
            gen_helper_fast_ldst_load(result, tcg_env, ldst_address,
                                      tcg_constant_i32(slot->width),
                                      tcg_constant_i32(slot->slot_index));
        }
        ia64_tr_store_static_gr(ctx, slot->target, result);
        if (slot->memory_class == 6) {
            ia64_tr_emit_fill_nat(ctx, slot, ldst_address);
        } else if (special) {
            gen_helper_fast_ldst_complete(
                tcg_env, ldst_address,
                tcg_constant_i32(slot->target),
                tcg_constant_i32(slot->width),
                tcg_constant_i32(slot->memory_class));
        }
        if (memory_done != NULL) {
            gen_set_label(memory_done);
        }
        ia64_tr_emit_ldst_base_update(ctx, slot, ldst_address);
        ia64_tr_note_runtime_dest(slot, runtime_dest_mask,
                                  runtime_dest_mask_hi);
        ia64_tr_finish_fast_slot_predicate_guard(skip);
        return;
    }
    case IA64_TCG_FAST_OP_LDST_STORE:
        g_assert(ldst_address != NULL);
        ia64_tr_load_static_gr(ctx, source2, slot->source2);
        if (ia64_tcg_fast_ldst_mode() == IA64_TCG_FAST_LDST_DIRECT) {
            ia64_tr_publish_memory_slot(ctx, slot);
            tcg_gen_qemu_st_i64(source2, ldst_address,
                                ia64_tr_data_mmu_index(ctx),
                                ia64_tr_ldst_memop(slot->width));
            ia64_tr_emit_ldst_alat_invalidate(slot, ldst_address);
        } else {
            gen_helper_fast_ldst_store(tcg_env, ldst_address, source2,
                                       tcg_constant_i32(slot->width),
                                       tcg_constant_i32(slot->slot_index));
        }
        if (slot->memory_class == 0x0e) {
            ia64_tr_emit_spill_unat(ctx, slot, ldst_address);
        }
        ia64_tr_emit_ldst_base_update(ctx, slot, ldst_address);
        ia64_tr_note_runtime_dest(slot, runtime_dest_mask,
                                  runtime_dest_mask_hi);
        ia64_tr_finish_fast_slot_predicate_guard(skip);
        return;
    default:
        g_assert_not_reached();
    }

    ia64_tr_store_static_gr(ctx, slot->target, result);
    ia64_tr_note_runtime_dest(slot, runtime_dest_mask, runtime_dest_mask_hi);
    ia64_tr_finish_fast_slot_predicate_guard(skip);
}

static bool ia64_tr_fast_bundle_has_ldst(const IA64TcgFastBundle *fast)
{
    return ia64_perf_fast_count(fast->op_counts,
                                IA64_PERF_FAST_COUNT_LDST_LOAD_SHIFT) != 0 ||
           ia64_perf_fast_count(fast->op_counts,
                                IA64_PERF_FAST_COUNT_LDST_STORE_SHIFT) != 0;
}

static bool ia64_tr_fast_bundle_has_required_helper(
    const IA64TcgFastBundle *fast)
{
    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        IA64TcgFastOp op = fast->slot[slot].op;
        bool speculative_prepare =
            op == IA64_TCG_FAST_OP_LDST_LOAD &&
            (fast->slot[slot].memory_class == 1 ||
             fast->slot[slot].memory_class == 3);
        bool ldst_helper = ia64_tcg_fast_ldst_mode() ==
                           IA64_TCG_FAST_LDST_HELPER &&
                           (op == IA64_TCG_FAST_OP_LDST_LOAD ||
                            op == IA64_TCG_FAST_OP_LDST_STORE);

        /*
         * Control-speculative preparation consults the current instruction
         * page's ED attribute through env->ip even in direct qemu_ld mode.
         * A multi-bundle TB may otherwise leave env->ip at an older bundle.
         */
        if (op == IA64_TCG_FAST_OP_FP_SLOT || speculative_prepare ||
            ldst_helper) {
            return true;
        }
    }
    return false;
}

static bool ia64_tr_fast_bundle_uses_stacked_gr(const IA64TcgFastBundle *fast)
{
    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        if (fast->slot[slot].uses_stacked_gr) {
            return true;
        }
    }
    return false;
}

static bool ia64_tr_fast_bundle_needs_runtime_fallback(
    const IA64TcgFastBundle *fast)
{
    return ia64_tr_fast_bundle_uses_stacked_gr(fast) ||
           fast->source_nat_mask != 0 || fast->source_nat_mask_hi != 0;
}

static bool ia64_tr_fast_bundle_requires_state_barrier(
    const IA64TcgFastBundle *fast)
{
    if (ia64_tr_fast_bundle_has_ldst(fast) ||
        ia64_tr_fast_bundle_has_required_helper(fast)) {
        return true;
    }
    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        if (fast->slot[slot].op == IA64_TCG_FAST_OP_ALLOC) {
            return true;
        }
    }
    return false;
}

static void ia64_tr_emit_fast_nat_guards(DisasContext *ctx,
                                         uint64_t source_mask,
                                         uint64_t source_mask_hi,
                                         TCGLabel *fallback)
{
    uint64_t static_mask = source_mask & UINT32_MAX & ~UINT64_C(1);

    if (static_mask != 0) {
        TCGv_i64 nat = tcg_temp_new_i64();

        if (ctx->state_cache_active) {
            tcg_gen_mov_i64(nat, ia64_tr_ensure_gr_nat(ctx));
        } else {
            tcg_gen_ld_i64(nat, tcg_env,
                           offsetof(CPUIA64State, nat.gr_nat));
        }
        tcg_gen_andi_i64(nat, nat, static_mask);
        tcg_gen_brcondi_i64(TCG_COND_NE, nat, 0, fallback);
    }

    source_mask &= ~UINT64_C(0xffffffff);
    while (source_mask != 0) {
        unsigned reg = ctz64(source_mask);
        TCGv_ptr ptr = tcg_temp_new_ptr();
        TCGv_i64 bit = tcg_temp_new_i64();
        TCGv_i64 nat = tcg_temp_new_i64();

        ia64_tr_stacked_nat_address(ctx, ptr, bit, reg);
        tcg_gen_ld_i64(nat, ptr, 0);
        tcg_gen_and_i64(nat, nat, bit);
        tcg_gen_brcondi_i64(TCG_COND_NE, nat, 0, fallback);
        source_mask &= source_mask - 1;
    }
    while (source_mask_hi != 0) {
        unsigned reg = 64 + ctz64(source_mask_hi);
        TCGv_ptr ptr = tcg_temp_new_ptr();
        TCGv_i64 bit = tcg_temp_new_i64();
        TCGv_i64 nat = tcg_temp_new_i64();

        ia64_tr_stacked_nat_address(ctx, ptr, bit, reg);
        tcg_gen_ld_i64(nat, ptr, 0);
        tcg_gen_and_i64(nat, nat, bit);
        tcg_gen_brcondi_i64(TCG_COND_NE, nat, 0, fallback);
        source_mask_hi &= source_mask_hi - 1;
    }
}

static void ia64_tr_emit_fast_bundle_guards(
    DisasContext *ctx, const IA64TcgFastBundle *fast, TCGLabel *fallback,
    TCGv_i64 ldst_address[IA64_SLOT_COUNT], bool zero_helper)
{
    if ((fast->source_nat_mask | fast->source_nat_mask_hi) != 0) {
        if (zero_helper) {
            ia64_tr_emit_fast_nat_guards(ctx, fast->source_nat_mask,
                                         fast->source_nat_mask_hi, fallback);
        } else {
            TCGv_i32 nat = tcg_temp_new_i32();

            gen_helper_fast_gr_nat_any(
                nat, tcg_env, tcg_constant_i64(fast->source_nat_mask),
                tcg_constant_i64(fast->source_nat_mask_hi));
            tcg_gen_brcondi_i32(TCG_COND_NE, nat, 0, fallback);
        }
    }
    if (ia64_tr_fast_bundle_uses_stacked_gr(fast)) {
        TCGv_i32 sor = tcg_temp_new_i32();

        ia64_tr_ensure_stacked_frame_base(ctx);
        tcg_gen_ld_i32(sor, tcg_env, offsetof(CPUIA64State, rse.sor));
        tcg_gen_brcondi_i32(TCG_COND_NE, sor, 0, fallback);
    }
    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        if (fast->slot[slot].op == IA64_TCG_FAST_OP_LDST_LOAD ||
            fast->slot[slot].op == IA64_TCG_FAST_OP_LDST_STORE) {
            ldst_address[slot] = tcg_temp_new_i64();
            ia64_tr_load_static_gr(ctx, ldst_address[slot],
                                   fast->slot[slot].base);
        }
    }
}

static void ia64_tr_emit_gr_alat_invalidate(TCGv_i64 dest_mask,
                                            TCGv_i64 dest_mask_hi,
                                            uint64_t pc)
{
    TCGLabel *done = gen_new_label();
    TCGLabel *nonzero = gen_new_label();
    TCGv_i32 valid = tcg_temp_new_i32();

    tcg_gen_brcondi_i64(TCG_COND_NE, dest_mask, 0, nonzero);
    tcg_gen_brcondi_i64(TCG_COND_EQ, dest_mask_hi, 0, done);
    gen_set_label(nonzero);
    tcg_gen_ld_i32(valid, tcg_env,
                   offsetof(CPUIA64State, alat.valid_mask));
    tcg_gen_brcondi_i32(TCG_COND_EQ, valid, 0, done);
    ia64_tr_commit_ip(pc);
    gen_helper_fast_gr_alat_invalidate(tcg_env, dest_mask, dest_mask_hi);
    gen_set_label(done);
}

static bool ia64_tr_translate_fast_bundle(DisasContext *ctx,
                                          const IA64DecodedBundle *bundle,
                                          uint64_t pc)
{
    IA64TcgFastBundle fast;
    IA64TrStateCacheDirty dirty_before = { 0 };
    TCGLabel *fallback;
    TCGLabel *done;
    TCGv_i64 runtime_dest_mask;
    TCGv_i64 runtime_dest_mask_hi;
    TCGv_i64 ldst_address[IA64_SLOT_COUNT] = { NULL, };
    bool has_ldst;
    bool cached_fallback;
    bool cache_suspended;
    bool needs_fallback;
    bool zero_helper;

    if (ia64_tcg_fast_disabled(IA64_TCG_FAST_DISABLE_BUNDLE)) {
        return false;
    }
    if (!ia64_tcg_build_fast_bundle(bundle, &fast)) {
        return false;
    }
    if (ia64_tcg_tb_flags_ri(ctx->base.tb->flags) != 0) {
        return false;
    }

    has_ldst = ia64_tr_fast_bundle_has_ldst(&fast);
    if (has_ldst && !ia64_tcg_fast_ldst_memory_inline_enabled()) {
        return false;
    }
    zero_helper = ia64_tr_use_zero_helper_path();
    ia64_tr_profile_add(
        ctx,
        zero_helper && !ia64_tr_fast_bundle_has_required_helper(&fast) ?
            IA64_PROFILE_BUNDLE_ZERO_HELPER :
            IA64_PROFILE_BUNDLE_HELPER_FAST,
        1);
    needs_fallback = ia64_tr_fast_bundle_needs_runtime_fallback(&fast);
    if (ctx->state_cache_active) {
        ia64_tr_capture_state_cache_dirty(ctx, &dirty_before);
    }
    cache_suspended = ctx->state_cache_active &&
                      ia64_tr_fast_bundle_requires_state_barrier(&fast);
    cached_fallback = ctx->state_cache_active && needs_fallback &&
                      !cache_suspended;
    if (cache_suspended) {
        ia64_tr_suspend_state_cache(ctx);
    }
    fallback = needs_fallback ? gen_new_label() : NULL;
    done = needs_fallback ? gen_new_label() : NULL;
    runtime_dest_mask = tcg_temp_new_i64();
    runtime_dest_mask_hi = tcg_temp_new_i64();

    if (needs_fallback) {
        ia64_tr_emit_fast_bundle_guards(ctx, &fast, fallback, ldst_address,
                                        zero_helper);
    } else if (has_ldst) {
        for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
            if (fast.slot[slot].op == IA64_TCG_FAST_OP_LDST_LOAD ||
                fast.slot[slot].op == IA64_TCG_FAST_OP_LDST_STORE) {
                ldst_address[slot] = tcg_temp_new_i64();
                ia64_tr_load_static_gr(ctx, ldst_address[slot],
                                       fast.slot[slot].base);
            }
        }
    }

    if (!zero_helper) {
        tcg_gen_movi_i64(cpu_ip, pc);
    } else if (ia64_tr_fast_bundle_has_required_helper(&fast)) {
        ia64_tr_commit_ip(pc);
    }
    tcg_gen_movi_i64(runtime_dest_mask, 0);
    tcg_gen_movi_i64(runtime_dest_mask_hi, 0);
    if (ia64_perf_enabled() || ia64_debug_hooks_active() ||
        ia64_firmware_linux_cmdline_append_pending()) {
        gen_helper_start_fast_bundle(tcg_env,
                                     tcg_constant_i32(fast.slot_count),
                                     tcg_constant_i32(fast.op_counts));
    } else if (has_ldst) {
        ia64_tr_emit_can_do_io();
    }
    ctx->inline_gr_nat_clear = zero_helper;
    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        ia64_tr_emit_fast_slot(ctx, &fast.slot[slot], ldst_address[slot],
                               runtime_dest_mask, runtime_dest_mask_hi);
    }
    ctx->inline_gr_nat_clear = false;
    if (zero_helper) {
        ia64_tr_emit_gr_alat_invalidate(runtime_dest_mask,
                                        runtime_dest_mask_hi, pc);
    } else {
        gen_helper_finish_fast_bundle(
            tcg_env, tcg_constant_i64(pc + IA64_BUNDLE_SIZE),
            runtime_dest_mask, runtime_dest_mask_hi);
    }
    ia64_tr_note_fast_bundle(ctx);
    if (needs_fallback) {
        tcg_gen_br(done);

        gen_set_label(fallback);
        if (has_ldst && ia64_perf_enabled()) {
            gen_helper_perf_tcg_ldst_fallback();
        }
        if (cached_fallback) {
            ia64_tr_emit_exec_bundle_cached_fallback(
                ctx, bundle, pc, &dirty_before);
        } else {
            ia64_tr_emit_exec_bundle(ctx, bundle, pc);
        }
        gen_set_label(done);
    }
    ia64_tr_resume_state_cache(ctx, cache_suspended);
    return true;
}

static void ia64_tr_emit_exec_slot(DisasContext *ctx,
                                   const IA64DecodedBundle *bundle,
                                   uint64_t pc, unsigned slot,
                                   TCGLabel *flow_exit)
{
    IA64TcgFallbackPlan fallback_plan =
        ia64_tcg_fallback_plan_for_bundle(bundle);
    IA64TcgFallbackArgs fallback_args =
        ia64_tcg_fallback_args(bundle, &fallback_plan, slot);
    TCGv_i32 flow_changed = tcg_temp_new_i32();

    /* A fault in this slot must not lose earlier retired bundles in the TB. */
    ia64_tr_state_cache_barrier(ctx);
    ia64_tr_flush_fast_bundle_ticks(ctx);
    ia64_tr_commit_ip(pc);
    gen_helper_exec_slot(
        flow_changed, tcg_env,
        tcg_constant_i64(fallback_args.header),
        tcg_constant_i64(fallback_args.slot1),
        tcg_constant_i64(fallback_args.slot2),
        tcg_constant_i64(fallback_args.desc01),
        tcg_constant_i64(fallback_args.desc2));
    tcg_gen_brcondi_i32(TCG_COND_NE, flow_changed, 0, flow_exit);
}

static bool ia64_tr_partial_slot_needs_guard(const IA64TcgFastSlot *slot)
{
    return slot->uses_stacked_gr || slot->source_nat_mask != 0 ||
           slot->source_nat_mask_hi != 0;
}

static void ia64_tr_emit_partial_fast_slot(
    DisasContext *ctx, const IA64DecodedBundle *bundle,
    const IA64TcgFastSlot *slot, uint64_t pc, TCGv_i64 runtime_dest_mask,
    TCGv_i64 runtime_dest_mask_hi, TCGLabel *flow_exit)
{
    TCGLabel *helper = NULL;
    TCGLabel *done = NULL;
    TCGv_i64 ldst_address = NULL;

    if (ia64_tr_partial_slot_needs_guard(slot)) {
        helper = gen_new_label();
        done = gen_new_label();
        if ((slot->source_nat_mask | slot->source_nat_mask_hi) != 0) {
            ia64_tr_emit_fast_nat_guards(ctx, slot->source_nat_mask,
                                         slot->source_nat_mask_hi, helper);
        }
        if (slot->uses_stacked_gr) {
            TCGv_i32 sor = tcg_temp_new_i32();

            ia64_tr_ensure_stacked_frame_base(ctx);
            tcg_gen_ld_i32(sor, tcg_env, offsetof(CPUIA64State, rse.sor));
            tcg_gen_brcondi_i32(TCG_COND_NE, sor, 0, helper);
        }
    }

    if (slot->op == IA64_TCG_FAST_OP_LDST_LOAD ||
        slot->op == IA64_TCG_FAST_OP_LDST_STORE) {
        ldst_address = tcg_temp_new_i64();
        ia64_tr_load_static_gr(ctx, ldst_address, slot->base);
    }
    ia64_tr_emit_fast_slot(ctx, slot, ldst_address, runtime_dest_mask,
                           runtime_dest_mask_hi);

    if (helper != NULL) {
        tcg_gen_br(done);
        gen_set_label(helper);
        ia64_tr_emit_exec_slot(ctx, bundle, pc, slot->slot_index, flow_exit);
        gen_set_label(done);
    }
}

static bool ia64_tr_translate_partial_bundle(DisasContext *ctx,
                                             const IA64DecodedBundle *bundle,
                                             uint64_t pc)
{
    IA64TcgFastBundle partial;
    TCGLabel *flow_exit;
    TCGLabel *done;
    TCGv_i64 runtime_dest_mask;
    TCGv_i64 runtime_dest_mask_hi;
    bool cache_suspended;
    bool has_ldst;

    /* Keep detailed tracing on the complete-bundle correctness oracle. */
    if (!ia64_tr_use_zero_helper_path() ||
        !ia64_tcg_build_partial_bundle(bundle, &partial) ||
        ia64_tcg_tb_flags_ri(ctx->base.tb->flags) != 0) {
        return false;
    }

    has_ldst = ia64_tr_fast_bundle_has_ldst(&partial);
    if (has_ldst && !ia64_tcg_fast_ldst_memory_inline_enabled()) {
        return false;
    }

    ia64_tr_profile_add(ctx, IA64_PROFILE_BUNDLE_PARTIAL, 1);
    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        if ((partial.helper_mask & (1u << slot)) != 0) {
            ia64_tr_profile_add_family(
                ctx, IA64_PROFILE_FAMILY_PARTIAL,
                bundle->info->slot_type[slot], bundle->slot[slot]);
        }
    }

    cache_suspended = ctx->state_cache_active;
    if (cache_suspended) {
        ia64_tr_suspend_state_cache(ctx);
    }
    flow_exit = gen_new_label();
    done = gen_new_label();
    runtime_dest_mask = tcg_temp_new_i64();
    runtime_dest_mask_hi = tcg_temp_new_i64();
    tcg_gen_movi_i64(runtime_dest_mask, 0);
    tcg_gen_movi_i64(runtime_dest_mask_hi, 0);
    if (ia64_tr_fast_bundle_has_required_helper(&partial)) {
        ia64_tr_commit_ip(pc);
    }
    if (has_ldst) {
        ia64_tr_emit_can_do_io();
    }

    ctx->inline_gr_nat_clear = true;
    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        if ((partial.helper_mask & (1u << slot)) != 0) {
            ia64_tr_emit_exec_slot(ctx, bundle, pc, slot, flow_exit);
        } else {
            ia64_tr_emit_partial_fast_slot(
                ctx, bundle, &partial.slot[slot], pc, runtime_dest_mask,
                runtime_dest_mask_hi, flow_exit);
        }
    }
    ctx->inline_gr_nat_clear = false;

    ia64_tr_emit_gr_alat_invalidate(runtime_dest_mask,
                                    runtime_dest_mask_hi, pc);
    ia64_tr_note_fast_bundle(ctx);
    {
        TCGLabel *continue_exec = gen_new_label();
        TCGv_i32 request = tcg_temp_new_i32();

        /* Publish a precise post-bundle state before queued host work runs. */
        tcg_gen_ld8u_i32(request, tcg_env,
                         IA64_CPU_STATE_OFFSET(exit_request));
        tcg_gen_brcondi_i32(TCG_COND_EQ, request, 0, continue_exec);
        ia64_tr_commit_ip(pc + IA64_BUNDLE_SIZE);
        ia64_tr_flush_fast_bundle_ticks(ctx);
        ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_MAIN);
        tcg_gen_exit_tb(NULL, 0);
        gen_set_label(continue_exec);
    }
    tcg_gen_br(done);

    gen_set_label(flow_exit);
    ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_MAIN);
    tcg_gen_exit_tb(NULL, 0);
    gen_set_label(done);
    ia64_tr_resume_state_cache(ctx, cache_suspended);
    return true;
}

static void ia64_tr_emit_main_loop_exit(DisasContext *ctx)
{
    ia64_tr_sync_state_cache(ctx);
    ia64_tr_flush_fast_bundle_ticks(ctx);
    if (ia64_perf_enabled()) {
        gen_helper_perf_tb_exit_main_loop();
    }
    ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_MAIN);
    tcg_gen_exit_tb(NULL, 0);
}

static void ia64_tr_count_chained_exit(void)
{
    if (ia64_perf_enabled()) {
        gen_helper_perf_tb_exit_chained();
    }
}

static void ia64_tr_emit_exit_request_guard(TCGLabel *main_loop_exit)
{
    TCGv_i32 request = tcg_temp_new_i32();

    tcg_gen_ld8u_i32(request, tcg_env,
                     IA64_CPU_STATE_OFFSET(exit_request));
    tcg_gen_brcondi_i32(TCG_COND_NE, request, 0, main_loop_exit);
}

static void ia64_tr_emit_fallthrough_exit(DisasContext *ctx, uint64_t target)
{
    if (translator_use_goto_tb(&ctx->base, target)) {
        TCGLabel *main_loop_exit = gen_new_label();

        ia64_tr_sync_state_cache(ctx);
        if (ia64_tr_use_zero_helper_path()) {
            ia64_tr_commit_ip(target);
        } else {
            tcg_gen_movi_i64(cpu_ip, target);
        }
        ia64_tr_flush_fast_bundle_ticks(ctx);
        if (ia64_tr_use_zero_helper_path()) {
            ia64_tr_emit_exit_request_guard(main_loop_exit);
        }
        ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_DIRECT);
        ia64_tr_count_chained_exit();
        tcg_gen_goto_tb(0);
        tcg_gen_exit_tb(ctx->base.tb, 0);

        gen_set_label(main_loop_exit);
        ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_MAIN);
        tcg_gen_exit_tb(NULL, 0);
    } else {
        if (ia64_tr_use_zero_helper_path()) {
            ia64_tr_commit_ip(target);
        } else {
            tcg_gen_movi_i64(cpu_ip, target);
        }
        ia64_tr_emit_main_loop_exit(ctx);
    }
}

static void ia64_tr_emit_inline_direct_branch_exit(
    DisasContext *ctx, uint64_t target, int tb_slot, bool use_goto_tb)
{
    TCGLabel *main_loop_exit = gen_new_label();

    ia64_tr_sync_state_cache(ctx);
    ia64_tr_commit_ip(target);
    if (ctx->fast_bundle_ticks != NULL) {
        ia64_tr_emit_benchmark_retire(ctx->fast_bundle_ticks);
    }
    ia64_tr_emit_exit_request_guard(main_loop_exit);
    if (use_goto_tb) {
        ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_DIRECT);
        tcg_gen_goto_tb(tb_slot);
        tcg_gen_exit_tb(ctx->base.tb, tb_slot);
    } else {
        ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_LOOKUP);
        tcg_gen_lookup_and_goto_ptr();
    }

    gen_set_label(main_loop_exit);
    ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_MAIN);
    tcg_gen_exit_tb(NULL, 0);
}

static void ia64_tr_emit_inline_indirect_branch_exit(DisasContext *ctx,
                                                      TCGv_i64 target)
{
    TCGLabel *main_loop_exit = gen_new_label();

    ia64_tr_sync_state_cache(ctx);
    ia64_tr_commit_ip_value(target);
    if (ctx->fast_bundle_ticks != NULL) {
        ia64_tr_emit_benchmark_retire(ctx->fast_bundle_ticks);
    }
    ia64_tr_emit_exit_request_guard(main_loop_exit);
    ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_LOOKUP);
    tcg_gen_lookup_and_goto_ptr();

    gen_set_label(main_loop_exit);
    ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_MAIN);
    tcg_gen_exit_tb(NULL, 0);
}

static void ia64_tr_emit_chk_a_gr(const IA64TcgSpecCheck *check,
                                  TCGLabel *recovery,
                                  TCGLabel *fallthrough)
{
    TCGLabel *hit[IA64_ALAT_COUNT] = { NULL, };
    TCGLabel *common_hit = check->clear ? NULL : gen_new_label();
    TCGv_i32 valid_mask = tcg_temp_new_i32();

    tcg_gen_ld_i32(valid_mask, tcg_env,
                   offsetof(CPUIA64State, alat.valid_mask));
    tcg_gen_brcondi_i32(TCG_COND_EQ, valid_mask, 0, recovery);
    for (unsigned i = 0; i < IA64_ALAT_COUNT; i++) {
        TCGLabel *next = gen_new_label();
        TCGv_i32 valid = tcg_temp_new_i32();
        TCGv_i32 target = tcg_temp_new_i32();
        intptr_t entry = offsetof(CPUIA64State, alat.entries) +
                         i * sizeof(IA64AlatEntry);

        tcg_gen_andi_i32(valid, valid_mask, 1u << i);
        tcg_gen_brcondi_i32(TCG_COND_EQ, valid, 0, next);
        tcg_gen_ld8u_i32(target, tcg_env,
                         entry + offsetof(IA64AlatEntry, target));
        if (check->clear) {
            hit[i] = gen_new_label();
            tcg_gen_brcondi_i32(TCG_COND_EQ, target, check->source, hit[i]);
        } else {
            tcg_gen_brcondi_i32(TCG_COND_EQ, target, check->source,
                                common_hit);
        }
        gen_set_label(next);
    }
    tcg_gen_br(recovery);

    if (!check->clear) {
        gen_set_label(common_hit);
        tcg_gen_br(fallthrough);
        return;
    }
    for (unsigned i = 0; i < IA64_ALAT_COUNT; i++) {
        TCGv_i32 remaining = tcg_temp_new_i32();
        intptr_t entry = offsetof(CPUIA64State, alat.entries) +
                         i * sizeof(IA64AlatEntry);

        gen_set_label(hit[i]);
        tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                        entry + offsetof(IA64AlatEntry, valid));
        tcg_gen_andi_i32(remaining, valid_mask, ~(1u << i));
        tcg_gen_st_i32(remaining, tcg_env,
                       offsetof(CPUIA64State, alat.valid_mask));
        tcg_gen_br(fallthrough);
    }
}

static bool ia64_tr_translate_speculation_check(
    DisasContext *ctx, const IA64DecodedBundle *bundle, uint64_t pc)
{
    IA64TcgSpecCheck check;
    TCGLabel *fallback = NULL;
    TCGLabel *done = NULL;
    TCGLabel *fallthrough = gen_new_label();
    TCGLabel *recovery = gen_new_label();
    TCGv_i64 ldst_address[IA64_SLOT_COUNT] = { NULL, };
    TCGv_i64 runtime_dest_mask = tcg_temp_new_i64();
    TCGv_i64 runtime_dest_mask_hi = tcg_temp_new_i64();
    bool cache_suspended;
    bool has_ldst;
    bool needs_fallback;

    if (!ia64_tr_spec_check_enabled() || !ia64_tr_use_zero_helper_path() ||
        ia64_tcg_tb_flags_ri(ctx->base.tb->flags) != 0 ||
        !ia64_tcg_build_speculation_check(bundle, pc, &check)) {
        return false;
    }
    has_ldst = ia64_tr_fast_bundle_has_ldst(&check.surrounding);
    if (has_ldst && !ia64_tcg_fast_ldst_memory_inline_enabled()) {
        return false;
    }

    ia64_tr_profile_add(ctx, IA64_PROFILE_BUNDLE_ZERO_HELPER, 1);
    ia64_tr_profile_add(ctx, IA64_PROFILE_SPEC_CHECK_INLINE, 1);
    cache_suspended = ctx->state_cache_active;
    if (cache_suspended) {
        ia64_tr_suspend_state_cache(ctx);
    }
    needs_fallback = ia64_tr_fast_bundle_needs_runtime_fallback(
                         &check.surrounding) ||
                     (check.kind == IA64_TCG_SPEC_CHECK_GR_NAT &&
                      check.source >= IA64_STATIC_GR_COUNT);
    if (needs_fallback) {
        fallback = gen_new_label();
        done = gen_new_label();
        ia64_tr_emit_fast_bundle_guards(ctx, &check.surrounding, fallback,
                                        ldst_address, true);
        if (check.kind == IA64_TCG_SPEC_CHECK_GR_NAT &&
            check.source >= IA64_STATIC_GR_COUNT) {
            TCGv_i32 sor = tcg_temp_new_i32();

            tcg_gen_ld_i32(sor, tcg_env, offsetof(CPUIA64State, rse.sor));
            tcg_gen_brcondi_i32(TCG_COND_NE, sor, 0, fallback);
        }
    } else if (has_ldst) {
        for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
            IA64TcgFastOp op = check.surrounding.slot[slot].op;

            if (slot != check.slot &&
                (op == IA64_TCG_FAST_OP_LDST_LOAD ||
                 op == IA64_TCG_FAST_OP_LDST_STORE)) {
                ldst_address[slot] = tcg_temp_new_i64();
                ia64_tr_load_static_gr(
                    ctx, ldst_address[slot],
                    check.surrounding.slot[slot].base);
            }
        }
    }

    tcg_gen_movi_i64(runtime_dest_mask, 0);
    tcg_gen_movi_i64(runtime_dest_mask_hi, 0);
    if (has_ldst) {
        ia64_tr_emit_can_do_io();
    }
    if (ia64_tr_fast_bundle_has_required_helper(&check.surrounding)) {
        ia64_tr_commit_ip(pc);
    }
    ctx->inline_gr_nat_clear = true;
    for (int slot = 0; slot < check.slot; slot++) {
        ia64_tr_emit_fast_slot(ctx, &check.surrounding.slot[slot],
                               ldst_address[slot], runtime_dest_mask,
                               runtime_dest_mask_hi);
    }
    ia64_tr_emit_gr_alat_invalidate(runtime_dest_mask,
                                    runtime_dest_mask_hi, pc);
    tcg_gen_movi_i64(runtime_dest_mask, 0);
    tcg_gen_movi_i64(runtime_dest_mask_hi, 0);

    if (check.predicate != 0) {
        TCGv_i64 predicate = tcg_temp_new_i64();

        ia64_tr_load_predicate(ctx, predicate, check.predicate);
        tcg_gen_brcondi_i64(TCG_COND_EQ, predicate, 0, fallthrough);
    }
    switch (check.kind) {
    case IA64_TCG_SPEC_CHECK_GR_NAT:
    {
        TCGv_i64 nat = tcg_temp_new_i64();

        ia64_tr_read_static_gr_nat(ctx, nat, check.source);
        tcg_gen_brcondi_i64(TCG_COND_NE, nat, 0, recovery);
        tcg_gen_br(fallthrough);
        break;
    }
    case IA64_TCG_SPEC_CHECK_FR_NATVAL:
    {
        TCGLabel *not_natval = gen_new_label();
        TCGv_i64 significand = tcg_temp_new_i64();
        TCGv_i64 exponent = tcg_temp_new_i64();
        intptr_t fr = offsetof(CPUIA64State, fr) +
                      check.source * sizeof(IA64FloatReg);

        tcg_gen_ld_i64(significand, tcg_env,
                       fr + offsetof(IA64FloatReg, raw[0]));
        tcg_gen_brcondi_i64(TCG_COND_NE, significand, 0, not_natval);
        tcg_gen_ld_i64(exponent, tcg_env,
                       fr + offsetof(IA64FloatReg, raw[1]));
        tcg_gen_andi_i64(exponent, exponent, 0x3ffff);
        tcg_gen_brcondi_i64(TCG_COND_EQ, exponent, 0x1fffe, recovery);
        gen_set_label(not_natval);
        tcg_gen_br(fallthrough);
        break;
    }
    case IA64_TCG_SPEC_CHECK_GR_ALAT:
        ia64_tr_emit_chk_a_gr(&check, recovery, fallthrough);
        break;
    case IA64_TCG_SPEC_CHECK_FR_ALAT:
        /* The modeled FR ALAT is intentionally empty. */
        tcg_gen_br(recovery);
        break;
    default:
        g_assert_not_reached();
    }

    gen_set_label(recovery);
    ia64_tr_note_fast_bundle(ctx);
    ia64_tr_emit_inline_direct_branch_exit(ctx, check.target_ip, 0, false);

    gen_set_label(fallthrough);
    for (int slot = check.slot + 1; slot < IA64_SLOT_COUNT; slot++) {
        ia64_tr_emit_fast_slot(ctx, &check.surrounding.slot[slot],
                               ldst_address[slot], runtime_dest_mask,
                               runtime_dest_mask_hi);
    }
    ctx->inline_gr_nat_clear = false;
    ia64_tr_emit_gr_alat_invalidate(runtime_dest_mask,
                                    runtime_dest_mask_hi, pc);
    ia64_tr_note_fast_bundle(ctx);

    if (needs_fallback) {
        tcg_gen_br(done);
        gen_set_label(fallback);
        ia64_tr_emit_exec_bundle_lookup_ptr(ctx, bundle, pc);
        gen_set_label(done);
    }
    ia64_tr_resume_state_cache(ctx, cache_suspended);
    return true;
}

/*
 * Enter the common zero-local IA-64 call frame without crossing into C.
 * Calls with a nonzero local partition take the compact correctness side exit
 * instead of embedding the full BSP-preservation sequence in every call TB.
 */
static TCGLabel *ia64_tr_emit_call_effects(DisasContext *ctx,
                                           uint8_t branch_reg,
                                           uint64_t return_ip)
{
    TCGLabel *slow = gen_new_label();
    TCGv_i64 old_cfm = tcg_temp_new_i64();
    TCGv_i64 sof = tcg_temp_new_i64();
    TCGv_i64 sol = tcg_temp_new_i64();
    TCGv_i64 pfs = tcg_temp_new_i64();
    TCGv_i64 ec = tcg_temp_new_i64();
    TCGv_i32 sof32 = tcg_temp_new_i32();

    tcg_gen_ld_i64(old_cfm, tcg_env, offsetof(CPUIA64State, cfm));
    tcg_gen_shri_i64(sol, old_cfm, 7);
    tcg_gen_andi_i64(sol, sol, 0x7f);
    tcg_gen_brcondi_i64(TCG_COND_NE, sol, 0, slow);

    ia64_tr_store_br(ctx, branch_reg, tcg_constant_i64(return_ip));
    tcg_gen_andi_i64(sof, old_cfm, 0x7f);
    ia64_tr_load_ar(ctx, ec, IA64_AR_EC);
    tcg_gen_andi_i64(ec, ec, 0x3f);
    tcg_gen_shli_i64(ec, ec, IA64_TR_PFS_PEC_SHIFT);
    tcg_gen_andi_i64(pfs, old_cfm, IA64_TR_PFS_CFM_MASK);
    tcg_gen_or_i64(pfs, pfs, ec);
    tcg_gen_ori_i64(pfs, pfs,
                    (uint64_t)ia64_tcg_tb_flags_cpl(ctx->base.tb->flags)
                        << IA64_TR_PFS_PPL_SHIFT);
    ia64_tr_store_ar(ctx, IA64_AR_PFS, pfs);

    tcg_gen_st_i64(sof, tcg_env, offsetof(CPUIA64State, cfm));
    tcg_gen_extrl_i64_i32(sof32, sof);
    tcg_gen_st_i32(sof32, tcg_env, offsetof(CPUIA64State, rse.sof));
    tcg_gen_st_i32(tcg_constant_i32(0), tcg_env,
                   offsetof(CPUIA64State, rse.sol));
    tcg_gen_st_i32(tcg_constant_i32(0), tcg_env,
                   offsetof(CPUIA64State, rse.sor));
    tcg_gen_st_i32(tcg_constant_i32(0), tcg_env,
                   offsetof(CPUIA64State, rse.rrb_gr));
    tcg_gen_st_i32(tcg_constant_i32(0), tcg_env,
                   offsetof(CPUIA64State, rse.rrb_fr));
    tcg_gen_st_i32(tcg_constant_i32(0), tcg_env,
                   offsetof(CPUIA64State, rse.rrb_pr));
    return slow;
}

static void ia64_tr_emit_direct_branch_exit(DisasContext *ctx,
                                            const IA64TcgDirectBranch *branch,
                                            uint64_t target,
                                            bool taken,
                                            int tb_slot,
                                            bool use_goto_tb)
{
    TCGLabel *main_loop_exit = gen_new_label();
    TCGv_i32 chain_ok = tcg_temp_new_i32();
    TCGv_i32 branch_flags = tcg_temp_new_i32();
    uint32_t static_flags = 0;

    if (taken && (branch->kind == IA64_TCG_DIRECT_BRANCH_INDIRECT ||
                  branch->kind == IA64_TCG_DIRECT_BRANCH_INDIRECT_CALL ||
                  branch->kind == IA64_TCG_DIRECT_BRANCH_RET ||
                  branch->kind == IA64_TCG_DIRECT_BRANCH_RFI)) {
        /* The runtime target comes from the raw B slot inside the helper. */
        if (branch->prefix.finalize_mask_hi != 0) {
            gen_helper_fast_gr_finish_hi(
                tcg_env, tcg_constant_i64(branch->prefix.finalize_mask_hi));
        }
        gen_helper_finish_indirect_branch_bundle(
            chain_ok, tcg_env,
            tcg_constant_i64(branch->branch_raw),
            ctx->fast_bundle_ticks != NULL ? ctx->fast_bundle_ticks :
                                             tcg_constant_i32(0),
            tcg_constant_i32(branch->prefix.slot_count),
            tcg_constant_i32(branch->prefix.op_counts),
            tcg_constant_i64(branch->prefix.finalize_mask));
        tcg_gen_brcondi_i32(TCG_COND_EQ, chain_ok, 0, main_loop_exit);
        ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_LOOKUP);
        tcg_gen_lookup_and_goto_ptr();

        gen_set_label(main_loop_exit);
        ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_MAIN);
        tcg_gen_exit_tb(NULL, 0);
        return;
    }

    /*
     * bit 0 is branch-taken, bit 1 marks a taken call whose branch register
     * sits in bits 2-4, and the remaining upper bits are pending fast-path
     * bundle ticks.
     */
    if (ctx->fast_bundle_ticks != NULL) {
        tcg_gen_shli_i32(branch_flags, ctx->fast_bundle_ticks, 5);
    } else {
        tcg_gen_movi_i32(branch_flags, 0);
    }
    if (taken) {
        static_flags |= 1;
        if (branch->kind == IA64_TCG_DIRECT_BRANCH_CALL) {
            static_flags |= 2 | ((uint32_t)branch->call_branch_reg << 2);
        }
    }
    if (static_flags != 0) {
        tcg_gen_ori_i32(branch_flags, branch_flags, static_flags);
    }

    if (branch->prefix.finalize_mask_hi != 0) {
        gen_helper_fast_gr_finish_hi(
            tcg_env, tcg_constant_i64(branch->prefix.finalize_mask_hi));
    }
    gen_helper_finish_direct_branch_bundle(chain_ok, tcg_env,
                                           tcg_constant_i64(target),
                                           branch_flags,
                                           tcg_constant_i32(
                                               branch->prefix.slot_count),
                                           tcg_constant_i32(
                                               branch->prefix.op_counts),
                                           tcg_constant_i64(
                                               branch->prefix.finalize_mask));
    tcg_gen_brcondi_i32(TCG_COND_EQ, chain_ok, 0, main_loop_exit);
    if (use_goto_tb) {
        ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_DIRECT);
        tcg_gen_goto_tb(tb_slot);
        tcg_gen_exit_tb(ctx->base.tb, tb_slot);
    } else {
        ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_LOOKUP);
        tcg_gen_lookup_and_goto_ptr();
    }

    gen_set_label(main_loop_exit);
    ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_MAIN);
    tcg_gen_exit_tb(NULL, 0);
}

static void ia64_tr_count_branch_fallback(const IA64DecodedBundle *bundle)
{
    if (ia64_tcg_bundle_has_indirect_branch(bundle)) {
        IA64_PERF_INC(IA64_PERF_TCG_BRANCH_INDIRECT_FALLBACK);
    }
    if (ia64_tcg_bundle_has_direct_branch(bundle)) {
        IA64_PERF_INC(IA64_PERF_TCG_BRANCH_DIRECT_FALLBACK);
    }
}

static void ia64_tr_profile_note_branch_reject(
    DisasContext *ctx, const IA64DecodedBundle *bundle, uint64_t pc)
{
    int prefix_slot = -1;
    IA64TcgBranchReject reject;

    if (!ctx->profile_enabled) {
        return;
    }
    reject = ia64_tcg_direct_branch_rejection(bundle, pc, &prefix_slot);
    ia64_tr_profile_add(ctx,
                        ia64_tr_profile_branch_reject_counter(reject), 1);
    if (prefix_slot >= 0 && prefix_slot < IA64_SLOT_COUNT) {
        ia64_tr_profile_add_family(
            ctx, IA64_PROFILE_FAMILY_BRANCH_PREFIX,
            bundle->info->slot_type[prefix_slot], bundle->slot[prefix_slot]);
    }
}

static void ia64_tr_profile_note_unsupported_slots(
    DisasContext *ctx, const IA64DecodedBundle *bundle, uint64_t pc)
{
    uint8_t mask;

    if (!ctx->profile_enabled || !bundle->valid ||
        ia64_tcg_fallback_reason_for_bundle(bundle, pc) !=
            IA64_TCG_FALLBACK_FAST_UNSUPPORTED_SLOT) {
        return;
    }
    mask = ia64_tcg_unsupported_slot_mask(bundle);
    for (int slot = 0; slot < IA64_SLOT_COUNT; slot++) {
        if ((mask & (1u << slot)) != 0) {
            ia64_tr_profile_add_family(
                ctx, IA64_PROFILE_FAMILY_UNSUPPORTED,
                bundle->info->slot_type[slot], bundle->slot[slot]);
        }
    }
}

typedef enum IA64TrBranchResult {
    IA64_TR_BRANCH_REJECT,
    IA64_TR_BRANCH_EXIT,
    IA64_TR_BRANCH_CONTINUE_REGION,
} IA64TrBranchResult;

static IA64TrBranchResult ia64_tr_translate_direct_branch(
    DisasContext *ctx, const IA64DecodedBundle *bundle, uint64_t pc)
{
    IA64TcgDirectBranch branch;
    IA64TrStateCacheDirty dirty_before = { 0 };
    TCGLabel *fallback;
    TCGLabel *flow_exit = NULL;
    TCGLabel *not_taken = NULL;
    TCGLabel *slow_call = NULL;
    TCGv_i64 ldst_address[IA64_SLOT_COUNT] = { NULL, };
    TCGv_i64 runtime_dest_mask;
    TCGv_i64 runtime_dest_mask_hi;
    TCGv_i64 tmp;
    TCGv_i64 indirect_target = NULL;
    bool cached_fallback;
    bool cache_suspended;
    bool has_ldst;
    bool region_continue = false;
    bool zero_helper;
    TCGLabel *region_label = NULL;

    if (ia64_tcg_fast_disabled(IA64_TCG_FAST_DISABLE_BRANCH)) {
        IA64_PERF_INC(IA64_PERF_TCG_BRANCH_DIRECT_FALLBACK);
        return IA64_TR_BRANCH_REJECT;
    }
    if (!ia64_tcg_build_direct_branch(bundle, pc, &branch)) {
        return IA64_TR_BRANCH_REJECT;
    }
    if (ia64_tcg_tb_flags_ri(ctx->base.tb->flags) != 0) {
        IA64_PERF_INC(IA64_PERF_TCG_BRANCH_DIRECT_FALLBACK);
        return IA64_TR_BRANCH_REJECT;
    }
    has_ldst = ia64_tr_fast_bundle_has_ldst(&branch.prefix);
    if (has_ldst && !ia64_tcg_fast_ldst_memory_inline_enabled()) {
        return IA64_TR_BRANCH_REJECT;
    }
    zero_helper = ia64_tr_use_zero_helper_path() &&
                  branch.kind != IA64_TCG_DIRECT_BRANCH_RET &&
                  branch.kind != IA64_TCG_DIRECT_BRANCH_RFI &&
                  (ia64_tr_inline_call_enabled() ||
                   (branch.kind != IA64_TCG_DIRECT_BRANCH_CALL &&
                    branch.kind != IA64_TCG_DIRECT_BRANCH_INDIRECT_CALL));
    if (branch.kind == IA64_TCG_DIRECT_BRANCH_CALL ||
        branch.kind == IA64_TCG_DIRECT_BRANCH_INDIRECT_CALL) {
        ia64_tr_profile_add(
            ctx, zero_helper ? IA64_PROFILE_BRANCH_INLINE_CALL :
                               IA64_PROFILE_BRANCH_CALL_HELPER,
            1);
    } else if (branch.kind == IA64_TCG_DIRECT_BRANCH_INDIRECT) {
        ia64_tr_profile_add(ctx, IA64_PROFILE_BRANCH_INLINE_INDIRECT, 1);
    } else if (branch.kind == IA64_TCG_DIRECT_BRANCH_RET ||
               branch.kind == IA64_TCG_DIRECT_BRANCH_RFI) {
        ia64_tr_profile_add(ctx, IA64_PROFILE_BRANCH_RSE_HELPER, 1);
    } else {
        ia64_tr_profile_add(ctx, IA64_PROFILE_BRANCH_INLINE_DIRECT, 1);
    }
    ia64_tr_profile_add(
        ctx,
        branch.prefix.helper_mask != 0 ? IA64_PROFILE_BUNDLE_PARTIAL :
        zero_helper ? IA64_PROFILE_BUNDLE_ZERO_HELPER :
                      IA64_PROFILE_BUNDLE_HELPER_FAST,
        1);
    if (ctx->state_cache_active) {
        ia64_tr_capture_state_cache_dirty(ctx, &dirty_before);
    }
    cache_suspended = ctx->state_cache_active &&
                      (!zero_helper || branch.prefix.helper_mask != 0 ||
                       ia64_tr_fast_bundle_requires_state_barrier(
                           &branch.prefix));
    cached_fallback = ctx->state_cache_active && !cache_suspended;
    if (cache_suspended) {
        ia64_tr_suspend_state_cache(ctx);
    }
    fallback = gen_new_label();
    if (branch.prefix.helper_mask != 0) {
        flow_exit = gen_new_label();
    }
    runtime_dest_mask = zero_helper ? tcg_temp_new_i64() : NULL;
    runtime_dest_mask_hi = zero_helper ? tcg_temp_new_i64() : NULL;
    tmp = tcg_temp_new_i64();

    ia64_tr_emit_fast_bundle_guards(ctx, &branch.prefix, fallback,
                                    ldst_address, zero_helper);

    if (!zero_helper) {
        tcg_gen_movi_i64(cpu_ip, pc);
    } else if (ia64_tr_fast_bundle_has_required_helper(&branch.prefix)) {
        ia64_tr_commit_ip(pc);
    }
    if (runtime_dest_mask != NULL) {
        tcg_gen_movi_i64(runtime_dest_mask, 0);
        tcg_gen_movi_i64(runtime_dest_mask_hi, 0);
    }
    if (has_ldst) {
        ia64_tr_emit_can_do_io();
    }
    ctx->inline_gr_nat_clear = zero_helper;
    for (int slot = 0; slot < branch.slot; slot++) {
        if ((branch.prefix.helper_mask & (1u << slot)) != 0) {
            ia64_tr_emit_exec_slot(ctx, bundle, pc, slot, flow_exit);
        } else {
            ia64_tr_emit_fast_slot(ctx, &branch.prefix.slot[slot],
                                   ldst_address[slot], runtime_dest_mask,
                                   runtime_dest_mask_hi);
        }
    }
    ctx->inline_gr_nat_clear = false;
    if (zero_helper) {
        ia64_tr_emit_gr_alat_invalidate(runtime_dest_mask,
                                        runtime_dest_mask_hi, pc);
        ia64_tr_note_fast_bundle(ctx);
    }
    if (branch.kind == IA64_TCG_DIRECT_BRANCH_CLOOP) {
        not_taken = gen_new_label();
        ia64_tr_load_ar(ctx, tmp, IA64_AR_LC);
        tcg_gen_brcondi_i64(TCG_COND_EQ, tmp, 0, not_taken);
        tcg_gen_subi_i64(tmp, tmp, 1);
        ia64_tr_store_ar(ctx, IA64_AR_LC, tmp);
    } else if (branch.conditional) {
        not_taken = gen_new_label();
        ia64_tr_load_predicate(ctx, tmp, branch.predicate);
        tcg_gen_brcondi_i64(TCG_COND_EQ, tmp, 0, not_taken);
    }

    if (zero_helper && ia64_tr_region_enabled() &&
        (branch.kind == IA64_TCG_DIRECT_BRANCH_COND ||
         branch.kind == IA64_TCG_DIRECT_BRANCH_CLOOP) &&
        (!branch.conditional || ia64_tr_conditional_region_enabled()) &&
        branch.nop_count == branch.prefix.slot_count &&
        !ia64_tr_fast_bundle_has_required_helper(&branch.prefix) &&
        !ia64_tr_fast_bundle_requires_state_barrier(&branch.prefix) &&
        ctx->region_branch_count < 4) {
        bool likely_taken = !branch.conditional ||
                            (((branch.branch_raw >> 33) & 1) == 0);
        uint64_t next_pc = likely_taken ? branch.target_ip
                                        : branch.fallthrough_ip;

        if (next_pc > pc && translator_is_same_page(&ctx->base, next_pc)) {
            region_label = gen_new_label();
            if (!branch.conditional) {
                tcg_gen_br(region_label);
            } else if (likely_taken) {
                tcg_gen_br(region_label);
                gen_set_label(not_taken);
                ia64_tr_emit_inline_direct_branch_exit(
                    ctx, branch.fallthrough_ip, 1, false);
            } else {
                ia64_tr_emit_inline_direct_branch_exit(
                    ctx, branch.target_ip, 0, false);
                gen_set_label(not_taken);
                tcg_gen_br(region_label);
            }
            ctx->base.pc_next = next_pc;
            ctx->region_branch_count++;
            ia64_tr_profile_add(ctx, IA64_PROFILE_BRANCH_REGION_FOLDED, 1);
            region_continue = true;
        }
    }

    if (!region_continue && zero_helper &&
        (branch.kind == IA64_TCG_DIRECT_BRANCH_INDIRECT ||
         branch.kind == IA64_TCG_DIRECT_BRANCH_INDIRECT_CALL)) {
        indirect_target = tcg_temp_new_i64();
        ia64_tr_load_br(ctx, indirect_target, branch.target_branch_reg);
        tcg_gen_andi_i64(indirect_target, indirect_target, ~UINT64_C(0xf));
        if (branch.kind == IA64_TCG_DIRECT_BRANCH_INDIRECT_CALL) {
            slow_call = ia64_tr_emit_call_effects(
                ctx, branch.call_branch_reg, branch.fallthrough_ip);
        }
        ia64_tr_emit_inline_indirect_branch_exit(ctx, indirect_target);
    } else if (!region_continue && zero_helper) {
        if (branch.kind == IA64_TCG_DIRECT_BRANCH_CALL) {
            slow_call = ia64_tr_emit_call_effects(
                ctx, branch.call_branch_reg, branch.fallthrough_ip);
        }
        ia64_tr_emit_inline_direct_branch_exit(
            ctx, branch.target_ip, 0,
            translator_use_goto_tb(&ctx->base, branch.target_ip));
    } else if (!region_continue) {
        ia64_tr_emit_direct_branch_exit(
            ctx, &branch, branch.target_ip, true, 0,
            translator_use_goto_tb(&ctx->base, branch.target_ip));
    }
    if (slow_call != NULL) {
        gen_set_label(slow_call);
        ia64_tr_sync_state_cache(ctx);
        ia64_tr_commit_ip(pc);
        ia64_tr_emit_direct_branch_exit(
            ctx, &branch, branch.target_ip, true, 0, false);
    }
    if (!region_continue && branch.conditional) {
        gen_set_label(not_taken);
        if (zero_helper) {
            ia64_tr_emit_inline_direct_branch_exit(
                ctx, branch.fallthrough_ip, 1,
                translator_use_goto_tb(&ctx->base,
                                       branch.fallthrough_ip));
        } else {
            ia64_tr_emit_direct_branch_exit(
                ctx, &branch, branch.fallthrough_ip, false, 1,
                translator_use_goto_tb(&ctx->base,
                                       branch.fallthrough_ip));
        }
    }

    gen_set_label(fallback);
    if (ia64_perf_enabled()) {
        gen_helper_perf_direct_branch_fallback();
    }
    if (has_ldst && ia64_perf_enabled()) {
        gen_helper_perf_tcg_ldst_fallback();
    }
    if (cached_fallback) {
        ia64_tr_emit_exec_bundle_lookup_ptr_cached_fallback(
            ctx, bundle, pc, &dirty_before);
    } else {
        ia64_tr_emit_exec_bundle_lookup_ptr(ctx, bundle, pc);
    }
    if (flow_exit != NULL) {
        gen_set_label(flow_exit);
        ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_MAIN);
        tcg_gen_exit_tb(NULL, 0);
    }
    if (region_continue) {
        gen_set_label(region_label);
    }
    ia64_tr_resume_state_cache(ctx, cache_suspended);
    return region_continue ? IA64_TR_BRANCH_CONTINUE_REGION
                           : IA64_TR_BRANCH_EXIT;
}

static void ia64_tr_translate_insn(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    IA64DecodedBundle bundle;
    IA64TcgTbBoundary boundary;
    IA64TrBranchResult branch_result;
    char bundle_text[160];
    uint64_t pc = ctx->base.pc_next;
    uint64_t dispatch_ip = pc;
    bool dispatch_ip_is_physical = false;
    uint64_t lo;
    uint64_t hi;

    if (ctx->state_cache_available && !ctx->state_cache_active &&
        ctx->base.num_insns >= ia64_tr_state_cache_min_bundles()) {
        ctx->state_cache_active = true;
    }
    ia64_tr_profile_add(ctx, IA64_PROFILE_BUNDLE_EXECUTED, 1);
    if (ctx->state_cache_active) {
        ia64_tr_profile_add(ctx, IA64_PROFILE_STATE_CACHE_ACTIVE_BUNDLE, 1);
    }
    lo = translator_ldq_end(ctx->env, &ctx->base, pc, MO_LE);
    hi = translator_ldq_end(ctx->env, &ctx->base, pc + 8, MO_LE);
    ia64_decode_bundle_words(lo, hi, &bundle);
    IA64_PERF_INC(IA64_PERF_BUNDLE_DECODED);
    if (!bundle.valid) {
        IA64_PERF_INC(IA64_PERF_BUNDLE_DECODE_INVALID);
    }
    ia64_format_decoded_bundle(&bundle, bundle_text, sizeof(bundle_text));
    trace_ia64_bundle_decode(pc, bundle_text);

    ctx->base.pc_next = pc + IA64_BUNDLE_SIZE;
    if (!ia64_tcg_pc_is_efi_call_gate(pc) &&
        ia64_tcg_bundle_is_firmware_call_gate_candidate(&bundle)) {
        dispatch_ip_is_physical = ia64_tr_instruction_physical_address(
            ctx, pc, &dispatch_ip);
    }
    boundary = ia64_tcg_tb_boundary_for_bundle_with_physical(
        &bundle, pc, dispatch_ip, dispatch_ip_is_physical);
    if (boundary == IA64_TCG_TB_BOUNDARY_EFI_CALL_GATE) {
        ia64_tr_profile_add(ctx, IA64_PROFILE_BUNDLE_HELPER_FAST, 1);
        ia64_tr_emit_firmware_call_gate(ctx, pc, dispatch_ip);
        trace_ia64_tcg_tb_boundary(pc, ia64_tcg_tb_boundary_name(boundary));
        IA64_PERF_INC(IA64_PERF_TB_EXIT_FLOW_TRANSLATED);
        ctx->base.is_jmp = DISAS_EXIT;
        return;
    }
    if (boundary == IA64_TCG_TB_BOUNDARY_SPECULATION_CHECK &&
        ia64_tr_translate_speculation_check(ctx, &bundle, pc)) {
        return;
    }
    if (boundary == IA64_TCG_TB_BOUNDARY_BRANCH) {
        branch_result = ia64_tr_translate_direct_branch(ctx, &bundle, pc);
        if (branch_result == IA64_TR_BRANCH_EXIT) {
            ctx->base.is_jmp = DISAS_NORETURN;
            return;
        }
        if (branch_result == IA64_TR_BRANCH_CONTINUE_REGION) {
            return;
        }
    }
    if (boundary == IA64_TCG_TB_BOUNDARY_BRANCH) {
        ia64_tr_profile_add(ctx, IA64_PROFILE_BUNDLE_FULL_HELPER, 1);
        ia64_tr_profile_note_branch_reject(ctx, &bundle, pc);
        ia64_tr_count_branch_fallback(&bundle);
        trace_ia64_tcg_tb_boundary(pc,
                                   ia64_tcg_tb_boundary_name(boundary));
        IA64_PERF_INC(IA64_PERF_TB_EXIT_FLOW_TRANSLATED);
        ia64_tr_emit_exec_bundle_lookup_ptr(ctx, &bundle, pc);
        ctx->base.is_jmp = DISAS_NORETURN;
        return;
    }
    if (ia64_tcg_tb_boundary_ends_tb(boundary) ||
        (!ia64_tr_translate_fast_bundle(ctx, &bundle, pc) &&
         !ia64_tr_translate_partial_bundle(ctx, &bundle, pc))) {
        ia64_tr_profile_add(ctx, IA64_PROFILE_BUNDLE_FULL_HELPER, 1);
        ia64_tr_profile_note_unsupported_slots(ctx, &bundle, pc);
        if (!ia64_tcg_tb_boundary_ends_tb(boundary) &&
            ia64_tcg_bundle_has_ldst_immediate(&bundle)) {
            IA64_PERF_INC(IA64_PERF_TCG_LDST_FALLBACK);
        }
        ia64_tr_emit_exec_bundle(ctx, &bundle, pc);
    }
    if (ia64_tcg_tb_boundary_ends_tb(boundary)) {
        trace_ia64_tcg_tb_boundary(pc,
                                   ia64_tcg_tb_boundary_name(boundary));
        IA64_PERF_INC(IA64_PERF_TB_EXIT_FLOW_TRANSLATED);
        ctx->base.is_jmp = DISAS_EXIT;
    }
}

static void ia64_tr_tb_stop(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);

    switch (ctx->base.is_jmp) {
    case DISAS_TOO_MANY:
        ia64_tr_emit_fallthrough_exit(ctx, ctx->base.pc_next);
        break;
    case DISAS_EXIT:
        ia64_tr_emit_main_loop_exit(ctx);
        break;
    case DISAS_NORETURN:
        break;
    default:
        g_assert_not_reached();
    }
}

static const TranslatorOps ia64_tr_ops = {
    .init_disas_context = ia64_tr_init_disas_context,
    .tb_start = ia64_tr_tb_start,
    .insn_start = ia64_tr_insn_start,
    .translate_insn = ia64_tr_translate_insn,
    .tb_stop = ia64_tr_tb_stop,
};

void ia64_translate_code(CPUState *cs, TranslationBlock *tb, int *max_insns,
                         vaddr pc, void *host_pc)
{
    IA64CPU *cpu = IA64_CPU(cs);
    DisasContext ctx;

    IA64_PERF_INC(IA64_PERF_TB_TRANSLATED);
    if (cpu->env.fault_exit_pending_tb_translate) {
        IA64_PERF_INC(IA64_PERF_TB_TRANSLATED_AFTER_FAULT);
        cpu->env.fault_exit_pending_tb_translate = false;
    }
    IA64_PERF_INC((IA64PerfCounter)(IA64_PERF_TB_GENERATED_REGION0 +
                                    (pc >> 61)));
    translator_loop(cs, tb, max_insns, pc, host_pc, &ia64_tr_ops, &ctx.base,
                    TCG_TYPE_VA);
}
