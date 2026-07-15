/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "cpu.h"
#include "bundle.h"
#include "decode.h"
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

/*
 * An IA-64 instruction can produce a GR result and a post-update result.
 * Keeping both slots here also makes the transaction representation usable
 * by the load/store tranche without collapsing two architecturally ordered
 * writes into one value.
 */
#define IA64_TR_GR_WRITES_PER_INSN 2
#define IA64_TR_PR_WRITES_PER_INSN 2
#define IA64_TR_BR_WRITES_PER_INSN 1
#define IA64_TR_I64_SCRATCH_COUNT 96
#define IA64_TR_I32_SCRATCH_COUNT 24

typedef struct IA64TrGrWrite {
    TCGv_i64 value;
    TCGv_i64 nat;
    TCGv_i64 written;
    uint8_t reg;
    bool preserve_source;
    bool must_write;
} IA64TrGrWrite;

typedef struct IA64TrPrWrite {
    TCGv_i64 value;
    TCGv_i64 written;
    uint8_t predicate;
    bool must_write;
} IA64TrPrWrite;

typedef struct IA64TrBrWrite {
    TCGv_i64 value;
    TCGv_i64 written;
    uint8_t reg;
    bool preserve_source;
    bool must_write;
    bool forward_to_branch;
} IA64TrBrWrite;

/*
 * Packed PR moves are one architectural masked-image transaction.  Keeping
 * them packed is important both for code size and for the all-or-none rotating
 * PR range: expanding the image into 48 mapped predicate writes would obscure
 * the lazy rrb_pr representation and make preservation unnecessarily costly.
 */
typedef struct IA64TrPrImageWrite {
    TCGv_i64 value;
    TCGv_i64 written;
    uint64_t mask;
    bool active;
    bool must_write;
} IA64TrPrImageWrite;

typedef struct IA64TrGrRef {
    uint8_t reg;
} IA64TrGrRef;

typedef struct IA64TrInstructionPlan {
    uint64_t address;
    uint64_t source_gr[2];
    uint64_t dest_gr[2];
    uint64_t preserve_gr[2];
    uint64_t source_ar[2];
    uint64_t dest_ar[2];
    uint64_t source_pr;
    uint64_t dest_pr;
    /* Eligible producer destinations and the branch-only live/entry selector. */
    uint64_t forward_pr;
    uint64_t branch_source_pr;
    uint64_t preserve_pr;
    uint64_t must_gr[2];
    uint64_t must_pr;
    uint8_t source_br;
    uint8_t dest_br;
    uint8_t preserve_br;
    uint8_t must_br;
    uint8_t forward_br;
    uint8_t branch_source_br;
    uint16_t bundle_index;
    uint8_t slot;
    bool source_cfm;
    bool dest_cfm;
    bool forward_pfs;
    bool branch_source_pfs;
    bool must_pfs;
    bool stop_after;
    bool unconditional_noreturn;
} IA64TrInstructionPlan;

typedef struct IA64TrDecodedBranchArm {
    TCGLabel *taken;
    TCGv_i64 indirect_target;
    TCGv_i64 return_pfs;
    uint64_t direct_target;
    bool indirect;
    bool call;
    bool ret;
} IA64TrDecodedBranchArm;

typedef struct IA64TrInstructionTransaction {
    IA64TrGrWrite gr[IA64_TR_GR_WRITES_PER_INSN];
    IA64TrPrWrite pr[IA64_TR_PR_WRITES_PER_INSN];
    IA64TrBrWrite br[IA64_TR_BR_WRITES_PER_INSN];
    IA64TrPrImageWrite pr_image;
    TCGv_i64 pre_ic;
    uint64_t address;
    uint64_t dest_gr[2];
    uint64_t preserve_gr[2];
    uint64_t must_gr[2];
    uint64_t source_ar[2];
    uint64_t dest_ar[2];
    uint64_t dest_pr;
    uint64_t forward_pr;
    uint64_t branch_source_pr;
    uint64_t preserve_pr;
    uint64_t must_pr;
    uint8_t source_br;
    uint8_t dest_br;
    uint8_t preserve_br;
    uint8_t must_br;
    uint8_t forward_br;
    uint8_t branch_source_br;
    uint8_t gr_count;
    uint8_t pr_count;
    uint8_t br_count;
    uint8_t slot;
    bool source_cfm;
    bool dest_cfm;
    bool forward_pfs;
    bool branch_source_pfs;
    bool must_pfs;
} IA64TrInstructionTransaction;

typedef struct IA64TrGroupTransaction {
    IA64TrInstructionTransaction *instruction;
    IA64TrInstructionTransaction *current;
    TCGv_i64 gr_value[IA64_TR_GR_WRITES_PER_INSN];
    TCGv_i64 gr_nat[IA64_TR_GR_WRITES_PER_INSN];
    TCGv_i64 gr_written[IA64_TR_GR_WRITES_PER_INSN];
    TCGv_i64 pr_value[IA64_TR_PR_WRITES_PER_INSN];
    TCGv_i64 pr_written[IA64_TR_PR_WRITES_PER_INSN];
    TCGv_i64 br_value[IA64_TR_BR_WRITES_PER_INSN];
    TCGv_i64 br_written[IA64_TR_BR_WRITES_PER_INSN];
    TCGv_i64 pr_image_value;
    TCGv_i64 pr_image_written;
    TCGv_i64 pre_ic;
    uint16_t instruction_capacity;
    uint16_t instruction_count;
    uint64_t gr_may_written[2];
    uint64_t gr_may_saved[2];
    uint64_t gr_must_saved[2];
    uint64_t pr_may_written;
    uint8_t br_may_written;
    uint8_t br_may_saved;
    uint8_t br_must_saved;
    bool pr_may_saved;
    bool pr_must_saved;
    bool branch_forward_may_nonzero;
    bool branch_br_forward_may_nonzero;
    bool pfs_may_saved;
    bool pfs_must_saved;
    bool branch_pfs_forward_may_nonzero;
    bool active;
} IA64TrGroupTransaction;

typedef struct DisasContext {
    DisasContextBase base;
    CPUIA64State *env;
    TCGv_i32 fast_bundle_ticks;
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
    bool fast_bundle_ticks_used;
    bool inline_gr_nat_clear;
    bool state_cache_available;
    bool state_cache_active;
    bool pr_valid;
    bool pr_dirty;
    bool gr_nat_valid;
    bool gr_nat_dirty;
    bool profile_enabled;
    bool instruction_group_start;
    bool typed_group_active;
    bool rewrite_region_decided;
    bool rewrite_region_selected;
    uint16_t rewrite_region_bundles_left;
    uint16_t rewrite_region_bundle_count;
    uint8_t rewrite_region_last_slot;
    size_t rewrite_region_ops_start;
    IA64TrGroupTransaction rewrite_group;
    IA64TrInstructionPlan *rewrite_plan;
    uint16_t rewrite_plan_capacity;
    uint16_t rewrite_plan_count;
    uint16_t rewrite_plan_emit_count;
    uint16_t rewrite_plan_index;
    TCGv_i64 rewrite_i64_scratch[IA64_TR_I64_SCRATCH_COUNT];
    TCGv_i32 rewrite_i32_scratch[IA64_TR_I32_SCRATCH_COUNT];
    uint8_t rewrite_i64_scratch_count;
    uint8_t rewrite_i32_scratch_count;
    bool rewrite_scratch_active;
    bool rewrite_control_flow_exit;
    bool source_overlay_known_clear;
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

/*
 * Proven debug-checked ceiling for one currently admitted typed integer
 * bundle.  The exit allowance covers cached-state publication, the explicit
 * source-visibility frontier, profiling, and either a chained or main-loop
 * TB exit.  Budget pressure may shorten a typed segment, but must never make
 * a semantically supported bundle change execution engines.
 */
#define IA64_TR_REWRITE_OPS_PER_BUNDLE 768
#define IA64_TR_REWRITE_EXIT_OPS 128

#define IA64_CPU_STATE_OFFSET(field) \
    ((intptr_t)offsetof(IA64CPU, parent_obj) + \
     (intptr_t)offsetof(CPUState, field) - \
     (intptr_t)offsetof(IA64CPU, env))
#define IA64_CPU_OFFSET(field) \
    ((intptr_t)offsetof(IA64CPU, field) - \
     (intptr_t)offsetof(IA64CPU, env))

#define IA64_TR_PSR_IC_BIT UINT64_C(0x0000000000002000)
#define IA64_TR_PR_ROTATING_MASK UINT64_C(0xffffffffffff0000)

static TCGv_i64 cpu_ip;
static TCGv_i64 cpu_logical_gr[IA64_GR_COUNT - IA64_STATIC_GR_COUNT];
static TCGv_i64 cpu_logical_nat[2];
static TCGv_i64 cpu_logical_dirty[2];
static char cpu_logical_gr_names[IA64_GR_COUNT - IA64_STATIC_GR_COUNT][5];
static const char * const cpu_logical_nat_names[2] = {
    "logical_nat0", "logical_nat1",
};
static const char * const cpu_logical_dirty_names[2] = {
    "logical_dirty0", "logical_dirty1",
};

static bool ia64_tr_use_zero_helper_path(void);
static bool ia64_tr_group_is_empty(const DisasContext *ctx);
static bool ia64_tr_emit_decoded_branch_split(
    DisasContext *ctx, const IA64Instruction *insn,
    IA64TrDecodedBranchArm *arm);
static void ia64_tr_emit_decoded_loop_branch_split(
    DisasContext *ctx, const IA64Instruction *insn,
    IA64TrDecodedBranchArm *arm);
static bool ia64_tr_emit_decoded_call_split(
    DisasContext *ctx, const IA64Instruction *insn,
    IA64TrDecodedBranchArm *arm);
static bool ia64_tr_emit_decoded_return_split(
    DisasContext *ctx, const IA64Instruction *insn,
    IA64TrDecodedBranchArm *arm);
static void ia64_tr_emit_decoded_branch_cfg_exits(
    DisasContext *ctx, IA64TrDecodedBranchArm arms[IA64_SLOT_COUNT],
    unsigned arm_count, bool has_fallthrough, uint64_t fallthrough_target,
    bool fallthrough_group_start, bool fallthrough_typed_active);

/*
 * TEMP_TB objects count against the fixed 512-temp translation ceiling even
 * after their last use.  Typed instructions therefore redefine a bounded
 * scratch bank after each finish-success point instead of allocating temps in
 * proportion to instruction-group length.  Persistent cache and staged-writer
 * values deliberately use ordinary allocations outside this arena.
 */
static TCGv_i64 ia64_tr_scratch_i64(DisasContext *ctx)
{
    unsigned index;

    if (!ctx->rewrite_scratch_active) {
        return tcg_temp_new_i64();
    }
    index = ctx->rewrite_i64_scratch_count++;
    g_assert(index < ARRAY_SIZE(ctx->rewrite_i64_scratch));
    if (ctx->rewrite_i64_scratch[index] == NULL) {
        ctx->rewrite_i64_scratch[index] = tcg_temp_new_i64();
    }
    return ctx->rewrite_i64_scratch[index];
}

static TCGv_i32 ia64_tr_scratch_i32(DisasContext *ctx)
{
    unsigned index;

    if (!ctx->rewrite_scratch_active) {
        return tcg_temp_new_i32();
    }
    index = ctx->rewrite_i32_scratch_count++;
    g_assert(index < ARRAY_SIZE(ctx->rewrite_i32_scratch));
    if (ctx->rewrite_i32_scratch[index] == NULL) {
        ctx->rewrite_i32_scratch[index] = tcg_temp_new_i32();
    }
    return ctx->rewrite_i32_scratch[index];
}

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
    for (unsigned i = 0; i < ARRAY_SIZE(cpu_logical_gr); i++) {
        snprintf(cpu_logical_gr_names[i], sizeof(cpu_logical_gr_names[i]),
                 "r%u", IA64_STATIC_GR_COUNT + i);
        cpu_logical_gr[i] = tcg_global_mem_new_i64(
            tcg_env,
            offsetof(CPUIA64State, gr[IA64_STATIC_GR_COUNT + i]),
            cpu_logical_gr_names[i]);
    }
    for (unsigned i = 0; i < ARRAY_SIZE(cpu_logical_nat); i++) {
        cpu_logical_nat[i] = tcg_global_mem_new_i64(
            tcg_env, offsetof(CPUIA64State, rse.logical_nat[i]),
            cpu_logical_nat_names[i]);
        cpu_logical_dirty[i] = tcg_global_mem_new_i64(
            tcg_env, offsetof(CPUIA64State, rse.logical_dirty[i]),
            cpu_logical_dirty_names[i]);
    }
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
    ctx->instruction_group_start =
        (ctx->base.tb->flags & IA64_TB_FLAG_GROUP_START) != 0;
    ctx->typed_group_active =
        (ctx->base.tb->flags & IA64_TB_FLAG_TYPED_GROUP) != 0;
    /*
     * A legacy-owned mid-group TB must stay on the legacy engine.  A typed
     * continuation carries an explicit TB flag and may revalidate/lower the
     * remaining same-page suffix without reconstructing its already-retired
     * prefix; ordinary source reads consume the persisted overlay.
     */
    ctx->rewrite_region_decided =
        !ctx->instruction_group_start && !ctx->typed_group_active;
    ctx->rewrite_region_selected = false;
    ctx->rewrite_region_bundles_left = 0;
    ctx->rewrite_region_bundle_count = 0;
    ctx->rewrite_region_last_slot = IA64_SLOT_COUNT - 1;
    ctx->rewrite_region_ops_start = 0;
    memset(&ctx->rewrite_group, 0, sizeof(ctx->rewrite_group));
    ctx->rewrite_plan = NULL;
    ctx->rewrite_plan_capacity = 0;
    ctx->rewrite_plan_count = 0;
    ctx->rewrite_plan_emit_count = 0;
    ctx->rewrite_plan_index = 0;
    memset(ctx->rewrite_i64_scratch, 0,
           sizeof(ctx->rewrite_i64_scratch));
    memset(ctx->rewrite_i32_scratch, 0,
           sizeof(ctx->rewrite_i32_scratch));
    ctx->rewrite_i64_scratch_count = 0;
    ctx->rewrite_i32_scratch_count = 0;
    ctx->rewrite_scratch_active = false;
    ctx->rewrite_control_flow_exit = false;
    ctx->source_overlay_known_clear = !ctx->typed_group_active;
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

/*
 * Temporary differential-testing switch for the rewrite.  The production
 * default is the typed full-TCG path; setting this to 0 leaves the untouched
 * bundle on the legacy classifier/oracle path before any TCG is emitted.
 */
static bool ia64_tr_full_tcg_rewrite_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        const char *value = g_getenv("VIBTANIUM_FULL_TCG_REWRITE");

        enabled = value == NULL ||
                  !(strcmp(value, "0") == 0 ||
                    g_ascii_strcasecmp(value, "off") == 0 ||
                    g_ascii_strcasecmp(value, "false") == 0);
    }
    return enabled;
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
}

static void ia64_tr_state_cache_barrier(DisasContext *ctx)
{
    /* A cache barrier publishes architectural state; staged groups must not. */
    g_assert(ia64_tr_group_is_empty(ctx));
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

/*
 * Retire accounting without the legacy finish helper's premature asynchronous-
 * interrupt poll.  A taken return must first commit its target/frame and
 * arbitrate synchronous branch traps.  The mandatory-load helper then performs
 * the architectural interrupt-priority check before each CFLE load, including
 * before the first and after the final successful load.  The benchmark TB flag
 * is the translation-time equivalent of ia64_benchmark_retire()'s runtime
 * active test.
 */
static void ia64_tr_retire_fast_bundle_ticks_deferred_interrupt(
    DisasContext *ctx)
{
    if (!ctx->fast_bundle_ticks_used) {
        return;
    }

    if ((ctx->base.tb->flags & IA64_TB_FLAG_BENCHMARK) != 0) {
        ia64_tr_emit_benchmark_retire(ctx->fast_bundle_ticks);
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

static void ia64_tr_store_source_visibility_state(DisasContext *ctx,
                                                  bool group_start,
                                                  bool typed_active)
{
    g_assert(!group_start || !typed_active);
    if (group_start && !ctx->source_overlay_known_clear) {
        tcg_gen_st_i64(tcg_constant_i64(0), tcg_env,
                       offsetof(CPUIA64State,
                                issue_group.saved_gr_mask));
        tcg_gen_st_i64(tcg_constant_i64(0), tcg_env,
                       offsetof(CPUIA64State,
                                issue_group.saved_gr_mask) +
                       sizeof(uint64_t));
        tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                        offsetof(CPUIA64State,
                                 issue_group.saved_br_mask));
        tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                        offsetof(CPUIA64State,
                                 issue_group.branch_br_forward_mask));
        tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                        offsetof(CPUIA64State, issue_group.pr_saved));
        tcg_gen_st_i64(
            tcg_constant_i64(0), tcg_env,
            offsetof(CPUIA64State, issue_group.branch_pr_forward_mask));
        tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                        offsetof(CPUIA64State, issue_group.pfs_saved));
        tcg_gen_st8_i32(
            tcg_constant_i32(0), tcg_env,
            offsetof(CPUIA64State, issue_group.branch_pfs_forwarded));
    }
    tcg_gen_st8_i32(tcg_constant_i32(typed_active), tcg_env,
                    offsetof(CPUIA64State, issue_group.typed_active));
    tcg_gen_st8_i32(tcg_constant_i32(group_start), tcg_env,
                    offsetof(CPUIA64State, instruction_group_start));
    tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                    offsetof(CPUIA64State, instruction_group_dirty));
}

static void ia64_tr_store_legacy_helper_frontier(bool group_start)
{
    /*
     * Do not clear typed_active or its overlay before the generic helper has
     * had a chance to enforce its fail-closed ownership guard.  A valid
     * legacy entry already has no overlay; this store only publishes the
     * bundle/slot frontier that may have advanced earlier in the same TB.
     */
    tcg_gen_st8_i32(tcg_constant_i32(group_start), tcg_env,
                    offsetof(CPUIA64State, instruction_group_start));
    tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                    offsetof(CPUIA64State, instruction_group_dirty));
}

static void ia64_tr_prepare_helper_ip(DisasContext *ctx, uint64_t ip)
{
    g_assert(!ctx->typed_group_active);
    ia64_tr_store_legacy_helper_frontier(ctx->instruction_group_start);
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
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    uint64_t restart_ri = dcbase->pc_next == dcbase->pc_first ?
                          ia64_tcg_tb_flags_ri(dcbase->tb->flags) : 0;
    uint64_t source_visibility =
        (ctx->instruction_group_start ? IA64_INSN_START_GROUP_START : 0) |
        (ctx->typed_group_active ? IA64_INSN_START_TYPED_GROUP : 0);

    /* The legacy execution oracle treats reserved PSR.ri=3 as bundle slot 0. */
    if (restart_ri >= IA64_SLOT_COUNT) {
        restart_ri = 0;
    }
    tcg_gen_insn_start(dcbase->pc_next,
                       restart_ri,
                       source_visibility);
}

static void ia64_tr_publish_restart_ri(uint8_t start_slot)
{
    g_assert(start_slot < IA64_SLOT_COUNT);
    tcg_gen_st8_i32(tcg_constant_i32(start_slot), tcg_env,
                    offsetof(CPUIA64State, ri));
    /*
     * Always make the cache authoritative, including RI=0.  A TB may have
     * been keyed from an unsynchronized env->ri override while env->psr still
     * contains an older RI, so clearing ri_dirty here would expose stale PSR
     * state before the helper reads its first slot.
     */
    tcg_gen_st8_i32(tcg_constant_i32(1), tcg_env,
                    offsetof(CPUIA64State, ri_dirty));
}

static void ia64_tr_emit_exec_bundle(DisasContext *ctx,
                                     const IA64DecodedBundle *bundle,
                                     uint64_t pc, uint8_t start_slot)
{
    IA64TcgFallbackPlan fallback_plan =
        ia64_tcg_fallback_plan_for_bundle(bundle);
    IA64TcgFallbackArgs fallback_args = ia64_tcg_fallback_args(
        bundle, &fallback_plan, IA64_TCG_FALLBACK_FULL_BUNDLE);

    ia64_tr_state_cache_barrier(ctx);
    ia64_tr_prepare_helper_ip(ctx, pc);
    ia64_tr_publish_restart_ri(start_slot);
    ia64_tr_flush_fast_bundle_ticks(ctx);
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
                                                uint64_t pc,
                                                uint8_t start_slot)
{
    IA64TcgFallbackPlan fallback_plan =
        ia64_tcg_fallback_plan_for_bundle(bundle);
    IA64TcgFallbackArgs fallback_args = ia64_tcg_fallback_args(
        bundle, &fallback_plan, IA64_TCG_FALLBACK_FULL_BUNDLE);
    TCGLabel *main_loop_exit = gen_new_label();
    TCGv_i32 chain_ok = tcg_temp_new_i32();

    ia64_tr_state_cache_barrier(ctx);
    ia64_tr_prepare_helper_ip(ctx, pc);
    ia64_tr_publish_restart_ri(start_slot);
    ia64_tr_flush_fast_bundle_ticks(ctx);
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

/*
 * Complete a bundle after a typed prefix reached an internal stop.  This is a
 * same-callback handoff, not a new TB: the translator framework, plugins, and
 * icount therefore account for the architectural bundle exactly once.  The
 * full-bundle helper deliberately consumes env->RI as its first slot.
 */
static void ia64_tr_emit_exec_bundle_suffix(
    DisasContext *ctx, const IA64DecodedBundle *bundle, uint64_t pc,
    uint8_t start_slot)
{
    IA64TcgFallbackPlan fallback_plan =
        ia64_tcg_fallback_plan_for_bundle(bundle);
    IA64TcgFallbackArgs fallback_args = ia64_tcg_fallback_args(
        bundle, &fallback_plan, IA64_TCG_FALLBACK_FULL_BUNDLE);

    g_assert(!ctx->typed_group_active);
    g_assert(bundle->valid && bundle->info->stop_after_slot[start_slot - 1]);
    ia64_tr_state_cache_barrier(ctx);
    ia64_tr_prepare_helper_ip(ctx, pc);
    /* commit_ip() canonicalizes RI, so publish the suffix only afterwards. */
    ia64_tr_publish_restart_ri(start_slot);
    /* An interrupt while flushing earlier bundles must resume at this suffix. */
    ia64_tr_flush_fast_bundle_ticks(ctx);
    gen_helper_exec_bundle(
        tcg_env,
        tcg_constant_i64(fallback_args.header),
        tcg_constant_i64(fallback_args.slot1),
        tcg_constant_i64(fallback_args.slot2),
        tcg_constant_i64(fallback_args.desc01),
        tcg_constant_i64(fallback_args.desc2));
}

static void ia64_tr_emit_exec_bundle_lookup_ptr_suffix(
    DisasContext *ctx, const IA64DecodedBundle *bundle, uint64_t pc,
    uint8_t start_slot)
{
    IA64TcgFallbackPlan fallback_plan =
        ia64_tcg_fallback_plan_for_bundle(bundle);
    IA64TcgFallbackArgs fallback_args = ia64_tcg_fallback_args(
        bundle, &fallback_plan, IA64_TCG_FALLBACK_FULL_BUNDLE);
    TCGLabel *main_loop_exit = gen_new_label();
    TCGv_i32 chain_ok = tcg_temp_new_i32();

    g_assert(!ctx->typed_group_active);
    g_assert(bundle->valid && bundle->info->stop_after_slot[start_slot - 1]);
    ia64_tr_state_cache_barrier(ctx);
    ia64_tr_prepare_helper_ip(ctx, pc);
    ia64_tr_publish_restart_ri(start_slot);
    ia64_tr_flush_fast_bundle_ticks(ctx);
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
    uint8_t start_slot,
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
    ia64_tr_prepare_helper_ip(ctx, pc);
    ia64_tr_publish_restart_ri(start_slot);
    ia64_tr_flush_fast_bundle_ticks(ctx);
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
    uint8_t start_slot,
    const IA64TrStateCacheDirty *dirty_before)
{
    IA64TcgFallbackPlan fallback_plan =
        ia64_tcg_fallback_plan_for_bundle(bundle);
    IA64TcgFallbackArgs fallback_args = ia64_tcg_fallback_args(
        bundle, &fallback_plan, IA64_TCG_FALLBACK_FULL_BUNDLE);
    TCGLabel *main_loop_exit = gen_new_label();
    TCGv_i32 chain_ok = tcg_temp_new_i32();

    ia64_tr_sync_state_cache_dirty(ctx, dirty_before);
    ia64_tr_prepare_helper_ip(ctx, pc);
    ia64_tr_publish_restart_ri(start_slot);
    ia64_tr_flush_fast_bundle_ticks(ctx);
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
                                            uint64_t dispatch_ip,
                                            uint8_t start_slot)
{
    ia64_tr_state_cache_barrier(ctx);
    ia64_tr_prepare_helper_ip(ctx, pc);
    ia64_tr_publish_restart_ri(start_slot);
    ia64_tr_flush_fast_bundle_ticks(ctx);
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

static unsigned ia64_tr_logical_gr_index(uint8_t reg)
{
    g_assert(ia64_tr_gr_is_stacked(reg));
    return reg - IA64_STATIC_GR_COUNT;
}

static unsigned ia64_tr_logical_gr_word(uint8_t reg)
{
    return ia64_tr_logical_gr_index(reg) >> 6;
}

static uint64_t ia64_tr_logical_gr_mask(uint8_t reg)
{
    return UINT64_C(1) << (ia64_tr_logical_gr_index(reg) & 63);
}

static void ia64_tr_mark_logical_gr_dirty(uint8_t reg)
{
    unsigned word = ia64_tr_logical_gr_word(reg);
    uint64_t mask = ia64_tr_logical_gr_mask(reg);

    tcg_gen_ori_i64(cpu_logical_dirty[word], cpu_logical_dirty[word], mask);
}

static void ia64_tr_clear_logical_gr_nat(uint8_t reg)
{
    unsigned word = ia64_tr_logical_gr_word(reg);
    uint64_t mask = ia64_tr_logical_gr_mask(reg);

    tcg_gen_andi_i64(cpu_logical_nat[word], cpu_logical_nat[word], ~mask);
}

static void ia64_tr_read_logical_gr_nat(TCGv_i64 dest, uint8_t reg)
{
    unsigned index = ia64_tr_logical_gr_index(reg);

    tcg_gen_shri_i64(dest, cpu_logical_nat[index >> 6], index & 63);
    tcg_gen_andi_i64(dest, dest, 1);
}

static void ia64_tr_write_logical_gr_nat(DisasContext *ctx, uint8_t reg,
                                         TCGv_i64 value)
{
    unsigned word = ia64_tr_logical_gr_word(reg);
    uint64_t mask = ia64_tr_logical_gr_mask(reg);
    TCGv_i64 selected = ia64_tr_scratch_i64(ctx);

    tcg_gen_andi_i64(cpu_logical_nat[word], cpu_logical_nat[word], ~mask);
    tcg_gen_neg_i64(selected, value);
    tcg_gen_andi_i64(selected, selected, mask);
    tcg_gen_or_i64(cpu_logical_nat[word], cpu_logical_nat[word], selected);
}

static void ia64_tr_clear_gr_nat(DisasContext *ctx, uint8_t reg)
{
    if (ia64_tr_gr_is_stacked(reg)) {
        ia64_tr_clear_logical_gr_nat(reg);
        ia64_tr_mark_logical_gr_dirty(reg);
        return;
    }

    if (ctx->state_cache_active) {
        TCGv_i64 nat = ia64_tr_ensure_gr_nat(ctx);

        tcg_gen_andi_i64(nat, nat, ~(UINT64_C(1) << reg));
        ctx->gr_nat_dirty = true;
    } else {
        TCGv_i64 nat = ia64_tr_scratch_i64(ctx);

        tcg_gen_ld_i64(nat, tcg_env, offsetof(CPUIA64State, nat.gr_nat));
        tcg_gen_andi_i64(nat, nat, ~(UINT64_C(1) << reg));
        tcg_gen_st_i64(nat, tcg_env, offsetof(CPUIA64State, nat.gr_nat));
    }
}

static void ia64_tr_load_static_gr(DisasContext *ctx, TCGv_i64 dest,
                                   uint8_t reg)
{
    if (ia64_tr_gr_is_stacked(reg)) {
        tcg_gen_mov_i64(dest,
                        cpu_logical_gr[ia64_tr_logical_gr_index(reg)]);
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
        tcg_gen_mov_i64(cpu_logical_gr[ia64_tr_logical_gr_index(reg)],
                        value);
        if (ctx->inline_gr_nat_clear) {
            ia64_tr_clear_logical_gr_nat(reg);
        }
        ia64_tr_mark_logical_gr_dirty(reg);
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

static void ia64_tr_predicate_bit(DisasContext *ctx, TCGv_i64 bit,
                                  uint8_t predicate)
{
    if (predicate < 16) {
        tcg_gen_movi_i64(bit, UINT64_C(1) << predicate);
        return;
    }

    TCGv_i32 rrb32 = ia64_tr_scratch_i32(ctx);
    TCGv_i64 mapped = ia64_tr_scratch_i64(ctx);
    TCGv_i64 wrapped = ia64_tr_scratch_i64(ctx);

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
    TCGv_i64 pr = ia64_tr_scratch_i64(ctx);
    TCGv_i64 bit = ia64_tr_scratch_i64(ctx);

    ia64_tr_predicate_bit(ctx, bit, predicate);
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
                                      ia64_tr_scratch_i64(ctx);
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
                                   ia64_tr_scratch_i64(ctx);
    bit = ia64_tr_scratch_i64(ctx);
    ia64_tr_predicate_bit(ctx, bit, predicate);
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
                                   ia64_tr_scratch_i64(ctx);
    bit = ia64_tr_scratch_i64(ctx);
    selected = ia64_tr_scratch_i64(ctx);
    ia64_tr_predicate_bit(ctx, bit, predicate);
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

static void ia64_tr_emit_addp4(DisasContext *ctx, TCGv_i64 dest,
                               TCGv_i64 left, TCGv_i64 right)
{
    TCGv_i64 low32 = ia64_tr_scratch_i64(ctx);
    TCGv_i64 region = ia64_tr_scratch_i64(ctx);

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
    if (reg == 0) {
        tcg_gen_movi_i64(dest, 0);
        return;
    }

    if (ia64_tr_gr_is_stacked(reg)) {
        ia64_tr_read_logical_gr_nat(dest, reg);
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

static void ia64_tr_gr_ref_init(IA64TrGrRef *ref, uint8_t reg)
{
    memset(ref, 0, sizeof(*ref));
    ref->reg = reg;
}

static void ia64_tr_load_static_gr_ref_pair(DisasContext *ctx,
                                            TCGv_i64 value, TCGv_i64 nat,
                                            const IA64TrGrRef *ref)
{
    if (ia64_tr_gr_is_stacked(ref->reg)) {
        tcg_gen_mov_i64(
            value,
            cpu_logical_gr[ia64_tr_logical_gr_index(ref->reg)]);
        ia64_tr_read_logical_gr_nat(nat, ref->reg);
        return;
    }

    ia64_tr_load_static_gr(ctx, value, ref->reg);
    ia64_tr_read_static_gr_nat(ctx, nat, ref->reg);
}

static void ia64_tr_load_static_gr_pair(DisasContext *ctx,
                                        TCGv_i64 value, TCGv_i64 nat,
                                        uint8_t reg)
{
    IA64TrGrRef ref;

    ia64_tr_gr_ref_init(&ref, reg);
    ia64_tr_load_static_gr_ref_pair(ctx, value, nat, &ref);
}

static void ia64_tr_write_gr_nat(DisasContext *ctx, uint8_t reg,
                                 TCGv_i64 value)
{
    if (reg == 0) {
        return;
    }

    if (ia64_tr_gr_is_stacked(reg)) {
        ia64_tr_write_logical_gr_nat(ctx, reg, value);
        ia64_tr_mark_logical_gr_dirty(reg);
        return;
    }

    TCGv_i64 nat = ia64_tr_scratch_i64(ctx);
    TCGv_i64 bit = ia64_tr_scratch_i64(ctx);
    TCGv_i64 selected = ia64_tr_scratch_i64(ctx);

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

static void ia64_tr_store_static_gr_ref_pair(DisasContext *ctx,
                                             const IA64TrGrRef *ref,
                                             TCGv_i64 value,
                                             TCGv_i64 nat_value)
{
    if (ia64_tr_gr_is_stacked(ref->reg)) {
        tcg_gen_mov_i64(
            cpu_logical_gr[ia64_tr_logical_gr_index(ref->reg)], value);
        ia64_tr_write_logical_gr_nat(ctx, ref->reg, nat_value);
        ia64_tr_mark_logical_gr_dirty(ref->reg);
        return;
    }

    ia64_tr_store_static_gr(ctx, ref->reg, value);
    ia64_tr_write_gr_nat(ctx, ref->reg, nat_value);
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
    TCGv_i64 source_unavailable = tcg_temp_new_i64();

    switch (slot->predicate_test_kind) {
    case IA64_PRED_TEST_BIT:
        ia64_tr_load_static_gr(ctx, source3, slot->source3);
        tcg_gen_shri_i64(result, source3, slot->immediate);
        tcg_gen_andi_i64(result, result, 1);
        ia64_tr_read_static_gr_nat(
            ctx, source_unavailable, slot->source3);
        break;
    case IA64_PRED_TEST_NAT:
        ia64_tr_read_static_gr_nat(ctx, result, slot->source3);
        tcg_gen_movi_i64(source_unavailable, 0);
        break;
    case IA64_PRED_TEST_FEATURE:
        tcg_gen_ld_i64(source3, tcg_env,
                       offsetof(CPUIA64State, cpuid) +
                       4 * sizeof(uint64_t));
        tcg_gen_shri_i64(result, source3, slot->immediate);
        tcg_gen_andi_i64(result, result, 1);
        tcg_gen_movi_i64(source_unavailable, 0);
        break;
    default:
        g_assert_not_reached();
    }

    if (slot->predicate_test_relation == IA64_PRED_TEST_ZERO) {
        tcg_gen_xori_i64(result, result, 1);
    }
    if (slot->predicate_write_kind == IA64_PRED_WRITE_NORMAL ||
        slot->predicate_write_kind == IA64_PRED_WRITE_UNCONDITIONAL) {
        TCGv_i64 inverted = tcg_temp_new_i64();
        TCGv_i64 p1_value = tcg_temp_new_i64();
        TCGv_i64 p2_value = tcg_temp_new_i64();

        tcg_gen_xori_i64(inverted, result, 1);
        tcg_gen_movcond_i64(TCG_COND_EQ, p1_value, source_unavailable,
                            tcg_constant_i64(0), result,
                            tcg_constant_i64(0));
        tcg_gen_movcond_i64(TCG_COND_EQ, p2_value, source_unavailable,
                            tcg_constant_i64(0), inverted,
                            tcg_constant_i64(0));
        ia64_tr_write_pr_bool(ctx, slot->predicate1, p1_value);
        ia64_tr_write_pr_bool(ctx, slot->predicate2, p2_value);
    } else {
        /* AND clears on an unavailable bit source; OR classes do not write. */
        tcg_gen_movcond_i64(TCG_COND_EQ, result, source_unavailable,
                            tcg_constant_i64(0), result,
                            tcg_constant_i64(0));
        ia64_tr_emit_predicate_pair_write(ctx, slot, result);
    }
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

static void ia64_tr_publish_fault_state(uint64_t pc, uint8_t slot_index,
                                        uint8_t slot_type, uint64_t raw,
                                        bool group_start)
{
    /*
     * The bundle has a single insn_start, so a fault inside the memory op
     * must find the executing slot in env->ri (see ia64_env_restore_ri).
     * Publish the decoded slot as well: data-fault delivery uses it to set
     * ISR.sp/ed for speculative loads.  The bundle-finish helper republishes
     * PSR.ri and clears the flag.
     */
    tcg_gen_st8_i32(tcg_constant_i32(slot_index), tcg_env,
                    offsetof(CPUIA64State, ri));
    tcg_gen_st8_i32(tcg_constant_i32(1), tcg_env,
                    offsetof(CPUIA64State, ri_dirty));
    tcg_gen_st8_i32(tcg_constant_i32(group_start), tcg_env,
                    offsetof(CPUIA64State, instruction_group_start));
    tcg_gen_st8_i32(tcg_constant_i32(1), tcg_env,
                    offsetof(CPUIA64State, instruction_group_dirty));
    tcg_gen_st8_i32(tcg_constant_i32(1), tcg_env,
                    offsetof(CPUIA64State, current_slot_valid));
    tcg_gen_st8_i32(tcg_constant_i32(slot_index), tcg_env,
                    offsetof(CPUIA64State, current_slot_ri));
    tcg_gen_st8_i32(tcg_constant_i32(slot_type), tcg_env,
                    offsetof(CPUIA64State, current_slot_type));
    tcg_gen_st_i64(tcg_constant_i64(pc), tcg_env,
                   offsetof(CPUIA64State, current_slot_ip));
    tcg_gen_st_i64(tcg_constant_i64(raw), tcg_env,
                   offsetof(CPUIA64State, current_slot_raw));
}

static void ia64_tr_publish_faulting_slot(DisasContext *ctx,
                                          const IA64TcgFastSlot *slot)
{
    uint64_t pc = ctx->base.pc_next - IA64_BUNDLE_SIZE;
    bool group_start = slot->slot_index == 0
                           ? ctx->instruction_group_start
                           : slot->starts_group;

    ia64_tr_publish_fault_state(pc, slot->slot_index, slot->slot_type,
                                slot->raw, group_start);
}

static void ia64_tr_finish_faulting_slot(void)
{
    /*
     * A successful access no longer needs the slot-precise unwind override.
     * A fault exits before this store and restore_state_to_opc consumes it.
     */
    tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                    offsetof(CPUIA64State, instruction_group_dirty));
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

    ia64_tr_publish_faulting_slot(ctx, slot);
    tcg_gen_movi_i64(cpu_ip, ctx->base.pc_next - IA64_BUNDLE_SIZE);
    /*
     * The focused helper owns the logical/physical RSE transition.  It is a
     * normal read/write-global TCG call, so its mirror updates invalidate the
     * memory-backed logical globals before translated execution resumes.
     */
    gen_helper_fast_alloc(tcg_env, tcg_constant_i64(raw));
    ia64_tr_finish_faulting_slot();
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
        ia64_tr_emit_addp4(ctx, result, source2, source3);
        break;
    case IA64_TCG_FAST_OP_ALU_SHLADD:
        ia64_tr_load_static_gr(ctx, source2, slot->source2);
        ia64_tr_load_static_gr(ctx, source3, slot->source3);
        tcg_gen_shli_i64(source2, source2, slot->immediate);
        if (slot->addp4) {
            ia64_tr_emit_addp4(ctx, result, source2, source3);
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
        ia64_tr_publish_faulting_slot(ctx, slot);
        gen_helper_fast_fp_slot(tcg_env,
                                tcg_constant_i32(slot->slot_type),
                                tcg_constant_i64(slot->raw),
                                tcg_constant_i32(slot->slot_index));
        ia64_tr_finish_faulting_slot();
        ia64_tr_note_runtime_dest(slot, runtime_dest_mask,
                                  runtime_dest_mask_hi);
        ia64_tr_finish_fast_slot_predicate_guard(skip);
        return;
    case IA64_TCG_FAST_OP_LDST_LOAD:
    {
        bool special = slot->memory_class != 0 &&
                       slot->memory_class != 4 &&
                       slot->memory_class != 5;
        TCGLabel *memory_done = special ? gen_new_label() : NULL;

        g_assert(ldst_address != NULL);
        ia64_tr_publish_faulting_slot(ctx, slot);
        {
            TCGv_i32 deferred = tcg_temp_new_i32();

            gen_helper_fast_ldst_prepare(
                deferred, tcg_env, ldst_address,
                tcg_constant_i32(slot->target),
                tcg_constant_i32(slot->width),
                tcg_constant_i32(slot->memory_class));
            if (special) {
                tcg_gen_brcondi_i32(TCG_COND_NE, deferred, 0, memory_done);
            }
        }
        if (ia64_tcg_fast_ldst_mode() == IA64_TCG_FAST_LDST_DIRECT) {
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
        ia64_tr_finish_faulting_slot();
        ia64_tr_emit_ldst_base_update(ctx, slot, ldst_address);
        ia64_tr_note_runtime_dest(slot, runtime_dest_mask,
                                  runtime_dest_mask_hi);
        ia64_tr_finish_fast_slot_predicate_guard(skip);
        return;
    }
    case IA64_TCG_FAST_OP_LDST_STORE:
    {
        TCGv_i32 checked = tcg_temp_new_i32();

        g_assert(ldst_address != NULL);
        ia64_tr_publish_faulting_slot(ctx, slot);
        gen_helper_fast_ldst_prepare(
            checked, tcg_env, ldst_address, tcg_constant_i32(0),
            tcg_constant_i32(slot->width),
            tcg_constant_i32(slot->memory_class));
        ia64_tr_load_static_gr(ctx, source2, slot->source2);
        if (ia64_tcg_fast_ldst_mode() == IA64_TCG_FAST_LDST_DIRECT) {
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
        ia64_tr_finish_faulting_slot();
        ia64_tr_emit_ldst_base_update(ctx, slot, ldst_address);
        ia64_tr_note_runtime_dest(slot, runtime_dest_mask,
                                  runtime_dest_mask_hi);
        ia64_tr_finish_fast_slot_predicate_guard(skip);
        return;
    }
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

static bool ia64_tr_fast_bundle_needs_runtime_fallback(
    const IA64TcgFastBundle *fast)
{
    return fast->source_nat_mask != 0 || fast->source_nat_mask_hi != 0;
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
    uint64_t logical_mask[2] = {
        (source_mask >> IA64_STATIC_GR_COUNT) |
            (source_mask_hi << (64 - IA64_STATIC_GR_COUNT)),
        source_mask_hi >> IA64_STATIC_GR_COUNT,
    };

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

    for (unsigned word = 0; word < ARRAY_SIZE(logical_mask); word++) {
        if (logical_mask[word] != 0) {
            TCGv_i64 nat = tcg_temp_new_i64();

            tcg_gen_andi_i64(nat, cpu_logical_nat[word],
                             logical_mask[word]);
            tcg_gen_brcondi_i64(TCG_COND_NE, nat, 0, fallback);
        }
    }
}

static void ia64_tr_emit_fast_bundle_guards(
    DisasContext *ctx, const IA64TcgFastBundle *fast, TCGLabel *fallback,
    TCGv_i64 ldst_address[IA64_SLOT_COUNT])
{
    if ((fast->source_nat_mask | fast->source_nat_mask_hi) != 0) {
        ia64_tr_emit_fast_nat_guards(ctx, fast->source_nat_mask,
                                     fast->source_nat_mask_hi, fallback);
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

static void ia64_tr_emit_gr_alat_invalidate(DisasContext *ctx,
                                            TCGv_i64 dest_mask,
                                            TCGv_i64 dest_mask_hi,
                                            uint64_t pc)
{
    TCGLabel *done = gen_new_label();
    TCGLabel *nonzero = gen_new_label();
    TCGv_i32 valid = ia64_tr_scratch_i32(ctx);

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

static void ia64_tr_group_reserve(DisasContext *ctx,
                                  unsigned instruction_capacity)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;

    g_assert(!group->active && group->current == NULL);
    g_assert(instruction_capacity <= UINT16_MAX);
    if (instruction_capacity <= group->instruction_capacity) {
        return;
    }
    group->instruction = g_renew(IA64TrInstructionTransaction,
                                 group->instruction,
                                 instruction_capacity);
    group->instruction_capacity = instruction_capacity;
}

static intptr_t ia64_tr_group_saved_gr_offset(uint8_t reg)
{
    return offsetof(CPUIA64State, issue_group.saved_gr) +
           reg * sizeof(uint64_t);
}

static intptr_t ia64_tr_group_saved_nat_offset(uint8_t reg)
{
    return offsetof(CPUIA64State, issue_group.saved_nat) +
           reg * sizeof(uint64_t);
}

/*
 * Read an ordinary GR source in the current source-visibility epoch.  This is
 * deliberately not the interface for the SDM's explicitly forwarded values
 * (for example alloc results or checked-load dependencies).
 */
static void ia64_tr_group_load_ordinary_gr_pair(DisasContext *ctx,
                                                TCGv_i64 value,
                                                TCGv_i64 nat, uint8_t reg)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;
    TCGv_i64 live_value;
    TCGv_i64 live_nat;
    TCGv_i64 saved_value;
    TCGv_i64 saved_nat;
    TCGv_i64 mask;
    unsigned half;
    uint64_t bit;

    if (reg == 0) {
        tcg_gen_movi_i64(value, 0);
        tcg_gen_movi_i64(nat, 0);
        return;
    }
    g_assert(group->active);
    half = reg >= 64;
    bit = UINT64_C(1) << (reg % 64);
    if ((group->gr_may_written[half] & bit) == 0) {
        ia64_tr_load_static_gr_pair(ctx, value, nat, reg);
        return;
    }
    if ((group->gr_must_saved[half] & bit) != 0) {
        tcg_gen_ld_i64(value, tcg_env,
                       ia64_tr_group_saved_gr_offset(reg));
        tcg_gen_ld_i64(nat, tcg_env,
                       ia64_tr_group_saved_nat_offset(reg));
        return;
    }

    live_value = ia64_tr_scratch_i64(ctx);
    live_nat = ia64_tr_scratch_i64(ctx);
    saved_value = ia64_tr_scratch_i64(ctx);
    saved_nat = ia64_tr_scratch_i64(ctx);
    mask = ia64_tr_scratch_i64(ctx);
    ia64_tr_load_static_gr_pair(ctx, live_value, live_nat, reg);
    tcg_gen_ld_i64(saved_value, tcg_env,
                   ia64_tr_group_saved_gr_offset(reg));
    tcg_gen_ld_i64(saved_nat, tcg_env,
                   ia64_tr_group_saved_nat_offset(reg));
    tcg_gen_ld_i64(mask, tcg_env,
                   offsetof(CPUIA64State, issue_group.saved_gr_mask) +
                   half * sizeof(uint64_t));
    tcg_gen_andi_i64(mask, mask, bit);
    tcg_gen_movcond_i64(TCG_COND_NE, value, mask, tcg_constant_i64(0),
                        saved_value, live_value);
    tcg_gen_movcond_i64(TCG_COND_NE, nat, mask, tcg_constant_i64(0),
                        saved_nat, live_nat);
}

static void ia64_tr_group_load_ordinary_br(DisasContext *ctx,
                                           TCGv_i64 value, uint8_t reg)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;
    uint8_t bit = 1u << reg;

    g_assert(group->active && reg < IA64_BR_COUNT);
    if ((group->br_may_written & bit) == 0) {
        ia64_tr_load_br(ctx, value, reg);
        return;
    }
    if ((group->br_must_saved & bit) != 0) {
        tcg_gen_ld_i64(value, tcg_env,
                       offsetof(CPUIA64State, issue_group.saved_br) +
                       reg * sizeof(uint64_t));
        return;
    }

    {
        TCGv_i64 live = ia64_tr_scratch_i64(ctx);
        TCGv_i64 saved = ia64_tr_scratch_i64(ctx);
        TCGv_i64 mask = ia64_tr_scratch_i64(ctx);

        ia64_tr_load_br(ctx, live, reg);
        tcg_gen_ld_i64(saved, tcg_env,
                       offsetof(CPUIA64State, issue_group.saved_br) +
                       reg * sizeof(uint64_t));
        tcg_gen_ld8u_i64(mask, tcg_env,
                         offsetof(CPUIA64State,
                                  issue_group.saved_br_mask));
        tcg_gen_andi_i64(mask, mask, bit);
        tcg_gen_movcond_i64(TCG_COND_NE, value, mask,
                            tcg_constant_i64(0), saved, live);
    }
}

static void ia64_tr_group_load_ordinary_pr_image(DisasContext *ctx,
                                                 TCGv_i64 value)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;

    g_assert(group->active);
    if (group->pr_may_written == 0) {
        if (ctx->state_cache_active) {
            tcg_gen_mov_i64(value, ia64_tr_ensure_pr(ctx));
        } else {
            tcg_gen_ld_i64(value, tcg_env, offsetof(CPUIA64State, pr));
        }
    } else if (group->pr_must_saved) {
        tcg_gen_ld_i64(value, tcg_env,
                       offsetof(CPUIA64State, issue_group.saved_pr));
    } else {
        TCGv_i64 live = ia64_tr_scratch_i64(ctx);
        TCGv_i64 saved = ia64_tr_scratch_i64(ctx);
        TCGv_i64 pr_saved = ia64_tr_scratch_i64(ctx);

        if (ctx->state_cache_active) {
            tcg_gen_mov_i64(live, ia64_tr_ensure_pr(ctx));
        } else {
            tcg_gen_ld_i64(live, tcg_env, offsetof(CPUIA64State, pr));
        }
        tcg_gen_ld_i64(saved, tcg_env,
                       offsetof(CPUIA64State, issue_group.saved_pr));
        tcg_gen_ld8u_i64(pr_saved, tcg_env,
                         offsetof(CPUIA64State, issue_group.pr_saved));
        tcg_gen_movcond_i64(TCG_COND_NE, value, pr_saved,
                            tcg_constant_i64(0), saved, live);
    }
    /*
     * This backing image is the architectural broadside rrb_pr=0 view.
     * Only an ordinary single-predicate read applies lazy rrb_pr mapping.
     */
    tcg_gen_ori_i64(value, value, 1);
}

static void ia64_tr_group_load_ordinary_predicate(DisasContext *ctx,
                                                  TCGv_i64 value,
                                                  uint8_t predicate)
{
    TCGv_i64 selected = ia64_tr_scratch_i64(ctx);
    TCGv_i64 bit = ia64_tr_scratch_i64(ctx);

    g_assert(predicate != 0);
    ia64_tr_group_load_ordinary_pr_image(ctx, selected);
    ia64_tr_predicate_bit(ctx, bit, predicate);
    tcg_gen_and_i64(value, selected, bit);
}

static void ia64_tr_group_update_branch_forward_predicate(
    DisasContext *ctx, uint8_t predicate, bool eligible)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;
    TCGv_i64 mask;
    TCGv_i64 bit;

    if (predicate == 0) {
        return;
    }
    g_assert(group->active && group->current != NULL);
    mask = ia64_tr_scratch_i64(ctx);
    bit = ia64_tr_scratch_i64(ctx);
    tcg_gen_ld_i64(mask, tcg_env,
                   offsetof(CPUIA64State,
                            issue_group.branch_pr_forward_mask));
    ia64_tr_predicate_bit(ctx, bit, predicate);
    tcg_gen_andc_i64(mask, mask, bit);
    if (eligible) {
        tcg_gen_or_i64(mask, mask, bit);
    }
    tcg_gen_st_i64(mask, tcg_env,
                   offsetof(CPUIA64State,
                            issue_group.branch_pr_forward_mask));
    group->branch_forward_may_nonzero = true;
    ctx->source_overlay_known_clear = false;
}

static void ia64_tr_group_update_branch_forward_image(
    DisasContext *ctx, uint64_t destination_mask, uint64_t eligible_mask)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;
    TCGv_i64 mask;

    destination_mask &= ~UINT64_C(1);
    eligible_mask &= destination_mask;
    if (destination_mask == 0) {
        return;
    }
    g_assert(group->active && group->current != NULL);
    mask = ia64_tr_scratch_i64(ctx);
    tcg_gen_ld_i64(mask, tcg_env,
                   offsetof(CPUIA64State,
                            issue_group.branch_pr_forward_mask));
    tcg_gen_andi_i64(mask, mask, ~destination_mask);
    if (eligible_mask != 0) {
        tcg_gen_ori_i64(mask, mask, eligible_mask);
    }
    tcg_gen_st_i64(mask, tcg_env,
                   offsetof(CPUIA64State,
                            issue_group.branch_pr_forward_mask));
    group->branch_forward_may_nonzero = true;
    ctx->source_overlay_known_clear = false;
}

static void ia64_tr_group_update_branch_forward_br(
    DisasContext *ctx, uint8_t reg, bool eligible)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;
    uint8_t bit = 1u << reg;
    TCGv_i64 mask = ia64_tr_scratch_i64(ctx);

    g_assert(group->active && group->current != NULL &&
             reg < IA64_BR_COUNT);
    tcg_gen_ld8u_i64(mask, tcg_env,
                     offsetof(CPUIA64State,
                              issue_group.branch_br_forward_mask));
    tcg_gen_andi_i64(mask, mask, (uint8_t)~bit);
    if (eligible) {
        tcg_gen_ori_i64(mask, mask, bit);
    }
    tcg_gen_st8_i64(mask, tcg_env,
                    offsetof(CPUIA64State,
                             issue_group.branch_br_forward_mask));
    group->branch_br_forward_may_nonzero = true;
    ctx->source_overlay_known_clear = false;
}

/*
 * Branches are the sole PR consumers that may bypass the ordinary source
 * epoch.  The persisted physical mask records actual eligible writes; a bit
 * without provenance selects the immutable group-entry image even when the
 * eagerly retired live PR image happens to be newer.
 */
static void ia64_tr_group_load_branch_predicate(DisasContext *ctx,
                                                 TCGv_i64 value,
                                                 uint8_t predicate)
{
    IA64TrInstructionTransaction *instruction =
        ctx->rewrite_group.current;
    TCGv_i64 bit;
    TCGv_i64 forward;
    TCGv_i64 live;
    TCGv_i64 ordinary;
    TCGv_i64 selected;

    if (predicate == 0) {
        tcg_gen_movi_i64(value, 1);
        return;
    }
    g_assert(instruction != NULL &&
             instruction->branch_source_pr ==
                 (UINT64_C(1) << predicate));

    bit = ia64_tr_scratch_i64(ctx);
    forward = ia64_tr_scratch_i64(ctx);
    live = ia64_tr_scratch_i64(ctx);
    ordinary = ia64_tr_scratch_i64(ctx);
    selected = ia64_tr_scratch_i64(ctx);
    ia64_tr_predicate_bit(ctx, bit, predicate);
    tcg_gen_ld_i64(forward, tcg_env,
                   offsetof(CPUIA64State,
                            issue_group.branch_pr_forward_mask));
    tcg_gen_and_i64(forward, forward, bit);
    if (ctx->state_cache_active) {
        tcg_gen_mov_i64(live, ia64_tr_ensure_pr(ctx));
    } else {
        tcg_gen_ld_i64(live, tcg_env, offsetof(CPUIA64State, pr));
    }
    ia64_tr_group_load_ordinary_pr_image(ctx, ordinary);
    tcg_gen_movcond_i64(TCG_COND_NE, selected, forward,
                        tcg_constant_i64(0), live, ordinary);
    tcg_gen_and_i64(value, selected, bit);
}

/*
 * An indirect branch consumes the live BR value only when the most recent
 * in-group producer explicitly published branch-forward provenance.  All
 * other BR consumers retain the immutable group-entry view.
 */
static void ia64_tr_group_load_branch_br(DisasContext *ctx, TCGv_i64 value,
                                         uint8_t reg)
{
    IA64TrInstructionTransaction *instruction =
        ctx->rewrite_group.current;
    uint8_t bit = 1u << reg;
    TCGv_i64 forward;
    TCGv_i64 live;
    TCGv_i64 ordinary;

    g_assert(instruction != NULL && reg < IA64_BR_COUNT &&
             instruction->branch_source_br == bit);
    forward = ia64_tr_scratch_i64(ctx);
    live = ia64_tr_scratch_i64(ctx);
    ordinary = ia64_tr_scratch_i64(ctx);
    tcg_gen_ld8u_i64(forward, tcg_env,
                     offsetof(CPUIA64State,
                              issue_group.branch_br_forward_mask));
    tcg_gen_andi_i64(forward, forward, bit);
    ia64_tr_load_br(ctx, live, reg);
    ia64_tr_group_load_ordinary_br(ctx, ordinary, reg);
    tcg_gen_movcond_i64(TCG_COND_NE, value, forward,
                        tcg_constant_i64(0), live, ordinary);
}

static void ia64_tr_group_load_ordinary_pfs(DisasContext *ctx,
                                            TCGv_i64 value)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;

    g_assert(group->active);
    if (!group->pfs_may_saved) {
        ia64_tr_load_ar(ctx, value, IA64_AR_PFS);
    } else if (group->pfs_must_saved) {
        tcg_gen_ld_i64(value, tcg_env,
                       offsetof(CPUIA64State, issue_group.saved_pfs));
    } else {
        TCGv_i64 live = ia64_tr_scratch_i64(ctx);
        TCGv_i64 saved = ia64_tr_scratch_i64(ctx);
        TCGv_i64 saved_valid = ia64_tr_scratch_i64(ctx);

        ia64_tr_load_ar(ctx, live, IA64_AR_PFS);
        tcg_gen_ld_i64(saved, tcg_env,
                       offsetof(CPUIA64State, issue_group.saved_pfs));
        tcg_gen_ld8u_i64(saved_valid, tcg_env,
                         offsetof(CPUIA64State, issue_group.pfs_saved));
        tcg_gen_movcond_i64(TCG_COND_NE, value, saved_valid,
                            tcg_constant_i64(0), saved, live);
    }
}

/* A branch sees the most recent eligible non-branch PFS write. */
static void ia64_tr_group_load_branch_pfs(DisasContext *ctx, TCGv_i64 value)
{
    IA64TrInstructionTransaction *instruction =
        ctx->rewrite_group.current;
    TCGv_i64 forward;
    TCGv_i64 live;
    TCGv_i64 ordinary;

    g_assert(instruction != NULL && instruction->branch_source_pfs);
    forward = ia64_tr_scratch_i64(ctx);
    live = ia64_tr_scratch_i64(ctx);
    ordinary = ia64_tr_scratch_i64(ctx);
    tcg_gen_ld8u_i64(
        forward, tcg_env,
        offsetof(CPUIA64State, issue_group.branch_pfs_forwarded));
    ia64_tr_load_ar(ctx, live, IA64_AR_PFS);
    ia64_tr_group_load_ordinary_pfs(ctx, ordinary);
    tcg_gen_movcond_i64(TCG_COND_NE, value, forward,
                        tcg_constant_i64(0), live, ordinary);
}

static void ia64_tr_group_write_pfs(DisasContext *ctx, TCGv_i64 value,
                                    bool must_write)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;
    TCGLabel *already_saved = NULL;

    g_assert(group->active && group->current != NULL);
    if (!group->pfs_must_saved) {
        if (group->pfs_may_saved) {
            TCGv_i64 saved_valid = ia64_tr_scratch_i64(ctx);

            already_saved = gen_new_label();
            tcg_gen_ld8u_i64(
                saved_valid, tcg_env,
                offsetof(CPUIA64State, issue_group.pfs_saved));
            tcg_gen_brcondi_i64(TCG_COND_NE, saved_valid, 0,
                                already_saved);
        }
        {
            TCGv_i64 old_pfs = ia64_tr_scratch_i64(ctx);

            ia64_tr_load_ar(ctx, old_pfs, IA64_AR_PFS);
            tcg_gen_st_i64(old_pfs, tcg_env,
                           offsetof(CPUIA64State, issue_group.saved_pfs));
            tcg_gen_st8_i32(
                tcg_constant_i32(1), tcg_env,
                offsetof(CPUIA64State, issue_group.pfs_saved));
        }
        if (already_saved != NULL) {
            gen_set_label(already_saved);
        }
    }
    ia64_tr_store_ar(ctx, IA64_AR_PFS, value);
    tcg_gen_st8_i32(
        tcg_constant_i32(1), tcg_env,
        offsetof(CPUIA64State, issue_group.branch_pfs_forwarded));
    group->pfs_may_saved = true;
    group->pfs_must_saved |= must_write;
    group->branch_pfs_forward_may_nonzero = true;
    ctx->source_overlay_known_clear = false;
}

static void ia64_tr_group_preserve_ordinary_gr_source(DisasContext *ctx,
                                                       IA64TrGrWrite *write,
                                                       const IA64TrGrRef *ref)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;
    uint8_t reg = write->reg;
    TCGv_i64 mask = NULL;
    TCGv_i64 live = ia64_tr_scratch_i64(ctx);
    TCGv_i64 nat = ia64_tr_scratch_i64(ctx);
    TCGLabel *saved = NULL;
    unsigned half = reg >= 64;
    uint64_t bit = UINT64_C(1) << (reg % 64);
    uint64_t may_saved = group->gr_may_saved[half];
    intptr_t mask_offset =
        offsetof(CPUIA64State, issue_group.saved_gr_mask) +
        half * sizeof(uint64_t);

    g_assert(reg != 0 && group->active && write->preserve_source &&
             (group->gr_must_saved[half] & bit) == 0);
    if (may_saved != 0) {
        mask = ia64_tr_scratch_i64(ctx);
        tcg_gen_ld_i64(mask, tcg_env, mask_offset);
        if ((may_saved & bit) != 0) {
            saved = gen_new_label();
            tcg_gen_brcondi_i64(TCG_COND_TSTNE, mask, bit, saved);
        }
    }
    ia64_tr_load_static_gr_ref_pair(ctx, live, nat, ref);
    tcg_gen_st_i64(live, tcg_env, ia64_tr_group_saved_gr_offset(reg));
    tcg_gen_st_i64(nat, tcg_env, ia64_tr_group_saved_nat_offset(reg));
    if (mask == NULL) {
        tcg_gen_st_i64(tcg_constant_i64(bit), tcg_env, mask_offset);
    } else {
        tcg_gen_ori_i64(mask, mask, bit);
        tcg_gen_st_i64(mask, tcg_env, mask_offset);
    }
    if (saved != NULL) {
        gen_set_label(saved);
    }
    group->gr_may_saved[half] |= bit;
    if (write->must_write) {
        group->gr_must_saved[half] |= bit;
    }
    ctx->source_overlay_known_clear = false;
}

static void ia64_tr_group_preserve_ordinary_br_source(
    DisasContext *ctx, IA64TrBrWrite *write)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;
    uint8_t bit = 1u << write->reg;
    TCGv_i64 mask = NULL;
    TCGv_i64 live = ia64_tr_scratch_i64(ctx);
    TCGLabel *saved = NULL;

    g_assert(group->active && write->preserve_source &&
             (group->br_must_saved & bit) == 0);
    if (group->br_may_saved != 0) {
        mask = ia64_tr_scratch_i64(ctx);
        tcg_gen_ld8u_i64(mask, tcg_env,
                         offsetof(CPUIA64State,
                                  issue_group.saved_br_mask));
        if ((group->br_may_saved & bit) != 0) {
            saved = gen_new_label();
            tcg_gen_brcondi_i64(TCG_COND_TSTNE, mask, bit, saved);
        }
    }
    ia64_tr_load_br(ctx, live, write->reg);
    tcg_gen_st_i64(live, tcg_env,
                   offsetof(CPUIA64State, issue_group.saved_br) +
                   write->reg * sizeof(uint64_t));
    if (mask == NULL) {
        tcg_gen_st8_i64(tcg_constant_i64(bit), tcg_env,
                        offsetof(CPUIA64State,
                                 issue_group.saved_br_mask));
    } else {
        tcg_gen_ori_i64(mask, mask, bit);
        tcg_gen_st8_i64(mask, tcg_env,
                        offsetof(CPUIA64State,
                                 issue_group.saved_br_mask));
    }
    if (saved != NULL) {
        gen_set_label(saved);
    }
    group->br_may_saved |= bit;
    if (write->must_write) {
        group->br_must_saved |= bit;
    }
    ctx->source_overlay_known_clear = false;
}

static void ia64_tr_group_preserve_ordinary_pr_source(DisasContext *ctx,
                                                       bool test_valid)
{
    TCGv_i64 pr_saved = NULL;
    TCGv_i64 pr = ia64_tr_scratch_i64(ctx);
    TCGLabel *saved = NULL;

    g_assert(ctx->rewrite_group.active);
    if (test_valid) {
        pr_saved = ia64_tr_scratch_i64(ctx);
        saved = gen_new_label();
        tcg_gen_ld8u_i64(pr_saved, tcg_env,
                         offsetof(CPUIA64State, issue_group.pr_saved));
        tcg_gen_brcondi_i64(TCG_COND_NE, pr_saved, 0, saved);
    }
    if (ctx->state_cache_active) {
        tcg_gen_mov_i64(pr, ia64_tr_ensure_pr(ctx));
    } else {
        tcg_gen_ld_i64(pr, tcg_env, offsetof(CPUIA64State, pr));
    }
    tcg_gen_st_i64(pr, tcg_env,
                   offsetof(CPUIA64State, issue_group.saved_pr));
    tcg_gen_st8_i32(tcg_constant_i32(1), tcg_env,
                    offsetof(CPUIA64State, issue_group.pr_saved));
    if (saved != NULL) {
        gen_set_label(saved);
    }
    ctx->source_overlay_known_clear = false;
}

static void ia64_tr_group_clear_ordinary_source_overlay(DisasContext *ctx)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;

    if (group->gr_may_saved[0] != 0) {
        tcg_gen_st_i64(tcg_constant_i64(0), tcg_env,
                       offsetof(CPUIA64State,
                                issue_group.saved_gr_mask));
    }
    if (group->gr_may_saved[1] != 0) {
        tcg_gen_st_i64(tcg_constant_i64(0), tcg_env,
                       offsetof(CPUIA64State,
                                issue_group.saved_gr_mask) +
                       sizeof(uint64_t));
    }
    if (group->br_may_saved != 0) {
        tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                        offsetof(CPUIA64State,
                                 issue_group.saved_br_mask));
    }
    if (group->pr_may_saved) {
        tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                        offsetof(CPUIA64State, issue_group.pr_saved));
    }
    if (group->branch_forward_may_nonzero) {
        tcg_gen_st_i64(
            tcg_constant_i64(0), tcg_env,
            offsetof(CPUIA64State, issue_group.branch_pr_forward_mask));
    }
    if (group->branch_br_forward_may_nonzero) {
        tcg_gen_st8_i32(
            tcg_constant_i32(0), tcg_env,
            offsetof(CPUIA64State, issue_group.branch_br_forward_mask));
    }
    if (group->pfs_may_saved) {
        tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                        offsetof(CPUIA64State, issue_group.pfs_saved));
    }
    if (group->branch_pfs_forward_may_nonzero) {
        tcg_gen_st8_i32(
            tcg_constant_i32(0), tcg_env,
            offsetof(CPUIA64State, issue_group.branch_pfs_forwarded));
    }
    tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                    offsetof(CPUIA64State, issue_group.typed_active));
}

static void ia64_tr_group_begin_instruction(
    DisasContext *ctx, const IA64Instruction *insn)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;
    IA64TrInstructionTransaction *instruction;
    const IA64TrInstructionPlan *plan;

    g_assert(ctx->rewrite_region_selected);
    g_assert(group->current == NULL);
    g_assert(!ctx->rewrite_scratch_active);
    g_assert(group->instruction_count < group->instruction_capacity);
    g_assert(ctx->rewrite_plan_index < ctx->rewrite_plan_emit_count);
    plan = &ctx->rewrite_plan[ctx->rewrite_plan_index++];
    g_assert(plan->address == insn->address && plan->slot == insn->slot);
    if (!group->active) {
        g_assert(group->instruction_count == 0);
        if (insn->starts_group) {
            g_assert(ctx->source_overlay_known_clear);
            group->gr_may_written[0] = 0;
            group->gr_may_written[1] = 0;
            group->gr_may_saved[0] = 0;
            group->gr_may_saved[1] = 0;
            group->gr_must_saved[0] = 0;
            group->gr_must_saved[1] = 0;
            group->br_may_written = 0;
            group->br_may_saved = 0;
            group->br_must_saved = 0;
            group->pr_may_written = 0;
            group->pr_may_saved = false;
            group->pr_must_saved = false;
            group->branch_forward_may_nonzero = false;
            group->branch_br_forward_may_nonzero = false;
            group->pfs_may_saved = false;
            group->pfs_must_saved = false;
            group->branch_pfs_forward_may_nonzero = false;
        } else {
            g_assert(ctx->typed_group_active);
            group->gr_may_written[0] = UINT64_MAX;
            group->gr_may_written[1] = UINT64_MAX;
            group->gr_may_saved[0] = UINT64_MAX;
            group->gr_may_saved[1] = UINT64_MAX;
            group->gr_must_saved[0] = 0;
            group->gr_must_saved[1] = 0;
            group->br_may_written = UINT8_MAX;
            group->br_may_saved = UINT8_MAX;
            group->br_must_saved = 0;
            group->pr_may_written = UINT64_MAX;
            group->pr_may_saved = true;
            group->pr_must_saved = false;
            group->branch_forward_may_nonzero = true;
            group->branch_br_forward_may_nonzero = true;
            group->pfs_may_saved = true;
            group->pfs_must_saved = false;
            group->branch_pfs_forward_may_nonzero = true;
        }
        group->active = true;
    }
    if (insn->starts_group) {
        uint64_t source_visibility;

        /*
         * translator_loop() emitted this bundle's insn_start before decode
         * selected the typed engine.  Patch the owner bit now so host-PC
         * unwind after activation cannot silently reclassify the epoch as
         * legacy-owned.  Slot-precise fault paths still publish the frontier
         * and set instruction_group_dirty before an exit-capable operation.
         */
        g_assert(ctx->base.insn_start != NULL);
        source_visibility = tcg_get_insn_start_param(
            ctx->base.insn_start, 2);
        tcg_set_insn_start_param(
            ctx->base.insn_start, 2,
            source_visibility | IA64_INSN_START_TYPED_GROUP);
        tcg_gen_st8_i32(tcg_constant_i32(1), tcg_env,
                        offsetof(CPUIA64State, issue_group.typed_active));
        ctx->typed_group_active = true;
    }

    instruction = &group->instruction[group->instruction_count++];
    memset(instruction, 0, sizeof(*instruction));
    instruction->address = insn->address;
    instruction->slot = insn->slot;
    memcpy(instruction->dest_gr, plan->dest_gr,
           sizeof(instruction->dest_gr));
    memcpy(instruction->preserve_gr, plan->preserve_gr,
           sizeof(instruction->preserve_gr));
    memcpy(instruction->must_gr, plan->must_gr,
           sizeof(instruction->must_gr));
    memcpy(instruction->source_ar, plan->source_ar,
           sizeof(instruction->source_ar));
    memcpy(instruction->dest_ar, plan->dest_ar,
           sizeof(instruction->dest_ar));
    instruction->dest_pr = plan->dest_pr;
    instruction->forward_pr = plan->forward_pr;
    g_assert((instruction->forward_pr & ~instruction->dest_pr) == 0);
    instruction->branch_source_pr = plan->branch_source_pr;
    instruction->preserve_pr = plan->preserve_pr;
    instruction->must_pr = plan->must_pr;
    instruction->source_br = plan->source_br;
    instruction->dest_br = plan->dest_br;
    instruction->preserve_br = plan->preserve_br;
    instruction->must_br = plan->must_br;
    instruction->forward_br = plan->forward_br;
    g_assert((instruction->forward_br & ~instruction->dest_br) == 0);
    instruction->branch_source_br = plan->branch_source_br;
    instruction->source_cfm = plan->source_cfm;
    instruction->dest_cfm = plan->dest_cfm;
    instruction->forward_pfs = plan->forward_pfs;
    instruction->branch_source_pfs = plan->branch_source_pfs;
    instruction->must_pfs = plan->must_pfs;
    if (group->pre_ic == NULL) {
        group->pre_ic = tcg_temp_new_i64();
    }
    instruction->pre_ic = group->pre_ic;
    tcg_gen_ld_i64(instruction->pre_ic, tcg_env,
                   offsetof(CPUIA64State, psr));
    tcg_gen_andi_i64(instruction->pre_ic, instruction->pre_ic,
                     IA64_TR_PSR_IC_BIT);
    group->current = instruction;
    ctx->rewrite_i64_scratch_count = 0;
    ctx->rewrite_i32_scratch_count = 0;
    ctx->rewrite_scratch_active = true;
}

static IA64TrGrWrite *ia64_tr_group_prepare_gr(DisasContext *ctx,
                                                uint8_t reg)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;
    IA64TrInstructionTransaction *instruction = group->current;
    IA64TrGrWrite *write;
    unsigned index;

    if (reg == 0) {
        return NULL;
    }
    g_assert(instruction != NULL);
    g_assert(instruction->gr_count < ARRAY_SIZE(instruction->gr));
    index = instruction->gr_count++;
    write = &instruction->gr[index];
    write->reg = reg;
    write->preserve_source =
        (instruction->preserve_gr[reg >= 64] &
         (UINT64_C(1) << (reg % 64))) != 0;
    write->must_write =
        (instruction->must_gr[reg >= 64] &
         (UINT64_C(1) << (reg % 64))) != 0;
    g_assert((instruction->dest_gr[reg >= 64] &
              (UINT64_C(1) << (reg % 64))) != 0);
    if (group->gr_value[index] == NULL) {
        group->gr_value[index] = tcg_temp_new_i64();
        group->gr_nat[index] = tcg_temp_new_i64();
    }
    write->value = group->gr_value[index];
    write->nat = group->gr_nat[index];
    if (write->must_write) {
        write->written = NULL;
    } else {
        if (group->gr_written[index] == NULL) {
            group->gr_written[index] = tcg_temp_new_i64();
        }
        write->written = group->gr_written[index];
        /*
         * TCG values must be defined on every predecessor of a merge label.
         * Retirement consults written before consuming this payload, but the
         * register allocator does not infer that correlation.  Seed optional
         * payloads before any qualifier/no-write branch.
         */
        tcg_gen_movi_i64(write->value, 0);
        tcg_gen_movi_i64(write->nat, 0);
        tcg_gen_movi_i64(write->written, 0);
    }

    /*
     * Prefix-fault paths may publish the state cache.  Prime every backing
     * value on the ordinary path before a predicate can branch around the
     * writer, so the non-fault continuation never inherits an uninitialized
     * translation-time cache selection.
     */
    if (!ia64_tr_gr_is_stacked(reg) && ctx->state_cache_active) {
        ia64_tr_ensure_static_gr(ctx, reg);
        ia64_tr_ensure_gr_nat(ctx);
    }
    return write;
}

static void ia64_tr_group_stage_gr(IA64TrGrWrite *write,
                                   TCGv_i64 value, TCGv_i64 nat)
{
    if (write == NULL) {
        return;
    }
    tcg_gen_mov_i64(write->value, value);
    tcg_gen_mov_i64(write->nat, nat);
    if (!write->must_write) {
        tcg_gen_movi_i64(write->written, 1);
    }
}

static IA64TrBrWrite *ia64_tr_group_prepare_br(DisasContext *ctx,
                                                uint8_t reg)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;
    IA64TrInstructionTransaction *instruction = group->current;
    IA64TrBrWrite *write;
    unsigned index;
    uint8_t bit = 1u << reg;

    g_assert(instruction != NULL && reg < IA64_BR_COUNT);
    g_assert(instruction->br_count < ARRAY_SIZE(instruction->br));
    g_assert((instruction->dest_br & bit) != 0);
    index = instruction->br_count++;
    write = &instruction->br[index];
    write->reg = reg;
    write->preserve_source = (instruction->preserve_br & bit) != 0;
    write->must_write = (instruction->must_br & bit) != 0;
    write->forward_to_branch = (instruction->forward_br & bit) != 0;
    if (group->br_value[index] == NULL) {
        group->br_value[index] = tcg_temp_new_i64();
    }
    write->value = group->br_value[index];
    if (write->must_write) {
        write->written = NULL;
    } else {
        if (group->br_written[index] == NULL) {
            group->br_written[index] = tcg_temp_new_i64();
        }
        write->written = group->br_written[index];
        tcg_gen_movi_i64(write->value, 0);
        tcg_gen_movi_i64(write->written, 0);
    }
    if (ctx->state_cache_active) {
        ia64_tr_ensure_br(ctx, reg);
    }
    return write;
}

static void ia64_tr_group_stage_br(IA64TrBrWrite *write, TCGv_i64 value)
{
    tcg_gen_mov_i64(write->value, value);
    if (!write->must_write) {
        tcg_gen_movi_i64(write->written, 1);
    }
}

static IA64TrPrWrite *ia64_tr_group_prepare_pr(DisasContext *ctx,
                                                uint8_t predicate)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;
    IA64TrInstructionTransaction *instruction = group->current;
    IA64TrPrWrite *write;
    unsigned index;

    if (predicate == 0) {
        return NULL;
    }
    g_assert(instruction != NULL);
    g_assert(!instruction->pr_image.active);
    g_assert(instruction->pr_count < ARRAY_SIZE(instruction->pr));
    index = instruction->pr_count++;
    write = &instruction->pr[index];
    write->predicate = predicate;
    write->must_write =
        (instruction->must_pr & (UINT64_C(1) << predicate)) != 0;
    g_assert((instruction->dest_pr &
              (UINT64_C(1) << predicate)) != 0);
    if (group->pr_value[index] == NULL) {
        group->pr_value[index] = tcg_temp_new_i64();
    }
    write->value = group->pr_value[index];
    if (write->must_write) {
        write->written = NULL;
    } else {
        if (group->pr_written[index] == NULL) {
            group->pr_written[index] = tcg_temp_new_i64();
        }
        write->written = group->pr_written[index];
        /* Keep the optional payload live and defined across merge labels. */
        tcg_gen_movi_i64(write->value, 0);
        tcg_gen_movi_i64(write->written, 0);
    }
    if (ctx->state_cache_active) {
        ia64_tr_ensure_pr(ctx);
    }
    return write;
}

static void ia64_tr_group_stage_pr_bool(IA64TrPrWrite *write,
                                        TCGv_i64 value)
{
    if (write == NULL) {
        return;
    }
    tcg_gen_mov_i64(write->value, value);
    if (!write->must_write) {
        tcg_gen_movi_i64(write->written, 1);
    }
}

static void ia64_tr_group_stage_pr_const(IA64TrPrWrite *write, bool value)
{
    ia64_tr_group_stage_pr_bool(write, tcg_constant_i64(value));
}

static IA64TrPrImageWrite *
ia64_tr_group_prepare_pr_image(DisasContext *ctx, uint64_t mask)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;
    IA64TrInstructionTransaction *instruction = group->current;
    IA64TrPrImageWrite *write;

    mask &= ~UINT64_C(1);
    if (mask == 0) {
        return NULL;
    }
    g_assert(instruction != NULL);
    write = &instruction->pr_image;
    g_assert(!write->active && instruction->pr_count == 0);
    g_assert((instruction->dest_pr & mask) == mask);
    /* A packed move can address rotating PRs only as the complete high 48. */
    g_assert((mask & IA64_TR_PR_ROTATING_MASK) == 0 ||
             (mask & IA64_TR_PR_ROTATING_MASK) ==
                 IA64_TR_PR_ROTATING_MASK);

    write->active = true;
    write->mask = mask;
    write->must_write = (instruction->must_pr & mask) == mask;
    if (group->pr_image_value == NULL) {
        group->pr_image_value = tcg_temp_new_i64();
    }
    write->value = group->pr_image_value;
    if (write->must_write) {
        write->written = NULL;
    } else {
        if (group->pr_image_written == NULL) {
            group->pr_image_written = tcg_temp_new_i64();
        }
        write->written = group->pr_image_written;
        /* Keep the optional payload live and defined across merge labels. */
        tcg_gen_movi_i64(write->value, 0);
        tcg_gen_movi_i64(write->written, 0);
    }
    if (ctx->state_cache_active) {
        ia64_tr_ensure_pr(ctx);
    }
    return write;
}

static void ia64_tr_group_stage_pr_image(IA64TrPrImageWrite *write,
                                         TCGv_i64 value)
{
    if (write == NULL) {
        return;
    }
    tcg_gen_mov_i64(write->value, value);
    if (!write->must_write) {
        tcg_gen_movi_i64(write->written, 1);
    }
}

static void ia64_tr_write_pr_image_masked(DisasContext *ctx,
                                          TCGv_i64 value, uint64_t mask)
{
    TCGv_i64 pr = ctx->state_cache_active ? ia64_tr_ensure_pr(ctx) :
                                            ia64_tr_scratch_i64(ctx);
    TCGv_i64 selected = ia64_tr_scratch_i64(ctx);

    g_assert(mask != 0 && (mask & 1) == 0);
    if (!ctx->state_cache_active) {
        tcg_gen_ld_i64(pr, tcg_env, offsetof(CPUIA64State, pr));
    }
    tcg_gen_andi_i64(selected, value, mask);
    tcg_gen_andi_i64(pr, pr, ~mask);
    tcg_gen_or_i64(pr, pr, selected);
    tcg_gen_ori_i64(pr, pr, 1);
    if (ctx->state_cache_active) {
        ctx->pr_dirty = true;
    } else {
        tcg_gen_st_i64(pr, tcg_env, offsetof(CPUIA64State, pr));
    }
}

static void ia64_tr_group_retire_instruction(
    DisasContext *ctx, IA64TrInstructionTransaction *instruction)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;
    TCGv_i64 dest_mask = NULL;
    TCGv_i64 dest_mask_hi = NULL;

    if (instruction->gr_count != 0) {
        dest_mask = ia64_tr_scratch_i64(ctx);
        dest_mask_hi = ia64_tr_scratch_i64(ctx);
        tcg_gen_movi_i64(dest_mask, 0);
        tcg_gen_movi_i64(dest_mask_hi, 0);
    }
    for (unsigned i = 0; i < instruction->gr_count; i++) {
        IA64TrGrWrite *write = &instruction->gr[i];
        IA64TrGrRef ref;
        unsigned half = write->reg >= 64;
        uint64_t bit = UINT64_C(1) << (write->reg % 64);
        TCGLabel *skip = write->must_write ? NULL : gen_new_label();

        if (skip != NULL) {
            tcg_gen_brcondi_i64(TCG_COND_EQ, write->written, 0, skip);
        }
        ia64_tr_gr_ref_init(&ref, write->reg);
        if (write->preserve_source &&
            (group->gr_must_saved[half] & bit) == 0) {
            ia64_tr_group_preserve_ordinary_gr_source(ctx, write, &ref);
        }
        ia64_tr_store_static_gr_ref_pair(ctx, &ref, write->value,
                                         write->nat);
        if (write->reg < 64) {
            tcg_gen_ori_i64(dest_mask, dest_mask,
                            UINT64_C(1) << write->reg);
        } else {
            tcg_gen_ori_i64(dest_mask_hi, dest_mask_hi,
                            UINT64_C(1) << (write->reg - 64));
        }
        if (skip != NULL) {
            gen_set_label(skip);
        }
    }
    group->gr_may_written[0] |= instruction->dest_gr[0];
    group->gr_may_written[1] |= instruction->dest_gr[1];
    if (dest_mask != NULL) {
        ia64_tr_emit_gr_alat_invalidate(ctx, dest_mask, dest_mask_hi,
                                        instruction->address);
    }

    for (unsigned i = 0; i < instruction->br_count; i++) {
        IA64TrBrWrite *write = &instruction->br[i];
        uint8_t bit = 1u << write->reg;
        TCGLabel *skip = write->must_write ? NULL : gen_new_label();

        if (skip != NULL) {
            tcg_gen_brcondi_i64(TCG_COND_EQ, write->written, 0, skip);
        }
        if (write->preserve_source &&
            (group->br_must_saved & bit) == 0) {
            ia64_tr_group_preserve_ordinary_br_source(ctx, write);
        }
        ia64_tr_store_br(ctx, write->reg, write->value);
        ia64_tr_group_update_branch_forward_br(
            ctx, write->reg, write->forward_to_branch);
        if (skip != NULL) {
            gen_set_label(skip);
        }
    }
    group->br_may_written |= instruction->dest_br;

    if (instruction->preserve_pr != 0 && !group->pr_must_saved) {
        bool preserve_must =
            (instruction->must_pr & instruction->preserve_pr) != 0;
        TCGLabel *skip_preserve = NULL;

        if (!preserve_must) {
            TCGv_i64 any_written = NULL;

            for (unsigned i = 0; i < instruction->pr_count; i++) {
                IA64TrPrWrite *write = &instruction->pr[i];
                uint64_t bit = UINT64_C(1) << write->predicate;

                if ((instruction->preserve_pr & bit) == 0) {
                    continue;
                }
                g_assert(!write->must_write && write->written != NULL);
                if (any_written == NULL) {
                    any_written = write->written;
                } else {
                    TCGv_i64 combined = ia64_tr_scratch_i64(ctx);

                    tcg_gen_or_i64(combined, any_written, write->written);
                    any_written = combined;
                }
            }
            if (instruction->pr_image.active &&
                (instruction->preserve_pr &
                 instruction->pr_image.mask) != 0) {
                IA64TrPrImageWrite *write = &instruction->pr_image;

                g_assert(!write->must_write && write->written != NULL);
                if (any_written == NULL) {
                    any_written = write->written;
                } else {
                    TCGv_i64 combined = ia64_tr_scratch_i64(ctx);

                    tcg_gen_or_i64(combined, any_written, write->written);
                    any_written = combined;
                }
            }
            g_assert(any_written != NULL);
            skip_preserve = gen_new_label();
            tcg_gen_brcondi_i64(TCG_COND_EQ, any_written, 0,
                                skip_preserve);
        }
        ia64_tr_group_preserve_ordinary_pr_source(
            ctx, group->pr_may_saved);
        if (skip_preserve != NULL) {
            gen_set_label(skip_preserve);
        }
        group->pr_may_saved = true;
        if (preserve_must) {
            group->pr_must_saved = true;
        }
    }

    for (unsigned i = 0; i < instruction->pr_count; i++) {
        IA64TrPrWrite *write = &instruction->pr[i];
        TCGLabel *skip = write->must_write ? NULL : gen_new_label();

        if (skip != NULL) {
            tcg_gen_brcondi_i64(TCG_COND_EQ, write->written, 0, skip);
        }
        ia64_tr_write_pr_bool(ctx, write->predicate, write->value);
        ia64_tr_group_update_branch_forward_predicate(
            ctx, write->predicate,
            (instruction->forward_pr &
             (UINT64_C(1) << write->predicate)) != 0);
        if (skip != NULL) {
            gen_set_label(skip);
        }
    }
    if (instruction->pr_image.active) {
        IA64TrPrImageWrite *write = &instruction->pr_image;
        TCGLabel *skip = write->must_write ? NULL : gen_new_label();

        if (skip != NULL) {
            tcg_gen_brcondi_i64(TCG_COND_EQ, write->written, 0, skip);
        }
        ia64_tr_write_pr_image_masked(ctx, write->value, write->mask);
        ia64_tr_group_update_branch_forward_image(
            ctx, write->mask, instruction->forward_pr);
        if (skip != NULL) {
            gen_set_label(skip);
        }
    }
    group->pr_may_written |= instruction->dest_pr;
}

static void ia64_tr_group_finish_instruction_success(
    DisasContext *ctx, const IA64Instruction *insn)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;
    IA64TrInstructionTransaction *instruction = group->current;
    TCGLabel *skip_iipa = gen_new_label();

    g_assert(instruction != NULL && instruction->address == insn->address &&
             instruction->slot == insn->slot);

    /*
     * This is the sole typed finish-success point.  The generated code is
     * reached by predicated-false instructions, but a no-return fault branches
     * away before it.  Retiring here materializes the precise prefix while the
     * first-write overlay keeps later ordinary reads on group-entry values.
     */
    ia64_tr_group_retire_instruction(ctx, instruction);
    tcg_gen_brcondi_i64(TCG_COND_EQ, instruction->pre_ic, 0, skip_iipa);
    tcg_gen_st_i64(tcg_constant_i64(insn->address &
                                    ~(uint64_t)(IA64_BUNDLE_SIZE - 1)),
                   tcg_env, offsetof(CPUIA64State, last_successful_bundle));
    gen_set_label(skip_iipa);
    instruction->pre_ic = NULL;
    for (unsigned i = 0; i < instruction->gr_count; i++) {
        instruction->gr[i].value = NULL;
        instruction->gr[i].nat = NULL;
        instruction->gr[i].written = NULL;
    }
    for (unsigned i = 0; i < instruction->pr_count; i++) {
        instruction->pr[i].value = NULL;
        instruction->pr[i].written = NULL;
    }
    for (unsigned i = 0; i < instruction->br_count; i++) {
        instruction->br[i].value = NULL;
        instruction->br[i].written = NULL;
    }
    instruction->pr_image.value = NULL;
    instruction->pr_image.written = NULL;
    group->current = NULL;
    ctx->rewrite_scratch_active = false;
}

static void ia64_tr_group_publish_prefix_for_noreturn_fault(DisasContext *ctx)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;

    g_assert(group->active && group->current != NULL);
    /*
     * Earlier instructions retired eagerly; only cached state needs export.
     * Clearing the ordinary-source view is valid only because the sole caller
     * immediately invokes a no-return interruption helper.  A returning helper
     * boundary must preserve the overlay instead.
    */
    ia64_tr_sync_state_cache(ctx);
    ia64_tr_group_clear_ordinary_source_overlay(ctx);
}

static void ia64_tr_group_close(DisasContext *ctx)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;

    g_assert(group->active && group->current == NULL &&
             group->instruction_count != 0);
    /* Finish-success already retired every result; a stop must not replay it. */
    ia64_tr_group_clear_ordinary_source_overlay(ctx);
    ctx->typed_group_active = false;
    ctx->source_overlay_known_clear = true;
    group->active = false;
    group->instruction_count = 0;
    group->gr_may_written[0] = 0;
    group->gr_may_written[1] = 0;
    group->gr_may_saved[0] = 0;
    group->gr_may_saved[1] = 0;
    group->gr_must_saved[0] = 0;
    group->gr_must_saved[1] = 0;
    group->br_may_written = 0;
    group->br_may_saved = 0;
    group->br_must_saved = 0;
    group->pr_may_written = 0;
    group->pr_may_saved = false;
    group->pr_must_saved = false;
    group->branch_forward_may_nonzero = false;
    group->branch_br_forward_may_nonzero = false;
    group->pfs_may_saved = false;
    group->pfs_must_saved = false;
    group->branch_pfs_forward_may_nonzero = false;
}

/*
 * End this translation segment without ending the architectural visibility
 * epoch.  Completed instructions are already live and the ordinary-source
 * overlay is CPU state; only translation-time descriptors are discarded.
 */
static void ia64_tr_group_suspend_for_typed_continuation(DisasContext *ctx)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;

    g_assert(group->active && group->current == NULL &&
             group->instruction_count != 0 && ctx->typed_group_active);
    group->active = false;
    group->instruction_count = 0;
}

static bool ia64_tr_group_is_empty(const DisasContext *ctx)
{
    const IA64TrGroupTransaction *group = &ctx->rewrite_group;

    return !group->active && group->current == NULL &&
           group->instruction_count == 0;
}

static IA64SlotType ia64_tr_decoded_slot_type(IA64InstructionUnit unit)
{
    switch (unit) {
    case IA64_INSN_UNIT_M:
        return IA64_SLOT_TYPE_M;
    case IA64_INSN_UNIT_I:
        return IA64_SLOT_TYPE_I;
    case IA64_INSN_UNIT_B:
        return IA64_SLOT_TYPE_B;
    case IA64_INSN_UNIT_F:
        return IA64_SLOT_TYPE_F;
    case IA64_INSN_UNIT_L:
        return IA64_SLOT_TYPE_L;
    case IA64_INSN_UNIT_X:
        return IA64_SLOT_TYPE_X;
    case IA64_INSN_UNIT_RESERVED:
    default:
        return IA64_SLOT_TYPE_INVALID;
    }
}

static void ia64_tr_emit_decoded_illegal_operation(
    DisasContext *ctx, const IA64Instruction *insn)
{
    /*
     * Every earlier instruction reached finish-success and retired in order;
     * the current instruction is still staged.  Export the already-retired
     * cache prefix before publishing the precise faulting slot.
     */
    ia64_tr_group_publish_prefix_for_noreturn_fault(ctx);
    tcg_gen_movi_i64(cpu_ip, insn->address);
    ia64_tr_publish_fault_state(insn->address, insn->slot,
                                ia64_tr_decoded_slot_type(insn->unit),
                                insn->raw, insn->starts_group);
    gen_helper_raise_illegal_operation(tcg_env);
}

static bool ia64_tr_decoded_is_noop(IA64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_NOP:
    case IA64_OP_HINT_M:
    case IA64_OP_HINT_I:
    case IA64_OP_HINT_B:
    case IA64_OP_HINT_F:
    case IA64_OP_HINT_X:
        return true;
    default:
        return false;
    }
}

typedef enum IA64TrDecodedCompareSource {
    IA64_TR_COMPARE_SOURCE_INVALID,
    IA64_TR_COMPARE_SOURCE_REGISTER,
    IA64_TR_COMPARE_SOURCE_ZERO,
    IA64_TR_COMPARE_SOURCE_IMMEDIATE,
} IA64TrDecodedCompareSource;

typedef struct IA64TrDecodedCompare {
    IA64CompareRelation relation;
    IA64PredicateUpdate pred_update;
    IA64TrDecodedCompareSource source;
    uint8_t width;
} IA64TrDecodedCompare;

#define IA64_TR_COMPARE(_width, _relation, _update, _source) \
    {                                                               \
        .relation = (_relation), .pred_update = (_update),          \
        .source = (_source), .width = (_width),                     \
    }

/*
 * Canonical typed-decoder output for the complete hardware A6/A7/A8 matrix.
 * Pseudo-op relations are intentionally absent: the decoder has already
 * normalized those by swapping operands and/or predicate destinations.
 */
static const IA64TrDecodedCompare
ia64_tr_decoded_compare_table[IA64_OP_COUNT] = {
    /* A6 ordinary register forms. */
    [IA64_OP_CMP_LT] =
        IA64_TR_COMPARE(8, IA64_CMP_LT, IA64_PRED_UPDATE_NORMAL,
                        IA64_TR_COMPARE_SOURCE_REGISTER),
    [IA64_OP_CMP_LTU] =
        IA64_TR_COMPARE(8, IA64_CMP_LTU, IA64_PRED_UPDATE_NORMAL,
                        IA64_TR_COMPARE_SOURCE_REGISTER),
    [IA64_OP_CMP_EQ] =
        IA64_TR_COMPARE(8, IA64_CMP_EQ, IA64_PRED_UPDATE_NORMAL,
                        IA64_TR_COMPARE_SOURCE_REGISTER),
    [IA64_OP_CMP4_LT] =
        IA64_TR_COMPARE(4, IA64_CMP_LT, IA64_PRED_UPDATE_NORMAL,
                        IA64_TR_COMPARE_SOURCE_REGISTER),
    [IA64_OP_CMP4_LTU] =
        IA64_TR_COMPARE(4, IA64_CMP_LTU, IA64_PRED_UPDATE_NORMAL,
                        IA64_TR_COMPARE_SOURCE_REGISTER),
    [IA64_OP_CMP4_EQ] =
        IA64_TR_COMPARE(4, IA64_CMP_EQ, IA64_PRED_UPDATE_NORMAL,
                        IA64_TR_COMPARE_SOURCE_REGISTER),

    /* A6 parallel register forms. */
    [IA64_OP_CMP_EQ_AND] =
        IA64_TR_COMPARE(8, IA64_CMP_EQ, IA64_PRED_UPDATE_AND,
                        IA64_TR_COMPARE_SOURCE_REGISTER),
    [IA64_OP_CMP_NE_AND] =
        IA64_TR_COMPARE(8, IA64_CMP_NE, IA64_PRED_UPDATE_AND,
                        IA64_TR_COMPARE_SOURCE_REGISTER),
    [IA64_OP_CMP_EQ_OR] =
        IA64_TR_COMPARE(8, IA64_CMP_EQ, IA64_PRED_UPDATE_OR,
                        IA64_TR_COMPARE_SOURCE_REGISTER),
    [IA64_OP_CMP_NE_OR] =
        IA64_TR_COMPARE(8, IA64_CMP_NE, IA64_PRED_UPDATE_OR,
                        IA64_TR_COMPARE_SOURCE_REGISTER),
    [IA64_OP_CMP_EQ_OR_ANDCM] =
        IA64_TR_COMPARE(8, IA64_CMP_EQ, IA64_PRED_UPDATE_OR_ANDCM,
                        IA64_TR_COMPARE_SOURCE_REGISTER),
    [IA64_OP_CMP_NE_OR_ANDCM] =
        IA64_TR_COMPARE(8, IA64_CMP_NE, IA64_PRED_UPDATE_OR_ANDCM,
                        IA64_TR_COMPARE_SOURCE_REGISTER),
    [IA64_OP_CMP4_EQ_AND] =
        IA64_TR_COMPARE(4, IA64_CMP_EQ, IA64_PRED_UPDATE_AND,
                        IA64_TR_COMPARE_SOURCE_REGISTER),
    [IA64_OP_CMP4_NE_AND] =
        IA64_TR_COMPARE(4, IA64_CMP_NE, IA64_PRED_UPDATE_AND,
                        IA64_TR_COMPARE_SOURCE_REGISTER),
    [IA64_OP_CMP4_EQ_OR] =
        IA64_TR_COMPARE(4, IA64_CMP_EQ, IA64_PRED_UPDATE_OR,
                        IA64_TR_COMPARE_SOURCE_REGISTER),
    [IA64_OP_CMP4_NE_OR] =
        IA64_TR_COMPARE(4, IA64_CMP_NE, IA64_PRED_UPDATE_OR,
                        IA64_TR_COMPARE_SOURCE_REGISTER),
    [IA64_OP_CMP4_EQ_OR_ANDCM] =
        IA64_TR_COMPARE(4, IA64_CMP_EQ, IA64_PRED_UPDATE_OR_ANDCM,
                        IA64_TR_COMPARE_SOURCE_REGISTER),
    [IA64_OP_CMP4_NE_OR_ANDCM] =
        IA64_TR_COMPARE(4, IA64_CMP_NE, IA64_PRED_UPDATE_OR_ANDCM,
                        IA64_TR_COMPARE_SOURCE_REGISTER),

    /* A7 parallel comparisons against zero. */
    [IA64_OP_CMP_GT_AND] =
        IA64_TR_COMPARE(8, IA64_CMP_GT, IA64_PRED_UPDATE_AND,
                        IA64_TR_COMPARE_SOURCE_ZERO),
    [IA64_OP_CMP_LE_AND] =
        IA64_TR_COMPARE(8, IA64_CMP_LE, IA64_PRED_UPDATE_AND,
                        IA64_TR_COMPARE_SOURCE_ZERO),
    [IA64_OP_CMP_GE_AND] =
        IA64_TR_COMPARE(8, IA64_CMP_GE, IA64_PRED_UPDATE_AND,
                        IA64_TR_COMPARE_SOURCE_ZERO),
    [IA64_OP_CMP_LT_AND] =
        IA64_TR_COMPARE(8, IA64_CMP_LT, IA64_PRED_UPDATE_AND,
                        IA64_TR_COMPARE_SOURCE_ZERO),
    [IA64_OP_CMP_GT_OR] =
        IA64_TR_COMPARE(8, IA64_CMP_GT, IA64_PRED_UPDATE_OR,
                        IA64_TR_COMPARE_SOURCE_ZERO),
    [IA64_OP_CMP_LE_OR] =
        IA64_TR_COMPARE(8, IA64_CMP_LE, IA64_PRED_UPDATE_OR,
                        IA64_TR_COMPARE_SOURCE_ZERO),
    [IA64_OP_CMP_GE_OR] =
        IA64_TR_COMPARE(8, IA64_CMP_GE, IA64_PRED_UPDATE_OR,
                        IA64_TR_COMPARE_SOURCE_ZERO),
    [IA64_OP_CMP_LT_OR] =
        IA64_TR_COMPARE(8, IA64_CMP_LT, IA64_PRED_UPDATE_OR,
                        IA64_TR_COMPARE_SOURCE_ZERO),
    [IA64_OP_CMP_GT_OR_ANDCM] =
        IA64_TR_COMPARE(8, IA64_CMP_GT, IA64_PRED_UPDATE_OR_ANDCM,
                        IA64_TR_COMPARE_SOURCE_ZERO),
    [IA64_OP_CMP_LE_OR_ANDCM] =
        IA64_TR_COMPARE(8, IA64_CMP_LE, IA64_PRED_UPDATE_OR_ANDCM,
                        IA64_TR_COMPARE_SOURCE_ZERO),
    [IA64_OP_CMP_GE_OR_ANDCM] =
        IA64_TR_COMPARE(8, IA64_CMP_GE, IA64_PRED_UPDATE_OR_ANDCM,
                        IA64_TR_COMPARE_SOURCE_ZERO),
    [IA64_OP_CMP_LT_OR_ANDCM] =
        IA64_TR_COMPARE(8, IA64_CMP_LT, IA64_PRED_UPDATE_OR_ANDCM,
                        IA64_TR_COMPARE_SOURCE_ZERO),
    [IA64_OP_CMP4_GT_AND] =
        IA64_TR_COMPARE(4, IA64_CMP_GT, IA64_PRED_UPDATE_AND,
                        IA64_TR_COMPARE_SOURCE_ZERO),
    [IA64_OP_CMP4_LE_AND] =
        IA64_TR_COMPARE(4, IA64_CMP_LE, IA64_PRED_UPDATE_AND,
                        IA64_TR_COMPARE_SOURCE_ZERO),
    [IA64_OP_CMP4_GE_AND] =
        IA64_TR_COMPARE(4, IA64_CMP_GE, IA64_PRED_UPDATE_AND,
                        IA64_TR_COMPARE_SOURCE_ZERO),
    [IA64_OP_CMP4_LT_AND] =
        IA64_TR_COMPARE(4, IA64_CMP_LT, IA64_PRED_UPDATE_AND,
                        IA64_TR_COMPARE_SOURCE_ZERO),
    [IA64_OP_CMP4_GT_OR] =
        IA64_TR_COMPARE(4, IA64_CMP_GT, IA64_PRED_UPDATE_OR,
                        IA64_TR_COMPARE_SOURCE_ZERO),
    [IA64_OP_CMP4_LE_OR] =
        IA64_TR_COMPARE(4, IA64_CMP_LE, IA64_PRED_UPDATE_OR,
                        IA64_TR_COMPARE_SOURCE_ZERO),
    [IA64_OP_CMP4_GE_OR] =
        IA64_TR_COMPARE(4, IA64_CMP_GE, IA64_PRED_UPDATE_OR,
                        IA64_TR_COMPARE_SOURCE_ZERO),
    [IA64_OP_CMP4_LT_OR] =
        IA64_TR_COMPARE(4, IA64_CMP_LT, IA64_PRED_UPDATE_OR,
                        IA64_TR_COMPARE_SOURCE_ZERO),
    [IA64_OP_CMP4_GT_OR_ANDCM] =
        IA64_TR_COMPARE(4, IA64_CMP_GT, IA64_PRED_UPDATE_OR_ANDCM,
                        IA64_TR_COMPARE_SOURCE_ZERO),
    [IA64_OP_CMP4_LE_OR_ANDCM] =
        IA64_TR_COMPARE(4, IA64_CMP_LE, IA64_PRED_UPDATE_OR_ANDCM,
                        IA64_TR_COMPARE_SOURCE_ZERO),
    [IA64_OP_CMP4_GE_OR_ANDCM] =
        IA64_TR_COMPARE(4, IA64_CMP_GE, IA64_PRED_UPDATE_OR_ANDCM,
                        IA64_TR_COMPARE_SOURCE_ZERO),
    [IA64_OP_CMP4_LT_OR_ANDCM] =
        IA64_TR_COMPARE(4, IA64_CMP_LT, IA64_PRED_UPDATE_OR_ANDCM,
                        IA64_TR_COMPARE_SOURCE_ZERO),

    /* A8 ordinary immediate forms. */
    [IA64_OP_CMP_LT_IMM] =
        IA64_TR_COMPARE(8, IA64_CMP_LT, IA64_PRED_UPDATE_NORMAL,
                        IA64_TR_COMPARE_SOURCE_IMMEDIATE),
    [IA64_OP_CMP_LTU_IMM] =
        IA64_TR_COMPARE(8, IA64_CMP_LTU, IA64_PRED_UPDATE_NORMAL,
                        IA64_TR_COMPARE_SOURCE_IMMEDIATE),
    [IA64_OP_CMP_EQ_IMM] =
        IA64_TR_COMPARE(8, IA64_CMP_EQ, IA64_PRED_UPDATE_NORMAL,
                        IA64_TR_COMPARE_SOURCE_IMMEDIATE),
    [IA64_OP_CMP4_LT_IMM] =
        IA64_TR_COMPARE(4, IA64_CMP_LT, IA64_PRED_UPDATE_NORMAL,
                        IA64_TR_COMPARE_SOURCE_IMMEDIATE),
    [IA64_OP_CMP4_LTU_IMM] =
        IA64_TR_COMPARE(4, IA64_CMP_LTU, IA64_PRED_UPDATE_NORMAL,
                        IA64_TR_COMPARE_SOURCE_IMMEDIATE),
    [IA64_OP_CMP4_EQ_IMM] =
        IA64_TR_COMPARE(4, IA64_CMP_EQ, IA64_PRED_UPDATE_NORMAL,
                        IA64_TR_COMPARE_SOURCE_IMMEDIATE),

    /* A8 parallel immediate forms. */
    [IA64_OP_CMP_EQ_AND_IMM] =
        IA64_TR_COMPARE(8, IA64_CMP_EQ, IA64_PRED_UPDATE_AND,
                        IA64_TR_COMPARE_SOURCE_IMMEDIATE),
    [IA64_OP_CMP_NE_AND_IMM] =
        IA64_TR_COMPARE(8, IA64_CMP_NE, IA64_PRED_UPDATE_AND,
                        IA64_TR_COMPARE_SOURCE_IMMEDIATE),
    [IA64_OP_CMP_EQ_OR_IMM] =
        IA64_TR_COMPARE(8, IA64_CMP_EQ, IA64_PRED_UPDATE_OR,
                        IA64_TR_COMPARE_SOURCE_IMMEDIATE),
    [IA64_OP_CMP_NE_OR_IMM] =
        IA64_TR_COMPARE(8, IA64_CMP_NE, IA64_PRED_UPDATE_OR,
                        IA64_TR_COMPARE_SOURCE_IMMEDIATE),
    [IA64_OP_CMP_EQ_OR_ANDCM_IMM] =
        IA64_TR_COMPARE(8, IA64_CMP_EQ, IA64_PRED_UPDATE_OR_ANDCM,
                        IA64_TR_COMPARE_SOURCE_IMMEDIATE),
    [IA64_OP_CMP_NE_OR_ANDCM_IMM] =
        IA64_TR_COMPARE(8, IA64_CMP_NE, IA64_PRED_UPDATE_OR_ANDCM,
                        IA64_TR_COMPARE_SOURCE_IMMEDIATE),
    [IA64_OP_CMP4_EQ_AND_IMM] =
        IA64_TR_COMPARE(4, IA64_CMP_EQ, IA64_PRED_UPDATE_AND,
                        IA64_TR_COMPARE_SOURCE_IMMEDIATE),
    [IA64_OP_CMP4_NE_AND_IMM] =
        IA64_TR_COMPARE(4, IA64_CMP_NE, IA64_PRED_UPDATE_AND,
                        IA64_TR_COMPARE_SOURCE_IMMEDIATE),
    [IA64_OP_CMP4_EQ_OR_IMM] =
        IA64_TR_COMPARE(4, IA64_CMP_EQ, IA64_PRED_UPDATE_OR,
                        IA64_TR_COMPARE_SOURCE_IMMEDIATE),
    [IA64_OP_CMP4_NE_OR_IMM] =
        IA64_TR_COMPARE(4, IA64_CMP_NE, IA64_PRED_UPDATE_OR,
                        IA64_TR_COMPARE_SOURCE_IMMEDIATE),
    [IA64_OP_CMP4_EQ_OR_ANDCM_IMM] =
        IA64_TR_COMPARE(4, IA64_CMP_EQ, IA64_PRED_UPDATE_OR_ANDCM,
                        IA64_TR_COMPARE_SOURCE_IMMEDIATE),
    [IA64_OP_CMP4_NE_OR_ANDCM_IMM] =
        IA64_TR_COMPARE(4, IA64_CMP_NE, IA64_PRED_UPDATE_OR_ANDCM,
                        IA64_TR_COMPARE_SOURCE_IMMEDIATE),
};

#undef IA64_TR_COMPARE

static const IA64TrDecodedCompare *
ia64_tr_decoded_compare(IA64Opcode opcode)
{
    if ((unsigned)opcode >= ARRAY_SIZE(ia64_tr_decoded_compare_table) ||
        ia64_tr_decoded_compare_table[opcode].source ==
            IA64_TR_COMPARE_SOURCE_INVALID) {
        return NULL;
    }
    return &ia64_tr_decoded_compare_table[opcode];
}

static bool ia64_tr_decoded_is_integer_compare_opcode(IA64Opcode opcode)
{
    return ia64_tr_decoded_compare(opcode) != NULL;
}

typedef enum IA64TrDecodedPredicateTestKind {
    IA64_TR_PREDICATE_TEST_INVALID,
    IA64_TR_PREDICATE_TEST_BIT,
    IA64_TR_PREDICATE_TEST_NAT,
    IA64_TR_PREDICATE_TEST_FEATURE,
} IA64TrDecodedPredicateTestKind;

typedef struct IA64TrDecodedPredicateTest {
    IA64TrDecodedPredicateTestKind kind;
    bool nonzero;
} IA64TrDecodedPredicateTest;

static const IA64TrDecodedPredicateTest
ia64_tr_decoded_predicate_test_table[IA64_OP_COUNT] = {
    [IA64_OP_TBIT_Z] = { IA64_TR_PREDICATE_TEST_BIT, false },
    [IA64_OP_TBIT_NZ] = { IA64_TR_PREDICATE_TEST_BIT, true },
    [IA64_OP_TNAT_Z] = { IA64_TR_PREDICATE_TEST_NAT, false },
    [IA64_OP_TNAT_NZ] = { IA64_TR_PREDICATE_TEST_NAT, true },
    [IA64_OP_TF_Z] = { IA64_TR_PREDICATE_TEST_FEATURE, false },
    [IA64_OP_TF_NZ] = { IA64_TR_PREDICATE_TEST_FEATURE, true },
};

static const IA64TrDecodedPredicateTest *
ia64_tr_decoded_predicate_test(IA64Opcode opcode)
{
    if ((unsigned)opcode >= ARRAY_SIZE(ia64_tr_decoded_predicate_test_table) ||
        ia64_tr_decoded_predicate_test_table[opcode].kind ==
            IA64_TR_PREDICATE_TEST_INVALID) {
        return NULL;
    }
    return &ia64_tr_decoded_predicate_test_table[opcode];
}

static bool ia64_tr_decoded_is_predicate_test_opcode(IA64Opcode opcode)
{
    return ia64_tr_decoded_predicate_test(opcode) != NULL;
}

static bool ia64_tr_decoded_is_direct_conditional_branch(IA64Opcode opcode)
{
    return opcode == IA64_OP_BR_COND || opcode == IA64_OP_BRL_COND;
}

static bool ia64_tr_decoded_is_loop_branch(IA64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_BR_CLOOP:
    case IA64_OP_BR_CTOP:
    case IA64_OP_BR_CEXIT:
    case IA64_OP_BR_WTOP:
    case IA64_OP_BR_WEXIT:
        return true;
    default:
        return false;
    }
}

static bool ia64_tr_decoded_is_call_branch(IA64Opcode opcode)
{
    return opcode == IA64_OP_BR_CALL ||
           opcode == IA64_OP_BRL_CALL ||
           opcode == IA64_OP_BR_CALL_INDIRECT;
}

static bool ia64_tr_decoded_is_return_branch(IA64Opcode opcode)
{
    return opcode == IA64_OP_BR_RET;
}

static bool ia64_tr_decoded_is_conditional_branch(IA64Opcode opcode)
{
    return ia64_tr_decoded_is_direct_conditional_branch(opcode) ||
           opcode == IA64_OP_BR_INDIRECT ||
           ia64_tr_decoded_is_loop_branch(opcode) ||
           ia64_tr_decoded_is_call_branch(opcode) ||
           ia64_tr_decoded_is_return_branch(opcode);
}

static bool ia64_tr_decoded_is_supported_predicate_test(
    const IA64Instruction *insn)
{
    const IA64TrDecodedPredicateTest *test =
        ia64_tr_decoded_predicate_test(insn->opcode);

    if (test == NULL || insn->unit != IA64_INSN_UNIT_I ||
        insn->pred_update > IA64_PRED_UPDATE_OR_ANDCM ||
        (insn->pred_update != IA64_PRED_UPDATE_NORMAL &&
         insn->compare_unc) ||
        (insn->pred_update == IA64_PRED_UPDATE_NORMAL && test->nonzero)) {
        return false;
    }

    switch (test->kind) {
    case IA64_TR_PREDICATE_TEST_BIT:
        return insn->imm >= 0 && insn->imm < 64;
    case IA64_TR_PREDICATE_TEST_NAT:
        return insn->imm == 0;
    case IA64_TR_PREDICATE_TEST_FEATURE:
        return insn->r3 == 0 && insn->imm >= 32 && insn->imm < 64;
    case IA64_TR_PREDICATE_TEST_INVALID:
    default:
        return false;
    }
}

static bool ia64_tr_decoded_is_supported_integer_compare(
    const IA64Instruction *insn)
{
    const IA64TrDecodedCompare *compare =
        ia64_tr_decoded_compare(insn->opcode);

    /* Trust the typed decode, but fail closed if its normalized fields drift. */
    return compare != NULL &&
           (insn->unit == IA64_INSN_UNIT_M ||
            insn->unit == IA64_INSN_UNIT_I) &&
           insn->compare_width == compare->width &&
           insn->compare_immediate ==
               (compare->source == IA64_TR_COMPARE_SOURCE_IMMEDIATE) &&
           insn->pred_update == compare->pred_update &&
           (compare->pred_update == IA64_PRED_UPDATE_NORMAL ||
            !insn->compare_unc) &&
           (compare->source != IA64_TR_COMPARE_SOURCE_ZERO ||
            insn->r2 == 0) &&
           (compare->source != IA64_TR_COMPARE_SOURCE_IMMEDIATE ||
            (insn->imm >= -128 && insn->imm <= 127));
}

static bool ia64_tr_decoded_opcode_supported(IA64Opcode opcode)
{
    /*
     * This first typed tranche contains only ordinary group-entry sources and
     * scalar GR/PR/BR destinations.  Keep general alloc/CFM/PFS, checked-load,
     * and memory/ALAT families out until each has its dedicated SDM forwarding
     * or sequential-effect interface.  Calls use their one focused frame
     * transition after the ordered link write has retired.  B4/B5 indirect
     * targets are admitted only through their explicit branch-only BR selector;
     * the ordinary overlay is not a substitute for that rule.
     */
    if (ia64_tr_decoded_is_noop(opcode) ||
        ia64_tr_decoded_is_integer_compare_opcode(opcode) ||
        ia64_tr_decoded_is_predicate_test_opcode(opcode) ||
        ia64_tr_decoded_is_conditional_branch(opcode)) {
        return true;
    }

    switch (opcode) {
    case IA64_OP_MOVL:
    case IA64_OP_ADDS:
    case IA64_OP_ADDL:
    case IA64_OP_ADD:
    case IA64_OP_ADD_ONE:
    case IA64_OP_SUB:
    case IA64_OP_SUB_ONE:
    case IA64_OP_SUB_IMM:
    case IA64_OP_AND:
    case IA64_OP_ANDCM:
    case IA64_OP_OR:
    case IA64_OP_XOR:
    case IA64_OP_AND_IMM:
    case IA64_OP_ANDCM_IMM:
    case IA64_OP_OR_IMM:
    case IA64_OP_XOR_IMM:
    case IA64_OP_SHLADD:
    case IA64_OP_SHL:
    case IA64_OP_SHR:
    case IA64_OP_SHRU:
    case IA64_OP_SHRP_IMM:
    case IA64_OP_DEPZ:
    case IA64_OP_DEPZ_IMM:
    case IA64_OP_DEP:
    case IA64_OP_DEP_IMM:
    case IA64_OP_EXTR:
    case IA64_OP_EXTRU:
    case IA64_OP_SXT1:
    case IA64_OP_SXT2:
    case IA64_OP_SXT4:
    case IA64_OP_ZXT1:
    case IA64_OP_ZXT2:
    case IA64_OP_ZXT4:
    case IA64_OP_SHLADDP4:
    case IA64_OP_MPY4:
    case IA64_OP_MPYSHL4:
    case IA64_OP_POPCNT:
    case IA64_OP_CLZ:
    case IA64_OP_ADDP4:
    case IA64_OP_ADDP4_IMM:
    case IA64_OP_MOV_PRGR:
    case IA64_OP_MOV_GRPR:
    case IA64_OP_MOV_PR_ROT_IMM:
    case IA64_OP_MOV_BRGR:
    case IA64_OP_MOV_GRBR:
    case IA64_OP_MOV_ARGR:
    case IA64_OP_MOV_GRAR:
        return true;
    default:
        return false;
    }
}

static unsigned ia64_tr_decoded_sources(const IA64Instruction *insn,
                                        uint8_t sources[3])
{
    const IA64TrDecodedCompare *compare =
        ia64_tr_decoded_compare(insn->opcode);
    const IA64TrDecodedPredicateTest *test =
        ia64_tr_decoded_predicate_test(insn->opcode);

    if (compare != NULL) {
        if (compare->source == IA64_TR_COMPARE_SOURCE_REGISTER &&
            insn->r2 != 0) {
            sources[0] = insn->r2;
            if (insn->r2 == insn->r3) {
                return 1;
            }
            sources[1] = insn->r3;
            return 2;
        }
        /* A7's zero and A8's immediate cannot contribute a source NaT. */
        sources[0] = insn->r3;
        return 1;
    }

    if (test != NULL) {
        if (test->kind == IA64_TR_PREDICATE_TEST_FEATURE) {
            return 0;
        }
        sources[0] = insn->r3;
        return 1;
    }

    switch (insn->opcode) {
    case IA64_OP_MOV_GRPR:
        /* The decoder stores mov pr=r's ordinary GR source in r1. */
        sources[0] = insn->r1;
        return 1;
    case IA64_OP_MOV_GRBR:
        /* The decoder stores mov b=r's ordinary GR source in r1. */
        sources[0] = insn->r1;
        return 1;
    case IA64_OP_MOV_GRAR:
        /* This tranche admits only the I-unit mov ar.pfs=r form. */
        sources[0] = insn->r1;
        return 1;
    case IA64_OP_ADDS:
    case IA64_OP_ADDL:
    case IA64_OP_SUB_IMM:
    case IA64_OP_AND_IMM:
    case IA64_OP_ANDCM_IMM:
    case IA64_OP_OR_IMM:
    case IA64_OP_XOR_IMM:
    case IA64_OP_DEP_IMM:
    case IA64_OP_EXTR:
    case IA64_OP_EXTRU:
    case IA64_OP_SXT1:
    case IA64_OP_SXT2:
    case IA64_OP_SXT4:
    case IA64_OP_ZXT1:
    case IA64_OP_ZXT2:
    case IA64_OP_ZXT4:
    case IA64_OP_POPCNT:
    case IA64_OP_CLZ:
    case IA64_OP_ADDP4_IMM:
        sources[0] = insn->r3;
        return 1;
    case IA64_OP_DEPZ:
        sources[0] = insn->r2;
        return 1;
    case IA64_OP_ADD:
    case IA64_OP_ADD_ONE:
    case IA64_OP_SUB:
    case IA64_OP_SUB_ONE:
    case IA64_OP_AND:
    case IA64_OP_ANDCM:
    case IA64_OP_OR:
    case IA64_OP_XOR:
    case IA64_OP_SHLADD:
    case IA64_OP_SHL:
    case IA64_OP_SHR:
    case IA64_OP_SHRU:
    case IA64_OP_SHRP_IMM:
    case IA64_OP_DEP:
    case IA64_OP_SHLADDP4:
    case IA64_OP_MPY4:
    case IA64_OP_MPYSHL4:
    case IA64_OP_ADDP4:
        sources[0] = insn->r2;
        sources[1] = insn->r3;
        return 2;
    default:
        return 0;
    }
}

static bool ia64_tr_decoded_instruction_supported(
    const IA64Instruction *insn)
{
    uint64_t rotating_dest = 0;
    bool branch_shape = true;

    if (insn->opcode == IA64_OP_MOV_GRPR) {
        rotating_dest = (uint64_t)insn->imm & IA64_TR_PR_ROTATING_MASK;
    } else if (insn->opcode == IA64_OP_MOV_PR_ROT_IMM) {
        rotating_dest = IA64_TR_PR_ROTATING_MASK;
    }
    if (insn->opcode == IA64_OP_MOV_ARGR ||
        insn->opcode == IA64_OP_MOV_GRAR) {
        branch_shape = insn->unit == IA64_INSN_UNIT_I &&
                       insn->slot_span == 1 &&
                       insn->r2 == IA64_AR_PFS;
    }
    if (insn->opcode == IA64_OP_BR_COND) {
        branch_shape = insn->unit == IA64_INSN_UNIT_B &&
                       insn->slot_span == 1 && (insn->imm & 0xf) == 0;
    } else if (insn->opcode == IA64_OP_BRL_COND) {
        branch_shape = insn->unit == IA64_INSN_UNIT_X &&
                       insn->slot_span == 2 && (insn->imm & 0xf) == 0;
    } else if (insn->opcode == IA64_OP_BR_INDIRECT) {
        branch_shape = insn->unit == IA64_INSN_UNIT_B &&
                       insn->slot_span == 1 && insn->b2 < IA64_BR_COUNT;
    } else if (insn->opcode == IA64_OP_BR_RET) {
        branch_shape = insn->unit == IA64_INSN_UNIT_B &&
                       insn->slot_span == 1 && insn->b2 < IA64_BR_COUNT;
    } else if (insn->opcode == IA64_OP_BR_CALL) {
        branch_shape = insn->unit == IA64_INSN_UNIT_B &&
                       insn->slot_span == 1 &&
                       insn->b1 < IA64_BR_COUNT &&
                       (insn->imm & 0xf) == 0;
    } else if (insn->opcode == IA64_OP_BRL_CALL) {
        branch_shape = insn->unit == IA64_INSN_UNIT_X &&
                       insn->slot == 1 && insn->slot_span == 2 &&
                       insn->b1 < IA64_BR_COUNT &&
                       (insn->imm & 0xf) == 0;
    } else if (insn->opcode == IA64_OP_BR_CALL_INDIRECT) {
        branch_shape = insn->unit == IA64_INSN_UNIT_B &&
                       insn->slot_span == 1 &&
                       insn->b1 < IA64_BR_COUNT &&
                       insn->b2 < IA64_BR_COUNT;
    } else if (ia64_tr_decoded_is_loop_branch(insn->opcode)) {
        bool while_form = insn->opcode == IA64_OP_BR_WTOP ||
                          insn->opcode == IA64_OP_BR_WEXIT;

        branch_shape = insn->unit == IA64_INSN_UNIT_B &&
                       insn->slot == IA64_SLOT_COUNT - 1 &&
                       insn->slot_span == 1 && (insn->imm & 0xf) == 0 &&
                       (while_form || insn->qp == 0);
    }
    return insn->valid && insn->status == IA64_DECODE_OK &&
           ia64_tr_decoded_opcode_supported(insn->opcode) &&
           branch_shape &&
           (rotating_dest == 0 ||
            rotating_dest == IA64_TR_PR_ROTATING_MASK) &&
           (!ia64_tr_decoded_is_integer_compare_opcode(insn->opcode) ||
            ia64_tr_decoded_is_supported_integer_compare(insn)) &&
           (!ia64_tr_decoded_is_predicate_test_opcode(insn->opcode) ||
            ia64_tr_decoded_is_supported_predicate_test(insn));
}

static void ia64_tr_rewrite_plan_reset(DisasContext *ctx)
{
    ctx->rewrite_plan_count = 0;
    ctx->rewrite_plan_emit_count = 0;
    ctx->rewrite_plan_index = 0;
}

static uint64_t ia64_tr_nonzero_register_bit(uint8_t reg)
{
    return reg == 0 ? 0 : UINT64_C(1) << (reg % 64);
}

static void ia64_tr_plan_ar_resource(uint64_t resource[2], uint8_t reg)
{
    g_assert(reg < IA64_AR_COUNT);
    resource[reg >> 6] |= UINT64_C(1) << (reg & 63);
}

static void ia64_tr_rewrite_plan_append(
    DisasContext *ctx, const IA64Instruction *insn, unsigned bundle_index)
{
    IA64TrInstructionPlan *plan;
    uint8_t sources[3];
    unsigned source_count;
    bool must_write;

    g_assert(bundle_index <= UINT16_MAX);
    if (ctx->rewrite_plan_count == ctx->rewrite_plan_capacity) {
        unsigned capacity = MAX(16u,
                                (unsigned)ctx->rewrite_plan_capacity * 2);

        g_assert(capacity <= UINT16_MAX);
        ctx->rewrite_plan = g_renew(IA64TrInstructionPlan,
                                    ctx->rewrite_plan, capacity);
        ctx->rewrite_plan_capacity = capacity;
    }

    plan = &ctx->rewrite_plan[ctx->rewrite_plan_count++];
    memset(plan, 0, sizeof(*plan));
    plan->address = insn->address;
    plan->bundle_index = bundle_index;
    plan->slot = insn->slot;
    plan->stop_after = insn->stop_after;

    if (ia64_tr_decoded_is_noop(insn->opcode)) {
        return;
    }

    if (insn->opcode == IA64_OP_MOV_BRGR) {
        plan->source_br = 1u << insn->r2;
        if (insn->qp != 0) {
            plan->source_pr = UINT64_C(1) << insn->qp;
        }
        if (insn->r1 != 0) {
            unsigned half = insn->r1 >= 64;
            uint64_t bit = ia64_tr_nonzero_register_bit(insn->r1);

            plan->dest_gr[half] = bit;
            if (insn->qp == 0) {
                plan->must_gr[half] = bit;
            }
        }
        return;
    }

    if (insn->opcode == IA64_OP_MOV_GRBR) {
        unsigned half = insn->r1 >= 64;
        uint8_t bit = 1u << insn->r2;

        plan->source_gr[half] =
            ia64_tr_nonzero_register_bit(insn->r1);
        if (insn->qp != 0) {
            plan->source_pr = UINT64_C(1) << insn->qp;
        }
        plan->dest_br = bit;
        plan->forward_br = bit;
        if (insn->qp == 0) {
            plan->must_br = bit;
        }
        return;
    }

    if (insn->opcode == IA64_OP_MOV_ARGR) {
        g_assert(insn->unit == IA64_INSN_UNIT_I &&
                 insn->r2 == IA64_AR_PFS);
        ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_PFS);
        if (insn->qp != 0) {
            plan->source_pr = UINT64_C(1) << insn->qp;
        }
        if (insn->r1 != 0) {
            uint64_t bit = ia64_tr_nonzero_register_bit(insn->r1);

            plan->dest_gr[insn->r1 >= 64] = bit;
            if (insn->qp == 0) {
                plan->must_gr[insn->r1 >= 64] = bit;
            }
        }
        return;
    }

    if (insn->opcode == IA64_OP_MOV_GRAR) {
        unsigned half = insn->r1 >= 64;

        g_assert(insn->unit == IA64_INSN_UNIT_I &&
                 insn->r2 == IA64_AR_PFS);
        plan->source_gr[half] =
            ia64_tr_nonzero_register_bit(insn->r1);
        if (insn->qp != 0) {
            plan->source_pr = UINT64_C(1) << insn->qp;
        }
        ia64_tr_plan_ar_resource(plan->dest_ar, IA64_AR_PFS);
        plan->forward_pfs = true;
        plan->must_pfs = insn->qp == 0;
        return;
    }

    if (insn->opcode == IA64_OP_MOV_PRGR) {
        if (insn->r1 != 0) {
            unsigned half = insn->r1 >= 64;
            uint64_t bit = ia64_tr_nonzero_register_bit(insn->r1);

            /* The observable result consumes the complete physical image. */
            plan->source_pr = UINT64_MAX & ~UINT64_C(1);
            plan->dest_gr[half] = bit;
            if (insn->qp == 0) {
                plan->must_gr[half] = bit;
            }
        }
        if (insn->qp != 0) {
            plan->source_pr |= UINT64_C(1) << insn->qp;
        }
        return;
    }

    if (insn->opcode == IA64_OP_MOV_GRPR) {
        uint64_t mask = (uint64_t)insn->imm & ~UINT64_C(1);
        unsigned half = insn->r1 >= 64;

        g_assert((mask & IA64_TR_PR_ROTATING_MASK) == 0 ||
                 (mask & IA64_TR_PR_ROTATING_MASK) ==
                     IA64_TR_PR_ROTATING_MASK);
        /* The GR/NaT pair is consumed even when the encoded mask is zero. */
        plan->source_gr[half] = ia64_tr_nonzero_register_bit(insn->r1);
        if (insn->qp != 0) {
            plan->source_pr = UINT64_C(1) << insn->qp;
        }
        plan->dest_pr = mask;
        plan->forward_pr = mask;
        if (insn->qp == 0) {
            plan->must_pr = mask;
        }
        return;
    }

    if (insn->opcode == IA64_OP_MOV_PR_ROT_IMM) {
        if (insn->qp != 0) {
            plan->source_pr = UINT64_C(1) << insn->qp;
        }
        plan->dest_pr = IA64_TR_PR_ROTATING_MASK;
        plan->forward_pr = IA64_TR_PR_ROTATING_MASK;
        if (insn->qp == 0) {
            plan->must_pr = IA64_TR_PR_ROTATING_MASK;
        }
        return;
    }

    if (ia64_tr_decoded_is_return_branch(insn->opcode)) {
        plan->branch_source_br = 1u << insn->b2;
        plan->branch_source_pfs = true;
        ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_PFS);
        ia64_tr_plan_ar_resource(plan->dest_ar, IA64_AR_EC);
        plan->source_cfm = true;
        plan->dest_cfm = true;
        if (insn->qp != 0) {
            plan->branch_source_pr = UINT64_C(1) << insn->qp;
        } else {
            plan->unconditional_noreturn = true;
        }
        return;
    }

    if (ia64_tr_decoded_is_call_branch(insn->opcode)) {
        uint8_t link = 1u << insn->b1;

        plan->dest_br = link;
        if (insn->opcode == IA64_OP_BR_CALL_INDIRECT) {
            plan->branch_source_br = 1u << insn->b2;
        }
        if (insn->qp != 0) {
            plan->branch_source_pr = UINT64_C(1) << insn->qp;
        } else {
            plan->must_br = link;
            plan->unconditional_noreturn = true;
        }
        ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_EC);
        ia64_tr_plan_ar_resource(plan->dest_ar, IA64_AR_PFS);
        plan->source_cfm = true;
        plan->dest_cfm = true;
        /* A call link is architectural state, never branch-forwarded. */
        g_assert(plan->source_br == 0 && plan->forward_br == 0);
        return;
    }

    if (ia64_tr_decoded_is_loop_branch(insn->opcode)) {
        bool modulo = insn->opcode != IA64_OP_BR_CLOOP;

        if (insn->opcode == IA64_OP_BR_CLOOP ||
            insn->opcode == IA64_OP_BR_CTOP ||
            insn->opcode == IA64_OP_BR_CEXIT) {
            ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_LC);
            ia64_tr_plan_ar_resource(plan->dest_ar, IA64_AR_LC);
        }
        if (modulo) {
            uint64_t p63 = UINT64_C(1) << 63;

            ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_EC);
            ia64_tr_plan_ar_resource(plan->dest_ar, IA64_AR_EC);
            plan->source_cfm = true;
            plan->dest_cfm = true;
            plan->dest_pr = p63;
            plan->must_pr = p63;
            /* p63 is written before rotation, never branch-forwarded. */
            g_assert(plan->forward_pr == 0);
        }
        if ((insn->opcode == IA64_OP_BR_WTOP ||
             insn->opcode == IA64_OP_BR_WEXIT) && insn->qp != 0) {
            plan->branch_source_pr = UINT64_C(1) << insn->qp;
        }
        return;
    }

    if (ia64_tr_decoded_is_conditional_branch(insn->opcode)) {
        if (insn->opcode == IA64_OP_BR_INDIRECT) {
            plan->branch_source_br = 1u << insn->b2;
        }
        if (insn->qp != 0) {
            plan->branch_source_pr = UINT64_C(1) << insn->qp;
        } else {
            /* A p0-qualified branch always starts a fresh target group. */
            plan->unconditional_noreturn = true;
        }
        return;
    }

    if (ia64_tr_decoded_is_integer_compare_opcode(insn->opcode) ||
        ia64_tr_decoded_is_predicate_test_opcode(insn->opcode)) {
        if (insn->p1 == insn->p2) {
            if (!insn->compare_unc && insn->qp != 0) {
                plan->source_pr = UINT64_C(1) << insn->qp;
            } else {
                plan->unconditional_noreturn = true;
            }
            return;
        }

        source_count = ia64_tr_decoded_sources(insn, sources);
        for (unsigned i = 0; i < source_count; i++) {
            uint8_t reg = sources[i];

            plan->source_gr[reg >= 64] |=
                ia64_tr_nonzero_register_bit(reg);
        }
        if (insn->qp != 0) {
            plan->source_pr = UINT64_C(1) << insn->qp;
        }
        if (insn->p1 != 0) {
            plan->dest_pr |= UINT64_C(1) << insn->p1;
        }
        if (insn->p2 != 0) {
            plan->dest_pr |= UINT64_C(1) << insn->p2;
        }
        plan->forward_pr = plan->dest_pr;
        if (insn->pred_update == IA64_PRED_UPDATE_NORMAL &&
            (insn->compare_unc || insn->qp == 0)) {
            plan->must_pr = plan->dest_pr;
        }
        return;
    }

    source_count = ia64_tr_decoded_sources(insn, sources);
    for (unsigned i = 0; i < source_count; i++) {
        uint8_t reg = sources[i];

        plan->source_gr[reg >= 64] |=
            ia64_tr_nonzero_register_bit(reg);
    }
    if (insn->qp != 0) {
        plan->source_pr = UINT64_C(1) << insn->qp;
    }
    if (insn->r1 == 0) {
        return;
    }
    plan->dest_gr[insn->r1 >= 64] =
        ia64_tr_nonzero_register_bit(insn->r1);
    must_write = insn->qp == 0;
    if (must_write) {
        plan->must_gr[insn->r1 >= 64] =
            ia64_tr_nonzero_register_bit(insn->r1);
    }
}

static void ia64_tr_rewrite_plan_append_bundle(
    DisasContext *ctx, const IA64DecodedInstructionBundle *decoded,
    unsigned bundle_index, uint8_t last_slot)
{
    for (unsigned slot = decoded->start_slot; slot <= last_slot; slot++) {
        if ((decoded->instruction_mask & (1u << slot)) != 0) {
            ia64_tr_rewrite_plan_append(
                ctx, &decoded->instruction[slot], bundle_index);
        }
    }
}

static void ia64_tr_rewrite_plan_finalize(DisasContext *ctx,
                                          unsigned segment_bundles)
{
    uint64_t live_gr[2];
    uint64_t live_pr;
    uint8_t live_br;

    g_assert(ctx->rewrite_plan_count != 0 && segment_bundles != 0);
    ctx->rewrite_plan_emit_count = 0;
    ctx->rewrite_plan_index = 0;
    while (ctx->rewrite_plan_emit_count < ctx->rewrite_plan_count &&
           ctx->rewrite_plan[ctx->rewrite_plan_emit_count].bundle_index <
               segment_bundles) {
        ctx->rewrite_plan_emit_count++;
    }
    g_assert(ctx->rewrite_plan_emit_count != 0);

    /*
     * Lookahead is an admission proof, not a durable source-visibility
     * contract.  If this emitted TB segment ends before a stop, its successor
     * may be invalidated or decoded differently, so every architectural
     * source remains live-out.  Stops and unconditional no-return faults cut
     * that liveness as the reverse walk reaches them.
     */
    if (ctx->rewrite_plan[ctx->rewrite_plan_emit_count - 1].stop_after) {
        live_gr[0] = 0;
        live_gr[1] = 0;
        live_pr = 0;
        live_br = 0;
    } else {
        live_gr[0] = UINT64_MAX & ~UINT64_C(1);
        live_gr[1] = UINT64_MAX;
        live_pr = UINT64_MAX & ~UINT64_C(1);
        live_br = UINT8_MAX;
    }

    for (unsigned i = ctx->rewrite_plan_emit_count; i-- > 0;) {
        IA64TrInstructionPlan *plan = &ctx->rewrite_plan[i];

        if (plan->stop_after || plan->unconditional_noreturn) {
            live_gr[0] = 0;
            live_gr[1] = 0;
            live_pr = 0;
            live_br = 0;
        }
        plan->preserve_gr[0] = plan->dest_gr[0] & live_gr[0];
        plan->preserve_gr[1] = plan->dest_gr[1] & live_gr[1];
        plan->preserve_pr = plan->dest_pr & live_pr;
        plan->preserve_br = plan->dest_br & live_br;
        live_gr[0] |= plan->source_gr[0];
        live_gr[1] |= plan->source_gr[1];
        live_pr |= plan->source_pr | plan->branch_source_pr;
        live_br |= plan->source_br | plan->branch_source_br;
    }
}

static bool ia64_tr_preflight_decoded_bundle_through(
    const IA64DecodedInstructionBundle *decoded, uint8_t last_slot)
{
    if (!decoded->valid_template || decoded->start_slot >= IA64_SLOT_COUNT ||
        last_slot >= IA64_SLOT_COUNT || last_slot < decoded->start_slot) {
        return false;
    }
    if (decoded->start_slot == 2 &&
        (decoded->instruction_mask & (1u << 1)) != 0 &&
        decoded->instruction[1].slot_span == 2) {
        return false;
    }

    for (unsigned slot = decoded->start_slot;
         slot <= last_slot; slot++) {
        const IA64Instruction *insn;

        if ((decoded->instruction_mask & (1u << slot)) == 0) {
            continue;
        }
        insn = &decoded->instruction[slot];
        if (!ia64_tr_decoded_instruction_supported(insn)) {
            return false;
        }
    }
    return true;
}

static bool ia64_tr_preflight_decoded_bundle(
    const IA64DecodedInstructionBundle *decoded)
{
    return ia64_tr_preflight_decoded_bundle_through(
        decoded, IA64_SLOT_COUNT - 1);
}

/*
 * A conditional branch creates an intra-bundle taken edge; its false edge
 * continues through every later instruction.  Validate that complete false
 * path, including any later conditional branches.  A p0-qualified simple
 * branch has no false edge, so it is the last admitted physical slot even when
 * the bundle contains encodings after it.  Loop forms remain dynamic state
 * machines even when their encoded predicate is p0 and therefore never use
 * this truncation rule.
 */
static bool ia64_tr_preflight_branch_cfg(
    const IA64DecodedInstructionBundle *decoded, uint8_t *last_slot)
{
    bool found_branch = false;

    if (!last_slot || !decoded->valid_template ||
        decoded->start_slot >= IA64_SLOT_COUNT) {
        return false;
    }
    for (unsigned slot = decoded->start_slot;
         slot < IA64_SLOT_COUNT; slot++) {
        const IA64Instruction *insn;

        if ((decoded->instruction_mask & (1u << slot)) == 0) {
            continue;
        }
        insn = &decoded->instruction[slot];
        if (!ia64_tr_decoded_is_conditional_branch(insn->opcode)) {
            continue;
        }
        found_branch = true;
        if (insn->qp == 0) {
            if (ia64_tr_decoded_is_loop_branch(insn->opcode)) {
                continue;
            }
            *last_slot = slot + insn->slot_span - 1;
            return ia64_tr_preflight_decoded_bundle_through(decoded,
                                                             *last_slot);
        }
    }
    if (!found_branch ||
        !ia64_tr_preflight_decoded_bundle_through(
            decoded, IA64_SLOT_COUNT - 1)) {
        return false;
    }
    *last_slot = IA64_SLOT_COUNT - 1;
    return true;
}

static bool ia64_tr_preflight_to_first_stop(
    const IA64DecodedInstructionBundle *decoded, uint8_t scan_last_slot,
    uint8_t *last_slot, bool *found_stop)
{
    if (!decoded->valid_template || decoded->start_slot >= IA64_SLOT_COUNT ||
        scan_last_slot >= IA64_SLOT_COUNT ||
        scan_last_slot < decoded->start_slot || !last_slot || !found_stop ||
        (decoded->start_slot == 2 &&
         (decoded->instruction_mask & (1u << 1)) != 0 &&
         decoded->instruction[1].slot_span == 2)) {
        return false;
    }

    *found_stop = false;
    *last_slot = scan_last_slot;
    for (unsigned slot = decoded->start_slot;
         slot <= scan_last_slot; slot++) {
        const IA64Instruction *insn;
        unsigned physical_last_slot;

        if ((decoded->instruction_mask & (1u << slot)) == 0) {
            continue;
        }
        insn = &decoded->instruction[slot];
        if (!ia64_tr_decoded_instruction_supported(insn)) {
            return false;
        }
        physical_last_slot = slot + insn->slot_span - 1;
        if (insn->stop_after) {
            *last_slot = physical_last_slot;
            *found_stop = true;
            return true;
        }
    }
    return true;
}

/*
 * A bundle-level legacy boundary or an unsupported fresh group may follow an
 * internal stop.  Only an already-owned typed group may retire through that
 * stop and return the fresh suffix to the coexistence engine.
 */
static bool ia64_tr_preflight_internal_stop_prefix(
    const IA64DecodedInstructionBundle *decoded, uint8_t *last_slot)
{
    bool found_stop;

    return ia64_tr_preflight_to_first_stop(
               decoded, IA64_SLOT_COUNT - 1, last_slot, &found_stop) &&
           found_stop && *last_slot < IA64_SLOT_COUNT - 1;
}

static bool ia64_tr_should_end_before_next_typed_group(void)
{
    /*
     * End at the already-retired group boundary while there is still enough
     * room to publish this TB's exit.  The next TB then begins with room for
     * at least one worst-case typed bundle.  The fallback in preflight still
     * admits one validated bundle because this threshold is soft and plugin
     * instrumentation may consume space between these two checks.
     */
    return !tcg_op_buf_has_space(IA64_TR_REWRITE_OPS_PER_BUNDLE +
                                 IA64_TR_REWRITE_EXIT_OPS);
}

static bool ia64_tr_preflight_rewrite_region(
    DisasContext *ctx, const IA64DecodedBundle *first_bundle,
    uint64_t pc, uint8_t start_slot, IA64TcgTbBoundary first_boundary,
    unsigned *bundle_count, uint8_t *last_slot)
{
    IA64DecodedBundle loaded_bundle;
    const IA64DecodedBundle *bundle = first_bundle;
    uint64_t scan_pc = pc;
    uint8_t scan_start_slot = start_slot;
    bool group_start = ctx->instruction_group_start;
    bool entered_typed = ctx->typed_group_active;
    bool fresh_typed_enabled = ia64_tr_full_tcg_rewrite_enabled();
    bool continuation_only = entered_typed && !fresh_typed_enabled;
    unsigned validated_bundles = 0;
    unsigned segment_bundles;
    uint8_t validated_last_slot = IA64_SLOT_COUNT - 1;
    int remaining_bundles =
        ctx->base.max_insns - ctx->base.num_insns + 1;

    g_assert(ctx->rewrite_plan_count == 0 &&
             ctx->rewrite_plan_emit_count == 0 &&
             ctx->rewrite_plan_index == 0);
    if ((!ctx->instruction_group_start && !ctx->typed_group_active) ||
        !bundle_count || !last_slot ||
        (!entered_typed && !fresh_typed_enabled) ||
        remaining_bundles <= 0) {
        return false;
    }

    /*
     * Validate through the next architectural group boundary or the end of
     * this instruction page, independently of the current TB's instruction or
     * op budget.  A page boundary is a deliberate typed-continuation point:
     * fetching the next page before this prefix executes could raise an early
     * instruction-access fault.
     */
    for (unsigned bundle_index = 0;
         bundle_index < TARGET_PAGE_SIZE / IA64_BUNDLE_SIZE; bundle_index++) {
        IA64DecodedInstructionBundle decoded;
        IA64TcgTbBoundary boundary = first_boundary;
        uint8_t accepted_last_slot = IA64_SLOT_COUNT - 1;
        uint8_t branch_last_slot = IA64_SLOT_COUNT - 1;
        bool end_region = false;
        bool branch_cfg;

        if (bundle_index != 0) {
            uint64_t lo;
            uint64_t hi;
            uint64_t physical_pc = 0;
            bool physical_pc_valid = false;

            if (!translator_is_same_page(&ctx->base, scan_pc)) {
                goto reject;
            }
            lo = translator_ldq_end(ctx->env, &ctx->base, scan_pc, MO_LE);
            hi = translator_ldq_end(ctx->env, &ctx->base, scan_pc + 8,
                                    MO_LE);
            ia64_decode_bundle_words(lo, hi, &loaded_bundle);
            bundle = &loaded_bundle;

            if (!ia64_tcg_pc_is_efi_call_gate(scan_pc) &&
                ia64_tcg_bundle_is_firmware_call_gate_candidate(bundle)) {
                physical_pc_valid = ia64_tr_instruction_physical_address(
                    ctx, scan_pc, &physical_pc);
            }
            boundary = ia64_tcg_tb_boundary_for_bundle_with_physical(
                bundle, scan_pc, physical_pc, physical_pc_valid);
        }

        if (!ia64_decode_instruction_bundle(bundle, scan_pc, group_start,
                                             scan_start_slot, &decoded)) {
            goto reject;
        }
        branch_cfg = ia64_tr_preflight_branch_cfg(
            &decoded, &branch_last_slot);
        if (continuation_only) {
            bool found_stop;

            /* EFI dispatch is bundle-scoped and has no proven prefix split. */
            if (boundary == IA64_TCG_TB_BOUNDARY_EFI_CALL_GATE ||
                !ia64_tr_preflight_to_first_stop(
                    &decoded,
                    branch_cfg ? branch_last_slot : IA64_SLOT_COUNT - 1,
                    &validated_last_slot, &found_stop)) {
                goto reject;
            }
            accepted_last_slot = validated_last_slot;
            if (branch_cfg && branch_last_slot < accepted_last_slot) {
                /* The first p0 edge suppresses every later physical slot. */
                accepted_last_slot = branch_last_slot;
                validated_last_slot = branch_last_slot;
                end_region = true;
            } else if (found_stop) {
                /*
                 * The restored owner overrides the destination kill switch
                 * only until its first architectural stop.  Do not start a
                 * fresh typed group later in this bundle, even when that
                 * suffix contains a typed branch CFG.
                 */
                end_region = true;
            } else if (branch_cfg) {
                if (boundary != IA64_TCG_TB_BOUNDARY_NONE &&
                    boundary != IA64_TCG_TB_BOUNDARY_BRANCH) {
                    goto reject;
                }
                accepted_last_slot = branch_last_slot;
                validated_last_slot = branch_last_slot;
                end_region = true;
            } else if (ia64_tcg_tb_boundary_ends_tb(boundary)) {
                goto reject;
            }
        } else if (branch_cfg) {
            if (boundary != IA64_TCG_TB_BOUNDARY_NONE &&
                boundary != IA64_TCG_TB_BOUNDARY_BRANCH) {
                goto reject;
            }
            accepted_last_slot = branch_last_slot;
            validated_last_slot = branch_last_slot;
            end_region = true;
        } else if (ia64_tcg_tb_boundary_ends_tb(boundary)) {
            if (!entered_typed ||
                boundary == IA64_TCG_TB_BOUNDARY_EFI_CALL_GATE ||
                !ia64_tr_preflight_internal_stop_prefix(
                    &decoded, &validated_last_slot)) {
                goto reject;
            }
            accepted_last_slot = validated_last_slot;
            end_region = true;
        } else if (!ia64_tr_preflight_decoded_bundle(&decoded)) {
            if (!entered_typed ||
                !ia64_tr_preflight_internal_stop_prefix(
                    &decoded, &validated_last_slot)) {
                goto reject;
            }
            accepted_last_slot = validated_last_slot;
            end_region = true;
        }
        ia64_tr_rewrite_plan_append_bundle(
            ctx, &decoded, bundle_index, accepted_last_slot);
        validated_bundles = bundle_index + 1;
        if (end_region) {
            break;
        }
        if (decoded.ends_at_group_boundary) {
            break;
        }

        scan_pc += IA64_BUNDLE_SIZE;
        scan_start_slot = 0;
        group_start = false;
        if (!translator_is_same_page(&ctx->base, scan_pc)) {
            break;
        }
    }

    if (validated_bundles == 0) {
        goto reject;
    }

    /*
     * Reserve only the segment emitted by this TB.  Longer validated chunks
     * are deliberately suspended and resumed with the persisted overlay.
     */
    segment_bundles = MIN(validated_bundles, (unsigned)remaining_bundles);
    if (ctx->base.plugin_enabled) {
        /* Plugin post-insn ops are emitted after translate_insn returns. */
        segment_bundles = MIN(segment_bundles, 1u);
    }
    while (segment_bundles != 0 &&
           !tcg_op_buf_has_space(
               (size_t)segment_bundles * IA64_TR_REWRITE_OPS_PER_BUNDLE +
               IA64_TR_REWRITE_EXIT_OPS)) {
        segment_bundles--;
    }
    if (segment_bundles == 0) {
        /*
         * TCG_OP_BUF_SOFT_LIMIT is deliberately not a hard allocation
         * limit.  As other targets do for a large first instruction, admit
         * one already-validated bundle and leave immediately afterwards.
         * In particular, do not report op pressure as semantic rejection and
         * redirect a typed-capable group to the legacy engine.
         */
        segment_bundles = 1;
    }

    g_assert(ia64_tr_group_is_empty(ctx));
    ia64_tr_rewrite_plan_finalize(ctx, segment_bundles);
    *bundle_count = segment_bundles;
    *last_slot = segment_bundles == validated_bundles ?
                 validated_last_slot : IA64_SLOT_COUNT - 1;
    return true;

reject:
    ia64_tr_rewrite_plan_reset(ctx);
    return false;
}

static G_NORETURN void ia64_tr_fail_typed_continuation(uint64_t pc,
                                                        const char *reason)
{
    /*
     * A typed prefix has already retired, so switching to the shadow-unaware
     * coexistence engine would silently corrupt ordinary source visibility.
     * This fail-closed guard is reachable only while opcode migration is
     * incomplete; the full-only end state has a typed lowering or precise
     * architected fault for every decode.
     */
    error_report("IA-64 typed continuation at 0x%016" PRIx64
                 " cannot remain typed: %s", pc, reason);
    abort();
}

static void ia64_tr_prime_decoded_instruction_state(
    DisasContext *ctx, const IA64Instruction *insn)
{
    uint8_t sources[3];
    unsigned source_count;
    bool static_nat = insn->r1 > 0 &&
                      insn->r1 < IA64_STATIC_GR_COUNT;

    if (insn->qp == 0 || ia64_tr_decoded_is_noop(insn->opcode)) {
        return;
    }

    source_count = ia64_tr_decoded_sources(insn, sources);
    if (!ctx->state_cache_active) {
        return;
    }

    ia64_tr_ensure_pr(ctx);
    if (insn->opcode == IA64_OP_MOV_BRGR) {
        ia64_tr_ensure_br(ctx, insn->r2);
    } else if (insn->opcode == IA64_OP_MOV_GRBR) {
        ia64_tr_ensure_br(ctx, insn->r2);
    }
    for (unsigned i = 0; i < source_count; i++) {
        uint8_t reg = sources[i];

        if (reg > 0 && reg < IA64_STATIC_GR_COUNT) {
            ia64_tr_ensure_static_gr(ctx, reg);
            static_nat = true;
        }
    }
    if (insn->r1 > 0 && insn->r1 < IA64_STATIC_GR_COUNT) {
        ia64_tr_ensure_static_gr(ctx, insn->r1);
    }
    if (static_nat) {
        ia64_tr_ensure_gr_nat(ctx);
    }
}

static TCGLabel *ia64_tr_emit_decoded_predicate_guard(
    DisasContext *ctx, const IA64Instruction *insn)
{
    TCGLabel *skip;
    TCGv_i64 predicate;

    if (insn->qp == 0 || ia64_tr_decoded_is_noop(insn->opcode)) {
        return NULL;
    }

    skip = gen_new_label();
    predicate = ia64_tr_scratch_i64(ctx);
    ia64_tr_group_load_ordinary_predicate(ctx, predicate, insn->qp);
    tcg_gen_brcondi_i64(TCG_COND_EQ, predicate, 0, skip);
    return skip;
}

static void ia64_tr_emit_decoded_register_nat_consumption(
    DisasContext *ctx, const IA64Instruction *insn)
{
    /* The current PR image remains staged; only the ordered prefix retires. */
    ia64_tr_group_publish_prefix_for_noreturn_fault(ctx);
    tcg_gen_movi_i64(cpu_ip, insn->address);
    ia64_tr_publish_fault_state(insn->address, insn->slot,
                                ia64_tr_decoded_slot_type(insn->unit),
                                insn->raw, insn->starts_group);
    gen_helper_raise_register_nat_consumption(tcg_env);
}

static void ia64_tr_emit_decoded_pr_move(DisasContext *ctx,
                                         const IA64Instruction *insn)
{
    TCGLabel *skip;

    g_assert(insn->opcode == IA64_OP_MOV_PRGR ||
             insn->opcode == IA64_OP_MOV_GRPR ||
             insn->opcode == IA64_OP_MOV_PR_ROT_IMM);

    if (insn->opcode == IA64_OP_MOV_PRGR) {
        IA64TrGrWrite *gr_write;
        TCGv_i64 image;

        if (insn->r1 == 0) {
            return;
        }
        ia64_tr_prime_decoded_instruction_state(ctx, insn);
        gr_write = ia64_tr_group_prepare_gr(ctx, insn->r1);
        skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
        image = ia64_tr_scratch_i64(ctx);
        ia64_tr_group_load_ordinary_pr_image(ctx, image);
        ia64_tr_group_stage_gr(gr_write, image, tcg_constant_i64(0));
        ia64_tr_finish_fast_slot_predicate_guard(skip);
        return;
    }

    if (insn->opcode == IA64_OP_MOV_GRPR) {
        uint64_t mask = (uint64_t)insn->imm & ~UINT64_C(1);
        IA64TrPrImageWrite *pr_write;
        TCGLabel *nat_clear = gen_new_label();
        TCGv_i64 value = ia64_tr_scratch_i64(ctx);
        TCGv_i64 nat = ia64_tr_scratch_i64(ctx);

        ia64_tr_prime_decoded_instruction_state(ctx, insn);
        pr_write = ia64_tr_group_prepare_pr_image(ctx, mask);
        skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
        /* This ordinary source read is required even for an encoded mask 0. */
        ia64_tr_group_load_ordinary_gr_pair(ctx, value, nat, insn->r1);
        tcg_gen_brcondi_i64(TCG_COND_EQ, nat, 0, nat_clear);
        ia64_tr_emit_decoded_register_nat_consumption(ctx, insn);
        gen_set_label(nat_clear);
        ia64_tr_group_stage_pr_image(pr_write, value);
        ia64_tr_finish_fast_slot_predicate_guard(skip);
        return;
    }

    {
        IA64TrPrImageWrite *pr_write;

        ia64_tr_prime_decoded_instruction_state(ctx, insn);
        pr_write = ia64_tr_group_prepare_pr_image(
            ctx, IA64_TR_PR_ROTATING_MASK);
        skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
        ia64_tr_group_stage_pr_image(
            pr_write, tcg_constant_i64((uint64_t)insn->imm));
        ia64_tr_finish_fast_slot_predicate_guard(skip);
    }
}

static void ia64_tr_emit_decoded_br_move(DisasContext *ctx,
                                         const IA64Instruction *insn)
{
    TCGLabel *skip;

    g_assert(insn->opcode == IA64_OP_MOV_BRGR ||
             insn->opcode == IA64_OP_MOV_GRBR);
    ia64_tr_prime_decoded_instruction_state(ctx, insn);

    if (insn->opcode == IA64_OP_MOV_BRGR) {
        IA64TrGrWrite *gr_write =
            ia64_tr_group_prepare_gr(ctx, insn->r1);
        TCGv_i64 value = ia64_tr_scratch_i64(ctx);

        skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
        ia64_tr_group_load_ordinary_br(ctx, value, insn->r2);
        ia64_tr_group_stage_gr(gr_write, value, tcg_constant_i64(0));
        ia64_tr_finish_fast_slot_predicate_guard(skip);
        return;
    }

    {
        IA64TrBrWrite *br_write =
            ia64_tr_group_prepare_br(ctx, insn->r2);
        TCGLabel *nat_clear = gen_new_label();
        TCGv_i64 value = ia64_tr_scratch_i64(ctx);
        TCGv_i64 nat = ia64_tr_scratch_i64(ctx);

        skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
        ia64_tr_group_load_ordinary_gr_pair(ctx, value, nat, insn->r1);
        tcg_gen_brcondi_i64(TCG_COND_EQ, nat, 0, nat_clear);
        ia64_tr_emit_decoded_register_nat_consumption(ctx, insn);
        gen_set_label(nat_clear);
        ia64_tr_group_stage_br(br_write, value);
        ia64_tr_finish_fast_slot_predicate_guard(skip);
    }
}

static void ia64_tr_emit_decoded_pfs_move(DisasContext *ctx,
                                          const IA64Instruction *insn)
{
    IA64TrInstructionTransaction *instruction =
        ctx->rewrite_group.current;
    TCGLabel *skip;

    g_assert((insn->opcode == IA64_OP_MOV_ARGR ||
              insn->opcode == IA64_OP_MOV_GRAR) &&
             insn->unit == IA64_INSN_UNIT_I &&
             insn->slot_span == 1 && insn->r2 == IA64_AR_PFS);
    ia64_tr_prime_decoded_instruction_state(ctx, insn);

    if (insn->opcode == IA64_OP_MOV_ARGR) {
        IA64TrGrWrite *gr_write =
            ia64_tr_group_prepare_gr(ctx, insn->r1);
        TCGv_i64 value = ia64_tr_scratch_i64(ctx);

        g_assert(instruction->source_ar[0] == 0 &&
                 instruction->source_ar[1] == 1 &&
                 instruction->dest_ar[0] == 0 &&
                 instruction->dest_ar[1] == 0 &&
                 !instruction->forward_pfs &&
                 !instruction->branch_source_pfs);
        skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
        ia64_tr_group_load_ordinary_pfs(ctx, value);
        ia64_tr_group_stage_gr(gr_write, value, tcg_constant_i64(0));
        ia64_tr_finish_fast_slot_predicate_guard(skip);
        return;
    }

    {
        TCGLabel *nat_clear = gen_new_label();
        TCGv_i64 value = ia64_tr_scratch_i64(ctx);
        TCGv_i64 nat = ia64_tr_scratch_i64(ctx);

        g_assert(instruction->source_ar[0] == 0 &&
                 instruction->source_ar[1] == 0 &&
                 instruction->dest_ar[0] == 0 &&
                 instruction->dest_ar[1] == 1 &&
                 instruction->forward_pfs &&
                 instruction->must_pfs == (insn->qp == 0));
        skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
        ia64_tr_group_load_ordinary_gr_pair(ctx, value, nat, insn->r1);
        tcg_gen_brcondi_i64(TCG_COND_EQ, nat, 0, nat_clear);
        ia64_tr_emit_decoded_register_nat_consumption(ctx, insn);
        gen_set_label(nat_clear);
        ia64_tr_group_write_pfs(ctx, value, instruction->must_pfs);
        ia64_tr_finish_fast_slot_predicate_guard(skip);
    }
}

static unsigned ia64_tr_decoded_bitfield_pos(const IA64Instruction *insn)
{
    return (uint64_t)insn->imm & 0x3f;
}

static unsigned ia64_tr_decoded_bitfield_len(const IA64Instruction *insn)
{
    unsigned pos = ia64_tr_decoded_bitfield_pos(insn);
    unsigned len = ((uint64_t)insn->imm >> 6) & 0x7f;

    g_assert(pos < 64);
    g_assert(len > 0);
    return MIN(len, 64 - pos);
}

static uint64_t ia64_tr_low_mask(unsigned len)
{
    g_assert(len > 0 && len <= 64);
    return len == 64 ? UINT64_MAX : (UINT64_C(1) << len) - 1;
}

static uint64_t ia64_tr_decoded_bitfield_mask(const IA64Instruction *insn)
{
    unsigned pos = ia64_tr_decoded_bitfield_pos(insn);
    unsigned len = ia64_tr_decoded_bitfield_len(insn);

    return ia64_tr_low_mask(len) << pos;
}

static void ia64_tr_emit_decoded_variable_shift(
    DisasContext *ctx, IA64Opcode opcode, TCGv_i64 result,
    TCGv_i64 count, TCGv_i64 value)
{
    TCGv_i64 amount = ia64_tr_scratch_i64(ctx);

    switch (opcode) {
    case IA64_OP_SHL:
    case IA64_OP_SHRU:
    {
        TCGv_i64 shifted = ia64_tr_scratch_i64(ctx);

        tcg_gen_andi_i64(amount, count, 63);
        if (opcode == IA64_OP_SHL) {
            tcg_gen_shl_i64(shifted, value, amount);
        } else {
            tcg_gen_shr_i64(shifted, value, amount);
        }
        tcg_gen_movcond_i64(TCG_COND_LTU, result, count,
                            tcg_constant_i64(64), shifted,
                            tcg_constant_i64(0));
        break;
    }
    case IA64_OP_SHR:
        tcg_gen_umin_i64(amount, count, tcg_constant_i64(63));
        tcg_gen_sar_i64(result, value, amount);
        break;
    default:
        g_assert_not_reached();
    }
}

static void ia64_tr_emit_decoded_integer_compare(
    DisasContext *ctx, const IA64Instruction *insn)
{
    const IA64TrDecodedCompare *compare =
        ia64_tr_decoded_compare(insn->opcode);
    TCGLabel *skip;
    TCGv_i64 left = ia64_tr_scratch_i64(ctx);
    TCGv_i64 right = ia64_tr_scratch_i64(ctx);
    TCGv_i64 left_nat = ia64_tr_scratch_i64(ctx);
    TCGv_i64 right_nat = ia64_tr_scratch_i64(ctx);
    TCGv_i64 source_nat = ia64_tr_scratch_i64(ctx);
    TCGv_i64 result = ia64_tr_scratch_i64(ctx);
    TCGv_i64 inverted = ia64_tr_scratch_i64(ctx);
    TCGv_i64 p1_value = ia64_tr_scratch_i64(ctx);
    TCGv_i64 p2_value = ia64_tr_scratch_i64(ctx);
    IA64TrPrWrite *p1_write;
    IA64TrPrWrite *p2_write;

    g_assert(ia64_tr_decoded_is_supported_integer_compare(insn));

    if (insn->p1 == insn->p2) {
        TCGLabel *resume = insn->compare_unc ? NULL :
                           ia64_tr_emit_decoded_predicate_guard(ctx, insn);

        if (resume == NULL) {
            resume = gen_new_label();
        }

        /*
         * Normal and parallel compares fault only when qualified; cmp.unc
         * faults even when qp is false.  No source read or predicate write
         * belongs to an equal-target instruction on either path.
        */
        ia64_tr_emit_decoded_illegal_operation(ctx, insn);
        gen_set_label(resume);
        return;
    }

    ia64_tr_prime_decoded_instruction_state(ctx, insn);
    p1_write = ia64_tr_group_prepare_pr(ctx, insn->p1);
    p2_write = ia64_tr_group_prepare_pr(ctx, insn->p2);
    if (insn->pred_update != IA64_PRED_UPDATE_NORMAL) {
        /* Every parallel form has architectural no-write result arms. */
        g_assert((p1_write == NULL || !p1_write->must_write) &&
                 (p2_write == NULL || !p2_write->must_write));
    }

    /*
     * cmp.unc initializes both targets independently of PR[qp].  A qp that
     * aliases a target still uses the ordinary source view from the start of
     * this visibility epoch, as required by the SDM.
     */
    if (insn->compare_unc) {
        ia64_tr_group_stage_pr_const(p1_write, false);
        ia64_tr_group_stage_pr_const(p2_write, false);
    }
    skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);

    if (insn->compare_immediate) {
        tcg_gen_movi_i64(left, insn->imm);
        tcg_gen_movi_i64(left_nat, 0);
    } else if (compare->source == IA64_TR_COMPARE_SOURCE_ZERO) {
        /* A7 encodes 0 relation r3, never r3 relation 0. */
        tcg_gen_movi_i64(left, 0);
        tcg_gen_movi_i64(left_nat, 0);
    } else {
        g_assert(compare->source == IA64_TR_COMPARE_SOURCE_REGISTER);
        ia64_tr_group_load_ordinary_gr_pair(
            ctx, left, left_nat, insn->r2);
    }

    if (compare->source == IA64_TR_COMPARE_SOURCE_REGISTER &&
        insn->r2 == insn->r3) {
        tcg_gen_mov_i64(right, left);
        tcg_gen_mov_i64(right_nat, left_nat);
    } else {
        ia64_tr_group_load_ordinary_gr_pair(
            ctx, right, right_nat, insn->r3);
    }
    if (compare->source == IA64_TR_COMPARE_SOURCE_REGISTER) {
        tcg_gen_or_i64(source_nat, left_nat, right_nat);
    } else {
        /* A7 zero and A8 imm8 have no NaT; only r3 contributes. */
        tcg_gen_mov_i64(source_nat, right_nat);
    }

    if (insn->compare_width == 4) {
        if (ia64_tr_compare_relation_is_signed(compare->relation)) {
            tcg_gen_ext32s_i64(left, left);
            tcg_gen_ext32s_i64(right, right);
        } else {
            tcg_gen_ext32u_i64(left, left);
            tcg_gen_ext32u_i64(right, right);
        }
    }

    tcg_gen_setcond_i64(ia64_tr_compare_cond(compare->relation),
                        result, left, right);

    switch (insn->pred_update) {
    case IA64_PRED_UPDATE_NORMAL:
        tcg_gen_xori_i64(inverted, result, 1);
        tcg_gen_movcond_i64(TCG_COND_EQ, p1_value, source_nat,
                            tcg_constant_i64(0), result,
                            tcg_constant_i64(0));
        tcg_gen_movcond_i64(TCG_COND_EQ, p2_value, source_nat,
                            tcg_constant_i64(0), inverted,
                            tcg_constant_i64(0));
        ia64_tr_group_stage_pr_bool(p1_write, p1_value);
        ia64_tr_group_stage_pr_bool(p2_write, p2_value);
        break;
    case IA64_PRED_UPDATE_AND:
    {
        TCGLabel *clear = gen_new_label();
        TCGLabel *done = gen_new_label();

        /* NaT or false clears both; true is architecturally no write. */
        tcg_gen_brcondi_i64(TCG_COND_NE, source_nat, 0, clear);
        tcg_gen_brcondi_i64(TCG_COND_NE, result, 0, done);
        gen_set_label(clear);
        ia64_tr_group_stage_pr_const(p1_write, false);
        ia64_tr_group_stage_pr_const(p2_write, false);
        gen_set_label(done);
        break;
    }
    case IA64_PRED_UPDATE_OR:
    {
        TCGLabel *done = gen_new_label();

        /* NaT or false is no write; true sets both predicates. */
        tcg_gen_brcondi_i64(TCG_COND_NE, source_nat, 0, done);
        tcg_gen_brcondi_i64(TCG_COND_EQ, result, 0, done);
        ia64_tr_group_stage_pr_const(p1_write, true);
        ia64_tr_group_stage_pr_const(p2_write, true);
        gen_set_label(done);
        break;
    }
    case IA64_PRED_UPDATE_OR_ANDCM:
    {
        TCGLabel *done = gen_new_label();

        /* NaT or false is no write; true sets p1 and clears p2. */
        tcg_gen_brcondi_i64(TCG_COND_NE, source_nat, 0, done);
        tcg_gen_brcondi_i64(TCG_COND_EQ, result, 0, done);
        ia64_tr_group_stage_pr_const(p1_write, true);
        ia64_tr_group_stage_pr_const(p2_write, false);
        gen_set_label(done);
        break;
    }
    default:
        g_assert_not_reached();
    }
    ia64_tr_finish_fast_slot_predicate_guard(skip);
}

static void ia64_tr_emit_decoded_predicate_test(
    DisasContext *ctx, const IA64Instruction *insn)
{
    const IA64TrDecodedPredicateTest *test =
        ia64_tr_decoded_predicate_test(insn->opcode);
    TCGLabel *skip;
    TCGv_i64 source = ia64_tr_scratch_i64(ctx);
    TCGv_i64 source_nat = ia64_tr_scratch_i64(ctx);
    TCGv_i64 source_unavailable = ia64_tr_scratch_i64(ctx);
    TCGv_i64 result = ia64_tr_scratch_i64(ctx);
    TCGv_i64 inverted = ia64_tr_scratch_i64(ctx);
    TCGv_i64 p1_value = ia64_tr_scratch_i64(ctx);
    TCGv_i64 p2_value = ia64_tr_scratch_i64(ctx);
    IA64TrPrWrite *p1_write;
    IA64TrPrWrite *p2_write;

    g_assert(ia64_tr_decoded_is_supported_predicate_test(insn));

    if (insn->p1 == insn->p2) {
        TCGLabel *resume = insn->compare_unc ? NULL :
                           ia64_tr_emit_decoded_predicate_guard(ctx, insn);

        if (resume == NULL) {
            resume = gen_new_label();
        }

        /*
         * As with integer compare, normal and parallel tests fault only when
         * qualified, while the .unc form faults even for a false qp.  The
         * illegal equal-target instruction reads neither GR/NaT nor CPUID[4].
         */
        ia64_tr_emit_decoded_illegal_operation(ctx, insn);
        gen_set_label(resume);
        return;
    }

    ia64_tr_prime_decoded_instruction_state(ctx, insn);
    p1_write = ia64_tr_group_prepare_pr(ctx, insn->p1);
    p2_write = ia64_tr_group_prepare_pr(ctx, insn->p2);
    if (insn->pred_update != IA64_PRED_UPDATE_NORMAL) {
        g_assert((p1_write == NULL || !p1_write->must_write) &&
                 (p2_write == NULL || !p2_write->must_write));
    }

    /* A false-qualified .unc still clears both unequal destinations. */
    if (insn->compare_unc) {
        ia64_tr_group_stage_pr_const(p1_write, false);
        ia64_tr_group_stage_pr_const(p2_write, false);
    }
    skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);

    switch (test->kind) {
    case IA64_TR_PREDICATE_TEST_BIT:
        ia64_tr_group_load_ordinary_gr_pair(
            ctx, source, source_nat, insn->r3);
        tcg_gen_shri_i64(result, source, insn->imm);
        tcg_gen_andi_i64(result, result, 1);
        tcg_gen_mov_i64(source_unavailable, source_nat);
        break;
    case IA64_TR_PREDICATE_TEST_NAT:
        ia64_tr_group_load_ordinary_gr_pair(
            ctx, source, source_nat, insn->r3);
        tcg_gen_andi_i64(result, source_nat, 1);
        tcg_gen_movi_i64(source_unavailable, 0);
        break;
    case IA64_TR_PREDICATE_TEST_FEATURE:
        tcg_gen_ld_i64(source, tcg_env,
                       offsetof(CPUIA64State, cpuid) +
                       4 * sizeof(uint64_t));
        tcg_gen_shri_i64(result, source, insn->imm);
        tcg_gen_andi_i64(result, result, 1);
        tcg_gen_movi_i64(source_unavailable, 0);
        break;
    case IA64_TR_PREDICATE_TEST_INVALID:
    default:
        g_assert_not_reached();
    }
    if (!test->nonzero) {
        tcg_gen_xori_i64(result, result, 1);
    }

    switch (insn->pred_update) {
    case IA64_PRED_UPDATE_NORMAL:
        tcg_gen_xori_i64(inverted, result, 1);
        tcg_gen_movcond_i64(TCG_COND_EQ, p1_value, source_unavailable,
                            tcg_constant_i64(0), result,
                            tcg_constant_i64(0));
        tcg_gen_movcond_i64(TCG_COND_EQ, p2_value, source_unavailable,
                            tcg_constant_i64(0), inverted,
                            tcg_constant_i64(0));
        ia64_tr_group_stage_pr_bool(p1_write, p1_value);
        ia64_tr_group_stage_pr_bool(p2_write, p2_value);
        break;
    case IA64_PRED_UPDATE_AND:
    {
        TCGLabel *clear = gen_new_label();
        TCGLabel *done = gen_new_label();

        /* A tbit NaT or a false relation clears both predicates. */
        tcg_gen_brcondi_i64(TCG_COND_NE, source_unavailable, 0, clear);
        tcg_gen_brcondi_i64(TCG_COND_NE, result, 0, done);
        gen_set_label(clear);
        ia64_tr_group_stage_pr_const(p1_write, false);
        ia64_tr_group_stage_pr_const(p2_write, false);
        gen_set_label(done);
        break;
    }
    case IA64_PRED_UPDATE_OR:
    {
        TCGLabel *done = gen_new_label();

        tcg_gen_brcondi_i64(TCG_COND_NE, source_unavailable, 0, done);
        tcg_gen_brcondi_i64(TCG_COND_EQ, result, 0, done);
        ia64_tr_group_stage_pr_const(p1_write, true);
        ia64_tr_group_stage_pr_const(p2_write, true);
        gen_set_label(done);
        break;
    }
    case IA64_PRED_UPDATE_OR_ANDCM:
    {
        TCGLabel *done = gen_new_label();

        tcg_gen_brcondi_i64(TCG_COND_NE, source_unavailable, 0, done);
        tcg_gen_brcondi_i64(TCG_COND_EQ, result, 0, done);
        ia64_tr_group_stage_pr_const(p1_write, true);
        ia64_tr_group_stage_pr_const(p2_write, false);
        gen_set_label(done);
        break;
    }
    default:
        g_assert_not_reached();
    }
    ia64_tr_finish_fast_slot_predicate_guard(skip);
}

static void ia64_tr_emit_decoded_instruction(
    DisasContext *ctx, const IA64Instruction *insn)
{
    uint8_t source_regs[3];
    unsigned source_count;
    TCGLabel *skip;
    TCGv_i64 result;
    TCGv_i64 source[3];
    TCGv_i64 source_nat[3] = { NULL, };
    TCGv_i64 result_nat;
    IA64TrGrWrite *gr_write;

    if (ia64_tr_decoded_is_noop(insn->opcode)) {
        return;
    }

    if (insn->opcode == IA64_OP_MOV_PRGR ||
        insn->opcode == IA64_OP_MOV_GRPR ||
        insn->opcode == IA64_OP_MOV_PR_ROT_IMM) {
        ia64_tr_emit_decoded_pr_move(ctx, insn);
        return;
    }

    if (insn->opcode == IA64_OP_MOV_BRGR ||
        insn->opcode == IA64_OP_MOV_GRBR) {
        ia64_tr_emit_decoded_br_move(ctx, insn);
        return;
    }

    if (insn->opcode == IA64_OP_MOV_ARGR ||
        insn->opcode == IA64_OP_MOV_GRAR) {
        ia64_tr_emit_decoded_pfs_move(ctx, insn);
        return;
    }

    if (ia64_tr_decoded_is_integer_compare_opcode(insn->opcode)) {
        ia64_tr_emit_decoded_integer_compare(ctx, insn);
        return;
    }

    if (ia64_tr_decoded_is_predicate_test_opcode(insn->opcode)) {
        ia64_tr_emit_decoded_predicate_test(ctx, insn);
        return;
    }

    ia64_tr_prime_decoded_instruction_state(ctx, insn);
    gr_write = ia64_tr_group_prepare_gr(ctx, insn->r1);
    skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
    result = ia64_tr_scratch_i64(ctx);
    source[0] = ia64_tr_scratch_i64(ctx);
    source[1] = ia64_tr_scratch_i64(ctx);
    source[2] = ia64_tr_scratch_i64(ctx);
    result_nat = ia64_tr_scratch_i64(ctx);
    tcg_gen_movi_i64(result_nat, 0);

    source_count = ia64_tr_decoded_sources(insn, source_regs);
    for (unsigned i = 0; i < source_count; i++) {
        bool reused = false;

        for (unsigned j = 0; j < i; j++) {
            if (source_regs[j] == source_regs[i]) {
                source[i] = source[j];
                source_nat[i] = source_nat[j];
                reused = true;
                break;
            }
        }
        if (reused) {
            continue;
        }
        source_nat[i] = ia64_tr_scratch_i64(ctx);
        ia64_tr_group_load_ordinary_gr_pair(
            ctx, source[i], source_nat[i], source_regs[i]);
        tcg_gen_or_i64(result_nat, result_nat, source_nat[i]);
    }

    switch (insn->opcode) {
    case IA64_OP_MOVL:
        tcg_gen_movi_i64(result, (uint64_t)insn->imm);
        break;
    case IA64_OP_ADDS:
    case IA64_OP_ADDL:
        tcg_gen_addi_i64(result, source[0], insn->imm);
        break;
    case IA64_OP_ADD:
        tcg_gen_add_i64(result, source[0], source[1]);
        break;
    case IA64_OP_ADD_ONE:
        tcg_gen_add_i64(result, source[0], source[1]);
        tcg_gen_addi_i64(result, result, 1);
        break;
    case IA64_OP_SUB:
        tcg_gen_sub_i64(result, source[0], source[1]);
        break;
    case IA64_OP_SUB_ONE:
        tcg_gen_sub_i64(result, source[0], source[1]);
        tcg_gen_subi_i64(result, result, 1);
        break;
    case IA64_OP_SUB_IMM:
        tcg_gen_movi_i64(result, (uint64_t)insn->imm);
        tcg_gen_sub_i64(result, result, source[0]);
        break;
    case IA64_OP_AND:
        tcg_gen_and_i64(result, source[0], source[1]);
        break;
    case IA64_OP_ANDCM:
        tcg_gen_andc_i64(result, source[0], source[1]);
        break;
    case IA64_OP_OR:
        tcg_gen_or_i64(result, source[0], source[1]);
        break;
    case IA64_OP_XOR:
        tcg_gen_xor_i64(result, source[0], source[1]);
        break;
    case IA64_OP_AND_IMM:
        tcg_gen_andi_i64(result, source[0], (uint64_t)insn->imm);
        break;
    case IA64_OP_ANDCM_IMM:
    {
        TCGv_i64 immediate = tcg_constant_i64((uint64_t)insn->imm);

        tcg_gen_andc_i64(result, immediate, source[0]);
        break;
    }
    case IA64_OP_OR_IMM:
        tcg_gen_ori_i64(result, source[0], (uint64_t)insn->imm);
        break;
    case IA64_OP_XOR_IMM:
        tcg_gen_xori_i64(result, source[0], (uint64_t)insn->imm);
        break;
    case IA64_OP_SHLADD:
        tcg_gen_shli_i64(result, source[0], insn->imm);
        tcg_gen_add_i64(result, result, source[1]);
        break;
    case IA64_OP_SHL:
    case IA64_OP_SHR:
    case IA64_OP_SHRU:
        ia64_tr_emit_decoded_variable_shift(
            ctx, insn->opcode, result, source[0], source[1]);
        break;
    case IA64_OP_SHRP_IMM:
        tcg_gen_extract2_i64(result, source[1], source[0],
                             insn->imm & 63);
        break;
    case IA64_OP_DEPZ:
    {
        unsigned pos = ia64_tr_decoded_bitfield_pos(insn);
        uint64_t mask = ia64_tr_decoded_bitfield_mask(insn);

        tcg_gen_shli_i64(result, source[0], pos);
        tcg_gen_andi_i64(result, result, mask);
        break;
    }
    case IA64_OP_DEPZ_IMM:
    {
        unsigned pos = ia64_tr_decoded_bitfield_pos(insn);
        uint64_t mask = ia64_tr_decoded_bitfield_mask(insn);
        uint8_t imm8 = ((uint64_t)insn->imm >> 13) & 0xff;
        uint64_t value = (uint64_t)(int64_t)(int8_t)imm8;

        tcg_gen_movi_i64(result, (value << pos) & mask);
        break;
    }
    case IA64_OP_DEP:
        tcg_gen_deposit_i64(result, source[1], source[0],
                            ia64_tr_decoded_bitfield_pos(insn),
                            ia64_tr_decoded_bitfield_len(insn));
        break;
    case IA64_OP_DEP_IMM:
    {
        uint64_t mask = ia64_tr_decoded_bitfield_mask(insn);
        bool fill = ((uint64_t)insn->imm >> 13) & 1;

        tcg_gen_andi_i64(result, source[0], ~mask);
        if (fill) {
            tcg_gen_ori_i64(result, result, mask);
        }
        break;
    }
    case IA64_OP_EXTR:
        tcg_gen_sextract_i64(result, source[0],
                             ia64_tr_decoded_bitfield_pos(insn),
                             ia64_tr_decoded_bitfield_len(insn));
        break;
    case IA64_OP_EXTRU:
        tcg_gen_extract_i64(result, source[0],
                            ia64_tr_decoded_bitfield_pos(insn),
                            ia64_tr_decoded_bitfield_len(insn));
        break;
    case IA64_OP_SXT1:
        tcg_gen_ext8s_i64(result, source[0]);
        break;
    case IA64_OP_SXT2:
        tcg_gen_ext16s_i64(result, source[0]);
        break;
    case IA64_OP_SXT4:
        tcg_gen_ext32s_i64(result, source[0]);
        break;
    case IA64_OP_ZXT1:
        tcg_gen_ext8u_i64(result, source[0]);
        break;
    case IA64_OP_ZXT2:
        tcg_gen_ext16u_i64(result, source[0]);
        break;
    case IA64_OP_ZXT4:
        tcg_gen_ext32u_i64(result, source[0]);
        break;
    case IA64_OP_SHLADDP4:
    {
        TCGv_i64 shifted = ia64_tr_scratch_i64(ctx);

        tcg_gen_shli_i64(shifted, source[0], insn->imm);
        ia64_tr_emit_addp4(ctx, result, shifted, source[1]);
        break;
    }
    case IA64_OP_MPY4:
    {
        TCGv_i64 left = ia64_tr_scratch_i64(ctx);
        TCGv_i64 right = ia64_tr_scratch_i64(ctx);

        tcg_gen_ext32u_i64(left, source[0]);
        tcg_gen_ext32u_i64(right, source[1]);
        tcg_gen_mul_i64(result, left, right);
        break;
    }
    case IA64_OP_MPYSHL4:
    {
        TCGv_i64 left = ia64_tr_scratch_i64(ctx);
        TCGv_i64 right = ia64_tr_scratch_i64(ctx);

        tcg_gen_shri_i64(left, source[0], 32);
        tcg_gen_ext32u_i64(right, source[1]);
        tcg_gen_mul_i64(result, left, right);
        tcg_gen_shli_i64(result, result, 32);
        break;
    }
    case IA64_OP_POPCNT:
        tcg_gen_ctpop_i64(result, source[0]);
        break;
    case IA64_OP_CLZ:
        tcg_gen_clzi_i64(result, source[0], 64);
        break;
    case IA64_OP_ADDP4:
        ia64_tr_emit_addp4(ctx, result, source[0], source[1]);
        break;
    case IA64_OP_ADDP4_IMM:
        ia64_tr_emit_addp4(ctx, result,
                          tcg_constant_i64((uint64_t)insn->imm), source[0]);
        break;
    default:
        g_assert_not_reached();
    }

    ia64_tr_group_stage_gr(gr_write, result, result_nat);
    ia64_tr_finish_fast_slot_predicate_guard(skip);
}

static void ia64_tr_clear_restart_ri(void)
{
    TCGv_i64 psr = tcg_temp_new_i64();

    tcg_gen_ld_i64(psr, tcg_env, offsetof(CPUIA64State, psr));
    tcg_gen_andi_i64(psr, psr, ~IA64_PSR_RI_MASK);
    tcg_gen_st_i64(psr, tcg_env, offsetof(CPUIA64State, psr));
    tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                    offsetof(CPUIA64State, ri));
    tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                    offsetof(CPUIA64State, ri_dirty));
}

static bool ia64_tr_try_decoded_bundle(DisasContext *ctx,
                                       const IA64DecodedBundle *bundle,
                                       uint64_t pc, uint8_t start_slot,
                                       uint8_t last_slot)
{
    IA64DecodedInstructionBundle decoded;
    IA64TrDecodedBranchArm branch_arm[IA64_SLOT_COUNT] = { 0 };
    unsigned branch_count = 0;
    bool unconditional_branch = false;

    if ((!ctx->typed_group_active &&
         !ia64_tr_full_tcg_rewrite_enabled()) ||
        last_slot >= IA64_SLOT_COUNT || last_slot < start_slot ||
        !ia64_decode_instruction_bundle(bundle, pc,
                                        ctx->instruction_group_start,
                                        start_slot, &decoded) ||
        !ia64_tr_preflight_decoded_bundle_through(&decoded, last_slot)) {
        return false;
    }

    if (last_slot == IA64_SLOT_COUNT - 1) {
        ia64_tr_profile_add(ctx, IA64_PROFILE_BUNDLE_ZERO_HELPER, 1);
    }

    for (unsigned slot = start_slot; slot <= last_slot; slot++) {
        const IA64Instruction *insn;

        if ((decoded.instruction_mask & (1u << slot)) == 0) {
            continue;
        }
        insn = &decoded.instruction[slot];
        ia64_tr_group_begin_instruction(ctx, insn);
        if (ia64_tr_decoded_is_conditional_branch(insn->opcode)) {
            g_assert(branch_count < ARRAY_SIZE(branch_arm));
            if (ia64_tr_decoded_is_loop_branch(insn->opcode)) {
                ia64_tr_emit_decoded_loop_branch_split(
                    ctx, insn, &branch_arm[branch_count++]);
                unconditional_branch = false;
            } else if (ia64_tr_decoded_is_return_branch(insn->opcode)) {
                unconditional_branch = ia64_tr_emit_decoded_return_split(
                    ctx, insn, &branch_arm[branch_count++]);
            } else if (ia64_tr_decoded_is_call_branch(insn->opcode)) {
                unconditional_branch = ia64_tr_emit_decoded_call_split(
                    ctx, insn, &branch_arm[branch_count++]);
            } else {
                unconditional_branch = ia64_tr_emit_decoded_branch_split(
                    ctx, insn, &branch_arm[branch_count++]);
            }
            if (unconditional_branch) {
                break;
            }
            continue;
        }
        ia64_tr_emit_decoded_instruction(ctx, insn);
        ia64_tr_group_finish_instruction_success(ctx, insn);
        if (insn->stop_after) {
            ia64_tr_group_close(ctx);
        }
    }

    if (branch_count != 0) {
        bool has_fallthrough = !unconditional_branch;
        bool fallthrough_group_start = true;
        bool fallthrough_typed_active = false;

        if (has_fallthrough) {
            fallthrough_group_start =
                last_slot == IA64_SLOT_COUNT - 1 ?
                decoded.ends_at_group_boundary : true;
            fallthrough_typed_active = !fallthrough_group_start;
            if (fallthrough_typed_active) {
                ia64_tr_group_suspend_for_typed_continuation(ctx);
            }
        }
        ctx->instruction_group_start = fallthrough_group_start;
        g_assert(!ctx->state_cache_active);
        g_assert(ia64_tr_group_is_empty(ctx));
        ia64_tr_emit_decoded_branch_cfg_exits(
            ctx, branch_arm, branch_count, has_fallthrough,
            pc + IA64_BUNDLE_SIZE, fallthrough_group_start,
            fallthrough_typed_active);
        ctx->rewrite_control_flow_exit = true;
        ctx->base.is_jmp = DISAS_NORETURN;
        return true;
    }

    if (pc == ctx->base.pc_first &&
        ia64_tcg_tb_flags_ri(ctx->base.tb->flags) != 0) {
        ia64_tr_clear_restart_ri();
    }
    ctx->instruction_group_start = last_slot == IA64_SLOT_COUNT - 1 ?
                                   decoded.ends_at_group_boundary : true;
    if (ctx->instruction_group_start) {
        g_assert(ia64_tr_group_is_empty(ctx));
    }
    if (last_slot == IA64_SLOT_COUNT - 1) {
        ia64_tr_note_fast_bundle(ctx);
    }
    return true;
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
        ia64_tr_emit_fast_bundle_guards(ctx, &fast, fallback,
                                        ldst_address);
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
        ia64_tr_store_source_visibility_state(
            ctx, ctx->instruction_group_start, false);
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
        ia64_tr_emit_gr_alat_invalidate(ctx, runtime_dest_mask,
                                        runtime_dest_mask_hi, pc);
    } else {
        gen_helper_finish_fast_bundle(
            tcg_env, tcg_constant_i64(pc + IA64_BUNDLE_SIZE),
            runtime_dest_mask, runtime_dest_mask_hi,
            tcg_constant_i32(bundle->info->stop_after_slot[2]));
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
                ctx, bundle, pc, 0, &dirty_before);
        } else {
            ia64_tr_emit_exec_bundle(ctx, bundle, pc, 0);
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

    g_assert(!ctx->typed_group_active);
    /* A fault in this slot must not lose earlier retired bundles in the TB. */
    ia64_tr_state_cache_barrier(ctx);
    ia64_tr_store_legacy_helper_frontier(
        slot == 0 ? ctx->instruction_group_start :
        bundle->info->stop_after_slot[slot - 1]);
    ia64_tr_commit_ip(pc);
    ia64_tr_flush_fast_bundle_ticks(ctx);
    gen_helper_exec_slot(
        flow_changed, tcg_env,
        tcg_constant_i64(fallback_args.header),
        tcg_constant_i64(fallback_args.slot1),
        tcg_constant_i64(fallback_args.slot2),
        tcg_constant_i64(fallback_args.desc01),
        tcg_constant_i64(fallback_args.desc2));
    tcg_gen_brcondi_i32(TCG_COND_NE, flow_changed, 0, flow_exit);
}

static bool ia64_tr_slot_ends_execution_epoch(IA64SlotType type, uint64_t raw)
{
    return ia64_slot_is_m_serialization(type, raw) ||
           ia64_slot_is_m_processor_mask(type, raw) ||
           ia64_slot_is_m_mov_to_processor_status(type, raw);
}

static int ia64_tr_first_execution_epoch_end_slot(
    const IA64DecodedBundle *bundle, unsigned start_slot)
{
    if (!bundle->valid || start_slot >= IA64_SLOT_COUNT) {
        return -1;
    }

    for (unsigned slot = start_slot; slot < IA64_SLOT_COUNT; slot++) {
        if (ia64_tr_slot_ends_execution_epoch(bundle->info->slot_type[slot],
                                              bundle->slot[slot])) {
            return slot;
        }
    }
    return -1;
}

/*
 * Serialization and guest PSR writes are slot boundaries, not bundle
 * boundaries.  Execute only the legacy-owned prefix through that operation,
 * then publish the first unexecuted slot as the restart RI.  Each selected-
 * slot helper applies the slot predicate and advances the ordinary-source
 * frontier; a returned flow change bypasses sequential RI publication and
 * keeps the helper's IP.
 *
 * Slot 2 already has no bundle suffix, so the normal full-bundle helper is
 * both exact and preferable there: it also performs the ordinary post-bundle
 * accounting and publishes the next bundle at RI=0.
 */
static bool ia64_tr_translate_execution_epoch_prefix(
    DisasContext *ctx, const IA64DecodedBundle *bundle, uint64_t pc,
    unsigned start_slot)
{
    int boundary_slot =
        ia64_tr_first_execution_epoch_end_slot(bundle, start_slot);
    TCGLabel *flow_exit;

    if (boundary_slot < 0 || boundary_slot == IA64_SLOT_COUNT - 1) {
        return false;
    }

    flow_exit = gen_new_label();
    for (unsigned slot = start_slot;
         slot <= (unsigned)boundary_slot; slot++) {
        ia64_tr_emit_exec_slot(ctx, bundle, pc, slot, flow_exit);
    }

    /* cpu_ip remains this bundle; only the first unexecuted RI advances. */
    ia64_tr_publish_restart_ri(boundary_slot + 1);
    gen_set_label(flow_exit);
    return true;
}

static bool ia64_tr_partial_slot_needs_guard(const IA64TcgFastSlot *slot)
{
    return slot->source_nat_mask != 0 || slot->source_nat_mask_hi != 0;
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

    ia64_tr_emit_gr_alat_invalidate(ctx, runtime_dest_mask,
                                    runtime_dest_mask_hi, pc);
    ia64_tr_note_fast_bundle(ctx);
    {
        TCGLabel *continue_exec = gen_new_label();
        TCGv_i32 request = tcg_temp_new_i32();

        /* Publish a precise post-bundle state before queued host work runs. */
        tcg_gen_ld8u_i32(request, tcg_env,
                         IA64_CPU_STATE_OFFSET(exit_request));
        tcg_gen_brcondi_i32(TCG_COND_EQ, request, 0, continue_exec);
        ia64_tr_store_source_visibility_state(
            ctx, bundle->info->stop_after_slot[2], false);
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
    ia64_tr_store_source_visibility_state(ctx, ctx->instruction_group_start,
                                          ctx->typed_group_active);
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
    DisasContext *ctx, uint64_t target, int tb_slot, bool use_goto_tb,
    bool instruction_group_start)
{
    TCGLabel *main_loop_exit = gen_new_label();

    ia64_tr_sync_state_cache(ctx);
    ia64_tr_store_source_visibility_state(ctx, instruction_group_start,
                                          false);
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

static void ia64_tr_store_typed_taken_visibility_state(void)
{
    /* A taken branch always starts a fresh issue group at RI=0. */
    tcg_gen_st_i64(tcg_constant_i64(0), tcg_env,
                   offsetof(CPUIA64State, issue_group.saved_gr_mask));
    tcg_gen_st_i64(tcg_constant_i64(0), tcg_env,
                   offsetof(CPUIA64State, issue_group.saved_gr_mask) +
                   sizeof(uint64_t));
    tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                    offsetof(CPUIA64State, issue_group.saved_br_mask));
    tcg_gen_st8_i32(
        tcg_constant_i32(0), tcg_env,
        offsetof(CPUIA64State, issue_group.branch_br_forward_mask));
    tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                    offsetof(CPUIA64State, issue_group.pr_saved));
    tcg_gen_st_i64(
        tcg_constant_i64(0), tcg_env,
        offsetof(CPUIA64State, issue_group.branch_pr_forward_mask));
    tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                    offsetof(CPUIA64State, issue_group.pfs_saved));
    tcg_gen_st8_i32(
        tcg_constant_i32(0), tcg_env,
        offsetof(CPUIA64State, issue_group.branch_pfs_forwarded));
    tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                    offsetof(CPUIA64State, issue_group.typed_active));
    tcg_gen_st8_i32(tcg_constant_i32(1), tcg_env,
                    offsetof(CPUIA64State, instruction_group_start));
    tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                    offsetof(CPUIA64State, instruction_group_dirty));
}

/*
 * Exit arm for a branch already lowered by the typed transaction.  Cached
 * state is synchronized before the first runtime split, so no arm-specific
 * translation-time dirty decision is needed here.
 */
static void ia64_tr_emit_typed_direct_branch_exit(
    DisasContext *ctx, uint64_t target, int tb_slot, bool use_goto_tb,
    bool instruction_group_start, bool typed_group_active, bool taken)
{
    TCGLabel *main_loop_exit = gen_new_label();

    if (taken) {
        g_assert(instruction_group_start && !typed_group_active);
        ia64_tr_store_typed_taken_visibility_state();
    } else {
        ia64_tr_store_source_visibility_state(
            ctx, instruction_group_start, typed_group_active);
    }
    ia64_tr_clear_restart_ri();
    ia64_tr_commit_ip(target);
    /* Any exit-capable tick helper must observe this arm's exact frontier. */
    ia64_tr_flush_fast_bundle_ticks(ctx);
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

static void ia64_tr_emit_typed_indirect_branch_exit(DisasContext *ctx,
                                                     TCGv_i64 target)
{
    TCGLabel *main_loop_exit = gen_new_label();

    ia64_tr_store_typed_taken_visibility_state();
    ia64_tr_clear_restart_ri();
    ia64_tr_commit_ip_value(target);
    ia64_tr_flush_fast_bundle_ticks(ctx);
    ia64_tr_emit_exit_request_guard(main_loop_exit);
    ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_LOOKUP);
    tcg_gen_lookup_and_goto_ptr();

    gen_set_label(main_loop_exit);
    ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_MAIN);
    tcg_gen_exit_tb(NULL, 0);
}

/*
 * A return is an indirect branch whose taken edge has an architecturally
 * ordered frame transition.  The target and fresh RI=0 issue-group state are
 * committed before restoring PFS/CFM/CPL so every subsequent trap or mandatory
 * RSE fill fault is attributed to the post-branch state.  A PSR.lp-enabled
 * lower-privilege transfer has priority over the taken-branch trap; only a
 * trap-free return may issue the mandatory loads needed to complete an older,
 * non-resident frame.
 *
 * The two frame helpers are deliberately narrow architectural seams.  Ordinary
 * branch selection, source forwarding, target alignment and TB lookup remain
 * direct TCG operations, and no helper receives instruction bits to decode.
 */
static void ia64_tr_emit_typed_return_exit(DisasContext *ctx,
                                            TCGv_i64 target,
                                            TCGv_i64 pfs)
{
    TCGLabel *not_lower_privilege = gen_new_label();
    TCGLabel *not_taken_trap = gen_new_label();
    TCGLabel *main_loop_exit = gen_new_label();
    TCGv_i32 lower_privilege = tcg_temp_new_i32();
    TCGv_i32 chain_ok = tcg_temp_new_i32();
    TCGv_i64 psr = tcg_temp_new_i64();
    TCGv_i64 psr_lp = tcg_temp_new_i64();

    ia64_tr_store_typed_taken_visibility_state();
    ia64_tr_clear_restart_ri();
    ia64_tr_commit_ip_value(target);
    /* Count the retired branch without permitting asynchronous observation. */
    ia64_tr_retire_fast_bundle_ticks_deferred_interrupt(ctx);

    gen_helper_return_frame_from_pfs(lower_privilege, tcg_env, pfs);
    tcg_gen_ld_i64(psr, tcg_env, offsetof(CPUIA64State, psr));
    tcg_gen_brcondi_i32(TCG_COND_EQ, lower_privilege, 0,
                        not_lower_privilege);
    tcg_gen_andi_i64(psr_lp, psr, IA64_PSR_LP_BIT);
    tcg_gen_brcondi_i64(TCG_COND_EQ, psr_lp, 0, not_lower_privilege);
    gen_helper_raise_lower_privilege_transfer_trap(tcg_env);

    gen_set_label(not_lower_privilege);
    tcg_gen_andi_i64(psr, psr, IA64_PSR_TB_BIT);
    tcg_gen_brcondi_i64(TCG_COND_EQ, psr, 0, not_taken_trap);
    gen_helper_raise_taken_branch_trap(tcg_env);

    gen_set_label(not_taken_trap);
    gen_helper_complete_rse_frame_loads(tcg_env);

    gen_helper_return_chain_ok(chain_ok, tcg_env);
    tcg_gen_brcondi_i32(TCG_COND_EQ, chain_ok, 0, main_loop_exit);
    ia64_tr_emit_exit_request_guard(main_loop_exit);
    ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_LOOKUP);
    tcg_gen_lookup_and_goto_ptr();

    gen_set_label(main_loop_exit);
    ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_MAIN);
    tcg_gen_exit_tb(NULL, 0);
}

static void ia64_tr_split_state_cache_at_typed_branch(DisasContext *ctx)
{
    if (ctx->state_cache_active) {
        ia64_tr_sync_state_cache(ctx);
        ia64_tr_invalidate_state_cache(ctx);
        ctx->state_cache_active = false;
    }
}

static void ia64_tr_emit_call_frame_transition(DisasContext *ctx)
{
    /* The returning helper may rewrite every frame-dependent global. */
    g_assert(!ctx->state_cache_active);
    gen_helper_enter_call_frame(tcg_env);
}

static void ia64_tr_assert_loop_branch_resources(
    const IA64TrInstructionTransaction *instruction,
    const IA64Instruction *insn)
{
    uint64_t lc = UINT64_C(1) << (IA64_AR_LC & 63);
    uint64_t ec = UINT64_C(1) << (IA64_AR_EC & 63);
    uint64_t p63 = UINT64_C(1) << 63;
    uint64_t expected_branch_pr = 0;
    uint64_t expected_ar;

    g_assert(instruction != NULL &&
             ia64_tr_decoded_is_loop_branch(insn->opcode));
    g_assert(instruction->dest_gr[0] == 0 &&
             instruction->dest_gr[1] == 0 &&
             instruction->must_gr[0] == 0 &&
             instruction->must_gr[1] == 0 &&
             instruction->branch_source_br == 0 &&
             instruction->dest_br == 0 &&
             instruction->must_br == 0 &&
             instruction->forward_br == 0);
    g_assert(instruction->source_ar[0] == 0 &&
             instruction->dest_ar[0] == 0);
    if (insn->opcode == IA64_OP_BR_CLOOP) {
        expected_ar = lc;
        g_assert(!instruction->source_cfm && !instruction->dest_cfm &&
                 instruction->dest_pr == 0 && instruction->must_pr == 0 &&
                 instruction->forward_pr == 0);
    } else if (insn->opcode == IA64_OP_BR_CTOP ||
               insn->opcode == IA64_OP_BR_CEXIT) {
        expected_ar = lc | ec;
        g_assert(instruction->source_cfm && instruction->dest_cfm);
    } else {
        expected_ar = ec;
        if (insn->qp != 0) {
            expected_branch_pr = UINT64_C(1) << insn->qp;
        }
        g_assert(instruction->source_cfm && instruction->dest_cfm);
    }
    g_assert(instruction->source_ar[1] == expected_ar &&
             instruction->dest_ar[1] == expected_ar &&
             instruction->branch_source_pr == expected_branch_pr);
    if (insn->opcode != IA64_OP_BR_CLOOP) {
        g_assert(instruction->dest_pr == p63 &&
                 instruction->must_pr == p63 &&
                 instruction->forward_pr == 0 &&
                 (instruction->forward_pr & p63) == 0);
    }
}

static void ia64_tr_emit_decoded_loop_branch_split(
    DisasContext *ctx, const IA64Instruction *insn,
    IA64TrDecodedBranchArm *arm)
{
    IA64TrInstructionTransaction *instruction =
        ctx->rewrite_group.current;
    TCGv_i64 taken = ia64_tr_scratch_i64(ctx);
    TCGv_i64 rotate = NULL;
    uint64_t bundle_ip = insn->address &
                         ~(uint64_t)(IA64_BUNDLE_SIZE - 1);

    g_assert(ia64_tr_decoded_is_loop_branch(insn->opcode) &&
             insn->unit == IA64_INSN_UNIT_B &&
             insn->slot == IA64_SLOT_COUNT - 1 && insn->slot_span == 1 &&
             (insn->imm & 0xf) == 0 &&
             ((insn->opcode == IA64_OP_BR_WTOP ||
               insn->opcode == IA64_OP_BR_WEXIT) || insn->qp == 0));
    ia64_tr_assert_loop_branch_resources(instruction, insn);
    memset(arm, 0, sizeof(*arm));
    arm->taken = gen_new_label();
    arm->direct_target = bundle_ip + (uint64_t)insn->imm;
    ia64_tr_profile_add(ctx, IA64_PROFILE_BRANCH_INLINE_DIRECT, 1);

    if (insn->opcode == IA64_OP_BR_CLOOP) {
        TCGv_i64 lc = ia64_tr_scratch_i64(ctx);
        TCGv_i64 lc_nonzero = ia64_tr_scratch_i64(ctx);
        TCGv_i64 decremented = ia64_tr_scratch_i64(ctx);
        TCGLabel *skip_decrement = gen_new_label();

        ia64_tr_load_ar(ctx, lc, IA64_AR_LC);
        tcg_gen_setcondi_i64(TCG_COND_NE, lc_nonzero, lc, 0);
        tcg_gen_mov_i64(taken, lc_nonzero);
        tcg_gen_brcondi_i64(TCG_COND_EQ, lc_nonzero, 0,
                            skip_decrement);
        tcg_gen_subi_i64(decremented, lc, 1);
        ia64_tr_store_ar(ctx, IA64_AR_LC, decremented);
        gen_set_label(skip_decrement);
    } else {
        IA64TrPrWrite *p63 = ia64_tr_group_prepare_pr(ctx, 63);
        TCGv_i64 ec = ia64_tr_scratch_i64(ctx);
        TCGv_i64 ec_nonzero = ia64_tr_scratch_i64(ctx);
        TCGv_i64 ec_gt_one = ia64_tr_scratch_i64(ctx);
        TCGv_i64 active = ia64_tr_scratch_i64(ctx);
        TCGv_i64 decrement_ec = ia64_tr_scratch_i64(ctx);
        TCGv_i64 decremented = ia64_tr_scratch_i64(ctx);
        TCGLabel *skip_ec_decrement = gen_new_label();

        rotate = ia64_tr_scratch_i64(ctx);
        ia64_tr_load_ar(ctx, ec, IA64_AR_EC);
        tcg_gen_setcondi_i64(TCG_COND_NE, ec_nonzero, ec, 0);
        tcg_gen_setcondi_i64(TCG_COND_GTU, ec_gt_one, ec, 1);

        if (insn->opcode == IA64_OP_BR_WTOP ||
            insn->opcode == IA64_OP_BR_WEXIT) {
            TCGv_i64 predicate = ia64_tr_scratch_i64(ctx);
            TCGv_i64 predicate_true = ia64_tr_scratch_i64(ctx);

            /* W-loop qp is branch-visible even when the value is false. */
            ia64_tr_group_load_branch_predicate(ctx, predicate, insn->qp);
            tcg_gen_setcondi_i64(TCG_COND_NE, predicate_true,
                                 predicate, 0);
            tcg_gen_or_i64(active, predicate_true, ec_gt_one);
            tcg_gen_or_i64(rotate, predicate_true, ec_nonzero);
            tcg_gen_andc_i64(decrement_ec, ec_nonzero, predicate_true);
            ia64_tr_group_stage_pr_const(p63, false);
        } else {
            TCGv_i64 lc = ia64_tr_scratch_i64(ctx);
            TCGv_i64 lc_nonzero = ia64_tr_scratch_i64(ctx);
            TCGv_i64 decrement_lc = ia64_tr_scratch_i64(ctx);
            TCGLabel *skip_lc_decrement = gen_new_label();

            ia64_tr_load_ar(ctx, lc, IA64_AR_LC);
            tcg_gen_setcondi_i64(TCG_COND_NE, lc_nonzero, lc, 0);
            tcg_gen_or_i64(active, lc_nonzero, ec_gt_one);
            tcg_gen_or_i64(rotate, lc_nonzero, ec_nonzero);
            tcg_gen_andc_i64(decrement_ec, ec_nonzero, lc_nonzero);
            ia64_tr_group_stage_pr_bool(p63, lc_nonzero);

            tcg_gen_brcondi_i64(TCG_COND_EQ, lc_nonzero, 0,
                                skip_lc_decrement);
            tcg_gen_subi_i64(decrement_lc, lc, 1);
            ia64_tr_store_ar(ctx, IA64_AR_LC, decrement_lc);
            gen_set_label(skip_lc_decrement);
        }

        tcg_gen_brcondi_i64(TCG_COND_EQ, decrement_ec, 0,
                            skip_ec_decrement);
        tcg_gen_subi_i64(decremented, ec, 1);
        ia64_tr_store_ar(ctx, IA64_AR_EC, decremented);
        gen_set_label(skip_ec_decrement);
        if (insn->opcode == IA64_OP_BR_CEXIT ||
            insn->opcode == IA64_OP_BR_WEXIT) {
            tcg_gen_xori_i64(taken, active, 1);
        } else {
            tcg_gen_mov_i64(taken, active);
        }
    }

    /* Retire p63 through the normal transaction while the old RRB owns it. */
    ia64_tr_group_finish_instruction_success(ctx, insn);
    if (insn->stop_after) {
        ia64_tr_group_close(ctx);
    }
    ia64_tr_split_state_cache_at_typed_branch(ctx);

    if (rotate != NULL) {
        TCGLabel *skip_rotation = gen_new_label();

        tcg_gen_brcondi_i64(TCG_COND_EQ, rotate, 0, skip_rotation);
        gen_helper_rotate_modulo_registers(tcg_env);
        gen_set_label(skip_rotation);
    }
    tcg_gen_brcondi_i64(TCG_COND_NE, taken, 0, arm->taken);
}

static void ia64_tr_assert_return_branch_resources(
    const IA64TrInstructionTransaction *instruction,
    const IA64Instruction *insn)
{
    uint64_t ec = UINT64_C(1) << (IA64_AR_EC & 63);
    uint64_t pfs = UINT64_C(1) << (IA64_AR_PFS & 63);
    uint64_t expected_branch_pr = insn->qp == 0 ? 0 :
        UINT64_C(1) << insn->qp;

    g_assert(instruction != NULL &&
             ia64_tr_decoded_is_return_branch(insn->opcode));
    g_assert(instruction->dest_gr[0] == 0 &&
             instruction->dest_gr[1] == 0 &&
             instruction->must_gr[0] == 0 &&
             instruction->must_gr[1] == 0 &&
             instruction->source_ar[0] == 0 &&
             instruction->source_ar[1] == pfs &&
             instruction->dest_ar[0] == 0 &&
             instruction->dest_ar[1] == ec &&
             instruction->dest_pr == 0 &&
             instruction->must_pr == 0 &&
             instruction->forward_pr == 0 &&
             instruction->branch_source_pr == expected_branch_pr &&
             instruction->source_br == 0 &&
             instruction->dest_br == 0 &&
             instruction->must_br == 0 &&
             instruction->forward_br == 0 &&
             instruction->branch_source_br == (1u << insn->b2) &&
             instruction->source_cfm && instruction->dest_cfm &&
             !instruction->forward_pfs &&
             instruction->branch_source_pfs &&
             !instruction->must_pfs);
}

static bool ia64_tr_emit_decoded_return_split(
    DisasContext *ctx, const IA64Instruction *insn,
    IA64TrDecodedBranchArm *arm)
{
    IA64TrInstructionTransaction *instruction =
        ctx->rewrite_group.current;
    TCGv_i64 predicate = ia64_tr_scratch_i64(ctx);
    TCGLabel *skip_return = gen_new_label();
    bool unconditional = insn->qp == 0;

    g_assert(ia64_tr_decoded_is_return_branch(insn->opcode) &&
             insn->unit == IA64_INSN_UNIT_B && insn->slot_span == 1 &&
             insn->b2 < IA64_BR_COUNT);
    ia64_tr_assert_return_branch_resources(instruction, insn);
    memset(arm, 0, sizeof(*arm));
    arm->taken = gen_new_label();
    arm->indirect = true;
    arm->ret = true;
    arm->indirect_target = tcg_temp_new_i64();
    arm->return_pfs = tcg_temp_new_i64();
    ia64_tr_profile_add(ctx, IA64_PROFILE_BRANCH_INLINE_INDIRECT, 1);

    /*
     * All branch-visible inputs are captured before retiring the instruction.
     * In particular PFS must survive both the fresh-target visibility reset
     * and the frame helper, and the BR target must survive any overlapping
     * producer in this issue group.
     */
    ia64_tr_group_load_branch_predicate(ctx, predicate, insn->qp);
    tcg_gen_brcondi_i64(TCG_COND_EQ, predicate, 0, skip_return);
    ia64_tr_group_load_branch_br(ctx, arm->indirect_target, insn->b2);
    tcg_gen_andi_i64(arm->indirect_target, arm->indirect_target,
                     ~UINT64_C(0xf));
    ia64_tr_group_load_branch_pfs(ctx, arm->return_pfs);
    ia64_tr_publish_fault_state(insn->address, insn->slot,
                                ia64_tr_decoded_slot_type(insn->unit),
                                insn->raw, insn->starts_group);
    gen_set_label(skip_return);

    ia64_tr_group_finish_instruction_success(ctx, insn);
    if (insn->stop_after || unconditional) {
        ia64_tr_group_close(ctx);
    }
    ia64_tr_split_state_cache_at_typed_branch(ctx);

    if (unconditional) {
        tcg_gen_br(arm->taken);
    } else {
        tcg_gen_brcondi_i64(TCG_COND_NE, predicate, 0, arm->taken);
    }
    return unconditional;
}

static void ia64_tr_assert_call_branch_resources(
    const IA64TrInstructionTransaction *instruction,
    const IA64Instruction *insn)
{
    uint64_t ec = UINT64_C(1) << (IA64_AR_EC & 63);
    uint64_t pfs = UINT64_C(1) << (IA64_AR_PFS & 63);
    uint64_t expected_branch_pr = insn->qp == 0 ? 0 :
        UINT64_C(1) << insn->qp;
    uint8_t link = 1u << insn->b1;
    uint8_t expected_target =
        insn->opcode == IA64_OP_BR_CALL_INDIRECT ? 1u << insn->b2 : 0;

    g_assert(instruction != NULL &&
             ia64_tr_decoded_is_call_branch(insn->opcode));
    g_assert(instruction->dest_gr[0] == 0 &&
             instruction->dest_gr[1] == 0 &&
             instruction->must_gr[0] == 0 &&
             instruction->must_gr[1] == 0 &&
             instruction->source_ar[0] == 0 &&
             instruction->source_ar[1] == ec &&
             instruction->dest_ar[0] == 0 &&
             instruction->dest_ar[1] == pfs &&
             instruction->dest_pr == 0 &&
             instruction->must_pr == 0 &&
             instruction->forward_pr == 0 &&
             instruction->branch_source_pr == expected_branch_pr &&
             instruction->source_br == 0 &&
             instruction->dest_br == link &&
             instruction->must_br == (insn->qp == 0 ? link : 0) &&
             instruction->forward_br == 0 &&
             instruction->branch_source_br == expected_target &&
             instruction->source_cfm && instruction->dest_cfm);
}

static bool ia64_tr_emit_decoded_call_split(
    DisasContext *ctx, const IA64Instruction *insn,
    IA64TrDecodedBranchArm *arm)
{
    IA64TrInstructionTransaction *instruction =
        ctx->rewrite_group.current;
    IA64TrBrWrite *link_write;
    TCGv_i64 predicate = ia64_tr_scratch_i64(ctx);
    TCGLabel *skip_call = gen_new_label();
    uint64_t bundle_ip = insn->address &
                         ~(uint64_t)(IA64_BUNDLE_SIZE - 1);
    bool indirect = insn->opcode == IA64_OP_BR_CALL_INDIRECT;
    bool unconditional = insn->qp == 0;

    g_assert(ia64_tr_decoded_is_call_branch(insn->opcode) &&
             insn->b1 < IA64_BR_COUNT &&
             ((insn->opcode == IA64_OP_BR_CALL &&
               insn->unit == IA64_INSN_UNIT_B && insn->slot_span == 1 &&
               (insn->imm & 0xf) == 0) ||
              (insn->opcode == IA64_OP_BRL_CALL &&
               insn->unit == IA64_INSN_UNIT_X && insn->slot == 1 &&
               insn->slot_span == 2 && (insn->imm & 0xf) == 0) ||
              (indirect && insn->unit == IA64_INSN_UNIT_B &&
               insn->slot_span == 1 && insn->b2 < IA64_BR_COUNT)));
    ia64_tr_assert_call_branch_resources(instruction, insn);
    memset(arm, 0, sizeof(*arm));
    arm->taken = gen_new_label();
    arm->call = true;
    arm->indirect = indirect;
    if (indirect) {
        /* This value must survive the b1 link write, including b1 == b2. */
        arm->indirect_target = tcg_temp_new_i64();
        ia64_tr_profile_add(ctx, IA64_PROFILE_BRANCH_INLINE_INDIRECT, 1);
    } else {
        arm->direct_target = bundle_ip + (uint64_t)insn->imm;
        ia64_tr_profile_add(ctx, IA64_PROFILE_BRANCH_INLINE_DIRECT, 1);
    }

    link_write = ia64_tr_group_prepare_br(ctx, insn->b1);
    g_assert(link_write != NULL && !link_write->forward_to_branch);
    ia64_tr_group_load_branch_predicate(ctx, predicate, insn->qp);
    tcg_gen_brcondi_i64(TCG_COND_EQ, predicate, 0, skip_call);
    if (indirect) {
        ia64_tr_group_load_branch_br(
            ctx, arm->indirect_target, insn->b2);
        tcg_gen_andi_i64(arm->indirect_target, arm->indirect_target,
                         ~UINT64_C(0xf));
    }
    ia64_tr_group_stage_br(
        link_write, tcg_constant_i64(bundle_ip + IA64_BUNDLE_SIZE));
    gen_set_label(skip_call);

    ia64_tr_group_finish_instruction_success(ctx, insn);
    if (insn->stop_after || unconditional) {
        ia64_tr_group_close(ctx);
    }
    ia64_tr_split_state_cache_at_typed_branch(ctx);

    if (unconditional) {
        tcg_gen_br(arm->taken);
    } else {
        tcg_gen_brcondi_i64(TCG_COND_NE, predicate, 0, arm->taken);
    }
    return unconditional;
}

static bool ia64_tr_emit_decoded_branch_split(
    DisasContext *ctx, const IA64Instruction *insn,
    IA64TrDecodedBranchArm *arm)
{
    TCGv_i64 predicate = ia64_tr_scratch_i64(ctx);
    bool unconditional = insn->qp == 0;

    g_assert(ia64_tr_decoded_is_conditional_branch(insn->opcode) &&
             !ia64_tr_decoded_is_loop_branch(insn->opcode) &&
             !ia64_tr_decoded_is_call_branch(insn->opcode));
    memset(arm, 0, sizeof(*arm));
    arm->taken = gen_new_label();
    ia64_tr_group_load_branch_predicate(ctx, predicate, insn->qp);
    if (insn->opcode == IA64_OP_BR_INDIRECT) {
        arm->indirect = true;
        arm->indirect_target = tcg_temp_new_i64();
        ia64_tr_group_load_branch_br(ctx, arm->indirect_target, insn->b2);
        tcg_gen_andi_i64(arm->indirect_target, arm->indirect_target,
                         ~UINT64_C(0xf));
        ia64_tr_profile_add(ctx, IA64_PROFILE_BRANCH_INLINE_INDIRECT, 1);
    } else {
        uint64_t bundle_ip = insn->address &
                             ~(uint64_t)(IA64_BUNDLE_SIZE - 1);

        arm->direct_target = bundle_ip + (uint64_t)insn->imm;
        ia64_tr_profile_add(ctx, IA64_PROFILE_BRANCH_INLINE_DIRECT, 1);
    }
    ia64_tr_group_finish_instruction_success(ctx, insn);

    /* A stop closes both arms; p0 has only the fresh-target arm. */
    if (insn->stop_after || unconditional) {
        ia64_tr_group_close(ctx);
    }
    ia64_tr_split_state_cache_at_typed_branch(ctx);

    if (unconditional) {
        tcg_gen_br(arm->taken);
    } else {
        tcg_gen_brcondi_i64(TCG_COND_NE, predicate, 0, arm->taken);
    }
    return unconditional;
}

static void ia64_tr_emit_decoded_branch_cfg_exits(
    DisasContext *ctx, IA64TrDecodedBranchArm arms[IA64_SLOT_COUNT],
    unsigned arm_count, bool has_fallthrough, uint64_t fallthrough_target,
    bool fallthrough_group_start, bool fallthrough_typed_active)
{
    int chained_direct_arm = -1;

    g_assert(arm_count > 0 && arm_count <= IA64_SLOT_COUNT);
    for (unsigned i = 0; i < arm_count; i++) {
        if (!arms[i].indirect) {
            chained_direct_arm = i;
            break;
        }
    }

    if (has_fallthrough) {
        ia64_tr_note_fast_bundle(ctx);
        ia64_tr_emit_typed_direct_branch_exit(
            ctx, fallthrough_target, 1,
            translator_use_goto_tb(&ctx->base, fallthrough_target),
            fallthrough_group_start, fallthrough_typed_active, false);
    }

    for (unsigned i = 0; i < arm_count; i++) {
        gen_set_label(arms[i].taken);
        ia64_tr_note_fast_bundle(ctx);
        if (arms[i].ret) {
            g_assert(arms[i].indirect && !arms[i].call &&
                     arms[i].indirect_target != NULL &&
                     arms[i].return_pfs != NULL);
            ia64_tr_emit_typed_return_exit(
                ctx, arms[i].indirect_target, arms[i].return_pfs);
            continue;
        }
        if (arms[i].call) {
            /* Entering frame transition; only this taken arm may invoke it. */
            ia64_tr_emit_call_frame_transition(ctx);
        }
        if (arms[i].indirect) {
            ia64_tr_emit_typed_indirect_branch_exit(
                ctx, arms[i].indirect_target);
        } else {
            bool chain = (int)i == chained_direct_arm &&
                         translator_use_goto_tb(
                             &ctx->base, arms[i].direct_target);

            ia64_tr_emit_typed_direct_branch_exit(
                ctx, arms[i].direct_target, 0, chain, true, false, true);
        }
    }
}

static void ia64_tr_emit_inline_indirect_branch_exit(DisasContext *ctx,
                                                      TCGv_i64 target)
{
    TCGLabel *main_loop_exit = gen_new_label();

    ia64_tr_sync_state_cache(ctx);
    ia64_tr_store_source_visibility_state(ctx, true, false);
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
        &check.surrounding);
    if (needs_fallback) {
        fallback = gen_new_label();
        done = gen_new_label();
        ia64_tr_emit_fast_bundle_guards(ctx, &check.surrounding, fallback,
                                        ldst_address);
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
    ia64_tr_emit_gr_alat_invalidate(ctx, runtime_dest_mask,
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
    ia64_tr_emit_inline_direct_branch_exit(ctx, check.target_ip, 0, false,
                                           true);

    gen_set_label(fallthrough);
    for (int slot = check.slot + 1; slot < IA64_SLOT_COUNT; slot++) {
        ia64_tr_emit_fast_slot(ctx, &check.surrounding.slot[slot],
                               ldst_address[slot], runtime_dest_mask,
                               runtime_dest_mask_hi);
    }
    ctx->inline_gr_nat_clear = false;
    ia64_tr_emit_gr_alat_invalidate(ctx, runtime_dest_mask,
                                    runtime_dest_mask_hi, pc);
    ia64_tr_note_fast_bundle(ctx);

    if (needs_fallback) {
        tcg_gen_br(done);
        gen_set_label(fallback);
        ia64_tr_emit_exec_bundle_lookup_ptr(ctx, bundle, pc, 0);
        gen_set_label(done);
    }
    ctx->instruction_group_start = bundle->info->stop_after_slot[2];
    ctx->rewrite_region_selected = false;
    ctx->rewrite_region_decided = !ctx->instruction_group_start;
    ctx->rewrite_region_bundles_left = 0;
    ctx->rewrite_region_bundle_count = 0;
    ctx->rewrite_region_last_slot = IA64_SLOT_COUNT - 1;
    ctx->rewrite_region_ops_start = 0;
    ia64_tr_resume_state_cache(ctx, cache_suspended);
    return true;
}

static void ia64_tr_emit_direct_branch_exit(DisasContext *ctx,
                                            const IA64TcgDirectBranch *branch,
                                            uint64_t target,
                                            bool taken,
                                            int tb_slot,
                                            bool use_goto_tb,
                                            bool fallthrough_group_start)
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
                                               branch->prefix.finalize_mask),
                                           tcg_constant_i32(
                                               fallthrough_group_start));
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
    bool fallthrough_group_start;
    TCGLabel *region_label = NULL;

    if (ia64_tcg_fast_disabled(IA64_TCG_FAST_DISABLE_BRANCH)) {
        IA64_PERF_INC(IA64_PERF_TCG_BRANCH_DIRECT_FALLBACK);
        return IA64_TR_BRANCH_REJECT;
    }
    if (!ia64_tcg_build_direct_branch(bundle, pc, &branch)) {
        return IA64_TR_BRANCH_REJECT;
    }
    fallthrough_group_start = bundle->info->stop_after_slot[2];
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
                  branch.kind != IA64_TCG_DIRECT_BRANCH_CALL &&
                  branch.kind != IA64_TCG_DIRECT_BRANCH_INDIRECT_CALL;
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
                                    ldst_address);

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
        ia64_tr_emit_gr_alat_invalidate(ctx, runtime_dest_mask,
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
                    ctx, branch.fallthrough_ip, 1, false,
                    fallthrough_group_start);
            } else {
                ia64_tr_emit_inline_direct_branch_exit(
                    ctx, branch.target_ip, 0, false, true);
                gen_set_label(not_taken);
                tcg_gen_br(region_label);
            }
            ctx->base.pc_next = next_pc;
            ctx->region_branch_count++;
            ia64_tr_profile_add(ctx, IA64_PROFILE_BRANCH_REGION_FOLDED, 1);
            ctx->instruction_group_start = likely_taken ? true :
                fallthrough_group_start;
            ctx->rewrite_region_selected = false;
            ctx->rewrite_region_decided =
                !ctx->instruction_group_start;
            ctx->rewrite_region_bundles_left = 0;
            ctx->rewrite_region_bundle_count = 0;
            ctx->rewrite_region_last_slot = IA64_SLOT_COUNT - 1;
            ctx->rewrite_region_ops_start = 0;
            region_continue = true;
        }
    }

    if (!region_continue && zero_helper &&
        branch.kind == IA64_TCG_DIRECT_BRANCH_INDIRECT) {
        indirect_target = tcg_temp_new_i64();
        ia64_tr_load_br(ctx, indirect_target, branch.target_branch_reg);
        tcg_gen_andi_i64(indirect_target, indirect_target, ~UINT64_C(0xf));
        ia64_tr_emit_inline_indirect_branch_exit(ctx, indirect_target);
    } else if (!region_continue && zero_helper) {
        ia64_tr_emit_inline_direct_branch_exit(
            ctx, branch.target_ip, 0,
            translator_use_goto_tb(&ctx->base, branch.target_ip), true);
    } else if (!region_continue) {
        ia64_tr_emit_direct_branch_exit(
            ctx, &branch, branch.target_ip, true, 0,
            translator_use_goto_tb(&ctx->base, branch.target_ip),
            fallthrough_group_start);
    }
    if (!region_continue && branch.conditional) {
        gen_set_label(not_taken);
        if (zero_helper) {
            ia64_tr_emit_inline_direct_branch_exit(
                ctx, branch.fallthrough_ip, 1,
                translator_use_goto_tb(&ctx->base,
                                       branch.fallthrough_ip),
                fallthrough_group_start);
        } else {
            ia64_tr_emit_direct_branch_exit(
                ctx, &branch, branch.fallthrough_ip, false, 1,
                translator_use_goto_tb(&ctx->base,
                                       branch.fallthrough_ip),
                fallthrough_group_start);
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
            ctx, bundle, pc, 0, &dirty_before);
    } else {
        ia64_tr_emit_exec_bundle_lookup_ptr(ctx, bundle, pc, 0);
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
    uint8_t start_slot;

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
    start_slot = pc == ctx->base.pc_first ?
                 ia64_tcg_tb_flags_ri(ctx->base.tb->flags) : 0;
    if (start_slot >= IA64_SLOT_COUNT) {
        start_slot = 0;
    }
    boundary = ia64_tcg_tb_boundary_for_bundle_from_slot_with_physical(
        &bundle, pc, dispatch_ip, dispatch_ip_is_physical, start_slot);

    /*
     * Typed ownership is resolved before the legacy boundary classifiers.
     * A carried epoch may close at an internal stop in a branch/special
     * bundle; in that case only the fresh suffix is handed to the generic
     * engine below, in this same translator callback.
     */
    if (!ctx->rewrite_region_decided) {
        unsigned bundle_count = 0;
        uint8_t last_slot = IA64_SLOT_COUNT - 1;

        ctx->rewrite_region_selected = ia64_tr_preflight_rewrite_region(
            ctx, &bundle, pc, start_slot, boundary, &bundle_count,
            &last_slot);
        if (!ctx->rewrite_region_selected && ctx->typed_group_active) {
            ia64_tr_fail_typed_continuation(
                pc, "unsupported suffix bundle");
        }
        ctx->rewrite_region_bundles_left =
            ctx->rewrite_region_selected ? bundle_count : 0;
        ctx->rewrite_region_bundle_count =
            ctx->rewrite_region_selected ? bundle_count : 0;
        ctx->rewrite_region_last_slot =
            ctx->rewrite_region_selected ? last_slot :
                                            IA64_SLOT_COUNT - 1;
        ctx->rewrite_region_ops_start =
            ctx->rewrite_region_selected ? tcg_ctx->nb_ops : 0;
        ctx->rewrite_region_decided = true;
        if (ctx->rewrite_region_selected) {
            ia64_tr_group_reserve(ctx, bundle_count * IA64_SLOT_COUNT);
        }
    }
    if (ctx->rewrite_region_selected) {
        uint8_t last_slot = ctx->rewrite_region_bundles_left == 1 ?
                            ctx->rewrite_region_last_slot :
                            IA64_SLOT_COUNT - 1;
        bool translated = ia64_tr_try_decoded_bundle(
            ctx, &bundle, pc, start_slot, last_slot);

        g_assert(translated);
        /*
         * The reusable scratch bank has a group-length-independent temp
         * bound, but emitted operations still scale across this deliberate
         * TB segment.  Check the reserved segment total; an open epoch is
         * suspended and resumed rather than redirected to the legacy path.
         */
        g_assert(tcg_ctx->nb_ops - ctx->rewrite_region_ops_start <
                 ctx->rewrite_region_bundle_count *
                 IA64_TR_REWRITE_OPS_PER_BUNDLE);
        g_assert(ctx->rewrite_region_bundles_left > 0);
        ctx->rewrite_region_bundles_left--;
        if (ctx->rewrite_region_bundles_left == 0) {
            g_assert(ctx->rewrite_plan_index ==
                     ctx->rewrite_plan_emit_count);
            ia64_tr_rewrite_plan_reset(ctx);
        }

        if (ctx->rewrite_control_flow_exit) {
            g_assert(ctx->rewrite_region_bundles_left == 0);
            g_assert(ia64_tr_group_is_empty(ctx));
            g_assert(ctx->base.is_jmp == DISAS_NORETURN);
            ctx->rewrite_region_selected = false;
            ctx->rewrite_region_bundle_count = 0;
            ctx->rewrite_region_last_slot = IA64_SLOT_COUNT - 1;
            ctx->rewrite_region_ops_start = 0;
            return;
        }

        if (last_slot < IA64_SLOT_COUNT - 1) {
            uint8_t suffix_slot = last_slot + 1;

            g_assert(ctx->instruction_group_start);
            g_assert(!ctx->typed_group_active);
            g_assert(ctx->rewrite_region_bundles_left == 0);
            g_assert(ia64_tr_group_is_empty(ctx));
            ctx->rewrite_region_selected = false;
            ctx->rewrite_region_bundles_left = 0;
            ctx->rewrite_region_bundle_count = 0;
            ctx->rewrite_region_last_slot = IA64_SLOT_COUNT - 1;
            ctx->rewrite_region_ops_start = 0;

            if (ia64_tr_translate_execution_epoch_prefix(
                    ctx, &bundle, pc, suffix_slot)) {
                ia64_tr_profile_add(ctx, IA64_PROFILE_BUNDLE_PARTIAL, 1);
                trace_ia64_tcg_tb_boundary(
                    pc, ia64_tcg_tb_boundary_name(boundary));
                IA64_PERF_INC(IA64_PERF_TB_EXIT_FLOW_TRANSLATED);
                ctx->base.is_jmp = DISAS_EXIT;
                return;
            }

            ia64_tr_profile_add(ctx, IA64_PROFILE_BUNDLE_FULL_HELPER, 1);
            if (boundary == IA64_TCG_TB_BOUNDARY_BRANCH) {
                ia64_tr_profile_note_branch_reject(ctx, &bundle, pc);
                ia64_tr_count_branch_fallback(&bundle);
            }
            if (ia64_tcg_tb_boundary_ends_tb(boundary)) {
                trace_ia64_tcg_tb_boundary(
                    pc, ia64_tcg_tb_boundary_name(boundary));
                IA64_PERF_INC(IA64_PERF_TB_EXIT_FLOW_TRANSLATED);
                ia64_tr_emit_exec_bundle_lookup_ptr_suffix(
                    ctx, &bundle, pc, suffix_slot);
                ctx->base.is_jmp = DISAS_NORETURN;
                return;
            }

            ia64_tr_profile_note_unsupported_slots(ctx, &bundle, pc);
            if (ia64_tcg_bundle_has_ldst_immediate(&bundle)) {
                IA64_PERF_INC(IA64_PERF_TCG_LDST_FALLBACK);
            }
            ia64_tr_emit_exec_bundle_suffix(
                ctx, &bundle, pc, suffix_slot);
            ctx->instruction_group_start =
                bundle.info->stop_after_slot[IA64_SLOT_COUNT - 1];
            ctx->rewrite_region_decided = !ctx->instruction_group_start;
            if (ctx->instruction_group_start &&
                ia64_tr_should_end_before_next_typed_group()) {
                ctx->base.is_jmp = DISAS_TOO_MANY;
            }
            return;
        }

        if (ctx->instruction_group_start) {
            g_assert(ctx->rewrite_region_bundles_left == 0);
            g_assert(ia64_tr_group_is_empty(ctx));
            ctx->rewrite_region_decided = false;
            ctx->rewrite_region_selected = false;
            ctx->rewrite_region_bundle_count = 0;
            ctx->rewrite_region_last_slot = IA64_SLOT_COUNT - 1;
            ctx->rewrite_region_ops_start = 0;
            if (ia64_tr_should_end_before_next_typed_group()) {
                ctx->base.is_jmp = DISAS_TOO_MANY;
            }
        } else if (ctx->rewrite_region_bundles_left == 0) {
            ia64_tr_group_suspend_for_typed_continuation(ctx);
            ctx->rewrite_region_selected = false;
            ctx->rewrite_region_bundle_count = 0;
            ctx->rewrite_region_last_slot = IA64_SLOT_COUNT - 1;
            ctx->rewrite_region_ops_start = 0;
            ctx->base.is_jmp = DISAS_TOO_MANY;
        } else {
            g_assert(!tcg_op_buf_full());
        }
        return;
    }
    if (ctx->typed_group_active) {
        ia64_tr_fail_typed_continuation(
            pc, ia64_tcg_tb_boundary_name(boundary));
    }

    if (boundary == IA64_TCG_TB_BOUNDARY_EFI_CALL_GATE) {
        ia64_tr_profile_add(ctx, IA64_PROFILE_BUNDLE_HELPER_FAST, 1);
        /* Firmware gates are atomic bundle services and return at RI=0. */
        ia64_tr_emit_firmware_call_gate(ctx, pc, dispatch_ip, 0);
        trace_ia64_tcg_tb_boundary(pc, ia64_tcg_tb_boundary_name(boundary));
        IA64_PERF_INC(IA64_PERF_TB_EXIT_FLOW_TRANSLATED);
        ctx->base.is_jmp = DISAS_EXIT;
        return;
    }
    if (ia64_tr_translate_execution_epoch_prefix(
            ctx, &bundle, pc, start_slot)) {
        ia64_tr_profile_add(ctx, IA64_PROFILE_BUNDLE_PARTIAL, 1);
        trace_ia64_tcg_tb_boundary(
            pc, ia64_tcg_tb_boundary_name(boundary));
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
        ia64_tr_emit_exec_bundle_lookup_ptr(ctx, &bundle, pc, start_slot);
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
        ia64_tr_emit_exec_bundle(ctx, &bundle, pc, start_slot);
    }
    if (!ia64_tcg_tb_boundary_ends_tb(boundary)) {
        ctx->instruction_group_start = bundle.info->stop_after_slot[2];
        if (ctx->instruction_group_start) {
            ctx->rewrite_region_decided = false;
            ctx->rewrite_region_selected = false;
            ctx->rewrite_region_bundles_left = 0;
            ctx->rewrite_region_bundle_count = 0;
            ctx->rewrite_region_last_slot = IA64_SLOT_COUNT - 1;
            ctx->rewrite_region_ops_start = 0;
            if (ia64_tr_should_end_before_next_typed_group()) {
                ctx->base.is_jmp = DISAS_TOO_MANY;
            }
        }
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

    g_assert(!ctx->rewrite_region_selected);
    g_assert(ctx->rewrite_region_bundles_left == 0);
    g_assert(ctx->rewrite_region_bundle_count == 0);
    g_assert(ctx->rewrite_region_last_slot == IA64_SLOT_COUNT - 1);
    g_assert(ctx->rewrite_region_ops_start == 0);
    g_assert(ctx->rewrite_plan_count == 0);
    g_assert(ctx->rewrite_plan_emit_count == 0);
    g_assert(ctx->rewrite_plan_index == 0);
    g_assert(ia64_tr_group_is_empty(ctx));

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
    g_free(ctx.rewrite_group.instruction);
    g_free(ctx.rewrite_plan);
}
