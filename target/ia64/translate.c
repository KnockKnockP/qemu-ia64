/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "qemu/cutils.h"
#include "qemu/error-report.h"
#include "cpu.h"
#include "bundle.h"
#include "decode.h"
#include "exception.h"
#include "firmware.h"
#include "insn.h"
#include "exec/helper-proto.h"
#include "exec/helper-gen.h"
#include "exec/memop.h"
#include "exec/target_page.h"
#include "exec/translation-block.h"
#include "exec/translator.h"
#include "hw/core/cpu.h"
#include "mem.h"
#include "opcode-traits.h"
#include "perf.h"
#include "system-plane.h"
#include "tcg/tcg-op.h"
#include "trace-target_ia64.h"

#define HELPER_H "helper.h"
#include "exec/helper-info.c.inc"
#undef HELPER_H

typedef struct IA64ProfileTbShape {
    uint32_t counter[IA64_PROFILE_COUNTER_COUNT];
    uint32_t group_length[IA64_PROFILE_GROUP_HIST_COUNT];
    uint32_t group_destination[IA64_PROFILE_GROUP_HIST_COUNT];
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
    uint64_t direct_target;
    IA64Opcode opcode;
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
    bool zero_store_candidate;
} IA64TrInstructionPlan;

typedef struct IA64TrDecodedBranchArm {
    TCGLabel *taken;
    TCGv_i64 indirect_target;
    TCGv_i64 return_pfs;
    uint64_t direct_target;
    uint64_t source_ip;
    uint64_t source_raw;
    uint8_t source_slot;
    uint8_t source_type;
    IA64Opcode opcode;
    bool indirect;
    bool call;
    bool ret;
    bool taken_trap;
} IA64TrDecodedBranchArm;

typedef struct IA64TrInstructionTransaction {
    IA64TrGrWrite gr[IA64_TR_GR_WRITES_PER_INSN];
    IA64TrPrWrite pr[IA64_TR_PR_WRITES_PER_INSN];
    IA64TrBrWrite br[IA64_TR_BR_WRITES_PER_INSN];
    IA64TrPrImageWrite pr_image;
    TCGv_i64 pre_psr;
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
    uint8_t post_alat_target;
    uint8_t post_alat_width;
    uint8_t post_alat_target_type;
    uint8_t post_alat_memory_class;
    TCGv_i64 post_alat_address;
    TCGv_i64 post_alat_record;
    bool post_alat_active;
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
    TCGv_i64 pre_psr;
    TCGv_i64 post_alat_address;
    TCGv_i64 post_alat_record;
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
    TCGv_i32 retired_bundle_count;
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
    bool retired_bundle_count_used;
    bool state_cache_available;
    bool state_cache_active;
    bool pr_valid;
    bool pr_dirty;
    bool gr_nat_valid;
    bool gr_nat_dirty;
    bool profile_enabled;
    bool instruction_group_start;
    bool typed_group_active;
    bool cfle_resume;
    bool rewrite_region_decided;
    bool typed_segment_active;
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
    bool alat_may_active;
    uint32_t perf_tb_id;
    IA64ProfileTbEnd profile_end_reason;
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
#define IA64_TR_PSR_I_BIT UINT64_C(0x0000000000004000)
#define IA64_TR_PSR_AC_BIT UINT64_C(0x0000000000000008)
#define IA64_TR_PSR_ED_BIT UINT64_C(0x0000080000000000)
#define IA64_TR_PSR_FAULT_SUPPRESSION_MASK \
    UINT64_C(0x000020e000000000)
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

static bool ia64_tr_group_is_empty(const DisasContext *ctx);
static IA64SlotType ia64_tr_decoded_slot_type(IA64InstructionUnit unit);
static bool ia64_tr_decoded_instruction_supported(
    const IA64Instruction *insn);
static void ia64_tr_clear_restart_ri(void);
static void ia64_tr_publish_fault_state(uint64_t pc, uint8_t slot_index,
                                        uint8_t slot_type, uint64_t raw,
                                        bool group_start);
static void ia64_tr_emit_application_target_check(
    DisasContext *ctx, const IA64Instruction *insn);
static bool ia64_tr_emit_decoded_branch_split(
    DisasContext *ctx, const IA64Instruction *insn,
    IA64TrDecodedBranchArm *arm);
static void ia64_tr_emit_decoded_fchkf_split(
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
static void ia64_tr_emit_decoded_rfi(DisasContext *ctx,
                                     const IA64Instruction *insn);
static void ia64_tr_split_state_cache_at_typed_branch(DisasContext *ctx);
static void ia64_tr_system_validate(DisasContext *ctx,
                                    const IA64Instruction *insn);
static void ia64_tr_emit_decoded_branch_cfg_exits(
    DisasContext *ctx, IA64TrDecodedBranchArm arms[IA64_SLOT_COUNT],
    unsigned arm_count, bool has_fallthrough, uint64_t fallthrough_target,
    bool fallthrough_group_start, bool fallthrough_typed_active,
    bool suppress_direct_chaining);

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
        ctx->base.pc_first, ctx->base.tb->flags,
        shape->counter, shape->group_length, shape->group_destination,
        ia64_tr_profile_dirty_count(ctx), exit, ctx->profile_end_reason);
    ia64_tr_profile_add_runtime_counter(
        IA64_CPU_OFFSET(production_profile.shape_exec[shape_slot]), 1);
    if (ia64_profile_sample_shift() != 0) {
        tcg_gen_st8_i32(
            tcg_constant_i32(0), tcg_env,
            IA64_CPU_OFFSET(production_profile.collecting));
        tcg_gen_exit_tb(NULL, 0);
    }
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

static bool ia64_tr_debug_fast_guard_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        const char *value = g_getenv("VIBTANIUM_TCG_DEBUG_FAST_GUARD");

        enabled = value == NULL ||
                  !(strcmp(value, "0") == 0 ||
                    g_ascii_strcasecmp(value, "off") == 0 ||
                    g_ascii_strcasecmp(value, "false") == 0);
    }
    return enabled;
}

static bool ia64_tr_retire_fast_guard_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        const char *value = g_getenv("VIBTANIUM_TCG_RETIRE_FAST_GUARD");

        enabled = value == NULL ||
                  !(strcmp(value, "0") == 0 ||
                    g_ascii_strcasecmp(value, "off") == 0 ||
                    g_ascii_strcasecmp(value, "false") == 0);
    }
    return enabled;
}

static bool ia64_tr_psr_finish_specialization_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        const char *value =
            g_getenv("VIBTANIUM_TCG_PSR_FINISH_SPECIALIZATION");

        enabled = value == NULL ||
                  !(strcmp(value, "0") == 0 ||
                    g_ascii_strcasecmp(value, "off") == 0 ||
                    g_ascii_strcasecmp(value, "false") == 0);
    }
    return enabled;
}

static bool ia64_tr_alat_empty_specialization_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        const char *value =
            g_getenv("VIBTANIUM_TCG_ALAT_EMPTY_SPECIALIZATION");

        enabled = value == NULL ||
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
    ctx->retired_bundle_count = NULL;
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
    ctx->retired_bundle_count_used = false;
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
    ctx->cfle_resume =
        (ctx->base.tb->flags & IA64_TB_FLAG_CFLE_RESUME) != 0;
    /* Every production TB is admitted and lowered by the typed engine. */
    ctx->rewrite_region_decided = false;
    ctx->typed_segment_active = false;
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
    ctx->alat_may_active =
        !ia64_tr_alat_empty_specialization_enabled() ||
        (ctx->base.tb->flags & IA64_TB_FLAG_ALAT_ACTIVE) != 0;
    ctx->perf_tb_id = ia64_perf_enabled() ? ia64_perf_register_tb() : 0;
    ctx->profile_end_reason = IA64_PROFILE_TB_END_OTHER;
    memset(&ctx->profile_shape, 0, sizeof(ctx->profile_shape));
    if (ctx->profile_enabled) {
        ctx->profile_shape.counter[
            (ctx->base.tb->flags & IA64_TB_FLAG_ALAT_ACTIVE) != 0 ?
                IA64_PROFILE_ALAT_ACTIVE_TB : IA64_PROFILE_ALAT_EMPTY_TB]++;
    }

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

    ctx->retired_bundle_count = tcg_temp_new_i32();
    tcg_gen_movi_i32(ctx->retired_bundle_count, 0);
    ctx->state_cache_available = ia64_tr_state_cache_enabled();
    ctx->state_cache_active = false;
    if (ia64_perf_enabled()) {
        gen_helper_perf_tb_exec(tcg_constant_i32(ctx->perf_tb_id));
    }
}

static void ia64_tr_note_retired_bundle(DisasContext *ctx)
{
    ctx->retired_bundle_count_used = true;
    tcg_gen_addi_i32(ctx->retired_bundle_count,
                     ctx->retired_bundle_count, 1);
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
        ia64_tr_profile_add(ctx, IA64_PROFILE_RESIDENT_LOAD, 1);
        ia64_tr_profile_add(ctx, IA64_PROFILE_ARCH_LOAD, 1);
    } else {
        ia64_tr_profile_add(ctx, IA64_PROFILE_STATE_CACHE_HIT, 1);
        ia64_tr_profile_add(ctx, IA64_PROFILE_RESIDENT_HIT, 1);
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
        ia64_tr_profile_add(ctx, IA64_PROFILE_RESIDENT_LOAD, 1);
        ia64_tr_profile_add(ctx, IA64_PROFILE_ARCH_LOAD, 1);
    } else {
        ia64_tr_profile_add(ctx, IA64_PROFILE_STATE_CACHE_HIT, 1);
        ia64_tr_profile_add(ctx, IA64_PROFILE_RESIDENT_HIT, 1);
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
        ia64_tr_profile_add(ctx, IA64_PROFILE_RESIDENT_LOAD, 1);
        ia64_tr_profile_add(ctx, IA64_PROFILE_ARCH_LOAD, 1);
    } else {
        ia64_tr_profile_add(ctx, IA64_PROFILE_STATE_CACHE_HIT, 1);
        ia64_tr_profile_add(ctx, IA64_PROFILE_RESIDENT_HIT, 1);
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
        ia64_tr_profile_add(ctx, IA64_PROFILE_RESIDENT_LOAD, 1);
        ia64_tr_profile_add(ctx, IA64_PROFILE_ARCH_LOAD, 1);
    } else {
        ia64_tr_profile_add(ctx, IA64_PROFILE_STATE_CACHE_HIT, 1);
        ia64_tr_profile_add(ctx, IA64_PROFILE_RESIDENT_HIT, 1);
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
        ia64_tr_profile_add(ctx, IA64_PROFILE_RESIDENT_LOAD, 1);
        ia64_tr_profile_add(ctx, IA64_PROFILE_ARCH_LOAD, 1);
    } else {
        ia64_tr_profile_add(ctx, IA64_PROFILE_STATE_CACHE_HIT, 1);
        ia64_tr_profile_add(ctx, IA64_PROFILE_RESIDENT_HIT, 1);
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
    uint32_t writebacks;

    ia64_tr_capture_state_cache_dirty(ctx, &dirty);
    writebacks = ctpop32(dirty.static_gr) + ctpop32(dirty.br) +
                 ctpop64(dirty.ar[0]) + ctpop64(dirty.ar[1]) +
                 dirty.pr + dirty.gr_nat;
    ia64_tr_profile_add(ctx, IA64_PROFILE_RESIDENT_SYNC, 1);
    ia64_tr_profile_add(ctx, IA64_PROFILE_RESIDENT_WRITEBACK, writebacks);
    ia64_tr_profile_add(ctx, IA64_PROFILE_STATE_CACHE_DIRTY_WRITEBACK,
                        writebacks);
    ia64_tr_profile_add(ctx, IA64_PROFILE_ARCH_STORE, writebacks);
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
    uint32_t valid = ctpop32(ctx->static_gr_valid) +
                     ctpop32(ctx->br_valid) +
                     ctpop64(ctx->ar_valid[0]) +
                     ctpop64(ctx->ar_valid[1]) +
                     ctx->pr_valid + ctx->gr_nat_valid;

    ia64_tr_profile_add(ctx, IA64_PROFILE_RESIDENT_SPILL, valid);
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

static void ia64_tr_flush_retired_bundles(DisasContext *ctx)
{
    TCGLabel *retire_only;
    TCGLabel *done;
    TCGv_i32 pending;
    TCGv_i64 psr;

    if (!ctx->retired_bundle_count_used) {
        return;
    }

    if (!ia64_tr_retire_fast_guard_enabled()) {
        gen_helper_retire_translated_bundles(tcg_env,
                                             ctx->retired_bundle_count);
        tcg_gen_movi_i32(ctx->retired_bundle_count, 0);
        return;
    }

    /*
     * retire_translated_bundles() can leave the TB only for an enabled
     * external interrupt.  Its own first two requirements are the target's
     * cached pending bit and PSR.i.  Keep the full helper as the authority for
     * vector/TPR selection, but avoid a host helper call at every ordinary TB
     * boundary when either cheap prerequisite is false.
     *
     * The benchmark TB flag is the translation-time equivalent of
     * ia64_benchmark_retire()'s runtime active test.  On the bypass arm we
     * therefore account inline; on the slow arm the unchanged helper accounts
     * exactly once.
     */
    retire_only = gen_new_label();
    done = gen_new_label();
    pending = tcg_temp_new_i32();
    psr = tcg_temp_new_i64();

    tcg_gen_ld8u_i32(pending, tcg_env,
                     offsetof(CPUIA64State, interrupt.pending));
    tcg_gen_brcondi_i32(TCG_COND_EQ, pending, 0, retire_only);
    tcg_gen_ld_i64(psr, tcg_env, offsetof(CPUIA64State, psr));
    tcg_gen_brcondi_i64(TCG_COND_TSTEQ, psr, IA64_TR_PSR_I_BIT,
                        retire_only);
    gen_helper_retire_translated_bundles(tcg_env,
                                         ctx->retired_bundle_count);
    tcg_gen_br(done);

    gen_set_label(retire_only);
    if ((ctx->base.tb->flags & IA64_TB_FLAG_BENCHMARK) != 0) {
        ia64_tr_emit_benchmark_retire(ctx->retired_bundle_count);
    }
    gen_set_label(done);
    tcg_gen_movi_i32(ctx->retired_bundle_count, 0);
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
static void ia64_tr_retire_bundles_deferred_interrupt(
    DisasContext *ctx)
{
    if (!ctx->retired_bundle_count_used) {
        return;
    }

    if ((ctx->base.tb->flags & IA64_TB_FLAG_BENCHMARK) != 0) {
        ia64_tr_emit_benchmark_retire(ctx->retired_bundle_count);
    }
    tcg_gen_movi_i32(ctx->retired_bundle_count, 0);
}

static void ia64_tr_commit_ip(uint64_t ip)
{
    tcg_gen_movi_i64(cpu_ip, ip);
    /*
     * A returning fault-capable helper publishes the executing slot through
     * env->ri.  Committing the next bundle must also canonicalize PSR.ri:
     * merely dropping ri_dirty can expose an older PSR slot at the next TB
     * boundary and restart the sequential bundle in slot 1 or 2.
     */
    ia64_tr_clear_restart_ri();
}

static void ia64_tr_commit_ip_value(TCGv_i64 ip)
{
    tcg_gen_mov_i64(cpu_ip, ip);
    ia64_tr_clear_restart_ri();
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
        tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                        offsetof(CPUIA64State,
                                 issue_group.saved_ar_count));
        tcg_gen_st_i64(tcg_constant_i64(0), tcg_env,
                       offsetof(CPUIA64State,
                                issue_group.saved_fr_mask));
        tcg_gen_st_i64(tcg_constant_i64(0), tcg_env,
                       offsetof(CPUIA64State,
                                issue_group.saved_fr_mask) +
                       sizeof(uint64_t));
        ia64_tr_profile_add(ctx, IA64_PROFILE_OVERLAY_CLEAR, 11);
        ia64_tr_profile_add(ctx, IA64_PROFILE_ARCH_STORE, 11);
    }
    tcg_gen_st8_i32(tcg_constant_i32(typed_active), tcg_env,
                    offsetof(CPUIA64State, issue_group.typed_active));
    tcg_gen_st8_i32(tcg_constant_i32(group_start), tcg_env,
                    offsetof(CPUIA64State, instruction_group_start));
    tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                    offsetof(CPUIA64State, instruction_group_dirty));
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

/*
 * An invalid template has no typed instruction descriptor.  Attribute the
 * Illegal Operation fault to the requested restart slot without invoking a
 * secondary raw decoder or any bundle-dispatch helper.
 */
static void ia64_tr_emit_invalid_template(DisasContext *ctx,
                                          const IA64DecodedBundle *bundle,
                                          uint64_t pc, uint8_t start_slot)
{
    g_assert(bundle != NULL && !bundle->valid);
    g_assert(start_slot < IA64_SLOT_COUNT);
    g_assert(ia64_tr_group_is_empty(ctx));

    ia64_tr_sync_state_cache(ctx);
    tcg_gen_movi_i64(cpu_ip, pc);
    ia64_tr_publish_fault_state(pc, start_slot, IA64_SLOT_TYPE_INVALID,
                                bundle->slot[start_slot],
                                ctx->instruction_group_start);
    gen_helper_raise_illegal_operation(tcg_env);
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
        return;
    }

    tcg_gen_st_i64(value, tcg_env, ia64_tr_static_gr_offset(ctx, reg));
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

static MemOp ia64_tr_ldst_memop(DisasContext *ctx, uint8_t width)
{
    MemOp memop;

    /* IA-64 permits unaligned data access; the interpreter path assembles
       unaligned values bytewise, which matches unaligned SoftMMU ops. */
    switch (width) {
    case 1:
        memop = MO_UB;
        break;
    case 2:
        memop = MO_UW;
        break;
    case 4:
        memop = MO_UL;
        break;
    case 8:
        memop = MO_UQ;
        break;
    default:
        g_assert_not_reached();
    }
    return memop | ((ctx->base.tb->flags & IA64_TB_FLAG_BE) != 0 ?
                    MO_BE : MO_LE);
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
    tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                    offsetof(CPUIA64State, current_slot_speculative_load));
    tcg_gen_st_i64(tcg_constant_i64(pc), tcg_env,
                   offsetof(CPUIA64State, current_slot_ip));
    tcg_gen_st_i64(tcg_constant_i64(raw), tcg_env,
                   offsetof(CPUIA64State, current_slot_raw));
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
    if (reg == IA64_AR_UNAT) {
        tcg_gen_ld_i64(value, tcg_env,
                       offsetof(CPUIA64State, nat.unat));
        return;
    }
    if (ctx->state_cache_active) {
        tcg_gen_mov_i64(value, ia64_tr_ensure_ar(ctx, reg));
    } else {
        tcg_gen_ld_i64(value, tcg_env,
                       offsetof(CPUIA64State, ar) +
                       reg * sizeof(uint64_t));
    }
}

static void ia64_tr_group_load_ordinary_ar(DisasContext *ctx,
                                           TCGv_i64 value, uint8_t reg)
{
    IA64TrInstructionTransaction *instruction =
        ctx->rewrite_group.current;

    g_assert(ctx->rewrite_group.active && instruction != NULL &&
             (instruction->source_ar[reg >> 6] &
              (UINT64_C(1) << (reg & 63))) != 0);
    ia64_tr_load_ar(ctx, value, reg);
    gen_helper_data_plane_ar_select(
        value, tcg_env, tcg_constant_i32(reg), value);
}

static void ia64_tr_store_ar(DisasContext *ctx, uint8_t reg, TCGv_i64 value)
{
    if (ctx->rewrite_group.active &&
        ctx->rewrite_group.current != NULL) {
        TCGv_i64 entry_value = ia64_tr_scratch_i64(ctx);

        ia64_tr_load_ar(ctx, entry_value, reg);
        gen_helper_data_plane_ar_preserve(
            tcg_env, tcg_constant_i32(reg), entry_value);
    }
    if (reg == IA64_AR_UNAT) {
        /* nat.unat is architectural authority; ar[UNAT] is a compatibility
           mirror used by legacy inspection paths. */
        tcg_gen_st_i64(value, tcg_env,
                       offsetof(CPUIA64State, nat.unat));
    }
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

static void ia64_tr_finish_predicate_guard(TCGLabel *skip)
{
    if (skip != NULL) {
        gen_set_label(skip);
    }
}

static void ia64_tr_emit_gr_alat_invalidate(DisasContext *ctx,
                                            TCGv_i64 dest_mask,
                                            TCGv_i64 dest_mask_hi,
                                            uint64_t pc)
{
    TCGLabel *done;
    TCGLabel *nonzero;
    TCGv_i32 valid;

    if (!ctx->alat_may_active) {
        return;
    }
    done = gen_new_label();
    nonzero = gen_new_label();
    valid = ia64_tr_scratch_i32(ctx);

    tcg_gen_brcondi_i64(TCG_COND_NE, dest_mask, 0, nonzero);
    tcg_gen_brcondi_i64(TCG_COND_EQ, dest_mask_hi, 0, done);
    gen_set_label(nonzero);
    tcg_gen_ld_i32(valid, tcg_env,
                   offsetof(CPUIA64State, alat.valid_mask));
    tcg_gen_brcondi_i32(TCG_COND_EQ, valid, 0, done);
    ia64_tr_commit_ip(pc);
    gen_helper_gr_alat_invalidate_mask(tcg_env, dest_mask, dest_mask_hi);
    gen_set_label(done);
}

static void ia64_tr_group_reserve(DisasContext *ctx,
                                  unsigned instruction_capacity)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;
    uint64_t started_ns;

    g_assert(!group->active && group->current == NULL);
    g_assert(instruction_capacity <= UINT16_MAX);
    if (instruction_capacity <= group->instruction_capacity) {
        return;
    }
    started_ns = ia64_perf_clock_ns();
    group->instruction = g_renew(IA64TrInstructionTransaction,
                                 group->instruction,
                                 instruction_capacity);
    IA64_PERF_INC(IA64_PERF_PLAN_ALLOCATION);
    IA64_PERF_ADD(IA64_PERF_PLAN_ALLOCATION_BYTES,
                  instruction_capacity *
                  sizeof(IA64TrInstructionTransaction));
    IA64_PERF_ADD(IA64_PERF_PLAN_ALLOC_HOST_NS,
                  ia64_perf_clock_ns() - started_ns);
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
        ia64_tr_profile_add(ctx, IA64_PROFILE_NAT_KNOWN_CLEAR, 1);
        return;
    }
    ia64_tr_profile_add(ctx, IA64_PROFILE_NAT_UNKNOWN, 1);
    ia64_tr_profile_add(ctx, IA64_PROFILE_NAT_DYNAMIC_LOAD, 1);
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
        ia64_tr_profile_add(ctx, IA64_PROFILE_ARCH_LOAD, 2);
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
    ia64_tr_profile_add(ctx, IA64_PROFILE_ARCH_LOAD, 3);
    ia64_tr_profile_add(ctx, IA64_PROFILE_OVERLAY_VALIDITY_LOAD, 1);
    ia64_tr_profile_add(ctx, IA64_PROFILE_OVERLAY_VALIDITY_BRANCH, 1);
    ia64_tr_profile_add(ctx, IA64_PROFILE_NAT_DYNAMIC_BRANCH, 1);
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
        ia64_tr_profile_add(ctx, IA64_PROFILE_ARCH_LOAD, 1);
    } else {
        TCGv_i64 live = ia64_tr_scratch_i64(ctx);
        TCGv_i64 saved = ia64_tr_scratch_i64(ctx);
        TCGv_i64 saved_valid = ia64_tr_scratch_i64(ctx);

        ia64_tr_load_ar(ctx, live, IA64_AR_PFS);
        tcg_gen_ld_i64(saved, tcg_env,
                       offsetof(CPUIA64State, issue_group.saved_pfs));
        tcg_gen_ld8u_i64(saved_valid, tcg_env,
                         offsetof(CPUIA64State, issue_group.pfs_saved));
        ia64_tr_profile_add(ctx, IA64_PROFILE_ARCH_LOAD, 2);
        ia64_tr_profile_add(ctx, IA64_PROFILE_OVERLAY_VALIDITY_LOAD, 1);
        ia64_tr_profile_add(ctx, IA64_PROFILE_OVERLAY_VALIDITY_BRANCH, 1);
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
            ia64_tr_profile_add(ctx, IA64_PROFILE_ARCH_LOAD, 1);
            ia64_tr_profile_add(ctx, IA64_PROFILE_OVERLAY_VALIDITY_LOAD, 1);
            ia64_tr_profile_add(ctx, IA64_PROFILE_OVERLAY_VALIDITY_BRANCH, 1);
        }
        {
            TCGv_i64 old_pfs = ia64_tr_scratch_i64(ctx);

            ia64_tr_load_ar(ctx, old_pfs, IA64_AR_PFS);
            tcg_gen_st_i64(old_pfs, tcg_env,
                           offsetof(CPUIA64State, issue_group.saved_pfs));
            tcg_gen_st8_i32(
                tcg_constant_i32(1), tcg_env,
                offsetof(CPUIA64State, issue_group.pfs_saved));
            ia64_tr_profile_add(ctx, IA64_PROFILE_OVERLAY_SAVE_PFS, 1);
            ia64_tr_profile_add(ctx, IA64_PROFILE_ARCH_STORE, 2);
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
        ia64_tr_profile_add(ctx, IA64_PROFILE_ARCH_LOAD, 1);
        ia64_tr_profile_add(ctx, IA64_PROFILE_OVERLAY_VALIDITY_LOAD, 1);
        if ((may_saved & bit) != 0) {
            saved = gen_new_label();
            tcg_gen_brcondi_i64(TCG_COND_TSTNE, mask, bit, saved);
            ia64_tr_profile_add(ctx,
                                IA64_PROFILE_OVERLAY_VALIDITY_BRANCH, 1);
        }
    }
    ia64_tr_load_static_gr_ref_pair(ctx, live, nat, ref);
    tcg_gen_st_i64(live, tcg_env, ia64_tr_group_saved_gr_offset(reg));
    tcg_gen_st_i64(nat, tcg_env, ia64_tr_group_saved_nat_offset(reg));
    ia64_tr_profile_add(ctx, IA64_PROFILE_OVERLAY_SAVE_GR, 1);
    ia64_tr_profile_add(ctx, IA64_PROFILE_OVERLAY_SAVE_NAT, 1);
    ia64_tr_profile_add(ctx, IA64_PROFILE_ARCH_STORE, 3);
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
        ia64_tr_profile_add(ctx, IA64_PROFILE_ARCH_LOAD, 1);
        ia64_tr_profile_add(ctx, IA64_PROFILE_OVERLAY_VALIDITY_LOAD, 1);
        if ((group->br_may_saved & bit) != 0) {
            saved = gen_new_label();
            tcg_gen_brcondi_i64(TCG_COND_TSTNE, mask, bit, saved);
            ia64_tr_profile_add(ctx,
                                IA64_PROFILE_OVERLAY_VALIDITY_BRANCH, 1);
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
    ia64_tr_profile_add(ctx, IA64_PROFILE_OVERLAY_SAVE_BR, 1);
    ia64_tr_profile_add(ctx, IA64_PROFILE_ARCH_STORE, 2);
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
        ia64_tr_profile_add(ctx, IA64_PROFILE_ARCH_LOAD, 1);
        ia64_tr_profile_add(ctx, IA64_PROFILE_OVERLAY_VALIDITY_LOAD, 1);
        ia64_tr_profile_add(ctx, IA64_PROFILE_OVERLAY_VALIDITY_BRANCH, 1);
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
    ia64_tr_profile_add(ctx, IA64_PROFILE_OVERLAY_SAVE_PR, 1);
    ia64_tr_profile_add(ctx, IA64_PROFILE_ARCH_STORE, 2);
    if (saved != NULL) {
        gen_set_label(saved);
    }
    ctx->source_overlay_known_clear = false;
}

static void ia64_tr_group_clear_ordinary_source_overlay(DisasContext *ctx)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;
    unsigned clears = 4;

    if (group->gr_may_saved[0] != 0) {
        clears++;
        tcg_gen_st_i64(tcg_constant_i64(0), tcg_env,
                       offsetof(CPUIA64State,
                                issue_group.saved_gr_mask));
    }
    if (group->gr_may_saved[1] != 0) {
        clears++;
        tcg_gen_st_i64(tcg_constant_i64(0), tcg_env,
                       offsetof(CPUIA64State,
                                issue_group.saved_gr_mask) +
                       sizeof(uint64_t));
    }
    if (group->br_may_saved != 0) {
        clears++;
        tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                        offsetof(CPUIA64State,
                                 issue_group.saved_br_mask));
    }
    if (group->pr_may_saved) {
        clears++;
        tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                        offsetof(CPUIA64State, issue_group.pr_saved));
    }
    if (group->branch_forward_may_nonzero) {
        clears++;
        tcg_gen_st_i64(
            tcg_constant_i64(0), tcg_env,
            offsetof(CPUIA64State, issue_group.branch_pr_forward_mask));
    }
    if (group->branch_br_forward_may_nonzero) {
        clears++;
        tcg_gen_st8_i32(
            tcg_constant_i32(0), tcg_env,
            offsetof(CPUIA64State, issue_group.branch_br_forward_mask));
    }
    if (group->pfs_may_saved) {
        clears++;
        tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                        offsetof(CPUIA64State, issue_group.pfs_saved));
    }
    if (group->branch_pfs_forward_may_nonzero) {
        clears++;
        tcg_gen_st8_i32(
            tcg_constant_i32(0), tcg_env,
            offsetof(CPUIA64State, issue_group.branch_pfs_forwarded));
    }
    tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                    offsetof(CPUIA64State, issue_group.saved_ar_count));
    tcg_gen_st_i64(tcg_constant_i64(0), tcg_env,
                   offsetof(CPUIA64State, issue_group.saved_fr_mask));
    tcg_gen_st_i64(tcg_constant_i64(0), tcg_env,
                   offsetof(CPUIA64State, issue_group.saved_fr_mask) +
                   sizeof(uint64_t));
    tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                    offsetof(CPUIA64State, issue_group.typed_active));
    ia64_tr_profile_add(ctx, IA64_PROFILE_OVERLAY_CLEAR, clears);
    ia64_tr_profile_add(ctx, IA64_PROFILE_ARCH_STORE, clears);
}

static void ia64_tr_group_begin_instruction(
    DisasContext *ctx, const IA64Instruction *insn)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;
    IA64TrInstructionTransaction *instruction;
    const IA64TrInstructionPlan *plan;

    g_assert(ctx->typed_segment_active);
    g_assert(group->current == NULL);
    g_assert(!ctx->rewrite_scratch_active);
    g_assert(group->instruction_count < group->instruction_capacity);
    g_assert(ctx->rewrite_plan_index < ctx->rewrite_plan_emit_count);
    plan = &ctx->rewrite_plan[ctx->rewrite_plan_index++];
    g_assert(plan->address == insn->address && plan->slot == insn->slot);
    if (!group->active) {
        g_assert(group->instruction_count == 0);
        if (insn->starts_group) {
            /*
             * A control-flow split can conservatively leave the translation
             * context unsure whether an earlier path still owns a persisted
             * source overlay.  The architectural group boundary is the
             * authority: clear any possible overlay before opening the new
             * typed group.  Besides avoiding stale group-entry operands, this
             * makes debug and release builds follow the same path instead of
             * relying on an assertion-only invariant.
             */
            if (!ctx->source_overlay_known_clear) {
                ia64_tr_store_source_visibility_state(ctx, true, false);
                ctx->source_overlay_known_clear = true;
            }
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
    if (!ia64_tr_psr_finish_specialization_enabled() ||
        (ctx->base.tb->flags & IA64_TB_FLAG_PSR_FINISH) != 0) {
        if (group->pre_psr == NULL) {
            group->pre_psr = tcg_temp_new_i64();
        }
        instruction->pre_psr = group->pre_psr;
        tcg_gen_ld_i64(instruction->pre_psr, tcg_env,
                       offsetof(CPUIA64State, psr));
    }
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
    unsigned writes = instruction->gr_count + instruction->br_count +
                      instruction->pr_count +
                      instruction->pr_image.active;

    ia64_tr_profile_add(ctx, IA64_PROFILE_STAGED_WRITE, writes);
    ia64_tr_profile_add(ctx, IA64_PROFILE_FINAL_COMMIT, writes);

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

    if (instruction->post_alat_active) {
        TCGLabel *skip = gen_new_label();

        tcg_gen_brcondi_i64(TCG_COND_EQ,
                            instruction->post_alat_record, 0, skip);
        gen_helper_data_plane_alat_record(
            tcg_env, instruction->post_alat_address,
            tcg_constant_i32(instruction->post_alat_target),
            tcg_constant_i32(instruction->post_alat_width),
            tcg_constant_i32(instruction->post_alat_target_type),
            tcg_constant_i32(instruction->post_alat_memory_class));
        gen_set_label(skip);
        /* A later instruction in this TB must observe a successful record. */
        ctx->alat_may_active = true;
    }
}

static void ia64_tr_group_finish_instruction_success(
    DisasContext *ctx, const IA64Instruction *insn)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;
    IA64TrInstructionTransaction *instruction = group->current;
    g_assert(instruction != NULL && instruction->address == insn->address &&
             instruction->slot == insn->slot);

    /*
     * This is the sole typed finish-success point.  The generated code is
     * reached by predicated-false instructions, but a no-return fault branches
     * away before it.  Retiring here materializes the precise prefix while the
     * first-write overlay keeps later ordinary reads on group-entry values.
     */
    ia64_tr_group_retire_instruction(ctx, instruction);
    /*
     * PSR.ed is a one-instruction suppression latch.  Test the entry image,
     * not the possibly updated PSR, so an RFI (or a future typed status
     * writer) may establish a fresh ED value after this retirement point.
     * Nullified instructions also retire successfully and consume the latch.
     */
    if (instruction->pre_psr != NULL) {
        TCGLabel *skip_iipa = gen_new_label();
        TCGLabel *skip_ed = gen_new_label();
        TCGLabel *skip_suppression = gen_new_label();
        TCGv_i64 psr = ia64_tr_scratch_i64(ctx);

        tcg_gen_brcondi_i64(TCG_COND_TSTEQ, instruction->pre_psr,
                            IA64_TR_PSR_ED_BIT, skip_ed);
        tcg_gen_ld_i64(psr, tcg_env, offsetof(CPUIA64State, psr));
        tcg_gen_andi_i64(psr, psr, ~IA64_TR_PSR_ED_BIT);
        tcg_gen_st_i64(psr, tcg_env, offsetof(CPUIA64State, psr));
        gen_set_label(skip_ed);
        tcg_gen_brcondi_i64(TCG_COND_TSTEQ, instruction->pre_psr,
                            IA64_TR_PSR_FAULT_SUPPRESSION_MASK,
                            skip_suppression);
        gen_helper_clear_fault_suppression(tcg_env, instruction->pre_psr);
        gen_set_label(skip_suppression);
        tcg_gen_brcondi_i64(TCG_COND_TSTEQ, instruction->pre_psr,
                            IA64_TR_PSR_IC_BIT, skip_iipa);
        tcg_gen_st_i64(tcg_constant_i64(insn->address &
                                        ~(uint64_t)(IA64_BUNDLE_SIZE - 1)),
                       tcg_env,
                       offsetof(CPUIA64State, last_successful_bundle));
        gen_set_label(skip_iipa);
    }
    instruction->pre_psr = NULL;
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
    instruction->post_alat_address = NULL;
    instruction->post_alat_record = NULL;
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
    ia64_tr_profile_add(ctx, IA64_PROFILE_GROUP_SAFEPOINT, 1);
    ia64_tr_profile_add(ctx, IA64_PROFILE_SYNC_FAULT, 1);
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
    ia64_tr_profile_add(ctx, IA64_PROFILE_DURABLE_MATERIALIZATION, 1);
    ia64_tr_profile_add(
        ctx, IA64_PROFILE_DURABLE_BYTES,
        (ctpop64(group->gr_may_saved[0]) +
         ctpop64(group->gr_may_saved[1])) * 16 +
        ctpop32(group->br_may_saved) * 8 + group->pr_may_saved * 8 +
        group->pfs_may_saved * 8);
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

static void ia64_tr_group_publish_state_for_returning_helper(
    DisasContext *ctx)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;

    g_assert(group->active && group->current != NULL);
    /*
     * A normalized helper may return after consulting or changing CPU state.
     * Export the cache, but retain the ordinary-source overlay: later slots in
     * this issue group must continue to select their group-entry images.
     */
    ia64_tr_profile_add(ctx, IA64_PROFILE_GROUP_SAFEPOINT, 1);
    ia64_tr_profile_add(ctx, IA64_PROFILE_SYNC_HELPER, 1);
    ia64_tr_sync_state_cache(ctx);
}

static void ia64_tr_emit_decoded_privileged_operation(
    DisasContext *ctx, const IA64Instruction *insn)
{
    /* RFI has not retired; export only its already-successful group prefix. */
    ia64_tr_group_publish_prefix_for_noreturn_fault(ctx);
    tcg_gen_movi_i64(cpu_ip, insn->address);
    ia64_tr_publish_fault_state(insn->address, insn->slot,
                                ia64_tr_decoded_slot_type(insn->unit),
                                insn->raw, insn->starts_group);
    gen_helper_raise_privileged_operation(tcg_env);
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

/*
 * ALAT allocation is an architecturally post-write effect.  A GR/FR write
 * invalidates the old tag first; installing the replacement before ordinary
 * destination retirement would let generic write invalidation erase it.
 */
static void ia64_tr_group_prepare_post_alat_record(
    DisasContext *ctx, uint8_t target, uint8_t width,
    IA64AlatTargetType target_type, uint8_t memory_class)
{
    IA64TrGroupTransaction *group = &ctx->rewrite_group;
    IA64TrInstructionTransaction *instruction = group->current;

    g_assert(instruction != NULL && !instruction->post_alat_active);
    if (group->post_alat_address == NULL) {
        group->post_alat_address = tcg_temp_new_i64();
        group->post_alat_record = tcg_temp_new_i64();
    }
    instruction->post_alat_active = true;
    instruction->post_alat_target = target;
    instruction->post_alat_width = width;
    instruction->post_alat_target_type = target_type;
    instruction->post_alat_memory_class = memory_class;
    instruction->post_alat_address = group->post_alat_address;
    instruction->post_alat_record = group->post_alat_record;
    tcg_gen_movi_i64(instruction->post_alat_address, 0);
    tcg_gen_movi_i64(instruction->post_alat_record, 0);
}

static void ia64_tr_group_stage_post_alat_record(
    IA64TrInstructionTransaction *instruction, TCGv_i64 address)
{
    g_assert(instruction != NULL && instruction->post_alat_active);
    tcg_gen_mov_i64(instruction->post_alat_address, address);
    tcg_gen_movi_i64(instruction->post_alat_record, 1);
}

static bool ia64_tr_decoded_is_ordinary_integer_load(IA64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_LD1:
    case IA64_OP_LD2:
    case IA64_OP_LD4:
    case IA64_OP_LD8:
        return true;
    default:
        return false;
    }
}

static bool ia64_tr_decoded_is_ordinary_integer_store(IA64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_ST1:
    case IA64_OP_ST2:
    case IA64_OP_ST4:
    case IA64_OP_ST8:
    case IA64_OP_ST1REL:
    case IA64_OP_ST2REL:
    case IA64_OP_ST4REL:
    case IA64_OP_ST8REL:
        return true;
    default:
        return false;
    }
}

static bool ia64_tr_decoded_is_ordinary_integer_memory(IA64Opcode opcode)
{
    return ia64_tr_decoded_is_ordinary_integer_load(opcode) ||
           ia64_tr_decoded_is_ordinary_integer_store(opcode);
}

static uint8_t ia64_tr_decoded_integer_memory_width(IA64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_LD1:
    case IA64_OP_ST1:
    case IA64_OP_ST1REL:
        return 1;
    case IA64_OP_LD2:
    case IA64_OP_ST2:
    case IA64_OP_ST2REL:
        return 2;
    case IA64_OP_LD4:
    case IA64_OP_ST4:
    case IA64_OP_ST4REL:
        return 4;
    case IA64_OP_LD8:
    case IA64_OP_ST8:
    case IA64_OP_ST8REL:
        return 8;
    default:
        return 0;
    }
}

static bool ia64_tr_decoded_is_supported_ordinary_integer_memory(
    const IA64Instruction *insn)
{
    bool load = ia64_tr_decoded_is_ordinary_integer_load(insn->opcode);
    bool store = ia64_tr_decoded_is_ordinary_integer_store(insn->opcode);
    bool release = insn->opcode == IA64_OP_ST1REL ||
                   insn->opcode == IA64_OP_ST2REL ||
                   insn->opcode == IA64_OP_ST4REL ||
                   insn->opcode == IA64_OP_ST8REL;

    if ((!load && !store) || insn->unit != IA64_INSN_UNIT_M ||
        insn->slot_span != 1 ||
        ia64_tr_decoded_integer_memory_width(insn->opcode) == 0 ||
        (insn->reg_base_update && insn->imm_base_update)) {
        return false;
    }
    if (load) {
        return !insn->mem_release &&
               (!insn->imm_base_update ||
                (insn->imm >= -256 && insn->imm <= 255));
    }
    return !insn->reg_base_update && !insn->mem_acquire &&
           insn->mem_release == release &&
           (!insn->imm_base_update ||
            (insn->imm >= -256 && insn->imm <= 255));
}

static bool ia64_tr_decoded_ordinary_integer_memory_statically_illegal(
    const IA64Instruction *insn)
{
    bool load = ia64_tr_decoded_is_ordinary_integer_load(insn->opcode);
    bool update = insn->reg_base_update || insn->imm_base_update;

    return load ? insn->r1 == 0 || (update && insn->r1 == insn->r3) ||
                  (update && insn->r3 == 0)
                : update && insn->r3 == 0;
}

/*
 * Typed ownership map for the final data-plane tranche.  The table is keyed
 * only by the policy-free decoder opcode; no raw-slot fields are inspected by
 * admission or lowering.  memory_class uses the architectural completer
 * classes shared with the focused speculation/ALAT helpers (s=1, a=2,
 * sa=3, fill=6, c.clr=8, c.nc=9, spill=14).
 */
typedef enum IA64TrDataPlaneKind {
    IA64_TR_DATA_PLANE_NONE,
    IA64_TR_DATA_PLANE_INTEGER_LOAD,
    IA64_TR_DATA_PLANE_INTEGER_SPILL,
    IA64_TR_DATA_PLANE_WIDE_LOAD,
    IA64_TR_DATA_PLANE_WIDE_STORE,
    IA64_TR_DATA_PLANE_XCHG,
    IA64_TR_DATA_PLANE_CMPXCHG,
    IA64_TR_DATA_PLANE_CMP8XCHG16,
    IA64_TR_DATA_PLANE_FETCHADD,
    IA64_TR_DATA_PLANE_FP_LOAD,
    IA64_TR_DATA_PLANE_FP_LOAD_PAIR,
    IA64_TR_DATA_PLANE_FP_STORE,
    IA64_TR_DATA_PLANE_FWB,
    IA64_TR_DATA_PLANE_FC,
    IA64_TR_DATA_PLANE_INVALA,
    IA64_TR_DATA_PLANE_INVALAT,
    IA64_TR_DATA_PLANE_CHK_S,
    IA64_TR_DATA_PLANE_CHK_A,
    IA64_TR_DATA_PLANE_LFETCH,
} IA64TrDataPlaneKind;

typedef struct IA64TrDataPlaneDescriptor {
    IA64TrDataPlaneKind kind;
    uint8_t width;
    uint8_t memory_class;
} IA64TrDataPlaneDescriptor;

#define IA64_TR_DP(_kind, _width, _class) \
    { .kind = IA64_TR_DATA_PLANE_##_kind, \
      .width = (_width), .memory_class = (_class) }

static const IA64TrDataPlaneDescriptor
ia64_tr_data_plane_table[IA64_OP_COUNT] = {
    [IA64_OP_LD1S] = IA64_TR_DP(INTEGER_LOAD, 1, 1),
    [IA64_OP_LD2S] = IA64_TR_DP(INTEGER_LOAD, 2, 1),
    [IA64_OP_LD4S] = IA64_TR_DP(INTEGER_LOAD, 4, 1),
    [IA64_OP_LD8S] = IA64_TR_DP(INTEGER_LOAD, 8, 1),
    [IA64_OP_LD1A] = IA64_TR_DP(INTEGER_LOAD, 1, 2),
    [IA64_OP_LD2A] = IA64_TR_DP(INTEGER_LOAD, 2, 2),
    [IA64_OP_LD4A] = IA64_TR_DP(INTEGER_LOAD, 4, 2),
    [IA64_OP_LD8A] = IA64_TR_DP(INTEGER_LOAD, 8, 2),
    [IA64_OP_LD1SA] = IA64_TR_DP(INTEGER_LOAD, 1, 3),
    [IA64_OP_LD2SA] = IA64_TR_DP(INTEGER_LOAD, 2, 3),
    [IA64_OP_LD4SA] = IA64_TR_DP(INTEGER_LOAD, 4, 3),
    [IA64_OP_LD8SA] = IA64_TR_DP(INTEGER_LOAD, 8, 3),
    [IA64_OP_LD8FILL] = IA64_TR_DP(INTEGER_LOAD, 8, 6),
    [IA64_OP_LD1C_CLR] = IA64_TR_DP(INTEGER_LOAD, 1, 8),
    [IA64_OP_LD2C_CLR] = IA64_TR_DP(INTEGER_LOAD, 2, 8),
    [IA64_OP_LD4C_CLR] = IA64_TR_DP(INTEGER_LOAD, 4, 8),
    [IA64_OP_LD8C_CLR] = IA64_TR_DP(INTEGER_LOAD, 8, 8),
    [IA64_OP_LD1C_NC] = IA64_TR_DP(INTEGER_LOAD, 1, 9),
    [IA64_OP_LD2C_NC] = IA64_TR_DP(INTEGER_LOAD, 2, 9),
    [IA64_OP_LD4C_NC] = IA64_TR_DP(INTEGER_LOAD, 4, 9),
    [IA64_OP_LD8C_NC] = IA64_TR_DP(INTEGER_LOAD, 8, 9),
    [IA64_OP_LD16] = IA64_TR_DP(WIDE_LOAD, 16, 0),

    [IA64_OP_ST8SPILL] = IA64_TR_DP(INTEGER_SPILL, 8, 14),
    [IA64_OP_ST16] = IA64_TR_DP(WIDE_STORE, 16, 0),

    [IA64_OP_XCHG1] = IA64_TR_DP(XCHG, 1, 0),
    [IA64_OP_XCHG2] = IA64_TR_DP(XCHG, 2, 0),
    [IA64_OP_XCHG4] = IA64_TR_DP(XCHG, 4, 0),
    [IA64_OP_XCHG8] = IA64_TR_DP(XCHG, 8, 0),
    [IA64_OP_CMPXCHG1] = IA64_TR_DP(CMPXCHG, 1, 0),
    [IA64_OP_CMPXCHG2] = IA64_TR_DP(CMPXCHG, 2, 0),
    [IA64_OP_CMPXCHG4] = IA64_TR_DP(CMPXCHG, 4, 0),
    [IA64_OP_CMPXCHG8] = IA64_TR_DP(CMPXCHG, 8, 0),
    [IA64_OP_CMP8XCHG16] = IA64_TR_DP(CMP8XCHG16, 16, 0),
    [IA64_OP_FETCHADD4] = IA64_TR_DP(FETCHADD, 4, 0),
    [IA64_OP_FETCHADD8] = IA64_TR_DP(FETCHADD, 8, 0),

    [IA64_OP_LDFD] = IA64_TR_DP(FP_LOAD, 8, 0),
    [IA64_OP_LDFS] = IA64_TR_DP(FP_LOAD, 4, 0),
    [IA64_OP_LDF_FILL] = IA64_TR_DP(FP_LOAD, 16, 6),
    [IA64_OP_LDF8] = IA64_TR_DP(FP_LOAD, 8, 0),
    [IA64_OP_LDFE] = IA64_TR_DP(FP_LOAD, 10, 0),
    [IA64_OP_LDFP8] = IA64_TR_DP(FP_LOAD_PAIR, 16, 0),
    [IA64_OP_LDFPD] = IA64_TR_DP(FP_LOAD_PAIR, 16, 0),
    [IA64_OP_LDFPS] = IA64_TR_DP(FP_LOAD_PAIR, 8, 0),
    [IA64_OP_STFD] = IA64_TR_DP(FP_STORE, 8, 0),
    [IA64_OP_STFS] = IA64_TR_DP(FP_STORE, 4, 0),
    [IA64_OP_STF_SPILL] = IA64_TR_DP(FP_STORE, 16, 14),
    [IA64_OP_STF8] = IA64_TR_DP(FP_STORE, 8, 0),
    [IA64_OP_STFE] = IA64_TR_DP(FP_STORE, 10, 0),

    [IA64_OP_FWB] = IA64_TR_DP(FWB, 0, 0),
    [IA64_OP_FC] = IA64_TR_DP(FC, 1, 0),
    [IA64_OP_INVALA] = IA64_TR_DP(INVALA, 0, 0),
    [IA64_OP_INVALAT] = IA64_TR_DP(INVALAT, 0, 0),
    [IA64_OP_CHK_S] = IA64_TR_DP(CHK_S, 0, 0),
    [IA64_OP_CHK_A] = IA64_TR_DP(CHK_A, 0, 0),
    [IA64_OP_CHK_A_CLR] = IA64_TR_DP(CHK_A, 0, 0),
    [IA64_OP_LFETCH] = IA64_TR_DP(LFETCH, 1, 0),
    [IA64_OP_LFETCH_FAULT] = IA64_TR_DP(LFETCH, 1, 0),
};

#undef IA64_TR_DP

static const IA64TrDataPlaneDescriptor *
ia64_tr_decoded_data_plane(IA64Opcode opcode)
{
    if ((unsigned)opcode >= ARRAY_SIZE(ia64_tr_data_plane_table) ||
        ia64_tr_data_plane_table[opcode].kind == IA64_TR_DATA_PLANE_NONE) {
        return NULL;
    }
    return &ia64_tr_data_plane_table[opcode];
}

static bool ia64_tr_decoded_is_data_plane_branch(IA64Opcode opcode)
{
    const IA64TrDataPlaneDescriptor *descriptor =
        ia64_tr_decoded_data_plane(opcode);

    return descriptor != NULL &&
           (descriptor->kind == IA64_TR_DATA_PLANE_CHK_S ||
            descriptor->kind == IA64_TR_DATA_PLANE_CHK_A);
}

static bool ia64_tr_decoded_bundle_requires_io_boundary(
    const IA64DecodedInstructionBundle *decoded, uint8_t accepted_last_slot)
{
    for (unsigned slot = decoded->start_slot;
         slot <= accepted_last_slot; slot++) {
        const IA64Instruction *insn;
        const IA64TrDataPlaneDescriptor *descriptor;

        if ((decoded->instruction_mask & (1u << slot)) == 0) {
            continue;
        }
        insn = &decoded->instruction[slot];
        if (insn->status == IA64_DECODE_OK &&
            (((insn->opcode == IA64_OP_MOV_ARGR ||
               insn->opcode == IA64_OP_MOV_GRAR ||
               insn->opcode == IA64_OP_MOV_IMMAR) &&
              insn->r2 == IA64_AR_ITC) ||
             (insn->opcode == IA64_OP_MOV_GRCR &&
              (insn->r2 == IA64_CR_ITM ||
               insn->r2 == IA64_CR_ITV)))) {
            return true;
        }
        if (ia64_tr_decoded_is_ordinary_integer_memory(insn->opcode)) {
            return true;
        }
        descriptor = ia64_tr_decoded_data_plane(insn->opcode);
        if (descriptor == NULL) {
            continue;
        }
        switch (descriptor->kind) {
        case IA64_TR_DATA_PLANE_INTEGER_LOAD:
        case IA64_TR_DATA_PLANE_INTEGER_SPILL:
        case IA64_TR_DATA_PLANE_WIDE_LOAD:
        case IA64_TR_DATA_PLANE_WIDE_STORE:
        case IA64_TR_DATA_PLANE_XCHG:
        case IA64_TR_DATA_PLANE_CMPXCHG:
        case IA64_TR_DATA_PLANE_CMP8XCHG16:
        case IA64_TR_DATA_PLANE_FETCHADD:
        case IA64_TR_DATA_PLANE_FP_LOAD:
        case IA64_TR_DATA_PLANE_FP_LOAD_PAIR:
        case IA64_TR_DATA_PLANE_FP_STORE:
        case IA64_TR_DATA_PLANE_FC:
        case IA64_TR_DATA_PLANE_CHK_S:
        case IA64_TR_DATA_PLANE_LFETCH:
            return true;
        case IA64_TR_DATA_PLANE_FWB:
        case IA64_TR_DATA_PLANE_INVALA:
        case IA64_TR_DATA_PLANE_INVALAT:
        case IA64_TR_DATA_PLANE_CHK_A:
        case IA64_TR_DATA_PLANE_NONE:
            break;
        }
    }
    return false;
}

static bool ia64_tr_decoded_is_supported_data_plane(
    const IA64Instruction *insn)
{
    const IA64TrDataPlaneDescriptor *descriptor =
        ia64_tr_decoded_data_plane(insn->opcode);

    if (descriptor == NULL || insn->slot_span != 1) {
        return false;
    }
    if (descriptor->kind == IA64_TR_DATA_PLANE_CHK_S) {
        return (insn->unit == IA64_INSN_UNIT_M ||
                insn->unit == IA64_INSN_UNIT_I) &&
               (insn->imm & 0xf) == 0;
    }
    if (descriptor->kind == IA64_TR_DATA_PLANE_CHK_A) {
        return insn->unit == IA64_INSN_UNIT_M &&
               (insn->imm & 0xf) == 0;
    }
    if (insn->unit != IA64_INSN_UNIT_M) {
        return false;
    }

    switch (descriptor->kind) {
    case IA64_TR_DATA_PLANE_INTEGER_LOAD:
    case IA64_TR_DATA_PLANE_FP_LOAD:
        return !(insn->reg_base_update && insn->imm_base_update) &&
               (!insn->imm_base_update ||
                (insn->imm >= -256 && insn->imm <= 255));
    case IA64_TR_DATA_PLANE_INTEGER_SPILL:
    case IA64_TR_DATA_PLANE_FP_STORE:
        return !insn->reg_base_update &&
               (!insn->imm_base_update ||
                (insn->imm >= -256 && insn->imm <= 255));
    case IA64_TR_DATA_PLANE_FP_LOAD_PAIR:
        return !insn->reg_base_update &&
               (!insn->imm_base_update ||
                insn->imm == descriptor->width);
    case IA64_TR_DATA_PLANE_LFETCH:
        return !(insn->reg_base_update && insn->imm_base_update) &&
               (!insn->imm_base_update ||
                (insn->imm >= -256 && insn->imm <= 255));
    default:
        return !insn->reg_base_update && !insn->imm_base_update;
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

typedef enum IA64TrFpOwner {
    IA64_TR_FP_INVALID,
    IA64_TR_FP_DIRECT,
    IA64_TR_FP_FOCUSED,
} IA64TrFpOwner;

typedef enum IA64TrFpSourceLayout {
    IA64_TR_FP_SOURCE_NONE,
    IA64_TR_FP_SOURCE_UNARY,
    IA64_TR_FP_SOURCE_R3,
    IA64_TR_FP_SOURCE_BINARY,
    IA64_TR_FP_SOURCE_TERNARY,
    IA64_TR_FP_SOURCE_XMPY,
} IA64TrFpSourceLayout;

typedef struct IA64TrFpDescriptor {
    IA64TrFpOwner owner;
    IA64TrFpSourceLayout source_layout;
} IA64TrFpDescriptor;

#define IA64_TR_FP_DIRECT_ROW(_layout) \
    { .owner = IA64_TR_FP_DIRECT, \
      .source_layout = IA64_TR_FP_SOURCE_##_layout }

#define IA64_TR_FP_FOCUSED_ROW(_layout) \
    { .owner = IA64_TR_FP_FOCUSED, \
      .source_layout = IA64_TR_FP_SOURCE_##_layout }

/* Exact register-format/significand operations need no FPSR transaction. */
static const IA64TrFpDescriptor ia64_tr_fp_table[IA64_OP_COUNT] = {
    [IA64_OP_FADD] = IA64_TR_FP_FOCUSED_ROW(BINARY),
    [IA64_OP_FSUB] = IA64_TR_FP_FOCUSED_ROW(BINARY),
    [IA64_OP_FMPY] = IA64_TR_FP_FOCUSED_ROW(BINARY),
    [IA64_OP_FMA] = IA64_TR_FP_FOCUSED_ROW(TERNARY),
    [IA64_OP_FMS] = IA64_TR_FP_FOCUSED_ROW(TERNARY),
    [IA64_OP_FNMA] = IA64_TR_FP_FOCUSED_ROW(TERNARY),
    [IA64_OP_FNORM] = IA64_TR_FP_FOCUSED_ROW(R3),
    [IA64_OP_FCMP] = IA64_TR_FP_FOCUSED_ROW(BINARY),
    [IA64_OP_FMIN] = IA64_TR_FP_FOCUSED_ROW(BINARY),
    [IA64_OP_FMAX] = IA64_TR_FP_FOCUSED_ROW(BINARY),
    [IA64_OP_FAMIN] = IA64_TR_FP_FOCUSED_ROW(BINARY),
    [IA64_OP_FAMAX] = IA64_TR_FP_FOCUSED_ROW(BINARY),
    [IA64_OP_FRCPA] = IA64_TR_FP_FOCUSED_ROW(BINARY),
    [IA64_OP_FPRCPA] = IA64_TR_FP_FOCUSED_ROW(BINARY),
    [IA64_OP_FPRSQRTA] = IA64_TR_FP_FOCUSED_ROW(R3),
    [IA64_OP_FRSQRTA] = IA64_TR_FP_FOCUSED_ROW(R3),
    [IA64_OP_FCVT_FX] = IA64_TR_FP_FOCUSED_ROW(UNARY),
    [IA64_OP_FCVT_FXU] = IA64_TR_FP_FOCUSED_ROW(UNARY),
    [IA64_OP_GETF_D] = IA64_TR_FP_FOCUSED_ROW(UNARY),
    [IA64_OP_GETF_S] = IA64_TR_FP_FOCUSED_ROW(UNARY),
    [IA64_OP_SETF_D] = IA64_TR_FP_FOCUSED_ROW(NONE),
    [IA64_OP_SETF_S] = IA64_TR_FP_FOCUSED_ROW(NONE),
    [IA64_OP_FPACK] = IA64_TR_FP_FOCUSED_ROW(BINARY),
    [IA64_OP_FPMIN] = IA64_TR_FP_FOCUSED_ROW(BINARY),
    [IA64_OP_FPMAX] = IA64_TR_FP_FOCUSED_ROW(BINARY),
    [IA64_OP_FPAMIN] = IA64_TR_FP_FOCUSED_ROW(BINARY),
    [IA64_OP_FPAMAX] = IA64_TR_FP_FOCUSED_ROW(BINARY),
    [IA64_OP_FPCMP] = IA64_TR_FP_FOCUSED_ROW(BINARY),
    [IA64_OP_FPCVT] = IA64_TR_FP_FOCUSED_ROW(UNARY),
    [IA64_OP_FPMA] = IA64_TR_FP_FOCUSED_ROW(TERNARY),
    [IA64_OP_FPMS] = IA64_TR_FP_FOCUSED_ROW(TERNARY),
    [IA64_OP_FPNMA] = IA64_TR_FP_FOCUSED_ROW(TERNARY),
    [IA64_OP_FCLASS] = IA64_TR_FP_DIRECT_ROW(UNARY),
    [IA64_OP_GETF_EXP] = IA64_TR_FP_DIRECT_ROW(UNARY),
    [IA64_OP_GETF_SIG] = IA64_TR_FP_DIRECT_ROW(UNARY),
    [IA64_OP_SETF_EXP] = IA64_TR_FP_DIRECT_ROW(NONE),
    [IA64_OP_SETF_SIG] = IA64_TR_FP_DIRECT_ROW(NONE),
    [IA64_OP_FSETC] = IA64_TR_FP_DIRECT_ROW(NONE),
    [IA64_OP_FCLRF] = IA64_TR_FP_DIRECT_ROW(NONE),
    [IA64_OP_FCHKF] = IA64_TR_FP_DIRECT_ROW(NONE),
    [IA64_OP_XMA_L] = IA64_TR_FP_DIRECT_ROW(TERNARY),
    [IA64_OP_XMA_H] = IA64_TR_FP_DIRECT_ROW(TERNARY),
    [IA64_OP_XMA_HU] = IA64_TR_FP_DIRECT_ROW(TERNARY),
    [IA64_OP_XMPY_HU] = IA64_TR_FP_DIRECT_ROW(XMPY),
    [IA64_OP_FSELECT] = IA64_TR_FP_DIRECT_ROW(TERNARY),
    [IA64_OP_FCVT_XF] = IA64_TR_FP_DIRECT_ROW(UNARY),
    [IA64_OP_FPABS] = IA64_TR_FP_DIRECT_ROW(UNARY),
    [IA64_OP_FPNEG] = IA64_TR_FP_DIRECT_ROW(UNARY),
    [IA64_OP_FPNEGABS] = IA64_TR_FP_DIRECT_ROW(UNARY),
    [IA64_OP_FMERGE] = IA64_TR_FP_DIRECT_ROW(BINARY),
    [IA64_OP_FMERGE_S] = IA64_TR_FP_DIRECT_ROW(BINARY),
    [IA64_OP_FMERGE_SE] = IA64_TR_FP_DIRECT_ROW(BINARY),
    [IA64_OP_FAND] = IA64_TR_FP_DIRECT_ROW(BINARY),
    [IA64_OP_FANDCM] = IA64_TR_FP_DIRECT_ROW(BINARY),
    [IA64_OP_FOR] = IA64_TR_FP_DIRECT_ROW(BINARY),
    [IA64_OP_FXOR] = IA64_TR_FP_DIRECT_ROW(BINARY),
    [IA64_OP_FSWAP] = IA64_TR_FP_DIRECT_ROW(BINARY),
    [IA64_OP_FSWAP_NL] = IA64_TR_FP_DIRECT_ROW(BINARY),
    [IA64_OP_FSWAP_NR] = IA64_TR_FP_DIRECT_ROW(BINARY),
    [IA64_OP_FMIX_LR] = IA64_TR_FP_DIRECT_ROW(BINARY),
    [IA64_OP_FMIX_R] = IA64_TR_FP_DIRECT_ROW(BINARY),
    [IA64_OP_FMIX_L] = IA64_TR_FP_DIRECT_ROW(BINARY),
    [IA64_OP_FSXT_R] = IA64_TR_FP_DIRECT_ROW(BINARY),
    [IA64_OP_FSXT_L] = IA64_TR_FP_DIRECT_ROW(BINARY),
    [IA64_OP_FPMERGE] = IA64_TR_FP_DIRECT_ROW(BINARY),
    [IA64_OP_FPMERGE_S] = IA64_TR_FP_DIRECT_ROW(BINARY),
    [IA64_OP_FPMERGE_SE] = IA64_TR_FP_DIRECT_ROW(BINARY),
};

#undef IA64_TR_FP_FOCUSED_ROW
#undef IA64_TR_FP_DIRECT_ROW

static const IA64TrFpDescriptor *
ia64_tr_decoded_fp_compute(IA64Opcode opcode)
{
    if ((unsigned)opcode >= ARRAY_SIZE(ia64_tr_fp_table) ||
        ia64_tr_fp_table[opcode].owner == IA64_TR_FP_INVALID) {
        return NULL;
    }
    return &ia64_tr_fp_table[opcode];
}

static bool ia64_tr_fp_has_fr_destination(IA64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_FCMP:
    case IA64_OP_GETF_D:
    case IA64_OP_GETF_S:
    case IA64_OP_FCLASS:
    case IA64_OP_GETF_EXP:
    case IA64_OP_GETF_SIG:
    case IA64_OP_FSETC:
    case IA64_OP_FCLRF:
    case IA64_OP_FCHKF:
        return false;
    default:
        return true;
    }
}

static bool ia64_tr_fp_is_approximation(IA64Opcode opcode)
{
    return opcode == IA64_OP_FRCPA || opcode == IA64_OP_FPRCPA ||
           opcode == IA64_OP_FPRSQRTA || opcode == IA64_OP_FRSQRTA;
}

static bool ia64_tr_fp_is_getf(IA64Opcode opcode)
{
    return opcode == IA64_OP_GETF_D || opcode == IA64_OP_GETF_S ||
           opcode == IA64_OP_GETF_EXP || opcode == IA64_OP_GETF_SIG;
}

static bool ia64_tr_fp_is_setf(IA64Opcode opcode)
{
    return opcode == IA64_OP_SETF_D || opcode == IA64_OP_SETF_S ||
           opcode == IA64_OP_SETF_EXP || opcode == IA64_OP_SETF_SIG;
}

static bool ia64_tr_fp_is_status_control(IA64Opcode opcode)
{
    return opcode == IA64_OP_FSETC || opcode == IA64_OP_FCLRF ||
           opcode == IA64_OP_FCHKF;
}

typedef enum IA64TrPackedForm {
    IA64_TR_PACKED_INVALID,
    IA64_TR_PACKED_ADD,
    IA64_TR_PACKED_SUB,
    IA64_TR_PACKED_SHLADD,
    IA64_TR_PACKED_SHRADD,
    IA64_TR_PACKED_AVG,
    IA64_TR_PACKED_AVGSUB,
    IA64_TR_PACKED_CMP_EQ,
    IA64_TR_PACKED_CMP_GT,
    IA64_TR_PACKED_MAX_U,
    IA64_TR_PACKED_MAX_S,
    IA64_TR_PACKED_MIN_U,
    IA64_TR_PACKED_MIN_S,
    IA64_TR_PACKED_MPY_L,
    IA64_TR_PACKED_MPY_R,
    IA64_TR_PACKED_MPYSH_S,
    IA64_TR_PACKED_MPYSH_U,
    IA64_TR_PACKED_SHL,
    IA64_TR_PACKED_SHR_S,
    IA64_TR_PACKED_SHR_U,
    IA64_TR_PACKED_SAD,
    IA64_TR_PACKED_MUX1,
    IA64_TR_PACKED_MUX2,
    IA64_TR_PACKED_MIX_L,
    IA64_TR_PACKED_MIX_R,
    IA64_TR_PACKED_PACK_S,
    IA64_TR_PACKED_PACK_U,
    IA64_TR_PACKED_UNPACK_H,
    IA64_TR_PACKED_UNPACK_L,
    IA64_TR_PACKED_CZX_L,
    IA64_TR_PACKED_CZX_R,
} IA64TrPackedForm;

typedef struct IA64TrPackedDescriptor {
    IA64TrPackedForm form;
    uint8_t element_bits;
    uint8_t source_count;
    bool a9_unit;
} IA64TrPackedDescriptor;

#define IA64_TR_PACKED(_form, _bits, _sources, _a9) \
    {                                                \
        .form = IA64_TR_PACKED_##_form,              \
        .element_bits = (_bits),                     \
        .source_count = (_sources),                  \
        .a9_unit = (_a9),                            \
    }

/*
 * Enum-exact ownership for this Macro-E tranche.  The decoder has already
 * normalized pseudo-encodings, register direction, and immediate counts;
 * the descriptor records only the semantic shape consumed by direct TCG.
 */
static const IA64TrPackedDescriptor
ia64_tr_packed_table[IA64_OP_COUNT] = {
    [IA64_OP_PADD1] = IA64_TR_PACKED(ADD, 8, 2, true),
    [IA64_OP_PADD2] = IA64_TR_PACKED(ADD, 16, 2, true),
    [IA64_OP_PADD4] = IA64_TR_PACKED(ADD, 32, 2, true),
    [IA64_OP_PSUB1] = IA64_TR_PACKED(SUB, 8, 2, true),
    [IA64_OP_PSUB2] = IA64_TR_PACKED(SUB, 16, 2, true),
    [IA64_OP_PSUB4] = IA64_TR_PACKED(SUB, 32, 2, true),
    [IA64_OP_PSHLADD2] = IA64_TR_PACKED(SHLADD, 16, 2, true),
    [IA64_OP_PSHRADD2] = IA64_TR_PACKED(SHRADD, 16, 2, true),
    [IA64_OP_PAVG1] = IA64_TR_PACKED(AVG, 8, 2, true),
    [IA64_OP_PAVG2] = IA64_TR_PACKED(AVG, 16, 2, true),
    [IA64_OP_PAVGSUB1] = IA64_TR_PACKED(AVGSUB, 8, 2, true),
    [IA64_OP_PAVGSUB2] = IA64_TR_PACKED(AVGSUB, 16, 2, true),
    [IA64_OP_PCMP1_EQ] = IA64_TR_PACKED(CMP_EQ, 8, 2, true),
    [IA64_OP_PCMP1_GT] = IA64_TR_PACKED(CMP_GT, 8, 2, true),
    [IA64_OP_PCMP2_EQ] = IA64_TR_PACKED(CMP_EQ, 16, 2, true),
    [IA64_OP_PCMP2_GT] = IA64_TR_PACKED(CMP_GT, 16, 2, true),
    [IA64_OP_PCMP4_EQ] = IA64_TR_PACKED(CMP_EQ, 32, 2, true),
    [IA64_OP_PCMP4_GT] = IA64_TR_PACKED(CMP_GT, 32, 2, true),
    [IA64_OP_PMAX1_U] = IA64_TR_PACKED(MAX_U, 8, 2, false),
    [IA64_OP_PMAX2] = IA64_TR_PACKED(MAX_S, 16, 2, false),
    [IA64_OP_PMIN1_U] = IA64_TR_PACKED(MIN_U, 8, 2, false),
    [IA64_OP_PMIN2] = IA64_TR_PACKED(MIN_S, 16, 2, false),
    [IA64_OP_PMPY2_L] = IA64_TR_PACKED(MPY_L, 16, 2, false),
    [IA64_OP_PMPY2_R] = IA64_TR_PACKED(MPY_R, 16, 2, false),
    [IA64_OP_PMPYSH2] = IA64_TR_PACKED(MPYSH_S, 16, 2, false),
    [IA64_OP_PMPYSH2_U] = IA64_TR_PACKED(MPYSH_U, 16, 2, false),
    [IA64_OP_PSHL2] = IA64_TR_PACKED(SHL, 16, 2, false),
    [IA64_OP_PSHL4] = IA64_TR_PACKED(SHL, 32, 2, false),
    [IA64_OP_PSHR2] = IA64_TR_PACKED(SHR_S, 16, 2, false),
    [IA64_OP_PSHR2_U] = IA64_TR_PACKED(SHR_U, 16, 2, false),
    [IA64_OP_PSHR4] = IA64_TR_PACKED(SHR_S, 32, 2, false),
    [IA64_OP_PSHR4_U] = IA64_TR_PACKED(SHR_U, 32, 2, false),
    [IA64_OP_PSAD1] = IA64_TR_PACKED(SAD, 8, 2, false),
    [IA64_OP_MUX1] = IA64_TR_PACKED(MUX1, 8, 1, false),
    [IA64_OP_MUX2] = IA64_TR_PACKED(MUX2, 16, 1, false),
    [IA64_OP_MIX1_L] = IA64_TR_PACKED(MIX_L, 8, 2, false),
    [IA64_OP_MIX1_R] = IA64_TR_PACKED(MIX_R, 8, 2, false),
    [IA64_OP_MIX2_L] = IA64_TR_PACKED(MIX_L, 16, 2, false),
    [IA64_OP_MIX2_R] = IA64_TR_PACKED(MIX_R, 16, 2, false),
    [IA64_OP_MIX4_L] = IA64_TR_PACKED(MIX_L, 32, 2, false),
    [IA64_OP_MIX4_R] = IA64_TR_PACKED(MIX_R, 32, 2, false),
    [IA64_OP_PACK2_SSS] = IA64_TR_PACKED(PACK_S, 16, 2, false),
    [IA64_OP_PACK2_USS] = IA64_TR_PACKED(PACK_U, 16, 2, false),
    [IA64_OP_PACK4_SSS] = IA64_TR_PACKED(PACK_S, 32, 2, false),
    [IA64_OP_UNPACK1_H] = IA64_TR_PACKED(UNPACK_H, 8, 2, false),
    [IA64_OP_UNPACK1_L] = IA64_TR_PACKED(UNPACK_L, 8, 2, false),
    [IA64_OP_UNPACK2_H] = IA64_TR_PACKED(UNPACK_H, 16, 2, false),
    [IA64_OP_UNPACK2_L] = IA64_TR_PACKED(UNPACK_L, 16, 2, false),
    [IA64_OP_UNPACK4_H] = IA64_TR_PACKED(UNPACK_H, 32, 2, false),
    [IA64_OP_UNPACK4_L] = IA64_TR_PACKED(UNPACK_L, 32, 2, false),
    [IA64_OP_CZX1_L] = IA64_TR_PACKED(CZX_L, 8, 1, false),
    [IA64_OP_CZX1_R] = IA64_TR_PACKED(CZX_R, 8, 1, false),
    [IA64_OP_CZX2_L] = IA64_TR_PACKED(CZX_L, 16, 1, false),
    [IA64_OP_CZX2_R] = IA64_TR_PACKED(CZX_R, 16, 1, false),
};

#undef IA64_TR_PACKED

static const IA64TrPackedDescriptor *
ia64_tr_decoded_packed(IA64Opcode opcode)
{
    if ((unsigned)opcode >= ARRAY_SIZE(ia64_tr_packed_table) ||
        ia64_tr_packed_table[opcode].form == IA64_TR_PACKED_INVALID) {
        return NULL;
    }
    return &ia64_tr_packed_table[opcode];
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

static bool ia64_tr_decoded_is_fp_status_branch(IA64Opcode opcode)
{
    return opcode == IA64_OP_FCHKF;
}

static bool ia64_tr_decoded_is_conditional_branch(IA64Opcode opcode)
{
    return ia64_tr_decoded_is_direct_conditional_branch(opcode) ||
           opcode == IA64_OP_BR_INDIRECT ||
           ia64_tr_decoded_is_loop_branch(opcode) ||
           ia64_tr_decoded_is_call_branch(opcode) ||
           ia64_tr_decoded_is_return_branch(opcode) ||
           ia64_tr_decoded_is_data_plane_branch(opcode) ||
           ia64_tr_decoded_is_fp_status_branch(opcode);
}

static bool ia64_tr_decoded_is_rfi(IA64Opcode opcode)
{
    return opcode == IA64_OP_RFI;
}

static bool ia64_tr_decoded_is_rse_spine(IA64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_ALLOC:
    case IA64_OP_COVER:
    case IA64_OP_FLUSHRS:
    case IA64_OP_LOADRS:
    case IA64_OP_CLRRRB:
    case IA64_OP_CLRRRB_PR:
        return true;
    default:
        return false;
    }
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

static bool ia64_tr_decoded_is_supported_packed(
    const IA64Instruction *insn)
{
    const IA64TrPackedDescriptor *descriptor =
        ia64_tr_decoded_packed(insn->opcode);

    if (descriptor == NULL || !(insn->slot_span == 1) ||
        (descriptor->element_bits != 8 &&
         descriptor->element_bits != 16 &&
         descriptor->element_bits != 32) ||
        (descriptor->source_count != 1 && descriptor->source_count != 2)) {
        return false;
    }
    if (descriptor->a9_unit) {
        if (insn->unit != IA64_INSN_UNIT_M &&
            insn->unit != IA64_INSN_UNIT_I) {
            return false;
        }
    } else if (insn->unit != IA64_INSN_UNIT_I) {
        return false;
    }

    switch (descriptor->form) {
    case IA64_TR_PACKED_ADD:
    case IA64_TR_PACKED_SUB:
        return descriptor->element_bits == 32 ? insn->imm == 0 :
                                                insn->imm >= 0 &&
                                                insn->imm <= 3;
    case IA64_TR_PACKED_SHLADD:
        return insn->imm >= 1 && insn->imm <= 4;
    case IA64_TR_PACKED_SHRADD:
        return insn->imm >= 1 && insn->imm <= 3;
    case IA64_TR_PACKED_AVG:
        return insn->imm == 0 || insn->imm == 1;
    case IA64_TR_PACKED_AVGSUB:
    case IA64_TR_PACKED_CMP_EQ:
    case IA64_TR_PACKED_CMP_GT:
    case IA64_TR_PACKED_MAX_U:
    case IA64_TR_PACKED_MAX_S:
    case IA64_TR_PACKED_MIN_U:
    case IA64_TR_PACKED_MIN_S:
    case IA64_TR_PACKED_MPY_L:
    case IA64_TR_PACKED_MPY_R:
    case IA64_TR_PACKED_SAD:
    case IA64_TR_PACKED_MIX_L:
    case IA64_TR_PACKED_MIX_R:
    case IA64_TR_PACKED_PACK_S:
    case IA64_TR_PACKED_PACK_U:
    case IA64_TR_PACKED_UNPACK_H:
    case IA64_TR_PACKED_UNPACK_L:
        return insn->imm == 0;
    case IA64_TR_PACKED_MPYSH_S:
    case IA64_TR_PACKED_MPYSH_U:
        return insn->imm == 0 || insn->imm == 7 ||
               insn->imm == 15 || insn->imm == 16;
    case IA64_TR_PACKED_SHL:
        return (insn->imm == -1 ||
                (insn->imm >= 0 && insn->imm <= 31)) &&
               (insn->imm < 0 || insn->r3 == 0);
    case IA64_TR_PACKED_SHR_S:
    case IA64_TR_PACKED_SHR_U:
        return (insn->imm == -1 ||
                (insn->imm >= 0 && insn->imm <= 31)) &&
               (insn->imm < 0 || insn->r2 == 0);
    case IA64_TR_PACKED_MUX1:
        return insn->r3 == 0 &&
               (insn->imm == 0 ||
                (insn->imm >= 8 && insn->imm <= 11));
    case IA64_TR_PACKED_MUX2:
        return insn->r3 == 0 && insn->imm >= 0 && insn->imm <= 255;
    case IA64_TR_PACKED_CZX_L:
    case IA64_TR_PACKED_CZX_R:
        return insn->r2 == 0 && insn->imm == 0;
    case IA64_TR_PACKED_INVALID:
    default:
        return false;
    }
}

/*
 * Exact typed ownership map for Macro D's privileged/system plane.  The
 * decoder has already normalized all encoding aliases; this table describes
 * architectural operands and policies only and is deliberately incapable of
 * recovering information from IA64Instruction.raw.
 */
typedef enum IA64TrSystemKind {
    IA64_TR_SYSTEM_INVALID,
    IA64_TR_SYSTEM_BREAK,
    IA64_TR_SYSTEM_BR_IA,
    IA64_TR_SYSTEM_MOV_IMMAR,
    IA64_TR_SYSTEM_MOV_CRGR,
    IA64_TR_SYSTEM_MOV_GRCR,
    IA64_TR_SYSTEM_SSM,
    IA64_TR_SYSTEM_RSM,
    IA64_TR_SYSTEM_ITR_D,
    IA64_TR_SYSTEM_ITR_I,
    IA64_TR_SYSTEM_PTR_D,
    IA64_TR_SYSTEM_PTR_I,
    IA64_TR_SYSTEM_PTC_L,
    IA64_TR_SYSTEM_PTC_G,
    IA64_TR_SYSTEM_TPA,
    IA64_TR_SYSTEM_SYNC_I,
    IA64_TR_SYSTEM_SRLZ,
    IA64_TR_SYSTEM_SRLZ_D,
    IA64_TR_SYSTEM_MF,
    IA64_TR_SYSTEM_MF_A,
    IA64_TR_SYSTEM_PROBE_R,
    IA64_TR_SYSTEM_PROBE_W,
    IA64_TR_SYSTEM_PROBE_RW,
    IA64_TR_SYSTEM_TAK,
    IA64_TR_SYSTEM_THASH,
    IA64_TR_SYSTEM_TTAG,
    IA64_TR_SYSTEM_PTC_E,
    IA64_TR_SYSTEM_ITC_D,
    IA64_TR_SYSTEM_ITC_I,
    IA64_TR_SYSTEM_PTC_GA,
    IA64_TR_SYSTEM_MOV_PSRGR,
    IA64_TR_SYSTEM_MOV_GRPSR,
    IA64_TR_SYSTEM_MOV_RRGR,
    IA64_TR_SYSTEM_MOV_GRRR,
    IA64_TR_SYSTEM_BSW0,
    IA64_TR_SYSTEM_BSW1,
    IA64_TR_SYSTEM_EPC,
    IA64_TR_SYSTEM_MOV_PKRGR_INDEXED,
    IA64_TR_SYSTEM_MOV_GRPKR_INDEXED,
    IA64_TR_SYSTEM_MOV_UMGR,
    IA64_TR_SYSTEM_MOV_GRUM,
    IA64_TR_SYSTEM_MOV_IBRGR_INDEXED,
    IA64_TR_SYSTEM_MOV_GRIBR_INDEXED,
    IA64_TR_SYSTEM_MOV_DBRGR_INDEXED,
    IA64_TR_SYSTEM_MOV_GRDBR_INDEXED,
    IA64_TR_SYSTEM_MOV_PMCGR_INDEXED,
    IA64_TR_SYSTEM_MOV_GRPMC_INDEXED,
    IA64_TR_SYSTEM_MOV_PMDGR_INDEXED,
    IA64_TR_SYSTEM_MOV_GRPMD_INDEXED,
    IA64_TR_SYSTEM_MOV_CPUID_INDEXED,
    IA64_TR_SYSTEM_MOV_DAHRGR_INDEXED,
    IA64_TR_SYSTEM_MOV_MSRGR,
    IA64_TR_SYSTEM_MOV_GRMSR,
    IA64_TR_SYSTEM_MOV_CURRENT_IP,
    IA64_TR_SYSTEM_VMSW,
    IA64_TR_SYSTEM_RUM,
    IA64_TR_SYSTEM_SUM_UM,
    IA64_TR_SYSTEM_BRP,
} IA64TrSystemKind;

typedef enum IA64TrSystemShape {
    IA64_TR_SYSTEM_SHAPE_NONE,
    IA64_TR_SYSTEM_SHAPE_BREAK,
    IA64_TR_SYSTEM_SHAPE_BRANCH,
    IA64_TR_SYSTEM_SHAPE_AR_IMMEDIATE,
    IA64_TR_SYSTEM_SHAPE_MASK,
    IA64_TR_SYSTEM_SHAPE_DEST_R1,
    IA64_TR_SYSTEM_SHAPE_SRC_R1,
    IA64_TR_SYSTEM_SHAPE_SRC_R2,
    IA64_TR_SYSTEM_SHAPE_DEST_R1_INDEX_R2,
    IA64_TR_SYSTEM_SHAPE_SRC_R1_INDEX_R2,
    IA64_TR_SYSTEM_SHAPE_DEST_R1_INDEX_R3,
    IA64_TR_SYSTEM_SHAPE_SRC_R2_INDEX_R3,
    IA64_TR_SYSTEM_SHAPE_INDEX_R3,
    IA64_TR_SYSTEM_SHAPE_PROBE,
} IA64TrSystemShape;

typedef enum IA64TrSystemLowering {
    IA64_TR_SYSTEM_LOWER_DIRECT,
    IA64_TR_SYSTEM_LOWER_EXCEPTION,
    IA64_TR_SYSTEM_LOWER_CONTROL,
    IA64_TR_SYSTEM_LOWER_STATE,
    IA64_TR_SYSTEM_LOWER_MMU,
} IA64TrSystemLowering;

typedef enum IA64TrSystemPrivilege {
    IA64_TR_SYSTEM_PRIV_NONE,
    IA64_TR_SYSTEM_PRIV_ALWAYS,
    IA64_TR_SYSTEM_PRIV_REGISTER,
    IA64_TR_SYSTEM_PRIV_PMD,
    IA64_TR_SYSTEM_PRIV_FEATURE,
} IA64TrSystemPrivilege;

typedef enum IA64TrSystemNatPolicy {
    IA64_TR_SYSTEM_NAT_NONE,
    IA64_TR_SYSTEM_NAT_VALUE,
    IA64_TR_SYSTEM_NAT_INDEX,
    IA64_TR_SYSTEM_NAT_VALUE_INDEX,
    IA64_TR_SYSTEM_NAT_ADDRESS,
    IA64_TR_SYSTEM_NAT_ADDRESS_SIZE,
    IA64_TR_SYSTEM_NAT_ADDRESS_LEVEL,
    IA64_TR_SYSTEM_NAT_PROPAGATE_ADDRESS,
} IA64TrSystemNatPolicy;

typedef enum IA64TrSystemTbEnd {
    IA64_TR_SYSTEM_TB_CONTINUE,
    IA64_TR_SYSTEM_TB_BUNDLE,
    IA64_TR_SYSTEM_TB_NEXT_SLOT,
    IA64_TR_SYSTEM_TB_CONTROL,
    IA64_TR_SYSTEM_TB_NORETURN,
    IA64_TR_SYSTEM_TB_CONDITIONAL_BUNDLE,
} IA64TrSystemTbEnd;

enum {
    IA64_TR_SYSTEM_GR_NONE = 0,
    IA64_TR_SYSTEM_GR_R1 = 1U << 0,
    IA64_TR_SYSTEM_GR_R2 = 1U << 1,
    IA64_TR_SYSTEM_GR_R3 = 1U << 2,
};

enum {
    IA64_TR_SYSTEM_BR_NONE = 0,
    IA64_TR_SYSTEM_BR_B1 = 1,
    IA64_TR_SYSTEM_BR_B2 = 2,
};

typedef struct IA64TrSystemDescriptor {
    IA64TrSystemKind kind;
    IA64TrSystemShape shape;
    IA64TrSystemLowering lowering;
    IA64TrSystemPrivilege privilege;
    IA64TrSystemNatPolicy nat_policy;
    IA64TrSystemTbEnd tb_end;
    uint16_t unit_mask;
    uint16_t status_mask;
    uint8_t span_mask;
    uint8_t src_gr_fields;
    uint8_t dst_gr_field;
    uint8_t src_br_field;
    bool predicable;
    bool must_end_group;
} IA64TrSystemDescriptor;

#define IA64_TR_SYSTEM_UNIT(_unit) (1U << IA64_INSN_UNIT_##_unit)
#define IA64_TR_SYSTEM_SPAN_1 (1U << 0)
#define IA64_TR_SYSTEM_SPAN_2 (1U << 1)
#define IA64_TR_SYSTEM_STATUS(_status) (1U << IA64_DECODE_##_status)
#define IA64_TR_SYSTEM_NORMALIZED_STATUS_MASK \
    (IA64_TR_SYSTEM_STATUS(OK) | \
     IA64_TR_SYSTEM_STATUS(ILLEGAL_UNIT) | \
     IA64_TR_SYSTEM_STATUS(ILLEGAL_REGISTER) | \
     IA64_TR_SYSTEM_STATUS(ILLEGAL_PLACEMENT) | \
     IA64_TR_SYSTEM_STATUS(RESERVED_FIELD))

#define IA64_TR_SYSTEM(_kind, _shape, _lowering, _units, _spans, \
                       _src_gr, _dst_gr, _src_br, _predicable, \
                       _privilege, _nat, _tb_end, _must_end) \
    { \
        .kind = IA64_TR_SYSTEM_##_kind, \
        .shape = IA64_TR_SYSTEM_SHAPE_##_shape, \
        .lowering = IA64_TR_SYSTEM_LOWER_##_lowering, \
        .privilege = IA64_TR_SYSTEM_PRIV_##_privilege, \
        .nat_policy = IA64_TR_SYSTEM_NAT_##_nat, \
        .tb_end = IA64_TR_SYSTEM_TB_##_tb_end, \
        .unit_mask = (_units), \
        .status_mask = IA64_TR_SYSTEM_NORMALIZED_STATUS_MASK, \
        .span_mask = (_spans), \
        .src_gr_fields = (_src_gr), \
        .dst_gr_field = (_dst_gr), \
        .src_br_field = (_src_br), \
        .predicable = (_predicable), \
        .must_end_group = (_must_end), \
    }

static const IA64TrSystemDescriptor
ia64_tr_system_table[IA64_OP_COUNT] = {
    [IA64_OP_BREAK] = IA64_TR_SYSTEM(
        BREAK, BREAK, EXCEPTION,
        IA64_TR_SYSTEM_UNIT(M) | IA64_TR_SYSTEM_UNIT(I) |
        IA64_TR_SYSTEM_UNIT(F) | IA64_TR_SYSTEM_UNIT(B) |
        IA64_TR_SYSTEM_UNIT(X),
        IA64_TR_SYSTEM_SPAN_1 | IA64_TR_SYSTEM_SPAN_2,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, true, NONE, NONE, NORETURN, false),
    [IA64_OP_BR_IA] = IA64_TR_SYSTEM(
        BR_IA, BRANCH, CONTROL, IA64_TR_SYSTEM_UNIT(B),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_BR_B2, false,
        NONE, NONE, NORETURN, false),
    [IA64_OP_MOV_IMMAR] = IA64_TR_SYSTEM(
        MOV_IMMAR, AR_IMMEDIATE, STATE,
        IA64_TR_SYSTEM_UNIT(M) | IA64_TR_SYSTEM_UNIT(I),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_BR_NONE, true,
        REGISTER, NONE, CONDITIONAL_BUNDLE, false),
    [IA64_OP_MOV_CRGR] = IA64_TR_SYSTEM(
        MOV_CRGR, DEST_R1_INDEX_R2, STATE, IA64_TR_SYSTEM_UNIT(M),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_GR_R1, IA64_TR_SYSTEM_BR_NONE, true,
        ALWAYS, NONE, CONDITIONAL_BUNDLE, false),
    [IA64_OP_MOV_GRCR] = IA64_TR_SYSTEM(
        MOV_GRCR, SRC_R1_INDEX_R2, STATE, IA64_TR_SYSTEM_UNIT(M),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_R1,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_BR_NONE, true,
        ALWAYS, VALUE, BUNDLE, false),
    [IA64_OP_SSM] = IA64_TR_SYSTEM(
        SSM, MASK, STATE, IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, true, ALWAYS, NONE, BUNDLE, false),
    [IA64_OP_RSM] = IA64_TR_SYSTEM(
        RSM, MASK, STATE, IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, true, ALWAYS, NONE, BUNDLE, false),
    [IA64_OP_ITR_D] = IA64_TR_SYSTEM(
        ITR_D, SRC_R2_INDEX_R3, MMU, IA64_TR_SYSTEM_UNIT(M),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_R2 |
        IA64_TR_SYSTEM_GR_R3, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, true, ALWAYS, VALUE_INDEX, BUNDLE, false),
    [IA64_OP_ITR_I] = IA64_TR_SYSTEM(
        ITR_I, SRC_R2_INDEX_R3, MMU, IA64_TR_SYSTEM_UNIT(M),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_R2 |
        IA64_TR_SYSTEM_GR_R3, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, true, ALWAYS, VALUE_INDEX, NEXT_SLOT,
        false),
    [IA64_OP_PTR_D] = IA64_TR_SYSTEM(
        PTR_D, SRC_R2_INDEX_R3, MMU, IA64_TR_SYSTEM_UNIT(M),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_R2 |
        IA64_TR_SYSTEM_GR_R3, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, true, ALWAYS, ADDRESS_SIZE, BUNDLE, false),
    [IA64_OP_PTR_I] = IA64_TR_SYSTEM(
        PTR_I, SRC_R2_INDEX_R3, MMU, IA64_TR_SYSTEM_UNIT(M),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_R2 |
        IA64_TR_SYSTEM_GR_R3, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, true, ALWAYS, ADDRESS_SIZE, BUNDLE, false),
    [IA64_OP_PTC_L] = IA64_TR_SYSTEM(
        PTC_L, SRC_R2_INDEX_R3, MMU, IA64_TR_SYSTEM_UNIT(M),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_R2 |
        IA64_TR_SYSTEM_GR_R3, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, true, ALWAYS, ADDRESS_SIZE, BUNDLE, false),
    [IA64_OP_PTC_G] = IA64_TR_SYSTEM(
        PTC_G, SRC_R2_INDEX_R3, MMU, IA64_TR_SYSTEM_UNIT(M),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_R2 |
        IA64_TR_SYSTEM_GR_R3, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, true, ALWAYS, ADDRESS_SIZE, BUNDLE, true),
    [IA64_OP_TPA] = IA64_TR_SYSTEM(
        TPA, DEST_R1_INDEX_R3, MMU, IA64_TR_SYSTEM_UNIT(M),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_R3,
        IA64_TR_SYSTEM_GR_R1, IA64_TR_SYSTEM_BR_NONE, true,
        ALWAYS, ADDRESS, CONTINUE, false),
    [IA64_OP_SYNC_I] = IA64_TR_SYSTEM(
        SYNC_I, NONE, DIRECT, IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, true, NONE, NONE, NEXT_SLOT, false),
    [IA64_OP_SRLZ] = IA64_TR_SYSTEM(
        SRLZ, NONE, DIRECT, IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, true, NONE, NONE, NEXT_SLOT, false),
    [IA64_OP_SRLZ_D] = IA64_TR_SYSTEM(
        SRLZ_D, NONE, DIRECT, IA64_TR_SYSTEM_UNIT(M),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_BR_NONE, true,
        NONE, NONE, NEXT_SLOT, false),
    [IA64_OP_MF] = IA64_TR_SYSTEM(
        MF, NONE, DIRECT, IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, true, NONE, NONE, CONTINUE, false),
    [IA64_OP_MF_A] = IA64_TR_SYSTEM(
        MF_A, NONE, DIRECT, IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, true, NONE, NONE, CONTINUE, false),
    [IA64_OP_PROBE_R] = IA64_TR_SYSTEM(
        PROBE_R, PROBE, MMU, IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_R2 | IA64_TR_SYSTEM_GR_R3,
        IA64_TR_SYSTEM_GR_R1, IA64_TR_SYSTEM_BR_NONE, true,
        NONE, ADDRESS_LEVEL, CONTINUE, false),
    [IA64_OP_PROBE_W] = IA64_TR_SYSTEM(
        PROBE_W, PROBE, MMU, IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_R2 | IA64_TR_SYSTEM_GR_R3,
        IA64_TR_SYSTEM_GR_R1, IA64_TR_SYSTEM_BR_NONE, true,
        NONE, ADDRESS_LEVEL, CONTINUE, false),
    [IA64_OP_PROBE_RW] = IA64_TR_SYSTEM(
        PROBE_RW, PROBE, MMU, IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_R3, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, true, NONE, ADDRESS, CONTINUE, false),
    [IA64_OP_TAK] = IA64_TR_SYSTEM(
        TAK, DEST_R1_INDEX_R3, MMU, IA64_TR_SYSTEM_UNIT(M),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_R3,
        IA64_TR_SYSTEM_GR_R1, IA64_TR_SYSTEM_BR_NONE, true,
        ALWAYS, ADDRESS, CONTINUE, false),
    [IA64_OP_THASH] = IA64_TR_SYSTEM(
        THASH, DEST_R1_INDEX_R3, MMU, IA64_TR_SYSTEM_UNIT(M),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_R3,
        IA64_TR_SYSTEM_GR_R1, IA64_TR_SYSTEM_BR_NONE, true,
        NONE, PROPAGATE_ADDRESS, CONTINUE, false),
    [IA64_OP_TTAG] = IA64_TR_SYSTEM(
        TTAG, DEST_R1_INDEX_R3, MMU, IA64_TR_SYSTEM_UNIT(M),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_R3,
        IA64_TR_SYSTEM_GR_R1, IA64_TR_SYSTEM_BR_NONE, true,
        NONE, PROPAGATE_ADDRESS, CONTINUE, false),
    [IA64_OP_PTC_E] = IA64_TR_SYSTEM(
        PTC_E, INDEX_R3, MMU, IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_R3, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, true, ALWAYS, ADDRESS, BUNDLE, false),
    [IA64_OP_ITC_D] = IA64_TR_SYSTEM(
        ITC_D, SRC_R2, MMU, IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_R2, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, true, ALWAYS, VALUE, BUNDLE, true),
    [IA64_OP_ITC_I] = IA64_TR_SYSTEM(
        ITC_I, SRC_R2, MMU, IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_R2, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, true, ALWAYS, VALUE, NEXT_SLOT, true),
    [IA64_OP_PTC_GA] = IA64_TR_SYSTEM(
        PTC_GA, SRC_R2_INDEX_R3, MMU, IA64_TR_SYSTEM_UNIT(M),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_R2 |
        IA64_TR_SYSTEM_GR_R3, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, true, ALWAYS, ADDRESS_SIZE, BUNDLE, true),
    [IA64_OP_MOV_PSRGR] = IA64_TR_SYSTEM(
        MOV_PSRGR, DEST_R1, DIRECT, IA64_TR_SYSTEM_UNIT(M),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_GR_R1, IA64_TR_SYSTEM_BR_NONE, true,
        ALWAYS, NONE, CONTINUE, false),
    [IA64_OP_MOV_GRPSR] = IA64_TR_SYSTEM(
        MOV_GRPSR, SRC_R1, STATE, IA64_TR_SYSTEM_UNIT(M),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_R1,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_BR_NONE, true,
        ALWAYS, VALUE, BUNDLE, false),
    [IA64_OP_MOV_RRGR] = IA64_TR_SYSTEM(
        MOV_RRGR, DEST_R1_INDEX_R2, STATE, IA64_TR_SYSTEM_UNIT(M),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_R2,
        IA64_TR_SYSTEM_GR_R1, IA64_TR_SYSTEM_BR_NONE, true,
        ALWAYS, INDEX, CONTINUE, false),
    [IA64_OP_MOV_GRRR] = IA64_TR_SYSTEM(
        MOV_GRRR, SRC_R2_INDEX_R3, STATE, IA64_TR_SYSTEM_UNIT(M),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_R2 |
        IA64_TR_SYSTEM_GR_R3, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, true, ALWAYS, VALUE_INDEX, BUNDLE, false),
    [IA64_OP_BSW0] = IA64_TR_SYSTEM(
        BSW0, NONE, CONTROL, IA64_TR_SYSTEM_UNIT(B), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, false, ALWAYS, NONE, CONTROL, true),
    [IA64_OP_BSW1] = IA64_TR_SYSTEM(
        BSW1, NONE, CONTROL, IA64_TR_SYSTEM_UNIT(B), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, false, ALWAYS, NONE, CONTROL, true),
    [IA64_OP_EPC] = IA64_TR_SYSTEM(
        EPC, NONE, CONTROL, IA64_TR_SYSTEM_UNIT(B), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, false, NONE, NONE, CONTROL, false),
    [IA64_OP_MOV_PKRGR_INDEXED] = IA64_TR_SYSTEM(
        MOV_PKRGR_INDEXED, DEST_R1_INDEX_R3, STATE,
        IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_R3, IA64_TR_SYSTEM_GR_R1,
        IA64_TR_SYSTEM_BR_NONE, true, ALWAYS, INDEX, CONTINUE, false),
    [IA64_OP_MOV_GRPKR_INDEXED] = IA64_TR_SYSTEM(
        MOV_GRPKR_INDEXED, SRC_R2_INDEX_R3, STATE,
        IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_R2 | IA64_TR_SYSTEM_GR_R3,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_BR_NONE, true,
        ALWAYS, VALUE_INDEX, BUNDLE, false),
    [IA64_OP_MOV_UMGR] = IA64_TR_SYSTEM(
        MOV_UMGR, DEST_R1, DIRECT, IA64_TR_SYSTEM_UNIT(M),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_GR_R1, IA64_TR_SYSTEM_BR_NONE, true,
        NONE, NONE, CONTINUE, false),
    [IA64_OP_MOV_GRUM] = IA64_TR_SYSTEM(
        MOV_GRUM, SRC_R1, STATE, IA64_TR_SYSTEM_UNIT(M),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_R1,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_BR_NONE, true,
        NONE, VALUE, BUNDLE, false),
    [IA64_OP_MOV_IBRGR_INDEXED] = IA64_TR_SYSTEM(
        MOV_IBRGR_INDEXED, DEST_R1_INDEX_R3, STATE,
        IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_R3, IA64_TR_SYSTEM_GR_R1,
        IA64_TR_SYSTEM_BR_NONE, true, ALWAYS, INDEX, CONTINUE, false),
    [IA64_OP_MOV_GRIBR_INDEXED] = IA64_TR_SYSTEM(
        MOV_GRIBR_INDEXED, SRC_R2_INDEX_R3, STATE,
        IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_R2 | IA64_TR_SYSTEM_GR_R3,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_BR_NONE, true,
        ALWAYS, VALUE_INDEX, CONTINUE, false),
    [IA64_OP_MOV_DBRGR_INDEXED] = IA64_TR_SYSTEM(
        MOV_DBRGR_INDEXED, DEST_R1_INDEX_R3, STATE,
        IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_R3, IA64_TR_SYSTEM_GR_R1,
        IA64_TR_SYSTEM_BR_NONE, true, ALWAYS, INDEX, CONTINUE, false),
    [IA64_OP_MOV_GRDBR_INDEXED] = IA64_TR_SYSTEM(
        MOV_GRDBR_INDEXED, SRC_R2_INDEX_R3, STATE,
        IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_R2 | IA64_TR_SYSTEM_GR_R3,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_BR_NONE, true,
        ALWAYS, VALUE_INDEX, CONTINUE, false),
    [IA64_OP_MOV_PMCGR_INDEXED] = IA64_TR_SYSTEM(
        MOV_PMCGR_INDEXED, DEST_R1_INDEX_R3, STATE,
        IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_R3, IA64_TR_SYSTEM_GR_R1,
        IA64_TR_SYSTEM_BR_NONE, true, ALWAYS, INDEX, CONTINUE, false),
    [IA64_OP_MOV_GRPMC_INDEXED] = IA64_TR_SYSTEM(
        MOV_GRPMC_INDEXED, SRC_R2_INDEX_R3, STATE,
        IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_R2 | IA64_TR_SYSTEM_GR_R3,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_BR_NONE, true,
        ALWAYS, VALUE_INDEX, CONTINUE, false),
    [IA64_OP_MOV_PMDGR_INDEXED] = IA64_TR_SYSTEM(
        MOV_PMDGR_INDEXED, DEST_R1_INDEX_R3, STATE,
        IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_R3, IA64_TR_SYSTEM_GR_R1,
        IA64_TR_SYSTEM_BR_NONE, true, PMD, INDEX, CONTINUE, false),
    [IA64_OP_MOV_GRPMD_INDEXED] = IA64_TR_SYSTEM(
        MOV_GRPMD_INDEXED, SRC_R2_INDEX_R3, STATE,
        IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_R2 | IA64_TR_SYSTEM_GR_R3,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_BR_NONE, true,
        ALWAYS, VALUE_INDEX, CONTINUE, false),
    [IA64_OP_MOV_CPUID_INDEXED] = IA64_TR_SYSTEM(
        MOV_CPUID_INDEXED, DEST_R1_INDEX_R3, STATE,
        IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_R3, IA64_TR_SYSTEM_GR_R1,
        IA64_TR_SYSTEM_BR_NONE, true, NONE, INDEX, CONTINUE, false),
    [IA64_OP_MOV_DAHRGR_INDEXED] = IA64_TR_SYSTEM(
        MOV_DAHRGR_INDEXED, DEST_R1_INDEX_R3, STATE,
        IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_R3, IA64_TR_SYSTEM_GR_R1,
        IA64_TR_SYSTEM_BR_NONE, true, ALWAYS, INDEX, CONTINUE, false),
    [IA64_OP_MOV_MSRGR] = IA64_TR_SYSTEM(
        MOV_MSRGR, DEST_R1_INDEX_R3, STATE, IA64_TR_SYSTEM_UNIT(M),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_R3,
        IA64_TR_SYSTEM_GR_R1, IA64_TR_SYSTEM_BR_NONE, true,
        ALWAYS, INDEX, CONTINUE, false),
    [IA64_OP_MOV_GRMSR] = IA64_TR_SYSTEM(
        MOV_GRMSR, SRC_R2_INDEX_R3, STATE, IA64_TR_SYSTEM_UNIT(M),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_R2 |
        IA64_TR_SYSTEM_GR_R3, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, true, ALWAYS, VALUE_INDEX, BUNDLE, false),
    [IA64_OP_MOV_CURRENT_IP] = IA64_TR_SYSTEM(
        MOV_CURRENT_IP, DEST_R1, DIRECT, IA64_TR_SYSTEM_UNIT(I),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_GR_R1, IA64_TR_SYSTEM_BR_NONE, true,
        NONE, NONE, CONTINUE, false),
    [IA64_OP_VMSW] = IA64_TR_SYSTEM(
        VMSW, NONE, CONTROL, IA64_TR_SYSTEM_UNIT(B), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, false, FEATURE, NONE, CONTROL, false),
    [IA64_OP_RUM] = IA64_TR_SYSTEM(
        RUM, MASK, STATE, IA64_TR_SYSTEM_UNIT(M), IA64_TR_SYSTEM_SPAN_1,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_BR_NONE, true, NONE, NONE, BUNDLE, false),
    [IA64_OP_SUM_UM] = IA64_TR_SYSTEM(
        SUM_UM, MASK, STATE, IA64_TR_SYSTEM_UNIT(M),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_BR_NONE, true,
        NONE, NONE, BUNDLE, false),
    [IA64_OP_BRP] = IA64_TR_SYSTEM(
        BRP, BRANCH, DIRECT, IA64_TR_SYSTEM_UNIT(B),
        IA64_TR_SYSTEM_SPAN_1, IA64_TR_SYSTEM_GR_NONE,
        IA64_TR_SYSTEM_GR_NONE, IA64_TR_SYSTEM_BR_NONE, false,
        NONE, NONE, CONTINUE, false),
};

#undef IA64_TR_SYSTEM

static const IA64TrSystemDescriptor *
ia64_tr_decoded_system(IA64Opcode opcode)
{
    if ((unsigned)opcode >= ARRAY_SIZE(ia64_tr_system_table) ||
        ia64_tr_system_table[opcode].kind == IA64_TR_SYSTEM_INVALID) {
        return NULL;
    }
    return &ia64_tr_system_table[opcode];
}

static bool ia64_tr_decoded_is_supported_system(
    const IA64Instruction *insn)
{
    const IA64TrSystemDescriptor *descriptor =
        ia64_tr_decoded_system(insn->opcode);
    uint16_t unit_bit;
    uint8_t span_bit;

    if (descriptor == NULL || !insn->valid ||
        (unsigned)insn->status >= 16 ||
        (descriptor->status_mask & (1U << insn->status)) == 0 ||
        insn->slot_span == 0 || insn->slot_span > 2) {
        return false;
    }

    unit_bit = 1U << insn->unit;
    span_bit = 1U << (insn->slot_span - 1);
    if (insn->status == IA64_DECODE_ILLEGAL_UNIT) {
        if (descriptor->unit_mask & unit_bit) {
            return false;
        }
    } else if ((descriptor->unit_mask & unit_bit) == 0) {
        return false;
    }
    if ((descriptor->span_mask & span_bit) == 0 ||
        (insn->status == IA64_DECODE_RESERVED_FIELD) !=
            insn->reserved_field ||
        (insn->status == IA64_DECODE_ILLEGAL_PLACEMENT) !=
            insn->placement_illegal) {
        return false;
    }

    if (!descriptor->predicable && insn->qp != 0) {
        return false;
    }
    if (descriptor->kind == IA64_TR_SYSTEM_BREAK &&
        insn->unit == IA64_INSN_UNIT_B && insn->qp != 0) {
        return false;
    }
    if (insn->status == IA64_DECODE_OK &&
        descriptor->must_end_group && !insn->stop_after) {
        return false;
    }

    /* Validate the normalized operand shape without consulting raw bits. */
    switch (descriptor->shape) {
    case IA64_TR_SYSTEM_SHAPE_BREAK:
    case IA64_TR_SYSTEM_SHAPE_NONE:
    case IA64_TR_SYSTEM_SHAPE_MASK:
    case IA64_TR_SYSTEM_SHAPE_INDEX_R3:
        break;
    case IA64_TR_SYSTEM_SHAPE_BRANCH:
        if (descriptor->src_br_field == IA64_TR_SYSTEM_BR_B2 &&
            insn->b2 >= IA64_BR_COUNT) {
            return false;
        }
        break;
    case IA64_TR_SYSTEM_SHAPE_AR_IMMEDIATE:
        /* MOV_IMMAR's normalized AR selector is r2, not a GR operand. */
        if (insn->r2 >= IA64_AR_COUNT) {
            return false;
        }
        break;
    case IA64_TR_SYSTEM_SHAPE_DEST_R1:
    case IA64_TR_SYSTEM_SHAPE_DEST_R1_INDEX_R2:
    case IA64_TR_SYSTEM_SHAPE_DEST_R1_INDEX_R3:
        if (insn->status == IA64_DECODE_OK &&
            descriptor->dst_gr_field == IA64_TR_SYSTEM_GR_R1 &&
            insn->r1 == 0) {
            return false;
        }
        break;
    case IA64_TR_SYSTEM_SHAPE_PROBE:
        /* M40 faulting probes have no destination; regular M38/M39 do. */
        if (insn->status == IA64_DECODE_OK && !insn->probe_fault &&
            descriptor->dst_gr_field == IA64_TR_SYSTEM_GR_R1 &&
            insn->r1 == 0) {
            return false;
        }
        break;
    case IA64_TR_SYSTEM_SHAPE_SRC_R1:
    case IA64_TR_SYSTEM_SHAPE_SRC_R1_INDEX_R2:
    case IA64_TR_SYSTEM_SHAPE_SRC_R2:
    case IA64_TR_SYSTEM_SHAPE_SRC_R2_INDEX_R3:
        break;
    default:
        return false;
    }
    return true;
}

static bool ia64_tr_decoded_opcode_supported(IA64Opcode opcode)
{
    const IA64OpcodeTraits *traits = ia64_opcode_traits_for(opcode);

    /* The generated enum-exact ownership table is the admission authority. */
    return traits != NULL && traits->decoder_live &&
           (traits->admission == IA64_OPCODE_ADMISSION_FULL ||
            traits->admission == IA64_OPCODE_ADMISSION_PARTIAL) &&
           (traits->lowering_owner == IA64_OPCODE_OWNER_DIRECT_TCG ||
            traits->lowering_owner == IA64_OPCODE_OWNER_FOCUSED_HELPER);
}

static bool ia64_tr_helper_allowed(IA64Opcode opcode,
                                   IA64OpcodeHelper helper)
{
    const IA64OpcodeTraits *traits = ia64_opcode_traits_for(opcode);

    return traits != NULL && traits->decoder_live &&
           traits->helper_whitelist == helper &&
           (traits->lowering_owner == IA64_OPCODE_OWNER_DIRECT_TCG ||
            traits->lowering_owner == IA64_OPCODE_OWNER_FOCUSED_HELPER);
}

static void ia64_tr_require_helper(IA64Opcode opcode,
                                   IA64OpcodeHelper helper)
{
    g_assert(helper != IA64_OPCODE_HELPER_NONE);
    g_assert(ia64_tr_helper_allowed(opcode, helper));
}

static bool ia64_tr_decoded_is_supported_application_move(
    const IA64Instruction *insn)
{
    if (insn == NULL || !insn->valid || insn->slot_span != 1 ||
        (insn->unit != IA64_INSN_UNIT_M &&
         insn->unit != IA64_INSN_UNIT_I) ||
        insn->r2 >= IA64_AR_COUNT) {
        return false;
    }
    if (insn->opcode != IA64_OP_MOV_ARGR &&
        insn->opcode != IA64_OP_MOV_GRAR) {
        return false;
    }
    return insn->status == IA64_DECODE_OK ||
           insn->status == IA64_DECODE_ILLEGAL_REGISTER;
}

static unsigned ia64_tr_decoded_sources(const IA64Instruction *insn,
                                        uint8_t sources[3])
{
    const IA64TrSystemDescriptor *system =
        ia64_tr_decoded_system(insn->opcode);
    const IA64TrDecodedCompare *compare =
        ia64_tr_decoded_compare(insn->opcode);
    const IA64TrDecodedPredicateTest *test =
        ia64_tr_decoded_predicate_test(insn->opcode);
    const IA64TrPackedDescriptor *packed =
        ia64_tr_decoded_packed(insn->opcode);

    if (system != NULL) {
        unsigned count = 0;

        if (system->src_gr_fields & IA64_TR_SYSTEM_GR_R1) {
            sources[count++] = insn->r1;
        }
        if ((system->src_gr_fields & IA64_TR_SYSTEM_GR_R2) &&
            !(system->shape == IA64_TR_SYSTEM_SHAPE_PROBE &&
              insn->probe_imm)) {
            sources[count++] = insn->r2;
        }
        if (system->src_gr_fields & IA64_TR_SYSTEM_GR_R3) {
            sources[count++] = insn->r3;
        }
        return count;
    }

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

    if (packed != NULL) {
        switch (packed->form) {
        case IA64_TR_PACKED_MUX1:
        case IA64_TR_PACKED_MUX2:
            g_assert(packed->source_count == 1);
            sources[0] = insn->r2;
            return 1;
        case IA64_TR_PACKED_CZX_L:
        case IA64_TR_PACKED_CZX_R:
            g_assert(packed->source_count == 1);
            sources[0] = insn->r3;
            return 1;
        case IA64_TR_PACKED_SHL:
            sources[0] = insn->r2;
            if (insn->imm < 0) {
                sources[1] = insn->r3;
                return 2;
            }
            return 1;
        case IA64_TR_PACKED_SHR_S:
        case IA64_TR_PACKED_SHR_U:
            if (insn->imm < 0) {
                sources[0] = insn->r2;
                sources[1] = insn->r3;
                return 2;
            }
            sources[0] = insn->r3;
            return 1;
        case IA64_TR_PACKED_INVALID:
            g_assert_not_reached();
        default:
            g_assert(packed->source_count == 2);
            sources[0] = insn->r2;
            sources[1] = insn->r3;
            return 2;
        }
    }

    {
        const IA64TrDataPlaneDescriptor *data_plane =
            ia64_tr_decoded_data_plane(insn->opcode);

        if (data_plane != NULL) {
            switch (data_plane->kind) {
            case IA64_TR_DATA_PLANE_INTEGER_LOAD:
            case IA64_TR_DATA_PLANE_FP_LOAD:
            case IA64_TR_DATA_PLANE_LFETCH:
                sources[0] = insn->r3;
                if (insn->reg_base_update && insn->r2 != insn->r3) {
                    sources[1] = insn->r2;
                    return 2;
                }
                return 1;
            case IA64_TR_DATA_PLANE_INTEGER_SPILL:
                sources[0] = insn->r3;
                if (insn->r2 != insn->r3) {
                    sources[1] = insn->r2;
                    return 2;
                }
                return 1;
            case IA64_TR_DATA_PLANE_WIDE_STORE:
            case IA64_TR_DATA_PLANE_XCHG:
            case IA64_TR_DATA_PLANE_CMPXCHG:
            case IA64_TR_DATA_PLANE_CMP8XCHG16:
                sources[0] = insn->r3;
                if (insn->r2 != insn->r3) {
                    sources[1] = insn->r2;
                    return 2;
                }
                return 1;
            case IA64_TR_DATA_PLANE_FETCHADD:
                sources[0] = insn->r3;
                if (insn->imm == 0 && insn->r2 != insn->r3) {
                    sources[1] = insn->r2;
                    return 2;
                }
                return 1;
            case IA64_TR_DATA_PLANE_FP_STORE:
            case IA64_TR_DATA_PLANE_FP_LOAD_PAIR:
            case IA64_TR_DATA_PLANE_WIDE_LOAD:
            case IA64_TR_DATA_PLANE_FC:
                sources[0] = insn->r3;
                return 1;
            case IA64_TR_DATA_PLANE_CHK_S:
                if (!insn->check_fp) {
                    sources[0] = insn->r2;
                    return 1;
                }
                return 0;
            case IA64_TR_DATA_PLANE_FWB:
            case IA64_TR_DATA_PLANE_INVALA:
            case IA64_TR_DATA_PLANE_INVALAT:
            case IA64_TR_DATA_PLANE_CHK_A:
                return 0;
            case IA64_TR_DATA_PLANE_NONE:
            default:
                g_assert_not_reached();
            }
        }
    }

    if (ia64_tr_decoded_is_ordinary_integer_load(insn->opcode)) {
        sources[0] = insn->r3;
        if (insn->reg_base_update && insn->r2 != insn->r3) {
            sources[1] = insn->r2;
            return 2;
        }
        return 1;
    }
    if (ia64_tr_decoded_is_ordinary_integer_store(insn->opcode)) {
        sources[0] = insn->r3;
        if (insn->r2 != insn->r3) {
            sources[1] = insn->r2;
            return 2;
        }
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
        /* The decoder stores every mov ar=r ordinary GR source in r1. */
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
    const IA64TrSystemDescriptor *system_descriptor =
        ia64_tr_decoded_system(insn->opcode);
    uint64_t rotating_dest = 0;
    bool branch_shape = true;

    if (insn->reserved_memory_width) {
        return insn->valid && insn->opcode == IA64_OP_ILLEGAL &&
               insn->status == IA64_DECODE_RESERVED_ENCODING &&
               insn->unit == IA64_INSN_UNIT_M && insn->slot_span == 1;
    }

    /*
     * A policy-free decoder miss is itself a complete typed result.  It is
     * not a live opcode-ledger row, but production translation owns its
     * qualifying predicate and precise Illegal Operation delivery.  Admit
     * every physical instruction-unit shape here so invalid raw bits can
     * never select the coexistence engine.
     */
    if (insn->opcode == IA64_OP_ILLEGAL &&
        insn->status == IA64_DECODE_RESERVED_ENCODING) {
        return !insn->valid && insn->unit != IA64_INSN_UNIT_RESERVED &&
               insn->slot_span >= 1 && insn->slot_span <= 2;
    }

    if (system_descriptor != NULL) {
        /* Traits remain the release switch until lowering is fully wired. */
        return ia64_tr_decoded_opcode_supported(insn->opcode) &&
               ia64_tr_decoded_is_supported_system(insn);
    }

    if (insn->opcode == IA64_OP_MOV_ARGR ||
        insn->opcode == IA64_OP_MOV_GRAR) {
        return ia64_tr_decoded_opcode_supported(insn->opcode) &&
               ia64_tr_decoded_is_supported_application_move(insn);
    }

    if (insn->opcode == IA64_OP_MOV_GRPR) {
        rotating_dest = (uint64_t)insn->imm & IA64_TR_PR_ROTATING_MASK;
    } else if (insn->opcode == IA64_OP_MOV_PR_ROT_IMM) {
        rotating_dest = IA64_TR_PR_ROTATING_MASK;
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
    } else if (ia64_tr_decoded_is_rse_spine(insn->opcode)) {
        switch (insn->opcode) {
        case IA64_OP_ALLOC:
        case IA64_OP_FLUSHRS:
        case IA64_OP_LOADRS:
            branch_shape = insn->unit == IA64_INSN_UNIT_M &&
                           insn->slot_span == 1 && insn->starts_group;
            break;
        case IA64_OP_COVER:
        case IA64_OP_CLRRRB:
        case IA64_OP_CLRRRB_PR:
            branch_shape = insn->unit == IA64_INSN_UNIT_B &&
                           insn->slot_span == 1 && insn->qp == 0 &&
                           insn->stop_after;
            break;
        default:
            g_assert_not_reached();
        }
    } else if (ia64_tr_decoded_is_rfi(insn->opcode)) {
        branch_shape = insn->unit == IA64_INSN_UNIT_B &&
                       insn->slot_span == 1 && insn->qp == 0 &&
                       insn->stop_after;
    } else if (ia64_tr_decoded_is_fp_status_branch(insn->opcode)) {
        branch_shape = insn->unit == IA64_INSN_UNIT_F &&
                       insn->slot_span == 1 && (insn->imm & 0xf) == 0 &&
                       insn->sf < 4;
    } else if (ia64_tr_decoded_is_data_plane_branch(insn->opcode)) {
        branch_shape = (insn->imm & 0xf) == 0 &&
                       (insn->opcode == IA64_OP_CHK_S ?
                        (insn->unit == IA64_INSN_UNIT_M ||
                         insn->unit == IA64_INSN_UNIT_I) :
                        insn->unit == IA64_INSN_UNIT_M);
    }
    return insn->valid && insn->status == IA64_DECODE_OK &&
           ia64_tr_decoded_opcode_supported(insn->opcode) &&
           branch_shape &&
           (rotating_dest == 0 ||
            rotating_dest == IA64_TR_PR_ROTATING_MASK) &&
           (!ia64_tr_decoded_is_ordinary_integer_memory(insn->opcode) ||
            ia64_tr_decoded_is_supported_ordinary_integer_memory(insn)) &&
           (ia64_tr_decoded_packed(insn->opcode) == NULL ||
            ia64_tr_decoded_is_supported_packed(insn)) &&
           (!ia64_tr_decoded_is_integer_compare_opcode(insn->opcode) ||
            ia64_tr_decoded_is_supported_integer_compare(insn)) &&
           (!ia64_tr_decoded_is_predicate_test_opcode(insn->opcode) ||
            ia64_tr_decoded_is_supported_predicate_test(insn)) &&
           (ia64_tr_decoded_data_plane(insn->opcode) == NULL ||
            ia64_tr_decoded_is_supported_data_plane(insn));
}

/*
 * These RSE encodings are decoded and owned by the typed engine, but their
 * operands make the instruction an unconditional Illegal Operation.  Keep
 * the test in one place: preflight needs to stop its durable plan at the same
 * physical instruction at which lowering emits the no-return fault.
 */
static bool ia64_tr_rse_spine_is_static_noreturn(
    const IA64Instruction *insn)
{
    uint32_t packed;
    uint32_t sof;
    uint32_t sol;
    uint32_t sor;

    if (!ia64_tr_decoded_is_rse_spine(insn->opcode)) {
        return false;
    }
    if (insn->opcode == IA64_OP_FLUSHRS ||
        insn->opcode == IA64_OP_LOADRS) {
        return insn->qp != 0;
    }
    if (insn->opcode != IA64_OP_ALLOC) {
        return false;
    }

    packed = (uint32_t)insn->imm;
    sof = packed & 0x7f;
    sol = (packed >> 7) & 0x7f;
    sor = (packed >> 14) & 0x0f;
    return insn->r1 == 0 ||
           (insn->r1 >= IA64_STATIC_GR_COUNT &&
            insn->r1 >= IA64_STATIC_GR_COUNT + sof) ||
           insn->qp != 0 || sof > IA64_RSE_PHYS_STACKED_REGS ||
           sol > sof || sor * 8 > sof;
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

static void ia64_tr_plan_ar_write_resources(uint64_t resource[2], uint8_t reg)
{
    ia64_tr_plan_ar_resource(resource, reg);
    if (reg == IA64_AR_BSPSTORE) {
        /* mov-to-BSPSTORE also rebases BSP and invalidates RNAT's value. */
        ia64_tr_plan_ar_resource(resource, IA64_AR_BSP);
        ia64_tr_plan_ar_resource(resource, IA64_AR_RNAT);
    }
}

static void ia64_tr_plan_gr_source(IA64TrInstructionPlan *plan, uint8_t reg)
{
    plan->source_gr[reg >= 64] |= ia64_tr_nonzero_register_bit(reg);
    plan->source_cfm |= reg >= IA64_STATIC_GR_COUNT;
}

static void ia64_tr_plan_gr_destination(IA64TrInstructionPlan *plan,
                                        uint8_t reg, bool must_write)
{
    uint64_t bit = ia64_tr_nonzero_register_bit(reg);

    plan->dest_gr[reg >= 64] |= bit;
    if (must_write) {
        plan->must_gr[reg >= 64] |= bit;
    }
    plan->source_cfm |= reg >= IA64_STATIC_GR_COUNT;
}

static void ia64_tr_rewrite_plan_data_plane(
    IA64TrInstructionPlan *plan, const IA64Instruction *insn,
    const IA64TrDataPlaneDescriptor *descriptor)
{
    bool must_write = insn->qp == 0;
    bool update = insn->reg_base_update || insn->imm_base_update;

    g_assert(descriptor != NULL);
    if (ia64_tr_decoded_is_data_plane_branch(insn->opcode)) {
        if (insn->qp != 0) {
            plan->branch_source_pr = UINT64_C(1) << insn->qp;
        }
        if (descriptor->kind == IA64_TR_DATA_PLANE_CHK_S &&
            !insn->check_fp) {
            ia64_tr_plan_gr_source(plan, insn->r2);
        }
        return;
    }

    if (insn->qp != 0) {
        plan->source_pr = UINT64_C(1) << insn->qp;
    }

    switch (descriptor->kind) {
    case IA64_TR_DATA_PLANE_INTEGER_LOAD:
        if (insn->r1 == 0 || (update && insn->r1 == insn->r3) ||
            (update && insn->r3 == 0)) {
            plan->unconditional_noreturn = must_write;
            return;
        }
        ia64_tr_plan_gr_source(plan, insn->r3);
        if (insn->reg_base_update) {
            ia64_tr_plan_gr_source(plan, insn->r2);
        }
        /* A deferred speculative load retains the old value and sets NaT. */
        if (descriptor->memory_class == 1 ||
            descriptor->memory_class == 3) {
            ia64_tr_plan_gr_source(plan, insn->r1);
        }
        /* A check-load ALAT hit preserves r1, so its destination is optional
           even for p0.  prepare_gr seeds written=0; only a miss/load stages
           a payload. */
        ia64_tr_plan_gr_destination(
            plan, insn->r1,
            must_write && descriptor->memory_class != 8 &&
            descriptor->memory_class != 9);
        if (update) {
            ia64_tr_plan_gr_destination(plan, insn->r3, must_write);
        }
        if (descriptor->memory_class == 6) {
            ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_UNAT);
        }
        return;
    case IA64_TR_DATA_PLANE_INTEGER_SPILL:
        if (update && insn->r3 == 0) {
            plan->unconditional_noreturn = must_write;
            return;
        }
        ia64_tr_plan_gr_source(plan, insn->r3);
        ia64_tr_plan_gr_source(plan, insn->r2);
        if (update) {
            ia64_tr_plan_gr_destination(plan, insn->r3, must_write);
        }
        if (descriptor->width == 8) {
            ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_UNAT);
            ia64_tr_plan_ar_resource(plan->dest_ar, IA64_AR_UNAT);
        }
        return;
    case IA64_TR_DATA_PLANE_WIDE_LOAD:
        if (insn->r1 == 0) {
            plan->unconditional_noreturn = must_write;
            return;
        }
        ia64_tr_plan_gr_source(plan, insn->r3);
        ia64_tr_plan_gr_destination(plan, insn->r1, must_write);
        ia64_tr_plan_ar_resource(plan->dest_ar, IA64_AR_CSD);
        return;
    case IA64_TR_DATA_PLANE_WIDE_STORE:
        ia64_tr_plan_gr_source(plan, insn->r3);
        ia64_tr_plan_gr_source(plan, insn->r2);
        ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_CSD);
        return;
    case IA64_TR_DATA_PLANE_XCHG:
    case IA64_TR_DATA_PLANE_CMPXCHG:
    case IA64_TR_DATA_PLANE_CMP8XCHG16:
        if (insn->r1 == 0) {
            plan->unconditional_noreturn = must_write;
            return;
        }
        ia64_tr_plan_gr_source(plan, insn->r3);
        ia64_tr_plan_gr_source(plan, insn->r2);
        ia64_tr_plan_gr_destination(plan, insn->r1, must_write);
        if (descriptor->kind != IA64_TR_DATA_PLANE_XCHG) {
            ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_CCV);
        }
        if (descriptor->kind == IA64_TR_DATA_PLANE_CMP8XCHG16) {
            ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_CSD);
        }
        return;
    case IA64_TR_DATA_PLANE_FETCHADD:
        if (insn->r1 == 0) {
            plan->unconditional_noreturn = must_write;
            return;
        }
        ia64_tr_plan_gr_source(plan, insn->r3);
        if (insn->imm == 0) {
            ia64_tr_plan_gr_source(plan, insn->r2);
        }
        ia64_tr_plan_gr_destination(plan, insn->r1, must_write);
        return;
    case IA64_TR_DATA_PLANE_FP_LOAD:
    case IA64_TR_DATA_PLANE_FP_LOAD_PAIR:
        ia64_tr_plan_gr_source(plan, insn->r3);
        if (insn->reg_base_update) {
            ia64_tr_plan_gr_source(plan, insn->r2);
        }
        if (update) {
            ia64_tr_plan_gr_destination(plan, insn->r3, must_write);
        }
        return;
    case IA64_TR_DATA_PLANE_FP_STORE:
        ia64_tr_plan_gr_source(plan, insn->r3);
        if (update) {
            ia64_tr_plan_gr_destination(plan, insn->r3, must_write);
        }
        return;
    case IA64_TR_DATA_PLANE_FC:
        ia64_tr_plan_gr_source(plan, insn->r3);
        return;
    case IA64_TR_DATA_PLANE_LFETCH:
        ia64_tr_plan_gr_source(plan, insn->r3);
        if (insn->reg_base_update) {
            ia64_tr_plan_gr_source(plan, insn->r2);
        }
        if (update) {
            ia64_tr_plan_gr_destination(plan, insn->r3, must_write);
        }
        return;
    case IA64_TR_DATA_PLANE_FWB:
    case IA64_TR_DATA_PLANE_INVALA:
    case IA64_TR_DATA_PLANE_INVALAT:
        return;
    case IA64_TR_DATA_PLANE_CHK_S:
    case IA64_TR_DATA_PLANE_CHK_A:
    case IA64_TR_DATA_PLANE_NONE:
    default:
        g_assert_not_reached();
    }
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
        uint64_t started_ns = ia64_perf_clock_ns();

        g_assert(capacity <= UINT16_MAX);
        ctx->rewrite_plan = g_renew(IA64TrInstructionPlan,
                                    ctx->rewrite_plan, capacity);
        IA64_PERF_INC(IA64_PERF_PLAN_ALLOCATION);
        IA64_PERF_ADD(IA64_PERF_PLAN_ALLOCATION_BYTES,
                      capacity * sizeof(IA64TrInstructionPlan));
        IA64_PERF_ADD(IA64_PERF_PLAN_ALLOC_HOST_NS,
                      ia64_perf_clock_ns() - started_ns);
        ctx->rewrite_plan_capacity = capacity;
    }

    plan = &ctx->rewrite_plan[ctx->rewrite_plan_count++];
    memset(plan, 0, sizeof(*plan));
    plan->address = insn->address;
    plan->direct_target =
        (insn->address & ~(uint64_t)(IA64_BUNDLE_SIZE - 1)) + insn->imm;
    plan->opcode = insn->opcode;
    plan->bundle_index = bundle_index;
    plan->slot = insn->slot;
    plan->stop_after = insn->stop_after;
    plan->zero_store_candidate = insn->opcode == IA64_OP_ST1 &&
                                 insn->r2 == 0;
    if (ia64_perf_enabled()) {
        ia64_perf_max(IA64_PERF_PLAN_USE_MAX, ctx->rewrite_plan_count);
    }

    {
        const IA64TrSystemDescriptor *system =
            ia64_tr_decoded_system(insn->opcode);

        if (system != NULL) {
            uint8_t system_sources[3];
            unsigned system_source_count;

            if (system->predicable && insn->qp != 0) {
                plan->source_pr = UINT64_C(1) << insn->qp;
            }
            if (insn->status != IA64_DECODE_OK) {
                plan->unconditional_noreturn =
                    !system->predicable || insn->qp == 0;
                return;
            }

            system_source_count =
                ia64_tr_decoded_sources(insn, system_sources);
            for (unsigned i = 0; i < system_source_count; i++) {
                ia64_tr_plan_gr_source(plan, system_sources[i]);
            }
            if (system->dst_gr_field == IA64_TR_SYSTEM_GR_R1 &&
                !(system->shape == IA64_TR_SYSTEM_SHAPE_PROBE &&
                  insn->probe_fault)) {
                ia64_tr_plan_gr_destination(
                    plan, insn->r1,
                    !system->predicable || insn->qp == 0);
            }
            if (system->src_br_field == IA64_TR_SYSTEM_BR_B2) {
                plan->source_br |= 1u << insn->b2;
            }
            if (system->kind == IA64_TR_SYSTEM_MOV_IMMAR) {
                ia64_tr_plan_ar_write_resources(plan->dest_ar, insn->r2);
                if (insn->r2 == IA64_AR_PFS) {
                    plan->forward_pfs = true;
                    plan->must_pfs = insn->qp == 0;
                }
            }
            if (system->kind == IA64_TR_SYSTEM_BR_IA) {
                plan->unconditional_noreturn = true;
                plan->source_cfm = true;
            } else if (system->kind == IA64_TR_SYSTEM_EPC) {
                plan->branch_source_pfs = true;
                ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_PFS);
            } else if (system->tb_end == IA64_TR_SYSTEM_TB_NORETURN &&
                       (!system->predicable || insn->qp == 0)) {
                plan->unconditional_noreturn = true;
            }
            return;
        }
    }

    if (insn->reserved_memory_width) {
        if (insn->qp != 0) {
            plan->source_pr = UINT64_C(1) << insn->qp;
        } else {
            plan->unconditional_noreturn = true;
        }
        return;
    }

    if (insn->opcode == IA64_OP_ILLEGAL &&
        insn->status == IA64_DECODE_RESERVED_ENCODING) {
        if (insn->qp != 0) {
            plan->source_pr = UINT64_C(1) << insn->qp;
        } else {
            plan->unconditional_noreturn = true;
        }
        return;
    }

    if (ia64_tr_decoded_is_noop(insn->opcode)) {
        return;
    }

    const IA64TrFpDescriptor *fp =
        ia64_tr_decoded_fp_compute(insn->opcode);

    if (fp != NULL) {
        if (ia64_tr_decoded_is_fp_status_branch(insn->opcode)) {
            ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_FPSR);
            if (insn->qp != 0) {
                plan->branch_source_pr = UINT64_C(1) << insn->qp;
            }
            return;
        }
        if (insn->qp != 0) {
            plan->source_pr = UINT64_C(1) << insn->qp;
        }
        if (insn->opcode == IA64_OP_FCLASS) {
            if (insn->p1 == insn->p2) {
                if (insn->compare_unc || insn->qp == 0) {
                    plan->unconditional_noreturn = true;
                }
                return;
            }
            if (insn->p1 != 0) {
                plan->dest_pr |= UINT64_C(1) << insn->p1;
            }
            if (insn->p2 != 0) {
                plan->dest_pr |= UINT64_C(1) << insn->p2;
            }
            if (insn->compare_unc || insn->qp == 0) {
                plan->must_pr = plan->dest_pr;
            }
            return;
        }
        if (ia64_tr_fp_is_status_control(insn->opcode)) {
            ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_FPSR);
            ia64_tr_plan_ar_resource(plan->dest_ar, IA64_AR_FPSR);
            return;
        }
        if (fp->owner == IA64_TR_FP_FOCUSED &&
            insn->opcode == IA64_OP_FCMP) {
            if (insn->p1 == insn->p2) {
                if (insn->compare_unc || insn->qp == 0) {
                    plan->unconditional_noreturn = true;
                }
                return;
            }
            if (insn->p1 != 0) {
                plan->dest_pr |= UINT64_C(1) << insn->p1;
            }
            if (insn->p2 != 0) {
                plan->dest_pr |= UINT64_C(1) << insn->p2;
            }
            plan->forward_pr = plan->dest_pr;
            if (insn->compare_unc || insn->qp == 0) {
                plan->must_pr = plan->dest_pr;
            }
            return;
        }
        if (fp->owner == IA64_TR_FP_FOCUSED &&
            ia64_tr_fp_is_approximation(insn->opcode)) {
            if (insn->p2 != 0) {
                plan->dest_pr |= UINT64_C(1) << insn->p2;
                plan->forward_pr |= UINT64_C(1) << insn->p2;
                /* The architected pre-qualification clear always writes. */
                plan->must_pr |= UINT64_C(1) << insn->p2;
            }
        }
        if (ia64_tr_fp_is_getf(insn->opcode)) {
            ia64_tr_plan_gr_destination(plan, insn->r1, insn->qp == 0);
            if (insn->r1 == 0) {
                plan->unconditional_noreturn = insn->qp == 0;
            }
        } else if (ia64_tr_fp_is_setf(insn->opcode)) {
            ia64_tr_plan_gr_source(plan, insn->r2);
        }
        if (ia64_tr_fp_has_fr_destination(insn->opcode) && insn->r1 < 2) {
            plan->unconditional_noreturn = insn->qp == 0;
        }
        return;
    }

    if (ia64_tr_decoded_is_rfi(insn->opcode)) {
        /* RFI restores its complete source image from interruption state. */
        plan->unconditional_noreturn = true;
        return;
    }

    if (ia64_tr_decoded_is_rse_spine(insn->opcode)) {
        plan->source_cfm = true;
        switch (insn->opcode) {
        case IA64_OP_ALLOC:
            ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_PFS);
            ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_BSP);
            ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_BSPSTORE);
            ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_RNAT);
            ia64_tr_plan_ar_resource(plan->dest_ar, IA64_AR_BSPSTORE);
            ia64_tr_plan_ar_resource(plan->dest_ar, IA64_AR_RNAT);
            plan->dest_cfm = true;
            if (insn->r1 != 0) {
                uint64_t bit = ia64_tr_nonzero_register_bit(insn->r1);

                plan->dest_gr[insn->r1 >= 64] = bit;
                plan->must_gr[insn->r1 >= 64] = bit;
            }
            break;
        case IA64_OP_COVER:
            ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_BSP);
            ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_BSPSTORE);
            ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_RNAT);
            ia64_tr_plan_ar_resource(plan->dest_ar, IA64_AR_BSP);
            ia64_tr_plan_ar_resource(plan->dest_ar, IA64_AR_RNAT);
            plan->dest_cfm = true;
            break;
        case IA64_OP_FLUSHRS:
            ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_BSP);
            ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_BSPSTORE);
            ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_RNAT);
            ia64_tr_plan_ar_resource(plan->dest_ar, IA64_AR_BSPSTORE);
            ia64_tr_plan_ar_resource(plan->dest_ar, IA64_AR_RNAT);
            break;
        case IA64_OP_LOADRS:
            ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_RSC);
            ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_BSP);
            ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_BSPSTORE);
            ia64_tr_plan_ar_resource(plan->source_ar, IA64_AR_RNAT);
            ia64_tr_plan_ar_resource(plan->dest_ar, IA64_AR_BSPSTORE);
            ia64_tr_plan_ar_resource(plan->dest_ar, IA64_AR_RNAT);
            break;
        case IA64_OP_CLRRRB:
        case IA64_OP_CLRRRB_PR:
            plan->dest_cfm = true;
            break;
        default:
            g_assert_not_reached();
        }
        return;
    }

    if (ia64_tr_decoded_data_plane(insn->opcode) != NULL) {
        ia64_tr_rewrite_plan_data_plane(
            plan, insn, ia64_tr_decoded_data_plane(insn->opcode));
        return;
    }

    if (ia64_tr_decoded_is_ordinary_integer_memory(insn->opcode)) {
        bool load =
            ia64_tr_decoded_is_ordinary_integer_load(insn->opcode);
        bool update = insn->reg_base_update || insn->imm_base_update;
        bool statically_illegal =
            ia64_tr_decoded_ordinary_integer_memory_statically_illegal(
                insn);

        if (insn->qp != 0) {
            plan->source_pr = UINT64_C(1) << insn->qp;
        }
        if (statically_illegal) {
            plan->unconditional_noreturn = insn->qp == 0;
            return;
        }

        plan->source_gr[insn->r3 >= 64] |=
            ia64_tr_nonzero_register_bit(insn->r3);
        if ((load && insn->reg_base_update) || !load) {
            plan->source_gr[insn->r2 >= 64] |=
                ia64_tr_nonzero_register_bit(insn->r2);
        }
        if (load) {
            uint64_t target = ia64_tr_nonzero_register_bit(insn->r1);

            plan->dest_gr[insn->r1 >= 64] |= target;
            if (insn->qp == 0) {
                plan->must_gr[insn->r1 >= 64] |= target;
            }
            plan->source_cfm = insn->r1 >= IA64_STATIC_GR_COUNT;
        }
        if (update) {
            uint64_t base = ia64_tr_nonzero_register_bit(insn->r3);

            plan->dest_gr[insn->r3 >= 64] |= base;
            if (insn->qp == 0) {
                plan->must_gr[insn->r3 >= 64] |= base;
            }
            plan->source_cfm |= insn->r3 >= IA64_STATIC_GR_COUNT;
        }
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
        if (insn->qp != 0) {
            plan->source_pr = UINT64_C(1) << insn->qp;
        }
        if (insn->status != IA64_DECODE_OK) {
            plan->unconditional_noreturn = insn->qp == 0;
            return;
        }
        g_assert(ia64_tr_decoded_is_supported_application_move(insn));
        ia64_tr_plan_ar_resource(plan->source_ar, insn->r2);
        ia64_tr_plan_gr_destination(plan, insn->r1, insn->qp == 0);
        return;
    }

    if (insn->opcode == IA64_OP_MOV_GRAR) {
        unsigned half = insn->r1 >= 64;

        if (insn->qp != 0) {
            plan->source_pr = UINT64_C(1) << insn->qp;
        }
        if (insn->status != IA64_DECODE_OK) {
            plan->unconditional_noreturn = insn->qp == 0;
            return;
        }
        g_assert(ia64_tr_decoded_is_supported_application_move(insn));
        plan->source_gr[half] =
            ia64_tr_nonzero_register_bit(insn->r1);
        ia64_tr_plan_ar_write_resources(plan->dest_ar, insn->r2);
        if (insn->r2 == IA64_AR_PFS) {
            plan->forward_pfs = true;
            plan->must_pfs = insn->qp == 0;
        }
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

/*
 * Translation-only classification of the architecture WP0 is intended to
 * replace.  It deliberately emits no guest code and changes no admission or
 * lowering decision: the resulting execution weights come solely from the
 * existing sampled-TB mechanism.
 */
static void ia64_tr_profile_group_census(DisasContext *ctx)
{
    IA64ProfileTbShape *shape = &ctx->profile_shape;
    unsigned slots = ctx->rewrite_plan_emit_count;
    unsigned destinations = 0;
    bool complete;
    bool memory = false;
    bool helper = false;
    bool control = false;
    bool rse = false;
    bool system = false;
    bool loop = false;
    bool loop_self = false;
    bool zero_store = false;

    if (!ctx->profile_enabled || slots == 0) {
        return;
    }

    complete = ctx->rewrite_plan[slots - 1].stop_after ||
               ctx->rewrite_plan[slots - 1].unconditional_noreturn;
    for (unsigned i = 0; i < slots; i++) {
        const IA64TrInstructionPlan *plan = &ctx->rewrite_plan[i];
        const IA64OpcodeTraits *traits =
            ia64_opcode_traits_for(plan->opcode);
        uint32_t states;
        bool slot_memory;

        destinations += ctpop64(plan->dest_gr[0]) +
                        ctpop64(plan->dest_gr[1]) +
                        ctpop64(plan->dest_pr) + ctpop32(plan->dest_br) +
                        ctpop64(plan->dest_ar[0]) +
                        ctpop64(plan->dest_ar[1]) + plan->dest_cfm;
        if (traits == NULL || traits->family == NULL) {
            system = true;
            continue;
        }
        states = traits->family->sources | traits->family->destinations;
        slot_memory = (states & IA64_OPCODE_STATE_MEMORY) != 0 ||
                      (traits->family->may_fault &
                       IA64_OPCODE_FAULT_MEMORY) != 0;
        memory |= slot_memory;
        helper |= traits->lowering_owner == IA64_OPCODE_OWNER_FOCUSED_HELPER;
        control |= traits->family->tb_behavior != IA64_OPCODE_TB_CONTINUE;
        rse |= (states & IA64_OPCODE_STATE_RSE) != 0 ||
               (traits->family->may_fault & IA64_OPCODE_FAULT_RSE) != 0;
        system |= (states & (IA64_OPCODE_STATE_CR |
                             IA64_OPCODE_STATE_PSR |
                             IA64_OPCODE_STATE_TRANSLATION |
                             IA64_OPCODE_STATE_INTERRUPT)) != 0;
        loop |= ia64_tr_decoded_is_loop_branch(plan->opcode);
        if (ia64_tr_decoded_is_loop_branch(plan->opcode)) {
            loop_self |= plan->direct_target == ctx->base.pc_first;
        }
        zero_store |= plan->zero_store_candidate;
        if ((states & IA64_OPCODE_STATE_GR) != 0 &&
            (states & (IA64_OPCODE_STATE_MEMORY |
                       IA64_OPCODE_STATE_RSE |
                       IA64_OPCODE_STATE_CONTROL)) == 0) {
            shape->counter[IA64_PROFILE_COMMON_INTEGER_SLOT]++;
        }
        if ((traits->family->destinations & IA64_OPCODE_STATE_PR) != 0) {
            shape->counter[IA64_PROFILE_COMMON_PREDICATE_SLOT]++;
        }
        if (traits->family->tb_behavior != IA64_OPCODE_TB_CONTINUE ||
            (states & IA64_OPCODE_STATE_CONTROL) != 0) {
            shape->counter[IA64_PROFILE_COMMON_BRANCH_SLOT]++;
        }
        if (slot_memory) {
            shape->counter[IA64_PROFILE_COMMON_MEMORY_SLOT]++;
        }
        if (ia64_tr_decoded_is_loop_branch(plan->opcode)) {
            shape->counter[IA64_PROFILE_COMMON_LOOP_SLOT]++;
        }
    }

    shape->counter[IA64_PROFILE_SLOT_EXECUTED] += slots;
    shape->group_length[MIN(slots, IA64_PROFILE_GROUP_HIST_MAX)]++;
    shape->group_destination[
        MIN(destinations, IA64_PROFILE_GROUP_HIST_MAX)]++;
    if (loop) {
        if (!loop_self) {
            shape->counter[IA64_PROFILE_LOOP_REJECT_NOT_SELF]++;
        } else if (rse || system || helper) {
            shape->counter[IA64_PROFILE_LOOP_REJECT_OBSERVATION]++;
        } else if (!complete) {
            shape->counter[IA64_PROFILE_LOOP_REJECT_BODY]++;
        } else {
            shape->counter[IA64_PROFILE_LOOP_RECOGNIZED]++;
            if (zero_store) {
                shape->counter[IA64_PROFILE_LOOP_ZERO_STORE]++;
                shape->counter[IA64_PROFILE_LOOP_SLOW_FALLBACK]++;
            }
        }
    }

    if (rse || system || ctx->base.plugin_enabled) {
        shape->counter[IA64_PROFILE_SHAPE_C_GROUP]++;
        shape->counter[IA64_PROFILE_SHAPE_C_SLOT] += slots;
        if (rse) {
            shape->counter[IA64_PROFILE_SHAPE_C_RSE]++;
        } else if (system) {
            shape->counter[IA64_PROFILE_SHAPE_C_SYSTEM]++;
        } else {
            shape->counter[IA64_PROFILE_SHAPE_C_OBSERVATION]++;
        }
    } else if (complete && !memory && !helper) {
        shape->counter[IA64_PROFILE_SHAPE_A_GROUP]++;
        shape->counter[IA64_PROFILE_SHAPE_A_SLOT] += slots;
    } else {
        shape->counter[IA64_PROFILE_SHAPE_B_GROUP]++;
        shape->counter[IA64_PROFILE_SHAPE_B_SLOT] += slots;
    }

    if (!complete) {
        uint64_t next_bundle =
            (ctx->rewrite_plan[slots - 1].address & ~UINT64_C(0xf)) +
            IA64_BUNDLE_SIZE;

        shape->counter[IA64_PROFILE_GROUP_TB_CROSSING]++;
        if ((next_bundle & TARGET_PAGE_MASK) !=
            (ctx->base.pc_first & TARGET_PAGE_MASK)) {
            shape->counter[IA64_PROFILE_GROUP_PAGE_CROSSING]++;
        }
    }
    if (memory) {
        ctx->profile_end_reason = IA64_PROFILE_TB_END_MEMORY;
    } else if (helper) {
        ctx->profile_end_reason = IA64_PROFILE_TB_END_HELPER;
    } else if (control) {
        ctx->profile_end_reason = IA64_PROFILE_TB_END_BRANCH;
    }
}

static void ia64_tr_perf_plan_census(DisasContext *ctx)
{
    bool memory = false;
    bool helper = false;
    bool control = false;
    bool page = false;

    if (!ia64_perf_enabled()) {
        return;
    }
    for (unsigned i = 0; i < ctx->rewrite_plan_emit_count; i++) {
        const IA64TrInstructionPlan *plan = &ctx->rewrite_plan[i];
        const IA64OpcodeTraits *traits =
            ia64_opcode_traits_for(plan->opcode);
        uint64_t sources = ctpop64(plan->source_gr[0]) +
                           ctpop64(plan->source_gr[1]);

        ia64_perf_add(IA64_PERF_NAT_UNKNOWN, sources);
        ia64_perf_add(IA64_PERF_NAT_DYNAMIC_LOAD, sources);
        if (traits == NULL || traits->family == NULL) {
            helper = true;
            continue;
        }
        memory |= ((traits->family->sources |
                    traits->family->destinations) &
                   IA64_OPCODE_STATE_MEMORY) != 0 ||
                  (traits->family->may_fault & IA64_OPCODE_FAULT_MEMORY) != 0;
        helper |= traits->lowering_owner ==
                  IA64_OPCODE_OWNER_FOCUSED_HELPER;
        control |= traits->family->tb_behavior != IA64_OPCODE_TB_CONTINUE;
        if (((traits->family->sources | traits->family->destinations) &
             IA64_OPCODE_STATE_RSE) != 0) {
            ia64_perf_count(IA64_PERF_NAT_RSE_UNKNOWN);
            ia64_perf_count(IA64_PERF_NAT_LATTICE_INVALIDATE);
        }
        if (traits->family->nat_rule == IA64_OPCODE_NAT_NONE) {
            ia64_perf_add(IA64_PERF_NAT_KNOWN_CLEAR,
                          ctpop64(plan->dest_gr[0]) +
                          ctpop64(plan->dest_gr[1]));
        }
    }
    if (ctx->rewrite_plan_emit_count != 0 &&
        !ctx->rewrite_plan[ctx->rewrite_plan_emit_count - 1].stop_after) {
        uint64_t next_bundle =
            (ctx->rewrite_plan[ctx->rewrite_plan_emit_count - 1].address &
             ~UINT64_C(0xf)) + IA64_BUNDLE_SIZE;

        page = (next_bundle & TARGET_PAGE_MASK) !=
               (ctx->base.pc_first & TARGET_PAGE_MASK);
    }
    if (memory) {
        ia64_perf_count(IA64_PERF_PLAN_END_MEMORY);
    } else if (helper) {
        ia64_perf_count(IA64_PERF_PLAN_END_HELPER);
    } else if (control) {
        ia64_perf_count(IA64_PERF_PLAN_END_BRANCH);
    } else if (page) {
        ia64_perf_count(IA64_PERF_PLAN_END_PAGE);
    } else {
        ia64_perf_count(IA64_PERF_PLAN_END_OTHER);
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
    IA64_PERF_ADD(IA64_PERF_PLAN_USE, ctx->rewrite_plan_emit_count);

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
    ia64_tr_profile_group_census(ctx);
    ia64_tr_perf_plan_census(ctx);
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
 * the bundle contains encodings after it.  Loop forms and checked branches
 * remain dynamic state machines even when their encoded predicate is p0 and
 * therefore never use this truncation rule.  RFI is an unconditional typed
 * transfer and uses the same terminal-prefix rule.
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
        if (!ia64_tr_decoded_is_conditional_branch(insn->opcode) &&
            !ia64_tr_decoded_is_rfi(insn->opcode)) {
            continue;
        }
        found_branch = true;
        if (ia64_tr_decoded_is_rfi(insn->opcode)) {
            *last_slot = slot + insn->slot_span - 1;
            return ia64_tr_preflight_decoded_bundle_through(decoded,
                                                             *last_slot);
        }
        if (insn->qp == 0) {
            if (ia64_tr_decoded_is_loop_branch(insn->opcode) ||
                ia64_tr_decoded_is_data_plane_branch(insn->opcode) ||
                ia64_tr_decoded_is_fp_status_branch(insn->opcode)) {
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

static IA64TrSystemTbEnd ia64_tr_first_system_tb_end(
    const IA64DecodedInstructionBundle *decoded, uint8_t *physical_last_slot)
{
    IA64TrSystemTbEnd bundle_end = IA64_TR_SYSTEM_TB_CONTINUE;

    for (unsigned slot = decoded->start_slot;
         slot < IA64_SLOT_COUNT; slot++) {
        const IA64Instruction *insn;
        const IA64TrSystemDescriptor *system;

        if ((decoded->instruction_mask & (1u << slot)) == 0) {
            continue;
        }
        insn = &decoded->instruction[slot];
        system = ia64_tr_decoded_system(insn->opcode);
        if (system == NULL ||
            system->tb_end == IA64_TR_SYSTEM_TB_CONTINUE) {
            continue;
        }
        if (system->tb_end == IA64_TR_SYSTEM_TB_NEXT_SLOT ||
            system->tb_end == IA64_TR_SYSTEM_TB_CONTROL ||
            system->tb_end == IA64_TR_SYSTEM_TB_NORETURN) {
            *physical_last_slot = slot + insn->slot_span - 1;
            return system->tb_end;
        }
        /*
         * A bundle-ending operation still executes every later slot.  Keep
         * scanning because a later serialization/control operation can end
         * the emitted prefix at its exact slot.  For example, the firmware's
         * canonical `rsm ;; srlz.d` bundle must resume at RI 2 rather than
         * planning that slot and then leaving it unlowered.
         */
        g_assert(system->tb_end == IA64_TR_SYSTEM_TB_BUNDLE ||
                 system->tb_end == IA64_TR_SYSTEM_TB_CONDITIONAL_BUNDLE);
        if (bundle_end == IA64_TR_SYSTEM_TB_CONTINUE) {
            bundle_end = system->tb_end;
        }
    }
    if (bundle_end != IA64_TR_SYSTEM_TB_CONTINUE) {
        *physical_last_slot = IA64_SLOT_COUNT - 1;
    }
    return bundle_end;
}

static bool ia64_tr_first_rse_static_noreturn(
    const IA64DecodedInstructionBundle *decoded, uint8_t *physical_last_slot)
{
    if (physical_last_slot == NULL) {
        return false;
    }
    for (unsigned slot = decoded->start_slot;
         slot < IA64_SLOT_COUNT; slot++) {
        const IA64Instruction *insn;

        if ((decoded->instruction_mask & (1u << slot)) == 0) {
            continue;
        }
        insn = &decoded->instruction[slot];
        if (ia64_tr_rse_spine_is_static_noreturn(insn)) {
            *physical_last_slot = slot + insn->slot_span - 1;
            return true;
        }
    }
    return false;
}

static bool ia64_tr_decoded_bundle_has_system(
    const IA64DecodedInstructionBundle *decoded)
{
    for (unsigned slot = decoded->start_slot;
         slot < IA64_SLOT_COUNT; slot++) {
        if ((decoded->instruction_mask & (1u << slot)) != 0 &&
            ia64_tr_decoded_system(decoded->instruction[slot].opcode) !=
                NULL) {
            return true;
        }
    }
    return false;
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
    uint64_t pc, uint8_t start_slot, unsigned *bundle_count,
    uint8_t *last_slot)
{
    IA64DecodedBundle loaded_bundle;
    const IA64DecodedBundle *bundle = first_bundle;
    uint64_t scan_pc = pc;
    uint8_t scan_start_slot = start_slot;
    bool group_start = ctx->instruction_group_start;
    unsigned validated_bundles = 0;
    unsigned segment_bundles;
    bool shortened_for_tb_limit;
    bool shortened_for_plugin = false;
    bool shortened_for_op_budget = false;
    uint8_t validated_last_slot = IA64_SLOT_COUNT - 1;
    int remaining_bundles =
        ctx->base.max_insns - ctx->base.num_insns + 1;

    g_assert(ctx->rewrite_plan_count == 0 &&
             ctx->rewrite_plan_emit_count == 0 &&
             ctx->rewrite_plan_index == 0);
    if ((!ctx->instruction_group_start && !ctx->typed_group_active) ||
        !bundle_count || !last_slot || remaining_bundles <= 0) {
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
        uint8_t accepted_last_slot = IA64_SLOT_COUNT - 1;
        uint8_t branch_last_slot = IA64_SLOT_COUNT - 1;
        uint8_t system_last_slot = IA64_SLOT_COUNT - 1;
        uint8_t rse_last_slot = IA64_SLOT_COUNT - 1;
        bool end_region = false;
        bool branch_cfg;
        bool rse_static_noreturn;
        bool has_system;
        IA64TrSystemTbEnd system_tb_end;

        if (bundle_index != 0) {
            uint64_t lo;
            uint64_t hi;

            if (!translator_is_same_page(&ctx->base, scan_pc)) {
                goto reject;
            }
            lo = translator_ldq_end(ctx->env, &ctx->base, scan_pc, MO_LE);
            hi = translator_ldq_end(ctx->env, &ctx->base, scan_pc + 8,
                                    MO_LE);
            ia64_decode_bundle_words(lo, hi, &loaded_bundle);
            bundle = &loaded_bundle;
            /*
             * Retire an already validated prefix before attributing an
             * invalid-template fault to the following bundle.  Rejecting the
             * whole translation-time group here would turn guest input into
             * a host-fatal typed-admission failure.
             */
            if (!bundle->valid) {
                break;
            }
        }

        if (!ia64_decode_instruction_bundle(bundle, scan_pc, group_start,
                                             scan_start_slot, &decoded)) {
            goto reject;
        }
        branch_cfg = ia64_tr_preflight_branch_cfg(
            &decoded, &branch_last_slot);
        system_tb_end = ia64_tr_first_system_tb_end(
            &decoded, &system_last_slot);
        rse_static_noreturn = ia64_tr_first_rse_static_noreturn(
            &decoded, &rse_last_slot);
        has_system = ia64_tr_decoded_bundle_has_system(&decoded);
        (void)has_system;
        if (system_tb_end != IA64_TR_SYSTEM_TB_CONTINUE || branch_cfg ||
            rse_static_noreturn) {
            /*
             * Select the earliest exact terminal prefix.  Bundle-ending
             * system rows and conditional branch CFGs naturally retain slot
             * 2; a p0 branch, exact system exit, or statically faulting RSE
             * row can shorten the admitted physical prefix.
             */
            if (system_tb_end == IA64_TR_SYSTEM_TB_NEXT_SLOT ||
                system_tb_end == IA64_TR_SYSTEM_TB_CONTROL ||
                system_tb_end == IA64_TR_SYSTEM_TB_NORETURN) {
                accepted_last_slot = MIN(accepted_last_slot,
                                         system_last_slot);
            }
            if (branch_cfg) {
                accepted_last_slot = MIN(accepted_last_slot,
                                         branch_last_slot);
            }
            if (rse_static_noreturn) {
                accepted_last_slot = MIN(accepted_last_slot, rse_last_slot);
            }
            if (!ia64_tr_preflight_decoded_bundle_through(
                    &decoded, accepted_last_slot)) {
                goto reject;
            }
            validated_last_slot = accepted_last_slot;
            end_region = true;
        } else if (!ia64_tr_preflight_decoded_bundle(&decoded)) {
            goto reject;
        }
        ia64_tr_rewrite_plan_append_bundle(
            ctx, &decoded, bundle_index, accepted_last_slot);
        validated_bundles = bundle_index + 1;
        if (ia64_tr_decoded_bundle_requires_io_boundary(
                &decoded, accepted_last_slot)) {
            end_region = true;
        }
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
    shortened_for_tb_limit = segment_bundles < validated_bundles;
    if (ctx->base.plugin_enabled) {
        /* Plugin post-insn ops are emitted after translate_insn returns. */
        shortened_for_plugin = segment_bundles > 1;
        segment_bundles = MIN(segment_bundles, 1u);
    }
    while (segment_bundles != 0 &&
           !tcg_op_buf_has_space(
               (size_t)segment_bundles * IA64_TR_REWRITE_OPS_PER_BUNDLE +
               IA64_TR_REWRITE_EXIT_OPS)) {
        shortened_for_op_budget = true;
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
    IA64_PERF_INC(IA64_PERF_PLAN_PREFLIGHT_SUCCESS);
    if (shortened_for_tb_limit) {
        IA64_PERF_INC(IA64_PERF_PLAN_SHORTEN_TB_LIMIT);
    }
    if (shortened_for_plugin) {
        IA64_PERF_INC(IA64_PERF_PLAN_SHORTEN_PLUGIN);
    }
    if (shortened_for_op_budget) {
        IA64_PERF_INC(IA64_PERF_PLAN_SHORTEN_OP_BUDGET);
    }
    return true;

reject:
    IA64_PERF_INC(IA64_PERF_PLAN_PREFLIGHT_REJECT);
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

    if (ia64_tr_decoded_fp_compute(insn->opcode) != NULL) {
        if (ctx->state_cache_active) {
            ia64_tr_ensure_pr(ctx);
        }
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

static void ia64_tr_emit_decoded_register_nat_consumption_isr(
    DisasContext *ctx, const IA64Instruction *insn, uint64_t isr_extra)
{
    /* The current PR image remains staged; only the ordered prefix retires. */
    ia64_tr_group_publish_prefix_for_noreturn_fault(ctx);
    tcg_gen_movi_i64(cpu_ip, insn->address);
    ia64_tr_publish_fault_state(insn->address, insn->slot,
                                ia64_tr_decoded_slot_type(insn->unit),
                                insn->raw, insn->starts_group);
    gen_helper_raise_register_nat_consumption(
        tcg_env, tcg_constant_i64(isr_extra));
}

static void ia64_tr_emit_decoded_register_nat_consumption(
    DisasContext *ctx, const IA64Instruction *insn)
{
    ia64_tr_emit_decoded_register_nat_consumption_isr(ctx, insn, 0);
}

static void ia64_tr_emit_decoded_data_nat_consumption(
    DisasContext *ctx, const IA64Instruction *insn,
    int32_t access_type)
{
    ia64_tr_group_publish_prefix_for_noreturn_fault(ctx);
    tcg_gen_movi_i64(cpu_ip, insn->address);
    ia64_tr_publish_fault_state(insn->address, insn->slot,
                                ia64_tr_decoded_slot_type(insn->unit),
                                insn->raw, insn->starts_group);
    gen_helper_raise_data_register_nat_consumption(
        tcg_env, tcg_constant_i32(access_type));
}

static void ia64_tr_emit_decoded_unaligned_data_reference(
    DisasContext *ctx, const IA64Instruction *insn, TCGv_i64 address,
    uint8_t payload_size, MMUAccessType access_type)
{
    ia64_tr_group_publish_prefix_for_noreturn_fault(ctx);
    tcg_gen_movi_i64(cpu_ip, insn->address);
    ia64_tr_publish_fault_state(insn->address, insn->slot,
                                ia64_tr_decoded_slot_type(insn->unit),
                                insn->raw, insn->starts_group);
    gen_helper_data_unaligned_pre_access(
        tcg_env, address, tcg_constant_i32(payload_size),
        tcg_constant_i32(access_type),
        tcg_constant_i32(ia64_tr_data_mmu_index(ctx)));
    gen_helper_raise_unaligned_data_reference(
        tcg_env, address, tcg_constant_i32(access_type));
}

static void ia64_tr_emit_decoded_memory_nat_check(
    DisasContext *ctx, const IA64Instruction *insn, TCGv_i64 nat,
    int32_t access_type, bool non_access)
{
    TCGLabel *valid = gen_new_label();
    int32_t exception_access_type = access_type;

    if (non_access) {
        switch (access_type) {
        case MMU_DATA_LOAD:
            exception_access_type =
                IA64_EXCEPTION_ACCESS_READ_NON_ACCESS;
            break;
        case MMU_DATA_STORE:
            exception_access_type =
                IA64_EXCEPTION_ACCESS_WRITE_NON_ACCESS;
            break;
        case IA64_EXCEPTION_ACCESS_SEMAPHORE:
            exception_access_type =
                IA64_EXCEPTION_ACCESS_SEMAPHORE_NON_ACCESS;
            break;
        default:
            g_assert_not_reached();
        }
    }

    tcg_gen_brcondi_i64(TCG_COND_EQ, nat, 0, valid);
    ia64_tr_emit_decoded_data_nat_consumption(
        ctx, insn, exception_access_type);
    gen_set_label(valid);
}

static void ia64_tr_emit_decoded_memory_target_check(
    DisasContext *ctx, const IA64Instruction *insn, uint8_t reg)
{
    TCGLabel *valid;
    TCGv_i32 sof;

    g_assert(reg != 0);
    if (reg < IA64_STATIC_GR_COUNT) {
        return;
    }

    valid = gen_new_label();
    sof = ia64_tr_scratch_i32(ctx);
    tcg_gen_ld_i32(sof, tcg_env, offsetof(CPUIA64State, rse.sof));
    tcg_gen_brcondi_i32(TCG_COND_GTU, sof,
                        reg - IA64_STATIC_GR_COUNT, valid);
    ia64_tr_emit_decoded_illegal_operation(ctx, insn);
    gen_set_label(valid);
}

static void ia64_tr_emit_decoded_memory_alignment_span_check(
    DisasContext *ctx, const IA64Instruction *insn, TCGv_i64 address,
    uint8_t alignment, uint8_t payload_size, MMUAccessType access_type)
{
    TCGLabel *valid;
    TCGLabel *fault;
    TCGv_i64 misalignment;
    TCGv_i64 psr;
    TCGv_i64 page_offset;

    if (alignment <= 1) {
        return;
    }

    valid = gen_new_label();
    fault = gen_new_label();
    misalignment = ia64_tr_scratch_i64(ctx);
    psr = ia64_tr_scratch_i64(ctx);
    page_offset = ia64_tr_scratch_i64(ctx);

    tcg_gen_andi_i64(misalignment, address, alignment - 1);
    tcg_gen_brcondi_i64(TCG_COND_EQ, misalignment, 0, valid);
    tcg_gen_ld_i64(psr, tcg_env, offsetof(CPUIA64State, psr));
    tcg_gen_brcondi_i64(TCG_COND_TSTNE, psr, IA64_TR_PSR_AC_BIT,
                        fault);
    tcg_gen_andi_i64(page_offset, address, 0xfff);
    tcg_gen_brcondi_i64(TCG_COND_LEU, page_offset,
                        0x1000 - payload_size,
                        valid);
    gen_set_label(fault);
    ia64_tr_emit_decoded_unaligned_data_reference(
        ctx, insn, address, payload_size, access_type);
    gen_set_label(valid);
}

static void ia64_tr_emit_decoded_memory_alignment_check(
    DisasContext *ctx, const IA64Instruction *insn, TCGv_i64 address,
    uint8_t width, MMUAccessType access_type)
{
    ia64_tr_emit_decoded_memory_alignment_span_check(
        ctx, insn, address, width, width, access_type);
}

static void ia64_tr_publish_decoded_memory_access(
    DisasContext *ctx, const IA64Instruction *insn)
{
    bool speculative_load = insn->fp_load_speculative;

    /*
     * A direct SoftMMU access may longjmp, but may also return.  Export the
     * eagerly retired cache prefix without destroying the group-entry source
     * overlay, then publish the exact restart slot before the access.
     */
    /*
     * Make this bundle the final common-translator instruction in its TB.
     * Under icount that causes the generic prologue to publish can_do_io only
     * at this bundle's insn_start; an earlier MMIO encounter therefore exits
     * through cpu_io_recompile without executing an architectural prefix
     * twice.  Never manufacture can_do_io in the middle of the instruction.
     */
    translator_io_start(&ctx->base);
    ia64_tr_sync_state_cache(ctx);
    tcg_gen_movi_i64(cpu_ip, insn->address);
    ia64_tr_publish_fault_state(insn->address, insn->slot,
                                ia64_tr_decoded_slot_type(insn->unit),
                                insn->raw, insn->starts_group);
    switch (insn->opcode) {
    case IA64_OP_LD1S:
    case IA64_OP_LD2S:
    case IA64_OP_LD4S:
    case IA64_OP_LD8S:
    case IA64_OP_LD1SA:
    case IA64_OP_LD2SA:
    case IA64_OP_LD4SA:
    case IA64_OP_LD8SA:
        speculative_load = true;
        break;
    default:
        break;
    }
    tcg_gen_st8_i32(tcg_constant_i32(speculative_load), tcg_env,
                    offsetof(CPUIA64State,
                             current_slot_speculative_load));
}

static void ia64_tr_emit_decoded_data_debug_pre_access(
    DisasContext *ctx, TCGv_i64 address, uint8_t size, uint32_t access)
{
    /*
     * Data breakpoints can match only while PSR.db=1 and PSR.dd=0.  Keep the
     * complete architectural matcher as the active TB shape, but emit no
     * debug work in the normal inactive shape.  Every guest PSR writer is an
     * existing TB endpoint, so the TB key is authoritative for all slots.
     */
    if (ia64_tr_debug_fast_guard_enabled() &&
        (ctx->base.tb->flags & IA64_TB_FLAG_DATA_DEBUG_ACTIVE) == 0) {
        return;
    }
    gen_helper_data_debug_pre_access(
        tcg_env, address, tcg_constant_i32(size),
        tcg_constant_i32(access),
        tcg_constant_i32(ia64_tr_data_mmu_index(ctx)));
}

static void ia64_tr_emit_decoded_store_alat_invalidate(
    DisasContext *ctx, TCGv_i64 address, uint8_t width)
{
    TCGLabel *done = gen_new_label();
    TCGv_i32 valid = ia64_tr_scratch_i32(ctx);

    tcg_gen_ld_i32(valid, tcg_env,
                   offsetof(CPUIA64State, alat.valid_mask));
    tcg_gen_brcondi_i32(TCG_COND_EQ, valid, 0, done);
    gen_helper_memory_store_alat_invalidate(
        tcg_env, address, tcg_constant_i32(width));
    gen_set_label(done);
}

static void ia64_tr_emit_decoded_ordinary_integer_memory(
    DisasContext *ctx, const IA64Instruction *insn)
{
    bool load = ia64_tr_decoded_is_ordinary_integer_load(insn->opcode);
    bool update = insn->reg_base_update || insn->imm_base_update;
    uint8_t width = ia64_tr_decoded_integer_memory_width(insn->opcode);
    MMUAccessType access_type = load ? MMU_DATA_LOAD : MMU_DATA_STORE;
    IA64TrGrWrite *target_write = NULL;
    IA64TrGrWrite *base_write = NULL;
    TCGLabel *skip;
    TCGv_i64 base;
    TCGv_i64 base_nat;
    TCGv_i64 operand;
    TCGv_i64 operand_nat;
    TCGv_i64 result;
    TCGv_i64 updated;

    g_assert(ia64_tr_decoded_is_supported_ordinary_integer_memory(insn));
    ia64_tr_prime_decoded_instruction_state(ctx, insn);

    /* Every statically illegal form remains suppressed by a false qp. */
    if (ia64_tr_decoded_ordinary_integer_memory_statically_illegal(insn)) {
        skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
        ia64_tr_emit_decoded_illegal_operation(ctx, insn);
        ia64_tr_finish_predicate_guard(skip);
        return;
    }

    /*
     * Optional payloads must be seeded before the predicate can jump to the
     * common finish-success label.  These preparations have no architectural
     * effect and precede all runtime legality/source checks.
     */
    if (load) {
        target_write = ia64_tr_group_prepare_gr(ctx, insn->r1);
    }
    if (update) {
        base_write = ia64_tr_group_prepare_gr(ctx, insn->r3);
    }
    skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);

    if (load) {
        ia64_tr_emit_decoded_memory_target_check(ctx, insn, insn->r1);
    }
    if (update) {
        ia64_tr_emit_decoded_memory_target_check(ctx, insn, insn->r3);
    }

    base = ia64_tr_scratch_i64(ctx);
    base_nat = ia64_tr_scratch_i64(ctx);
    operand = ia64_tr_scratch_i64(ctx);
    operand_nat = ia64_tr_scratch_i64(ctx);
    result = ia64_tr_scratch_i64(ctx);
    updated = ia64_tr_scratch_i64(ctx);

    ia64_tr_group_load_ordinary_gr_pair(ctx, base, base_nat, insn->r3);
    if (load && insn->reg_base_update) {
        if (insn->r2 == insn->r3) {
            tcg_gen_mov_i64(operand, base);
            tcg_gen_mov_i64(operand_nat, base_nat);
        } else {
            ia64_tr_group_load_ordinary_gr_pair(
                ctx, operand, operand_nat, insn->r2);
        }
    } else if (!load) {
        if (insn->r2 == insn->r3) {
            tcg_gen_mov_i64(operand, base);
            tcg_gen_mov_i64(operand_nat, base_nat);
        } else {
            ia64_tr_group_load_ordinary_gr_pair(
                ctx, operand, operand_nat, insn->r2);
        }
    } else {
        tcg_gen_movi_i64(operand, 0);
        tcg_gen_movi_i64(operand_nat, 0);
    }

    ia64_tr_emit_decoded_memory_nat_check(
        ctx, insn, base_nat, access_type, true);
    if (!load) {
        /* Store base NaT has priority over its value NaT. */
        ia64_tr_emit_decoded_memory_nat_check(
            ctx, insn, operand_nat, access_type, false);
    }
    ia64_tr_publish_decoded_memory_access(ctx, insn);
    ia64_tr_emit_decoded_data_debug_pre_access(
        ctx, base, width,
        load ? IA64_DEBUG_ACCESS_READ : IA64_DEBUG_ACCESS_WRITE);
    ia64_tr_emit_decoded_memory_alignment_check(
        ctx, insn, base, width, access_type);

    if (load) {
        tcg_gen_qemu_ld_i64(result, base, ia64_tr_data_mmu_index(ctx),
                            ia64_tr_ldst_memop(ctx, width));
        if (insn->mem_acquire) {
            tcg_gen_mb(TCG_BAR_LDAQ | TCG_MO_LD_LD | TCG_MO_LD_ST);
        }
        ia64_tr_group_stage_gr(target_write, result, tcg_constant_i64(0));
    } else {
        if (insn->mem_release) {
            tcg_gen_mb(TCG_BAR_STRL | TCG_MO_LD_ST | TCG_MO_ST_ST);
        }
        tcg_gen_qemu_st_i64(operand, base, ia64_tr_data_mmu_index(ctx),
                            ia64_tr_ldst_memop(ctx, width));
        ia64_tr_emit_decoded_store_alat_invalidate(
            ctx, base, width);
    }

    if (update) {
        if (insn->reg_base_update) {
            tcg_gen_add_i64(updated, base, operand);
            ia64_tr_group_stage_gr(base_write, updated, operand_nat);
        } else {
            tcg_gen_addi_i64(updated, base, insn->imm);
            ia64_tr_group_stage_gr(base_write, updated,
                                   tcg_constant_i64(0));
        }
    }
    ia64_tr_finish_faulting_slot();
    ia64_tr_finish_predicate_guard(skip);
}

static void ia64_tr_emit_decoded_strict_alignment_check(
    DisasContext *ctx, const IA64Instruction *insn, TCGv_i64 address,
    uint8_t alignment, MMUAccessType access_type)
{
    TCGLabel *valid;
    TCGv_i64 misalignment;

    if (alignment <= 1) {
        return;
    }
    valid = gen_new_label();
    misalignment = ia64_tr_scratch_i64(ctx);
    tcg_gen_andi_i64(misalignment, address, alignment - 1);
    tcg_gen_brcondi_i64(TCG_COND_EQ, misalignment, 0, valid);
    ia64_tr_emit_decoded_unaligned_data_reference(
        ctx, insn, address, alignment, access_type);
    gen_set_label(valid);
}

static bool ia64_tr_decoded_data_plane_integer_load_statically_illegal(
    const IA64Instruction *insn)
{
    bool update = insn->reg_base_update || insn->imm_base_update;

    return insn->r1 == 0 || (update && insn->r1 == insn->r3) ||
           (update && insn->r3 == 0);
}

static void ia64_tr_emit_decoded_data_plane_integer_load(
    DisasContext *ctx, const IA64Instruction *insn,
    const IA64TrDataPlaneDescriptor *descriptor)
{
    bool update = insn->reg_base_update || insn->imm_base_update;
    bool speculative = descriptor->memory_class == 1 ||
                       descriptor->memory_class == 3;
    IA64TrGrWrite *target_write = NULL;
    IA64TrGrWrite *base_write = NULL;
    TCGLabel *skip;
    TCGLabel *base_valid = gen_new_label();
    TCGLabel *memory = gen_new_label();
    TCGLabel *defer = gen_new_label();
    TCGLabel *advanced_zero = gen_new_label();
    TCGLabel *done = gen_new_label();
    TCGv_i64 base = ia64_tr_scratch_i64(ctx);
    TCGv_i64 base_nat = ia64_tr_scratch_i64(ctx);
    TCGv_i64 increment = ia64_tr_scratch_i64(ctx);
    TCGv_i64 increment_nat = ia64_tr_scratch_i64(ctx);
    TCGv_i64 old_target = ia64_tr_scratch_i64(ctx);
    TCGv_i64 old_target_nat = ia64_tr_scratch_i64(ctx);
    TCGv_i64 result = ia64_tr_scratch_i64(ctx);
    TCGv_i64 result_nat = ia64_tr_scratch_i64(ctx);
    TCGv_i64 updated = ia64_tr_scratch_i64(ctx);
    TCGv_i32 action = ia64_tr_scratch_i32(ctx);

    g_assert(descriptor->kind == IA64_TR_DATA_PLANE_INTEGER_LOAD);
    ia64_tr_require_helper(insn->opcode,
                           IA64_OPCODE_HELPER_SPECIAL_LDST);
    ia64_tr_prime_decoded_instruction_state(ctx, insn);
    if (ia64_tr_decoded_data_plane_integer_load_statically_illegal(insn)) {
        skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
        ia64_tr_emit_decoded_illegal_operation(ctx, insn);
        ia64_tr_finish_predicate_guard(skip);
        return;
    }

    target_write = ia64_tr_group_prepare_gr(ctx, insn->r1);
    if (descriptor->memory_class == 2 ||
        descriptor->memory_class == 3 ||
        descriptor->memory_class == 9) {
        ia64_tr_group_prepare_post_alat_record(
            ctx, insn->r1, descriptor->width, IA64_ALAT_TARGET_GR,
            descriptor->memory_class);
    }
    if (update) {
        base_write = ia64_tr_group_prepare_gr(ctx, insn->r3);
    }
    skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
    ia64_tr_emit_decoded_memory_target_check(ctx, insn, insn->r1);
    if (update) {
        ia64_tr_emit_decoded_memory_target_check(ctx, insn, insn->r3);
    }

    ia64_tr_group_load_ordinary_gr_pair(ctx, base, base_nat, insn->r3);
    ia64_tr_group_load_ordinary_gr_pair(
        ctx, old_target, old_target_nat, insn->r1);
    if (insn->reg_base_update) {
        if (insn->r2 == insn->r3) {
            tcg_gen_mov_i64(increment, base);
            tcg_gen_mov_i64(increment_nat, base_nat);
        } else {
            ia64_tr_group_load_ordinary_gr_pair(
                ctx, increment, increment_nat, insn->r2);
        }
    } else {
        tcg_gen_movi_i64(increment, (uint64_t)insn->imm);
        tcg_gen_movi_i64(increment_nat, 0);
    }

    if (speculative) {
        tcg_gen_brcondi_i64(TCG_COND_EQ, base_nat, 0, base_valid);
        ia64_tr_publish_decoded_memory_access(ctx, insn);
        gen_helper_data_plane_integer_load_prepare_nat(
            action, tcg_env, tcg_constant_i32(insn->r1),
            tcg_constant_i32(descriptor->memory_class));
        tcg_gen_br(defer);
        gen_set_label(base_valid);
    } else {
        ia64_tr_emit_decoded_memory_nat_check(
            ctx, insn, base_nat, MMU_DATA_LOAD, true);
    }

    ia64_tr_publish_decoded_memory_access(ctx, insn);
    gen_helper_data_plane_integer_load_prepare(
        action, tcg_env, base, tcg_constant_i32(insn->r1),
        tcg_constant_i32(descriptor->width),
        tcg_constant_i32(descriptor->memory_class));
    tcg_gen_brcondi_i32(TCG_COND_EQ, action, 1, done);
    tcg_gen_brcondi_i32(TCG_COND_EQ, action, 2, defer);
    tcg_gen_brcondi_i32(TCG_COND_EQ, action, 3, advanced_zero);
    tcg_gen_br(memory);

    gen_set_label(memory);
    ia64_tr_emit_decoded_data_debug_pre_access(
        ctx, base, descriptor->width, IA64_DEBUG_ACCESS_READ);
    ia64_tr_emit_decoded_memory_alignment_check(
        ctx, insn, base, descriptor->width, MMU_DATA_LOAD);
    tcg_gen_qemu_ld_i64(result, base, ia64_tr_data_mmu_index(ctx),
                        ia64_tr_ldst_memop(ctx, descriptor->width));
    tcg_gen_movi_i64(result_nat, 0);
    if (descriptor->memory_class == 6) {
        TCGv_i64 unat = ia64_tr_scratch_i64(ctx);
        TCGv_i64 bitpos = ia64_tr_scratch_i64(ctx);

        ia64_tr_group_load_ordinary_ar(ctx, unat, IA64_AR_UNAT);
        tcg_gen_shri_i64(bitpos, base, 3);
        tcg_gen_andi_i64(bitpos, bitpos, 0x3f);
        tcg_gen_shr_i64(result_nat, unat, bitpos);
        tcg_gen_andi_i64(result_nat, result_nat, 1);
    }
    gen_helper_data_plane_integer_load_complete(
        tcg_env, base, tcg_constant_i32(insn->r1),
        tcg_constant_i32(descriptor->width),
        tcg_constant_i32(descriptor->memory_class));
    ia64_tr_group_stage_gr(target_write, result, result_nat);
    if (descriptor->memory_class == 2 ||
        descriptor->memory_class == 3 ||
        descriptor->memory_class == 9) {
        ia64_tr_group_stage_post_alat_record(
            ctx->rewrite_group.current, base);
    }
    tcg_gen_br(done);

    gen_set_label(defer);
    ia64_tr_group_stage_gr(
        target_write, old_target, tcg_constant_i64(1));
    tcg_gen_br(done);

    gen_set_label(advanced_zero);
    ia64_tr_group_stage_gr(
        target_write, tcg_constant_i64(0), tcg_constant_i64(0));

    gen_set_label(done);
    if (update) {
        if (insn->reg_base_update) {
            tcg_gen_add_i64(updated, base, increment);
            tcg_gen_or_i64(increment_nat, increment_nat, base_nat);
            ia64_tr_group_stage_gr(base_write, updated, increment_nat);
        } else {
            tcg_gen_addi_i64(updated, base, insn->imm);
            ia64_tr_group_stage_gr(
                base_write, updated, base_nat);
        }
    }
    ia64_tr_finish_faulting_slot();
    ia64_tr_finish_predicate_guard(skip);
}

static void ia64_tr_emit_decoded_data_plane_integer_spill(
    DisasContext *ctx, const IA64Instruction *insn,
    const IA64TrDataPlaneDescriptor *descriptor)
{
    bool update = insn->imm_base_update;
    IA64TrGrWrite *base_write = NULL;
    TCGLabel *skip;
    TCGv_i64 base = ia64_tr_scratch_i64(ctx);
    TCGv_i64 base_nat = ia64_tr_scratch_i64(ctx);
    TCGv_i64 value = ia64_tr_scratch_i64(ctx);
    TCGv_i64 value_nat = ia64_tr_scratch_i64(ctx);
    TCGv_i64 updated = ia64_tr_scratch_i64(ctx);

    g_assert(descriptor->kind == IA64_TR_DATA_PLANE_INTEGER_SPILL);
    ia64_tr_require_helper(insn->opcode,
                           IA64_OPCODE_HELPER_SPECIAL_LDST);
    ia64_tr_prime_decoded_instruction_state(ctx, insn);
    if (update && insn->r3 == 0) {
        skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
        ia64_tr_emit_decoded_illegal_operation(ctx, insn);
        ia64_tr_finish_predicate_guard(skip);
        return;
    }
    if (update) {
        base_write = ia64_tr_group_prepare_gr(ctx, insn->r3);
    }
    skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
    if (update) {
        ia64_tr_emit_decoded_memory_target_check(ctx, insn, insn->r3);
    }
    ia64_tr_group_load_ordinary_gr_pair(ctx, base, base_nat, insn->r3);
    if (insn->r2 == insn->r3) {
        tcg_gen_mov_i64(value, base);
        tcg_gen_mov_i64(value_nat, base_nat);
    } else {
        ia64_tr_group_load_ordinary_gr_pair(
            ctx, value, value_nat, insn->r2);
    }
    ia64_tr_emit_decoded_memory_nat_check(
        ctx, insn, base_nat, MMU_DATA_STORE, true);
    ia64_tr_publish_decoded_memory_access(ctx, insn);
    ia64_tr_emit_decoded_data_debug_pre_access(
        ctx, base, descriptor->width, IA64_DEBUG_ACCESS_WRITE);
    ia64_tr_emit_decoded_memory_alignment_check(
        ctx, insn, base, descriptor->width, MMU_DATA_STORE);
    tcg_gen_qemu_st_i64(value, base, ia64_tr_data_mmu_index(ctx),
                        ia64_tr_ldst_memop(ctx, descriptor->width));
    ia64_tr_emit_decoded_store_alat_invalidate(
        ctx, base, descriptor->width);

    /* Only st8.spill is architectural; reserved decoder widths do not alter
       UNAT, matching the normalized prototype decoder/reference behavior. */
    if (descriptor->width == 8) {
        TCGv_i64 unat = ia64_tr_scratch_i64(ctx);
        TCGv_i64 bitpos = ia64_tr_scratch_i64(ctx);
        TCGv_i64 bit = ia64_tr_scratch_i64(ctx);
        TCGv_i64 set = ia64_tr_scratch_i64(ctx);
        TCGv_i64 clear = ia64_tr_scratch_i64(ctx);
        TCGv_i64 next = ia64_tr_scratch_i64(ctx);

        ia64_tr_group_load_ordinary_ar(ctx, unat, IA64_AR_UNAT);
        tcg_gen_shri_i64(bitpos, base, 3);
        tcg_gen_andi_i64(bitpos, bitpos, 0x3f);
        tcg_gen_shl_i64(bit, tcg_constant_i64(1), bitpos);
        tcg_gen_or_i64(set, unat, bit);
        tcg_gen_andc_i64(clear, unat, bit);
        tcg_gen_movcond_i64(TCG_COND_NE, next, value_nat,
                            tcg_constant_i64(0), set, clear);
        ia64_tr_store_ar(ctx, IA64_AR_UNAT, next);
    }
    if (update) {
        tcg_gen_addi_i64(updated, base, insn->imm);
        ia64_tr_group_stage_gr(
            base_write, updated, tcg_constant_i64(0));
    }
    ia64_tr_finish_faulting_slot();
    ia64_tr_finish_predicate_guard(skip);
}

static void ia64_tr_emit_decoded_data_plane_atomic(
    DisasContext *ctx, const IA64Instruction *insn,
    const IA64TrDataPlaneDescriptor *descriptor)
{
    bool fetch_register = descriptor->kind == IA64_TR_DATA_PLANE_FETCHADD &&
                          insn->imm == 0;
    IA64TrGrWrite *target_write;
    TCGLabel *skip;
    TCGv_i64 base = ia64_tr_scratch_i64(ctx);
    TCGv_i64 base_nat = ia64_tr_scratch_i64(ctx);
    TCGv_i64 value = ia64_tr_scratch_i64(ctx);
    TCGv_i64 value_nat = ia64_tr_scratch_i64(ctx);
    TCGv_i64 old = ia64_tr_scratch_i64(ctx);

    g_assert(descriptor->kind == IA64_TR_DATA_PLANE_XCHG ||
             descriptor->kind == IA64_TR_DATA_PLANE_CMPXCHG ||
             descriptor->kind == IA64_TR_DATA_PLANE_FETCHADD);
    if (descriptor->kind == IA64_TR_DATA_PLANE_CMPXCHG) {
        ia64_tr_require_helper(insn->opcode, IA64_OPCODE_HELPER_ATOMIC);
    }
    ia64_tr_prime_decoded_instruction_state(ctx, insn);
    if (insn->r1 == 0) {
        skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
        ia64_tr_emit_decoded_illegal_operation(ctx, insn);
        ia64_tr_finish_predicate_guard(skip);
        return;
    }
    target_write = ia64_tr_group_prepare_gr(ctx, insn->r1);
    skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
    ia64_tr_emit_decoded_memory_target_check(ctx, insn, insn->r1);
    ia64_tr_group_load_ordinary_gr_pair(ctx, base, base_nat, insn->r3);
    if (descriptor->kind == IA64_TR_DATA_PLANE_FETCHADD && !fetch_register) {
        tcg_gen_movi_i64(value, (uint64_t)insn->imm);
        tcg_gen_movi_i64(value_nat, 0);
    } else if (insn->r2 == insn->r3) {
        tcg_gen_mov_i64(value, base);
        tcg_gen_mov_i64(value_nat, base_nat);
    } else {
        ia64_tr_group_load_ordinary_gr_pair(
            ctx, value, value_nat, insn->r2);
    }
    ia64_tr_emit_decoded_memory_nat_check(
        ctx, insn, base_nat,
        IA64_EXCEPTION_ACCESS_SEMAPHORE, true);
    ia64_tr_emit_decoded_memory_nat_check(
        ctx, insn, value_nat,
        IA64_EXCEPTION_ACCESS_SEMAPHORE, false);
    ia64_tr_publish_decoded_memory_access(ctx, insn);
    ia64_tr_emit_decoded_data_debug_pre_access(
        ctx, base, descriptor->width,
        IA64_DEBUG_ACCESS_READ | IA64_DEBUG_ACCESS_WRITE);
    ia64_tr_emit_decoded_strict_alignment_check(
        ctx, insn, base, descriptor->width,
        (MMUAccessType)IA64_EXCEPTION_ACCESS_SEMAPHORE);
    gen_helper_data_plane_semaphore_probe(
        tcg_env, base,
        tcg_constant_i32(descriptor->kind ==
                         IA64_TR_DATA_PLANE_FETCHADD));

    if (insn->mem_release) {
        tcg_gen_mb(TCG_BAR_STRL | TCG_MO_LD_ST | TCG_MO_ST_ST);
    }
    switch (descriptor->kind) {
    case IA64_TR_DATA_PLANE_XCHG:
        tcg_gen_atomic_xchg_i64(old, base, value,
                                ia64_tr_data_mmu_index(ctx),
                                ia64_tr_ldst_memop(ctx, descriptor->width));
        ia64_tr_emit_decoded_store_alat_invalidate(
            ctx, base, descriptor->width);
        break;
    case IA64_TR_DATA_PLANE_FETCHADD:
        tcg_gen_atomic_fetch_add_i64(
            old, base, value, ia64_tr_data_mmu_index(ctx),
            ia64_tr_ldst_memop(ctx, descriptor->width));
        ia64_tr_emit_decoded_store_alat_invalidate(
            ctx, base, descriptor->width);
        break;
    case IA64_TR_DATA_PLANE_CMPXCHG:
    {
        TCGv_i64 compare = ia64_tr_scratch_i64(ctx);

        ia64_tr_group_load_ordinary_ar(ctx, compare, IA64_AR_CCV);
        gen_helper_data_plane_cmpxchg(
            old, tcg_env, base, compare, value,
            tcg_constant_i32(descriptor->width));
        break;
    }
    default:
        g_assert_not_reached();
    }
    if (insn->mem_acquire) {
        tcg_gen_mb(TCG_BAR_LDAQ | TCG_MO_LD_LD | TCG_MO_LD_ST);
    }
    ia64_tr_group_stage_gr(target_write, old, tcg_constant_i64(0));
    ia64_tr_finish_faulting_slot();
    ia64_tr_finish_predicate_guard(skip);
}

static void ia64_tr_emit_decoded_data_plane_wide(
    DisasContext *ctx, const IA64Instruction *insn,
    const IA64TrDataPlaneDescriptor *descriptor)
{
    IA64TrGrWrite *target_write = NULL;
    TCGLabel *skip;
    TCGv_i64 base = ia64_tr_scratch_i64(ctx);
    TCGv_i64 base_nat = ia64_tr_scratch_i64(ctx);

    g_assert(descriptor->kind == IA64_TR_DATA_PLANE_WIDE_LOAD ||
             descriptor->kind == IA64_TR_DATA_PLANE_WIDE_STORE);
    ia64_tr_prime_decoded_instruction_state(ctx, insn);
    if (descriptor->kind == IA64_TR_DATA_PLANE_WIDE_LOAD &&
        insn->r1 == 0) {
        skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
        ia64_tr_emit_decoded_illegal_operation(ctx, insn);
        ia64_tr_finish_predicate_guard(skip);
        return;
    }
    if (descriptor->kind == IA64_TR_DATA_PLANE_WIDE_LOAD) {
        target_write = ia64_tr_group_prepare_gr(ctx, insn->r1);
    }
    skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
    if (descriptor->kind == IA64_TR_DATA_PLANE_WIDE_LOAD) {
        ia64_tr_emit_decoded_memory_target_check(ctx, insn, insn->r1);
    }
    ia64_tr_group_load_ordinary_gr_pair(ctx, base, base_nat, insn->r3);
    ia64_tr_emit_decoded_memory_nat_check(
        ctx, insn, base_nat,
        descriptor->kind == IA64_TR_DATA_PLANE_WIDE_LOAD ?
            MMU_DATA_LOAD : MMU_DATA_STORE, true);
    if (descriptor->kind == IA64_TR_DATA_PLANE_WIDE_LOAD) {
        TCGv_i64 low = ia64_tr_scratch_i64(ctx);
        TCGv_i64 high = ia64_tr_scratch_i64(ctx);
        TCGv_i64 numeric_low = ia64_tr_scratch_i64(ctx);
        TCGv_i64 numeric_high = ia64_tr_scratch_i64(ctx);
        TCGv_i128 pair = tcg_temp_new_i128();
        bool big_endian = (ctx->base.tb->flags & IA64_TB_FLAG_BE) != 0;

        ia64_tr_publish_decoded_memory_access(ctx, insn);
        ia64_tr_emit_decoded_data_debug_pre_access(
            ctx, base, 16, IA64_DEBUG_ACCESS_READ);
        ia64_tr_emit_decoded_strict_alignment_check(
            ctx, insn, base, 16, MMU_DATA_LOAD);
        gen_helper_data_plane_wb_only_probe(
            tcg_env, base, tcg_constant_i32(0));
        /*
         * Keep ld16 one architectural memory transaction.  Apart from being
         * the SDM operation, this prevents a fault in the upper half from
         * replaying a completed MMIO read in the lower half on restart.
         */
        tcg_gen_qemu_ld_i128(
            pair, base, ia64_tr_data_mmu_index(ctx),
            MO_128 | MO_ALIGN_16 | (big_endian ? MO_BE : MO_LE));
        tcg_gen_extr_i128_i64(numeric_low, numeric_high, pair);
        if (big_endian) {
            tcg_gen_mov_i64(low, numeric_high);
            tcg_gen_mov_i64(high, numeric_low);
        } else {
            tcg_gen_mov_i64(low, numeric_low);
            tcg_gen_mov_i64(high, numeric_high);
        }
        if (insn->mem_acquire) {
            tcg_gen_mb(TCG_BAR_LDAQ | TCG_MO_LD_LD | TCG_MO_LD_ST);
        }
        ia64_tr_group_stage_gr(
            target_write, low, tcg_constant_i64(0));
        ia64_tr_store_ar(ctx, IA64_AR_CSD, high);
    } else {
        TCGv_i64 low = ia64_tr_scratch_i64(ctx);
        TCGv_i64 low_nat = ia64_tr_scratch_i64(ctx);
        TCGv_i64 high = ia64_tr_scratch_i64(ctx);
        TCGv_i128 pair = tcg_temp_new_i128();
        bool big_endian = (ctx->base.tb->flags & IA64_TB_FLAG_BE) != 0;

        ia64_tr_group_load_ordinary_gr_pair(
            ctx, low, low_nat, insn->r2);
        ia64_tr_emit_decoded_memory_nat_check(
            ctx, insn, low_nat, MMU_DATA_STORE, false);
        ia64_tr_group_load_ordinary_ar(ctx, high, IA64_AR_CSD);
        ia64_tr_publish_decoded_memory_access(ctx, insn);
        ia64_tr_emit_decoded_data_debug_pre_access(
            ctx, base, 16, IA64_DEBUG_ACCESS_WRITE);
        ia64_tr_emit_decoded_strict_alignment_check(
            ctx, insn, base, 16, MMU_DATA_STORE);
        gen_helper_data_plane_wb_only_probe(
            tcg_env, base, tcg_constant_i32(1));
        if (insn->mem_release) {
            tcg_gen_mb(TCG_BAR_STRL | TCG_MO_LD_ST | TCG_MO_ST_ST);
        }
        /*
         * An aligned qemu_st_i128 has the architectural single-copy atomic
         * store semantics while checking only write permission.  An xchg
         * helper would incorrectly turn st16 into an RMW and reject a
         * write-only mapping.
         */
        if (big_endian) {
            tcg_gen_concat_i64_i128(pair, high, low);
        } else {
            tcg_gen_concat_i64_i128(pair, low, high);
        }
        tcg_gen_qemu_st_i128(
            pair, base, ia64_tr_data_mmu_index(ctx),
            MO_128 | MO_ALIGN_16 | (big_endian ? MO_BE : MO_LE));
        ia64_tr_emit_decoded_store_alat_invalidate(ctx, base, 16);
    }
    ia64_tr_finish_faulting_slot();
    ia64_tr_finish_predicate_guard(skip);
}

static void ia64_tr_emit_decoded_data_plane_cmp8xchg16(
    DisasContext *ctx, const IA64Instruction *insn,
    const IA64TrDataPlaneDescriptor *descriptor)
{
    IA64TrGrWrite *target_write;
    TCGLabel *skip;
    TCGv_i64 base = ia64_tr_scratch_i64(ctx);
    TCGv_i64 base_nat = ia64_tr_scratch_i64(ctx);
    TCGv_i64 low = ia64_tr_scratch_i64(ctx);
    TCGv_i64 low_nat = ia64_tr_scratch_i64(ctx);
    TCGv_i64 high = ia64_tr_scratch_i64(ctx);
    TCGv_i64 compare = ia64_tr_scratch_i64(ctx);
    TCGv_i64 old = ia64_tr_scratch_i64(ctx);

    g_assert(descriptor->kind == IA64_TR_DATA_PLANE_CMP8XCHG16);
    ia64_tr_require_helper(insn->opcode, IA64_OPCODE_HELPER_ATOMIC);
    ia64_tr_prime_decoded_instruction_state(ctx, insn);
    if (insn->r1 == 0) {
        skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
        ia64_tr_emit_decoded_illegal_operation(ctx, insn);
        ia64_tr_finish_predicate_guard(skip);
        return;
    }
    target_write = ia64_tr_group_prepare_gr(ctx, insn->r1);
    skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
    ia64_tr_emit_decoded_memory_target_check(ctx, insn, insn->r1);
    ia64_tr_group_load_ordinary_gr_pair(ctx, base, base_nat, insn->r3);
    ia64_tr_group_load_ordinary_gr_pair(ctx, low, low_nat, insn->r2);
    ia64_tr_emit_decoded_memory_nat_check(
        ctx, insn, base_nat,
        IA64_EXCEPTION_ACCESS_SEMAPHORE, true);
    ia64_tr_emit_decoded_memory_nat_check(
        ctx, insn, low_nat,
        IA64_EXCEPTION_ACCESS_SEMAPHORE, false);
    ia64_tr_group_load_ordinary_ar(ctx, compare, IA64_AR_CCV);
    ia64_tr_group_load_ordinary_ar(ctx, high, IA64_AR_CSD);
    ia64_tr_publish_decoded_memory_access(ctx, insn);
    {
        TCGv_i64 block = ia64_tr_scratch_i64(ctx);

        tcg_gen_andi_i64(block, base, ~UINT64_C(0xf));
        ia64_tr_emit_decoded_data_debug_pre_access(
            ctx, block, 16,
            IA64_DEBUG_ACCESS_READ | IA64_DEBUG_ACCESS_WRITE);
    }
    ia64_tr_emit_decoded_strict_alignment_check(
        ctx, insn, base, 8,
        (MMUAccessType)IA64_EXCEPTION_ACCESS_SEMAPHORE);
    gen_helper_data_plane_semaphore_probe(
        tcg_env, base, tcg_constant_i32(0));
    if (insn->mem_release) {
        tcg_gen_mb(TCG_BAR_STRL | TCG_MO_LD_ST | TCG_MO_ST_ST);
    }
    gen_helper_data_plane_cmp8xchg16(
        old, tcg_env, base, compare, low, high);
    if (insn->mem_acquire) {
        tcg_gen_mb(TCG_BAR_LDAQ | TCG_MO_LD_LD | TCG_MO_LD_ST);
    }
    ia64_tr_group_stage_gr(target_write, old, tcg_constant_i64(0));
    ia64_tr_finish_faulting_slot();
    ia64_tr_finish_predicate_guard(skip);
}

static void ia64_tr_emit_decoded_data_plane_cache_control(
    DisasContext *ctx, const IA64Instruction *insn,
    const IA64TrDataPlaneDescriptor *descriptor)
{
    TCGLabel *skip;

    g_assert(descriptor->kind == IA64_TR_DATA_PLANE_FWB ||
             descriptor->kind == IA64_TR_DATA_PLANE_FC ||
             descriptor->kind == IA64_TR_DATA_PLANE_INVALA ||
             descriptor->kind == IA64_TR_DATA_PLANE_INVALAT);
    if (descriptor->kind != IA64_TR_DATA_PLANE_FWB) {
        ia64_tr_require_helper(insn->opcode,
                               IA64_OPCODE_HELPER_DATA_PLANE);
    }
    ia64_tr_prime_decoded_instruction_state(ctx, insn);
    skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);

    switch (descriptor->kind) {
    case IA64_TR_DATA_PLANE_FWB:
        /* The cacheless model has no write buffer to drain. */
        break;
    case IA64_TR_DATA_PLANE_INVALA:
        gen_helper_data_plane_alat_invalidate_all(tcg_env);
        break;
    case IA64_TR_DATA_PLANE_INVALAT:
        gen_helper_data_plane_alat_invalidate_one(
            tcg_env, tcg_constant_i32(insn->r1),
            tcg_constant_i32(insn->check_fp ? IA64_ALAT_TARGET_FR :
                                                   IA64_ALAT_TARGET_GR));
        break;
    case IA64_TR_DATA_PLANE_FC: {
        TCGv_i64 base = ia64_tr_scratch_i64(ctx);
        TCGv_i64 base_nat = ia64_tr_scratch_i64(ctx);

        ia64_tr_group_load_ordinary_gr_pair(
            ctx, base, base_nat, insn->r3);
        ia64_tr_emit_decoded_memory_nat_check(
            ctx, insn, base_nat,
            IA64_EXCEPTION_ACCESS_FC_READ_NON_ACCESS, false);
        ia64_tr_publish_decoded_memory_access(ctx, insn);
        gen_helper_data_plane_fc(tcg_env, base);
        ia64_tr_finish_faulting_slot();
        break;
    }
    case IA64_TR_DATA_PLANE_NONE:
    default:
        g_assert_not_reached();
    }
    ia64_tr_finish_predicate_guard(skip);
}

static void ia64_tr_emit_decoded_data_plane_lfetch(
    DisasContext *ctx, const IA64Instruction *insn,
    const IA64TrDataPlaneDescriptor *descriptor)
{
    bool update = insn->reg_base_update || insn->imm_base_update;
    bool faulting = insn->opcode == IA64_OP_LFETCH_FAULT;
    IA64TrGrWrite *base_write = NULL;
    TCGLabel *skip;
    TCGv_i64 base;
    TCGv_i64 base_nat;
    TCGv_i64 increment;
    TCGv_i64 increment_nat;
    TCGv_i64 updated;

    g_assert(descriptor->kind == IA64_TR_DATA_PLANE_LFETCH);
    if (faulting) {
        ia64_tr_require_helper(insn->opcode,
                               IA64_OPCODE_HELPER_DATA_PLANE);
    }
    ia64_tr_prime_decoded_instruction_state(ctx, insn);

    if (update && insn->r3 == 0) {
        skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
        ia64_tr_emit_decoded_illegal_operation(ctx, insn);
        ia64_tr_finish_predicate_guard(skip);
        return;
    }
    if (update) {
        base_write = ia64_tr_group_prepare_gr(ctx, insn->r3);
    }
    skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
    if (update) {
        /* Target legality has priority over PSR.ed and every address fault. */
        ia64_tr_emit_decoded_memory_target_check(ctx, insn, insn->r3);
    }

    base = ia64_tr_scratch_i64(ctx);
    base_nat = ia64_tr_scratch_i64(ctx);
    increment = ia64_tr_scratch_i64(ctx);
    increment_nat = ia64_tr_scratch_i64(ctx);
    updated = ia64_tr_scratch_i64(ctx);
    ia64_tr_group_load_ordinary_gr_pair(ctx, base, base_nat, insn->r3);
    if (insn->reg_base_update) {
        if (insn->r2 == insn->r3) {
            tcg_gen_mov_i64(increment, base);
            tcg_gen_mov_i64(increment_nat, base_nat);
        } else {
            ia64_tr_group_load_ordinary_gr_pair(
                ctx, increment, increment_nat, insn->r2);
        }
    } else {
        tcg_gen_movi_i64(increment, 0);
        tcg_gen_movi_i64(increment_nat, 0);
    }

    if (faulting) {
        TCGLabel *skip_request = gen_new_label();
        TCGv_i64 psr = ia64_tr_scratch_i64(ctx);

        /* ED suppresses both NaT consumption and the translation request. */
        tcg_gen_ld_i64(psr, tcg_env, offsetof(CPUIA64State, psr));
        tcg_gen_brcondi_i64(TCG_COND_TSTNE, psr, IA64_TR_PSR_ED_BIT,
                            skip_request);
        ia64_tr_emit_decoded_memory_nat_check(
            ctx, insn, base_nat,
            IA64_EXCEPTION_ACCESS_LFETCH_FAULT_READ_NON_ACCESS, false);
        ia64_tr_publish_decoded_memory_access(ctx, insn);
        gen_helper_data_plane_lfetch_fault(tcg_env, base);
        ia64_tr_finish_faulting_slot();
        gen_set_label(skip_request);
    }
    /* Non-faulting prefetch and implicit post-update prefetch are hints. */

    if (insn->reg_base_update) {
        TCGv_i64 updated_nat = ia64_tr_scratch_i64(ctx);

        tcg_gen_add_i64(updated, base, increment);
        tcg_gen_or_i64(updated_nat, base_nat, increment_nat);
        ia64_tr_group_stage_gr(base_write, updated, updated_nat);
    } else if (insn->imm_base_update) {
        tcg_gen_addi_i64(updated, base, insn->imm);
        ia64_tr_group_stage_gr(base_write, updated, base_nat);
    }
    ia64_tr_finish_predicate_guard(skip);
}

static void ia64_tr_emit_decoded_checked_branch_split(
    DisasContext *ctx, const IA64Instruction *insn,
    IA64TrDecodedBranchArm *arm)
{
    const IA64TrDataPlaneDescriptor *descriptor =
        ia64_tr_decoded_data_plane(insn->opcode);
    TCGLabel *skip_check = gen_new_label();
    TCGv_i64 predicate = ia64_tr_scratch_i64(ctx);
    TCGv_i64 failed = ia64_tr_scratch_i64(ctx);
    uint64_t bundle_ip = insn->address &
                         ~(uint64_t)(IA64_BUNDLE_SIZE - 1);

    g_assert(descriptor != NULL &&
             (descriptor->kind == IA64_TR_DATA_PLANE_CHK_S ||
              descriptor->kind == IA64_TR_DATA_PLANE_CHK_A));
    ia64_tr_require_helper(insn->opcode,
                           IA64_OPCODE_HELPER_DATA_PLANE);
    memset(arm, 0, sizeof(*arm));
    arm->taken = gen_new_label();
    arm->direct_target = bundle_ip + (uint64_t)insn->imm;
    ia64_tr_profile_add(ctx, IA64_PROFILE_BRANCH_INLINE_DIRECT, 1);

    tcg_gen_movi_i64(failed, 0);
    ia64_tr_group_load_branch_predicate(ctx, predicate, insn->qp);
    tcg_gen_brcondi_i64(TCG_COND_EQ, predicate, 0, skip_check);
    if (descriptor->kind == IA64_TR_DATA_PLANE_CHK_S) {
        if (insn->check_fp) {
            TCGv_i32 fp_failed = ia64_tr_scratch_i32(ctx);

            /* The FR read can raise a Disabled FP Register fault. */
            ia64_tr_publish_decoded_memory_access(ctx, insn);
            gen_helper_data_plane_chk_s_fr(
                fp_failed, tcg_env, tcg_constant_i32(insn->r2));
            ia64_tr_finish_faulting_slot();
            tcg_gen_extu_i32_i64(failed, fp_failed);
        } else {
            TCGv_i64 ignored = ia64_tr_scratch_i64(ctx);
            TCGv_i64 nat = ia64_tr_scratch_i64(ctx);

            ia64_tr_group_load_ordinary_gr_pair(
                ctx, ignored, nat, insn->r2);
            tcg_gen_mov_i64(failed, nat);
        }
    } else {
        TCGv_i32 hit = ia64_tr_scratch_i32(ctx);
        TCGv_i32 miss = ia64_tr_scratch_i32(ctx);

        gen_helper_data_plane_chk_a(
            hit, tcg_env, tcg_constant_i32(insn->r2),
            tcg_constant_i32(insn->check_fp ? IA64_ALAT_TARGET_FR :
                                                   IA64_ALAT_TARGET_GR),
            tcg_constant_i32(insn->opcode == IA64_OP_CHK_A_CLR));
        tcg_gen_xori_i32(miss, hit, 1);
        tcg_gen_extu_i32_i64(failed, miss);
    }
    gen_set_label(skip_check);

    ia64_tr_group_finish_instruction_success(ctx, insn);
    if (insn->stop_after) {
        ia64_tr_group_close(ctx);
    }
    ia64_tr_split_state_cache_at_typed_branch(ctx);
    tcg_gen_brcondi_i64(TCG_COND_NE, failed, 0, arm->taken);
}

enum {
    IA64_TR_FP_LOAD_CONTINUE = 0,
    IA64_TR_FP_LOAD_ALAT_HIT = 1,
    IA64_TR_FP_LOAD_DEFER = 2,
    IA64_TR_FP_LOAD_ADVANCED_ZERO = 3,
    IA64_TR_FP_LOAD_BASE_NAT = 4,
};

enum {
    IA64_TR_FP_STORE_CONTINUE = 0,
    IA64_TR_FP_STORE_BASE_NAT = 1,
    IA64_TR_FP_STORE_VALUE_NAT = 2,
};

static IA64FloatingMemoryFormat
ia64_tr_data_plane_fp_format(IA64Opcode opcode)
{
    switch (opcode) {
    case IA64_OP_LDFS:
    case IA64_OP_LDFPS:
    case IA64_OP_STFS:
        return IA64_FLOAT_FMT_SINGLE;
    case IA64_OP_LDFD:
    case IA64_OP_LDFPD:
    case IA64_OP_STFD:
        return IA64_FLOAT_FMT_DOUBLE;
    case IA64_OP_LDF8:
    case IA64_OP_LDFP8:
    case IA64_OP_STF8:
        return IA64_FLOAT_FMT_SIGNIFICAND;
    case IA64_OP_LDFE:
    case IA64_OP_STFE:
        return IA64_FLOAT_FMT_EXTENDED;
    case IA64_OP_LDF_FILL:
    case IA64_OP_STF_SPILL:
        return IA64_FLOAT_FMT_SPILL_FILL;
    default:
        g_assert_not_reached();
    }
}

static uint8_t ia64_tr_data_plane_fp_memory_class(
    const IA64Instruction *insn, const IA64TrDataPlaneDescriptor *descriptor)
{
    if (descriptor->memory_class == 6) {
        return 6;
    }
    if (insn->fp_load_check) {
        return insn->fp_load_check_clear ? 8 : 9;
    }
    if (insn->fp_load_speculative && insn->fp_load_advanced) {
        return 3;
    }
    if (insn->fp_load_speculative) {
        return 1;
    }
    if (insn->fp_load_advanced) {
        return 2;
    }
    return descriptor->memory_class;
}

/* FP memory helpers retire one or two converted destinations as a bounded
   transaction.  The focused helper preserves both pair entry images before
   either write; these named hooks also form the substrate used by the FP
   compute tranche. */
static void ia64_tr_group_prepare_fr(DisasContext *ctx, uint8_t reg)
{
    g_assert(ctx->rewrite_group.active &&
             ctx->rewrite_group.current != NULL && reg >= 2);
}

static void ia64_tr_group_load_ordinary_fr(
    DisasContext *ctx, TCGv_i64 low, TCGv_i64 high, uint8_t reg,
    IA64FloatingMemoryFormat format)
{
    g_assert(ctx->rewrite_group.active &&
             ctx->rewrite_group.current != NULL);
    gen_helper_data_plane_fp_store_value(
        low, tcg_env, tcg_constant_i32(reg), tcg_constant_i32(format),
        tcg_constant_i32(0));
    gen_helper_data_plane_fp_store_value(
        high, tcg_env, tcg_constant_i32(reg), tcg_constant_i32(format),
        tcg_constant_i32(1));
}

static void ia64_tr_group_stage_fr(
    DisasContext *ctx, TCGv_i64 address, TCGv_i64 low, TCGv_i64 high,
    uint32_t targets, uint32_t info)
{
    g_assert(ctx->rewrite_group.active &&
             ctx->rewrite_group.current != NULL);
    gen_helper_data_plane_fp_load_complete(
        tcg_env, address, low, high, tcg_constant_i32(targets),
        tcg_constant_i32(info));
}

static unsigned ia64_tr_fp_source_regs(
    const IA64Instruction *insn, const IA64TrFpDescriptor *descriptor,
    uint8_t regs[3])
{
    switch (descriptor->source_layout) {
    case IA64_TR_FP_SOURCE_NONE:
        return 0;
    case IA64_TR_FP_SOURCE_UNARY:
        regs[0] = insn->r2;
        return 1;
    case IA64_TR_FP_SOURCE_R3:
        regs[0] = insn->r3;
        return 1;
    case IA64_TR_FP_SOURCE_BINARY:
        regs[0] = insn->r2;
        regs[1] = insn->r3;
        return 2;
    case IA64_TR_FP_SOURCE_TERNARY:
        regs[0] = insn->r2;
        regs[1] = insn->r3;
        regs[2] = insn->r4;
        return 3;
    case IA64_TR_FP_SOURCE_XMPY:
        regs[0] = insn->r3;
        regs[1] = insn->r4;
        return 2;
    default:
        g_assert_not_reached();
    }
}

static void ia64_tr_emit_decoded_disabled_fp_regs(
    DisasContext *ctx, const IA64Instruction *insn,
    const uint8_t *regs, unsigned reg_count)
{
    uint64_t packed = reg_count;

    g_assert(reg_count <= 4);
    for (unsigned i = 0; i < reg_count; i++) {
        packed |= (uint64_t)regs[i] << ((i + 1) * 8);
    }

    /* The helper may deliver a pre-result Disabled FP Register fault. */
    ia64_tr_sync_state_cache(ctx);
    tcg_gen_movi_i64(cpu_ip, insn->address);
    ia64_tr_publish_fault_state(insn->address, insn->slot,
                                ia64_tr_decoded_slot_type(insn->unit),
                                insn->raw, insn->starts_group);
    gen_helper_data_plane_fp_check_disabled_set(
        tcg_env, tcg_constant_i64(packed));
}

static void ia64_tr_emit_decoded_disabled_fp_check(
    DisasContext *ctx, const IA64Instruction *insn,
    const IA64TrFpDescriptor *descriptor)
{
    uint8_t regs[4] = { insn->r1, };
    unsigned source_count =
        ia64_tr_fp_source_regs(insn, descriptor, &regs[1]);

    ia64_tr_emit_decoded_disabled_fp_regs(
        ctx, insn, regs, source_count + 1);
}

static void ia64_tr_fp_is_natval(DisasContext *ctx, TCGv_i64 result,
                                 TCGv_i64 low, TCGv_i64 high)
{
    TCGv_i64 low_zero = ia64_tr_scratch_i64(ctx);
    TCGv_i64 sign_exponent = ia64_tr_scratch_i64(ctx);

    tcg_gen_setcondi_i64(TCG_COND_EQ, low_zero, low, 0);
    tcg_gen_andi_i64(sign_exponent, high, UINT64_C(0x3ffff));
    tcg_gen_setcondi_i64(TCG_COND_EQ, sign_exponent, sign_exponent,
                         UINT64_C(0x1fffe));
    tcg_gen_and_i64(result, low_zero, sign_exponent);
}

static void ia64_tr_fp_accumulate_natval(
    DisasContext *ctx, TCGv_i64 any_nat, TCGv_i64 low, TCGv_i64 high)
{
    TCGv_i64 is_nat = ia64_tr_scratch_i64(ctx);

    ia64_tr_fp_is_natval(ctx, is_nat, low, high);
    tcg_gen_or_i64(any_nat, any_nat, is_nat);
}

static void ia64_tr_fp_classify(DisasContext *ctx, TCGv_i64 result,
                                TCGv_i64 is_nat, TCGv_i64 low,
                                TCGv_i64 high, uint16_t mask)
{
    TCGLabel *nat = gen_new_label();
    TCGLabel *qnan = gen_new_label();
    TCGLabel *snan = gen_new_label();
    TCGLabel *finite = gen_new_label();
    TCGLabel *zero = gen_new_label();
    TCGLabel *unnormalized = gen_new_label();
    TCGLabel *normalized = gen_new_label();
    TCGLabel *infinity = gen_new_label();
    TCGLabel *done = gen_new_label();
    TCGv_i64 exponent = ia64_tr_scratch_i64(ctx);
    TCGv_i64 integer_bit = ia64_tr_scratch_i64(ctx);
    TCGv_i64 quiet_bit = ia64_tr_scratch_i64(ctx);
    TCGv_i64 sign = ia64_tr_scratch_i64(ctx);
    TCGv_i64 sign_match = ia64_tr_scratch_i64(ctx);

    tcg_gen_movi_i64(result, 0);
    tcg_gen_andi_i64(exponent, high, UINT64_C(0x1ffff));
    tcg_gen_andi_i64(integer_bit, low,
                     UINT64_C(0x8000000000000000));
    tcg_gen_andi_i64(quiet_bit, low,
                     UINT64_C(0x4000000000000000));
    tcg_gen_andi_i64(sign, high, UINT64_C(0x20000));
    tcg_gen_movcond_i64(TCG_COND_NE, sign_match,
                        sign, tcg_constant_i64(0),
                        tcg_constant_i64((mask & 0x002) != 0),
                        tcg_constant_i64((mask & 0x001) != 0));

    tcg_gen_brcondi_i64(TCG_COND_NE, is_nat, 0, nat);
    tcg_gen_brcondi_i64(TCG_COND_NE, exponent, 0x1ffff, finite);
    tcg_gen_brcondi_i64(TCG_COND_EQ, low,
                        UINT64_C(0x8000000000000000), infinity);
    tcg_gen_brcondi_i64(TCG_COND_EQ, low, 0, done);
    tcg_gen_brcondi_i64(TCG_COND_EQ, integer_bit, 0, done);
    tcg_gen_brcondi_i64(TCG_COND_NE, quiet_bit, 0, qnan);
    tcg_gen_br(snan);

    gen_set_label(finite);
    tcg_gen_brcondi_i64(TCG_COND_NE, exponent, 0, normalized);
    tcg_gen_brcondi_i64(TCG_COND_EQ, low, 0, zero);
    tcg_gen_br(unnormalized);

    gen_set_label(normalized);
    tcg_gen_brcondi_i64(TCG_COND_EQ, integer_bit, 0, unnormalized);
    if ((mask & 0x010) != 0) {
        tcg_gen_mov_i64(result, sign_match);
    }
    tcg_gen_br(done);

    gen_set_label(unnormalized);
    if ((mask & 0x008) != 0) {
        tcg_gen_mov_i64(result, sign_match);
    }
    tcg_gen_br(done);

    gen_set_label(zero);
    if ((mask & 0x004) != 0) {
        tcg_gen_mov_i64(result, sign_match);
    }
    tcg_gen_br(done);

    gen_set_label(infinity);
    if ((mask & 0x020) != 0) {
        tcg_gen_mov_i64(result, sign_match);
    }
    tcg_gen_br(done);

    gen_set_label(snan);
    tcg_gen_movi_i64(result, (mask & 0x040) != 0);
    tcg_gen_br(done);

    gen_set_label(qnan);
    tcg_gen_movi_i64(result, (mask & 0x080) != 0);
    tcg_gen_br(done);

    gen_set_label(nat);
    tcg_gen_movi_i64(result, (mask & 0x100) != 0);
    gen_set_label(done);
}

static void ia64_tr_emit_decoded_fclass(
    DisasContext *ctx, const IA64Instruction *insn)
{
    IA64TrPrWrite *p1_write;
    IA64TrPrWrite *p2_write;
    TCGLabel *skip;
    TCGv_i64 low;
    TCGv_i64 high;
    TCGv_i64 is_nat;
    TCGv_i64 member;
    TCGv_i64 available;
    TCGv_i64 p1;
    TCGv_i64 p2;
    uint8_t source = insn->r2;
    uint16_t mask = insn->imm & 0x1ff;

    if (insn->p1 == insn->p2) {
        TCGLabel *resume = insn->compare_unc ? NULL :
                           ia64_tr_emit_decoded_predicate_guard(ctx, insn);

        if (resume == NULL) {
            resume = gen_new_label();
        }
        ia64_tr_emit_decoded_illegal_operation(ctx, insn);
        gen_set_label(resume);
        return;
    }

    ia64_tr_prime_decoded_instruction_state(ctx, insn);
    p1_write = ia64_tr_group_prepare_pr(ctx, insn->p1);
    p2_write = ia64_tr_group_prepare_pr(ctx, insn->p2);
    if (insn->compare_unc) {
        ia64_tr_group_stage_pr_const(p1_write, false);
        ia64_tr_group_stage_pr_const(p2_write, false);
    }
    skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
    ia64_tr_emit_decoded_disabled_fp_regs(ctx, insn, &source, 1);
    ia64_tr_finish_faulting_slot();

    low = ia64_tr_scratch_i64(ctx);
    high = ia64_tr_scratch_i64(ctx);
    is_nat = ia64_tr_scratch_i64(ctx);
    member = ia64_tr_scratch_i64(ctx);
    available = ia64_tr_scratch_i64(ctx);
    p1 = ia64_tr_scratch_i64(ctx);
    p2 = ia64_tr_scratch_i64(ctx);
    ia64_tr_group_load_ordinary_fr(
        ctx, low, high, source, IA64_FLOAT_FMT_SPILL_FILL);
    ia64_tr_fp_is_natval(ctx, is_nat, low, high);
    ia64_tr_fp_classify(ctx, member, is_nat, low, high, mask);
    if ((mask & 0x100) != 0) {
        tcg_gen_movi_i64(available, 1);
    } else {
        tcg_gen_xori_i64(available, is_nat, 1);
    }
    tcg_gen_and_i64(p1, member, available);
    tcg_gen_xori_i64(p2, member, 1);
    tcg_gen_and_i64(p2, p2, available);
    ia64_tr_group_stage_pr_bool(p1_write, p1);
    ia64_tr_group_stage_pr_bool(p2_write, p2);
    ia64_tr_finish_predicate_guard(skip);
}

static void ia64_tr_emit_decoded_getf_exact(
    DisasContext *ctx, const IA64Instruction *insn)
{
    IA64TrGrWrite *write;
    TCGLabel *skip;
    TCGv_i64 low;
    TCGv_i64 high;
    TCGv_i64 value;
    TCGv_i64 nat;
    uint8_t source = insn->r2;

    ia64_tr_prime_decoded_instruction_state(ctx, insn);
    if (insn->r1 == 0) {
        skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
        ia64_tr_emit_decoded_illegal_operation(ctx, insn);
        ia64_tr_finish_predicate_guard(skip);
        return;
    }
    write = ia64_tr_group_prepare_gr(ctx, insn->r1);
    skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
    ia64_tr_emit_application_target_check(ctx, insn);
    ia64_tr_emit_decoded_disabled_fp_regs(ctx, insn, &source, 1);
    ia64_tr_finish_faulting_slot();

    low = ia64_tr_scratch_i64(ctx);
    high = ia64_tr_scratch_i64(ctx);
    value = ia64_tr_scratch_i64(ctx);
    nat = ia64_tr_scratch_i64(ctx);
    ia64_tr_group_load_ordinary_fr(
        ctx, low, high, source, IA64_FLOAT_FMT_SPILL_FILL);
    if (insn->opcode == IA64_OP_GETF_SIG) {
        tcg_gen_mov_i64(value, low);
    } else {
        tcg_gen_andi_i64(value, high, UINT64_C(0x3ffff));
    }
    ia64_tr_fp_is_natval(ctx, nat, low, high);
    ia64_tr_group_stage_gr(write, value, nat);
    ia64_tr_finish_predicate_guard(skip);
}

static void ia64_tr_emit_decoded_setf_exact(
    DisasContext *ctx, const IA64Instruction *insn)
{
    TCGLabel *skip;
    TCGv_i64 value;
    TCGv_i64 nat;
    TCGv_i64 low;
    TCGv_i64 high;
    uint8_t target = insn->r1;

    ia64_tr_prime_decoded_instruction_state(ctx, insn);
    skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
    if (target < 2) {
        ia64_tr_emit_decoded_illegal_operation(ctx, insn);
        ia64_tr_finish_predicate_guard(skip);
        return;
    }
    ia64_tr_group_prepare_fr(ctx, target);
    ia64_tr_emit_decoded_disabled_fp_regs(ctx, insn, &target, 1);
    ia64_tr_finish_faulting_slot();

    value = ia64_tr_scratch_i64(ctx);
    nat = ia64_tr_scratch_i64(ctx);
    low = ia64_tr_scratch_i64(ctx);
    high = ia64_tr_scratch_i64(ctx);
    ia64_tr_group_load_ordinary_gr_pair(ctx, value, nat, insn->r2);
    if (insn->opcode == IA64_OP_SETF_SIG) {
        tcg_gen_mov_i64(low, value);
        tcg_gen_movi_i64(high, UINT64_C(0x1003e));
    } else {
        tcg_gen_movi_i64(low, UINT64_C(0x8000000000000000));
        tcg_gen_andi_i64(high, value, UINT64_C(0x3ffff));
    }
    tcg_gen_movcond_i64(TCG_COND_NE, low, nat, tcg_constant_i64(0),
                        tcg_constant_i64(0), low);
    tcg_gen_movcond_i64(TCG_COND_NE, high, nat, tcg_constant_i64(0),
                        tcg_constant_i64(UINT64_C(0x1fffe)), high);
    ia64_tr_group_stage_fr(
        ctx, tcg_constant_i64(0), low, high, target,
        IA64_FLOAT_FMT_SPILL_FILL);
    ia64_tr_finish_predicate_guard(skip);
}

static void ia64_tr_emit_reserved_register_field(
    DisasContext *ctx, const IA64Instruction *insn)
{
    ia64_tr_group_publish_prefix_for_noreturn_fault(ctx);
    tcg_gen_movi_i64(cpu_ip, insn->address);
    ia64_tr_publish_fault_state(insn->address, insn->slot,
                                ia64_tr_decoded_slot_type(insn->unit),
                                insn->raw, insn->starts_group);
    gen_helper_raise_reserved_register_field(tcg_env);
}

static void ia64_tr_emit_decoded_fsetc(
    DisasContext *ctx, const IA64Instruction *insn)
{
    TCGLabel *skip;
    TCGLabel *valid = gen_new_label();
    TCGv_i64 fpsr = ia64_tr_scratch_i64(ctx);
    TCGv_i64 controls = ia64_tr_scratch_i64(ctx);
    TCGv_i64 reserved = ia64_tr_scratch_i64(ctx);
    TCGv_i64 pc = ia64_tr_scratch_i64(ctx);
    TCGv_i64 result = ia64_tr_scratch_i64(ctx);
    unsigned shift = 6 + 13 * (insn->sf & 3);
    uint64_t field_mask = UINT64_C(0x7f) << shift;

    ia64_tr_prime_decoded_instruction_state(ctx, insn);
    skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
    ia64_tr_group_load_ordinary_ar(ctx, fpsr, IA64_AR_FPSR);
    tcg_gen_shri_i64(controls, fpsr, 6);
    tcg_gen_andi_i64(controls, controls, UINT64_C(0x7f));
    tcg_gen_andi_i64(controls, controls, insn->r2 & 0x7f);
    tcg_gen_ori_i64(controls, controls, insn->r3 & 0x7f);
    tcg_gen_shri_i64(pc, controls, 2);
    tcg_gen_andi_i64(pc, pc, 3);
    tcg_gen_setcondi_i64(TCG_COND_EQ, reserved, pc, 1);
    if ((insn->sf & 3) == 0) {
        TCGv_i64 td = ia64_tr_scratch_i64(ctx);

        tcg_gen_andi_i64(td, controls, UINT64_C(0x40));
        tcg_gen_or_i64(reserved, reserved, td);
    }
    tcg_gen_brcondi_i64(TCG_COND_EQ, reserved, 0, valid);
    ia64_tr_emit_reserved_register_field(ctx, insn);
    gen_set_label(valid);

    tcg_gen_andi_i64(result, fpsr, ~field_mask);
    tcg_gen_shli_i64(controls, controls, shift);
    tcg_gen_or_i64(result, result, controls);
    ia64_tr_store_ar(ctx, IA64_AR_FPSR, result);
    ia64_tr_finish_predicate_guard(skip);
}

static void ia64_tr_emit_decoded_fclrf(
    DisasContext *ctx, const IA64Instruction *insn)
{
    TCGLabel *skip;
    TCGv_i64 fpsr = ia64_tr_scratch_i64(ctx);
    uint64_t mask = UINT64_C(0x3f) <<
                    (13 + 13 * (insn->sf & 3));

    ia64_tr_prime_decoded_instruction_state(ctx, insn);
    skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
    ia64_tr_group_load_ordinary_ar(ctx, fpsr, IA64_AR_FPSR);
    tcg_gen_andi_i64(fpsr, fpsr, ~mask);
    ia64_tr_store_ar(ctx, IA64_AR_FPSR, fpsr);
    ia64_tr_finish_predicate_guard(skip);
}

static bool ia64_tr_emit_decoded_fp_direct_special(
    DisasContext *ctx, const IA64Instruction *insn)
{
    switch (insn->opcode) {
    case IA64_OP_FCLASS:
        ia64_tr_emit_decoded_fclass(ctx, insn);
        return true;
    case IA64_OP_GETF_EXP:
    case IA64_OP_GETF_SIG:
        ia64_tr_emit_decoded_getf_exact(ctx, insn);
        return true;
    case IA64_OP_SETF_EXP:
    case IA64_OP_SETF_SIG:
        ia64_tr_emit_decoded_setf_exact(ctx, insn);
        return true;
    case IA64_OP_FSETC:
        ia64_tr_emit_decoded_fsetc(ctx, insn);
        return true;
    case IA64_OP_FCLRF:
        ia64_tr_emit_decoded_fclrf(ctx, insn);
        return true;
    default:
        return false;
    }
}

static void ia64_tr_emit_decoded_fp_compute(
    DisasContext *ctx, const IA64Instruction *insn)
{
    const IA64TrFpDescriptor *descriptor =
        ia64_tr_decoded_fp_compute(insn->opcode);
    uint8_t source_regs[3];
    unsigned source_count;
    TCGLabel *skip;
    TCGv_i64 source_low[3] = { NULL, };
    TCGv_i64 source_high[3] = { NULL, };
    TCGv_i64 result_low;
    TCGv_i64 result_high;
    TCGv_i64 any_nat;

    g_assert(descriptor != NULL && descriptor->owner == IA64_TR_FP_DIRECT);
    if (ia64_tr_emit_decoded_fp_direct_special(ctx, insn)) {
        return;
    }
    ia64_tr_prime_decoded_instruction_state(ctx, insn);
    skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
    if (insn->r1 < 2) {
        ia64_tr_emit_decoded_illegal_operation(ctx, insn);
        ia64_tr_finish_predicate_guard(skip);
        return;
    }

    ia64_tr_group_prepare_fr(ctx, insn->r1);
    ia64_tr_emit_decoded_disabled_fp_check(ctx, insn, descriptor);
    ia64_tr_finish_faulting_slot();

    source_count = ia64_tr_fp_source_regs(insn, descriptor, source_regs);
    any_nat = ia64_tr_scratch_i64(ctx);
    tcg_gen_movi_i64(any_nat, 0);
    for (unsigned i = 0; i < source_count; i++) {
        source_low[i] = ia64_tr_scratch_i64(ctx);
        source_high[i] = ia64_tr_scratch_i64(ctx);
        ia64_tr_group_load_ordinary_fr(
            ctx, source_low[i], source_high[i], source_regs[i],
            IA64_FLOAT_FMT_SPILL_FILL);
        ia64_tr_fp_accumulate_natval(
            ctx, any_nat, source_low[i], source_high[i]);
    }

    result_low = ia64_tr_scratch_i64(ctx);
    result_high = ia64_tr_scratch_i64(ctx);
    switch (insn->opcode) {
    case IA64_OP_XMA_L:
    case IA64_OP_XMA_H:
    case IA64_OP_XMA_HU: {
        TCGv_i64 product_low = ia64_tr_scratch_i64(ctx);
        TCGv_i64 product_high = ia64_tr_scratch_i64(ctx);

        if (insn->opcode == IA64_OP_XMA_H) {
            tcg_gen_muls2_i64(product_low, product_high,
                              source_low[1], source_low[2]);
        } else {
            tcg_gen_mulu2_i64(product_low, product_high,
                              source_low[1], source_low[2]);
        }
        tcg_gen_add2_i64(product_low, product_high,
                         product_low, product_high, source_low[0],
                         tcg_constant_i64(0));
        tcg_gen_mov_i64(result_low,
                        insn->opcode == IA64_OP_XMA_L ?
                            product_low : product_high);
        tcg_gen_movi_i64(result_high, UINT64_C(0x1003e));
        break;
    }
    case IA64_OP_XMPY_HU: {
        TCGv_i64 product_low = ia64_tr_scratch_i64(ctx);

        tcg_gen_mulu2_i64(product_low, result_low,
                          source_low[0], source_low[1]);
        tcg_gen_movi_i64(result_high, UINT64_C(0x1003e));
        break;
    }
    case IA64_OP_FSELECT: {
        TCGv_i64 selected = ia64_tr_scratch_i64(ctx);

        tcg_gen_and_i64(result_low, source_low[1], source_low[0]);
        tcg_gen_andc_i64(selected, source_low[2], source_low[0]);
        tcg_gen_or_i64(result_low, result_low, selected);
        tcg_gen_movi_i64(result_high, UINT64_C(0x1003e));
        break;
    }
    case IA64_OP_FCVT_XF: {
        TCGv_i64 sign_mask = ia64_tr_scratch_i64(ctx);
        TCGv_i64 sign = ia64_tr_scratch_i64(ctx);
        TCGv_i64 magnitude = ia64_tr_scratch_i64(ctx);
        TCGv_i64 shift = ia64_tr_scratch_i64(ctx);

        tcg_gen_sari_i64(sign_mask, source_low[0], 63);
        tcg_gen_xor_i64(magnitude, source_low[0], sign_mask);
        tcg_gen_sub_i64(magnitude, magnitude, sign_mask);
        tcg_gen_clzi_i64(shift, magnitude, 64);
        tcg_gen_shl_i64(result_low, magnitude, shift);
        tcg_gen_shri_i64(sign, source_low[0], 63);
        tcg_gen_shli_i64(sign, sign, 17);
        tcg_gen_subfi_i64(result_high, UINT64_C(0x1003e), shift);
        tcg_gen_or_i64(result_high, result_high, sign);
        tcg_gen_movcond_i64(TCG_COND_EQ, result_high,
                            magnitude, tcg_constant_i64(0),
                            tcg_constant_i64(0), result_high);
        break;
    }
    case IA64_OP_FPABS:
        tcg_gen_andi_i64(result_low, source_low[0],
                         UINT64_C(0x7fffffff7fffffff));
        tcg_gen_movi_i64(result_high, UINT64_C(0x1003e));
        break;
    case IA64_OP_FPNEG:
        tcg_gen_xori_i64(result_low, source_low[0],
                         UINT64_C(0x8000000080000000));
        tcg_gen_movi_i64(result_high, UINT64_C(0x1003e));
        break;
    case IA64_OP_FPNEGABS:
        tcg_gen_ori_i64(result_low, source_low[0],
                        UINT64_C(0x8000000080000000));
        tcg_gen_movi_i64(result_high, UINT64_C(0x1003e));
        break;
    case IA64_OP_FMERGE:
        tcg_gen_mov_i64(result_low, source_low[1]);
        tcg_gen_andi_i64(result_high, source_high[1],
                         ~(UINT64_C(1) << 17));
        {
            TCGv_i64 sign = ia64_tr_scratch_i64(ctx);

            tcg_gen_not_i64(sign, source_high[0]);
            tcg_gen_andi_i64(sign, sign, UINT64_C(1) << 17);
            tcg_gen_or_i64(result_high, result_high, sign);
        }
        break;
    case IA64_OP_FMERGE_S:
        tcg_gen_mov_i64(result_low, source_low[1]);
        tcg_gen_andi_i64(result_high, source_high[1],
                         ~(UINT64_C(1) << 17));
        {
            TCGv_i64 sign = ia64_tr_scratch_i64(ctx);

            tcg_gen_andi_i64(sign, source_high[0], UINT64_C(1) << 17);
            tcg_gen_or_i64(result_high, result_high, sign);
        }
        break;
    case IA64_OP_FMERGE_SE:
        tcg_gen_mov_i64(result_low, source_low[1]);
        tcg_gen_mov_i64(result_high, source_high[0]);
        break;
    case IA64_OP_FAND:
        tcg_gen_and_i64(result_low, source_low[0], source_low[1]);
        tcg_gen_movi_i64(result_high, UINT64_C(0x1003e));
        break;
    case IA64_OP_FANDCM:
        tcg_gen_andc_i64(result_low, source_low[0], source_low[1]);
        tcg_gen_movi_i64(result_high, UINT64_C(0x1003e));
        break;
    case IA64_OP_FOR:
        tcg_gen_or_i64(result_low, source_low[0], source_low[1]);
        tcg_gen_movi_i64(result_high, UINT64_C(0x1003e));
        break;
    case IA64_OP_FXOR:
        tcg_gen_xor_i64(result_low, source_low[0], source_low[1]);
        tcg_gen_movi_i64(result_high, UINT64_C(0x1003e));
        break;
    case IA64_OP_FSWAP:
    case IA64_OP_FSWAP_NL:
    case IA64_OP_FSWAP_NR: {
        TCGv_i64 left = ia64_tr_scratch_i64(ctx);
        TCGv_i64 right = ia64_tr_scratch_i64(ctx);

        tcg_gen_ext32u_i64(left, source_low[1]);
        tcg_gen_shli_i64(left, left, 32);
        tcg_gen_shri_i64(right, source_low[0], 32);
        tcg_gen_or_i64(result_low, left, right);
        if (insn->opcode == IA64_OP_FSWAP_NL) {
            tcg_gen_xori_i64(result_low, result_low,
                             UINT64_C(0x8000000000000000));
        } else if (insn->opcode == IA64_OP_FSWAP_NR) {
            tcg_gen_xori_i64(result_low, result_low,
                             UINT64_C(0x0000000080000000));
        }
        tcg_gen_movi_i64(result_high, UINT64_C(0x1003e));
        break;
    }
    case IA64_OP_FMIX_LR:
    case IA64_OP_FMIX_R:
    case IA64_OP_FMIX_L: {
        TCGv_i64 high_lane = ia64_tr_scratch_i64(ctx);
        TCGv_i64 low_lane = ia64_tr_scratch_i64(ctx);

        if (insn->opcode == IA64_OP_FMIX_R) {
            tcg_gen_ext32u_i64(high_lane, source_low[0]);
        } else {
            tcg_gen_shri_i64(high_lane, source_low[0], 32);
        }
        if (insn->opcode == IA64_OP_FMIX_L) {
            tcg_gen_shri_i64(low_lane, source_low[1], 32);
        } else {
            tcg_gen_ext32u_i64(low_lane, source_low[1]);
        }
        tcg_gen_shli_i64(high_lane, high_lane, 32);
        tcg_gen_or_i64(result_low, high_lane, low_lane);
        tcg_gen_movi_i64(result_high, UINT64_C(0x1003e));
        break;
    }
    case IA64_OP_FSXT_R: {
        TCGv_i64 high_lane = ia64_tr_scratch_i64(ctx);
        TCGv_i64 low_lane = ia64_tr_scratch_i64(ctx);

        tcg_gen_sextract_i64(high_lane, source_low[0], 31, 1);
        tcg_gen_shli_i64(high_lane, high_lane, 32);
        tcg_gen_ext32u_i64(low_lane, source_low[1]);
        tcg_gen_or_i64(result_low, high_lane, low_lane);
        tcg_gen_movi_i64(result_high, UINT64_C(0x1003e));
        break;
    }
    case IA64_OP_FSXT_L: {
        TCGv_i64 high_lane = ia64_tr_scratch_i64(ctx);
        TCGv_i64 low_lane = ia64_tr_scratch_i64(ctx);

        tcg_gen_sari_i64(high_lane, source_low[0], 63);
        tcg_gen_shli_i64(high_lane, high_lane, 32);
        tcg_gen_shri_i64(low_lane, source_low[1], 32);
        tcg_gen_or_i64(result_low, high_lane, low_lane);
        tcg_gen_movi_i64(result_high, UINT64_C(0x1003e));
        break;
    }
    case IA64_OP_FPMERGE:
    case IA64_OP_FPMERGE_S:
    case IA64_OP_FPMERGE_SE: {
        TCGv_i64 left = ia64_tr_scratch_i64(ctx);
        TCGv_i64 right = ia64_tr_scratch_i64(ctx);

        if (insn->opcode == IA64_OP_FPMERGE_SE) {
            tcg_gen_andi_i64(left, source_low[0],
                             UINT64_C(0xff800000ff800000));
            tcg_gen_andi_i64(right, source_low[1],
                             UINT64_C(0x007fffff007fffff));
        } else {
            tcg_gen_andi_i64(left, source_low[0],
                             UINT64_C(0x8000000080000000));
            if (insn->opcode == IA64_OP_FPMERGE) {
                tcg_gen_xori_i64(left, left,
                                 UINT64_C(0x8000000080000000));
            }
            tcg_gen_andi_i64(right, source_low[1],
                             UINT64_C(0x7fffffff7fffffff));
        }
        tcg_gen_or_i64(result_low, left, right);
        tcg_gen_movi_i64(result_high, UINT64_C(0x1003e));
        break;
    }
    default:
        g_assert_not_reached();
    }

    tcg_gen_movcond_i64(TCG_COND_NE, result_low,
                        any_nat, tcg_constant_i64(0),
                        tcg_constant_i64(0), result_low);
    tcg_gen_movcond_i64(TCG_COND_NE, result_high,
                        any_nat, tcg_constant_i64(0),
                        tcg_constant_i64(UINT64_C(0x1fffe)), result_high);
    ia64_tr_group_stage_fr(
        ctx, tcg_constant_i64(0), result_low, result_high, insn->r1,
        IA64_FLOAT_FMT_SPILL_FILL);
    ia64_tr_finish_predicate_guard(skip);
}

static uint64_t ia64_tr_fp_controls(const IA64Instruction *insn)
{
    uint64_t controls = insn->sf & 3;

    controls |= (uint64_t)(insn->fp_precision & 3) << 2;
    controls |= (uint64_t)(insn->imm & 0xff) << 4;
    controls |= (uint64_t)(insn->p1 & 0x3f) << 12;
    controls |= (uint64_t)(insn->p2 & 0x3f) << 18;
    controls |= (uint64_t)insn->compare_unc << 24;
    return controls;
}

static void ia64_tr_emit_decoded_fp_focused(
    DisasContext *ctx, const IA64Instruction *insn)
{
    const IA64TrFpDescriptor *descriptor =
        ia64_tr_decoded_fp_compute(insn->opcode);
    IA64TrPrWrite *p1_write = NULL;
    IA64TrPrWrite *p2_write = NULL;
    IA64TrGrWrite *gr_write = NULL;
    uint8_t sources[3];
    uint8_t checked[4];
    unsigned source_count;
    unsigned checked_count = 0;
    TCGLabel *skip;
    TCGv_i64 helper_result;

    g_assert(descriptor != NULL && descriptor->owner == IA64_TR_FP_FOCUSED);
    ia64_tr_require_helper(insn->opcode,
                           IA64_OPCODE_HELPER_DATA_PLANE);

    if (insn->opcode == IA64_OP_FCMP && insn->p1 == insn->p2) {
        TCGLabel *resume = insn->compare_unc ? NULL :
                           ia64_tr_emit_decoded_predicate_guard(ctx, insn);

        if (resume == NULL) {
            resume = gen_new_label();
        }
        ia64_tr_emit_decoded_illegal_operation(ctx, insn);
        gen_set_label(resume);
        return;
    }

    ia64_tr_prime_decoded_instruction_state(ctx, insn);
    if (insn->opcode == IA64_OP_FCMP) {
        p1_write = ia64_tr_group_prepare_pr(ctx, insn->p1);
        p2_write = ia64_tr_group_prepare_pr(ctx, insn->p2);
        if (insn->compare_unc) {
            ia64_tr_group_stage_pr_const(p1_write, false);
            ia64_tr_group_stage_pr_const(p2_write, false);
        }
    } else if (ia64_tr_fp_is_approximation(insn->opcode)) {
        p2_write = ia64_tr_group_prepare_pr(ctx, insn->p2);
        /* F6/F7 clear p2 independently of qualification. */
        ia64_tr_group_stage_pr_const(p2_write, false);
    } else if (ia64_tr_fp_is_getf(insn->opcode)) {
        gr_write = ia64_tr_group_prepare_gr(ctx, insn->r1);
    }

    skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
    if ((ia64_tr_fp_has_fr_destination(insn->opcode) && insn->r1 < 2) ||
        (ia64_tr_fp_is_getf(insn->opcode) && insn->r1 == 0)) {
        ia64_tr_emit_decoded_illegal_operation(ctx, insn);
        ia64_tr_finish_predicate_guard(skip);
        return;
    }

    if (ia64_tr_fp_has_fr_destination(insn->opcode)) {
        ia64_tr_group_prepare_fr(ctx, insn->r1);
        checked[checked_count++] = insn->r1;
    }
    source_count = ia64_tr_fp_source_regs(insn, descriptor, sources);
    for (unsigned i = 0; i < source_count; i++) {
        checked[checked_count++] = sources[i];
    }
    ia64_tr_emit_decoded_disabled_fp_regs(
        ctx, insn, checked, checked_count);
    ia64_tr_finish_faulting_slot();

    helper_result = ia64_tr_scratch_i64(ctx);
    gen_helper_fp_compute(
        helper_result, tcg_env, tcg_constant_i32(insn->opcode),
        tcg_constant_i32(insn->r1), tcg_constant_i32(insn->r2),
        tcg_constant_i32(insn->r3), tcg_constant_i32(insn->r4),
        tcg_constant_i64(ia64_tr_fp_controls(insn)));

    if (insn->opcode == IA64_OP_FCMP) {
        TCGv_i64 p1 = ia64_tr_scratch_i64(ctx);
        TCGv_i64 p2 = ia64_tr_scratch_i64(ctx);

        tcg_gen_andi_i64(p1, helper_result, 1);
        tcg_gen_shri_i64(p2, helper_result, 1);
        tcg_gen_andi_i64(p2, p2, 1);
        ia64_tr_group_stage_pr_bool(p1_write, p1);
        ia64_tr_group_stage_pr_bool(p2_write, p2);
    } else if (ia64_tr_fp_is_approximation(insn->opcode)) {
        TCGv_i64 predicate = ia64_tr_scratch_i64(ctx);

        tcg_gen_andi_i64(predicate, helper_result, 1);
        ia64_tr_group_stage_pr_bool(p2_write, predicate);
    } else if (ia64_tr_fp_is_getf(insn->opcode)) {
        TCGv_i64 low = ia64_tr_scratch_i64(ctx);
        TCGv_i64 high = ia64_tr_scratch_i64(ctx);
        TCGv_i64 nat = ia64_tr_scratch_i64(ctx);

        ia64_tr_group_load_ordinary_fr(
            ctx, low, high, insn->r2, IA64_FLOAT_FMT_SPILL_FILL);
        ia64_tr_fp_is_natval(ctx, nat, low, high);
        ia64_tr_group_stage_gr(gr_write, helper_result, nat);
    }
    ia64_tr_finish_predicate_guard(skip);
}

static bool ia64_tr_data_plane_fp_load_statically_illegal(
    const IA64Instruction *insn,
    const IA64TrDataPlaneDescriptor *descriptor)
{
    bool pair = descriptor->kind == IA64_TR_DATA_PLANE_FP_LOAD_PAIR;
    bool update = insn->reg_base_update || insn->imm_base_update;

    return insn->r1 < 2 || (pair && insn->r2 < 2) ||
           (update && insn->r3 == 0);
}

static void ia64_tr_emit_decoded_data_plane_fp_pair_check(
    DisasContext *ctx, const IA64Instruction *insn)
{
    TCGLabel *legal = gen_new_label();
    TCGv_i32 pair_legal = ia64_tr_scratch_i32(ctx);

    gen_helper_data_plane_fp_pair_legal(
        pair_legal, tcg_env, tcg_constant_i32(insn->r1),
        tcg_constant_i32(insn->r2));
    tcg_gen_brcondi_i32(TCG_COND_NE, pair_legal, 0, legal);
    ia64_tr_emit_decoded_illegal_operation(ctx, insn);
    gen_set_label(legal);
}

static void ia64_tr_emit_decoded_data_plane_fp_load(
    DisasContext *ctx, const IA64Instruction *insn,
    const IA64TrDataPlaneDescriptor *descriptor)
{
    bool pair = descriptor->kind == IA64_TR_DATA_PLANE_FP_LOAD_PAIR;
    bool update = insn->reg_base_update || insn->imm_base_update;
    bool big_endian = (ctx->base.tb->flags & IA64_TB_FLAG_BE) != 0;
    IA64FloatingMemoryFormat format =
        ia64_tr_data_plane_fp_format(insn->opcode);
    uint8_t memory_class =
        ia64_tr_data_plane_fp_memory_class(insn, descriptor);
    uint8_t payload = descriptor->width;
    uint8_t alignment = payload == 10 ? 16 : payload;
    uint8_t debug_span = payload == 10 ? 16 : payload;
    uint32_t targets = insn->r1 | ((uint32_t)insn->r2 << 8) |
                       ((uint32_t)pair << 16);
    uint32_t info = format | ((uint32_t)payload << 8) |
                    ((uint32_t)memory_class << 16);
    IA64TrGrWrite *base_write = NULL;
    TCGLabel *skip;
    TCGLabel *memory = gen_new_label();
    TCGLabel *base_nat_fault = gen_new_label();
    TCGLabel *done = gen_new_label();
    TCGv_i64 base = ia64_tr_scratch_i64(ctx);
    TCGv_i64 base_nat = ia64_tr_scratch_i64(ctx);
    TCGv_i64 increment = ia64_tr_scratch_i64(ctx);
    TCGv_i64 increment_nat = ia64_tr_scratch_i64(ctx);
    TCGv_i64 low = ia64_tr_scratch_i64(ctx);
    TCGv_i64 high = ia64_tr_scratch_i64(ctx);
    TCGv_i64 updated = ia64_tr_scratch_i64(ctx);
    TCGv_i32 action = ia64_tr_scratch_i32(ctx);

    ia64_tr_require_helper(insn->opcode,
                           IA64_OPCODE_HELPER_SPECIAL_LDST);

    g_assert(descriptor->kind == IA64_TR_DATA_PLANE_FP_LOAD || pair);
    ia64_tr_prime_decoded_instruction_state(ctx, insn);
    if (ia64_tr_data_plane_fp_load_statically_illegal(insn, descriptor)) {
        skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
        ia64_tr_emit_decoded_illegal_operation(ctx, insn);
        ia64_tr_finish_predicate_guard(skip);
        return;
    }

    ia64_tr_group_prepare_fr(ctx, insn->r1);
    if (pair) {
        ia64_tr_group_prepare_fr(ctx, insn->r2);
    }
    if (memory_class == 2 || memory_class == 3 || memory_class == 9) {
        ia64_tr_group_prepare_post_alat_record(
            ctx, insn->r1, payload, IA64_ALAT_TARGET_FR, memory_class);
    }
    if (update) {
        base_write = ia64_tr_group_prepare_gr(ctx, insn->r3);
    }
    skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);

    /* Pair-bank legality is checked before the GR update target and before
       either disabled-FR or base-NaT delivery. */
    if (pair) {
        ia64_tr_emit_decoded_data_plane_fp_pair_check(ctx, insn);
    }
    if (update) {
        ia64_tr_emit_decoded_memory_target_check(ctx, insn, insn->r3);
    }

    ia64_tr_group_load_ordinary_gr_pair(ctx, base, base_nat, insn->r3);
    if (insn->reg_base_update) {
        if (insn->r2 == insn->r3) {
            tcg_gen_mov_i64(increment, base);
            tcg_gen_mov_i64(increment_nat, base_nat);
        } else {
            ia64_tr_group_load_ordinary_gr_pair(
                ctx, increment, increment_nat, insn->r2);
        }
    } else {
        tcg_gen_movi_i64(increment, (uint64_t)insn->imm);
        tcg_gen_movi_i64(increment_nat, 0);
    }

    ia64_tr_publish_decoded_memory_access(ctx, insn);
    gen_helper_data_plane_fp_load_prepare(
        action, tcg_env, base, base_nat, tcg_constant_i32(targets),
        tcg_constant_i32(info));
    tcg_gen_brcondi_i32(TCG_COND_EQ, action,
                        IA64_TR_FP_LOAD_CONTINUE, memory);
    tcg_gen_brcondi_i32(TCG_COND_EQ, action,
                        IA64_TR_FP_LOAD_BASE_NAT, base_nat_fault);
    /* ALAT hit, speculative deferral, and advanced-zero have already
       completed their destination semantics and perform no memory access. */
    tcg_gen_br(done);

    gen_set_label(base_nat_fault);
    ia64_tr_emit_decoded_memory_nat_check(
        ctx, insn, base_nat, MMU_DATA_LOAD, true);
    tcg_gen_br(done);

    gen_set_label(memory);
    ia64_tr_emit_decoded_data_debug_pre_access(
        ctx, base, debug_span, IA64_DEBUG_ACCESS_READ);
    ia64_tr_emit_decoded_memory_alignment_span_check(
        ctx, insn, base, alignment, payload, MMU_DATA_LOAD);
    if (format == IA64_FLOAT_FMT_EXTENDED) {
        gen_helper_data_plane_wb_only_probe(
            tcg_env, base, tcg_constant_i32(0));
        gen_helper_data_plane_fp_extended_preflight(
            tcg_env, base,
            tcg_constant_i32(ia64_tr_data_mmu_index(ctx)),
            tcg_constant_i32(0));
    }
    tcg_gen_movi_i64(low, 0);
    tcg_gen_movi_i64(high, 0);
    switch (format) {
    case IA64_FLOAT_FMT_SINGLE:
        if (pair) {
            TCGv_i64 packed = ia64_tr_scratch_i64(ctx);

            tcg_gen_qemu_ld_i64(
                packed, base, ia64_tr_data_mmu_index(ctx),
                ia64_tr_ldst_memop(ctx, 8));
            if (big_endian) {
                tcg_gen_shri_i64(low, packed, 32);
                tcg_gen_ext32u_i64(high, packed);
            } else {
                tcg_gen_ext32u_i64(low, packed);
                tcg_gen_shri_i64(high, packed, 32);
            }
        } else {
            tcg_gen_qemu_ld_i64(
                low, base, ia64_tr_data_mmu_index(ctx),
                ia64_tr_ldst_memop(ctx, 4));
        }
        break;
    case IA64_FLOAT_FMT_DOUBLE:
    case IA64_FLOAT_FMT_SIGNIFICAND:
        if (pair) {
            TCGv_i128 packed = tcg_temp_new_i128();
            TCGv_i64 numeric_low = ia64_tr_scratch_i64(ctx);
            TCGv_i64 numeric_high = ia64_tr_scratch_i64(ctx);

            tcg_gen_qemu_ld_i128(
                packed, base, ia64_tr_data_mmu_index(ctx),
                MO_128 | (big_endian ? MO_BE : MO_LE));
            tcg_gen_extr_i128_i64(numeric_low, numeric_high, packed);
            if (big_endian) {
                tcg_gen_mov_i64(low, numeric_high);
                tcg_gen_mov_i64(high, numeric_low);
            } else {
                tcg_gen_mov_i64(low, numeric_low);
                tcg_gen_mov_i64(high, numeric_high);
            }
        } else {
            tcg_gen_qemu_ld_i64(
                low, base, ia64_tr_data_mmu_index(ctx),
                ia64_tr_ldst_memop(ctx, 8));
        }
        break;
    case IA64_FLOAT_FMT_EXTENDED: {
        TCGv_i64 second = ia64_tr_scratch_i64(ctx);

        if (big_endian) {
            tcg_gen_qemu_ld_i64(
                high, base, ia64_tr_data_mmu_index(ctx),
                ia64_tr_ldst_memop(ctx, 2));
            tcg_gen_addi_i64(second, base, 2);
            tcg_gen_qemu_ld_i64(
                low, second, ia64_tr_data_mmu_index(ctx),
                ia64_tr_ldst_memop(ctx, 8));
        } else {
            tcg_gen_qemu_ld_i64(
                low, base, ia64_tr_data_mmu_index(ctx),
                ia64_tr_ldst_memop(ctx, 8));
            tcg_gen_addi_i64(second, base, 8);
            tcg_gen_qemu_ld_i64(
                high, second, ia64_tr_data_mmu_index(ctx),
                ia64_tr_ldst_memop(ctx, 2));
        }
        break;
    }
    case IA64_FLOAT_FMT_SPILL_FILL: {
        TCGv_i128 packed = tcg_temp_new_i128();

        tcg_gen_qemu_ld_i128(
            packed, base, ia64_tr_data_mmu_index(ctx),
            MO_128 | (big_endian ? MO_BE : MO_LE));
        /* Both endian layouts decode to mantissa in the numeric low half and
           the 18-bit sign/exponent image in the numeric high half. */
        tcg_gen_extr_i128_i64(low, high, packed);
        break;
    }
    default:
        g_assert_not_reached();
    }

    ia64_tr_group_stage_fr(ctx, base, low, high, targets, info);
    if (memory_class == 2 || memory_class == 3 || memory_class == 9) {
        ia64_tr_group_stage_post_alat_record(
            ctx->rewrite_group.current, base);
    }

    gen_set_label(done);
    if (update) {
        if (insn->reg_base_update) {
            tcg_gen_add_i64(updated, base, increment);
            tcg_gen_or_i64(increment_nat, increment_nat, base_nat);
            ia64_tr_group_stage_gr(base_write, updated, increment_nat);
        } else {
            tcg_gen_addi_i64(updated, base, insn->imm);
            ia64_tr_group_stage_gr(base_write, updated, base_nat);
        }
    }
    ia64_tr_finish_faulting_slot();
    ia64_tr_finish_predicate_guard(skip);
}

static void ia64_tr_emit_decoded_data_plane_fp_store(
    DisasContext *ctx, const IA64Instruction *insn,
    const IA64TrDataPlaneDescriptor *descriptor)
{
    bool update = insn->imm_base_update;
    bool big_endian = (ctx->base.tb->flags & IA64_TB_FLAG_BE) != 0;
    IA64FloatingMemoryFormat format =
        ia64_tr_data_plane_fp_format(insn->opcode);
    uint8_t payload = descriptor->width;
    uint8_t alignment = payload == 10 ? 16 : payload;
    uint8_t debug_span = payload == 10 ? 16 : payload;
    IA64TrGrWrite *base_write = NULL;
    TCGLabel *skip;
    TCGLabel *memory = gen_new_label();
    TCGLabel *base_nat_fault = gen_new_label();
    TCGLabel *value_nat_fault = gen_new_label();
    TCGLabel *done = gen_new_label();
    TCGv_i64 base = ia64_tr_scratch_i64(ctx);
    TCGv_i64 base_nat = ia64_tr_scratch_i64(ctx);
    TCGv_i64 low = ia64_tr_scratch_i64(ctx);
    TCGv_i64 high = ia64_tr_scratch_i64(ctx);
    TCGv_i64 updated = ia64_tr_scratch_i64(ctx);
    TCGv_i32 action = ia64_tr_scratch_i32(ctx);

    g_assert(descriptor->kind == IA64_TR_DATA_PLANE_FP_STORE);
    ia64_tr_require_helper(insn->opcode,
                           IA64_OPCODE_HELPER_SPECIAL_LDST);
    ia64_tr_prime_decoded_instruction_state(ctx, insn);
    if (update && insn->r3 == 0) {
        skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
        ia64_tr_emit_decoded_illegal_operation(ctx, insn);
        ia64_tr_finish_predicate_guard(skip);
        return;
    }
    if (update) {
        base_write = ia64_tr_group_prepare_gr(ctx, insn->r3);
    }
    skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
    if (update) {
        ia64_tr_emit_decoded_memory_target_check(ctx, insn, insn->r3);
    }
    ia64_tr_group_load_ordinary_gr_pair(ctx, base, base_nat, insn->r3);

    /* Disabled FR has priority over base NaT, which in turn has priority over
       a source NaTVal. */
    ia64_tr_publish_decoded_memory_access(ctx, insn);
    gen_helper_data_plane_fp_store_prepare(
        action, tcg_env, base_nat, tcg_constant_i32(insn->r2),
        tcg_constant_i32(format));
    tcg_gen_brcondi_i32(TCG_COND_EQ, action,
                        IA64_TR_FP_STORE_CONTINUE, memory);
    tcg_gen_brcondi_i32(TCG_COND_EQ, action,
                        IA64_TR_FP_STORE_BASE_NAT, base_nat_fault);
    tcg_gen_br(value_nat_fault);

    gen_set_label(base_nat_fault);
    ia64_tr_emit_decoded_memory_nat_check(
        ctx, insn, base_nat, MMU_DATA_STORE, true);
    tcg_gen_br(done);

    gen_set_label(value_nat_fault);
    ia64_tr_emit_decoded_memory_nat_check(
        ctx, insn, tcg_constant_i64(1), MMU_DATA_STORE, false);
    tcg_gen_br(done);

    gen_set_label(memory);
    ia64_tr_emit_decoded_data_debug_pre_access(
        ctx, base, debug_span, IA64_DEBUG_ACCESS_WRITE);
    ia64_tr_emit_decoded_memory_alignment_span_check(
        ctx, insn, base, alignment, payload, MMU_DATA_STORE);
    if (format == IA64_FLOAT_FMT_EXTENDED) {
        gen_helper_data_plane_wb_only_probe(
            tcg_env, base, tcg_constant_i32(1));
        gen_helper_data_plane_fp_extended_preflight(
            tcg_env, base,
            tcg_constant_i32(ia64_tr_data_mmu_index(ctx)),
            tcg_constant_i32(1));
    }
    ia64_tr_group_load_ordinary_fr(
        ctx, low, high, insn->r2, format);
    switch (format) {
    case IA64_FLOAT_FMT_SINGLE:
        tcg_gen_qemu_st_i64(
            low, base, ia64_tr_data_mmu_index(ctx),
            ia64_tr_ldst_memop(ctx, 4));
        break;
    case IA64_FLOAT_FMT_DOUBLE:
    case IA64_FLOAT_FMT_SIGNIFICAND:
        tcg_gen_qemu_st_i64(
            low, base, ia64_tr_data_mmu_index(ctx),
            ia64_tr_ldst_memop(ctx, 8));
        break;
    case IA64_FLOAT_FMT_EXTENDED: {
        TCGv_i64 second = ia64_tr_scratch_i64(ctx);

        if (big_endian) {
            tcg_gen_qemu_st_i64(
                high, base, ia64_tr_data_mmu_index(ctx),
                ia64_tr_ldst_memop(ctx, 2));
            tcg_gen_addi_i64(second, base, 2);
            tcg_gen_qemu_st_i64(
                low, second, ia64_tr_data_mmu_index(ctx),
                ia64_tr_ldst_memop(ctx, 8));
        } else {
            tcg_gen_qemu_st_i64(
                low, base, ia64_tr_data_mmu_index(ctx),
                ia64_tr_ldst_memop(ctx, 8));
            tcg_gen_addi_i64(second, base, 8);
            tcg_gen_qemu_st_i64(
                high, second, ia64_tr_data_mmu_index(ctx),
                ia64_tr_ldst_memop(ctx, 2));
        }
        break;
    }
    case IA64_FLOAT_FMT_SPILL_FILL: {
        TCGv_i128 packed = tcg_temp_new_i128();

        tcg_gen_concat_i64_i128(packed, low, high);
        tcg_gen_qemu_st_i128(
            packed, base, ia64_tr_data_mmu_index(ctx),
            MO_128 | (big_endian ? MO_BE : MO_LE));
        break;
    }
    default:
        g_assert_not_reached();
    }
    ia64_tr_emit_decoded_store_alat_invalidate(ctx, base, payload);
    if (update) {
        tcg_gen_addi_i64(updated, base, insn->imm);
        ia64_tr_group_stage_gr(
            base_write, updated, tcg_constant_i64(0));
    }

    gen_set_label(done);
    ia64_tr_finish_faulting_slot();
    ia64_tr_finish_predicate_guard(skip);
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
        ia64_tr_finish_predicate_guard(skip);
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
        ia64_tr_finish_predicate_guard(skip);
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
        ia64_tr_finish_predicate_guard(skip);
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
        ia64_tr_finish_predicate_guard(skip);
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
        ia64_tr_finish_predicate_guard(skip);
    }
}

static void ia64_tr_publish_application_helper_state(
    DisasContext *ctx, const IA64Instruction *insn)
{
    ia64_tr_group_publish_state_for_returning_helper(ctx);
    tcg_gen_movi_i64(cpu_ip, insn->address);
    ia64_tr_publish_fault_state(insn->address, insn->slot,
                                ia64_tr_decoded_slot_type(insn->unit),
                                insn->raw, insn->starts_group);
}

static void ia64_tr_emit_application_target_check(
    DisasContext *ctx, const IA64Instruction *insn)
{
    TCGLabel *valid;
    TCGv_i64 sof;

    if (insn->r1 == 0) {
        ia64_tr_emit_decoded_illegal_operation(ctx, insn);
        return;
    }
    if (insn->r1 < IA64_STATIC_GR_COUNT) {
        return;
    }

    valid = gen_new_label();
    sof = ia64_tr_scratch_i64(ctx);
    tcg_gen_ld_i64(sof, tcg_env, offsetof(CPUIA64State, cfm));
    tcg_gen_andi_i64(sof, sof, 0x7f);
    tcg_gen_brcondi_i64(TCG_COND_GTU, sof,
                        insn->r1 - IA64_STATIC_GR_COUNT, valid);
    ia64_tr_emit_decoded_illegal_operation(ctx, insn);
    gen_set_label(valid);
}

static void ia64_tr_emit_application_write_value_check(
    DisasContext *ctx, const IA64Instruction *insn,
    uint32_t selector, TCGv_i64 value)
{
    TCGLabel *valid_value = gen_new_label();
    TCGv_i32 valid = ia64_tr_scratch_i32(ctx);

    gen_helper_application_register_write_value_valid(
        valid, tcg_constant_i32(selector), value);
    tcg_gen_brcondi_i32(TCG_COND_NE, valid, 0, valid_value);
    ia64_tr_group_publish_prefix_for_noreturn_fault(ctx);
    tcg_gen_movi_i64(cpu_ip, insn->address);
    ia64_tr_publish_fault_state(insn->address, insn->slot,
                                ia64_tr_decoded_slot_type(insn->unit),
                                insn->raw, insn->starts_group);
    gen_helper_raise_reserved_register_field(tcg_env);
    gen_set_label(valid_value);
}

static void ia64_tr_emit_decoded_application_move(
    DisasContext *ctx, const IA64Instruction *insn)
{
    IA64TrInstructionTransaction *instruction =
        ctx->rewrite_group.current;
    TCGLabel *skip;

    g_assert((insn->opcode == IA64_OP_MOV_ARGR ||
              insn->opcode == IA64_OP_MOV_GRAR) &&
             ia64_tr_decoded_is_supported_application_move(insn));
    ia64_tr_require_helper(insn->opcode,
                           IA64_OPCODE_HELPER_SYSTEM_PLANE);
    ia64_tr_prime_decoded_instruction_state(ctx, insn);

    if (insn->status != IA64_DECODE_OK) {
        skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
        ia64_tr_system_validate(ctx, insn);
        ia64_tr_finish_predicate_guard(skip);
        return;
    }

    if (insn->opcode == IA64_OP_MOV_ARGR) {
        IA64TrGrWrite *gr_write =
            ia64_tr_group_prepare_gr(ctx, insn->r1);
        TCGv_i64 value = ia64_tr_scratch_i64(ctx);
        uint64_t expected = UINT64_C(1) << (insn->r2 & 63);

        g_assert(instruction->source_ar[insn->r2 >> 6] == expected &&
                 instruction->source_ar[(insn->r2 >> 6) ^ 1] == 0 &&
                 instruction->dest_ar[0] == 0 &&
                 instruction->dest_ar[1] == 0 &&
                 !instruction->forward_pfs);
        skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
        ia64_tr_emit_application_target_check(ctx, insn);
        if (insn->r2 == IA64_AR_PFS) {
            g_assert(!instruction->branch_source_pfs);
            ia64_tr_group_load_ordinary_pfs(ctx, value);
        } else {
            if (insn->r2 == IA64_AR_ITC &&
                (tb_cflags(ctx->base.tb) & CF_USE_ICOUNT) != 0) {
                translator_io_start(&ctx->base);
            }
            ia64_tr_publish_application_helper_state(ctx, insn);
            gen_helper_application_register_preflight(
                tcg_env, tcg_constant_i32(insn->r2),
                tcg_constant_i32(0));
            ia64_tr_reload_state_cache(ctx);
            gen_helper_application_register_read(
                value, tcg_env, tcg_constant_i32(insn->r2));
            ia64_tr_reload_state_cache(ctx);
            ia64_tr_finish_faulting_slot();
        }
        ia64_tr_group_stage_gr(gr_write, value, tcg_constant_i64(0));
        ia64_tr_finish_predicate_guard(skip);
        return;
    }

    {
        TCGLabel *nat_clear = gen_new_label();
        TCGv_i64 value = ia64_tr_scratch_i64(ctx);
        TCGv_i64 nat = ia64_tr_scratch_i64(ctx);
        uint64_t expected[2] = { 0, 0 };

        ia64_tr_plan_ar_write_resources(expected, insn->r2);

        g_assert(instruction->source_ar[0] == 0 &&
                 instruction->source_ar[1] == 0 &&
                 instruction->dest_ar[0] == expected[0] &&
                 instruction->dest_ar[1] == expected[1] &&
                 instruction->forward_pfs ==
                    (insn->r2 == IA64_AR_PFS) &&
                 instruction->must_pfs ==
                    (insn->r2 == IA64_AR_PFS && insn->qp == 0));
        skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
        if (insn->r2 != IA64_AR_PFS) {
            if (insn->r2 == IA64_AR_ITC &&
                (tb_cflags(ctx->base.tb) & CF_USE_ICOUNT) != 0) {
                translator_io_start(&ctx->base);
            }
            ia64_tr_publish_application_helper_state(ctx, insn);
            gen_helper_application_register_write_legality(
                tcg_env, tcg_constant_i32(insn->r2));
            ia64_tr_reload_state_cache(ctx);
        }
        ia64_tr_group_load_ordinary_gr_pair(ctx, value, nat, insn->r1);
        tcg_gen_brcondi_i64(TCG_COND_EQ, nat, 0, nat_clear);
        ia64_tr_emit_decoded_register_nat_consumption(ctx, insn);
        gen_set_label(nat_clear);
        if (insn->r2 == IA64_AR_PFS) {
            ia64_tr_emit_application_write_value_check(
                ctx, insn, insn->r2, value);
            ia64_tr_group_write_pfs(ctx, value, instruction->must_pfs);
        } else {
            ia64_tr_publish_application_helper_state(ctx, insn);
            gen_helper_application_register_write(
                tcg_env, tcg_constant_i32(insn->r2), value);
            ia64_tr_reload_state_cache(ctx);
            ia64_tr_finish_faulting_slot();
        }
        ia64_tr_finish_predicate_guard(skip);
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
    ia64_tr_finish_predicate_guard(skip);
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
    ia64_tr_finish_predicate_guard(skip);
}

static void ia64_tr_packed_extract_lane(TCGv_i64 dest, TCGv_i64 source,
                                        unsigned bits, unsigned lane,
                                        bool sign_extend)
{
    tcg_gen_extract_i64(dest, source, lane * bits, bits);
    if (!sign_extend) {
        return;
    }
    switch (bits) {
    case 8:
        tcg_gen_ext8s_i64(dest, dest);
        break;
    case 16:
        tcg_gen_ext16s_i64(dest, dest);
        break;
    case 32:
        tcg_gen_ext32s_i64(dest, dest);
        break;
    default:
        g_assert_not_reached();
    }
}

static void ia64_tr_packed_insert_lane(TCGv_i64 result, TCGv_i64 lane,
                                       unsigned bits, unsigned index)
{
    tcg_gen_deposit_i64(result, result, lane, index * bits, bits);
}

static void ia64_tr_packed_saturate_signed(TCGv_i64 result,
                                           TCGv_i64 value, unsigned bits)
{
    int64_t minimum = -((int64_t)1 << (bits - 1));
    int64_t maximum = ((int64_t)1 << (bits - 1)) - 1;

    tcg_gen_smax_i64(result, value, tcg_constant_i64(minimum));
    tcg_gen_smin_i64(result, result, tcg_constant_i64(maximum));
}

static void ia64_tr_packed_saturate_unsigned(TCGv_i64 result,
                                             TCGv_i64 value, unsigned bits)
{
    uint64_t maximum = (UINT64_C(1) << bits) - 1;

    tcg_gen_smax_i64(result, value, tcg_constant_i64(0));
    tcg_gen_smin_i64(result, result, tcg_constant_i64(maximum));
}

static const uint8_t ia64_tr_packed_mux1_lane[16][8] = {
    [0x0] = { 0, 0, 0, 0, 0, 0, 0, 0 },
    [0x8] = { 0, 4, 2, 6, 1, 5, 3, 7 },
    [0x9] = { 0, 4, 1, 5, 2, 6, 3, 7 },
    [0xa] = { 0, 2, 4, 6, 1, 3, 5, 7 },
    [0xb] = { 7, 6, 5, 4, 3, 2, 1, 0 },
};

static void ia64_tr_emit_decoded_packed_compute(
    DisasContext *ctx, const IA64Instruction *insn,
    const IA64TrPackedDescriptor *descriptor, TCGv_i64 result,
    TCGv_i64 source[2])
{
    unsigned bits = descriptor->element_bits;
    unsigned lane_count = 64 / bits;
    TCGv_i64 lane_a = ia64_tr_scratch_i64(ctx);
    TCGv_i64 lane_b = ia64_tr_scratch_i64(ctx);
    TCGv_i64 lane = ia64_tr_scratch_i64(ctx);
    TCGv_i64 temp = ia64_tr_scratch_i64(ctx);
    TCGv_i64 temp2 = ia64_tr_scratch_i64(ctx);
    TCGv_i64 temp3 = ia64_tr_scratch_i64(ctx);
    TCGv_i64 temp4 = ia64_tr_scratch_i64(ctx);
    TCGv_i64 temp5 = ia64_tr_scratch_i64(ctx);
    TCGv_i64 temp6 = ia64_tr_scratch_i64(ctx);
    TCGv_i64 count = ia64_tr_scratch_i64(ctx);

    switch (descriptor->form) {
    case IA64_TR_PACKED_ADD:
    case IA64_TR_PACKED_SUB:
    {
        bool left_signed = insn->imm == 1;
        bool right_signed = insn->imm == 1 || insn->imm == 3;

        tcg_gen_movi_i64(result, 0);
        for (unsigned i = 0; i < lane_count; i++) {
            ia64_tr_packed_extract_lane(lane_a, source[0], bits, i,
                                        left_signed);
            ia64_tr_packed_extract_lane(lane_b, source[1], bits, i,
                                        right_signed);
            if (descriptor->form == IA64_TR_PACKED_ADD) {
                tcg_gen_add_i64(temp, lane_a, lane_b);
            } else {
                tcg_gen_sub_i64(temp, lane_a, lane_b);
            }
            if (insn->imm == 0) {
                tcg_gen_mov_i64(lane, temp);
            } else if (insn->imm == 1) {
                ia64_tr_packed_saturate_signed(lane, temp, bits);
            } else {
                ia64_tr_packed_saturate_unsigned(lane, temp, bits);
            }
            ia64_tr_packed_insert_lane(result, lane, bits, i);
        }
        break;
    }
    case IA64_TR_PACKED_SHLADD:
        tcg_gen_movi_i64(result, 0);
        for (unsigned i = 0; i < lane_count; i++) {
            ia64_tr_packed_extract_lane(lane_a, source[0], 16, i, true);
            ia64_tr_packed_extract_lane(lane_b, source[1], 16, i, true);
            tcg_gen_shli_i64(temp, lane_a, insn->imm);
            ia64_tr_packed_saturate_signed(temp2, temp, 16);
            tcg_gen_add_i64(temp3, temp, lane_b);
            ia64_tr_packed_saturate_signed(temp4, temp3, 16);
            tcg_gen_setcondi_i64(TCG_COND_GT, temp5, temp, 0x7fff);
            tcg_gen_setcondi_i64(TCG_COND_LT, temp6, temp, -0x8000);
            tcg_gen_or_i64(temp5, temp5, temp6);
            /* A saturating shift does not subsequently add r3. */
            tcg_gen_movcond_i64(TCG_COND_NE, lane, temp5,
                                tcg_constant_i64(0), temp2, temp4);
            ia64_tr_packed_insert_lane(result, lane, 16, i);
        }
        break;
    case IA64_TR_PACKED_SHRADD:
        tcg_gen_movi_i64(result, 0);
        for (unsigned i = 0; i < lane_count; i++) {
            ia64_tr_packed_extract_lane(lane_a, source[0], 16, i, true);
            ia64_tr_packed_extract_lane(lane_b, source[1], 16, i, true);
            tcg_gen_sari_i64(temp, lane_a, insn->imm);
            tcg_gen_add_i64(temp, temp, lane_b);
            ia64_tr_packed_saturate_signed(lane, temp, 16);
            ia64_tr_packed_insert_lane(result, lane, 16, i);
        }
        break;
    case IA64_TR_PACKED_AVG:
        tcg_gen_movi_i64(result, 0);
        for (unsigned i = 0; i < lane_count; i++) {
            ia64_tr_packed_extract_lane(lane_a, source[0], bits, i, false);
            ia64_tr_packed_extract_lane(lane_b, source[1], bits, i, false);
            tcg_gen_add_i64(temp, lane_a, lane_b);
            if (insn->imm != 0) {
                tcg_gen_addi_i64(temp, temp, 1);
                tcg_gen_shri_i64(lane, temp, 1);
            } else {
                tcg_gen_shri_i64(lane, temp, 1);
                tcg_gen_andi_i64(temp2, temp, 1);
                tcg_gen_or_i64(lane, lane, temp2);
            }
            ia64_tr_packed_insert_lane(result, lane, bits, i);
        }
        break;
    case IA64_TR_PACKED_AVGSUB:
    {
        uint64_t extended_mask = (UINT64_C(1) << (bits + 1)) - 1;

        tcg_gen_movi_i64(result, 0);
        for (unsigned i = 0; i < lane_count; i++) {
            ia64_tr_packed_extract_lane(lane_a, source[0], bits, i, false);
            ia64_tr_packed_extract_lane(lane_b, source[1], bits, i, false);
            tcg_gen_sub_i64(temp, lane_a, lane_b);
            tcg_gen_andi_i64(temp, temp, extended_mask);
            tcg_gen_shri_i64(lane, temp, 1);
            tcg_gen_andi_i64(temp2, temp, 1);
            tcg_gen_or_i64(lane, lane, temp2);
            ia64_tr_packed_insert_lane(result, lane, bits, i);
        }
        break;
    }
    case IA64_TR_PACKED_CMP_EQ:
    case IA64_TR_PACKED_CMP_GT:
    {
        bool greater = descriptor->form == IA64_TR_PACKED_CMP_GT;

        tcg_gen_movi_i64(result, 0);
        for (unsigned i = 0; i < lane_count; i++) {
            ia64_tr_packed_extract_lane(lane_a, source[0], bits, i,
                                        greater);
            ia64_tr_packed_extract_lane(lane_b, source[1], bits, i,
                                        greater);
            tcg_gen_setcond_i64(greater ? TCG_COND_GT : TCG_COND_EQ,
                                lane, lane_a, lane_b);
            tcg_gen_neg_i64(lane, lane);
            ia64_tr_packed_insert_lane(result, lane, bits, i);
        }
        break;
    }
    case IA64_TR_PACKED_MAX_U:
    case IA64_TR_PACKED_MAX_S:
    case IA64_TR_PACKED_MIN_U:
    case IA64_TR_PACKED_MIN_S:
    {
        bool signed_values = descriptor->form == IA64_TR_PACKED_MAX_S ||
                             descriptor->form == IA64_TR_PACKED_MIN_S;
        bool maximum = descriptor->form == IA64_TR_PACKED_MAX_U ||
                       descriptor->form == IA64_TR_PACKED_MAX_S;
        TCGCond condition = maximum ?
            (signed_values ? TCG_COND_GT : TCG_COND_GTU) :
            (signed_values ? TCG_COND_LT : TCG_COND_LTU);

        tcg_gen_movi_i64(result, 0);
        for (unsigned i = 0; i < lane_count; i++) {
            ia64_tr_packed_extract_lane(lane_a, source[0], bits, i,
                                        signed_values);
            ia64_tr_packed_extract_lane(lane_b, source[1], bits, i,
                                        signed_values);
            tcg_gen_movcond_i64(condition, lane, lane_a, lane_b,
                                lane_a, lane_b);
            ia64_tr_packed_insert_lane(result, lane, bits, i);
        }
        break;
    }
    case IA64_TR_PACKED_MPY_L:
    case IA64_TR_PACKED_MPY_R:
    {
        unsigned first = descriptor->form == IA64_TR_PACKED_MPY_L ? 1 : 0;

        tcg_gen_movi_i64(result, 0);
        for (unsigned i = 0; i < 2; i++) {
            unsigned source_lane = first + i * 2;

            ia64_tr_packed_extract_lane(lane_a, source[0], 16,
                                        source_lane, true);
            ia64_tr_packed_extract_lane(lane_b, source[1], 16,
                                        source_lane, true);
            tcg_gen_mul_i64(lane, lane_a, lane_b);
            ia64_tr_packed_insert_lane(result, lane, 32, i);
        }
        break;
    }
    case IA64_TR_PACKED_MPYSH_S:
    case IA64_TR_PACKED_MPYSH_U:
    {
        bool signed_values = descriptor->form == IA64_TR_PACKED_MPYSH_S;

        tcg_gen_movi_i64(result, 0);
        for (unsigned i = 0; i < lane_count; i++) {
            ia64_tr_packed_extract_lane(lane_a, source[0], 16, i,
                                        signed_values);
            ia64_tr_packed_extract_lane(lane_b, source[1], 16, i,
                                        signed_values);
            tcg_gen_mul_i64(temp, lane_a, lane_b);
            if (signed_values) {
                tcg_gen_sari_i64(lane, temp, insn->imm);
            } else {
                tcg_gen_shri_i64(lane, temp, insn->imm);
            }
            ia64_tr_packed_insert_lane(result, lane, 16, i);
        }
        break;
    }
    case IA64_TR_PACKED_SHL:
        if (insn->imm < 0) {
            tcg_gen_mov_i64(count, source[1]);
        } else {
            tcg_gen_movi_i64(count, insn->imm);
        }
        tcg_gen_umin_i64(count, count, tcg_constant_i64(bits));
        tcg_gen_movi_i64(result, 0);
        for (unsigned i = 0; i < lane_count; i++) {
            ia64_tr_packed_extract_lane(lane_a, source[0], bits, i, false);
            tcg_gen_shl_i64(lane, lane_a, count);
            ia64_tr_packed_insert_lane(result, lane, bits, i);
        }
        break;
    case IA64_TR_PACKED_SHR_S:
    case IA64_TR_PACKED_SHR_U:
    {
        bool signed_values = descriptor->form == IA64_TR_PACKED_SHR_S;
        TCGv_i64 value = insn->imm < 0 ? source[1] : source[0];

        if (insn->imm < 0) {
            tcg_gen_mov_i64(count, source[0]);
        } else {
            tcg_gen_movi_i64(count, insn->imm);
        }
        tcg_gen_umin_i64(count, count, tcg_constant_i64(bits));
        tcg_gen_movi_i64(result, 0);
        for (unsigned i = 0; i < lane_count; i++) {
            ia64_tr_packed_extract_lane(lane_a, value, bits, i,
                                        signed_values);
            if (signed_values) {
                tcg_gen_sar_i64(lane, lane_a, count);
            } else {
                tcg_gen_shr_i64(lane, lane_a, count);
            }
            ia64_tr_packed_insert_lane(result, lane, bits, i);
        }
        break;
    }
    case IA64_TR_PACKED_SAD:
        tcg_gen_movi_i64(result, 0);
        for (unsigned i = 0; i < lane_count; i++) {
            ia64_tr_packed_extract_lane(lane_a, source[0], 8, i, false);
            ia64_tr_packed_extract_lane(lane_b, source[1], 8, i, false);
            tcg_gen_sub_i64(temp, lane_a, lane_b);
            tcg_gen_neg_i64(temp2, temp);
            tcg_gen_movcond_i64(TCG_COND_LT, lane, temp,
                                tcg_constant_i64(0), temp2, temp);
            tcg_gen_add_i64(result, result, lane);
        }
        break;
    case IA64_TR_PACKED_MUX1:
        tcg_gen_movi_i64(result, 0);
        for (unsigned i = 0; i < 8; i++) {
            unsigned source_lane =
                ia64_tr_packed_mux1_lane[insn->imm][i];

            ia64_tr_packed_extract_lane(lane, source[0], 8,
                                        source_lane, false);
            ia64_tr_packed_insert_lane(result, lane, 8, i);
        }
        break;
    case IA64_TR_PACKED_MUX2:
        tcg_gen_movi_i64(result, 0);
        for (unsigned i = 0; i < 4; i++) {
            unsigned source_lane = ((uint64_t)insn->imm >> (i * 2)) & 3;

            ia64_tr_packed_extract_lane(lane, source[0], 16,
                                        source_lane, false);
            ia64_tr_packed_insert_lane(result, lane, 16, i);
        }
        break;
    case IA64_TR_PACKED_MIX_L:
    case IA64_TR_PACKED_MIX_R:
    {
        unsigned first = descriptor->form == IA64_TR_PACKED_MIX_L ? 1 : 0;

        tcg_gen_movi_i64(result, 0);
        for (unsigned i = 0; i < lane_count / 2; i++) {
            unsigned source_lane = first + i * 2;

            ia64_tr_packed_extract_lane(lane_a, source[1], bits,
                                        source_lane, false);
            ia64_tr_packed_extract_lane(lane_b, source[0], bits,
                                        source_lane, false);
            ia64_tr_packed_insert_lane(result, lane_a, bits, i * 2);
            ia64_tr_packed_insert_lane(result, lane_b, bits, i * 2 + 1);
        }
        break;
    }
    case IA64_TR_PACKED_PACK_S:
    case IA64_TR_PACKED_PACK_U:
    {
        unsigned output_bits = bits / 2;
        unsigned input_lanes = 64 / bits;
        bool unsigned_result = descriptor->form == IA64_TR_PACKED_PACK_U;

        tcg_gen_movi_i64(result, 0);
        for (unsigned source_index = 0; source_index < 2; source_index++) {
            for (unsigned i = 0; i < input_lanes; i++) {
                unsigned output_lane = source_index * input_lanes + i;

                ia64_tr_packed_extract_lane(lane_a, source[source_index],
                                            bits, i, true);
                if (unsigned_result) {
                    ia64_tr_packed_saturate_unsigned(lane, lane_a,
                                                     output_bits);
                } else {
                    ia64_tr_packed_saturate_signed(lane, lane_a,
                                                   output_bits);
                }
                ia64_tr_packed_insert_lane(result, lane, output_bits,
                                           output_lane);
            }
        }
        break;
    }
    case IA64_TR_PACKED_UNPACK_H:
    case IA64_TR_PACKED_UNPACK_L:
    {
        unsigned half = lane_count / 2;
        unsigned base = descriptor->form == IA64_TR_PACKED_UNPACK_H ?
                        half : 0;

        tcg_gen_movi_i64(result, 0);
        for (unsigned i = 0; i < half; i++) {
            ia64_tr_packed_extract_lane(lane_a, source[1], bits,
                                        base + i, false);
            ia64_tr_packed_extract_lane(lane_b, source[0], bits,
                                        base + i, false);
            ia64_tr_packed_insert_lane(result, lane_a, bits, i * 2);
            ia64_tr_packed_insert_lane(result, lane_b, bits, i * 2 + 1);
        }
        break;
    }
    case IA64_TR_PACKED_CZX_L:
    case IA64_TR_PACKED_CZX_R:
        tcg_gen_movi_i64(result, lane_count);
        for (unsigned scan = 0; scan < lane_count; scan++) {
            unsigned source_lane =
                descriptor->form == IA64_TR_PACKED_CZX_L ?
                scan : lane_count - 1 - scan;
            unsigned zero_index = lane_count - 1 - scan;

            ia64_tr_packed_extract_lane(lane, source[0], bits,
                                        source_lane, false);
            tcg_gen_movcond_i64(TCG_COND_EQ, result, lane,
                                tcg_constant_i64(0),
                                tcg_constant_i64(zero_index), result);
        }
        break;
    case IA64_TR_PACKED_INVALID:
    default:
        g_assert_not_reached();
    }
}

static void ia64_tr_emit_decoded_packed(
    DisasContext *ctx, const IA64Instruction *insn)
{
    const IA64TrPackedDescriptor *descriptor =
        ia64_tr_decoded_packed(insn->opcode);
    uint8_t source_regs[3];
    TCGv_i64 source[2] = { NULL, NULL };
    TCGv_i64 source_nat[2] = { NULL, NULL };
    TCGv_i64 result;
    TCGv_i64 result_nat;
    IA64TrGrWrite *write;
    TCGLabel *skip;
    unsigned source_count;

    g_assert(descriptor != NULL &&
             ia64_tr_decoded_is_supported_packed(insn));
    ia64_tr_prime_decoded_instruction_state(ctx, insn);
    write = ia64_tr_group_prepare_gr(ctx, insn->r1);
    skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
    if (insn->r1 != 0) {
        ia64_tr_emit_decoded_memory_target_check(ctx, insn, insn->r1);
    }

    result = ia64_tr_scratch_i64(ctx);
    result_nat = ia64_tr_scratch_i64(ctx);
    tcg_gen_movi_i64(result_nat, 0);
    source_count = ia64_tr_decoded_sources(insn, source_regs);
    g_assert(source_count >= 1 && source_count <= descriptor->source_count &&
             source_count <= ARRAY_SIZE(source));
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
        source[i] = ia64_tr_scratch_i64(ctx);
        source_nat[i] = ia64_tr_scratch_i64(ctx);
        ia64_tr_group_load_ordinary_gr_pair(
            ctx, source[i], source_nat[i], source_regs[i]);
        tcg_gen_or_i64(result_nat, result_nat, source_nat[i]);
    }
    ia64_tr_emit_decoded_packed_compute(
        ctx, insn, descriptor, result, source);
    ia64_tr_group_stage_gr(write, result, result_nat);
    ia64_tr_finish_predicate_guard(skip);
}

static void ia64_tr_system_validate(DisasContext *ctx,
                                    const IA64Instruction *insn)
{
    if (insn->status == IA64_DECODE_OK) {
        return;
    }

    if (insn->status == IA64_DECODE_RESERVED_FIELD) {
        ia64_tr_group_publish_prefix_for_noreturn_fault(ctx);
        tcg_gen_movi_i64(cpu_ip, insn->address);
        ia64_tr_publish_fault_state(insn->address, insn->slot,
                                    ia64_tr_decoded_slot_type(insn->unit),
                                    insn->raw, insn->starts_group);
        gen_helper_raise_reserved_register_field(tcg_env);
        return;
    }
    ia64_tr_emit_decoded_illegal_operation(ctx, insn);
}

static void ia64_tr_system_load_gr(DisasContext *ctx, uint8_t reg,
                                   TCGv_i64 value, TCGv_i64 nat)
{
    ia64_tr_group_load_ordinary_gr_pair(ctx, value, nat, reg);
}

static uint64_t ia64_tr_system_nat_isr_extra(
    const IA64TrSystemDescriptor *descriptor,
    const IA64Instruction *insn)
{
    uint64_t non_access = UINT64_C(1) << IA64_ISR_NA_BIT;

    switch (descriptor->kind) {
    case IA64_TR_SYSTEM_TPA:
        return non_access;
    case IA64_TR_SYSTEM_TAK:
        return non_access | UINT64_C(3);
    case IA64_TR_SYSTEM_PROBE_R:
        return non_access | (UINT64_C(1) << IA64_ISR_R_BIT) |
               (insn->probe_fault ? UINT64_C(5) : UINT64_C(2));
    case IA64_TR_SYSTEM_PROBE_W:
        return non_access | (UINT64_C(1) << IA64_ISR_W_BIT) |
               (insn->probe_fault ? UINT64_C(5) : UINT64_C(2));
    case IA64_TR_SYSTEM_PROBE_RW:
        return non_access | (UINT64_C(1) << IA64_ISR_R_BIT) |
               (UINT64_C(1) << IA64_ISR_W_BIT) | UINT64_C(5);
    default:
        return 0;
    }
}

static void ia64_tr_emit_decoded_system(
    DisasContext *ctx, const IA64Instruction *insn)
{
    const IA64TrSystemDescriptor *descriptor =
        ia64_tr_decoded_system(insn->opcode);
    const IA64OpcodeTraits *traits =
        ia64_opcode_traits_for(insn->opcode);
    IA64TrGrWrite *write = NULL;
    TCGLabel *skip;
    TCGLabel *nat_clear;
    TCGv_i64 arg0 = ia64_tr_scratch_i64(ctx);
    TCGv_i64 arg1 = ia64_tr_scratch_i64(ctx);
    TCGv_i64 nat0 = ia64_tr_scratch_i64(ctx);
    TCGv_i64 nat1 = ia64_tr_scratch_i64(ctx);
    TCGv_i64 any_nat = ia64_tr_scratch_i64(ctx);
    TCGv_i64 result = ia64_tr_scratch_i64(ctx);
    TCGv_i64 result_nat = ia64_tr_scratch_i64(ctx);
    TCGv_i32 selector = tcg_constant_i32(0);
    TCGv_i32 preflight_selector =
        tcg_constant_i32(
            descriptor->kind == IA64_TR_SYSTEM_MOV_IMMAR ||
            descriptor->kind == IA64_TR_SYSTEM_MOV_CRGR ||
            descriptor->kind == IA64_TR_SYSTEM_MOV_GRCR ? insn->r2 : 0);
    uint32_t flags = 0;

    g_assert(descriptor != NULL &&
             ia64_tr_decoded_is_supported_system(insn));
    g_assert(traits != NULL);
    if (traits->lowering_owner == IA64_OPCODE_OWNER_FOCUSED_HELPER) {
        ia64_tr_require_helper(insn->opcode,
                               IA64_OPCODE_HELPER_SYSTEM_PLANE);
    }
    ia64_tr_prime_decoded_instruction_state(ctx, insn);
    if (insn->status == IA64_DECODE_OK &&
        descriptor->dst_gr_field == IA64_TR_SYSTEM_GR_R1 &&
        !(descriptor->shape == IA64_TR_SYSTEM_SHAPE_PROBE &&
          insn->probe_fault)) {
        write = ia64_tr_group_prepare_gr(ctx, insn->r1);
    }

    /* Qualifying predication precedes every legality, privilege and NaT path. */
    skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
    ia64_tr_system_validate(ctx, insn);

    if ((tb_cflags(ctx->base.tb) & CF_USE_ICOUNT) != 0 &&
        ((descriptor->kind == IA64_TR_SYSTEM_MOV_IMMAR &&
          insn->r2 == IA64_AR_ITC) ||
         (descriptor->kind == IA64_TR_SYSTEM_MOV_GRCR &&
          (insn->r2 == IA64_CR_ITM || insn->r2 == IA64_CR_ITV)))) {
        translator_io_start(&ctx->base);
    }

    /*
     * Always-privileged operation checks precede every operand NaT check.
     * MOV to a kernel AR is the one selector-dependent check; its selector is
     * a normalized immediate and is therefore available before GR sources.
     */
    ia64_tr_group_publish_state_for_returning_helper(ctx);
    tcg_gen_movi_i64(cpu_ip, insn->address);
    ia64_tr_publish_fault_state(insn->address, insn->slot,
                                ia64_tr_decoded_slot_type(insn->unit),
                                insn->raw, insn->starts_group);
    gen_helper_system_preflight(tcg_env,
                                tcg_constant_i32(insn->opcode),
                                preflight_selector);
    ia64_tr_reload_state_cache(ctx);

    tcg_gen_movi_i64(arg0, 0);
    tcg_gen_movi_i64(arg1, 0);
    tcg_gen_movi_i64(nat0, 0);
    tcg_gen_movi_i64(nat1, 0);
    tcg_gen_movi_i64(result_nat, 0);

    switch (descriptor->kind) {
    case IA64_TR_SYSTEM_BREAK:
        tcg_gen_movi_i64(arg0, insn->imm);
        break;
    case IA64_TR_SYSTEM_BR_IA:
        ia64_tr_group_load_ordinary_br(ctx, arg0, insn->b2);
        break;
    case IA64_TR_SYSTEM_MOV_IMMAR:
        tcg_gen_movi_i64(arg0, insn->imm);
        selector = tcg_constant_i32(insn->r2);
        break;
    case IA64_TR_SYSTEM_MOV_CRGR:
        selector = tcg_constant_i32(insn->r2);
        break;
    case IA64_TR_SYSTEM_MOV_GRCR:
        selector = tcg_constant_i32(insn->r2);
        ia64_tr_system_load_gr(ctx, insn->r1, arg0, nat0);
        break;
    case IA64_TR_SYSTEM_SSM:
    case IA64_TR_SYSTEM_RSM:
    case IA64_TR_SYSTEM_RUM:
    case IA64_TR_SYSTEM_SUM_UM:
        tcg_gen_movi_i64(arg0, insn->imm);
        break;
    case IA64_TR_SYSTEM_ITR_D:
    case IA64_TR_SYSTEM_ITR_I:
        ia64_tr_system_load_gr(ctx, insn->r2, arg0, nat0);
        ia64_tr_system_load_gr(ctx, insn->r3, arg1, nat1);
        break;
    case IA64_TR_SYSTEM_PTR_D:
    case IA64_TR_SYSTEM_PTR_I:
    case IA64_TR_SYSTEM_PTC_L:
    case IA64_TR_SYSTEM_PTC_G:
    case IA64_TR_SYSTEM_PTC_GA:
        ia64_tr_system_load_gr(ctx, insn->r3, arg0, nat0);
        ia64_tr_system_load_gr(ctx, insn->r2, arg1, nat1);
        break;
    case IA64_TR_SYSTEM_TPA:
    case IA64_TR_SYSTEM_TAK:
    case IA64_TR_SYSTEM_THASH:
    case IA64_TR_SYSTEM_TTAG:
    case IA64_TR_SYSTEM_PTC_E:
        ia64_tr_system_load_gr(ctx, insn->r3, arg0, nat0);
        break;
    case IA64_TR_SYSTEM_PROBE_R:
    case IA64_TR_SYSTEM_PROBE_W:
    case IA64_TR_SYSTEM_PROBE_RW:
        ia64_tr_system_load_gr(ctx, insn->r3, arg0, nat0);
        if (insn->probe_imm) {
            tcg_gen_movi_i64(arg1, insn->imm);
            flags |= IA64_SYSTEM_PLANE_PROBE_IMMEDIATE;
        } else {
            ia64_tr_system_load_gr(ctx, insn->r2, arg1, nat1);
        }
        if (insn->probe_fault) {
            flags |= IA64_SYSTEM_PLANE_PROBE_FAULT;
        }
        break;
    case IA64_TR_SYSTEM_ITC_D:
    case IA64_TR_SYSTEM_ITC_I:
        ia64_tr_system_load_gr(ctx, insn->r2, arg0, nat0);
        break;
    case IA64_TR_SYSTEM_MOV_GRPSR:
    case IA64_TR_SYSTEM_MOV_GRUM:
        ia64_tr_system_load_gr(ctx, insn->r1, arg0, nat0);
        break;
    case IA64_TR_SYSTEM_MOV_RRGR:
        ia64_tr_system_load_gr(ctx, insn->r2, arg0, nat0);
        break;
    case IA64_TR_SYSTEM_MOV_GRRR:
        ia64_tr_system_load_gr(ctx, insn->r2, arg0, nat0);
        ia64_tr_system_load_gr(ctx, insn->r3, arg1, nat1);
        break;
    case IA64_TR_SYSTEM_MOV_PKRGR_INDEXED:
    case IA64_TR_SYSTEM_MOV_IBRGR_INDEXED:
    case IA64_TR_SYSTEM_MOV_DBRGR_INDEXED:
    case IA64_TR_SYSTEM_MOV_PMCGR_INDEXED:
    case IA64_TR_SYSTEM_MOV_PMDGR_INDEXED:
    case IA64_TR_SYSTEM_MOV_CPUID_INDEXED:
    case IA64_TR_SYSTEM_MOV_DAHRGR_INDEXED:
    case IA64_TR_SYSTEM_MOV_MSRGR:
    {
        TCGv_i32 runtime_selector = ia64_tr_scratch_i32(ctx);

        ia64_tr_system_load_gr(ctx, insn->r3, arg0, nat0);
        tcg_gen_extrl_i64_i32(runtime_selector, arg0);
        selector = runtime_selector;
        break;
    }
    case IA64_TR_SYSTEM_MOV_GRPKR_INDEXED:
    case IA64_TR_SYSTEM_MOV_GRIBR_INDEXED:
    case IA64_TR_SYSTEM_MOV_GRDBR_INDEXED:
    case IA64_TR_SYSTEM_MOV_GRPMC_INDEXED:
    case IA64_TR_SYSTEM_MOV_GRPMD_INDEXED:
    case IA64_TR_SYSTEM_MOV_GRMSR:
    {
        TCGv_i32 runtime_selector = ia64_tr_scratch_i32(ctx);

        ia64_tr_system_load_gr(ctx, insn->r2, arg0, nat0);
        ia64_tr_system_load_gr(ctx, insn->r3, arg1, nat1);
        tcg_gen_extrl_i64_i32(runtime_selector, arg1);
        selector = runtime_selector;
        break;
    }
    case IA64_TR_SYSTEM_MOV_CURRENT_IP:
        tcg_gen_movi_i64(arg0, insn->address);
        break;
    case IA64_TR_SYSTEM_EPC:
        ia64_tr_group_load_branch_pfs(ctx, arg0);
        break;
    case IA64_TR_SYSTEM_SYNC_I:
    case IA64_TR_SYSTEM_SRLZ:
    case IA64_TR_SYSTEM_SRLZ_D:
    case IA64_TR_SYSTEM_MF:
    case IA64_TR_SYSTEM_MF_A:
    case IA64_TR_SYSTEM_MOV_PSRGR:
    case IA64_TR_SYSTEM_BSW0:
    case IA64_TR_SYSTEM_BSW1:
    case IA64_TR_SYSTEM_MOV_UMGR:
    case IA64_TR_SYSTEM_VMSW:
    case IA64_TR_SYSTEM_BRP:
        break;
    case IA64_TR_SYSTEM_INVALID:
    default:
        g_assert_not_reached();
    }

    if (descriptor->nat_policy != IA64_TR_SYSTEM_NAT_NONE &&
        descriptor->nat_policy != IA64_TR_SYSTEM_NAT_PROPAGATE_ADDRESS) {
        nat_clear = gen_new_label();
        tcg_gen_or_i64(any_nat, nat0, nat1);
        tcg_gen_brcondi_i64(TCG_COND_EQ, any_nat, 0, nat_clear);
        ia64_tr_emit_decoded_register_nat_consumption_isr(
            ctx, insn, ia64_tr_system_nat_isr_extra(descriptor, insn));
        gen_set_label(nat_clear);
    }

    if (descriptor->kind == IA64_TR_SYSTEM_MOV_IMMAR &&
        insn->r2 == IA64_AR_PFS) {
        ia64_tr_emit_application_write_value_check(
            ctx, insn, insn->r2, arg0);
        ia64_tr_group_write_pfs(ctx, arg0, insn->qp == 0);
        ia64_tr_finish_faulting_slot();
        ia64_tr_finish_predicate_guard(skip);
        return;
    }

    if (descriptor->kind == IA64_TR_SYSTEM_MF ||
        descriptor->kind == IA64_TR_SYSTEM_MF_A) {
        tcg_gen_mb(TCG_MO_ALL | TCG_BAR_SC);
    }

    switch (descriptor->kind) {
    case IA64_TR_SYSTEM_SYNC_I:
    case IA64_TR_SYSTEM_MF:
    case IA64_TR_SYSTEM_MF_A:
    case IA64_TR_SYSTEM_BRP:
        ia64_tr_finish_faulting_slot();
        ia64_tr_group_stage_gr(write, result, result_nat);
        ia64_tr_finish_predicate_guard(skip);
        return;
    case IA64_TR_SYSTEM_SRLZ:
    case IA64_TR_SYSTEM_SRLZ_D:
        tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                        offsetof(CPUIA64State, psr_ic_inflight));
        ia64_tr_finish_faulting_slot();
        ia64_tr_group_stage_gr(write, result, result_nat);
        ia64_tr_finish_predicate_guard(skip);
        return;
    case IA64_TR_SYSTEM_MOV_CURRENT_IP:
        tcg_gen_movi_i64(result, insn->address);
        ia64_tr_finish_faulting_slot();
        ia64_tr_group_stage_gr(write, result, result_nat);
        ia64_tr_finish_predicate_guard(skip);
        return;
    case IA64_TR_SYSTEM_MOV_PSRGR:
        tcg_gen_ld_i64(result, tcg_env, offsetof(CPUIA64State, psr));
        /* Firmware observes the PSR state, not the current bundle slot. */
        tcg_gen_andi_i64(result, result, ~IA64_PSR_RI_MASK);
        ia64_tr_finish_faulting_slot();
        ia64_tr_group_stage_gr(write, result, result_nat);
        ia64_tr_finish_predicate_guard(skip);
        return;
    case IA64_TR_SYSTEM_MOV_UMGR:
        tcg_gen_ld_i64(result, tcg_env, offsetof(CPUIA64State, psr));
        tcg_gen_andi_i64(result, result, IA64_PSR_UM_MASK);
        ia64_tr_finish_faulting_slot();
        ia64_tr_group_stage_gr(write, result, result_nat);
        ia64_tr_finish_predicate_guard(skip);
        return;
    default:
        break;
    }

    /*
     * The helper may fault or return.  Publish the exact restart slot and
     * cached prefix without clearing the group-entry source overlay.
     */
    ia64_tr_group_publish_state_for_returning_helper(ctx);
    tcg_gen_movi_i64(cpu_ip, insn->address);
    ia64_tr_publish_fault_state(insn->address, insn->slot,
                                ia64_tr_decoded_slot_type(insn->unit),
                                insn->raw, insn->starts_group);
    gen_helper_system_plane(result, tcg_env,
                            tcg_constant_i32(insn->opcode), selector,
                            tcg_constant_i32(flags), arg0, arg1);
    ia64_tr_reload_state_cache(ctx);
    ia64_tr_finish_faulting_slot();

    if (descriptor->nat_policy ==
        IA64_TR_SYSTEM_NAT_PROPAGATE_ADDRESS) {
        tcg_gen_mov_i64(result_nat, nat0);
    }
    ia64_tr_group_stage_gr(write, result, result_nat);
    if (descriptor->tb_end == IA64_TR_SYSTEM_TB_NEXT_SLOT) {
        /* The bundle driver turns this marker into an exact RI continuation. */
    }
    ia64_tr_finish_predicate_guard(skip);
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

    if (ia64_tr_decoded_system(insn->opcode) != NULL) {
        ia64_tr_emit_decoded_system(ctx, insn);
        return;
    }

    if (ia64_tr_decoded_is_ordinary_integer_memory(insn->opcode)) {
        ia64_tr_emit_decoded_ordinary_integer_memory(ctx, insn);
        return;
    }

    {
        const IA64TrDataPlaneDescriptor *descriptor =
            ia64_tr_decoded_data_plane(insn->opcode);

        if (descriptor != NULL) {
            switch (descriptor->kind) {
        case IA64_TR_DATA_PLANE_INTEGER_LOAD:
            ia64_tr_emit_decoded_data_plane_integer_load(
                ctx, insn, descriptor);
            return;
        case IA64_TR_DATA_PLANE_INTEGER_SPILL:
            ia64_tr_emit_decoded_data_plane_integer_spill(
                ctx, insn, descriptor);
            return;
        case IA64_TR_DATA_PLANE_XCHG:
        case IA64_TR_DATA_PLANE_CMPXCHG:
        case IA64_TR_DATA_PLANE_FETCHADD:
            ia64_tr_emit_decoded_data_plane_atomic(ctx, insn, descriptor);
            return;
        case IA64_TR_DATA_PLANE_WIDE_LOAD:
        case IA64_TR_DATA_PLANE_WIDE_STORE:
            ia64_tr_emit_decoded_data_plane_wide(ctx, insn, descriptor);
            return;
        case IA64_TR_DATA_PLANE_CMP8XCHG16:
            ia64_tr_emit_decoded_data_plane_cmp8xchg16(
                ctx, insn, descriptor);
            return;
        case IA64_TR_DATA_PLANE_FP_LOAD:
        case IA64_TR_DATA_PLANE_FP_LOAD_PAIR:
            ia64_tr_emit_decoded_data_plane_fp_load(
                ctx, insn, descriptor);
            return;
        case IA64_TR_DATA_PLANE_FP_STORE:
            ia64_tr_emit_decoded_data_plane_fp_store(
                ctx, insn, descriptor);
            return;
        case IA64_TR_DATA_PLANE_FWB:
        case IA64_TR_DATA_PLANE_FC:
        case IA64_TR_DATA_PLANE_INVALA:
        case IA64_TR_DATA_PLANE_INVALAT:
            ia64_tr_emit_decoded_data_plane_cache_control(
                ctx, insn, descriptor);
            return;
        case IA64_TR_DATA_PLANE_LFETCH:
            ia64_tr_emit_decoded_data_plane_lfetch(
                ctx, insn, descriptor);
            return;
        default:
            break;
            }
        }
    }

    {
        const IA64TrFpDescriptor *fp =
            ia64_tr_decoded_fp_compute(insn->opcode);

        if (fp != NULL) {
            if (fp->owner == IA64_TR_FP_FOCUSED) {
                ia64_tr_emit_decoded_fp_focused(ctx, insn);
            } else {
                ia64_tr_emit_decoded_fp_compute(ctx, insn);
            }
            return;
        }
    }

    if (insn->reserved_memory_width ||
        (insn->opcode == IA64_OP_ILLEGAL &&
         insn->status == IA64_DECODE_RESERVED_ENCODING)) {
        ia64_tr_prime_decoded_instruction_state(ctx, insn);
        skip = ia64_tr_emit_decoded_predicate_guard(ctx, insn);
        ia64_tr_emit_decoded_illegal_operation(ctx, insn);
        ia64_tr_finish_predicate_guard(skip);
        return;
    }

    if (ia64_tr_decoded_packed(insn->opcode) != NULL) {
        ia64_tr_emit_decoded_packed(ctx, insn);
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
        ia64_tr_emit_decoded_application_move(ctx, insn);
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
    ia64_tr_finish_predicate_guard(skip);
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

static uint64_t ia64_tr_ar_resource_bit(uint8_t reg)
{
    return UINT64_C(1) << (reg & 63);
}

static void ia64_tr_assert_rse_spine_resources(
    const IA64TrInstructionTransaction *instruction,
    const IA64Instruction *insn)
{
    uint64_t bsp = ia64_tr_ar_resource_bit(IA64_AR_BSP);
    uint64_t bspstore = ia64_tr_ar_resource_bit(IA64_AR_BSPSTORE);
    uint64_t rnat = ia64_tr_ar_resource_bit(IA64_AR_RNAT);
    uint64_t rsc = ia64_tr_ar_resource_bit(IA64_AR_RSC);
    uint64_t pfs = ia64_tr_ar_resource_bit(IA64_AR_PFS);
    uint64_t gr = ia64_tr_nonzero_register_bit(insn->r1);

    g_assert(instruction != NULL &&
             ia64_tr_decoded_is_rse_spine(insn->opcode));
    g_assert(instruction->dest_pr == 0 &&
             instruction->must_pr == 0 &&
             instruction->forward_pr == 0 &&
             instruction->branch_source_pr == 0 &&
             instruction->source_br == 0 &&
             instruction->dest_br == 0 &&
             instruction->must_br == 0 &&
             instruction->forward_br == 0 &&
             instruction->branch_source_br == 0 &&
             !instruction->forward_pfs &&
             !instruction->branch_source_pfs &&
             !instruction->must_pfs);

    switch (insn->opcode) {
    case IA64_OP_ALLOC:
        g_assert(instruction->dest_gr[insn->r1 >= 64] == gr &&
                 instruction->must_gr[insn->r1 >= 64] == gr &&
                 instruction->source_ar[0] == (bsp | bspstore | rnat) &&
                 instruction->source_ar[1] == pfs &&
                 instruction->dest_ar[0] == (bspstore | rnat) &&
                 instruction->dest_ar[1] == 0 &&
                 instruction->source_cfm && instruction->dest_cfm);
        break;
    case IA64_OP_COVER:
        g_assert(instruction->dest_gr[0] == 0 &&
                 instruction->dest_gr[1] == 0 &&
                 instruction->source_ar[0] == (bsp | bspstore | rnat) &&
                 instruction->source_ar[1] == 0 &&
                 instruction->dest_ar[0] == (bsp | rnat) &&
                 instruction->dest_ar[1] == 0 &&
                 instruction->source_cfm && instruction->dest_cfm);
        break;
    case IA64_OP_FLUSHRS:
        g_assert(instruction->dest_gr[0] == 0 &&
                 instruction->dest_gr[1] == 0 &&
                 instruction->source_ar[0] == (bsp | bspstore | rnat) &&
                 instruction->source_ar[1] == 0 &&
                 instruction->dest_ar[0] == (bspstore | rnat) &&
                 instruction->dest_ar[1] == 0 &&
                 instruction->source_cfm && !instruction->dest_cfm);
        break;
    case IA64_OP_LOADRS:
        g_assert(instruction->dest_gr[0] == 0 &&
                 instruction->dest_gr[1] == 0 &&
                 instruction->source_ar[0] ==
                     (rsc | bsp | bspstore | rnat) &&
                 instruction->source_ar[1] == 0 &&
                 instruction->dest_ar[0] == (bspstore | rnat) &&
                 instruction->dest_ar[1] == 0 &&
                 instruction->source_cfm && !instruction->dest_cfm);
        break;
    case IA64_OP_CLRRRB:
    case IA64_OP_CLRRRB_PR:
        g_assert(instruction->dest_gr[0] == 0 &&
                 instruction->dest_gr[1] == 0 &&
                 instruction->source_ar[0] == 0 &&
                 instruction->source_ar[1] == 0 &&
                 instruction->dest_ar[0] == 0 &&
                 instruction->dest_ar[1] == 0 &&
                 instruction->source_cfm && instruction->dest_cfm);
        break;
    default:
        g_assert_not_reached();
    }
}

/*
 * These instructions own frame/backing-store state sequentially even inside
 * the typed issue-group transaction.  The helper is deliberately narrow: it
 * receives decoded fields, publishes each completed RSE word itself, and
 * returns alloc's old PFS for ordinary transactional GR retirement.
 */
static bool ia64_tr_emit_decoded_rse_spine(
    DisasContext *ctx, const IA64Instruction *insn)
{
    IA64TrInstructionTransaction *instruction =
        ctx->rewrite_group.current;
    uint32_t packed = (uint32_t)insn->imm;

    g_assert(ia64_tr_decoded_is_rse_spine(insn->opcode));
    ia64_tr_require_helper(insn->opcode,
                           IA64_OPCODE_HELPER_RSE_SPINE);
    ia64_tr_assert_rse_spine_resources(instruction, insn);

    if (ia64_tr_rse_spine_is_static_noreturn(insn)) {
        ia64_tr_emit_decoded_illegal_operation(ctx, insn);
        return true;
    }

    tcg_gen_movi_i64(cpu_ip, insn->address);
    ia64_tr_publish_fault_state(insn->address, insn->slot,
                                ia64_tr_decoded_slot_type(insn->unit),
                                insn->raw, insn->starts_group);
    switch (insn->opcode) {
    case IA64_OP_ALLOC:
    {
        IA64TrGrWrite *write = ia64_tr_group_prepare_gr(ctx, insn->r1);
        TCGv_i64 old_pfs = ia64_tr_scratch_i64(ctx);

        packed |= (uint32_t)insn->r1 << 18;
        gen_helper_rse_alloc(old_pfs, tcg_env, tcg_constant_i32(packed));
        ia64_tr_finish_faulting_slot();
        ia64_tr_group_stage_gr(write, old_pfs, tcg_constant_i64(0));
        break;
    }
    case IA64_OP_COVER:
        gen_helper_rse_cover(tcg_env);
        ia64_tr_finish_faulting_slot();
        break;
    case IA64_OP_FLUSHRS:
        gen_helper_rse_flushrs(tcg_env);
        ia64_tr_finish_faulting_slot();
        break;
    case IA64_OP_LOADRS:
        gen_helper_rse_loadrs(tcg_env);
        ia64_tr_finish_faulting_slot();
        break;
    case IA64_OP_CLRRRB:
    case IA64_OP_CLRRRB_PR:
        gen_helper_rse_clrrrb(
            tcg_env,
            tcg_constant_i32(insn->opcode == IA64_OP_CLRRRB_PR));
        ia64_tr_finish_faulting_slot();
        break;
    default:
        g_assert_not_reached();
    }
    return false;
}

/*
 * A system instruction may require a fresh TB while the architectural issue
 * group remains open.  In particular, the instruction-side translation and
 * serialization rows resume at the next physical slot, not at the next
 * bundle.  Publish the typed source overlay before leaving so the suffix TB
 * observes the same group-entry image as the prefix.
 */
static void ia64_tr_emit_system_main_loop_exit(DisasContext *ctx,
                                               uint64_t bundle_pc,
                                               uint8_t next_slot)
{
    g_assert(next_slot <= IA64_SLOT_COUNT);
    g_assert(ia64_tr_group_is_empty(ctx));
    g_assert(!ctx->instruction_group_start || !ctx->typed_group_active);

    ia64_tr_sync_state_cache(ctx);
    ia64_tr_store_source_visibility_state(
        ctx, ctx->instruction_group_start, ctx->typed_group_active);
    /* A PSR-writing helper may have materialized the transient fault RI. */
    ia64_tr_clear_restart_ri();
    if (next_slot < IA64_SLOT_COUNT) {
        ia64_tr_commit_ip(bundle_pc);
        ia64_tr_publish_restart_ri(next_slot);
    } else {
        ia64_tr_commit_ip(bundle_pc + IA64_BUNDLE_SIZE);
    }
    ia64_tr_flush_retired_bundles(ctx);
    ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_MAIN);
    tcg_gen_exit_tb(NULL, 0);
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
    bool system_bundle_exit = false;

    if (last_slot >= IA64_SLOT_COUNT || last_slot < start_slot ||
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
        if (ia64_tr_decoded_is_rse_spine(insn->opcode)) {
            /* A returning RSE helper may rewrite every frame mirror. */
            ia64_tr_split_state_cache_at_typed_branch(ctx);
        }
        ia64_tr_group_begin_instruction(ctx, insn);
        if (ia64_tr_decoded_is_rse_spine(insn->opcode)) {
            bool terminal = ia64_tr_emit_decoded_rse_spine(ctx, insn);

            ia64_tr_group_finish_instruction_success(ctx, insn);
            if (insn->stop_after || terminal) {
                ia64_tr_group_close(ctx);
            }
            if (terminal) {
                ctx->instruction_group_start = true;
                ctx->rewrite_control_flow_exit = true;
                ctx->base.is_jmp = DISAS_NORETURN;
                return true;
            }
            continue;
        }
        if (ia64_tr_decoded_is_rfi(insn->opcode)) {
            ia64_tr_emit_decoded_rfi(ctx, insn);
            ctx->instruction_group_start = true;
            ctx->rewrite_control_flow_exit = true;
            ctx->base.is_jmp = DISAS_NORETURN;
            return true;
        }
        if (ia64_tr_decoded_is_conditional_branch(insn->opcode)) {
            g_assert(branch_count < ARRAY_SIZE(branch_arm));
            if (ia64_tr_decoded_is_fp_status_branch(insn->opcode)) {
                ia64_tr_emit_decoded_fchkf_split(
                    ctx, insn, &branch_arm[branch_count++]);
                unconditional_branch = false;
            } else if (ia64_tr_decoded_is_data_plane_branch(insn->opcode)) {
                ia64_tr_emit_decoded_checked_branch_split(
                    ctx, insn, &branch_arm[branch_count++]);
                unconditional_branch = false;
            } else if (ia64_tr_decoded_is_loop_branch(insn->opcode)) {
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
        {
            const IA64TrSystemDescriptor *system =
                ia64_tr_decoded_system(insn->opcode);

            if (system == NULL && insn->opcode == IA64_OP_MOV_GRAR &&
                insn->status == IA64_DECODE_OK &&
                insn->r2 == IA64_AR_ITC) {
                system_bundle_exit = true;
                continue;
            }
            if (system == NULL ||
                system->tb_end == IA64_TR_SYSTEM_TB_CONTINUE) {
                continue;
            }
            if (system->tb_end == IA64_TR_SYSTEM_TB_BUNDLE ||
                system->tb_end == IA64_TR_SYSTEM_TB_CONDITIONAL_BUNDLE) {
                system_bundle_exit = true;
                continue;
            }

            g_assert(system->tb_end == IA64_TR_SYSTEM_TB_NEXT_SLOT ||
                     system->tb_end == IA64_TR_SYSTEM_TB_CONTROL ||
                     system->tb_end == IA64_TR_SYSTEM_TB_NORETURN);
            if (!insn->stop_after) {
                ia64_tr_group_suspend_for_typed_continuation(ctx);
                ctx->instruction_group_start = false;
            } else {
                ctx->instruction_group_start = true;
            }
            if (slot + insn->slot_span == IA64_SLOT_COUNT) {
                ia64_tr_note_retired_bundle(ctx);
            }
            ia64_tr_emit_system_main_loop_exit(
                ctx, pc, slot + insn->slot_span);
            ctx->rewrite_control_flow_exit = true;
            ctx->base.is_jmp = DISAS_NORETURN;
            return true;
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
            fallthrough_typed_active, system_bundle_exit);
        ctx->rewrite_control_flow_exit = true;
        ctx->base.is_jmp = DISAS_NORETURN;
        return true;
    }

    if (system_bundle_exit) {
        ctx->instruction_group_start = decoded.ends_at_group_boundary;
        if (!ctx->instruction_group_start) {
            ia64_tr_group_suspend_for_typed_continuation(ctx);
        }
        ia64_tr_note_retired_bundle(ctx);
        ia64_tr_emit_system_main_loop_exit(ctx, pc, IA64_SLOT_COUNT);
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
        ia64_tr_note_retired_bundle(ctx);
    }
    return true;
}

static void ia64_tr_emit_main_loop_exit(DisasContext *ctx)
{
    ia64_tr_profile_add(ctx, IA64_PROFILE_SYNC_EXIT, 1);
    ia64_tr_sync_state_cache(ctx);
    ia64_tr_flush_retired_bundles(ctx);
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
    if (ia64_perf_enabled()) {
        TCGLabel *not_requested = gen_new_label();

        tcg_gen_brcondi_i32(TCG_COND_EQ, request, 0, not_requested);
        gen_helper_perf_exit_request();
        tcg_gen_br(main_loop_exit);
        gen_set_label(not_requested);
    } else {
        tcg_gen_brcondi_i32(TCG_COND_NE, request, 0, main_loop_exit);
    }
}

static void ia64_tr_emit_fallthrough_exit(DisasContext *ctx, uint64_t target)
{
    ia64_tr_store_source_visibility_state(ctx, ctx->instruction_group_start,
                                          ctx->typed_group_active);
    if (translator_use_goto_tb(&ctx->base, target)) {
        TCGLabel *main_loop_exit = gen_new_label();

        ia64_tr_profile_add(ctx, IA64_PROFILE_SYNC_EXIT, 1);
        ia64_tr_sync_state_cache(ctx);
        ia64_tr_commit_ip(target);
        ia64_tr_flush_retired_bundles(ctx);
        ia64_tr_emit_exit_request_guard(main_loop_exit);
        ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_DIRECT);
        ia64_tr_count_chained_exit();
        tcg_gen_goto_tb(0);
        tcg_gen_exit_tb(ctx->base.tb, 0);

        gen_set_label(main_loop_exit);
        ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_MAIN);
        tcg_gen_exit_tb(NULL, 0);
    } else {
        ia64_tr_commit_ip(target);
        ia64_tr_emit_main_loop_exit(ctx);
    }
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
                    offsetof(CPUIA64State, issue_group.saved_ar_count));
    tcg_gen_st_i64(tcg_constant_i64(0), tcg_env,
                   offsetof(CPUIA64State, issue_group.saved_fr_mask));
    tcg_gen_st_i64(tcg_constant_i64(0), tcg_env,
                   offsetof(CPUIA64State, issue_group.saved_fr_mask) +
                   sizeof(uint64_t));
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
    bool instruction_group_start, bool typed_group_active, bool taken,
    const IA64TrDecodedBranchArm *arm)
{
    TCGLabel *main_loop_exit = gen_new_label();

    if (taken) {
        g_assert(instruction_group_start && !typed_group_active);
        ia64_tr_store_typed_taken_visibility_state();
        ia64_tr_profile_add(ctx, IA64_PROFILE_OVERLAY_CLEAR, 11);
        ia64_tr_profile_add(ctx, IA64_PROFILE_ARCH_STORE, 15);
    } else {
        ia64_tr_store_source_visibility_state(
            ctx, instruction_group_start, typed_group_active);
    }
    ia64_tr_clear_restart_ri();
    ia64_tr_commit_ip(target);
    if (taken && arm != NULL && arm->taken_trap) {
        TCGLabel *no_trap = gen_new_label();
        TCGv_i64 psr = tcg_temp_new_i64();

        tcg_gen_st8_i32(tcg_constant_i32(1), tcg_env,
                        offsetof(CPUIA64State, current_slot_valid));
        tcg_gen_st8_i32(tcg_constant_i32(arm->source_slot), tcg_env,
                        offsetof(CPUIA64State, current_slot_ri));
        tcg_gen_st8_i32(tcg_constant_i32(arm->source_type), tcg_env,
                        offsetof(CPUIA64State, current_slot_type));
        tcg_gen_st_i64(tcg_constant_i64(arm->source_ip), tcg_env,
                       offsetof(CPUIA64State, current_slot_ip));
        tcg_gen_st_i64(tcg_constant_i64(arm->source_raw), tcg_env,
                       offsetof(CPUIA64State, current_slot_raw));
        ia64_tr_retire_bundles_deferred_interrupt(ctx);
        tcg_gen_ld_i64(psr, tcg_env, offsetof(CPUIA64State, psr));
        tcg_gen_andi_i64(psr, psr, IA64_PSR_TB_BIT);
        tcg_gen_brcondi_i64(TCG_COND_EQ, psr, 0, no_trap);
        gen_helper_raise_taken_branch_trap(tcg_env);
        gen_set_label(no_trap);
        tcg_gen_st8_i32(tcg_constant_i32(0), tcg_env,
                        offsetof(CPUIA64State, current_slot_valid));
    }
    /* Any exit-capable tick helper must observe this arm's exact frontier. */
    ia64_tr_flush_retired_bundles(ctx);
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
    ia64_tr_profile_add(ctx, IA64_PROFILE_OVERLAY_CLEAR, 11);
    ia64_tr_profile_add(ctx, IA64_PROFILE_ARCH_STORE, 15);
    ia64_tr_clear_restart_ri();
    ia64_tr_commit_ip_value(target);
    ia64_tr_flush_retired_bundles(ctx);
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
                                           IA64Opcode opcode,
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

    ia64_tr_require_helper(opcode, IA64_OPCODE_HELPER_RETURN_FRAME);
    ia64_tr_store_typed_taken_visibility_state();
    ia64_tr_profile_add(ctx, IA64_PROFILE_OVERLAY_CLEAR, 11);
    ia64_tr_profile_add(ctx, IA64_PROFILE_ARCH_STORE, 15);
    ia64_tr_clear_restart_ri();
    ia64_tr_commit_ip_value(target);
    /* Count the retired branch without permitting asynchronous observation. */
    ia64_tr_retire_bundles_deferred_interrupt(ctx);

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

static void ia64_tr_assert_rfi_resources(
    const IA64TrInstructionTransaction *instruction,
    const IA64Instruction *insn)
{
    g_assert(instruction != NULL && ia64_tr_decoded_is_rfi(insn->opcode));
    g_assert(instruction->dest_gr[0] == 0 &&
             instruction->dest_gr[1] == 0 &&
             instruction->must_gr[0] == 0 &&
             instruction->must_gr[1] == 0 &&
             instruction->source_ar[0] == 0 &&
             instruction->source_ar[1] == 0 &&
             instruction->dest_ar[0] == 0 &&
             instruction->dest_ar[1] == 0 &&
             instruction->dest_pr == 0 &&
             instruction->must_pr == 0 &&
             instruction->forward_pr == 0 &&
             instruction->branch_source_pr == 0 &&
             instruction->source_br == 0 &&
             instruction->dest_br == 0 &&
             instruction->must_br == 0 &&
             instruction->forward_br == 0 &&
             instruction->branch_source_br == 0 &&
             !instruction->source_cfm && !instruction->dest_cfm &&
             !instruction->forward_pfs &&
             !instruction->branch_source_pfs &&
             !instruction->must_pfs);
}

/*
 * RFI is an unconditional, stop-terminated control transfer whose source
 * state lives in CR.IIP/IPSR/IFS rather than in the ordinary issue-group
 * overlay.  Retire the successful prefix and the RFI itself first, then let a
 * single focused helper restore PSR/RI/frame state and perform restartable
 * mandatory loads.  No raw instruction bits or generic branch dispatcher
 * cross this seam.
 */
static void ia64_tr_emit_decoded_rfi(DisasContext *ctx,
                                     const IA64Instruction *insn)
{
    IA64TrInstructionTransaction *instruction =
        ctx->rewrite_group.current;
    TCGLabel *cpl_zero = gen_new_label();
    TCGLabel *main_loop_exit = gen_new_label();
    TCGv_i32 chain_ok = tcg_temp_new_i32();
    TCGv_i64 psr = tcg_temp_new_i64();

    g_assert(ia64_tr_decoded_is_rfi(insn->opcode) &&
             insn->unit == IA64_INSN_UNIT_B && insn->slot_span == 1 &&
             insn->qp == 0 && insn->stop_after);
    ia64_tr_require_helper(insn->opcode, IA64_OPCODE_HELPER_RFI);
    ia64_tr_assert_rfi_resources(instruction, insn);

    /* Privilege is checked against the current PSR before RFI can retire. */
    tcg_gen_ld_i64(psr, tcg_env, offsetof(CPUIA64State, psr));
    tcg_gen_brcondi_i64(TCG_COND_TSTEQ, psr, IA64_PSR_CPL_MASK, cpl_zero);
    ia64_tr_emit_decoded_privileged_operation(ctx, insn);
    gen_set_label(cpl_zero);

    ia64_tr_publish_fault_state(insn->address, insn->slot,
                                ia64_tr_decoded_slot_type(insn->unit),
                                insn->raw, insn->starts_group);
    ia64_tr_group_finish_instruction_success(ctx, insn);
    ia64_tr_group_close(ctx);
    ia64_tr_split_state_cache_at_typed_branch(ctx);

    ia64_tr_store_typed_taken_visibility_state();
    ia64_tr_profile_add(ctx, IA64_PROFILE_OVERLAY_CLEAR, 11);
    ia64_tr_profile_add(ctx, IA64_PROFILE_ARCH_STORE, 15);
        ia64_tr_note_retired_bundle(ctx);
    ia64_tr_retire_bundles_deferred_interrupt(ctx);
    gen_helper_rfi(tcg_env, tcg_constant_i64(insn->address));

    gen_helper_return_chain_ok(chain_ok, tcg_env);
    tcg_gen_brcondi_i32(TCG_COND_EQ, chain_ok, 0, main_loop_exit);
    ia64_tr_emit_exit_request_guard(main_loop_exit);
    ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_LOOKUP);
    tcg_gen_lookup_and_goto_ptr();

    gen_set_label(main_loop_exit);
    ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_MAIN);
    tcg_gen_exit_tb(NULL, 0);
}

static void ia64_tr_emit_call_frame_transition(DisasContext *ctx,
                                               IA64Opcode opcode)
{
    /* The returning helper may rewrite every frame-dependent global. */
    g_assert(!ctx->state_cache_active);
    ia64_tr_require_helper(opcode, IA64_OPCODE_HELPER_CALL_FRAME);
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
    arm->opcode = insn->opcode;
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
    arm->opcode = insn->opcode;
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

static void ia64_tr_emit_decoded_fchkf_split(
    DisasContext *ctx, const IA64Instruction *insn,
    IA64TrDecodedBranchArm *arm)
{
    TCGv_i64 predicate = ia64_tr_scratch_i64(ctx);
    TCGv_i64 fpsr = ia64_tr_scratch_i64(ctx);
    TCGv_i64 flags = ia64_tr_scratch_i64(ctx);
    TCGv_i64 enabled_and_deferred = ia64_tr_scratch_i64(ctx);
    TCGv_i64 condition = ia64_tr_scratch_i64(ctx);
    unsigned flags_shift = 13 + 13 * (insn->sf & 3);
    uint64_t bundle_ip = insn->address &
                         ~(uint64_t)(IA64_BUNDLE_SIZE - 1);

    g_assert(insn->opcode == IA64_OP_FCHKF &&
             insn->unit == IA64_INSN_UNIT_F &&
             insn->slot_span == 1 && (insn->imm & 0xf) == 0);
    memset(arm, 0, sizeof(*arm));
    arm->taken = gen_new_label();
    arm->direct_target = bundle_ip + (uint64_t)insn->imm;
    arm->source_ip = insn->address;
    arm->source_raw = insn->raw;
    arm->source_slot = insn->slot;
    arm->source_type = ia64_tr_decoded_slot_type(insn->unit);
    arm->taken_trap = true;
    ia64_tr_profile_add(ctx, IA64_PROFILE_BRANCH_INLINE_DIRECT, 1);

    ia64_tr_group_load_branch_predicate(ctx, predicate, insn->qp);
    ia64_tr_group_load_ordinary_ar(ctx, fpsr, IA64_AR_FPSR);
    tcg_gen_shri_i64(flags, fpsr, flags_shift);
    tcg_gen_andi_i64(flags, flags, UINT64_C(0x3f));

    /* A selected flag is safe only when its trap is masked and the same
       condition is already recorded in sf0.  Every other selected flag takes
       the architected check branch. */
    tcg_gen_andi_i64(enabled_and_deferred, fpsr, UINT64_C(0x3f));
    tcg_gen_shri_i64(condition, fpsr, 13);
    tcg_gen_andi_i64(condition, condition, UINT64_C(0x3f));
    tcg_gen_and_i64(enabled_and_deferred, enabled_and_deferred, condition);
    tcg_gen_andc_i64(condition, flags, enabled_and_deferred);
    tcg_gen_setcondi_i64(TCG_COND_NE, condition, condition, 0);
    tcg_gen_and_i64(condition, condition, predicate);

    ia64_tr_group_finish_instruction_success(ctx, insn);
    if (insn->stop_after) {
        ia64_tr_group_close(ctx);
    }
    ia64_tr_split_state_cache_at_typed_branch(ctx);
    tcg_gen_brcondi_i64(TCG_COND_NE, condition, 0, arm->taken);
}

static void ia64_tr_emit_decoded_branch_cfg_exits(
    DisasContext *ctx, IA64TrDecodedBranchArm arms[IA64_SLOT_COUNT],
    unsigned arm_count, bool has_fallthrough, uint64_t fallthrough_target,
    bool fallthrough_group_start, bool fallthrough_typed_active,
    bool suppress_direct_chaining)
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
        ia64_tr_note_retired_bundle(ctx);
        ia64_tr_emit_typed_direct_branch_exit(
            ctx, fallthrough_target, 1,
            !suppress_direct_chaining &&
            translator_use_goto_tb(&ctx->base, fallthrough_target),
            fallthrough_group_start, fallthrough_typed_active, false, NULL);
    }

    for (unsigned i = 0; i < arm_count; i++) {
        gen_set_label(arms[i].taken);
        ia64_tr_note_retired_bundle(ctx);
        if (arms[i].ret) {
            g_assert(arms[i].indirect && !arms[i].call &&
                     arms[i].indirect_target != NULL &&
                     arms[i].return_pfs != NULL);
            ia64_tr_emit_typed_return_exit(
                ctx, arms[i].opcode, arms[i].indirect_target,
                arms[i].return_pfs);
            continue;
        }
        if (arms[i].call) {
            /* Entering frame transition; only this taken arm may invoke it. */
            ia64_tr_emit_call_frame_transition(ctx, arms[i].opcode);
        }
        if (arms[i].indirect) {
            ia64_tr_emit_typed_indirect_branch_exit(
                ctx, arms[i].indirect_target);
        } else {
            bool chain = (int)i == chained_direct_arm &&
                         !suppress_direct_chaining &&
                         translator_use_goto_tb(
                             &ctx->base, arms[i].direct_target);

            ia64_tr_emit_typed_direct_branch_exit(
                ctx, arms[i].direct_target, 0, chain, true, false, true,
                &arms[i]);
        }
    }
}

static void ia64_tr_emit_instruction_debug_guard(
    DisasContext *ctx, const IA64DecodedBundle *bundle,
    uint64_t pc, uint8_t start_slot)
{
    TCGv_i32 matched;
    TCGLabel *resume;
    uint8_t slot_type = bundle->valid ?
                        bundle->info->slot_type[start_slot] :
                        IA64_SLOT_TYPE_INVALID;

    g_assert(start_slot < IA64_SLOT_COUNT);
    /*
     * Instruction debug is a fetch-side check.  It precedes qualifying
     * predication and every decode legality/admission path, including a
     * bundle which will ultimately be rejected by the typed decoder.
     */
    /*
     * Instruction breakpoints can match only while PSR.db=1 and PSR.id=0.
     * The TB key selects the inactive no-code shape or the complete active
     * matcher.  Every guest PSR writer is already a TB endpoint, so no earlier
     * slot can silently change this shape.
     */
    if (ia64_tr_debug_fast_guard_enabled() &&
        (ctx->base.tb->flags & IA64_TB_FLAG_INSN_DEBUG_ACTIVE) == 0) {
        return;
    }
    matched = tcg_temp_new_i32();
    resume = gen_new_label();
    ia64_tr_sync_state_cache(ctx);
    gen_helper_instruction_debug_match(matched, tcg_env,
                                       tcg_constant_i64(pc));
    tcg_gen_brcondi_i32(TCG_COND_EQ, matched, 0, resume);
    tcg_gen_movi_i64(cpu_ip, pc);
    ia64_tr_publish_fault_state(
        pc, start_slot, slot_type,
        bundle->slot[start_slot], ctx->instruction_group_start);
    gen_helper_raise_instruction_debug(tcg_env);
    gen_set_label(resume);
}

static void ia64_tr_emit_firmware_call_gate(DisasContext *ctx, uint64_t pc)
{
    ia64_tr_sync_state_cache(ctx);
    ia64_tr_flush_retired_bundles(ctx);
    ia64_tr_publish_restart_ri(0);
    gen_helper_firmware_call_gate(tcg_env, tcg_constant_i64(pc),
                                  tcg_constant_i64(pc));
    ia64_tr_invalidate_state_cache(ctx);
    ia64_tr_profile_emit(ctx, IA64_PROFILE_EXIT_MAIN);
}

static void ia64_tr_translate_insn(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);
    IA64DecodedBundle bundle;
    char bundle_text[160];
    uint64_t pc = ctx->base.pc_next;
    uint64_t lo;
    uint64_t hi;
    uint64_t started_ns;
    uint8_t start_slot;

    /*
     * An interruption may leave a mandatory current-frame load sequence at
     * a restart boundary after the architectural target IP was committed.
     * CFLE is part of the TB key, so this one-shot TB cannot alias an ordinary
     * guest-code TB at the same IP.  Resume the sequence before even probing
     * the target bundle, then return to cpu_exec so the next lookup observes
     * either cleared CFLE or interruption delivery.  This pseudo-TB retires
     * no guest instruction.  Advancing the translator cursor only gives QEMU
     * the required nonzero TB coverage; the runtime guest IP stays unchanged.
     */
    if (ctx->cfle_resume) {
        g_assert(ctx->base.num_insns == 1);
        ctx->base.pc_next = ctx->base.pc_first + IA64_BUNDLE_SIZE;
        gen_helper_complete_rse_frame_loads(tcg_env);
        ctx->base.is_jmp = DISAS_EXIT;
        return;
    }

    if (ctx->state_cache_available && !ctx->state_cache_active &&
        ctx->base.num_insns >= ia64_tr_state_cache_min_bundles()) {
        ctx->state_cache_active = true;
    }
    ia64_tr_profile_add(ctx, IA64_PROFILE_BUNDLE_EXECUTED, 1);
    if ((ctx->base.tb->flags & IA64_TB_FLAG_ALAT_ACTIVE) != 0) {
        ia64_tr_profile_add(ctx, IA64_PROFILE_ALAT_ACTIVE_BUNDLE, 1);
    } else {
        ia64_tr_profile_add(ctx, IA64_PROFILE_ALAT_EMPTY_BUNDLE, 1);
    }
    if (ctx->state_cache_active) {
        ia64_tr_profile_add(ctx, IA64_PROFILE_STATE_CACHE_ACTIVE_BUNDLE, 1);
    }

    /*
     * Firmware call gates are host-owned transactions, including their
     * region-7 runtime aliases.  Recognize them before fetching guest code so
     * SetVirtualAddressMap does not require an artificial instruction-TLB
     * mapping for bundles that are never executed as instructions.
     */
    if (ia64_firmware_is_call_gate(pc)) {
        ctx->base.pc_next = pc + IA64_BUNDLE_SIZE;
        ia64_tr_emit_firmware_call_gate(ctx, pc);
        ctx->base.is_jmp = DISAS_EXIT;
        return;
    }

    started_ns = ia64_perf_clock_ns();
    lo = translator_ldq_end(ctx->env, &ctx->base, pc, MO_LE);
    hi = translator_ldq_end(ctx->env, &ctx->base, pc + 8, MO_LE);
    ia64_decode_bundle_words(lo, hi, &bundle);
    IA64_PERF_INC(IA64_PERF_BUNDLE_DECODED);
    if (!bundle.valid) {
        IA64_PERF_INC(IA64_PERF_BUNDLE_DECODE_INVALID);
    }
    ia64_format_decoded_bundle(&bundle, bundle_text, sizeof(bundle_text));
    trace_ia64_bundle_decode(pc, bundle_text);
    IA64_PERF_ADD(IA64_PERF_DECODE_HOST_NS,
                  ia64_perf_clock_ns() - started_ns);

    ctx->base.pc_next = pc + IA64_BUNDLE_SIZE;
    start_slot = pc == ctx->base.pc_first ?
                 ia64_tcg_tb_flags_ri(ctx->base.tb->flags) : 0;
    if (start_slot >= IA64_SLOT_COUNT) {
        start_slot = 0;
    }
    ia64_tr_emit_instruction_debug_guard(ctx, &bundle, pc, start_slot);

    if (!bundle.valid) {
        ia64_tr_emit_invalid_template(ctx, &bundle, pc, start_slot);
        ctx->base.is_jmp = DISAS_NORETURN;
        return;
    }

    if (!ctx->rewrite_region_decided) {
        unsigned bundle_count = 0;
        uint8_t last_slot = IA64_SLOT_COUNT - 1;

        started_ns = ia64_perf_clock_ns();
        ctx->typed_segment_active = ia64_tr_preflight_rewrite_region(
            ctx, &bundle, pc, start_slot, &bundle_count, &last_slot);
        IA64_PERF_ADD(IA64_PERF_PREFLIGHT_HOST_NS,
                      ia64_perf_clock_ns() - started_ns);
        if (!ctx->typed_segment_active) {
            ia64_tr_fail_typed_continuation(
                pc, "closed typed preflight rejected a valid bundle");
        }
        ctx->rewrite_region_bundles_left = bundle_count;
        ctx->rewrite_region_bundle_count = bundle_count;
        ctx->rewrite_region_last_slot = last_slot;
        ctx->rewrite_region_ops_start = tcg_ctx->nb_ops;
        ctx->rewrite_region_decided = true;
        ia64_tr_group_reserve(ctx, bundle_count * IA64_SLOT_COUNT);
    }

    g_assert(ctx->typed_segment_active);
    {
        uint8_t last_slot = ctx->rewrite_region_bundles_left == 1 ?
                            ctx->rewrite_region_last_slot :
                            IA64_SLOT_COUNT - 1;
        bool translated;

        started_ns = ia64_perf_clock_ns();
        translated = ia64_tr_try_decoded_bundle(
            ctx, &bundle, pc, start_slot, last_slot);
        IA64_PERF_ADD(IA64_PERF_TCG_EMISSION_HOST_NS,
                      ia64_perf_clock_ns() - started_ns);

        if (!translated) {
            ia64_tr_fail_typed_continuation(
                pc, "closed typed lowering rejected a preflighted bundle");
        }
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
            ctx->typed_segment_active = false;
            ctx->rewrite_region_bundle_count = 0;
            ctx->rewrite_region_last_slot = IA64_SLOT_COUNT - 1;
            ctx->rewrite_region_ops_start = 0;
            return;
        }

        /* Branch and slot-ending system rows own every legal partial bundle. */
        g_assert(last_slot == IA64_SLOT_COUNT - 1);

        if (ctx->instruction_group_start) {
            g_assert(ctx->rewrite_region_bundles_left == 0);
            g_assert(ia64_tr_group_is_empty(ctx));
            ctx->rewrite_region_decided = false;
            ctx->typed_segment_active = false;
            ctx->rewrite_region_bundle_count = 0;
            ctx->rewrite_region_last_slot = IA64_SLOT_COUNT - 1;
            ctx->rewrite_region_ops_start = 0;
            if (ia64_tr_should_end_before_next_typed_group()) {
                ctx->base.is_jmp = DISAS_TOO_MANY;
            }
        } else if (ctx->rewrite_region_bundles_left == 0) {
            ia64_tr_group_suspend_for_typed_continuation(ctx);
            ctx->typed_segment_active = false;
            ctx->rewrite_region_bundle_count = 0;
            ctx->rewrite_region_last_slot = IA64_SLOT_COUNT - 1;
            ctx->rewrite_region_ops_start = 0;
            ctx->base.is_jmp = DISAS_TOO_MANY;
        } else {
            g_assert(!tcg_op_buf_full());
        }
    }
}

static void ia64_tr_tb_stop(DisasContextBase *dcbase, CPUState *cs)
{
    DisasContext *ctx = container_of(dcbase, DisasContext, base);

    g_assert(!ctx->typed_segment_active);
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
    IA64_PERF_ADD(IA64_PERF_PLAN_CAPACITY, ctx.rewrite_plan_capacity);
    if (ia64_perf_enabled()) {
        ia64_perf_max(IA64_PERF_PLAN_CAPACITY_MAX,
                      ctx.rewrite_plan_capacity);
    }
    g_free(ctx.rewrite_group.instruction);
    g_free(ctx.rewrite_plan);
}
