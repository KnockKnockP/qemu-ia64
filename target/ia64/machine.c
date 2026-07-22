/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/cputlb.h"
#include "insn.h"
#include "mem.h"
#include "migration/vmstate.h"
#include "qemu/error-report.h"
#include "system-plane.h"

#define IA64_PSR_BN_BIT UINT64_C(0x0000100000000000)
#define IA64_RSE_PHYSICAL_COUNT IA64_MAX_STACKED_REGS

static const VMStateDescription vmstate_float_reg = {
    .name = "float-reg",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT64_ARRAY(raw, IA64FloatReg, 2),
        VMSTATE_END_OF_LIST()
    }
};

static uint32_t ia64_vmstate_rse_num_regs(uint64_t bspstore, uint64_t bsp)
{
    uint64_t slots;

    if (bsp <= bspstore) {
        return 0;
    }
    slots = (bsp - bspstore) >> 3;
    return slots - (((bspstore >> 3) & 0x3f) + slots) / 0x40;
}

static int32_t ia64_vmstate_rse_nat_words(uint64_t low, uint64_t high)
{
    return (int64_t)(high >> 9) - (int64_t)(low >> 9);
}

static int ia64_validate_rse_vmstate(const IA64RSEState *rse)
{
    int64_t partition_total;
    int64_t dirty_words;
    uint64_t expected_bspstore;

    if (rse->sof > IA64_RSE_PHYSICAL_COUNT ||
        rse->bol >= IA64_RSE_PHYSICAL_COUNT ||
        rse->current_frame_base >= IA64_STACKED_GR_COUNT ||
        rse->dirty < -(int32_t)IA64_RSE_PHYSICAL_COUNT ||
        rse->dirty > (int32_t)IA64_RSE_PHYSICAL_COUNT ||
        rse->dirty_nat < -2 || rse->dirty_nat > 2 ||
        rse->clean < 0 || rse->clean > IA64_RSE_PHYSICAL_COUNT ||
        rse->clean_nat < 0 || rse->clean_nat > 2 ||
        rse->invalid < 0 || rse->invalid > IA64_RSE_PHYSICAL_COUNT) {
        error_report("IA-64 migration stream has out-of-range RSE "
                     "partition state");
        return -EINVAL;
    }

    partition_total = (int64_t)rse->sof + rse->dirty + rse->clean +
                      rse->invalid;
    if (partition_total != IA64_RSE_PHYSICAL_COUNT) {
        error_report("IA-64 migration stream RSE partitions do not cover "
                     "the 96-register physical file");
        return -EINVAL;
    }
    if ((rse->bsp | rse->bspstore) & 7) {
        error_report("IA-64 migration stream has an unaligned RSE backing "
                     "store pointer");
        return -EINVAL;
    }

    dirty_words = (int64_t)rse->dirty + rse->dirty_nat;
    expected_bspstore = rse->bsp - (uint64_t)(dirty_words * 8);
    if (rse->bspstore != expected_bspstore) {
        error_report("IA-64 migration stream has inconsistent BSP/BSPSTORE "
                     "and dirty partitions");
        return -EINVAL;
    }

    if (rse->dirty < 0 || rse->dirty_nat < 0) {
        uint64_t span_slots;
        uint32_t missing_regs;
        uint32_t missing_nats;

        if (rse->dirty > 0 || rse->dirty_nat > 0 ||
            rse->clean != 0 || rse->clean_nat != 0 ||
            rse->bspstore <= rse->bsp) {
            error_report("IA-64 migration stream has a non-canonical "
                         "incomplete RSE partition state");
            return -EINVAL;
        }
        span_slots = (rse->bspstore - rse->bsp) >> 3;
        missing_regs = ia64_vmstate_rse_num_regs(rse->bsp, rse->bspstore);
        missing_nats = span_slots - missing_regs;
        if (rse->dirty != -(int32_t)missing_regs ||
            rse->dirty_nat != -(int32_t)missing_nats) {
            error_report("IA-64 migration stream incomplete RSE counters "
                         "do not describe its BSP/BSPSTORE span");
            return -EINVAL;
        }
    } else {
        uint64_t lower_clean = rse->bspstore -
            (uint64_t)((int64_t)rse->clean + rse->clean_nat) * 8;

        if (rse->dirty_nat !=
            ia64_vmstate_rse_nat_words(rse->bspstore, rse->bsp) ||
            rse->clean_nat !=
            ia64_vmstate_rse_nat_words(lower_clean, rse->bspstore)) {
            error_report("IA-64 migration stream has inconsistent RSE NaT "
                         "collection partitions");
            return -EINVAL;
        }
    }
    return 0;
}

static int ia64_rse_vmstate_pre_load(void *opaque)
{
    IA64RSEState *rse = opaque;

    rse->bol = 0;
    rse->dirty = 0;
    rse->dirty_nat = 0;
    rse->clean = 0;
    rse->clean_nat = 0;
    rse->invalid = IA64_RSE_PHYSICAL_COUNT;
    rse->cfle = false;
    rse->reference = false;
    rse->bsp_load = 0;
    rse->clean_count = 0;
    memset(rse->logical_nat, 0, sizeof(rse->logical_nat));
    memset(rse->logical_dirty, 0, sizeof(rse->logical_dirty));
    memset(rse->stacked_nat, 0, sizeof(rse->stacked_nat));
    return 0;
}

static int ia64_rse_vmstate_post_load(void *opaque, int version_id)
{
    IA64RSEState *rse = opaque;

    /* The issuing-memory-reference tag is never wire state. */
    rse->reference = false;
    if (version_id != 5) {
        error_report("unsupported IA-64 RSE VMState version %d", version_id);
        return -EINVAL;
    }

    return ia64_validate_rse_vmstate(rse);
}

static const VMStateDescription vmstate_rse = {
    .name = "rse",
    .version_id = 5,
    .minimum_version_id = 5,
    .pre_load = ia64_rse_vmstate_pre_load,
    .post_load = ia64_rse_vmstate_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT64(rsc, IA64RSEState),
        VMSTATE_UINT64(bsp, IA64RSEState),
        VMSTATE_UINT64(bspstore, IA64RSEState),
        VMSTATE_UINT64(rnat, IA64RSEState),
        VMSTATE_UINT64(loadrs, IA64RSEState),
        VMSTATE_UINT32(sof, IA64RSEState),
        VMSTATE_UINT32(sol, IA64RSEState),
        VMSTATE_UINT32(sor, IA64RSEState),
        VMSTATE_UINT32(rrb_gr, IA64RSEState),
        VMSTATE_UINT32(rrb_fr, IA64RSEState),
        VMSTATE_UINT32(rrb_pr, IA64RSEState),
        VMSTATE_UINT32(current_frame_base, IA64RSEState),
        VMSTATE_UINT64_ARRAY(stacked_gr, IA64RSEState,
                             IA64_STACKED_GR_COUNT),
        VMSTATE_UINT64_ARRAY_V(stacked_nat, IA64RSEState,
                               IA64_RSE_NAT_WORDS, 2),
        VMSTATE_UINT32_V(bol, IA64RSEState, 4),
        VMSTATE_INT32_V(dirty, IA64RSEState, 4),
        VMSTATE_INT32_V(dirty_nat, IA64RSEState, 4),
        VMSTATE_INT32_V(clean, IA64RSEState, 4),
        VMSTATE_INT32_V(clean_nat, IA64RSEState, 4),
        VMSTATE_INT32_V(invalid, IA64RSEState, 4),
        VMSTATE_BOOL_V(cfle, IA64RSEState, 4),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_nat = {
    .name = "nat",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT64_ARRAY(gr_nat, IA64NaTState, 2),
        VMSTATE_UINT64(unat, IA64NaTState),
        VMSTATE_UINT64(rnat, IA64NaTState),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_alat_entry = {
    .name = "alat-entry",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_BOOL(valid, IA64AlatEntry),
        VMSTATE_UINT8(target, IA64AlatEntry),
        VMSTATE_UINT8(width, IA64AlatEntry),
        VMSTATE_BOOL(physical, IA64AlatEntry),
        VMSTATE_UINT64(address, IA64AlatEntry),
        VMSTATE_END_OF_LIST()
    }
};

/*
 * Keep the v1 entry payload frozen.  GR/FR tags live in a versioned optional
 * subsection below, so an absent subsection is an explicit legacy-GR default
 * rather than an ambiguous change to the unversioned struct-array layout.
 */
static const VMStateDescription vmstate_alat_entry_target_type = {
    .name = "alat-entry-target-type",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT8(target_type, IA64AlatEntry),
        VMSTATE_END_OF_LIST()
    }
};

static bool ia64_alat_vmstate_width_valid(uint8_t target_type, uint8_t width)
{
    if (target_type == IA64_ALAT_TARGET_GR) {
        return width == 1 || width == 2 || width == 4 || width == 8;
    }
    if (target_type == IA64_ALAT_TARGET_FR) {
        return width == 4 || width == 8 || width == 10 || width == 16;
    }
    return false;
}

static int ia64_validate_alat_vmstate(const IA64AlatState *alat)
{
    if (alat->next >= IA64_ALAT_COUNT) {
        error_report("IA-64 migration stream has out-of-range ALAT "
                     "replacement cursor %u", alat->next);
        return -EINVAL;
    }

    for (unsigned i = 0; i < IA64_ALAT_COUNT; i++) {
        const IA64AlatEntry *entry = &alat->entries[i];

        if (entry->target_type >= IA64_ALAT_TARGET_TYPE_COUNT) {
            error_report("IA-64 migration stream ALAT entry %u has invalid "
                         "target type %u", i, entry->target_type);
            return -EINVAL;
        }
        if (!entry->valid) {
            continue;
        }
        if ((entry->target_type == IA64_ALAT_TARGET_GR &&
             (entry->target == 0 || entry->target >= IA64_GR_COUNT)) ||
            (entry->target_type == IA64_ALAT_TARGET_FR &&
             (entry->target < 2 || entry->target >= IA64_FR_COUNT))) {
            error_report("IA-64 migration stream ALAT entry %u has invalid "
                         "%s target %u", i,
                         entry->target_type == IA64_ALAT_TARGET_FR ?
                         "FR" : "GR", entry->target);
            return -EINVAL;
        }
        if (!ia64_alat_vmstate_width_valid(entry->target_type,
                                            entry->width)) {
            error_report("IA-64 migration stream ALAT entry %u has invalid "
                         "%s width %u", i,
                         entry->target_type == IA64_ALAT_TARGET_FR ?
                         "FR" : "GR", entry->width);
            return -EINVAL;
        }
    }
    return 0;
}

static int ia64_alat_vmstate_pre_load(void *opaque)
{
    IA64AlatState *alat = opaque;

    /* Missing target-type subsection means the legacy all-GR schema. */
    for (unsigned i = 0; i < IA64_ALAT_COUNT; i++) {
        alat->entries[i].target_type = IA64_ALAT_TARGET_GR;
    }
    alat->valid_mask = 0;
    memset(alat->gr_mask, 0, sizeof(alat->gr_mask));
    memset(alat->gr_refcount, 0, sizeof(alat->gr_refcount));
    return 0;
}

static int ia64_alat_vmstate_pre_save(void *opaque)
{
    return ia64_validate_alat_vmstate(opaque);
}

static int ia64_alat_vmstate_post_load(void *opaque, int version_id)
{
    if (version_id != 1) {
        error_report("IA-64 migration stream has unsupported ALAT version %d",
                     version_id);
        return -EINVAL;
    }
    return ia64_validate_alat_vmstate(opaque);
}

static bool ia64_alat_target_types_needed(void *opaque)
{
    IA64AlatState *alat = opaque;

    for (unsigned i = 0; i < IA64_ALAT_COUNT; i++) {
        if (alat->entries[i].target_type != IA64_ALAT_TARGET_GR) {
            return true;
        }
    }
    return false;
}

static const VMStateDescription vmstate_alat_target_types = {
    .name = "alat/target-types",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = ia64_alat_target_types_needed,
    .fields = (const VMStateField[]) {
        VMSTATE_STRUCT_ARRAY(entries, IA64AlatState, IA64_ALAT_COUNT, 0,
                             vmstate_alat_entry_target_type, IA64AlatEntry),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_alat = {
    .name = "alat",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_load = ia64_alat_vmstate_pre_load,
    .pre_save = ia64_alat_vmstate_pre_save,
    .post_load = ia64_alat_vmstate_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_STRUCT_ARRAY(entries, IA64AlatState, IA64_ALAT_COUNT, 0,
                             vmstate_alat_entry, IA64AlatEntry),
        VMSTATE_UINT8(next, IA64AlatState),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription * const []) {
        &vmstate_alat_target_types,
        NULL
    }
};

static int ia64_interrupt_vmstate_pre_load(void *opaque)
{
    IA64InterruptState *interrupt = opaque;

    memset(interrupt->in_service, 0, sizeof(interrupt->in_service));
    interrupt->legacy_pending_interruption = 0;
    interrupt->pending_vector = 0;
    interrupt->timer_compare_latched = IA64_TIMER_COMPARE_IDLE;
    interrupt->pending = 0;
    return 0;
}

static int ia64_interrupt_vmstate_post_load(void *opaque, int version_id)
{
    IA64InterruptState *interrupt = opaque;
    const uint64_t valid_word0 =
        (~UINT64_C(0) << 16) | UINT64_C(1) | (UINT64_C(1) << 2);

    if (interrupt->timer_compare_latched > IA64_TIMER_COMPARE_ARMED) {
        error_report("IA-64 migration stream has invalid timer comparison "
                     "state %u", interrupt->timer_compare_latched);
        return -EINVAL;
    }
    if (version_id >= 3 &&
        (interrupt->in_service[0] & ~valid_word0) != 0) {
        error_report("IA-64 migration stream marks a reserved external "
                     "interrupt vector in service");
        return -EINVAL;
    }
    return 0;
}

static int ia64_interrupt_vmstate_pre_save(void *opaque)
{
    return ia64_interrupt_vmstate_post_load(opaque, 3);
}

static const VMStateDescription vmstate_interrupt = {
    .name = "interrupt",
    .version_id = 3,
    .minimum_version_id = 3,
    .pre_save = ia64_interrupt_vmstate_pre_save,
    .pre_load = ia64_interrupt_vmstate_pre_load,
    .post_load = ia64_interrupt_vmstate_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT64_ARRAY(in_service, IA64InterruptState, 4),
        VMSTATE_UINT8(timer_compare_latched, IA64InterruptState),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_translation_entry = {
    .name = "translation-entry",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_BOOL(valid, IA64TranslationEntry),
        VMSTATE_BOOL(instruction, IA64TranslationEntry),
        VMSTATE_BOOL(pinned, IA64TranslationEntry),
        VMSTATE_UINT64(vaddr_base, IA64TranslationEntry),
        VMSTATE_UINT64(paddr_base, IA64TranslationEntry),
        VMSTATE_UINT64(raw, IA64TranslationEntry),
        VMSTATE_UINT64(itir, IA64TranslationEntry),
        VMSTATE_UINT32(rid, IA64TranslationEntry),
        VMSTATE_UINT32(key, IA64TranslationEntry),
        VMSTATE_UINT8(page_size, IA64TranslationEntry),
        VMSTATE_UINT8(memory_attribute, IA64TranslationEntry),
        VMSTATE_UINT8(privilege_level, IA64TranslationEntry),
        VMSTATE_UINT8(access_rights, IA64TranslationEntry),
        VMSTATE_BOOL(present, IA64TranslationEntry),
        VMSTATE_BOOL(accessed, IA64TranslationEntry),
        VMSTATE_BOOL(dirty, IA64TranslationEntry),
        VMSTATE_BOOL(exception_deferral, IA64TranslationEntry),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_memory = {
    .name = "memory",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT64(last_vaddr, IA64MemorySkeletonState),
        VMSTATE_UINT64(last_paddr, IA64MemorySkeletonState),
        VMSTATE_UINT8(last_region, IA64MemorySkeletonState),
        VMSTATE_UINT8(last_status, IA64MemorySkeletonState),
        VMSTATE_UINT8(last_page_size, IA64MemorySkeletonState),
        VMSTATE_BOOL(identity_region0_only, IA64MemorySkeletonState),
        VMSTATE_STRUCT_ARRAY(itr, IA64MemorySkeletonState, IA64_ITR_COUNT, 0,
                             vmstate_translation_entry, IA64TranslationEntry),
        VMSTATE_STRUCT_ARRAY(dtr, IA64MemorySkeletonState, IA64_DTR_COUNT, 0,
                             vmstate_translation_entry, IA64TranslationEntry),
        /*
         * Dynamic TLB entries are cache state.  Keep serializing only the
         * original 32 slots so older Debian frontier snapshots remain loadable.
         */
        VMSTATE_STRUCT_SUB_ARRAY(itc, IA64MemorySkeletonState, 0,
                                 IA64_TC_VMSTATE_COUNT, 0,
                                 vmstate_translation_entry,
                                 IA64TranslationEntry),
        VMSTATE_STRUCT_SUB_ARRAY(dtc, IA64MemorySkeletonState, 0,
                                 IA64_TC_VMSTATE_COUNT, 0,
                                 vmstate_translation_entry,
                                 IA64TranslationEntry),
        VMSTATE_UINT8(next_itc, IA64MemorySkeletonState),
        VMSTATE_UINT8(next_dtc, IA64MemorySkeletonState),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_exception = {
    .name = "exception",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT32(kind, IA64ExceptionRecord),
        VMSTATE_UINT64(ip, IA64ExceptionRecord),
        VMSTATE_UINT64(address, IA64ExceptionRecord),
        VMSTATE_INT32(access_type, IA64ExceptionRecord),
        VMSTATE_UINT64(vector, IA64ExceptionRecord),
        VMSTATE_BOOL(pending, IA64ExceptionRecord),
        VMSTATE_BUFFER(message, IA64ExceptionRecord),
        VMSTATE_END_OF_LIST()
    }
};

static int ia64_validate_issue_group_overlay(CPUIA64State *env);

static int ia64_env_pre_save(void *opaque)
{
    CPUIA64State *env = opaque;
    const uint64_t valid_interrupt_word0 =
        (~UINT64_C(0) << 16) | UINT64_C(1) | (UINT64_C(1) << 2);
    int ret;

    /*
     * instruction_group_dirty is a translated-memory unwind breadcrumb, not
     * architectural state.  A migration boundary must never observe it.
     */
    if (env->instruction_group_dirty) {
        error_report("IA-64 migration reached a transient instruction-group "
                     "fault breadcrumb");
        return -EINVAL;
    }
    if (env->rse.reference) {
        error_report("IA-64 migration reached the middle of an issued "
                     "RSE memory reference");
        return -EINVAL;
    }
    ret = ia64_validate_rse_vmstate(&env->rse);
    if (ret < 0) {
        return ret;
    }
    if ((env->cr[IA64_CR_IRR0] & ~valid_interrupt_word0) != 0) {
        error_report("IA-64 migration reached a reserved pending external "
                     "interrupt vector");
        return -EINVAL;
    }
    if ((env->rse.dirty < 0 || env->rse.dirty_nat < 0) &&
        env->rse.bsp_load != env->rse.bspstore) {
        error_report("IA-64 migration reached an incomplete RSE frame with "
                     "inconsistent BSPLOAD");
        return -EINVAL;
    }
    /* ri/ri_dirty is a runtime cache; migrate its canonical PSR image. */
    ia64_env_sync_psr_ri(env);
    ret = ia64_validate_issue_group_overlay(env);
    if (ret < 0) {
        return ret;
    }
    /*
     * r32-r127 are a transient logical mirror.  Commit only its dirty names
     * to the canonical physical RSE arrays before either representation is
     * written to the stream.  This deliberately does not add VMState fields:
     * old streams already contain the physical arrays needed for restore.
     */
    ia64_rse_sync_logical_out(env);
    /* Serialize the current clock-backed ITC value in ar[IA64_AR_ITC]. */
    ia64_itc_sync(env);
    return 0;
}

static int ia64_env_pre_load(void *opaque)
{
    CPUIA64State *env = opaque;

    /* Transient mirror metadata is never stream authority. */
    memset(env->rse.logical_nat, 0, sizeof(env->rse.logical_nat));
    memset(env->rse.logical_dirty, 0, sizeof(env->rse.logical_dirty));
    env->rse.reference = false;
    env->rse.cfle = false;
    env->current_slot_valid = false;
    env->current_slot_ri = 0;
    env->current_slot_type = 0;
    env->current_slot_speculative_load = false;
    env->current_slot_prefix_materialized = false;
    env->current_slot_may_external_access = false;
    env->current_slot_memory_class = 0;
    env->current_slot_ip = 0;
    env->current_slot_raw = 0;
    env->current_slot_metadata = 0;
    /* Older streams predate issue-group frontier tracking. */
    ia64_env_begin_source_visibility_epoch(env);
    /* An absent outer collection-state subsection means reset defaults. */
    env->last_successful_bundle = 0;
    env->psr_ic_inflight = false;
    return 0;
}

static bool ia64_instruction_group_state_needed(void *opaque)
{
    CPUIA64State *env = opaque;

    return !env->instruction_group_start;
}

static const VMStateDescription vmstate_instruction_group_state = {
    .name = "env/instruction-group-start",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = ia64_instruction_group_state_needed,
    .fields = (const VMStateField[]) {
        VMSTATE_BOOL(instruction_group_start, CPUIA64State),
        VMSTATE_END_OF_LIST()
    },
};

static bool ia64_issue_group_overlay_needed(void *opaque)
{
    CPUIA64State *env = opaque;

    /* Successful direct memory may leave an inactive restart image in the
     * shared storage bank.  Only a typed owner makes that image architectural
     * issue-group state and therefore migration-visible. */
    return env->issue_group.typed_active;
}

static int ia64_issue_group_overlay_post_load(void *opaque, int version_id)
{
    CPUIA64State *env = opaque;

    if (version_id < 2) {
        /* In v1, presence of this subsection was the epoch-owner marker. */
        env->issue_group.typed_active = true;
    }
    if (version_id < 3) {
        /*
         * Every typed PR writer admitted by the v1/v2 rewrite was eligible
         * for compare/test-to-branch forwarding.  The old stream has both the
         * group-entry image and the retired live image, so their physical-bit
         * delta is the exact provenance needed when the values differ.  Bits
         * whose values agree are observationally indifferent to selection.
         */
        env->issue_group.branch_pr_forward_mask =
            env->issue_group.typed_active && env->issue_group.pr_saved ?
            (env->pr ^ env->issue_group.saved_pr) & ~UINT64_C(1) : 0;
    }
    if (version_id < 4) {
        /* No typed BR producer existed in v1-v3 streams. */
        env->issue_group.saved_br_mask = 0;
        env->issue_group.branch_br_forward_mask = 0;
    }
    if (version_id < 5) {
        /* No typed AR.PFS resource existed in v1-v4 streams. */
        env->issue_group.saved_pfs = 0;
        env->issue_group.pfs_saved = false;
        env->issue_group.branch_pfs_forwarded = false;
    }
    if (version_id < 6) {
        /* No generic ordinary-AR resource existed in v1-v5 streams. */
        memset(env->issue_group.saved_ar_value, 0,
               sizeof(env->issue_group.saved_ar_value));
        memset(env->issue_group.saved_ar_index, 0,
               sizeof(env->issue_group.saved_ar_index));
        env->issue_group.saved_ar_count = 0;
    }
    if (version_id < 7) {
        /* No typed check-load forwarding existed in v1-v6 streams. */
        env->issue_group.check_gr_forward_mask[0] = 0;
        env->issue_group.check_gr_forward_mask[1] = 0;
    }
    return 0;
}

static const VMStateDescription vmstate_issue_group_overlay = {
    .name = "env/issue-group-overlay",
    .version_id = 7,
    .minimum_version_id = 1,
    .needed = ia64_issue_group_overlay_needed,
    .post_load = ia64_issue_group_overlay_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT64_ARRAY(issue_group.saved_gr, CPUIA64State,
                             IA64_GR_COUNT),
        VMSTATE_UINT64_ARRAY(issue_group.saved_nat, CPUIA64State,
                             IA64_GR_COUNT),
        VMSTATE_UINT64_ARRAY(issue_group.saved_gr_mask, CPUIA64State, 2),
        VMSTATE_UINT64_ARRAY_V(issue_group.saved_br, CPUIA64State,
                               IA64_BR_COUNT, 4),
        VMSTATE_UINT64(issue_group.saved_pr, CPUIA64State),
        VMSTATE_BOOL(issue_group.pr_saved, CPUIA64State),
        VMSTATE_BOOL_V(issue_group.typed_active, CPUIA64State, 2),
        VMSTATE_UINT64_V(issue_group.branch_pr_forward_mask,
                         CPUIA64State, 3),
        VMSTATE_UINT8_V(issue_group.saved_br_mask, CPUIA64State, 4),
        VMSTATE_UINT8_V(issue_group.branch_br_forward_mask,
                        CPUIA64State, 4),
        VMSTATE_UINT64_V(issue_group.saved_pfs, CPUIA64State, 5),
        VMSTATE_BOOL_V(issue_group.pfs_saved, CPUIA64State, 5),
        VMSTATE_BOOL_V(issue_group.branch_pfs_forwarded,
                       CPUIA64State, 5),
        VMSTATE_UINT64_ARRAY_V(issue_group.saved_ar_value, CPUIA64State,
                               IA64_ISSUE_GROUP_AR_CAPACITY, 6),
        VMSTATE_UINT8_ARRAY_V(issue_group.saved_ar_index, CPUIA64State,
                              IA64_ISSUE_GROUP_AR_CAPACITY, 6),
        VMSTATE_UINT8_V(issue_group.saved_ar_count, CPUIA64State, 6),
        VMSTATE_UINT64_ARRAY_V(issue_group.check_gr_forward_mask,
                               CPUIA64State, 2, 7),
        VMSTATE_END_OF_LIST()
    },
};

static bool ia64_issue_group_fr_overlay_needed(void *opaque)
{
    CPUIA64State *env = opaque;

    return env->issue_group.typed_active &&
           (env->issue_group.saved_fr_mask[0] != 0 ||
            env->issue_group.saved_fr_mask[1] != 0);
}

/* Kept as a separate optional subsection so the existing ordinary-source
   overlay wire versions remain readable. */
static const VMStateDescription vmstate_issue_group_fr_overlay = {
    .name = "env/issue-group-fr-overlay",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = ia64_issue_group_fr_overlay_needed,
    .fields = (const VMStateField[]) {
        VMSTATE_STRUCT_ARRAY(issue_group.saved_fr, CPUIA64State,
                             IA64_FR_COUNT, 0, vmstate_float_reg,
                             IA64FloatReg),
        VMSTATE_UINT64_ARRAY(issue_group.saved_fr_mask, CPUIA64State, 2),
        VMSTATE_END_OF_LIST()
    },
};

static int ia64_validate_issue_group_overlay(CPUIA64State *env)
{
    uint64_t mask[2] = {
        env->issue_group.saved_gr_mask[0],
        env->issue_group.saved_gr_mask[1],
    };
    uint64_t ar_seen[2] = { 0, 0 };

    if (env->issue_group.saved_ar_count >
        IA64_ISSUE_GROUP_AR_CAPACITY) {
        error_report("IA-64 migration stream has too many saved ordinary "
                     "AR sources");
        return -EINVAL;
    }
    for (unsigned i = 0; i < env->issue_group.saved_ar_count; i++) {
        uint32_t reg = env->issue_group.saved_ar_index[i];
        uint64_t bit;

        if (reg >= IA64_AR_COUNT) {
            error_report("IA-64 migration stream has invalid saved ordinary "
                         "AR%u", reg);
            return -EINVAL;
        }
        bit = UINT64_C(1) << (reg & 63);
        if (ar_seen[reg >> 6] & bit) {
            error_report("IA-64 migration stream saves ordinary AR%u more "
                         "than once", reg);
            return -EINVAL;
        }
        ar_seen[reg >> 6] |= bit;
    }

    if (env->instruction_group_start &&
        ia64_issue_group_overlay_needed(env)) {
        error_report("IA-64 migration stream has an ordinary-source overlay "
                     "at a fresh visibility frontier");
        return -EINVAL;
    }
    if (!env->issue_group.typed_active) {
        /* Inactive pending-restart storage is neither serialized nor
         * interpreted as an architectural ordinary-source overlay. */
        return 0;
    }
    if (mask[0] & 1) {
        error_report("IA-64 migration stream marks immutable GR0 as saved");
        return -EINVAL;
    }
    if (env->issue_group.check_gr_forward_mask[0] & 1) {
        error_report("IA-64 migration stream forwards immutable GR0");
        return -EINVAL;
    }
    if ((env->issue_group.check_gr_forward_mask[0] & ~mask[0]) != 0 ||
        (env->issue_group.check_gr_forward_mask[1] & ~mask[1]) != 0) {
        error_report("IA-64 migration stream forwards a check-load result "
                     "without its ordinary-source entry image");
        return -EINVAL;
    }
    if (env->issue_group.saved_fr_mask[0] & UINT64_C(3)) {
        error_report("IA-64 migration stream marks immutable FR0/FR1 as "
                     "saved");
        return -EINVAL;
    }
    for (unsigned half = 0; half < ARRAY_SIZE(mask); half++) {
        while (mask[half] != 0) {
            unsigned bit = ctz64(mask[half]);
            unsigned reg = half * 64 + bit;

            if (env->issue_group.saved_nat[reg] > 1) {
                error_report("IA-64 migration stream has non-Boolean saved "
                             "NaT for GR%u", reg);
                return -EINVAL;
            }
            mask[half] &= mask[half] - 1;
        }
    }
    if (env->issue_group.pr_saved && !(env->issue_group.saved_pr & 1)) {
        error_report("IA-64 migration stream saved a PR image without p0");
        return -EINVAL;
    }
    if (env->issue_group.branch_pr_forward_mask & 1) {
        error_report("IA-64 migration stream forwards immutable PR0");
        return -EINVAL;
    }
    if (env->issue_group.branch_pfs_forwarded &&
        !env->issue_group.pfs_saved) {
        error_report("IA-64 migration stream forwards AR.PFS without its "
                     "ordinary-source entry image");
        return -EINVAL;
    }
    return 0;
}

static int ia64_env_post_load(void *opaque, int version_id)
{
    CPUIA64State *env = opaque;
    const uint64_t valid_interrupt_word0 =
        (~UINT64_C(0) << 16) | UINT64_C(1) | (UINT64_C(1) << 2);
    int ret;

    ret = ia64_validate_issue_group_overlay(env);
    if (ret < 0) {
        return ret;
    }
    if ((env->cr[IA64_CR_IRR0] & ~valid_interrupt_word0) != 0) {
        error_report("IA-64 migration stream marks a reserved external "
                     "interrupt vector pending");
        return -EINVAL;
    }

    if (version_id != 8) {
        error_report("unsupported IA-64 environment VMState version %d",
                     version_id);
        return -EINVAL;
    }
    ia64_rse_reconstruct_transients(env);
    /*
     * Physical RSE state is authoritative on the wire.  Rebuild every
     * logical stacked name after loading, overwriting the gr[32..127] image
     * carried by old streams and clearing transient logical dirty state.
     */
    ia64_rse_sync_logical_in(env);
    ia64_cpu_init_synthetic_cpuid(env);
    for (unsigned i = IA64_TC_VMSTATE_COUNT; i < IA64_TC_COUNT; i++) {
        env->memory.itc[i].valid = false;
        env->memory.dtc[i].valid = false;
    }
    env->memory.next_itc %= IA64_TC_COUNT;
    env->memory.next_dtc %= IA64_TC_COUNT;
    ia64_translation_lookup_cache_flush(env);
    ia64_alat_reconstruct_transients(env);
    ia64_pmu_sanitize_state(env);
    /*
     * Guest time continues from the serialized ITC value; re-derive the
     * clock offset and re-arm the CR.ITM deadline for the new clock.  The
     * consumed-comparison latch is architectural continuation state: clearing
     * it here would inject a duplicate timer interrupt after migration.
     */
    ia64_itc_set(env, env->ar[IA64_AR_ITC]);
    ia64_reconcile_interrupt_state(env);
    ia64_refresh_interrupt_delivery(env);
    env->gr[0] = 0;
    env->pr |= 1;
    env->ri = ia64_psr_ri(env->psr);
    env->ri_dirty = false;
    env->instruction_group_dirty = false;
    env->fault_exit_pending_tb_translate = false;
    return 0;
}

static bool ia64_env_uses_rse_v5(void *opaque, int version_id)
{
    (void)opaque;
    return version_id == 8;
}

static bool ia64_env_uses_interrupt_v3(void *opaque, int version_id)
{
    (void)opaque;
    return version_id >= 7;
}

static const VMStateDescription vmstate_env = {
    .name = "env",
    .version_id = 8,
    .minimum_version_id = 8,
    .pre_save = ia64_env_pre_save,
    .pre_load = ia64_env_pre_load,
    .post_load = ia64_env_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT64_ARRAY(gr, CPUIA64State, IA64_GR_COUNT),
        VMSTATE_UINT64_ARRAY_V(banked_gr, CPUIA64State, 16, 2),
        VMSTATE_STRUCT_ARRAY(fr, CPUIA64State, IA64_FR_COUNT, 0,
                             vmstate_float_reg, IA64FloatReg),
        VMSTATE_UINT64(pr, CPUIA64State),
        VMSTATE_UINT64_ARRAY(br, CPUIA64State, IA64_BR_COUNT),
        VMSTATE_UINT64_ARRAY(ar, CPUIA64State, IA64_AR_COUNT),
        VMSTATE_UINT64_ARRAY(cr, CPUIA64State, IA64_CR_COUNT),
        VMSTATE_UINT64_ARRAY(rr, CPUIA64State, IA64_RR_COUNT),
        VMSTATE_UINT64_ARRAY(pkr, CPUIA64State, IA64_PKR_COUNT),
        VMSTATE_UINT64_ARRAY_V(dbr, CPUIA64State, IA64_DBR_COUNT, 6),
        VMSTATE_UINT64_ARRAY_V(ibr, CPUIA64State, IA64_IBR_COUNT, 6),
        VMSTATE_UINT64_ARRAY_V(cpuid, CPUIA64State, IA64_CPUID_COUNT, 6),
        VMSTATE_UINT64_ARRAY_V(dahr, CPUIA64State, IA64_DAHR_COUNT, 6),
        VMSTATE_UINT64_ARRAY_V(msr, CPUIA64State, IA64_MSR_COUNT, 6),
        VMSTATE_UINT64_ARRAY_V(pmc, CPUIA64State, IA64_PMC_COUNT, 6),
        VMSTATE_UINT64_ARRAY_V(pmd, CPUIA64State, IA64_PMD_COUNT, 6),
        VMSTATE_UINT64_ARRAY(itr, CPUIA64State, IA64_ITR_COUNT),
        VMSTATE_UINT64_ARRAY(dtr, CPUIA64State, IA64_DTR_COUNT),
        VMSTATE_UINT64(ip, CPUIA64State),
        VMSTATE_UINT64(psr, CPUIA64State),
        VMSTATE_UINT64(cfm, CPUIA64State),
        VMSTATE_BOOL_V(firmware_identity_tlb, CPUIA64State, 4),
        /* The typed-only cutover deliberately starts a new RSE wire schema. */
        VMSTATE_VSTRUCT_TEST(rse, CPUIA64State, ia64_env_uses_rse_v5, 0,
                             vmstate_rse, IA64RSEState, 5),
        VMSTATE_STRUCT(nat, CPUIA64State, 0, vmstate_nat, IA64NaTState),
        VMSTATE_VSTRUCT_TEST(interrupt, CPUIA64State,
                             ia64_env_uses_interrupt_v3, 0,
                             vmstate_interrupt, IA64InterruptState, 3),
        VMSTATE_STRUCT(memory, CPUIA64State, 0, vmstate_memory,
                       IA64MemorySkeletonState),
        VMSTATE_STRUCT(exception, CPUIA64State, 0, vmstate_exception,
                       IA64ExceptionRecord),
        VMSTATE_VSTRUCT_V(alat, CPUIA64State, 3, vmstate_alat,
                          IA64AlatState, 1),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription * const []) {
        &vmstate_instruction_group_state,
        &vmstate_issue_group_overlay,
        &vmstate_issue_group_fr_overlay,
        NULL
    },
};

static int ia64_cpu_post_load(void *opaque, int version_id)
{
    IA64CPU *cpu = opaque;

    if (version_id != 6) {
        error_report("unsupported IA-64 CPU VMState version %d", version_id);
        return -EINVAL;
    }
    if ((cpu->env.rse.dirty < 0 || cpu->env.rse.dirty_nat < 0) &&
        cpu->env.rse.bsp_load != cpu->env.rse.bspstore) {
        error_report("IA-64 migration stream has inconsistent BSPLOAD for "
                     "an incomplete RSE frame");
        return -EINVAL;
    }

    cpu->env.gr[0] = 0;
    cpu->env.pr |= 1;
    cpu->env.ri = ia64_psr_ri(cpu->env.psr);
    cpu->env.ri_dirty = false;
    tlb_flush(CPU(cpu));
    return 0;
}

static bool ia64_collection_state_needed(void *opaque)
{
    IA64CPU *cpu = opaque;

    return cpu->env.last_successful_bundle != 0 ||
           cpu->env.psr_ic_inflight;
}

static const VMStateDescription vmstate_ia64_collection_state = {
    .name = "cpu/ia64-collection-state",
    .version_id = 1,
    .minimum_version_id = 1,
    .needed = ia64_collection_state_needed,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT64(env.last_successful_bundle, IA64CPU),
        VMSTATE_BOOL(env.psr_ic_inflight, IA64CPU),
        VMSTATE_END_OF_LIST()
    },
};

static bool ia64_cpu_uses_env_v8(void *opaque, int version_id)
{
    (void)opaque;
    return version_id == 6;
}

const VMStateDescription vmstate_ia64_cpu = {
    .name = "cpu",
    .version_id = 6,
    .minimum_version_id = 6,
    .post_load = ia64_cpu_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_STRUCT(parent_obj, IA64CPU, 0, vmstate_cpu_common, CPUState),
        /* CPU v6 is the typed-only VMState boundary (env v8/RSE v5). */
        VMSTATE_VSTRUCT_TEST(env, IA64CPU, ia64_cpu_uses_env_v8, 0,
                             vmstate_env, CPUIA64State, 8),
        VMSTATE_UINT64_V(env.rse.bsp_load, IA64CPU, 2),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription * const []) {
        &vmstate_ia64_collection_state,
        NULL
    },
};
