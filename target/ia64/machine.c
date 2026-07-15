/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/cputlb.h"
#include "firmware.h"
#include "insn.h"
#include "mem.h"
#include "migration/vmstate.h"
#include "qemu/error-report.h"

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
    rse->pending_fill_count = 0;
    rse->pending_fill_ip = 0;
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
    if (version_id < 4) {
        uint32_t resident_dirty;
        uint32_t capacity;

        if (rse->sof > IA64_RSE_PHYSICAL_COUNT) {
            error_report("legacy IA-64 migration stream has SOF above 96");
            return -EINVAL;
        }
        capacity = IA64_RSE_PHYSICAL_COUNT - rse->sof;
        resident_dirty = MIN(ia64_vmstate_rse_num_regs(rse->bspstore,
                                                       rse->bsp),
                             capacity);
        rse->dirty = resident_dirty;
        rse->dirty_nat = ia64_vmstate_rse_nat_words(rse->bspstore,
                                                    rse->bsp);
        rse->clean = 0;
        rse->clean_nat = 0;
        rse->invalid = capacity - resident_dirty;
        rse->bol = resident_dirty % IA64_RSE_PHYSICAL_COUNT;
        rse->cfle = false;
        /* v3's pre-probe continuation has no authority in the new model. */
        rse->pending_fill_count = 0;
        rse->pending_fill_ip = 0;
    } else if (rse->cfle || rse->pending_fill_count != 0 ||
               rse->pending_fill_ip != 0) {
        error_report("IA-64 migration stream contains an in-flight RSE "
                     "completion mechanism");
        return -EINVAL;
    }

    return ia64_validate_rse_vmstate(rse);
}

static const VMStateDescription vmstate_rse = {
    .name = "rse",
    .version_id = 4,
    .minimum_version_id = 1,
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
        VMSTATE_UINT32_V(pending_fill_count, IA64RSEState, 3),
        VMSTATE_UINT64_V(pending_fill_ip, IA64RSEState, 3),
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

static const VMStateDescription vmstate_alat = {
    .name = "alat",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_STRUCT_ARRAY(entries, IA64AlatState, IA64_ALAT_COUNT, 0,
                             vmstate_alat_entry, IA64AlatEntry),
        VMSTATE_UINT8(next, IA64AlatState),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_interrupt = {
    .name = "interrupt",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT64(pending_interruption, IA64InterruptState),
        VMSTATE_UINT64(pending_vector, IA64InterruptState),
        VMSTATE_UINT8(pending, IA64InterruptState),
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
    if (env->rse.cfle || env->rse.reference) {
        error_report("IA-64 migration reached the middle of a mandatory "
                     "RSE memory reference");
        return -EINVAL;
    }
    if (env->rse.pending_fill_count != 0 || env->rse.pending_fill_ip != 0) {
        error_report("IA-64 migration reached a legacy pending RSE fill");
        return -EINVAL;
    }
    ret = ia64_validate_rse_vmstate(&env->rse);
    if (ret < 0) {
        return ret;
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
    env->current_slot_ip = 0;
    env->current_slot_raw = 0;
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

    return env->issue_group.saved_gr_mask[0] != 0 ||
           env->issue_group.saved_gr_mask[1] != 0 ||
           env->issue_group.saved_br_mask != 0 ||
           env->issue_group.branch_br_forward_mask != 0 ||
           env->issue_group.pr_saved ||
           env->issue_group.branch_pr_forward_mask != 0 ||
           env->issue_group.pfs_saved ||
           env->issue_group.branch_pfs_forwarded ||
           env->issue_group.typed_active;
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
    return 0;
}

static const VMStateDescription vmstate_issue_group_overlay = {
    .name = "env/issue-group-overlay",
    .version_id = 5,
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
        VMSTATE_END_OF_LIST()
    },
};

static int ia64_validate_issue_group_overlay(CPUIA64State *env)
{
    uint64_t mask[2] = {
        env->issue_group.saved_gr_mask[0],
        env->issue_group.saved_gr_mask[1],
    };

    if (env->instruction_group_start &&
        ia64_issue_group_overlay_needed(env)) {
        error_report("IA-64 migration stream has an ordinary-source overlay "
                     "at a fresh visibility frontier");
        return -EINVAL;
    }
    if (!env->issue_group.typed_active &&
        (mask[0] != 0 || mask[1] != 0 || env->issue_group.pr_saved ||
         env->issue_group.branch_pr_forward_mask != 0 ||
         env->issue_group.saved_br_mask != 0 ||
         env->issue_group.branch_br_forward_mask != 0 ||
         env->issue_group.pfs_saved ||
         env->issue_group.branch_pfs_forwarded)) {
        error_report("IA-64 migration stream has saved ordinary sources "
                     "or explicit forwarding without a typed epoch owner");
        return -EINVAL;
    }
    if (mask[0] & 1) {
        error_report("IA-64 migration stream marks immutable GR0 as saved");
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
    int ret;

    ret = ia64_validate_issue_group_overlay(env);
    if (ret < 0) {
        return ret;
    }

    if (version_id < 2 && (env->psr & IA64_PSR_BN_BIT)) {
        memcpy(env->banked_gr, &env->gr[16], sizeof(env->banked_gr));
    }
    if (version_id < 3) {
        memset(&env->alat, 0, sizeof(env->alat));
    }
    if (version_id < 4) {
        env->firmware_identity_tlb = false;
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
    env->interrupt.timer_compare_latched = 0;
    /*
     * Guest time continues from the serialized ITC value; re-derive the
     * clock offset and re-arm the CR.ITM deadline for the new clock.
     */
    ia64_itc_set(env, env->ar[IA64_AR_ITC]);
    ia64_itc_timer_update(env);
    ia64_reconcile_interrupt_state(env);
    env->gr[0] = 0;
    env->pr |= 1;
    env->ri = ia64_psr_ri(env->psr);
    env->ri_dirty = false;
    env->instruction_group_dirty = false;
    env->fault_exit_pending_tb_translate = false;
    ia64_firmware_recover_post_load(env->ip);
    return 0;
}

static bool ia64_env_uses_rse_v1(void *opaque, int version_id)
{
    (void)opaque;
    return version_id <= 3;
}

static bool ia64_env_uses_rse_v3(void *opaque, int version_id)
{
    (void)opaque;
    return version_id == 4;
}

static bool ia64_env_uses_rse_v4(void *opaque, int version_id)
{
    (void)opaque;
    return version_id >= 5;
}

static const VMStateDescription vmstate_env = {
    .name = "env",
    .version_id = 5,
    .minimum_version_id = 1,
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
        VMSTATE_UINT64_ARRAY(itr, CPUIA64State, IA64_ITR_COUNT),
        VMSTATE_UINT64_ARRAY(dtr, CPUIA64State, IA64_DTR_COUNT),
        VMSTATE_UINT64(ip, CPUIA64State),
        VMSTATE_UINT64(psr, CPUIA64State),
        VMSTATE_UINT64(cfm, CPUIA64State),
        VMSTATE_BOOL_V(firmware_identity_tlb, CPUIA64State, 4),
        /*
         * RSE used to be embedded with VMSTATE_STRUCT, which does not put a
         * nested version on the wire.  Pin each outer env generation to one
         * exact RSE schema so CPU v3/env v5 and every future stream are
         * unambiguous.  Env v1-v3 all predate stacked-NaT/RSE-continuation
         * fields and therefore select RSE v1.  Env v4 selects the latest RSE
         * v3 layout produced before this fix.  Historical env-v4 payloads
         * also exist with RSE v1 and v2, but share the same outer version and
         * are consequently impossible to distinguish from v3 on the wire.
         */
        VMSTATE_VSTRUCT_TEST(rse, CPUIA64State, ia64_env_uses_rse_v1, 0,
                             vmstate_rse, IA64RSEState, 1),
        VMSTATE_VSTRUCT_TEST(rse, CPUIA64State, ia64_env_uses_rse_v3, 0,
                             vmstate_rse, IA64RSEState, 3),
        VMSTATE_VSTRUCT_TEST(rse, CPUIA64State, ia64_env_uses_rse_v4, 0,
                             vmstate_rse, IA64RSEState, 4),
        VMSTATE_STRUCT(nat, CPUIA64State, 0, vmstate_nat, IA64NaTState),
        VMSTATE_STRUCT(interrupt, CPUIA64State, 0, vmstate_interrupt,
                       IA64InterruptState),
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
        NULL
    },
};

static int ia64_cpu_post_load(void *opaque, int version_id)
{
    IA64CPU *cpu = opaque;

    if (version_id >= 3 &&
        (cpu->env.rse.dirty < 0 || cpu->env.rse.dirty_nat < 0) &&
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

static bool ia64_cpu_uses_env_v3(void *opaque, int version_id)
{
    (void)opaque;
    return version_id == 1;
}

static bool ia64_cpu_uses_env_v4(void *opaque, int version_id)
{
    (void)opaque;
    return version_id == 2;
}

static bool ia64_cpu_uses_env_v5(void *opaque, int version_id)
{
    (void)opaque;
    return version_id >= 3;
}

const VMStateDescription vmstate_ia64_cpu = {
    .name = "cpu",
    .version_id = 3,
    .minimum_version_id = 1,
    .post_load = ia64_cpu_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_STRUCT(parent_obj, IA64CPU, 0, vmstate_cpu_common, CPUState),
        /*
         * CPU v1 and v2 likewise embedded a moving env descriptor without a
         * nested version.  Select the latest layout that is distinguishable
         * at each outer boundary: v1 -> env v3/RSE v1, v2 -> env v4/RSE v3.
         * CPU v3 is the first fully versioned chain: env v5/RSE v4.
         */
        VMSTATE_VSTRUCT_TEST(env, IA64CPU, ia64_cpu_uses_env_v3, 0,
                             vmstate_env, CPUIA64State, 3),
        VMSTATE_VSTRUCT_TEST(env, IA64CPU, ia64_cpu_uses_env_v4, 0,
                             vmstate_env, CPUIA64State, 4),
        VMSTATE_VSTRUCT_TEST(env, IA64CPU, ia64_cpu_uses_env_v5, 0,
                             vmstate_env, CPUIA64State, 5),
        VMSTATE_UINT64_V(env.rse.bsp_load, IA64CPU, 2),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription * const []) {
        &vmstate_ia64_collection_state,
        NULL
    },
};
