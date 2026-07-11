/* Included by interp.c. */

static void ia64_exec_flushrs(CPUIA64State *env)
{
    uint32_t dirty = ia64_rse_num_regs(env->rse.bspstore, env->rse.bsp);
    uint32_t first_slot;
    uint64_t address = env->rse.bspstore;

    IA64_PERF_INC(IA64_PERF_OP_RSE_FLUSHRS);
    if (dirty == 0 || env->rse.bspstore == 0) {
        env->rse.bsp_load = env->rse.bspstore;
        env->rse.clean_count = MIN(env->rse.clean_count,
                                   env->rse.current_frame_base);
        return;
    }

    first_slot = ia64_rse_dirty_partition_first_slot(env, dirty);
    for (uint32_t i = 0; i < dirty;) {
        uint32_t slot;
        uint64_t value;

        if (ia64_rse_address_is_rnat_slot(address)) {
            ia64_ldst_write(env, address, 8, env->rse.rnat);
            ia64_rse_shadow_note_spill(address, env->rse.rnat);
            ia64_rse_clear_rnat(env);
            address += 8;
            continue;
        }

        slot = ia64_rse_wrap_slot(first_slot + i);
        value = env->rse.stacked_gr[slot];
        if (ia64_rse_read_physical_nat(env, slot)) {
            env->rse.rnat |=
                UINT64_C(1) << ia64_rse_nat_collection_bit(address);
        } else {
            env->rse.rnat &=
                ~(UINT64_C(1) << ia64_rse_nat_collection_bit(address));
        }
        ia64_rse_sync_rnat(env);
        ia64_ldst_write(env, address, 8, value);
        ia64_rse_shadow_note_spill(address, value);
        address += 8;
        i++;
    }

    env->rse.bspstore = address;
    env->rse.bsp = address;
    env->rse.bsp_load = address;
    env->rse.clean_count = env->rse.current_frame_base;
    env->ar[IA64_AR_BSPSTORE] = address;
    env->ar[IA64_AR_BSP] = address;
}

static uint64_t ia64_rse_read_backing_store_register(CPUIA64State *env,
                                                     uint64_t address,
                                                     void *opaque)
{
    uint64_t value = ia64_ldst_read(env, address, 8);

    ia64_rse_shadow_check_fill(env, address, value);
    return value;
}

static void ia64_rse_write_backing_store_register(CPUIA64State *env,
                                                  uint64_t address,
                                                  uint64_t value,
                                                  void *opaque)
{
    ia64_ldst_write(env, address, 8, value);
    ia64_rse_shadow_note_spill(address, value);
}

static bool ia64_rse_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_RSE_TRACE") != NULL;
    }
    return enabled != 0;
}

/*
 * Enforce the physical stacked register file bound before alloc grows the
 * current frame: spill the oldest dirty registers to the backing store so
 * that dirty + sof never exceeds IA64_RSE_PHYS_STACKED_REGS, exactly like
 * hardware's mandatory RSE stores.  See ia64_rse_spill_excess_dirty for why
 * guests break without this.
 */
static void ia64_rse_spill_for_alloc(CPUIA64State *env, uint64_t raw)
{
    uint32_t new_sof = (raw >> 13) & 0x7f;
    uint64_t old_bspstore = env->rse.bspstore;
    uint32_t spilled;

    spilled = ia64_rse_spill_excess_dirty(
        env, new_sof, ia64_rse_write_backing_store_register, NULL);
    if (spilled == 0) {
        return;
    }
    IA64_PERF_INC(IA64_PERF_OP_RSE_ALLOC_SPILL);
    IA64_PERF_ADD(IA64_PERF_OP_RSE_ALLOC_SPILL_REG, spilled);
    if (ia64_rse_trace_enabled()) {
        fprintf(stderr,
                "[ia64-rse] ip=0x%016" PRIx64
                " alloc-spill sof=%u spilled=%u"
                " bspstore=0x%016" PRIx64 "->0x%016" PRIx64
                " bsp=0x%016" PRIx64 "\n",
                env->ip, new_sof, spilled, old_bspstore,
                env->rse.bspstore, env->rse.bsp);
    }
}

static void ia64_exec_alloc_with_spill(CPUIA64State *env, uint64_t raw)
{
    ia64_rse_spill_for_alloc(env, raw);
    ia64_exec_m34_alloc(env, raw);
}

static void ia64_rse_sync_ar_after_fill(CPUIA64State *env)
{
    env->ar[IA64_AR_BSP] = env->rse.bsp;
    env->ar[IA64_AR_BSPSTORE] = env->rse.bspstore;
    ia64_rse_sync_rnat(env);
}

/*
 * Mandatory RSE fill after a frame is restored (br.ret, or rfi with a valid
 * CR.IFS).  Each register of the restored frame is either still resident in the
 * physical stacked register file ("dirty": its backing-store address is at or
 * above AR.BSPSTORE) or was already spilled to the backing store ("clean":
 * below AR.BSPSTORE).  Reload exactly the clean registers from memory and leave
 * the resident ones untouched.
 *
 * This per-register clean/dirty decision -- keyed off the architectural
 * AR.BSPSTORE boundary rather than a reconstructed scalar count -- is what makes
 * a context switch correct: switch_to flushes the outgoing task and repoints
 * AR.BSPSTORE/AR.RNAT at the incoming task's backing store, so the restored
 * frame's preserved registers come back from the new task's spilled image
 * instead of leaking stale physical-stack contents from the previous task (or
 * from an as-yet-unfilled brand-new thread).  Ordinary intra-task call/return
 * leaves AR.BSPSTORE far below the frame, so nothing is reloaded and the live
 * register file keeps being used.
 */
static void ia64_rse_fill_restored_frame(CPUIA64State *env, uint32_t count)
{
    uint64_t old_bspstore = env->rse.bspstore;
    uint64_t old_bsp_load = env->rse.bsp_load;
    uint32_t filled;
    bool trace = ia64_rse_trace_enabled();

    IA64_PERF_INC(IA64_PERF_OP_RSE_FILL_RESTORED);
    if (count == 0 || env->rse.bsp == 0) {
        return;
    }

    filled = ia64_rse_load_restored_frame(
        env, count, ia64_rse_read_backing_store_register, NULL);
    if (filled == 0) {
        return;
    }
    IA64_PERF_INC(IA64_PERF_OP_RSE_FILL_RESTORED_MEM);
    IA64_PERF_ADD(IA64_PERF_OP_RSE_FILL_RESTORED_REG, filled);

    ia64_rse_sync_ar_after_fill(env);

    if (trace) {
        fprintf(stderr,
                "[ia64-rse] ip=0x%016" PRIx64
                " fill-restored count=%u filled=%u"
                " bspstore=0x%016" PRIx64 "->0x%016" PRIx64
                " bspload=0x%016" PRIx64 "->0x%016" PRIx64
                " bsp=0x%016" PRIx64 "\n",
                env->ip, count, filled, old_bspstore, env->rse.bspstore,
                old_bsp_load, env->rse.bsp_load, env->rse.bsp);
    }
}

static void ia64_rse_maybe_fill_restored_frame(CPUIA64State *env,
                                               uint32_t count)
{
    uint64_t load_end = env->rse.bsp_load != 0 ? env->rse.bsp_load
                                               : env->rse.bspstore;

    if (count == 0 || env->rse.bsp == 0 || load_end <= env->rse.bsp) {
        return;
    }
    ia64_rse_fill_restored_frame(env, count);
}

/*
 * br.ret and rfi must be restartable.  The frame pop commits BSP, CFM and
 * the physical frame base before the mandatory RSE fill runs, and the fill
 * reads the backing store, which can fault (TLB miss or unmapped RBS page).
 * If the fault were raised from inside the fill, the guest kernel would
 * resolve it and re-execute the branch, popping the frame a second time and
 * reloading the restored frame from one frame lower in the backing store.
 * Probe the exact range the fill will read while the pre-branch state is
 * still intact, so any fault is delivered restart-clean.
 */
static void ia64_rse_probe_restored_frame_fill(CPUIA64State *env,
                                               uint32_t count)
{
    uint64_t frame_base;
    uint64_t frame_end;
    uint64_t load_end;
    uint64_t address;

    if (count == 0 || env->rse.bsp == 0) {
        return;
    }

    count = MIN(count, (uint32_t)IA64_STACKED_GR_COUNT);
    frame_base = ia64_rse_skip_regs(env->rse.bsp, -(int64_t)count);
    frame_end = env->rse.bsp;
    load_end = env->rse.bsp_load != 0 ? env->rse.bsp_load
                                      : env->rse.bspstore;
    if (load_end > frame_end) {
        load_end = frame_end;
    }

    address = ia64_rse_reg_address(frame_base);
    while (address < load_end) {
        IA64TranslateResult result;

        if (!ia64_translate_address(env, address, MMU_DATA_LOAD, 0, false,
                                    &result)) {
            ia64_exit_after_translation_fault(env, &result);
        }
        address = (address | ((UINT64_C(1) << TARGET_PAGE_BITS) - 1)) + 1;
    }
}

/*
 * RFI restores PSR before the RSE resumes filling clean registers.  Schedule
 * that work at the resumed bundle so a VHPT/page fault is collected with the
 * restored state and can restart the fill at the same bundle.  br.ret keeps
 * its pre-commit probe because it does not change the translation regime.
 */
static void ia64_rse_schedule_pending_fill(CPUIA64State *env, uint32_t count,
                                           uint64_t resume_ip)
{
    if (count == 0 || env->rse.bsp == 0) {
        return;
    }
    env->rse.pending_fill_count = count;
    env->rse.pending_fill_ip = resume_ip;
}

static void ia64_rse_complete_pending_fill(CPUIA64State *env)
{
    uint32_t count = env->rse.pending_fill_count;

    if (count == 0) {
        return;
    }
    ia64_rse_maybe_fill_restored_frame(env, count);
    env->rse.pending_fill_count = 0;
    env->rse.pending_fill_ip = 0;
}

static void ia64_exec_loadrs(CPUIA64State *env)
{
    uint64_t bytes = (env->rse.rsc >> 16) & 0x3fff;
    uint64_t end = env->rse.bsp;
    uint64_t start;
    uint32_t count;
    uint32_t before;

    IA64_PERF_INC(IA64_PERF_OP_RSE_LOADRS);
    if (end == 0 || end < bytes) {
        return;
    }

    start = end - bytes;
    count = ia64_rse_num_regs(start, end);
    before = ia64_rse_num_regs(env->rse.bspstore, env->rse.bsp);
    if (count != 0) {
        ia64_rse_load_dirty_partition(env, start, end,
                                      ia64_rse_read_backing_store_register,
                                      NULL);
    }
    ia64_rse_set_dirty_partition(env, start, end);
    ia64_rse_clear_rnat(env);
    if (ia64_rse_trace_enabled()) {
        fprintf(stderr,
                "[ia64-rse] ip=0x%016" PRIx64
                " loadrs bytes=0x%016" PRIx64 " count=%u"
                " dirty-before=%u bspstore=0x%016" PRIx64
                " bsp=0x%016" PRIx64 " start=0x%016" PRIx64
                " end=0x%016" PRIx64 "\n",
                env->ip, bytes, count, before, env->rse.bspstore,
                env->rse.bsp, start, end);
    }
}
