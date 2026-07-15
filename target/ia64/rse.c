/* Included by interp.c. */

uint64_t ia64_rse_read_u64(CPUIA64State *env, vaddr address,
                           uintptr_t retaddr)
{
    uint64_t value;
    int mmu_idx = ia64_rse_mmu_index(ia64_env_psr(env), env->rse.rsc);

    env->rse.reference = true;
    if (env->rse.rsc & IA64_RSC_BE_BIT) {
        value = cpu_ldq_be_mmuidx_ra(env, address, mmu_idx, retaddr);
    } else {
        value = cpu_ldq_le_mmuidx_ra(env, address, mmu_idx, retaddr);
    }
    env->rse.reference = false;
    return value;
}

void ia64_rse_write_u64(CPUIA64State *env, vaddr address, uint64_t value,
                        uintptr_t retaddr)
{
    int mmu_idx = ia64_rse_mmu_index(ia64_env_psr(env), env->rse.rsc);

    env->rse.reference = true;
    if (env->rse.rsc & IA64_RSC_BE_BIT) {
        cpu_stq_be_mmuidx_ra(env, address, value, mmu_idx, retaddr);
    } else {
        cpu_stq_le_mmuidx_ra(env, address, value, mmu_idx, retaddr);
    }
    env->rse.reference = false;
}

static void ia64_rse_write_backing_store_register(CPUIA64State *env,
                                                  uint64_t address,
                                                  uint64_t value,
                                                  void *opaque);

static void ia64_exec_flushrs(CPUIA64State *env)
{
    IA64_PERF_INC(IA64_PERF_OP_RSE_FLUSHRS);
    ia64_rse_sync_logical_out(env);
    while (env->rse.dirty + env->rse.dirty_nat > 0) {
        g_assert(ia64_rse_mandatory_store_step(
            env, ia64_rse_write_backing_store_register, NULL, NULL));
    }
}

static uint64_t ia64_rse_read_backing_store_register(CPUIA64State *env,
                                                     uint64_t address,
                                                     void *opaque)
{
    uint64_t value = ia64_rse_read_u64(env, address, GETPC());

    ia64_rse_shadow_check_fill(env, address, value);
    return value;
}

static void ia64_rse_write_backing_store_register(CPUIA64State *env,
                                                  uint64_t address,
                                                  uint64_t value,
                                                  void *opaque)
{
    ia64_rse_write_u64(env, address, value, GETPC());
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

static bool ia64_rse_read_mandatory_word(CPUIA64State *env,
                                         uint64_t address,
                                         uint64_t *value, void *opaque)
{
    /*
     * ra == 0 deliberately attributes a mandatory br.ret/rfi fill fault to
     * the already-committed target instruction.  reference remains set if
     * cpu_ldq exits through fault delivery, allowing ISR.rs/ir construction.
     */
    IA64_PERF_INC(IA64_PERF_LDST_READ);
    *value = ia64_rse_read_u64(env, address, 0);
    ia64_trace_ldst(env, "rse-load", address, 8, *value);
    ia64_rse_shadow_check_fill(env, address, *value);
    return true;
}

static void ia64_rse_complete_frame_loads(CPUIA64State *env)
{
    uint64_t old_bspstore = env->rse.bspstore;
    int32_t missing = -MIN(env->rse.dirty, 0);
    IA64RSEStepResult result;
    bool trace = ia64_rse_trace_enabled();

    IA64_PERF_INC(IA64_PERF_OP_RSE_FILL_RESTORED);
    if (env->rse.dirty >= 0 && env->rse.dirty_nat >= 0) {
        return;
    }

    result = ia64_rse_complete_mandatory_loads(
        env, ia64_rse_read_mandatory_word, NULL);
    g_assert(result == IA64_RSE_STEP_DONE);
    IA64_PERF_INC(IA64_PERF_OP_RSE_FILL_RESTORED_MEM);
    IA64_PERF_ADD(IA64_PERF_OP_RSE_FILL_RESTORED_REG, missing);

    if (trace) {
        fprintf(stderr,
                "[ia64-rse] ip=0x%016" PRIx64
                " fill-restored filled=%d"
                " bspstore=0x%016" PRIx64 "->0x%016" PRIx64
                " bsp=0x%016" PRIx64 "\n",
                env->ip, missing, old_bspstore, env->rse.bspstore,
                env->rse.bsp);
    }
}

static void ia64_rse_schedule_pending_fill(CPUIA64State *env, uint32_t count,
                                           uint64_t resume_ip)
{
    (void)count;
    if (env->rse.dirty >= 0 && env->rse.dirty_nat >= 0) {
        return;
    }
    env->rse.pending_fill_count = 1;
    env->rse.pending_fill_ip = resume_ip;
}

static void ia64_rse_complete_pending_fill(CPUIA64State *env)
{
    if (env->rse.pending_fill_count == 0) {
        return;
    }
    ia64_rse_complete_frame_loads(env);
    env->rse.pending_fill_count = 0;
    env->rse.pending_fill_ip = 0;
}

static void ia64_rse_loadrs_one_word(CPUIA64State *env)
{
    int64_t live_words = (int64_t)env->rse.clean + env->rse.clean_nat +
                         env->rse.dirty + env->rse.dirty_nat;
    uint64_t address = env->rse.bsp - (live_words + 1) * 8;
    uint64_t value;

    if (ia64_rse_address_is_rnat_slot(address)) {
        value = ia64_rse_read_backing_store_register(
            env, address, NULL) & IA64_RNAT_VALID_MASK;
        env->psr &= ~(IA64_PSR_DA_BIT | IA64_PSR_DD_BIT);
        env->rse.rnat = value;
        env->rse.dirty_nat++;
    } else {
        uint32_t physical;
        uint32_t storage;
        uint64_t bit;

        if (env->rse.dirty == IA64_RSE_PHYS_STACKED_REGS) {
            ia64_raise_illegal_operation(env);
        }
        value = ia64_rse_read_backing_store_register(env, address, NULL);
        env->psr &= ~(IA64_PSR_DA_BIT | IA64_PSR_DD_BIT);
        physical = ia64_rse_wrap_physical(
            (int32_t)env->rse.bol -
            (env->rse.clean + env->rse.dirty + 1));
        storage = ia64_rse_physical_to_storage(env, physical);
        bit = UINT64_C(1) << ia64_rse_nat_collection_bit(address);
        env->rse.stacked_gr[storage] = value;
        ia64_rse_write_physical_nat(env, storage,
                                    (env->rse.rnat & bit) != 0);
        env->rse.dirty++;
        env->rse.invalid--;
    }
    env->rse.bspstore = env->rse.bsp -
        ((int64_t)env->rse.dirty + env->rse.dirty_nat) * 8;
    env->rse.bsp_load = env->rse.bspstore;
    env->ar[IA64_AR_BSPSTORE] = env->rse.bspstore;
    ia64_rse_sync_rnat(env);
}

static void ia64_exec_loadrs(CPUIA64State *env)
{
    uint64_t bytes = ((env->rse.rsc >> 16) & 0x3fff) & ~7ULL;
    int32_t words = bytes >> 3;
    int32_t words_to_load;
    int32_t before = env->rse.dirty;

    IA64_PERF_INC(IA64_PERF_OP_RSE_LOADRS);
    ia64_rse_sync_logical_out(env);
    ia64_rse_check_partitions(env, "loadrs-entry");

    words_to_load = words - (env->rse.clean + env->rse.clean_nat +
                             env->rse.dirty + env->rse.dirty_nat);
    if (words_to_load >= 0) {
        env->rse.dirty += env->rse.clean;
        env->rse.dirty_nat += env->rse.clean_nat;
        env->rse.clean = 0;
        env->rse.clean_nat = 0;
        env->rse.bspstore = env->rse.bsp -
            ((int64_t)env->rse.dirty + env->rse.dirty_nat) * 8;
        while (words_to_load-- > 0) {
            ia64_rse_loadrs_one_word(env);
        }
    } else {
        uint64_t tear = env->rse.bsp - bytes;

        env->rse.dirty_nat = (int32_t)((int64_t)(env->rse.bsp >> 9) -
                                       (int64_t)(tear >> 9));
        env->rse.dirty = words - env->rse.dirty_nat;
        if (env->rse.dirty + env->rse.sof >
            IA64_RSE_PHYS_STACKED_REGS) {
            ia64_raise_illegal_operation(env);
        }
        env->rse.bspstore = env->rse.bsp -
            ((int64_t)env->rse.dirty + env->rse.dirty_nat) * 8;
        env->rse.clean = 0;
        env->rse.clean_nat = 0;
        env->rse.invalid = IA64_RSE_PHYS_STACKED_REGS -
                           env->rse.sof - env->rse.dirty;
    }

    env->rse.bsp_load = env->rse.bspstore;
    env->rse.clean_count = 0;
    env->ar[IA64_AR_BSPSTORE] = env->rse.bspstore;
    ia64_rse_clear_rnat(env);
    ia64_rse_check_partitions(env, "loadrs-exit");
    if (ia64_rse_trace_enabled()) {
        fprintf(stderr,
                "[ia64-rse] ip=0x%016" PRIx64
                " loadrs bytes=0x%016" PRIx64
                " dirty-before=%d dirty-after=%d"
                " bspstore=0x%016" PRIx64 " bsp=0x%016" PRIx64 "\n",
                env->ip, bytes, before, env->rse.dirty,
                env->rse.bspstore, env->rse.bsp);
    }
}
