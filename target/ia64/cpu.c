/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "qemu/qemu-print.h"
#include "qemu/timer.h"
#include "qapi/error.h"
#include "cpu.h"
#include "exception.h"
#include "flight-recorder.h"
#include "insn.h"
#include "mem.h"
#include "perf.h"
#include "accel/tcg/cpu-loop.h"
#include "exec/cputlb.h"
#include "exec/page-protection.h"
#include "exec/tb-flush.h"
#include "exec/translation-block.h"
#include "exec/target_page.h"
#include "gdbstub/helpers.h"
#include "hw/core/sysemu-cpu-ops.h"
#include "system/memory.h"
#include "accel/tcg/cpu-ops.h"
#include "tcg/debug-assert.h"

static void ia64_cpu_set_pc(CPUState *cs, vaddr value)
{
    IA64CPU *cpu = IA64_CPU(cs);

    cpu->env.ip = value;
}

static vaddr ia64_cpu_get_pc(CPUState *cs)
{
    IA64CPU *cpu = IA64_CPU(cs);

    return cpu->env.ip;
}

static void ia64_cpu_synchronize_from_tb(CPUState *cs,
                                         const TranslationBlock *tb)
{
    IA64CPU *cpu = IA64_CPU(cs);
    unsigned ri = ia64_tcg_tb_flags_ri(tb->flags);

    tcg_debug_assert(!tcg_cflags_has(cs, CF_PCREL));
    cpu->env.ip = tb->pc;
    ia64_env_set_psr(&cpu->env, ia64_psr_with_ri(cpu->env.psr, ri));
}

static void ia64_restore_state_to_opc(CPUState *cs,
                                      const TranslationBlock *tb,
                                      const uint64_t *data)
{
    IA64CPU *cpu = IA64_CPU(cs);
    unsigned ri = ia64_env_restore_ri(&cpu->env, data[1] & 3);

    cpu->env.ip = data[0];
    ia64_env_set_psr(&cpu->env, ia64_psr_with_ri(cpu->env.psr, ri));
}

static TCGTBCPUState ia64_get_tb_cpu_state(CPUState *cs)
{
    IA64CPU *cpu = IA64_CPU(cs);
    uint32_t flags = ia64_tcg_tb_flags_from_psr(ia64_env_psr(&cpu->env));

    if (cpu->benchmark_active) {
        flags |= IA64_TB_FLAG_BENCHMARK;
    }
    if (cpu->production_profile.collecting) {
        flags |= IA64_TB_FLAG_PROFILE;
    }

    return (TCGTBCPUState) {
        .pc = cpu->env.ip,
        .flags = flags,
    };
}

static void ia64_tb_lookup_stats(CPUState *cs, bool hit)
{
    (void)cs;

    IA64_PERF_INC(IA64_PERF_TB_LOOKUP);
    IA64_PERF_INC(hit ? IA64_PERF_TB_LOOKUP_HIT :
                        IA64_PERF_TB_LOOKUP_MISS);
}

static void ia64_tb_flush_stats(CPUState *cs)
{
    (void)cs;

    IA64_PERF_INC(IA64_PERF_TB_FLUSH);
}

static void ia64_tb_invalidate_stats(CPUState *cs)
{
    (void)cs;

    IA64_PERF_INC(IA64_PERF_TB_INVALIDATED);
}

static bool ia64_cpu_has_work(CPUState *cs)
{
    IA64CPU *cpu = IA64_CPU(cs);

    return cpu_test_interrupt(cs, CPU_INTERRUPT_HARD) ||
           ia64_external_interrupt_enabled(&cpu->env);
}

static int ia64_cpu_mmu_index(CPUState *cs, bool ifetch)
{
    IA64CPU *cpu = IA64_CPU(cs);

    return ia64_tcg_mmu_index_for_psr(cpu->env.psr, ifetch);
}

static void ia64_count_data_tlb_region(CPUState *cs, hwaddr paddr, int size,
                                       MMUAccessType access_type)
{
    MemoryRegion *mr;
    hwaddr xlat = paddr;
    hwaddr len = MAX(size, 1);
    bool store = access_type == MMU_DATA_STORE;

    if (!ia64_perf_enabled() ||
        (access_type != MMU_DATA_LOAD && access_type != MMU_DATA_STORE)) {
        return;
    }

    mr = address_space_translate(cs->as, paddr, &xlat, &len, store,
                                 MEMTXATTRS_UNSPECIFIED);
    if (!memory_region_is_ram(mr) && !memory_region_is_romd(mr)) {
        IA64_PERF_INC(store ? IA64_PERF_LDST_MMIO_STORE :
                              IA64_PERF_LDST_MMIO_LOAD);
    }
}

static bool ia64_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
    IA64CPU *cpu = IA64_CPU(cs);
    CPUIA64State *env = &cpu->env;

    IA64_PERF_INC(IA64_PERF_INTERRUPT_EXEC_CHECK);
    /*
     * The CR.ITM deadline timer only raises CPU_INTERRUPT_HARD; the IRR
     * latch must happen here, on the vCPU thread, where guest interrupt
     * state can be touched safely.
     */
    if ((interrupt_request & CPU_INTERRUPT_HARD) != 0 &&
        ia64_itc_timer_poll(env)) {
        ia64_latch_timer_interrupt(env);
    }

    if ((interrupt_request & CPU_INTERRUPT_HARD) == 0 &&
        !ia64_external_interrupt_pending(env)) {
        return false;
    }

    if (!ia64_external_interrupt_pending(env)) {
        cpu_reset_interrupt(cs, CPU_INTERRUPT_HARD);
        return false;
    }

    if (!ia64_external_interrupt_enabled(env)) {
        IA64_PERF_INC(IA64_PERF_INTERRUPT_EXEC_PENDING_MASKED);
        return false;
    }

    cpu_reset_interrupt(cs, CPU_INTERRUPT_HARD);
    IA64_PERF_INC(IA64_PERF_INTERRUPT_DELIVERED);
    ia64_diag_record_external_interrupt(env, interrupt_request);
    ia64_deliver_exception(env, IA64_EXCEPTION_EXTERNAL_INTERRUPT, env->ip,
                           MMU_DATA_LOAD, "external interrupt");
    return true;
}

void ia64_cpu_dump_state(CPUState *cs, FILE *f, int flags)
{
    IA64CPU *cpu = IA64_CPU(cs);
    CPUIA64State *env = &cpu->env;

    qemu_fprintf(f, "IP  %016" PRIx64 "\n", env->ip);
    qemu_fprintf(f, "PSR %016" PRIx64 "  PR %016" PRIx64
                    "  CFM %016" PRIx64 "\n",
                 ia64_env_psr(env), env->pr, env->cfm);
    qemu_fprintf(f, "RSE RSC %016" PRIx64 "  BSP %016" PRIx64
                    "  BSPSTORE %016" PRIx64 "  BSPLOAD %016" PRIx64
                    "  RNAT %016" PRIx64
                    "  BASE %u\n",
                 env->rse.rsc, env->rse.bsp, env->rse.bspstore,
                 env->rse.bsp_load, env->rse.rnat,
                 env->rse.current_frame_base);
    qemu_fprintf(f, "NaT %016" PRIx64 ":%016" PRIx64
                    "  UNAT %016" PRIx64 "  RNAT %016" PRIx64 "\n",
                 env->nat.gr_nat[1], env->nat.gr_nat[0],
                 env->nat.unat, env->nat.rnat);
    qemu_fprintf(f, "CR.IVA %016" PRIx64 "  CR.IIP %016" PRIx64
                    "  CR.ISR %016" PRIx64 "  CR.IFA %016" PRIx64 "\n",
                 env->cr[IA64_CR_IVA], env->cr[IA64_CR_IIP],
                 env->cr[IA64_CR_ISR], env->cr[IA64_CR_IFA]);

    for (int i = 0; i < IA64_GR_COUNT; i++) {
        qemu_fprintf(f, "r%-2d %016" PRIx64 "%s",
                     i, ia64_read_gr(env, i), (i % 2) ? "\n" : "  ");
    }

    for (int i = 0; i < IA64_BR_COUNT; i++) {
        qemu_fprintf(f, "b%-2d %016" PRIx64 "%s",
                     i, env->br[i], (i % 2) ? "\n" : "  ");
    }
}

hwaddr ia64_cpu_get_phys_addr_debug(CPUState *cs, vaddr addr)
{
    IA64CPU *cpu = IA64_CPU(cs);
    IA64TranslateResult result;

    if (!ia64_translate_address(&cpu->env, addr, MMU_DATA_LOAD,
                                ia64_cpu_mmu_index(cs, false), true,
                                &result)) {
        return -1;
    }

    return result.paddr;
}

bool ia64_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                       MMUAccessType access_type, int mmu_idx,
                       bool probe, uintptr_t retaddr)
{
    IA64CPU *cpu = IA64_CPU(cs);
    IA64TranslateResult result;
    IA64VHPTWalkStatus vhpt_status = IA64_VHPT_WALK_MISS;
    IA64ExceptionKind exception_kind = IA64_EXCEPTION_NONE;

    IA64_PERF_INC(IA64_PERF_QEMU_TLB_FILL);
    switch (access_type) {
    case MMU_INST_FETCH:
        IA64_PERF_INC(IA64_PERF_QEMU_TLB_FILL_INST);
        break;
    case MMU_DATA_LOAD:
        IA64_PERF_INC(IA64_PERF_QEMU_TLB_FILL_LOAD);
        break;
    case MMU_DATA_STORE:
        IA64_PERF_INC(IA64_PERF_QEMU_TLB_FILL_STORE);
        break;
    default:
        break;
    }

    if (!ia64_translate_address_no_detail(&cpu->env, address, access_type,
                                          mmu_idx, false, &result) &&
        !probe && result.status == IA64_TRANSLATE_TLB_MISS) {
        if (!ia64_firmware_identity_tlb_fill(&cpu->env, address, access_type,
                                             mmu_idx, &result) &&
            ia64_vhpt_walk_runtime_enabled()) {
            vhpt_status = ia64_try_vhpt_walk(&cpu->env, cs->as, address,
                                             access_type);
            if (vhpt_status == IA64_VHPT_WALK_INSTALLED) {
                ia64_translate_address_no_detail(&cpu->env, address,
                                                 access_type, mmu_idx, false,
                                                 &result);
            } else if (vhpt_status == IA64_VHPT_WALK_FAULT) {
                exception_kind = IA64_EXCEPTION_VHPT_TRANSLATION;
            }
        }
    }

    if (result.status == IA64_TRANSLATE_OK) {
        /*
         * QEMU's softmmu TLB maps one TARGET_PAGE_SIZE page per fill.  IA-64
         * page size remains part of the target-side lookup; split it here so
         * region-tagged large virtual pages do not leak into QEMU's dirty
         * RAM bookkeeping.
         */
        tlb_set_page(cs, address & TARGET_PAGE_MASK,
                     result.paddr & TARGET_PAGE_MASK, result.prot, mmu_idx,
                     TARGET_PAGE_SIZE);
        ia64_count_data_tlb_region(cs, result.paddr, size, access_type);
        IA64_PERF_INC(IA64_PERF_QEMU_TLB_FILL_SUCCESS);
        return true;
    }

    if (probe) {
        IA64_PERF_INC(IA64_PERF_QEMU_TLB_FILL_PROBE_FAIL);
        return false;
    }

    cpu_restore_state(cs, retaddr);
    IA64_PERF_INC(IA64_PERF_QEMU_TLB_FILL_EXCEPTION);
    if (access_type == MMU_DATA_LOAD) {
        IA64_PERF_INC(IA64_PERF_QEMU_TLB_FILL_EXCEPTION_LOAD);
        IA64_PERF_INC(IA64_PERF_LDST_LOAD_FAULT);
    } else if (access_type == MMU_DATA_STORE) {
        IA64_PERF_INC(IA64_PERF_QEMU_TLB_FILL_EXCEPTION_STORE);
        IA64_PERF_INC(IA64_PERF_LDST_STORE_FAULT);
    } else if (access_type == MMU_INST_FETCH) {
        IA64_PERF_INC(IA64_PERF_QEMU_TLB_FILL_EXCEPTION_INST);
    }

    if (exception_kind == IA64_EXCEPTION_NONE) {
        exception_kind = ia64_exception_for_translate_result(&result);
    }
    ia64_deliver_exception_fast(&cpu->env, exception_kind, address,
                                access_type, NULL);
    IA64_PERF_INC(IA64_PERF_CPU_LOOP_EXIT);
    cpu->env.fault_exit_pending_tb_translate = true;
    cpu_loop_exit(cs);
    return true;
}

int ia64_cpu_gdb_read_register(CPUState *cs, GByteArray *mem_buf, int n)
{
    IA64CPU *cpu = IA64_CPU(cs);
    CPUIA64State *env = &cpu->env;

    if (n == 0) {
        return gdb_get_reg64(mem_buf, 0);
    }

    if (n < IA64_GR_COUNT) {
        return gdb_get_reg64(mem_buf, ia64_read_gr(env, n));
    }

    switch (n) {
    case 128:
        return gdb_get_reg64(mem_buf, env->ip);
    case 129:
        return gdb_get_reg64(mem_buf, ia64_env_psr(env));
    case 130:
        return gdb_get_reg64(mem_buf, env->pr);
    default:
        return 0;
    }
}

int ia64_cpu_gdb_write_register(CPUState *cs, uint8_t *mem_buf, int n)
{
    IA64CPU *cpu = IA64_CPU(cs);
    CPUIA64State *env = &cpu->env;

    if (n == 0) {
        return 8;
    }

    if (n < IA64_GR_COUNT) {
        ia64_write_gr(env, n, ldq_le_p(mem_buf));
        return 8;
    }

    switch (n) {
    case 128:
        env->ip = ldq_le_p(mem_buf);
        return 8;
    case 129:
        ia64_env_set_psr(env, ldq_le_p(mem_buf));
        return 8;
    case 130:
        env->pr = ldq_le_p(mem_buf);
        return 8;
    default:
        return 0;
    }
}

static void ia64_cpu_reset_hold(Object *obj, ResetType type)
{
    CPUState *cs = CPU(obj);
    IA64CPUClass *mcc = IA64_CPU_GET_CLASS(obj);
    IA64CPU *cpu = IA64_CPU(cs);

    if (mcc->parent_phases.hold) {
        mcc->parent_phases.hold(obj, type);
    }

    switch (cpu->model) {
    case IA64_CPU_MODEL_ITANIUM2:
        ia64_cpu_reset_synthetic_itanium2(&cpu->env);
        break;
    default:
        g_assert_not_reached();
    }

    /*
     * The synthetic reset clears itc_clock_backed; re-attach AR.ITC to the
     * virtual clock and restart guest time from zero.
     */
    cpu->env.itc_clock_backed = cpu->env.itm_timer != NULL;
    ia64_itc_set(&cpu->env, 0);
    ia64_itc_timer_update(&cpu->env);
}

static ObjectClass *ia64_cpu_class_by_name(const char *cpu_model)
{
    ObjectClass *oc;
    char *typename;

    oc = object_class_by_name(cpu_model);
    if (oc && object_class_dynamic_cast(oc, TYPE_IA64_CPU)) {
        return oc;
    }

    typename = g_strdup_printf(IA64_CPU_TYPE_NAME("%s"), cpu_model);
    oc = object_class_by_name(typename);
    g_free(typename);

    if (oc && object_class_dynamic_cast(oc, TYPE_IA64_CPU)) {
        return oc;
    }

    return NULL;
}

static void ia64_itm_timer_cb(void *opaque)
{
    IA64CPU *cpu = opaque;

    /*
     * Runs on the main loop thread; only kick the vCPU.  The
     * cpu_exec_interrupt hook polls the ITC/ITM compare and latches the
     * timer interrupt on the vCPU thread.
     */
    cpu_interrupt(CPU(cpu), CPU_INTERRUPT_HARD);
}

static void ia64_cpu_realizefn(DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    IA64CPU *cpu = IA64_CPU(dev);
    IA64CPUClass *mcc = IA64_CPU_GET_CLASS(dev);
    Error *local_err = NULL;

    cpu_exec_realizefn(cs, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return;
    }

    cpu->env.itm_timer = timer_new_ns(QEMU_CLOCK_VIRTUAL, ia64_itm_timer_cb,
                                      cpu);

    qemu_init_vcpu(cs);
    cpu_reset(cs);

    mcc->parent_realize(dev, errp);
}

static const gchar *ia64_gdb_arch_name(CPUState *cs)
{
    return "ia64";
}

static const struct SysemuCPUOps ia64_sysemu_ops = {
    .has_work = ia64_cpu_has_work,
    .get_phys_addr_debug = ia64_cpu_get_phys_addr_debug,
};

#define IA64_TCG_OPS_COMMON \
    .initialize = ia64_translate_init, \
    .translate_code = ia64_translate_code, \
    .get_tb_cpu_state = ia64_get_tb_cpu_state, \
    .synchronize_from_tb = ia64_cpu_synchronize_from_tb, \
    .restore_state_to_opc = ia64_restore_state_to_opc, \
    .mmu_index = ia64_cpu_mmu_index, \
    .tlb_fill = ia64_cpu_tlb_fill, \
    .pointer_wrap = cpu_pointer_wrap_notreached, \
    .cpu_exec_interrupt = ia64_cpu_exec_interrupt, \
    .cpu_exec_halt = ia64_cpu_has_work, \
    .cpu_exec_reset = cpu_reset

static const TCGCPUOps ia64_tcg_ops = {
    IA64_TCG_OPS_COMMON,
};

static const TCGCPUOps ia64_tcg_perf_ops = {
    IA64_TCG_OPS_COMMON,
    .tb_lookup_stats = ia64_tb_lookup_stats,
    .tb_flush_stats = ia64_tb_flush_stats,
    .tb_invalidate_stats = ia64_tb_invalidate_stats,
};

#undef IA64_TCG_OPS_COMMON

static const TCGCPUOps *ia64_tcg_ops_for_process(void)
{
    return ia64_perf_init_enabled() ? &ia64_tcg_perf_ops : &ia64_tcg_ops;
}

static void ia64_cpu_class_init(ObjectClass *oc, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(oc);
    CPUClass *cc = CPU_CLASS(oc);
    ResettableClass *rc = RESETTABLE_CLASS(oc);
    IA64CPUClass *mcc = IA64_CPU_CLASS(oc);

    device_class_set_parent_realize(dc, ia64_cpu_realizefn,
                                    &mcc->parent_realize);
    resettable_class_set_parent_phases(rc, NULL, ia64_cpu_reset_hold, NULL,
                                       &mcc->parent_phases);

    cc->class_by_name = ia64_cpu_class_by_name;
    cc->dump_state = ia64_cpu_dump_state;
    cc->set_pc = ia64_cpu_set_pc;
    cc->get_pc = ia64_cpu_get_pc;
    dc->vmsd = &vmstate_ia64_cpu;
    cc->sysemu_ops = &ia64_sysemu_ops;
    cc->gdb_read_register = ia64_cpu_gdb_read_register;
    cc->gdb_write_register = ia64_cpu_gdb_write_register;
    cc->gdb_num_core_regs = 131;
    cc->gdb_arch_name = ia64_gdb_arch_name;
    cc->tcg_ops = ia64_tcg_ops_for_process();
}

static void ia64_cpu_set_benchmark_on_cpu(CPUState *cs,
                                          run_on_cpu_data data)
{
    IA64CPU *cpu = IA64_CPU(cs);
    bool active = data.host_int != 0;

    if (active == cpu->benchmark_active) {
        return;
    }

    if (active) {
        cpu->benchmark_retired_bundles = 0;
        cpu->benchmark_elapsed_ns = 0;
        cpu->benchmark_host_cycles = 0;
        cpu->benchmark_active = true;
        tb_flush__exclusive_or_serial();
        cpu->benchmark_start_ns = qemu_clock_get_ns(QEMU_CLOCK_REALTIME);
        cpu->benchmark_start_host_cycles = cpu_get_host_ticks();
        return;
    }

    cpu->benchmark_active = false;
    cpu->benchmark_elapsed_ns =
        qemu_clock_get_ns(QEMU_CLOCK_REALTIME) - cpu->benchmark_start_ns;
    cpu->benchmark_host_cycles =
        cpu_get_host_ticks() - cpu->benchmark_start_host_cycles;
    tb_flush__exclusive_or_serial();
}

static bool ia64_cpu_get_benchmark_active(Object *obj, Error **errp)
{
    (void)errp;
    return IA64_CPU(obj)->benchmark_active;
}

static void ia64_cpu_set_benchmark_active(Object *obj, bool active,
                                          Error **errp)
{
    IA64CPU *cpu = IA64_CPU(obj);
    CPUState *cs = CPU(obj);

    (void)errp;
    if (active == cpu->benchmark_requested) {
        return;
    }
    cpu->benchmark_requested = active;
    if (cs->created) {
        /*
         * Keep the main AioContext free while firmware storage helpers wait
         * for I/O dispatched to that context.  The exclusive callback flushes
         * and switches translation mode at the same vCPU safe point where it
         * records the benchmark timestamps.
         */
        async_safe_run_on_cpu(cs, ia64_cpu_set_benchmark_on_cpu,
                              RUN_ON_CPU_HOST_INT(active));
    } else {
        ia64_cpu_set_benchmark_on_cpu(cs, RUN_ON_CPU_HOST_INT(active));
    }
}

static bool ia64_cpu_get_production_profile_active(Object *obj,
                                                   Error **errp)
{
    (void)errp;
    return ia64_profile_get_active(IA64_CPU(obj));
}

static void ia64_cpu_set_production_profile_active(Object *obj, bool active,
                                                   Error **errp)
{
    IA64CPU *cpu = IA64_CPU(obj);

    (void)errp;
    if (cpu->production_profile.requested == active) {
        return;
    }
    cpu->production_profile.requested = active;
    ia64_profile_set_active(cpu, active);
}

static void ia64_cpu_initfn(Object *obj)
{
    IA64CPU *cpu = IA64_CPU(obj);

    ia64_profile_register_cpu(cpu);

    object_property_add_bool(obj, "x-production-profile-active",
                             ia64_cpu_get_production_profile_active,
                             ia64_cpu_set_production_profile_active);
    object_property_set_description(
        obj, "x-production-profile-active",
        "start/stop and reset IA-64 production-shape sampling");

    object_property_add_bool(obj, "x-benchmark-active",
                             ia64_cpu_get_benchmark_active,
                             ia64_cpu_set_benchmark_active);
    object_property_set_description(
        obj, "x-benchmark-active",
        "start/stop and reset the IA-64 retired-bundle benchmark");
    object_property_add_uint64_ptr(
        obj, "x-benchmark-retired-bundles",
        &cpu->benchmark_retired_bundles, OBJ_PROP_FLAG_READ);
    object_property_set_description(obj, "x-benchmark-retired-bundles",
                                    "retired bundles in the last benchmark");
    object_property_add_uint64_ptr(
        obj, "x-benchmark-elapsed-ns", &cpu->benchmark_elapsed_ns,
        OBJ_PROP_FLAG_READ);
    object_property_set_description(obj, "x-benchmark-elapsed-ns",
                                    "host monotonic nanoseconds benchmarked");
    object_property_add_uint64_ptr(
        obj, "x-benchmark-host-cycles", &cpu->benchmark_host_cycles,
        OBJ_PROP_FLAG_READ);
    object_property_set_description(obj, "x-benchmark-host-cycles",
                                    "host cycle-counter ticks benchmarked");
}

static void itanium2_cpu_initfn(Object *obj)
{
    IA64CPU *cpu = IA64_CPU(obj);

    cpu->model = IA64_CPU_MODEL_ITANIUM2;
}

static const TypeInfo ia64_cpu_type_infos[] = {
    {
        .name = TYPE_IA64_CPU,
        .parent = TYPE_CPU,
        .instance_size = sizeof(IA64CPU),
        .instance_init = ia64_cpu_initfn,
        .abstract = true,
        .class_size = sizeof(IA64CPUClass),
        .class_init = ia64_cpu_class_init,
    },
    {
        .name = TYPE_ITANIUM2_CPU,
        .parent = TYPE_IA64_CPU,
        .instance_init = itanium2_cpu_initfn,
    },
};

DEFINE_TYPES(ia64_cpu_type_infos)
