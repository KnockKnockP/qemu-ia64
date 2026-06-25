/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "qemu/qemu-print.h"
#include "qapi/error.h"
#include "cpu.h"
#include "exec/cputlb.h"
#include "exec/page-protection.h"
#include "exec/translation-block.h"
#include "exec/target_page.h"
#include "gdbstub/helpers.h"
#include "hw/core/sysemu-cpu-ops.h"
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

    tcg_debug_assert(!tcg_cflags_has(cs, CF_PCREL));
    cpu->env.ip = tb->pc;
}

static void ia64_restore_state_to_opc(CPUState *cs,
                                      const TranslationBlock *tb,
                                      const uint64_t *data)
{
    IA64CPU *cpu = IA64_CPU(cs);

    cpu->env.ip = data[0];
}

static TCGTBCPUState ia64_get_tb_cpu_state(CPUState *cs)
{
    IA64CPU *cpu = IA64_CPU(cs);

    return (TCGTBCPUState) {
        .pc = cpu->env.ip,
        .flags = 0,
    };
}

static bool ia64_cpu_has_work(CPUState *cs)
{
    return cpu_test_interrupt(cs, CPU_INTERRUPT_HARD);
}

static int ia64_cpu_mmu_index(CPUState *cs, bool ifetch)
{
    return 0;
}

static bool ia64_cpu_exec_interrupt(CPUState *cs, int interrupt_request)
{
    return false;
}

void ia64_cpu_dump_state(CPUState *cs, FILE *f, int flags)
{
    IA64CPU *cpu = IA64_CPU(cs);
    CPUIA64State *env = &cpu->env;

    qemu_fprintf(f, "IP  " TARGET_FMT_lx "\n", env->ip);
    qemu_fprintf(f, "PSR %016" PRIx64 "  PR %016" PRIx64
                    "  CFM %016" PRIx64 "\n",
                 env->psr, env->pr, env->cfm);

    for (int i = 0; i < 8; i++) {
        qemu_fprintf(f, "r%-2d %016" PRIx64 "%s",
                     i, env->gr[i], (i % 2) ? "\n" : "  ");
    }
}

hwaddr ia64_cpu_get_phys_addr_debug(CPUState *cs, vaddr addr)
{
    return addr;
}

bool ia64_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                       MMUAccessType access_type, int mmu_idx,
                       bool probe, uintptr_t retaddr)
{
    hwaddr page = address & TARGET_PAGE_MASK;

    tlb_set_page(cs, page, page, PAGE_READ | PAGE_WRITE | PAGE_EXEC,
                 mmu_idx, TARGET_PAGE_SIZE);
    return true;
}

int ia64_cpu_gdb_read_register(CPUState *cs, GByteArray *mem_buf, int n)
{
    IA64CPU *cpu = IA64_CPU(cs);
    CPUIA64State *env = &cpu->env;

    if (n < 128) {
        return gdb_get_reg64(mem_buf, env->gr[n]);
    }

    switch (n) {
    case 128:
        return gdb_get_reg64(mem_buf, env->ip);
    case 129:
        return gdb_get_reg64(mem_buf, env->psr);
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

    if (n < 128) {
        env->gr[n] = ldq_le_p(mem_buf);
        return 8;
    }

    switch (n) {
    case 128:
        env->ip = ldq_le_p(mem_buf);
        return 8;
    case 129:
        env->psr = ldq_le_p(mem_buf);
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
    CPUIA64State *env = &cpu->env;

    if (mcc->parent_phases.hold) {
        mcc->parent_phases.hold(obj, type);
    }

    memset(env, 0, offsetof(CPUIA64State, end_reset_fields));
    env->pr = 1;
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

static void ia64_cpu_realizefn(DeviceState *dev, Error **errp)
{
    CPUState *cs = CPU(dev);
    IA64CPUClass *mcc = IA64_CPU_GET_CLASS(dev);
    Error *local_err = NULL;

    cpu_exec_realizefn(cs, &local_err);
    if (local_err != NULL) {
        error_propagate(errp, local_err);
        return;
    }

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

static const TCGCPUOps ia64_tcg_ops = {
    .initialize = ia64_translate_init,
    .translate_code = ia64_translate_code,
    .get_tb_cpu_state = ia64_get_tb_cpu_state,
    .synchronize_from_tb = ia64_cpu_synchronize_from_tb,
    .restore_state_to_opc = ia64_restore_state_to_opc,
    .mmu_index = ia64_cpu_mmu_index,
    .tlb_fill = ia64_cpu_tlb_fill,
    .cpu_exec_interrupt = ia64_cpu_exec_interrupt,
    .cpu_exec_halt = ia64_cpu_has_work,
    .cpu_exec_reset = cpu_reset,
};

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
    cc->sysemu_ops = &ia64_sysemu_ops;
    cc->gdb_read_register = ia64_cpu_gdb_read_register;
    cc->gdb_write_register = ia64_cpu_gdb_write_register;
    cc->gdb_num_core_regs = 131;
    cc->gdb_arch_name = ia64_gdb_arch_name;
    cc->tcg_ops = &ia64_tcg_ops;
}

static void ia64_cpu_initfn(Object *obj)
{
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
    },
};

DEFINE_TYPES(ia64_cpu_type_infos)
