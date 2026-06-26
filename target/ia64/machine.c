/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "cpu.h"
#include "exec/cputlb.h"
#include "migration/vmstate.h"

static const VMStateDescription vmstate_float_reg = {
    .name = "float-reg",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT64_ARRAY(raw, IA64FloatReg, 2),
        VMSTATE_END_OF_LIST()
    }
};

static const VMStateDescription vmstate_rse = {
    .name = "rse",
    .version_id = 1,
    .minimum_version_id = 1,
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
        VMSTATE_STRUCT_ARRAY(itc, IA64MemorySkeletonState, IA64_TC_COUNT, 0,
                             vmstate_translation_entry, IA64TranslationEntry),
        VMSTATE_STRUCT_ARRAY(dtc, IA64MemorySkeletonState, IA64_TC_COUNT, 0,
                             vmstate_translation_entry, IA64TranslationEntry),
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

static const VMStateDescription vmstate_env = {
    .name = "env",
    .version_id = 1,
    .minimum_version_id = 1,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT64_ARRAY(gr, CPUIA64State, IA64_GR_COUNT),
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
        VMSTATE_STRUCT(rse, CPUIA64State, 0, vmstate_rse, IA64RSEState),
        VMSTATE_STRUCT(nat, CPUIA64State, 0, vmstate_nat, IA64NaTState),
        VMSTATE_STRUCT(interrupt, CPUIA64State, 0, vmstate_interrupt,
                       IA64InterruptState),
        VMSTATE_STRUCT(memory, CPUIA64State, 0, vmstate_memory,
                       IA64MemorySkeletonState),
        VMSTATE_STRUCT(exception, CPUIA64State, 0, vmstate_exception,
                       IA64ExceptionRecord),
        VMSTATE_END_OF_LIST()
    }
};

static int ia64_cpu_post_load(void *opaque, int version_id)
{
    IA64CPU *cpu = opaque;

    cpu->env.gr[0] = 0;
    cpu->env.pr |= 1;
    tlb_flush(CPU(cpu));
    return 0;
}

const VMStateDescription vmstate_ia64_cpu = {
    .name = "cpu",
    .version_id = 1,
    .minimum_version_id = 1,
    .post_load = ia64_cpu_post_load,
    .fields = (const VMStateField[]) {
        VMSTATE_STRUCT(parent_obj, IA64CPU, 0, vmstate_cpu_common, CPUState),
        VMSTATE_STRUCT(env, IA64CPU, 0, vmstate_env, CPUIA64State),
        VMSTATE_END_OF_LIST()
    }
};
