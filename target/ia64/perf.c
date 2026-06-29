/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "cpu.h"
#include "mem.h"
#include "perf.h"
#include "tcg-skeleton.h"

int ia64_perf_enabled_cached = -1;

static uint64_t ia64_perf_counters[IA64_PERF_COUNTER_COUNT];
static int64_t ia64_perf_start_us;
static bool ia64_perf_registered;

static const char * const ia64_perf_counter_names[IA64_PERF_COUNTER_COUNT] = {
    [IA64_PERF_TB_TRANSLATED] = "tb.translated",
    [IA64_PERF_TB_EXECUTED] = "tb.executed",
    [IA64_PERF_TB_LOOKUP] = "tb.lookup",
    [IA64_PERF_TB_LOOKUP_HIT] = "tb.lookup.hit",
    [IA64_PERF_TB_LOOKUP_MISS] = "tb.lookup.miss",
    [IA64_PERF_TB_INVALIDATED] = "tb.invalidated",
    [IA64_PERF_TB_FLUSH] = "tb.flush",
    [IA64_PERF_TB_TRANSLATED_AFTER_FAULT] = "tb.translated.after_fault",
    [IA64_PERF_TB_GENERATED_REGION0] = "tb.generated.region0",
    [IA64_PERF_TB_GENERATED_REGION1] = "tb.generated.region1",
    [IA64_PERF_TB_GENERATED_REGION2] = "tb.generated.region2",
    [IA64_PERF_TB_GENERATED_REGION3] = "tb.generated.region3",
    [IA64_PERF_TB_GENERATED_REGION4] = "tb.generated.region4",
    [IA64_PERF_TB_GENERATED_REGION5] = "tb.generated.region5",
    [IA64_PERF_TB_GENERATED_REGION6] = "tb.generated.region6",
    [IA64_PERF_TB_GENERATED_REGION7] = "tb.generated.region7",
    [IA64_PERF_TB_EXIT_FLOW_TRANSLATED] = "tb.exit.flow_translated",
    [IA64_PERF_BUNDLE_DECODED] = "bundle.decoded",
    [IA64_PERF_BUNDLE_DECODE_INVALID] = "bundle.decode_invalid",
    [IA64_PERF_BUNDLE_EXECUTED] = "bundle.executed",
    [IA64_PERF_HELPER_EXEC_BUNDLE] = "helper.exec_bundle",
    [IA64_PERF_HELPER_EFI_DISPATCH] = "helper.efi_dispatch",
    [IA64_PERF_TCG_FIRMWARE_CALL_GATE_FAST] =
        "tcg.firmware.call_gate_fast",
    [IA64_PERF_TCG_FIRMWARE_CALL_GATE_FALLBACK] =
        "tcg.firmware.call_gate_fallback",
    [IA64_PERF_TCG_FAST_BUNDLE] = "tcg.fast.bundle",
    [IA64_PERF_TCG_FAST_SLOT] = "tcg.fast.slot",
    [IA64_PERF_TCG_FAST_NOP] = "tcg.fast.nop",
    [IA64_PERF_TCG_FAST_ALU_ADD] = "tcg.fast.alu_add",
    [IA64_PERF_TCG_FAST_ALU_LOGIC] = "tcg.fast.alu_logic",
    [IA64_PERF_TCG_FAST_ADDL] = "tcg.fast.addl",
    [IA64_PERF_TCG_FAST_COMPARE] = "tcg.fast.compare",
    [IA64_PERF_TCG_FAST_INTEGER_MISC] = "tcg.fast.integer_misc",
    [IA64_PERF_TCG_LDST_LOAD] = "tcg.ldst.load",
    [IA64_PERF_TCG_LDST_STORE] = "tcg.ldst.store",
    [IA64_PERF_TCG_LDST_FALLBACK] = "tcg.ldst.fallback",
    [IA64_PERF_TCG_BRANCH_DIRECT_TRANSLATED] = "tcg.branch.direct_translated",
    [IA64_PERF_TCG_BRANCH_DIRECT_FALLBACK] = "tcg.branch.direct_fallback",
    [IA64_PERF_TCG_BRANCH_INDIRECT_FALLBACK] = "tcg.branch.indirect_fallback",
    [IA64_PERF_TCG_FALLBACK_INVALID_TEMPLATE] =
        "tcg.fallback.invalid_template",
    [IA64_PERF_TCG_FALLBACK_BOUNDARY_EFI_CALL_GATE] =
        "tcg.fallback.boundary.efi_call_gate",
    [IA64_PERF_TCG_FALLBACK_BOUNDARY_BREAK] =
        "tcg.fallback.boundary.break",
    [IA64_PERF_TCG_FALLBACK_BOUNDARY_SPECULATION_CHECK] =
        "tcg.fallback.boundary.speculation_check",
    [IA64_PERF_TCG_FALLBACK_BOUNDARY_VIRTUAL_TRANSLATION] =
        "tcg.fallback.boundary.virtual_translation",
    [IA64_PERF_TCG_FALLBACK_BOUNDARY_BRANCH] =
        "tcg.fallback.boundary.branch",
    [IA64_PERF_TCG_FALLBACK_BOUNDARY_CPU_STATE] =
        "tcg.fallback.boundary.cpu_state",
    [IA64_PERF_TCG_FALLBACK_BOUNDARY_TRANSLATION_STATE] =
        "tcg.fallback.boundary.translation_state",
    [IA64_PERF_TCG_FALLBACK_BOUNDARY_RSE_STATE] =
        "tcg.fallback.boundary.rse_state",
    [IA64_PERF_TCG_FALLBACK_FAST_LONG_IMMEDIATE] =
        "tcg.fallback.fast.long_immediate",
    [IA64_PERF_TCG_FALLBACK_FAST_PREDICATED_SLOT] =
        "tcg.fallback.fast.predicated_slot",
    [IA64_PERF_TCG_FALLBACK_FAST_STATIC_GR] =
        "tcg.fallback.fast.static_gr",
    [IA64_PERF_TCG_FALLBACK_FAST_LDST_SLOT] =
        "tcg.fallback.fast.ldst_slot",
    [IA64_PERF_TCG_FALLBACK_FAST_LDST_TRACE] =
        "tcg.fallback.fast.ldst_trace",
    [IA64_PERF_TCG_FALLBACK_FAST_LDST_REGISTER_UPDATE] =
        "tcg.fallback.fast.ldst_register_update",
    [IA64_PERF_TCG_FALLBACK_FAST_LDST_MEMORY_CLASS] =
        "tcg.fallback.fast.ldst_memory_class",
    [IA64_PERF_TCG_FALLBACK_FAST_LDST_TARGET] =
        "tcg.fallback.fast.ldst_target",
    [IA64_PERF_TCG_FALLBACK_FAST_UNSUPPORTED_SLOT] =
        "tcg.fallback.fast.unsupported_slot",
    [IA64_PERF_TCG_FALLBACK_RUNTIME_GUARD] =
        "tcg.fallback.runtime_guard",
    [IA64_PERF_TB_EXIT_DIRECT_BRANCH] = "tb.exit.direct_branch",
    [IA64_PERF_TB_EXIT_CHAINED] = "tb.exit.chained",
    [IA64_PERF_TB_EXIT_MAIN_LOOP] = "tb.exit.main_loop",
    [IA64_PERF_INTERP_SLOT_ITERATION] = "interp.slot.iteration",
    [IA64_PERF_INTERP_SLOT_EXECUTED] = "interp.slot.executed",
    [IA64_PERF_INTERP_LONG_IMMEDIATE] = "interp.slot.long_immediate",
    [IA64_PERF_INTERP_PREDICATED_FALSE] = "interp.slot.predicated_false",
    [IA64_PERF_INTERP_FALSE_PRED_SIDE_EFFECT] = "interp.slot.false_predicate_side_effect",
    [IA64_PERF_SLOT_TYPE_M] = "slot.type.m",
    [IA64_PERF_SLOT_TYPE_I] = "slot.type.i",
    [IA64_PERF_SLOT_TYPE_F] = "slot.type.f",
    [IA64_PERF_SLOT_TYPE_B] = "slot.type.b",
    [IA64_PERF_SLOT_TYPE_L] = "slot.type.l",
    [IA64_PERF_SLOT_TYPE_X] = "slot.type.x",
    [IA64_PERF_SLOT_TYPE_INVALID] = "slot.type.invalid",
    [IA64_PERF_OP_SMOKE] = "op.smoke_supported",
    [IA64_PERF_OP_NOP] = "op.nop",
    [IA64_PERF_OP_BREAK] = "op.break",
    [IA64_PERF_OP_ALLOC] = "op.alloc",
    [IA64_PERF_OP_MOV_IP] = "op.mov_ip",
    [IA64_PERF_OP_BRANCH_REGISTER] = "op.branch_register",
    [IA64_PERF_OP_PREDICATE_REGISTER] = "op.predicate_register",
    [IA64_PERF_OP_APPLICATION_REGISTER] = "op.application_register",
    [IA64_PERF_OP_SPECULATION_CHECK] = "op.speculation_check",
    [IA64_PERF_OP_PROCESSOR_MASK] = "op.processor_mask",
    [IA64_PERF_OP_PROCESSOR_STATUS] = "op.processor_status",
    [IA64_PERF_OP_REGION_REGISTER] = "op.region_register",
    [IA64_PERF_OP_CONTROL_REGISTER] = "op.control_register",
    [IA64_PERF_OP_PROCESSOR_ID] = "op.processor_id",
    [IA64_PERF_OP_INDEXED_SYSTEM_REGISTER] = "op.indexed_system_register",
    [IA64_PERF_OP_INSERT_TRANSLATION] = "op.insert_translation",
    [IA64_PERF_OP_PROBE_TRANSLATION] = "op.probe_translation",
    [IA64_PERF_OP_VIRTUAL_TRANSLATION] = "op.virtual_translation",
    [IA64_PERF_OP_PURGE_TRANSLATION] = "op.purge_translation",
    [IA64_PERF_OP_INVALA] = "op.invala",
    [IA64_PERF_OP_RSE_FLUSHRS] = "op.rse.flushrs",
    [IA64_PERF_OP_RSE_LOADRS] = "op.rse.loadrs",
    [IA64_PERF_OP_RSE_FILL_RESTORED] = "op.rse.fill_restored",
    [IA64_PERF_OP_RSE_FILL_RESTORED_MEM] = "op.rse.fill_restored.mem",
    [IA64_PERF_OP_RSE_FILL_RESTORED_REG] = "op.rse.fill_restored.reg",
    [IA64_PERF_OP_SYSTEM_NOOP] = "op.system_noop",
    [IA64_PERF_OP_SETF_GETF] = "op.setf_getf",
    [IA64_PERF_OP_ATOMIC] = "op.atomic",
    [IA64_PERF_OP_EXTRACT_DEPOSIT] = "op.extract_deposit",
    [IA64_PERF_OP_SHIFT_EXTEND] = "op.shift_extend",
    [IA64_PERF_OP_FLOAT] = "op.float",
    [IA64_PERF_OP_FLOAT_MEMORY] = "op.float_memory",
    [IA64_PERF_OP_LOAD] = "op.load",
    [IA64_PERF_OP_STORE] = "op.store",
    [IA64_PERF_OP_PREFETCH] = "op.prefetch",
    [IA64_PERF_OP_COMPARE] = "op.compare",
    [IA64_PERF_OP_PREDICATE_TEST] = "op.predicate_test",
    [IA64_PERF_OP_NAT_TEST] = "op.nat_test",
    [IA64_PERF_OP_ALU] = "op.alu",
    [IA64_PERF_OP_ADDL] = "op.addl",
    [IA64_PERF_OP_BRANCH_DIRECT] = "op.branch.direct",
    [IA64_PERF_OP_BRANCH_CALL] = "op.branch.call",
    [IA64_PERF_OP_BRANCH_INDIRECT] = "op.branch.indirect",
    [IA64_PERF_OP_BRANCH_PREDICT] = "op.branch.predict",
    [IA64_PERF_BRANCH_TAKEN] = "branch.taken",
    [IA64_PERF_BRANCH_FALLTHROUGH] = "branch.fallthrough",
    [IA64_PERF_COUNTED_STORE_LOOP] = "op.counted_store_loop",
    [IA64_PERF_LDST_READ] = "ldst.read_helper",
    [IA64_PERF_LDST_WRITE] = "ldst.write_helper",
    [IA64_PERF_LDST_UNALIGNED_READ] = "ldst.unaligned_read",
    [IA64_PERF_LDST_UNALIGNED_WRITE] = "ldst.unaligned_write",
    [IA64_PERF_LDST_MMIO_LOAD] = "ldst.mmio_load",
    [IA64_PERF_LDST_MMIO_STORE] = "ldst.mmio_store",
    [IA64_PERF_LDST_LOAD_FAULT] = "ldst.load_fault",
    [IA64_PERF_LDST_STORE_FAULT] = "ldst.store_fault",
    [IA64_PERF_LDST_TRACE_PADDR_PROBE] = "ldst.trace_paddr_probe",
    [IA64_PERF_ATOMIC_MEMORY_OP] = "ldst.atomic_memory_op",
    [IA64_PERF_ALAT_RESOLVE] = "alat.resolve",
    [IA64_PERF_ALAT_RECORD_LOAD] = "alat.record_load",
    [IA64_PERF_ALAT_INVALIDATE_STORE] = "alat.invalidate_store",
    [IA64_PERF_TARGET_TRANSLATE] = "mmu.target_translate",
    [IA64_PERF_TARGET_TRANSLATE_INST] = "mmu.target_translate.inst",
    [IA64_PERF_TARGET_TRANSLATE_LOAD] = "mmu.target_translate.load",
    [IA64_PERF_TARGET_TRANSLATE_STORE] = "mmu.target_translate.store",
    [IA64_PERF_TARGET_TRANSLATE_DEBUG] = "mmu.target_translate.debug",
    [IA64_PERF_TARGET_TRANSLATE_NO_DETAIL] = "mmu.target_translate.no_detail",
    [IA64_PERF_TARGET_TRANSLATE_PHYSICAL] = "mmu.target_translate.physical",
    [IA64_PERF_TARGET_TRANSLATE_LOOKUP] = "mmu.target_translate.lookup",
    [IA64_PERF_TARGET_TRANSLATE_OK] = "mmu.target_translate.ok",
    [IA64_PERF_TARGET_TRANSLATE_TLB_MISS] = "mmu.target_translate.tlb_miss",
    [IA64_PERF_TARGET_TRANSLATE_NOT_PRESENT] = "mmu.target_translate.not_present",
    [IA64_PERF_TARGET_TRANSLATE_ACCESS_DENIED] = "mmu.target_translate.access_denied",
    [IA64_PERF_TARGET_TRANSLATE_OTHER_FAIL] = "mmu.target_translate.other_fail",
    [IA64_PERF_TARGET_TRANSLATION_INSTALL] = "mmu.translation_install",
    [IA64_PERF_TARGET_TRANSLATION_INSTALL_INST] = "mmu.translation_install.inst",
    [IA64_PERF_TARGET_TRANSLATION_INSTALL_DATA] = "mmu.translation_install.data",
    [IA64_PERF_TARGET_TRANSLATION_PURGE_CACHE] = "mmu.translation_purge.cache",
    [IA64_PERF_TARGET_TRANSLATION_PURGE_REGISTER] = "mmu.translation_purge.register",
    [IA64_PERF_TARGET_TRANSLATION_PURGE_ALL] = "mmu.translation_purge.all",
    [IA64_PERF_QEMU_TLB_FILL] = "qemu_tlb.fill",
    [IA64_PERF_QEMU_TLB_FILL_INST] = "qemu_tlb.fill.inst",
    [IA64_PERF_QEMU_TLB_FILL_LOAD] = "qemu_tlb.fill.load",
    [IA64_PERF_QEMU_TLB_FILL_STORE] = "qemu_tlb.fill.store",
    [IA64_PERF_QEMU_TLB_FILL_SUCCESS] = "qemu_tlb.fill.success",
    [IA64_PERF_QEMU_TLB_FILL_PROBE_FAIL] = "qemu_tlb.fill.probe_fail",
    [IA64_PERF_QEMU_TLB_FILL_EXCEPTION] = "qemu_tlb.fill.exception",
    [IA64_PERF_QEMU_TLB_FILL_EXCEPTION_INST] = "qemu_tlb.fill.exception.inst",
    [IA64_PERF_QEMU_TLB_FILL_EXCEPTION_LOAD] = "qemu_tlb.fill.exception.load",
    [IA64_PERF_QEMU_TLB_FILL_EXCEPTION_STORE] = "qemu_tlb.fill.exception.store",
    [IA64_PERF_QEMU_TLB_FLUSH_FULL] = "qemu_tlb.flush.full",
    [IA64_PERF_QEMU_TLB_FLUSH_RANGE] = "qemu_tlb.flush.range",
    [IA64_PERF_CPU_LOOP_EXIT] = "cpu_loop.exit",
    [IA64_PERF_INTERRUPT_CHECK] = "interrupt.check",
    [IA64_PERF_INTERRUPT_TIMER_CHECK] = "interrupt.timer_check",
    [IA64_PERF_INTERRUPT_TIMER_FAST_NOT_DUE] = "interrupt.timer_fast_not_due",
    [IA64_PERF_INTERRUPT_TIMER_DUE] = "interrupt.timer_due",
    [IA64_PERF_INTERRUPT_TIMER_LATCHED] = "interrupt.timer_latched",
    [IA64_PERF_INTERRUPT_EXEC_CHECK] = "interrupt.exec_check",
    [IA64_PERF_INTERRUPT_EXEC_PENDING_MASKED] = "interrupt.exec_pending_masked",
    [IA64_PERF_INTERRUPT_UNMASK_PENDING] = "interrupt.unmask_pending",
    [IA64_PERF_INTERRUPT_DELIVERED] = "interrupt.delivered",
    [IA64_PERF_EXCEPTION_DELIVERED] = "exception.delivered",
    [IA64_PERF_EXCEPTION_TLB_MISS] = "exception.tlb_miss",
    [IA64_PERF_EXCEPTION_PAGE_FAULT] = "exception.page_fault",
    [IA64_PERF_EXCEPTION_BREAK] = "exception.break",
    [IA64_PERF_EXCEPTION_EXTERNAL_INTERRUPT] = "exception.external_interrupt",
    [IA64_PERF_EXCEPTION_OTHER] = "exception.other",
    [IA64_PERF_EXCEPTION_RECORD_FORMATTED] = "exception.record.formatted",
    [IA64_PERF_EXCEPTION_RECORD_FAST] = "exception.record.fast",
    [IA64_PERF_TRANSITION_BREAK] = "transition.break",
    [IA64_PERF_TRANSITION_BREAK_SYSCALL] = "transition.break.syscall",
    [IA64_PERF_TRANSITION_COVER] = "transition.cover",
    [IA64_PERF_TRANSITION_EPC] = "transition.epc",
    [IA64_PERF_TRANSITION_RFI] = "transition.rfi",
    [IA64_PERF_TRANSITION_RFI_VALID_IFS] = "transition.rfi.valid_ifs",
    [IA64_PERF_TRANSITION_RFI_TO_USER] = "transition.rfi.to_user",
    [IA64_PERF_TRANSITION_RFI_TO_KERNEL] = "transition.rfi.to_kernel",
    [IA64_PERF_TRANSITION_PRIVILEGE_CHANGE] = "transition.privilege_change",
    [IA64_PERF_TRANSITION_USER_TO_KERNEL] = "transition.user_to_kernel",
    [IA64_PERF_TRANSITION_KERNEL_TO_USER] = "transition.kernel_to_user",
    [IA64_PERF_TRANSITION_BANK_SWITCH] = "transition.bank_switch",
    [IA64_PERF_TRANSITION_BANK_SWITCH_TO_BANK0] = "transition.bank_switch.to_bank0",
    [IA64_PERF_TRANSITION_BANK_SWITCH_TO_BANK1] = "transition.bank_switch.to_bank1",
    [IA64_PERF_FIRMWARE_PAL] = "firmware.pal",
    [IA64_PERF_FIRMWARE_PAL_HALT] = "firmware.pal.halt",
    [IA64_PERF_FIRMWARE_PAL_HALT_LIGHT] = "firmware.pal.halt_light",
    [IA64_PERF_FIRMWARE_PAL_CACHE_MAINT] = "firmware.pal.cache_maint",
    [IA64_PERF_FIRMWARE_PAL_CACHE_INFO] = "firmware.pal.cache_info",
    [IA64_PERF_FIRMWARE_PAL_MEMORY_ATTRIBUTES] = "firmware.pal.memory_attributes",
    [IA64_PERF_FIRMWARE_PAL_PTCE_INFO] = "firmware.pal.ptce_info",
    [IA64_PERF_FIRMWARE_PAL_RSE_INFO] = "firmware.pal.rse_info",
    [IA64_PERF_FIRMWARE_PAL_VM_PAGE_SIZE] = "firmware.pal.vm_page_size",
    [IA64_PERF_FIRMWARE_PAL_FEATURES] = "firmware.pal.features",
    [IA64_PERF_FIRMWARE_PAL_DEBUG] = "firmware.pal.debug",
    [IA64_PERF_FIRMWARE_PAL_FREQUENCY] = "firmware.pal.frequency",
    [IA64_PERF_FIRMWARE_PAL_PERF_MONITOR] = "firmware.pal.perf_monitor",
    [IA64_PERF_FIRMWARE_PAL_FIXED_PLATFORM] = "firmware.pal.fixed_platform",
    [IA64_PERF_FIRMWARE_PAL_VERSION] = "firmware.pal.version",
    [IA64_PERF_FIRMWARE_PAL_REGISTER_INFO] = "firmware.pal.register_info",
    [IA64_PERF_FIRMWARE_PAL_PREFETCH] = "firmware.pal.prefetch",
    [IA64_PERF_FIRMWARE_PAL_LOGICAL_TO_PHYSICAL] = "firmware.pal.logical_to_physical",
    [IA64_PERF_FIRMWARE_PAL_CACHE_SHARED] = "firmware.pal.cache_shared",
    [IA64_PERF_FIRMWARE_PAL_SHUTDOWN] = "firmware.pal.shutdown",
    [IA64_PERF_FIRMWARE_PAL_HALT_INFO] = "firmware.pal.halt_info",
    [IA64_PERF_FIRMWARE_PAL_BRAND] = "firmware.pal.brand",
    [IA64_PERF_FIRMWARE_PAL_MACHINE_CHECK] = "firmware.pal.machine_check",
    [IA64_PERF_FIRMWARE_PAL_OTHER] = "firmware.pal.other",
    [IA64_PERF_FIRMWARE_SAL] = "firmware.sal",
    [IA64_PERF_FIRMWARE_EFI] = "firmware.efi",
    [IA64_PERF_UNSUPPORTED_ABORT] = "abort.unsupported",
    [IA64_PERF_ZERO_BRANCH_ABORT] = "abort.zero_branch",
};

static void ia64_perf_dump(void)
{
    int64_t elapsed_us = g_get_monotonic_time() - ia64_perf_start_us;

    if (ia64_perf_enabled_cached == 0) {
        return;
    }

    fprintf(stderr, "[ia64-perf] enabled=1\n");
    fprintf(stderr, "[ia64-perf] elapsed_us=%" PRId64 "\n", elapsed_us);
    for (unsigned i = 0; i < IA64_PERF_COUNTER_COUNT; i++) {
        if (ia64_perf_counters[i] != 0) {
            fprintf(stderr, "[ia64-perf] %s=%" PRIu64 "\n",
                    ia64_perf_counter_names[i], ia64_perf_counters[i]);
        }
    }
}

bool ia64_perf_init_enabled(void)
{
    const char *value = g_getenv("VIBTANIUM_IA64_PERF");

    ia64_perf_enabled_cached = value != NULL && *value != '\0';
    if (ia64_perf_enabled_cached && !ia64_perf_registered) {
        ia64_perf_start_us = g_get_monotonic_time();
        atexit(ia64_perf_dump);
        ia64_perf_registered = true;
    }

    return ia64_perf_enabled_cached != 0;
}

void ia64_perf_count(IA64PerfCounter counter)
{
    if (counter < IA64_PERF_COUNTER_COUNT) {
        ia64_perf_counters[counter]++;
    }
}

void ia64_perf_add(IA64PerfCounter counter, uint64_t value)
{
    if (counter < IA64_PERF_COUNTER_COUNT) {
        ia64_perf_counters[counter] += value;
    }
}

void ia64_perf_count_slot_type(IA64SlotType type)
{
    switch (type) {
    case IA64_SLOT_TYPE_M:
        ia64_perf_count(IA64_PERF_SLOT_TYPE_M);
        break;
    case IA64_SLOT_TYPE_I:
        ia64_perf_count(IA64_PERF_SLOT_TYPE_I);
        break;
    case IA64_SLOT_TYPE_F:
        ia64_perf_count(IA64_PERF_SLOT_TYPE_F);
        break;
    case IA64_SLOT_TYPE_B:
        ia64_perf_count(IA64_PERF_SLOT_TYPE_B);
        break;
    case IA64_SLOT_TYPE_L:
        ia64_perf_count(IA64_PERF_SLOT_TYPE_L);
        break;
    case IA64_SLOT_TYPE_X:
        ia64_perf_count(IA64_PERF_SLOT_TYPE_X);
        break;
    default:
        ia64_perf_count(IA64_PERF_SLOT_TYPE_INVALID);
        break;
    }
}

void ia64_perf_count_access_type(int access_type)
{
    switch (access_type) {
    case MMU_INST_FETCH:
        ia64_perf_count(IA64_PERF_TARGET_TRANSLATE_INST);
        break;
    case MMU_DATA_LOAD:
        ia64_perf_count(IA64_PERF_TARGET_TRANSLATE_LOAD);
        break;
    case MMU_DATA_STORE:
        ia64_perf_count(IA64_PERF_TARGET_TRANSLATE_STORE);
        break;
    default:
        break;
    }
}

void ia64_perf_count_translate_status(unsigned status)
{
    switch (status) {
    case IA64_TRANSLATE_OK:
        ia64_perf_count(IA64_PERF_TARGET_TRANSLATE_OK);
        break;
    case IA64_TRANSLATE_TLB_MISS:
        ia64_perf_count(IA64_PERF_TARGET_TRANSLATE_TLB_MISS);
        break;
    case IA64_TRANSLATE_NOT_PRESENT:
        ia64_perf_count(IA64_PERF_TARGET_TRANSLATE_NOT_PRESENT);
        break;
    case IA64_TRANSLATE_ACCESS_DENIED:
        ia64_perf_count(IA64_PERF_TARGET_TRANSLATE_ACCESS_DENIED);
        break;
    default:
        ia64_perf_count(IA64_PERF_TARGET_TRANSLATE_OTHER_FAIL);
        break;
    }
}

void ia64_perf_count_exception_kind(unsigned kind)
{
    switch (kind) {
    case IA64_EXCEPTION_INSTRUCTION_TLB_MISS:
    case IA64_EXCEPTION_DATA_TLB_MISS:
    case IA64_EXCEPTION_ALTERNATE_INSTRUCTION_TLB_MISS:
    case IA64_EXCEPTION_ALTERNATE_DATA_TLB_MISS:
    case IA64_EXCEPTION_DATA_NESTED_TLB:
        ia64_perf_count(IA64_PERF_EXCEPTION_TLB_MISS);
        break;
    case IA64_EXCEPTION_PAGE_FAULT:
        ia64_perf_count(IA64_PERF_EXCEPTION_PAGE_FAULT);
        break;
    case IA64_EXCEPTION_BREAK:
        ia64_perf_count(IA64_PERF_EXCEPTION_BREAK);
        break;
    case IA64_EXCEPTION_EXTERNAL_INTERRUPT:
        ia64_perf_count(IA64_PERF_EXCEPTION_EXTERNAL_INTERRUPT);
        break;
    default:
        ia64_perf_count(IA64_PERF_EXCEPTION_OTHER);
        break;
    }
}

void ia64_perf_count_tcg_fallback_reason(unsigned reason)
{
    static const IA64PerfCounter counters[IA64_TCG_FALLBACK_COUNT] = {
        [IA64_TCG_FALLBACK_INVALID_TEMPLATE] =
            IA64_PERF_TCG_FALLBACK_INVALID_TEMPLATE,
        [IA64_TCG_FALLBACK_BOUNDARY_EFI_CALL_GATE] =
            IA64_PERF_TCG_FALLBACK_BOUNDARY_EFI_CALL_GATE,
        [IA64_TCG_FALLBACK_BOUNDARY_BREAK] =
            IA64_PERF_TCG_FALLBACK_BOUNDARY_BREAK,
        [IA64_TCG_FALLBACK_BOUNDARY_SPECULATION_CHECK] =
            IA64_PERF_TCG_FALLBACK_BOUNDARY_SPECULATION_CHECK,
        [IA64_TCG_FALLBACK_BOUNDARY_VIRTUAL_TRANSLATION] =
            IA64_PERF_TCG_FALLBACK_BOUNDARY_VIRTUAL_TRANSLATION,
        [IA64_TCG_FALLBACK_BOUNDARY_BRANCH] =
            IA64_PERF_TCG_FALLBACK_BOUNDARY_BRANCH,
        [IA64_TCG_FALLBACK_BOUNDARY_CPU_STATE] =
            IA64_PERF_TCG_FALLBACK_BOUNDARY_CPU_STATE,
        [IA64_TCG_FALLBACK_BOUNDARY_TRANSLATION_STATE] =
            IA64_PERF_TCG_FALLBACK_BOUNDARY_TRANSLATION_STATE,
        [IA64_TCG_FALLBACK_BOUNDARY_RSE_STATE] =
            IA64_PERF_TCG_FALLBACK_BOUNDARY_RSE_STATE,
        [IA64_TCG_FALLBACK_FAST_LONG_IMMEDIATE] =
            IA64_PERF_TCG_FALLBACK_FAST_LONG_IMMEDIATE,
        [IA64_TCG_FALLBACK_FAST_PREDICATED_SLOT] =
            IA64_PERF_TCG_FALLBACK_FAST_PREDICATED_SLOT,
        [IA64_TCG_FALLBACK_FAST_STATIC_GR] =
            IA64_PERF_TCG_FALLBACK_FAST_STATIC_GR,
        [IA64_TCG_FALLBACK_FAST_LDST_SLOT] =
            IA64_PERF_TCG_FALLBACK_FAST_LDST_SLOT,
        [IA64_TCG_FALLBACK_FAST_LDST_TRACE] =
            IA64_PERF_TCG_FALLBACK_FAST_LDST_TRACE,
        [IA64_TCG_FALLBACK_FAST_LDST_REGISTER_UPDATE] =
            IA64_PERF_TCG_FALLBACK_FAST_LDST_REGISTER_UPDATE,
        [IA64_TCG_FALLBACK_FAST_LDST_MEMORY_CLASS] =
            IA64_PERF_TCG_FALLBACK_FAST_LDST_MEMORY_CLASS,
        [IA64_TCG_FALLBACK_FAST_LDST_TARGET] =
            IA64_PERF_TCG_FALLBACK_FAST_LDST_TARGET,
        [IA64_TCG_FALLBACK_FAST_UNSUPPORTED_SLOT] =
            IA64_PERF_TCG_FALLBACK_FAST_UNSUPPORTED_SLOT,
        [IA64_TCG_FALLBACK_RUNTIME_GUARD] =
            IA64_PERF_TCG_FALLBACK_RUNTIME_GUARD,
    };

    if (reason > IA64_TCG_FALLBACK_NONE &&
        reason < IA64_TCG_FALLBACK_COUNT) {
        ia64_perf_count(counters[reason]);
    }
}
