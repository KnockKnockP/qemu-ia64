/*
 * Focused VMState coverage for the IA-64 typed issue-group continuation.
 *
 * Include machine.c so this test exercises the production-private subsection
 * descriptions and validation routine instead of duplicating their schema.
 */
#include "qemu/osdep.h"

#include "migration/qemu-file-types.h"
#include "migration/vmstate.h"
#include "../migration/qemu-file.h"
#include "../migration/savevm.h"
#include "io/channel-file.h"
#include "qapi/error.h"
#include "qemu/module.h"

#include "../../target/ia64/machine.c"

/*
 * machine.c's complete CPU description retains its pre/post-load callbacks in
 * this test executable.  The focused root deliberately invokes the production
 * pre-load hook to verify absent-version defaults, while the unrelated
 * architecture hooks below remain inert.  The current typed-only CPU/env/RSE
 * descriptions, overlay descriptions, and validators are compiled directly
 * from production above.
 */
void ia64_itc_sync(CPUIA64State *env)
{
    (void)env;
}

static unsigned rse_hook_sequence;
static unsigned rse_reconstruct_order;
static unsigned rse_sync_out_order;
static unsigned rse_sync_in_order;
static unsigned rse_sync_out_count;
static unsigned rse_sync_in_count;

static uint32_t test_logical_stacked_slot(const CPUIA64State *env,
                                          unsigned logical)
{
    uint32_t rotating_count = env->rse.sor * 8;
    uint32_t offset = logical;

    g_assert_cmpuint(logical, <, IA64_GR_COUNT - IA64_STATIC_GR_COUNT);
    if (rotating_count != 0 && offset < rotating_count) {
        offset = (offset + env->rse.rrb_gr) % rotating_count;
    }
    return ia64_rse_wrap_slot(env->rse.current_frame_base + offset);
}

static bool test_word_bit(const uint64_t words[2], unsigned bit)
{
    return (words[bit / 64] & (UINT64_C(1) << (bit % 64))) != 0;
}

static void test_set_word_bit(uint64_t words[2], unsigned bit, bool value)
{
    uint64_t mask = UINT64_C(1) << (bit % 64);

    if (value) {
        words[bit / 64] |= mask;
    } else {
        words[bit / 64] &= ~mask;
    }
}

static bool test_physical_nat(const CPUIA64State *env, uint32_t slot)
{
    slot = ia64_rse_wrap_slot(slot);
    return (env->rse.stacked_nat[slot / 64] &
            (UINT64_C(1) << (slot % 64))) != 0;
}

static void test_set_physical_nat(CPUIA64State *env, uint32_t slot,
                                  bool value)
{
    uint64_t mask;

    slot = ia64_rse_wrap_slot(slot);
    mask = UINT64_C(1) << (slot % 64);
    if (value) {
        env->rse.stacked_nat[slot / 64] |= mask;
    } else {
        env->rse.stacked_nat[slot / 64] &= ~mask;
    }
}

void ia64_rse_reconstruct_transients(CPUIA64State *env)
{
    (void)env;
    rse_reconstruct_order = ++rse_hook_sequence;
}

/*
 * The production RSE implementation is intentionally not linked into this
 * focused VMState binary.  These contract stubs model the two boundary APIs
 * so the tests below exercise machine.c's call placement and current wire
 * authority rather than silently making the hooks no-ops.
 */
void ia64_rse_sync_logical_out(CPUIA64State *env)
{
    rse_sync_out_count++;
    rse_sync_out_order = ++rse_hook_sequence;
    for (unsigned logical = 0;
         logical < IA64_GR_COUNT - IA64_STATIC_GR_COUNT; logical++) {
        uint32_t slot;

        if (!test_word_bit(env->rse.logical_dirty, logical)) {
            continue;
        }
        slot = test_logical_stacked_slot(env, logical);
        env->rse.stacked_gr[slot] =
            env->gr[IA64_STATIC_GR_COUNT + logical];
        test_set_physical_nat(env, slot,
                              test_word_bit(env->rse.logical_nat, logical));
    }
    memset(env->rse.logical_dirty, 0, sizeof(env->rse.logical_dirty));
}

void ia64_rse_sync_logical_in(CPUIA64State *env)
{
    rse_sync_in_count++;
    rse_sync_in_order = ++rse_hook_sequence;
    g_assert_cmphex(env->rse.logical_dirty[0], ==, 0);
    g_assert_cmphex(env->rse.logical_dirty[1], ==, 0);
    memset(env->rse.logical_nat, 0, sizeof(env->rse.logical_nat));
    for (unsigned logical = 0;
         logical < IA64_GR_COUNT - IA64_STATIC_GR_COUNT; logical++) {
        uint32_t slot = test_logical_stacked_slot(env, logical);

        env->gr[IA64_STATIC_GR_COUNT + logical] =
            env->rse.stacked_gr[slot];
        test_set_word_bit(env->rse.logical_nat, logical,
                          test_physical_nat(env, slot));
    }
    memset(env->rse.logical_dirty, 0, sizeof(env->rse.logical_dirty));
}

void ia64_cpu_init_synthetic_cpuid(CPUIA64State *env)
{
    (void)env;
}

void ia64_translation_lookup_cache_flush(CPUIA64State *env)
{
    (void)env;
}

void ia64_psr_mmu_state_changed(CPUIA64State *env,
                                uint64_t old_psr, uint64_t new_psr)
{
    (void)env;
    (void)old_psr;
    (void)new_psr;
}

void ia64_alat_reconstruct_transients(CPUIA64State *env)
{
    (void)env;
}

void ia64_itc_set(CPUIA64State *env, uint64_t value)
{
    (void)env;
    (void)value;
}

void ia64_itc_timer_update(CPUIA64State *env)
{
    (void)env;
}

static unsigned interrupt_reconcile_count;
static unsigned interrupt_refresh_delivery_count;

void ia64_reconcile_interrupt_state(CPUIA64State *env)
{
    static const uint8_t special_priority[] = { 2, 0 };

    interrupt_reconcile_count++;
    env->interrupt.pending = false;
    env->interrupt.pending_vector = 0;
    for (unsigned i = 0; i < ARRAY_SIZE(special_priority); i++) {
        unsigned vector = special_priority[i];

        if (env->cr[IA64_CR_IRR0 + vector / 64] &
            (UINT64_C(1) << (vector & 63))) {
            env->interrupt.pending = true;
            env->interrupt.pending_vector = vector;
            return;
        }
    }
    for (int word = 3; word >= 0; word--) {
        uint64_t pending = env->cr[IA64_CR_IRR0 + word];

        if (word == 0) {
            pending &= (~UINT64_C(0) << 16);
        }
        if (pending != 0) {
            env->interrupt.pending = true;
            env->interrupt.pending_vector =
                (uint64_t)word * 64 + 63 - clz64(pending);
            return;
        }
    }
}

void ia64_refresh_interrupt_delivery(CPUIA64State *env)
{
    interrupt_refresh_delivery_count++;
    if (env->interrupt.pending) {
        qatomic_or(&env_cpu(env)->interrupt_request, CPU_INTERRUPT_HARD);
    } else {
        qatomic_and(&env_cpu(env)->interrupt_request, ~CPU_INTERRUPT_HARD);
    }
}

void tlb_flush(CPUState *cpu)
{
    (void)cpu;
}

static int temp_fd;

static QEMUFile *open_test_file(bool write)
{
    QIOChannel *ioc;
    QEMUFile *f;
    int fd = dup(temp_fd);

    g_assert_cmpint(fd, >=, 0);
    g_assert_cmpint(lseek(fd, 0, SEEK_SET), ==, 0);
    if (write) {
        g_assert_cmpint(ftruncate(fd, 0), ==, 0);
    }

    ioc = QIO_CHANNEL(qio_channel_file_new_fd(fd));
    f = write ? qemu_file_new_output(ioc) : qemu_file_new_input(ioc);
    object_unref(OBJECT(ioc));
    return f;
}

static int validate_loaded_issue_group(void *opaque, int version_id)
{
    CPUIA64State *env = opaque;

    g_assert_cmpint(version_id, ==, 1);
    return ia64_validate_issue_group_overlay(env);
}

/*
 * This root contains the live PR image plus the three pieces of IA-64 state
 * involved in carrying an open typed group across a migration boundary.  All
 * subsection descriptions and their .needed callbacks are production objects.
 */
static const VMStateDescription vmstate_issue_group_test_root = {
    .name = "env",
    .version_id = 1,
    .minimum_version_id = 1,
    .pre_load = ia64_env_pre_load,
    .post_load = validate_loaded_issue_group,
    .fields = (const VMStateField[]) {
        VMSTATE_UINT64(pr, CPUIA64State),
        VMSTATE_END_OF_LIST()
    },
    .subsections = (const VMStateDescription * const []) {
        &vmstate_instruction_group_state,
        &vmstate_issue_group_overlay,
        &vmstate_issue_group_fr_overlay,
        NULL
    },
};

/*
 * Exercise the current typed-only env payload followed by the outer CPU field
 * and production collection-state subsection.  Omitting CPUState's unrelated
 * common payload keeps this focused while preserving the fixed CPU-v6 /
 * env-v8 / RSE-v5 / interrupt-v3 version chain.
 */
static const VMStateDescription vmstate_collection_test_root = {
    .name = "cpu",
    .version_id = 6,
    .minimum_version_id = 6,
    .post_load = ia64_cpu_post_load,
    .fields = (const VMStateField[]) {
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

static int save_issue_group_with_vmsd(const CPUIA64State *env,
                                      const VMStateDescription *vmsd)
{
    Error *local_err = NULL;
    QEMUFile *f = open_test_file(true);
    int ret;

    ret = vmstate_save_state(f, vmsd, (void *)env, NULL, &local_err);
    if (local_err) {
        error_report_err(local_err);
    }
    if (ret == 0) {
        qemu_put_byte(f, QEMU_VM_EOF);
        ret = qemu_file_get_error(f);
    }
    qemu_fclose(f);
    return ret;
}

static int save_issue_group(const CPUIA64State *env)
{
    return save_issue_group_with_vmsd(env, &vmstate_issue_group_test_root);
}

static int load_issue_group(CPUIA64State *env)
{
    Error *local_err = NULL;
    QEMUFile *f = open_test_file(false);
    int ret;

    ret = vmstate_load_state(f, &vmstate_issue_group_test_root, env, 1,
                             &local_err);
    if (local_err) {
        error_free(local_err);
    }
    qemu_fclose(f);
    return ret;
}

static int save_cpu_with_vmsd(const IA64CPU *cpu,
                              const VMStateDescription *vmsd)
{
    Error *local_err = NULL;
    QEMUFile *f = open_test_file(true);
    int ret;

    ret = vmstate_save_state(f, vmsd, (void *)cpu, NULL, &local_err);
    if (local_err) {
        error_report_err(local_err);
    }
    if (ret == 0) {
        qemu_put_byte(f, QEMU_VM_EOF);
        ret = qemu_file_get_error(f);
    }
    qemu_fclose(f);
    return ret;
}

static int load_cpu_with_current_root(IA64CPU *cpu)
{
    Error *local_err = NULL;
    QEMUFile *f = open_test_file(false);
    int ret;

    ret = vmstate_load_state(f, &vmstate_collection_test_root, cpu,
                             vmstate_collection_test_root.version_id,
                             &local_err);
    if (local_err) {
        error_free(local_err);
    }
    qemu_fclose(f);
    return ret;
}

static int save_rse_with_vmsd(const IA64RSEState *rse,
                              const VMStateDescription *vmsd)
{
    Error *local_err = NULL;
    QEMUFile *f = open_test_file(true);
    int ret;

    ret = vmstate_save_state(f, vmsd, (void *)rse, NULL, &local_err);
    if (local_err) {
        error_report_err(local_err);
    }
    if (ret == 0) {
        qemu_put_byte(f, QEMU_VM_EOF);
        ret = qemu_file_get_error(f);
    }
    qemu_fclose(f);
    return ret;
}

static int load_rse_with_current_vmsd(IA64RSEState *rse)
{
    Error *local_err = NULL;
    QEMUFile *f = open_test_file(false);
    int ret;

    ret = vmstate_load_state(f, &vmstate_rse, rse,
                             vmstate_rse.version_id, &local_err);
    if (local_err) {
        error_free(local_err);
    }
    qemu_fclose(f);
    return ret;
}

static int save_alat_with_vmsd(const IA64AlatState *alat,
                               const VMStateDescription *vmsd)
{
    Error *local_err = NULL;
    QEMUFile *f = open_test_file(true);
    int ret;

    ret = vmstate_save_state(f, vmsd, (void *)alat, NULL, &local_err);
    if (local_err) {
        error_report_err(local_err);
    }
    if (ret == 0) {
        qemu_put_byte(f, QEMU_VM_EOF);
        ret = qemu_file_get_error(f);
    }
    qemu_fclose(f);
    return ret;
}

static int load_alat_with_current_vmsd(IA64AlatState *alat)
{
    Error *local_err = NULL;
    QEMUFile *f = open_test_file(false);
    int ret;

    ret = vmstate_load_state(f, &vmstate_alat, alat, 1, &local_err);
    if (local_err) {
        error_free(local_err);
    }
    qemu_fclose(f);
    return ret;
}

static int save_interrupt_state(const IA64InterruptState *interrupt)
{
    Error *local_err = NULL;
    QEMUFile *f = open_test_file(true);
    int ret;

    ret = vmstate_save_state(f, &vmstate_interrupt, (void *)interrupt,
                             NULL, &local_err);
    if (local_err) {
        error_report_err(local_err);
    }
    if (ret == 0) {
        qemu_put_byte(f, QEMU_VM_EOF);
        ret = qemu_file_get_error(f);
    }
    qemu_fclose(f);
    return ret;
}

static int load_interrupt_state(IA64InterruptState *interrupt)
{
    Error *local_err = NULL;
    QEMUFile *f = open_test_file(false);
    int ret;

    ret = vmstate_load_state(f, &vmstate_interrupt, interrupt,
                             vmstate_interrupt.version_id, &local_err);
    if (local_err) {
        error_free(local_err);
    }
    qemu_fclose(f);
    return ret;
}

static void init_cpu_stream(IA64CPU *cpu, uint64_t last_successful_bundle,
                            bool psr_ic_inflight)
{
    CPUIA64State *env;

    memset(cpu, 0, sizeof(*cpu));
    env = &cpu->env;
    env->gr[0] = 0;
    env->pr = 1;
    env->instruction_group_start = true;
    env->rse.invalid = IA64_GR_COUNT - IA64_STATIC_GR_COUNT;
    env->last_successful_bundle = last_successful_bundle;
    env->psr_ic_inflight = psr_ic_inflight;
}

static void init_typed_source(CPUIA64State *env)
{
    memset(env, 0, sizeof(*env));
    env->instruction_group_start = false;
    env->issue_group.typed_active = true;
    env->rse.invalid = IA64_GR_COUNT - IA64_STATIC_GR_COUNT;
}

static void init_destination(CPUIA64State *env)
{
    memset(env, 0xa5, sizeof(*env));
    ia64_env_begin_source_visibility_epoch(env);
}

static void assert_issue_group_equal(const IA64IssueGroupState *actual,
                                     const IA64IssueGroupState *expected)
{
    uint64_t fr_mask[2];

    g_assert_cmpmem(actual->saved_gr, sizeof(actual->saved_gr),
                    expected->saved_gr, sizeof(expected->saved_gr));
    g_assert_cmpmem(actual->saved_nat, sizeof(actual->saved_nat),
                    expected->saved_nat, sizeof(expected->saved_nat));
    g_assert_cmpmem(actual->saved_gr_mask, sizeof(actual->saved_gr_mask),
                    expected->saved_gr_mask,
                    sizeof(expected->saved_gr_mask));
    g_assert_cmpmem(actual->saved_fr_mask, sizeof(actual->saved_fr_mask),
                    expected->saved_fr_mask,
                    sizeof(expected->saved_fr_mask));
    memcpy(fr_mask, expected->saved_fr_mask, sizeof(fr_mask));
    for (unsigned half = 0; half < ARRAY_SIZE(fr_mask); half++) {
        while (fr_mask[half] != 0) {
            unsigned bit = ctz64(fr_mask[half]);
            unsigned reg = half * 64 + bit;

            g_assert_cmpmem(actual->saved_fr[reg].raw,
                            sizeof(actual->saved_fr[reg].raw),
                            expected->saved_fr[reg].raw,
                            sizeof(expected->saved_fr[reg].raw));
            fr_mask[half] &= fr_mask[half] - 1;
        }
    }
    g_assert_cmpmem(actual->saved_br, sizeof(actual->saved_br),
                    expected->saved_br, sizeof(expected->saved_br));
    g_assert_cmpmem(actual->saved_ar_value,
                    sizeof(actual->saved_ar_value),
                    expected->saved_ar_value,
                    sizeof(expected->saved_ar_value));
    g_assert_cmpmem(actual->saved_ar_index,
                    sizeof(actual->saved_ar_index),
                    expected->saved_ar_index,
                    sizeof(expected->saved_ar_index));
    g_assert_cmpuint(actual->saved_pr, ==, expected->saved_pr);
    g_assert_cmpuint(actual->saved_pfs, ==, expected->saved_pfs);
    g_assert_cmpuint(actual->branch_pr_forward_mask, ==,
                     expected->branch_pr_forward_mask);
    g_assert_cmpuint(actual->saved_br_mask, ==, expected->saved_br_mask);
    g_assert_cmpuint(actual->branch_br_forward_mask, ==,
                     expected->branch_br_forward_mask);
    g_assert_cmpint(actual->pr_saved, ==, expected->pr_saved);
    g_assert_cmpint(actual->pfs_saved, ==, expected->pfs_saved);
    g_assert_cmpint(actual->branch_pfs_forwarded, ==,
                    expected->branch_pfs_forwarded);
    g_assert_cmpuint(actual->saved_ar_count, ==,
                     expected->saved_ar_count);
    g_assert_cmpint(actual->typed_active, ==, expected->typed_active);
}

static void assert_round_trip(const CPUIA64State *source)
{
    CPUIA64State destination;

    g_assert_cmpint(save_issue_group(source), ==, 0);
    init_destination(&destination);
    destination.issue_group.branch_pr_forward_mask = UINT64_MAX;
    g_assert_cmpint(load_issue_group(&destination), ==, 0);

    g_assert_false(destination.instruction_group_start);
    assert_issue_group_equal(&destination.issue_group, &source->issue_group);
}

static void test_empty_typed_continuation(void)
{
    CPUIA64State source;

    init_typed_source(&source);
    g_assert_true(ia64_issue_group_overlay_needed(&source));
    assert_round_trip(&source);
}

static void test_gr_nat_overlay(void)
{
    CPUIA64State source;

    init_typed_source(&source);
    source.issue_group.saved_gr_mask[0] = UINT64_C(1) << 5;
    source.issue_group.saved_gr_mask[1] = UINT64_C(1) << (70 - 64);
    source.issue_group.saved_gr[5] = UINT64_C(0x0123456789abcdef);
    source.issue_group.saved_nat[5] = 1;
    source.issue_group.saved_gr[70] = UINT64_C(0xfedcba9876543210);
    source.issue_group.saved_nat[70] = 0;
    assert_round_trip(&source);
}

static void test_fr_overlay(void)
{
    CPUIA64State source;

    init_typed_source(&source);
    source.issue_group.saved_fr_mask[0] = UINT64_C(1) << 2;
    source.issue_group.saved_fr_mask[1] = UINT64_C(1) << (127 - 64);
    source.issue_group.saved_fr[2].raw[0] =
        UINT64_C(0x0123456789abcdef);
    source.issue_group.saved_fr[2].raw[1] =
        UINT64_C(0xfedcba9876543210);
    source.issue_group.saved_fr[127].raw[0] =
        UINT64_C(0x1122334455667788);
    source.issue_group.saved_fr[127].raw[1] =
        UINT64_C(0x8877665544332211);

    assert_round_trip(&source);
}

static void test_pr_overlay(void)
{
    CPUIA64State source;

    init_typed_source(&source);
    source.issue_group.saved_pr = UINT64_C(0x8000000000000021);
    source.issue_group.pr_saved = true;
    assert_round_trip(&source);
}

static void test_br_overlay(void)
{
    CPUIA64State source;

    init_typed_source(&source);
    source.issue_group.saved_br_mask =
        (1u << 0) | (1u << 3) | (1u << 7);
    source.issue_group.saved_br[0] = UINT64_C(0x0123456789abcdef);
    source.issue_group.saved_br[3] = UINT64_C(0x8877665544332211);
    source.issue_group.saved_br[7] = UINT64_C(0xfedcba9876543210);
    assert_round_trip(&source);
}

static void test_pfs_overlay(void)
{
    CPUIA64State source;

    init_typed_source(&source);
    source.issue_group.saved_pfs = UINT64_C(0x123456789abcdef0);
    source.issue_group.pfs_saved = true;
    source.issue_group.branch_pfs_forwarded = true;
    assert_round_trip(&source);
}

static void test_ar_overlay(void)
{
    const uint64_t unat_entry = UINT64_C(0x0123456789abcdef);
    const uint64_t unat_retired = UINT64_C(0x1122334455667788);
    const uint64_t csd_entry = UINT64_C(0xfedcba9876543210);
    const uint64_t csd_retired = UINT64_C(0x8877665544332211);
    CPUIA64State source;
    CPUIA64State destination;

    init_typed_source(&source);
    source.issue_group.saved_ar_count = 2;
    source.issue_group.saved_ar_index[0] = IA64_AR_UNAT;
    source.issue_group.saved_ar_value[0] = unat_entry;
    source.issue_group.saved_ar_index[1] = IA64_AR_CSD;
    source.issue_group.saved_ar_value[1] = csd_entry;

    g_assert_cmpint(save_issue_group(&source), ==, 0);
    init_destination(&destination);
    destination.ar[IA64_AR_UNAT] = unat_retired;
    destination.nat.unat = unat_retired;
    destination.ar[IA64_AR_CSD] = csd_retired;
    g_assert_cmpint(load_issue_group(&destination), ==, 0);

    g_assert_false(destination.instruction_group_start);
    assert_issue_group_equal(&destination.issue_group, &source.issue_group);
    g_assert_cmphex(destination.ar[IA64_AR_UNAT], ==, unat_retired);
    g_assert_cmphex(destination.ar[IA64_AR_CSD], ==, csd_retired);
    g_assert_cmpuint(destination.issue_group.saved_ar_index[0], ==,
                     IA64_AR_UNAT);
    g_assert_cmphex(destination.issue_group.saved_ar_value[0], ==,
                    unat_entry);
    g_assert_cmpuint(destination.issue_group.saved_ar_index[1], ==,
                     IA64_AR_CSD);
    g_assert_cmphex(destination.issue_group.saved_ar_value[1], ==,
                    csd_entry);
}

static void test_branch_br_forward_overlay(void)
{
    CPUIA64State source;

    init_typed_source(&source);
    source.issue_group.branch_br_forward_mask =
        (1u << 0) | (1u << 4) | (1u << 7);
    assert_round_trip(&source);
}

static void test_branch_pr_forward_overlay(void)
{
    CPUIA64State source;

    init_typed_source(&source);
    source.issue_group.branch_pr_forward_mask =
        (UINT64_C(1) << 1) | (UINT64_C(1) << 17) | (UINT64_C(1) << 63);
    assert_round_trip(&source);
}

static void test_branch_pr_forward_needed(void)
{
    CPUIA64State env = { 0 };

    g_assert_false(ia64_issue_group_overlay_needed(&env));
    env.issue_group.branch_pr_forward_mask = UINT64_C(1) << 42;
    g_assert_true(ia64_issue_group_overlay_needed(&env));
}

static void test_pfs_overlay_needed(void)
{
    CPUIA64State env = { 0 };

    env.issue_group.saved_pfs = UINT64_C(0xfeedfacecafebeef);
    g_assert_false(ia64_issue_group_overlay_needed(&env));
    env.issue_group.pfs_saved = true;
    g_assert_true(ia64_issue_group_overlay_needed(&env));
    env.issue_group.pfs_saved = false;
    env.issue_group.branch_pfs_forwarded = true;
    g_assert_true(ia64_issue_group_overlay_needed(&env));
}

static void test_ar_overlay_needed(void)
{
    CPUIA64State env = { 0 };

    /* Backing slots are inert unless the sparse count includes them. */
    env.issue_group.saved_ar_index[0] = IA64_AR_CSD;
    env.issue_group.saved_ar_value[0] = UINT64_C(0xfeedfacecafebeef);
    g_assert_false(ia64_issue_group_overlay_needed(&env));
    env.issue_group.saved_ar_count = 1;
    g_assert_true(ia64_issue_group_overlay_needed(&env));
}

static void test_fr_overlay_needed(void)
{
    CPUIA64State env = { 0 };

    /* Saved backing values are inert until their validity bit is present. */
    env.issue_group.saved_fr[2].raw[0] =
        UINT64_C(0x0123456789abcdef);
    env.issue_group.saved_fr[127].raw[1] =
        UINT64_C(0xfedcba9876543210);
    g_assert_false(ia64_issue_group_fr_overlay_needed(&env));

    env.issue_group.saved_fr_mask[0] = UINT64_C(1) << 2;
    g_assert_true(ia64_issue_group_fr_overlay_needed(&env));
    env.issue_group.saved_fr_mask[0] = 0;
    env.issue_group.saved_fr_mask[1] = UINT64_C(1) << (127 - 64);
    g_assert_true(ia64_issue_group_fr_overlay_needed(&env));
}

static void test_br_overlay_needed(void)
{
    CPUIA64State env = { 0 };

    /* Backing values without validity bits are deliberately inert. */
    env.issue_group.saved_br[2] = UINT64_C(0xdeadbeefcafebabe);
    g_assert_false(ia64_issue_group_overlay_needed(&env));

    env.issue_group.saved_br_mask = 1u << 2;
    g_assert_true(ia64_issue_group_overlay_needed(&env));
    env.issue_group.saved_br_mask = 0;
    g_assert_false(ia64_issue_group_overlay_needed(&env));

    env.issue_group.branch_br_forward_mask = 1u << 6;
    g_assert_true(ia64_issue_group_overlay_needed(&env));
}

static void test_combined_overlay(void)
{
    CPUIA64State source;

    init_typed_source(&source);
    source.issue_group.saved_gr_mask[0] = UINT64_C(1) << 63;
    source.issue_group.saved_gr_mask[1] = UINT64_C(1) << (127 - 64);
    source.issue_group.saved_gr[63] = UINT64_C(0x1111222233334444);
    source.issue_group.saved_nat[63] = 0;
    source.issue_group.saved_gr[127] = UINT64_C(0xaaaabbbbccccdddd);
    source.issue_group.saved_nat[127] = 1;
    source.issue_group.saved_pr = UINT64_C(0x4000000000000401);
    source.issue_group.pr_saved = true;
    source.issue_group.branch_pr_forward_mask =
        (UINT64_C(1) << 10) | (UINT64_C(1) << 62);
    source.issue_group.saved_br_mask = (1u << 1) | (1u << 6);
    source.issue_group.saved_br[1] = UINT64_C(0x13579bdf2468ace0);
    source.issue_group.saved_br[6] = UINT64_C(0x0f1e2d3c4b5a6978);
    source.issue_group.branch_br_forward_mask = (1u << 2) | (1u << 6);
    assert_round_trip(&source);
}

typedef void (*CorruptState)(CPUIA64State *env);

static void assert_load_rejected(CorruptState corrupt)
{
    CPUIA64State source;
    CPUIA64State destination;

    init_typed_source(&source);
    corrupt(&source);
    g_assert_cmpint(save_issue_group(&source), ==, 0);

    init_destination(&destination);
    g_assert_cmpint(load_issue_group(&destination), !=, 0);
}

static void corrupt_fresh_frontier(CPUIA64State *env)
{
    env->instruction_group_start = true;
}

static void corrupt_missing_typed_owner(CPUIA64State *env)
{
    env->issue_group.typed_active = false;
    env->issue_group.saved_gr_mask[0] = UINT64_C(1) << 2;
}

static void corrupt_forward_at_fresh_frontier(CPUIA64State *env)
{
    env->instruction_group_start = true;
    env->issue_group.branch_pr_forward_mask = UINT64_C(1) << 9;
}

static void corrupt_forward_without_typed_owner(CPUIA64State *env)
{
    env->issue_group.typed_active = false;
    env->issue_group.branch_pr_forward_mask = UINT64_C(1) << 31;
}

static void corrupt_forward_p0(CPUIA64State *env)
{
    env->issue_group.branch_pr_forward_mask = UINT64_C(1);
}

static void corrupt_br_at_fresh_frontier(CPUIA64State *env)
{
    env->instruction_group_start = true;
    env->issue_group.saved_br_mask = 1u << 3;
    env->issue_group.saved_br[3] = UINT64_C(0xabcdef0123456789);
}

static void corrupt_br_without_typed_owner(CPUIA64State *env)
{
    env->issue_group.typed_active = false;
    env->issue_group.saved_br_mask = 1u << 5;
    env->issue_group.saved_br[5] = UINT64_C(0x0123456789abcdef);
}

static void corrupt_br_forward_at_fresh_frontier(CPUIA64State *env)
{
    env->instruction_group_start = true;
    env->issue_group.branch_br_forward_mask = 1u << 1;
}

static void corrupt_br_forward_without_typed_owner(CPUIA64State *env)
{
    env->issue_group.typed_active = false;
    env->issue_group.branch_br_forward_mask = 1u << 7;
}

static void corrupt_pfs_without_typed_owner(CPUIA64State *env)
{
    env->issue_group.typed_active = false;
    env->issue_group.pfs_saved = true;
    env->issue_group.saved_pfs = UINT64_C(0x1234);
}

static void corrupt_pfs_forward_without_saved_source(CPUIA64State *env)
{
    env->issue_group.branch_pfs_forwarded = true;
}

static void corrupt_gr0(CPUIA64State *env)
{
    env->issue_group.saved_gr_mask[0] = 1;
}

static void corrupt_nat(CPUIA64State *env)
{
    env->issue_group.saved_gr_mask[0] = UINT64_C(1) << 3;
    env->issue_group.saved_nat[3] = 2;
}

static void corrupt_pr(CPUIA64State *env)
{
    env->issue_group.pr_saved = true;
    env->issue_group.saved_pr = UINT64_C(0x20);
}

static void corrupt_ar_count(CPUIA64State *env)
{
    env->issue_group.saved_ar_count = IA64_ISSUE_GROUP_AR_CAPACITY + 1;
}

static void corrupt_ar_index(CPUIA64State *env)
{
    env->issue_group.saved_ar_count = 1;
    env->issue_group.saved_ar_index[0] = IA64_AR_COUNT;
}

static void corrupt_ar_duplicate(CPUIA64State *env)
{
    env->issue_group.saved_ar_count = 2;
    env->issue_group.saved_ar_index[0] = IA64_AR_UNAT;
    env->issue_group.saved_ar_index[1] = IA64_AR_UNAT;
}

static void corrupt_ar_without_typed_owner(CPUIA64State *env)
{
    env->issue_group.typed_active = false;
    env->issue_group.saved_ar_count = 1;
    env->issue_group.saved_ar_index[0] = IA64_AR_CSD;
    env->issue_group.saved_ar_value[0] = UINT64_C(0x1234);
}

static void corrupt_ar_at_fresh_frontier(CPUIA64State *env)
{
    env->instruction_group_start = true;
    env->issue_group.saved_ar_count = 1;
    env->issue_group.saved_ar_index[0] = IA64_AR_CSD;
    env->issue_group.saved_ar_value[0] = UINT64_C(0x5678);
}

static void corrupt_fr0(CPUIA64State *env)
{
    env->issue_group.saved_fr_mask[0] = UINT64_C(1) << 0;
}

static void corrupt_fr1(CPUIA64State *env)
{
    env->issue_group.saved_fr_mask[0] = UINT64_C(1) << 1;
}

static void corrupt_fr_without_typed_owner(CPUIA64State *env)
{
    env->issue_group.typed_active = false;
    env->issue_group.saved_fr_mask[0] = UINT64_C(1) << 2;
    env->issue_group.saved_fr[2].raw[0] = UINT64_C(0x1234);
}

static void corrupt_fr_at_fresh_frontier(CPUIA64State *env)
{
    env->instruction_group_start = true;
    env->issue_group.saved_fr_mask[1] = UINT64_C(1) << (127 - 64);
    env->issue_group.saved_fr[127].raw[1] = UINT64_C(0x5678);
}

static void test_reject_fresh_frontier(void)
{
    assert_load_rejected(corrupt_fresh_frontier);
}

static void test_reject_missing_typed_owner(void)
{
    assert_load_rejected(corrupt_missing_typed_owner);
}

static void test_reject_forward_at_fresh_frontier(void)
{
    assert_load_rejected(corrupt_forward_at_fresh_frontier);
}

static void test_reject_forward_without_typed_owner(void)
{
    assert_load_rejected(corrupt_forward_without_typed_owner);
}

static void test_reject_forward_p0(void)
{
    assert_load_rejected(corrupt_forward_p0);
}

static void test_reject_br_at_fresh_frontier(void)
{
    assert_load_rejected(corrupt_br_at_fresh_frontier);
}

static void test_reject_br_without_typed_owner(void)
{
    assert_load_rejected(corrupt_br_without_typed_owner);
}

static void test_reject_br_forward_at_fresh_frontier(void)
{
    assert_load_rejected(corrupt_br_forward_at_fresh_frontier);
}

static void test_reject_br_forward_without_typed_owner(void)
{
    assert_load_rejected(corrupt_br_forward_without_typed_owner);
}

static void test_reject_gr0(void)
{
    assert_load_rejected(corrupt_gr0);
}

static void test_reject_non_boolean_nat(void)
{
    assert_load_rejected(corrupt_nat);
}

static void test_reject_pr_without_p0(void)
{
    assert_load_rejected(corrupt_pr);
}

static void test_reject_pfs_without_typed_owner(void)
{
    assert_load_rejected(corrupt_pfs_without_typed_owner);
}

static void test_reject_pfs_forward_without_saved_source(void)
{
    assert_load_rejected(corrupt_pfs_forward_without_saved_source);
}

static void test_reject_ar_count(void)
{
    assert_load_rejected(corrupt_ar_count);
}

static void test_reject_ar_index(void)
{
    assert_load_rejected(corrupt_ar_index);
}

static void test_reject_ar_duplicate(void)
{
    assert_load_rejected(corrupt_ar_duplicate);
}

static void test_reject_ar_without_typed_owner(void)
{
    assert_load_rejected(corrupt_ar_without_typed_owner);
}

static void test_reject_ar_at_fresh_frontier(void)
{
    assert_load_rejected(corrupt_ar_at_fresh_frontier);
}

static void test_reject_fr0_fr1(void)
{
    assert_load_rejected(corrupt_fr0);
    assert_load_rejected(corrupt_fr1);
}

static void test_reject_fr_without_typed_owner(void)
{
    assert_load_rejected(corrupt_fr_without_typed_owner);
}

static void test_reject_fr_at_fresh_frontier(void)
{
    assert_load_rejected(corrupt_fr_at_fresh_frontier);
}

static void test_pre_save_valid_typed(void)
{
    CPUIA64State env;

    init_typed_source(&env);
    env.issue_group.saved_gr_mask[0] = UINT64_C(1) << 4;
    env.issue_group.saved_gr[4] = UINT64_C(0x76543210fedcba98);
    env.issue_group.saved_nat[4] = 1;
    g_assert_cmpint(ia64_env_pre_save(&env), ==, 0);
}

static void test_pre_save_reject_fresh_typed(void)
{
    CPUIA64State env;

    init_typed_source(&env);
    env.instruction_group_start = true;
    g_assert_cmpint(ia64_env_pre_save(&env), ==, -EINVAL);
}

static void test_pre_save_reject_orphan_overlay(void)
{
    CPUIA64State env;

    init_typed_source(&env);
    env.issue_group.typed_active = false;
    env.issue_group.saved_gr_mask[1] = UINT64_C(1) << 7;
    env.issue_group.saved_gr[71] = UINT64_C(0xabcdef0123456789);
    env.issue_group.saved_nat[71] = 0;
    g_assert_cmpint(ia64_env_pre_save(&env), ==, -EINVAL);
}

static void test_pre_save_fr_overlay_validation(void)
{
    CPUIA64State env;

    init_typed_source(&env);
    env.issue_group.saved_fr_mask[0] = UINT64_C(1) << 2;
    env.issue_group.saved_fr_mask[1] = UINT64_C(1) << (127 - 64);
    env.issue_group.saved_fr[2].raw[0] =
        UINT64_C(0x0123456789abcdef);
    env.issue_group.saved_fr[127].raw[1] =
        UINT64_C(0xfedcba9876543210);
    g_assert_cmpint(ia64_env_pre_save(&env), ==, 0);

    init_typed_source(&env);
    corrupt_fr0(&env);
    g_assert_cmpint(ia64_env_pre_save(&env), ==, -EINVAL);

    init_typed_source(&env);
    corrupt_fr1(&env);
    g_assert_cmpint(ia64_env_pre_save(&env), ==, -EINVAL);

    init_typed_source(&env);
    corrupt_fr_without_typed_owner(&env);
    g_assert_cmpint(ia64_env_pre_save(&env), ==, -EINVAL);

    init_typed_source(&env);
    corrupt_fr_at_fresh_frontier(&env);
    g_assert_cmpint(ia64_env_pre_save(&env), ==, -EINVAL);
}

static void test_pre_save_reject_dirty_breadcrumb(void)
{
    CPUIA64State env;

    init_typed_source(&env);
    env.instruction_group_dirty = true;
    g_assert_cmpint(ia64_env_pre_save(&env), ==, -EINVAL);
}

static void test_pre_save_canonicalizes_ri(void)
{
    CPUIA64State env = { 0 };
    uint64_t expected_psr;

    env.instruction_group_start = true;
    env.rse.invalid = IA64_GR_COUNT - IA64_STATIC_GR_COUNT;
    env.psr = UINT64_C(0x123456789abcdef0);
    env.ri = 2;
    env.ri_dirty = true;
    expected_psr = ia64_psr_with_ri(env.psr, env.ri);

    g_assert_cmpint(ia64_env_pre_save(&env), ==, 0);
    g_assert_cmpuint(env.psr, ==, expected_psr);
    g_assert_cmpuint(ia64_psr_ri(env.psr), ==, 2);
    g_assert_cmpuint(env.ri, ==, 2);
    g_assert_false(env.ri_dirty);
}

static void test_pre_save_flushes_only_dirty_logical_names(void)
{
    static const unsigned dirty_names[] = { 0, 1, 15, 16, 63, 64, 95 };
    CPUIA64State env = { 0 };
    uint64_t clean_physical_value;
    bool clean_physical_nat;
    uint32_t clean_slot;

    env.instruction_group_start = true;
    env.pr = 1;
    env.rse.invalid = IA64_GR_COUNT - IA64_STATIC_GR_COUNT;
    env.rse.current_frame_base = IA64_STACKED_GR_COUNT - 6;
    env.rse.sor = 2;
    env.rse.rrb_gr = 5;
    for (unsigned slot = 0; slot < IA64_STACKED_GR_COUNT; slot++) {
        env.rse.stacked_gr[slot] =
            UINT64_C(0xd000000000000000) | slot;
        test_set_physical_nat(&env, slot, (slot & 1) != 0);
    }
    for (unsigned logical = 0;
         logical < IA64_GR_COUNT - IA64_STATIC_GR_COUNT; logical++) {
        env.gr[IA64_STATIC_GR_COUNT + logical] =
            UINT64_C(0xa100000000000000) | logical;
        test_set_word_bit(env.rse.logical_nat, logical,
                          (logical % 3) == 1);
    }
    for (unsigned i = 0; i < ARRAY_SIZE(dirty_names); i++) {
        test_set_word_bit(env.rse.logical_dirty, dirty_names[i], true);
    }

    /* A clean mismatch must remain physical-authoritative at sync-out. */
    clean_slot = test_logical_stacked_slot(&env, 2);
    clean_physical_value = env.rse.stacked_gr[clean_slot];
    clean_physical_nat = test_physical_nat(&env, clean_slot);

    rse_hook_sequence = 0;
    rse_sync_out_order = 0;
    rse_sync_out_count = 0;
    g_assert_cmpint(ia64_env_pre_save(&env), ==, 0);
    g_assert_cmpuint(rse_sync_out_count, ==, 1);
    g_assert_cmpuint(rse_sync_out_order, >, 0);
    g_assert_cmphex(env.rse.logical_dirty[0], ==, 0);
    g_assert_cmphex(env.rse.logical_dirty[1], ==, 0);

    for (unsigned i = 0; i < ARRAY_SIZE(dirty_names); i++) {
        unsigned logical = dirty_names[i];
        uint32_t slot = test_logical_stacked_slot(&env, logical);

        g_assert_cmphex(env.rse.stacked_gr[slot], ==,
                        env.gr[IA64_STATIC_GR_COUNT + logical]);
        g_assert_cmpint(test_physical_nat(&env, slot), ==,
                        test_word_bit(env.rse.logical_nat, logical));
    }
    g_assert_cmphex(env.rse.stacked_gr[clean_slot], ==,
                    clean_physical_value);
    g_assert_cmpint(test_physical_nat(&env, clean_slot), ==,
                    clean_physical_nat);
}

static void seed_physical_logical_mapping(CPUIA64State *env,
                                          uint32_t frame_base,
                                          uint32_t sor,
                                          uint32_t rrb_gr)
{
    env->rse.current_frame_base = frame_base;
    env->rse.sor = sor;
    env->rse.rrb_gr = rrb_gr;
    memset(env->rse.stacked_gr, 0, sizeof(env->rse.stacked_gr));
    memset(env->rse.stacked_nat, 0, sizeof(env->rse.stacked_nat));
    for (unsigned logical = 0;
         logical < IA64_GR_COUNT - IA64_STATIC_GR_COUNT; logical++) {
        uint32_t slot = test_logical_stacked_slot(env, logical);

        env->rse.stacked_gr[slot] =
            UINT64_C(0x5100000000000000) |
            ((uint64_t)frame_base << 16) | logical;
        test_set_physical_nat(env, slot, (logical % 5) == 2);
        env->gr[IA64_STATIC_GR_COUNT + logical] =
            UINT64_C(0xbad0000000000000) | logical;
    }
    env->rse.logical_nat[0] = UINT64_MAX;
    env->rse.logical_nat[1] = UINT64_MAX;
    env->rse.logical_dirty[0] = UINT64_MAX;
    env->rse.logical_dirty[1] = UINT64_MAX;
}

static void assert_logical_mirror_matches_physical(const CPUIA64State *env)
{
    for (unsigned logical = 0;
         logical < IA64_GR_COUNT - IA64_STATIC_GR_COUNT; logical++) {
        uint32_t slot = test_logical_stacked_slot(env, logical);

        g_assert_cmphex(env->gr[IA64_STATIC_GR_COUNT + logical], ==,
                        env->rse.stacked_gr[slot]);
        g_assert_cmpint(test_word_bit(env->rse.logical_nat, logical), ==,
                        test_physical_nat(env, slot));
    }
    g_assert_cmphex(env->rse.logical_dirty[0], ==, 0);
    g_assert_cmphex(env->rse.logical_dirty[1], ==, 0);
    /* Only 96 architectural logical names exist. */
    g_assert_cmphex(env->rse.logical_nat[1] >> 32, ==, 0);
}

static void test_post_load_reconstructs_wrapped_rotating_mirror(void)
{
    IA64CPU cpu = { 0 };
    CPUIA64State *env = &cpu.env;

    env->instruction_group_start = true;
    env->pr = 1;
    seed_physical_logical_mapping(env, IA64_STACKED_GR_COUNT - 7, 3, 19);
    g_assert_cmpint(ia64_env_pre_load(env), ==, 0);
    g_assert_cmphex(env->rse.logical_nat[0], ==, 0);
    g_assert_cmphex(env->rse.logical_nat[1], ==, 0);
    g_assert_cmphex(env->rse.logical_dirty[0], ==, 0);
    g_assert_cmphex(env->rse.logical_dirty[1], ==, 0);
    rse_hook_sequence = 0;
    rse_reconstruct_order = 0;
    rse_sync_in_order = 0;
    rse_sync_in_count = 0;

    g_assert_cmpint(ia64_env_post_load(env, 8), ==, 0);
    g_assert_cmpuint(rse_sync_in_count, ==, 1);
    g_assert_cmpuint(rse_reconstruct_order, >, 0);
    g_assert_cmpuint(rse_sync_in_order, >, rse_reconstruct_order);
    assert_logical_mirror_matches_physical(env);
}

static void test_pre_load_clears_transient_mirror_metadata(void)
{
    CPUIA64State env = { 0 };

    env.rse.logical_nat[0] = UINT64_MAX;
    env.rse.logical_nat[1] = UINT64_MAX;
    env.rse.logical_dirty[0] = UINT64_MAX;
    env.rse.logical_dirty[1] = UINT64_MAX;
    env.rse.cfle = true;
    env.rse.reference = true;
    env.current_slot_valid = true;
    env.current_slot_ri = 2;
    env.current_slot_type = 7;
    env.current_slot_speculative_load = true;
    env.current_slot_ip = UINT64_C(0x123456789abcdef0);
    env.current_slot_raw = UINT64_C(0x1ffffffffff);
    g_assert_cmpint(ia64_env_pre_load(&env), ==, 0);
    g_assert_cmphex(env.rse.logical_nat[0], ==, 0);
    g_assert_cmphex(env.rse.logical_nat[1], ==, 0);
    g_assert_cmphex(env.rse.logical_dirty[0], ==, 0);
    g_assert_cmphex(env.rse.logical_dirty[1], ==, 0);
    g_assert_false(env.rse.cfle);
    g_assert_false(env.rse.reference);
    g_assert_false(env.current_slot_valid);
    g_assert_cmpuint(env.current_slot_ri, ==, 0);
    g_assert_cmpuint(env.current_slot_type, ==, 0);
    g_assert_false(env.current_slot_speculative_load);
    g_assert_cmphex(env.current_slot_ip, ==, 0);
    g_assert_cmphex(env.current_slot_raw, ==, 0);
}

static void test_post_load_v8_reconstructs_logical_mirror(void)
{
    IA64CPU cpu = { 0 };
    CPUIA64State *env = &cpu.env;

    env->instruction_group_start = true;
    env->pr = 1;
    env->interrupt.timer_compare_latched = 1;
    seed_physical_logical_mapping(
        env, IA64_STACKED_GR_COUNT - 1, 2, 24);
    g_assert_cmpint(ia64_env_pre_load(env), ==, 0);
    g_assert_cmphex(env->rse.logical_dirty[0], ==, 0);
    g_assert_cmphex(env->rse.logical_dirty[1], ==, 0);
    rse_hook_sequence = 0;
    rse_reconstruct_order = 0;
    rse_sync_in_order = 0;
    rse_sync_in_count = 0;

    g_assert_cmpint(ia64_env_post_load(env, 8), ==, 0);
    g_assert_cmpuint(env->interrupt.timer_compare_latched, ==, 1);
    g_assert_cmpuint(rse_sync_in_count, ==, 1);
    g_assert_cmpuint(rse_sync_in_order, >, rse_reconstruct_order);
    assert_logical_mirror_matches_physical(env);
}

static void test_interrupt_state_round_trip(void)
{
    IA64InterruptState source = {
        .in_service = {
            0,
            UINT64_C(1) << (0x45 & 63),
            UINT64_C(1) << (0x80 & 63),
            0,
        },
        .pending_vector = UINT64_C(0xee),
        .timer_compare_latched = IA64_TIMER_COMPARE_CONSUMED,
        .pending = 1,
    };
    IA64InterruptState destination;

    g_assert_cmpint(vmstate_interrupt.version_id, ==, 3);
    g_assert_cmpint(vmstate_interrupt.minimum_version_id, ==, 3);
    g_assert_cmpint(save_interrupt_state(&source), ==, 0);
    memset(&destination, 0xa5, sizeof(destination));
    g_assert_cmpint(load_interrupt_state(&destination), ==, 0);

    for (unsigned i = 0; i < ARRAY_SIZE(source.in_service); i++) {
        g_assert_cmphex(destination.in_service[i], ==, source.in_service[i]);
    }
    g_assert_cmpuint(destination.timer_compare_latched, ==,
                     IA64_TIMER_COMPARE_CONSUMED);
    /* These are runtime caches rebuilt from CR.IRR*, not wire authority. */
    g_assert_cmphex(destination.pending_vector, ==, 0);
    g_assert_cmpuint(destination.pending, ==, 0);
    g_assert_cmphex(destination.legacy_pending_interruption, ==, 0);
}

static void test_interrupt_vmstate_rejects_invalid_state(void)
{
    IA64InterruptState interrupt = { 0 };

    interrupt.in_service[0] = UINT64_C(1) << 1;
    g_assert_cmpint(save_interrupt_state(&interrupt), ==, -EINVAL);

    memset(&interrupt, 0, sizeof(interrupt));
    interrupt.timer_compare_latched = IA64_TIMER_COMPARE_ARMED + 1;
    g_assert_cmpint(save_interrupt_state(&interrupt), ==, -EINVAL);
}

static void test_interrupt_pending_in_service_cpu_round_trip(void)
{
    IA64CPU source;
    IA64CPU destination;
    const uint64_t vector45 = UINT64_C(1) << (0x45 & 63);
    const uint64_t vector80 = UINT64_C(1) << (0x80 & 63);

    init_cpu_stream(&source, 0, false);
    source.env.psr = UINT64_C(1) << 14;
    source.env.cr[IA64_CR_IRR1] = vector45;
    source.env.interrupt.in_service[1] = vector45;
    source.env.interrupt.in_service[2] = vector80;
    source.env.interrupt.timer_compare_latched =
        IA64_TIMER_COMPARE_CONSUMED;
    /* Poisoned derived state must not become wire authority. */
    source.env.interrupt.pending = 0;
    source.env.interrupt.pending_vector = UINT64_MAX;
    interrupt_reconcile_count = 0;
    interrupt_refresh_delivery_count = 0;
    g_assert_cmpint(save_cpu_with_vmsd(
                        &source, &vmstate_collection_test_root), ==, 0);

    init_cpu_stream(&destination, 0, false);
    g_assert_cmpint(load_cpu_with_current_root(&destination), ==, 0);
    g_assert_cmphex(destination.env.cr[IA64_CR_IRR1], ==, vector45);
    g_assert_cmphex(destination.env.interrupt.in_service[1], ==, vector45);
    g_assert_cmphex(destination.env.interrupt.in_service[2], ==, vector80);
    g_assert_cmpuint(destination.env.interrupt.timer_compare_latched, ==,
                     IA64_TIMER_COMPARE_CONSUMED);
    g_assert_cmpuint(interrupt_reconcile_count, ==, 1);
    g_assert_cmpuint(interrupt_refresh_delivery_count, ==, 1);
    g_assert_true(destination.env.interrupt.pending);
    g_assert_cmphex(destination.env.interrupt.pending_vector, ==, 0x45);
    g_assert_cmphex(qatomic_read(&destination.parent_obj.interrupt_request) &
                    CPU_INTERRUPT_HARD, ==, CPU_INTERRUPT_HARD);

    /* A stale HARD request is discarded when authoritative IRR is empty. */
    init_cpu_stream(&source, 0, false);
    g_assert_cmpint(save_cpu_with_vmsd(
                        &source, &vmstate_collection_test_root), ==, 0);
    init_cpu_stream(&destination, 0, false);
    qatomic_set(&destination.parent_obj.interrupt_request,
                CPU_INTERRUPT_HARD);
    interrupt_reconcile_count = 0;
    interrupt_refresh_delivery_count = 0;
    g_assert_cmpint(load_cpu_with_current_root(&destination), ==, 0);
    g_assert_cmpuint(interrupt_reconcile_count, ==, 1);
    g_assert_cmpuint(interrupt_refresh_delivery_count, ==, 1);
    g_assert_false(destination.env.interrupt.pending);
    g_assert_cmphex(qatomic_read(&destination.parent_obj.interrupt_request) &
                    CPU_INTERRUPT_HARD, ==, 0);
}

static void test_stream_ignores_stale_serialized_logical_gr(void)
{
    IA64CPU source;
    IA64CPU destination;
    uint64_t stale_gr32;

    /* The transient mirror must not manufacture a new wire generation. */
    g_assert_cmpint(vmstate_rse.version_id, ==, 5);
    g_assert_cmpint(vmstate_rse.minimum_version_id, ==, 5);
    g_assert_cmpint(vmstate_issue_group_overlay.version_id, ==, 6);
    g_assert_cmpint(vmstate_env.version_id, ==, 8);
    g_assert_cmpint(vmstate_env.minimum_version_id, ==, 8);
    g_assert_cmpint(vmstate_ia64_cpu.version_id, ==, 6);
    g_assert_cmpint(vmstate_ia64_cpu.minimum_version_id, ==, 6);
    init_cpu_stream(&source, 0, false);
    seed_physical_logical_mapping(
        &source.env, IA64_STACKED_GR_COUNT - 9, 4, 27);
    /* The serialized logical GR image is stale and no mirror is dirty. */
    source.env.rse.logical_dirty[0] = 0;
    source.env.rse.logical_dirty[1] = 0;
    stale_gr32 = source.env.gr[32];
    g_assert_cmphex(stale_gr32, !=,
                    source.env.rse.stacked_gr[
                        test_logical_stacked_slot(&source.env, 0)]);
    g_assert_cmpint(save_cpu_with_vmsd(
                        &source, &vmstate_collection_test_root), ==, 0);

    init_cpu_stream(&destination, 0, false);
    destination.env.rse.logical_nat[0] = UINT64_MAX;
    destination.env.rse.logical_nat[1] = UINT64_MAX;
    destination.env.rse.logical_dirty[0] = UINT64_MAX;
    destination.env.rse.logical_dirty[1] = UINT64_MAX;
    g_assert_cmpint(load_cpu_with_current_root(&destination), ==, 0);

    assert_logical_mirror_matches_physical(&destination.env);
    g_assert_cmphex(destination.env.gr[32], !=, stale_gr32);
}

static void test_alat_target_type_round_trip(void)
{
    IA64AlatState source = { 0 };
    IA64AlatState destination;

    source.next = 2;
    source.entries[0] = (IA64AlatEntry) {
        .valid = true,
        .target = 12,
        .target_type = IA64_ALAT_TARGET_GR,
        .width = 8,
        .physical = true,
        .address = UINT64_C(0x12345000),
    };
    source.entries[1] = (IA64AlatEntry) {
        .valid = true,
        .target = 47,
        .target_type = IA64_ALAT_TARGET_FR,
        .width = 10,
        .physical = false,
        .address = UINT64_C(0xfeed0000),
    };

    g_assert_cmpint(save_alat_with_vmsd(&source, &vmstate_alat), ==, 0);
    memset(&destination, 0xa5, sizeof(destination));
    g_assert_cmpint(load_alat_with_current_vmsd(&destination), ==, 0);

    g_assert_cmpuint(destination.next, ==, 2);
    g_assert_true(destination.entries[0].valid);
    g_assert_cmpuint(destination.entries[0].target_type, ==,
                     IA64_ALAT_TARGET_GR);
    g_assert_cmpuint(destination.entries[0].target, ==, 12);
    g_assert_cmpuint(destination.entries[0].width, ==, 8);
    g_assert_true(destination.entries[0].physical);
    g_assert_cmphex(destination.entries[0].address, ==,
                    UINT64_C(0x12345000));
    g_assert_true(destination.entries[1].valid);
    g_assert_cmpuint(destination.entries[1].target_type, ==,
                     IA64_ALAT_TARGET_FR);
    g_assert_cmpuint(destination.entries[1].target, ==, 47);
    g_assert_cmpuint(destination.entries[1].width, ==, 10);
    g_assert_false(destination.entries[1].physical);
    g_assert_cmphex(destination.entries[1].address, ==,
                    UINT64_C(0xfeed0000));
    /* These summaries remain transient wire-independent GR-only state. */
    g_assert_cmpuint(destination.valid_mask, ==, 0);
    g_assert_cmphex(destination.gr_mask[0], ==, 0);
    g_assert_cmphex(destination.gr_mask[1], ==, 0);
}

static void test_alat_vmstate_rejects_invalid_entries(void)
{
    IA64AlatState alat = { 0 };

    alat.entries[0].target_type = IA64_ALAT_TARGET_TYPE_COUNT;
    g_assert_cmpint(ia64_alat_vmstate_post_load(&alat, 1), ==, -EINVAL);

    memset(&alat, 0, sizeof(alat));
    alat.entries[0] = (IA64AlatEntry) {
        .valid = true,
        .target = 0,
        .target_type = IA64_ALAT_TARGET_GR,
        .width = 8,
    };
    g_assert_cmpint(ia64_alat_vmstate_post_load(&alat, 1), ==, -EINVAL);

    alat.entries[0].target = 12;
    alat.entries[0].width = 10;
    g_assert_cmpint(ia64_alat_vmstate_post_load(&alat, 1), ==, -EINVAL);

    alat.entries[0].target_type = IA64_ALAT_TARGET_FR;
    alat.entries[0].target = 1;
    alat.entries[0].width = 8;
    g_assert_cmpint(ia64_alat_vmstate_post_load(&alat, 1), ==, -EINVAL);

    alat.entries[0].target = 12;
    alat.entries[0].width = 2;
    g_assert_cmpint(ia64_alat_vmstate_post_load(&alat, 1), ==, -EINVAL);

    alat.entries[0].width = 16;
    alat.next = IA64_ALAT_COUNT;
    g_assert_cmpint(ia64_alat_vmstate_post_load(&alat, 1), ==, -EINVAL);

    alat.next = 1;
    g_assert_cmpint(ia64_alat_vmstate_post_load(&alat, 1), ==, 0);
}

static void test_collection_state_subsection_round_trip(void)
{
    static const struct {
        uint64_t last_successful_bundle;
        bool psr_ic_inflight;
    } rows[] = {
        { 0, false },
        { 0, true },
        { UINT64_C(0x123456789abcde0), false },
        { UINT64_C(0xfedcba987654320), true },
    };

    for (unsigned i = 0; i < ARRAY_SIZE(rows); i++) {
        IA64CPU source;
        IA64CPU destination;

        init_cpu_stream(&source, rows[i].last_successful_bundle,
                        rows[i].psr_ic_inflight);
        source.env.rse.bsp_load = UINT64_C(0x8877665544332211);
        g_assert_cmpint(save_cpu_with_vmsd(
                            &source, &vmstate_collection_test_root), ==, 0);

        init_cpu_stream(&destination, UINT64_MAX,
                        !rows[i].psr_ic_inflight);
        g_assert_cmpint(load_cpu_with_current_root(&destination), ==, 0);
        g_assert_cmphex(destination.env.last_successful_bundle, ==,
                        rows[i].last_successful_bundle);
        g_assert_cmpint(destination.env.psr_ic_inflight, ==,
                        rows[i].psr_ic_inflight);
        g_assert_cmphex(destination.env.rse.bsp_load, ==,
                        UINT64_C(0x8877665544332211));
    }
}

static void seed_complete_rse_vmstate(IA64RSEState *rse)
{
    memset(rse, 0, sizeof(*rse));
    rse->rsc = UINT64_C(0x1122334455667788);
    rse->bsp = UINT64_C(0x1050);
    rse->bspstore = UINT64_C(0x1000);
    rse->rnat = UINT64_C(0x0123456789abcdef);
    rse->loadrs = UINT64_C(0x80);
    rse->sof = 20;
    rse->sol = 7;
    rse->sor = 2;
    rse->rrb_gr = 5;
    rse->rrb_fr = 9;
    rse->rrb_pr = 11;
    rse->current_frame_base = IA64_STACKED_GR_COUNT - 6;
    rse->bol = 7;
    rse->dirty = 10;
    rse->dirty_nat = 0;
    rse->clean = 30;
    rse->clean_nat = 1;
    rse->invalid = 36;
    rse->stacked_gr[0] = UINT64_C(0xfeedfacecafebeef);
    rse->stacked_gr[IA64_STACKED_GR_COUNT - 1] =
        UINT64_C(0x8877665544332211);
    rse->stacked_nat[0] = UINT64_C(0x8000000000000001);
    rse->stacked_nat[IA64_RSE_NAT_WORDS - 1] =
        UINT64_C(0x4000000000000002);
}

static void seed_incomplete_rse_vmstate(IA64RSEState *rse)
{
    memset(rse, 0, sizeof(*rse));
    /* Two register words followed by the 0x7ff8 RNAT collection word. */
    rse->bsp = UINT64_C(0x7fe8);
    rse->bspstore = UINT64_C(0x8000);
    rse->rnat = UINT64_C(0x5555aaaa0000ffff);
    rse->sof = 20;
    rse->sol = 4;
    rse->current_frame_base = 3;
    rse->bol = 95;
    rse->dirty = -2;
    rse->dirty_nat = -1;
    rse->clean = 0;
    rse->clean_nat = 0;
    rse->invalid = 78;
    rse->stacked_gr[3] = UINT64_C(0x123456789abcdef0);
    rse->stacked_nat[0] = UINT64_C(1) << 3;
}

static void test_typed_only_version_boundary(void)
{
    IA64CPU cpu;
    IA64RSEState rse;

    init_cpu_stream(&cpu, 0, false);
    seed_complete_rse_vmstate(&rse);

    g_assert_cmpint(vmstate_ia64_cpu.version_id, ==, 6);
    g_assert_cmpint(vmstate_ia64_cpu.minimum_version_id, ==, 6);
    g_assert_cmpint(vmstate_collection_test_root.version_id, ==, 6);
    g_assert_cmpint(vmstate_collection_test_root.minimum_version_id, ==, 6);
    g_assert_cmpint(vmstate_env.version_id, ==, 8);
    g_assert_cmpint(vmstate_env.minimum_version_id, ==, 8);
    g_assert_cmpint(vmstate_rse.version_id, ==, 5);
    g_assert_cmpint(vmstate_rse.minimum_version_id, ==, 5);
    g_assert_true(ia64_cpu_uses_env_v8(NULL, 6));
    g_assert_false(ia64_cpu_uses_env_v8(NULL, 5));
    g_assert_true(ia64_env_uses_rse_v5(NULL, 8));
    g_assert_false(ia64_env_uses_rse_v5(NULL, 7));

    g_assert_cmpint(ia64_cpu_post_load(&cpu, 5), ==, -EINVAL);
    g_assert_cmpint(ia64_env_post_load(&cpu.env, 7), ==, -EINVAL);
    g_assert_cmpint(ia64_rse_vmstate_post_load(&rse, 4), ==, -EINVAL);
}

static void assert_rse_canonical_equal(const IA64RSEState *actual,
                                       const IA64RSEState *expected)
{
    g_assert_cmphex(actual->rsc, ==, expected->rsc);
    g_assert_cmphex(actual->bsp, ==, expected->bsp);
    g_assert_cmphex(actual->bspstore, ==, expected->bspstore);
    g_assert_cmphex(actual->rnat, ==, expected->rnat);
    g_assert_cmphex(actual->loadrs, ==, expected->loadrs);
    g_assert_cmpuint(actual->sof, ==, expected->sof);
    g_assert_cmpuint(actual->sol, ==, expected->sol);
    g_assert_cmpuint(actual->sor, ==, expected->sor);
    g_assert_cmpuint(actual->rrb_gr, ==, expected->rrb_gr);
    g_assert_cmpuint(actual->rrb_fr, ==, expected->rrb_fr);
    g_assert_cmpuint(actual->rrb_pr, ==, expected->rrb_pr);
    g_assert_cmpuint(actual->current_frame_base, ==,
                     expected->current_frame_base);
    g_assert_cmpuint(actual->bol, ==, expected->bol);
    g_assert_cmpint(actual->dirty, ==, expected->dirty);
    g_assert_cmpint(actual->dirty_nat, ==, expected->dirty_nat);
    g_assert_cmpint(actual->clean, ==, expected->clean);
    g_assert_cmpint(actual->clean_nat, ==, expected->clean_nat);
    g_assert_cmpint(actual->invalid, ==, expected->invalid);
    g_assert_cmpmem(actual->stacked_gr, sizeof(actual->stacked_gr),
                    expected->stacked_gr, sizeof(expected->stacked_gr));
    g_assert_cmpmem(actual->stacked_nat, sizeof(actual->stacked_nat),
                    expected->stacked_nat, sizeof(expected->stacked_nat));
    g_assert_cmpint(actual->cfle, ==, expected->cfle);
    g_assert_false(actual->reference);
}

static void test_rse_v5_complete_and_incomplete_round_trip(void)
{
    for (unsigned active_cfle = 0; active_cfle < 2; active_cfle++) {
        for (unsigned incomplete = 0; incomplete < 2; incomplete++) {
            IA64RSEState source;
            IA64RSEState destination;

            if (incomplete) {
                seed_incomplete_rse_vmstate(&source);
            } else {
                seed_complete_rse_vmstate(&source);
            }
            source.cfle = active_cfle;
            g_assert_cmpint(save_rse_with_vmsd(
                                &source, &vmstate_rse), ==, 0);
            memset(&destination, 0xa5, sizeof(destination));
            g_assert_cmpint(load_rse_with_current_vmsd(
                                &destination), ==, 0);
            assert_rse_canonical_equal(&destination, &source);
        }
    }
}

static void test_cpu_v6_active_cfle_round_trip(void)
{
    for (unsigned incomplete = 0; incomplete < 2; incomplete++) {
        IA64CPU source;
        IA64CPU destination;

        init_cpu_stream(&source, UINT64_C(0x1230), false);
        if (incomplete) {
            seed_incomplete_rse_vmstate(&source.env.rse);
        } else {
            seed_complete_rse_vmstate(&source.env.rse);
        }
        source.env.rse.cfle = true;
        source.env.rse.bsp_load = source.env.rse.bspstore;
        source.env.ar[IA64_AR_BSP] = source.env.rse.bsp;
        source.env.ar[IA64_AR_BSPSTORE] = source.env.rse.bspstore;
        source.env.cr[IA64_CR_IIP] = UINT64_C(0x200);
        source.env.cr[IA64_CR_IFS] = 0;

        g_assert_cmpint(save_cpu_with_vmsd(
                            &source, &vmstate_collection_test_root), ==, 0);
        init_cpu_stream(&destination, 0, false);
        destination.env.rse.bsp_load = UINT64_MAX;
        g_assert_cmpint(load_cpu_with_current_root(&destination), ==, 0);

        assert_rse_canonical_equal(&destination.env.rse, &source.env.rse);
        g_assert_true(destination.env.rse.cfle);
        g_assert_cmphex(destination.env.rse.bsp_load, ==,
                        source.env.rse.bspstore);
        g_assert_cmphex(destination.env.cr[IA64_CR_IIP], ==,
                        UINT64_C(0x200));
        g_assert_cmphex(destination.env.cr[IA64_CR_IFS], ==, 0);
    }
}

typedef void (*CorruptRSEState)(IA64RSEState *rse);

static void assert_rse_v5_load_rejected(CorruptRSEState corrupt)
{
    IA64RSEState source;
    IA64RSEState destination;

    seed_complete_rse_vmstate(&source);
    corrupt(&source);
    g_assert_cmpint(save_rse_with_vmsd(&source, &vmstate_rse), ==, 0);
    memset(&destination, 0, sizeof(destination));
    g_assert_cmpint(load_rse_with_current_vmsd(&destination), !=, 0);
}

static void corrupt_rse_bol(IA64RSEState *rse)
{
    rse->bol = IA64_GR_COUNT - IA64_STATIC_GR_COUNT;
}

static void corrupt_rse_partition_sum(IA64RSEState *rse)
{
    rse->invalid--;
}

static void corrupt_rse_bsp_relation(IA64RSEState *rse)
{
    rse->bspstore += 8;
}

static void corrupt_rse_dirty_nat_count(IA64RSEState *rse)
{
    rse->bsp = UINT64_C(0x1058);
    rse->dirty_nat = 1;
}

static void corrupt_rse_clean_nat_count(IA64RSEState *rse)
{
    rse->clean_nat = 0;
}

static void assert_incomplete_rse_v5_load_rejected(CorruptRSEState corrupt)
{
    IA64RSEState source;
    IA64RSEState destination;

    seed_incomplete_rse_vmstate(&source);
    corrupt(&source);
    g_assert_cmpint(save_rse_with_vmsd(&source, &vmstate_rse), ==, 0);
    memset(&destination, 0, sizeof(destination));
    g_assert_cmpint(load_rse_with_current_vmsd(&destination), !=, 0);
}

static void corrupt_rse_incomplete_mixed_sign(IA64RSEState *rse)
{
    /* Preserve both the partition total and combined backing-store words. */
    rse->dirty = -4;
    rse->dirty_nat = 1;
    rse->invalid = 80;
}

static void corrupt_rse_incomplete_word_classes(IA64RSEState *rse)
{
    /* The span contains two registers and one RNAT, not three registers. */
    rse->dirty = -3;
    rse->dirty_nat = 0;
    rse->invalid = 79;
}

static void corrupt_rse_incomplete_clean_partition(IA64RSEState *rse)
{
    rse->clean = 1;
    rse->invalid--;
}

static void test_rse_v5_malformed_rejection(void)
{
    assert_rse_v5_load_rejected(corrupt_rse_bol);
    assert_rse_v5_load_rejected(corrupt_rse_partition_sum);
    assert_rse_v5_load_rejected(corrupt_rse_bsp_relation);
    assert_rse_v5_load_rejected(corrupt_rse_dirty_nat_count);
    assert_rse_v5_load_rejected(corrupt_rse_clean_nat_count);
    assert_incomplete_rse_v5_load_rejected(
        corrupt_rse_incomplete_mixed_sign);
    assert_incomplete_rse_v5_load_rejected(
        corrupt_rse_incomplete_word_classes);
    assert_incomplete_rse_v5_load_rejected(
        corrupt_rse_incomplete_clean_partition);
}

static void test_rse_pre_save_boundaries(void)
{
    CPUIA64State env = { 0 };

    env.instruction_group_start = true;
    env.pr = 1;
    seed_complete_rse_vmstate(&env.rse);
    env.rse.cfle = true;
    g_assert_cmpint(ia64_env_pre_save(&env), ==, 0);
    g_assert_true(env.rse.cfle);

    env.rse.reference = true;
    g_assert_cmpint(ia64_env_pre_save(&env), ==, -EINVAL);

    env.rse.reference = false;
    seed_incomplete_rse_vmstate(&env.rse);
    env.rse.cfle = true;
    env.rse.bsp_load = env.rse.bspstore;
    g_assert_cmpint(ia64_env_pre_save(&env), ==, 0);
    g_assert_true(env.rse.cfle);

    env.rse.bsp_load += 8;
    g_assert_cmpint(ia64_env_pre_save(&env), ==, -EINVAL);
}

int main(int argc, char **argv)
{
    g_autofree char *temp_file = g_strdup_printf("%s/ia64-vmstate.XXXXXX",
                                                 g_get_tmp_dir());
    int ret;

    temp_fd = mkstemp(temp_file);
    g_assert_cmpint(temp_fd, >=, 0);
    module_call_init(MODULE_INIT_QOM);
    g_setenv("QTEST_SILENT_ERRORS", "1", 1);

    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/ia64/vmstate/round-trip/empty-typed",
                    test_empty_typed_continuation);
    g_test_add_func("/ia64/vmstate/round-trip/gr-nat", test_gr_nat_overlay);
    g_test_add_func("/ia64/vmstate/round-trip/fr", test_fr_overlay);
    g_test_add_func("/ia64/vmstate/round-trip/pr", test_pr_overlay);
    g_test_add_func("/ia64/vmstate/round-trip/br", test_br_overlay);
    g_test_add_func("/ia64/vmstate/round-trip/pfs", test_pfs_overlay);
    g_test_add_func("/ia64/vmstate/round-trip/ar", test_ar_overlay);
    g_test_add_func("/ia64/vmstate/round-trip/branch-pr-forward",
                    test_branch_pr_forward_overlay);
    g_test_add_func("/ia64/vmstate/round-trip/branch-br-forward",
                    test_branch_br_forward_overlay);
    g_test_add_func("/ia64/vmstate/round-trip/combined",
                    test_combined_overlay);
    g_test_add_func("/ia64/vmstate/needed/branch-pr-forward",
                    test_branch_pr_forward_needed);
    g_test_add_func("/ia64/vmstate/needed/br-state",
                    test_br_overlay_needed);
    g_test_add_func("/ia64/vmstate/needed/pfs-state",
                    test_pfs_overlay_needed);
    g_test_add_func("/ia64/vmstate/needed/ar-state",
                    test_ar_overlay_needed);
    g_test_add_func("/ia64/vmstate/needed/fr-state",
                    test_fr_overlay_needed);
    g_test_add_func("/ia64/vmstate/reject/fresh-frontier",
                    test_reject_fresh_frontier);
    g_test_add_func("/ia64/vmstate/reject/missing-typed-owner",
                    test_reject_missing_typed_owner);
    g_test_add_func("/ia64/vmstate/reject/forward-at-fresh-frontier",
                    test_reject_forward_at_fresh_frontier);
    g_test_add_func("/ia64/vmstate/reject/forward-without-typed-owner",
                    test_reject_forward_without_typed_owner);
    g_test_add_func("/ia64/vmstate/reject/forward-p0",
                    test_reject_forward_p0);
    g_test_add_func("/ia64/vmstate/reject/br-at-fresh-frontier",
                    test_reject_br_at_fresh_frontier);
    g_test_add_func("/ia64/vmstate/reject/br-without-typed-owner",
                    test_reject_br_without_typed_owner);
    g_test_add_func("/ia64/vmstate/reject/br-forward-at-fresh-frontier",
                    test_reject_br_forward_at_fresh_frontier);
    g_test_add_func("/ia64/vmstate/reject/br-forward-without-typed-owner",
                    test_reject_br_forward_without_typed_owner);
    g_test_add_func("/ia64/vmstate/reject/gr0", test_reject_gr0);
    g_test_add_func("/ia64/vmstate/reject/non-boolean-nat",
                    test_reject_non_boolean_nat);
    g_test_add_func("/ia64/vmstate/reject/pr-without-p0",
                    test_reject_pr_without_p0);
    g_test_add_func("/ia64/vmstate/reject/pfs-without-typed-owner",
                    test_reject_pfs_without_typed_owner);
    g_test_add_func("/ia64/vmstate/reject/pfs-forward-without-saved-source",
                    test_reject_pfs_forward_without_saved_source);
    g_test_add_func("/ia64/vmstate/reject/ar-count",
                    test_reject_ar_count);
    g_test_add_func("/ia64/vmstate/reject/ar-index",
                    test_reject_ar_index);
    g_test_add_func("/ia64/vmstate/reject/ar-duplicate",
                    test_reject_ar_duplicate);
    g_test_add_func("/ia64/vmstate/reject/ar-without-typed-owner",
                    test_reject_ar_without_typed_owner);
    g_test_add_func("/ia64/vmstate/reject/ar-at-fresh-frontier",
                    test_reject_ar_at_fresh_frontier);
    g_test_add_func("/ia64/vmstate/reject/fr0-fr1",
                    test_reject_fr0_fr1);
    g_test_add_func("/ia64/vmstate/reject/fr-without-typed-owner",
                    test_reject_fr_without_typed_owner);
    g_test_add_func("/ia64/vmstate/reject/fr-at-fresh-frontier",
                    test_reject_fr_at_fresh_frontier);
    g_test_add_func("/ia64/vmstate/pre-save/valid-typed",
                    test_pre_save_valid_typed);
    g_test_add_func("/ia64/vmstate/pre-save/reject-fresh-typed",
                    test_pre_save_reject_fresh_typed);
    g_test_add_func("/ia64/vmstate/pre-save/reject-orphan-overlay",
                    test_pre_save_reject_orphan_overlay);
    g_test_add_func("/ia64/vmstate/pre-save/fr-overlay-validation",
                    test_pre_save_fr_overlay_validation);
    g_test_add_func("/ia64/vmstate/pre-save/reject-dirty-breadcrumb",
                    test_pre_save_reject_dirty_breadcrumb);
    g_test_add_func("/ia64/vmstate/pre-save/canonicalize-ri",
                    test_pre_save_canonicalizes_ri);
    g_test_add_func("/ia64/vmstate/logical-mirror/pre-save-dirty-only",
                    test_pre_save_flushes_only_dirty_logical_names);
    g_test_add_func("/ia64/vmstate/logical-mirror/post-load-wrapped-rotating",
                    test_post_load_reconstructs_wrapped_rotating_mirror);
    g_test_add_func("/ia64/vmstate/logical-mirror/pre-load-clears-transients",
                    test_pre_load_clears_transient_mirror_metadata);
    g_test_add_func("/ia64/vmstate/logical-mirror/post-load-v8",
                    test_post_load_v8_reconstructs_logical_mirror);
    g_test_add_func("/ia64/vmstate/interrupt/state-round-trip",
                    test_interrupt_state_round_trip);
    g_test_add_func("/ia64/vmstate/interrupt/reject-invalid",
                    test_interrupt_vmstate_rejects_invalid_state);
    g_test_add_func("/ia64/vmstate/interrupt/pending-in-service-cpu-round-trip",
                    test_interrupt_pending_in_service_cpu_round_trip);
    g_test_add_func("/ia64/vmstate/logical-mirror/stale-stream-gr-ignored",
                    test_stream_ignores_stale_serialized_logical_gr);
    g_test_add_func("/ia64/vmstate/alat/target-type-round-trip",
                    test_alat_target_type_round_trip);
    g_test_add_func("/ia64/vmstate/alat/reject-invalid",
                    test_alat_vmstate_rejects_invalid_entries);
    g_test_add_func("/ia64/vmstate/collection-state/subsection-round-trip",
                    test_collection_state_subsection_round_trip);
    g_test_add_func("/ia64/vmstate/typed-only-version-boundary",
                    test_typed_only_version_boundary);
    g_test_add_func("/ia64/vmstate/rse/v5-complete-incomplete-round-trip",
                    test_rse_v5_complete_and_incomplete_round_trip);
    g_test_add_func("/ia64/vmstate/rse/cpu-v6-active-cfle-round-trip",
                    test_cpu_v6_active_cfle_round_trip);
    g_test_add_func("/ia64/vmstate/rse/v5-malformed-rejection",
                    test_rse_v5_malformed_rejection);
    g_test_add_func("/ia64/vmstate/rse/pre-save-boundaries",
                    test_rse_pre_save_boundaries);
    ret = g_test_run();

    close(temp_fd);
    unlink(temp_file);
    return ret;
}
