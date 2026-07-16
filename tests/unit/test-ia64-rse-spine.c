/*
 * IA-64 typed RSE-spine semantic and restartability tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "target/ia64/insn.h"

#include <setjmp.h>

typedef struct TestStoreCapture {
    uint64_t address[32];
    uint64_t value[32];
    uint32_t count;
    uint32_t issued;
    uint32_t fault_at;
    uint32_t interrupt_at;
    uint32_t polls;
    bool faulted;
    bool interrupted;
    jmp_buf fault;
} TestStoreCapture;

static uint64_t test_cfm(uint32_t sof, uint32_t sol, uint32_t sor,
                         uint32_t rrb_gr, uint32_t rrb_fr,
                         uint32_t rrb_pr)
{
    return ia64_make_cfm(sof, sol, sor) |
           ((uint64_t)rrb_gr << 18) |
           ((uint64_t)rrb_fr << 25) |
           ((uint64_t)rrb_pr << 32);
}

static void test_init_resident_frame(CPUIA64State *env, uint64_t cfm)
{
    uint32_t sof = cfm & 0x7f;

    ia64_cpu_reset_synthetic_itanium2(env);
    ia64_set_cfm(env, cfm);
    env->rse.dirty = 0;
    env->rse.dirty_nat = 0;
    env->rse.clean = 0;
    env->rse.clean_nat = 0;
    env->rse.invalid = IA64_RSE_PHYS_STACKED_REGS - sof;
    env->rse.clean_count = 0;
    g_assert_true(ia64_rse_partitions_valid(env));
}

static void test_alloc_validation_is_precommit(void)
{
    CPUIA64State env;
    CPUIA64State before;

    test_init_resident_frame(&env, test_cfm(8, 3, 1, 5, 6, 7));
    before = env;

    g_assert_cmpint(ia64_rse_validate_alloc(&env, 0, 8, 3, 1, 0), ==,
                    IA64_RSE_ALLOC_ILLEGAL_OPERATION);
    g_assert_cmpint(ia64_rse_validate_alloc(&env, 40, 8, 3, 1, 0), ==,
                    IA64_RSE_ALLOC_ILLEGAL_OPERATION);
    g_assert_cmpint(ia64_rse_validate_alloc(&env, 39, 8, 3, 1, 0), ==,
                    IA64_RSE_ALLOC_VALID);
    g_assert_cmpint(ia64_rse_validate_alloc(&env, 1, 8, 3, 1, 1), ==,
                    IA64_RSE_ALLOC_ILLEGAL_OPERATION);
    g_assert_cmpint(ia64_rse_validate_alloc(&env, 1, 97, 3, 1, 0), ==,
                    IA64_RSE_ALLOC_ILLEGAL_OPERATION);
    g_assert_cmpint(ia64_rse_validate_alloc(&env, 1, 8, 9, 1, 0), ==,
                    IA64_RSE_ALLOC_ILLEGAL_OPERATION);
    g_assert_cmpint(ia64_rse_validate_alloc(&env, 1, 8, 3, 2, 0), ==,
                    IA64_RSE_ALLOC_ILLEGAL_OPERATION);
    g_assert_cmpint(ia64_rse_validate_alloc(&env, 1, 16, 3, 2, 0), ==,
                    IA64_RSE_ALLOC_RESERVED_REGISTER_FIELD);
    g_assert_cmpmem(&env, sizeof(env), &before, sizeof(before));

    ia64_set_cfm(&env, test_cfm(8, 3, 1, 0, 0, 0));
    before = env;
    g_assert_cmpint(ia64_rse_validate_alloc(&env, 47, 16, 3, 2, 0), ==,
                    IA64_RSE_ALLOC_VALID);
    g_assert_cmpmem(&env, sizeof(env), &before, sizeof(before));
}

static void test_alloc_commit_preserves_rename_bases(void)
{
    const uint64_t old_cfm = test_cfm(8, 3, 1, 5, 6, 7);
    const uint64_t old_pfs = UINT64_C(0xd123456789abcdef);
    const uint64_t frame_mask = (UINT64_C(1) << 18) - 1;
    CPUIA64State env;
    uint64_t result;

    test_init_resident_frame(&env, old_cfm);
    env.ar[IA64_AR_PFS] = old_pfs;
    result = ia64_rse_commit_alloc(&env, 43, 12, 4, 1);

    g_assert_cmphex(result, ==, old_pfs);
    g_assert_cmphex(env.ar[IA64_AR_PFS], ==, old_pfs);
    g_assert_cmphex(env.cfm, ==,
                    (old_cfm & ~frame_mask) | ia64_make_cfm(12, 4, 1));
    g_assert_cmpuint(env.rse.rrb_gr, ==, 5);
    g_assert_cmpuint(env.rse.rrb_fr, ==, 6);
    g_assert_cmpuint(env.rse.rrb_pr, ==, 7);
    g_assert_cmpint(env.rse.invalid, ==, 84);
    g_assert_true(ia64_rse_partitions_valid(&env));
}

static void test_mark_stacked_alat(CPUIA64State *env)
{
    env->alat.entries[0].valid = true;
    env->alat.entries[0].target = IA64_STATIC_GR_COUNT;
    ia64_alat_reconstruct_transients(env);
    g_assert_true(env->alat.entries[0].valid);
}

static void test_cover_and_clear_rename_bases(void)
{
    const uint64_t cfm = test_cfm(8, 3, 1, 5, 6, 7);
    CPUIA64State env;

    test_init_resident_frame(&env, cfm);
    env.psr = 0;
    test_mark_stacked_alat(&env);
    ia64_rse_cover_frame(&env);
    g_assert_cmphex(env.cr[IA64_CR_IFS], ==, cfm | IA64_IFS_VALID_BIT);
    g_assert_cmphex(env.cfm, ==, 0);
    g_assert_false(env.alat.entries[0].valid);
    g_assert_true(ia64_rse_partitions_valid(&env));

    test_init_resident_frame(&env, cfm);
    test_mark_stacked_alat(&env);
    ia64_rse_clear_rename_bases(&env, true);
    g_assert_cmpuint(env.rse.rrb_gr, ==, 5);
    g_assert_cmpuint(env.rse.rrb_fr, ==, 6);
    g_assert_cmpuint(env.rse.rrb_pr, ==, 0);
    g_assert_false(env.alat.entries[0].valid);

    ia64_set_cfm(&env, cfm);
    test_mark_stacked_alat(&env);
    ia64_rse_clear_rename_bases(&env, false);
    g_assert_cmpuint(env.rse.rrb_gr, ==, 0);
    g_assert_cmpuint(env.rse.rrb_fr, ==, 0);
    g_assert_cmpuint(env.rse.rrb_pr, ==, 0);
    g_assert_false(env.alat.entries[0].valid);
}

static void test_loadrs_legality(void)
{
    CPUIA64State env;
    CPUIA64State before;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.rse.rsc = UINT64_C(8) << IA64_RSC_LOADRS_SHIFT;
    before = env;
    g_assert_true(ia64_rse_loadrs_is_legal(&env));
    g_assert_cmpmem(&env, sizeof(env), &before, sizeof(before));

    ia64_set_cfm(&env, ia64_make_cfm(8, 0, 0));
    env.rse.rsc = 0;
    g_assert_true(ia64_rse_loadrs_is_legal(&env));
    env.rse.rsc = UINT64_C(8) << IA64_RSC_LOADRS_SHIFT;
    g_assert_false(ia64_rse_loadrs_is_legal(&env));
    env.rse.rsc = 1;
    g_assert_false(ia64_rse_loadrs_is_legal(&env));
}

static void test_store_word(CPUIA64State *env, uint64_t address,
                            uint64_t value, void *opaque)
{
    TestStoreCapture *capture = opaque;

    g_assert_nonnull(env);
    g_assert_nonnull(capture);
    if (!capture->faulted && capture->issued == capture->fault_at) {
        capture->faulted = true;
        capture->issued++;
        longjmp(capture->fault, 1);
    }
    g_assert_cmpuint(capture->count, <, G_N_ELEMENTS(capture->address));
    capture->address[capture->count] = address;
    capture->value[capture->count] = value;
    capture->count++;
    capture->issued++;
}

static bool test_store_interruption_pending(CPUIA64State *env, void *opaque)
{
    TestStoreCapture *capture = opaque;

    g_assert_nonnull(env);
    g_assert_nonnull(capture);
    capture->polls++;
    if (!capture->interrupted &&
        capture->count == capture->interrupt_at) {
        capture->interrupted = true;
        return true;
    }
    return false;
}

static void test_init_rnat_crossing_spill(CPUIA64State *env)
{
    ia64_cpu_reset_synthetic_itanium2(env);
    env->rse.bol = 90;
    env->rse.current_frame_base = 90;
    env->rse.bspstore = 0x61e0;
    env->rse.bsp = ia64_rse_skip_regs(env->rse.bspstore, 90);
    env->rse.bsp_load = env->rse.bspstore;
    env->ar[IA64_AR_BSPSTORE] = env->rse.bspstore;
    env->ar[IA64_AR_BSP] = env->rse.bsp;
    env->rse.dirty = 90;
    env->rse.dirty_nat =
        (env->rse.bsp - env->rse.bspstore) / 8 - 90;
    env->rse.invalid = 6;
    env->rse.rnat = 0;
    ia64_rse_sync_rnat(env);
    for (uint32_t i = 0; i < IA64_STACKED_GR_COUNT; i++) {
        env->rse.stacked_gr[i] = UINT64_C(0xb0d0000000000000) | i;
    }
    ia64_rse_write_physical_nat(env, 1, true);
    ia64_rse_write_physical_nat(env, 4, true);
    g_assert_true(ia64_rse_partitions_valid(env));
}

static void test_alloc_spill_rnat_fault_retry_matrix(void)
{
    TestStoreCapture baseline_capture = {
        .fault_at = UINT32_MAX,
    };
    CPUIA64State baseline;

    test_init_rnat_crossing_spill(&baseline);
    g_assert_cmpuint(ia64_rse_spill_excess_dirty(
                         &baseline, 20, test_store_word, &baseline_capture),
                     ==, 14);
    g_assert_cmpuint(baseline_capture.count, ==, 15);
    g_assert_cmphex(baseline_capture.address[3], ==, 0x61f8);

    for (uint32_t fault_at = 0; fault_at < baseline_capture.count;
         fault_at++) {
        TestStoreCapture *capture = g_new0(TestStoreCapture, 1);
        CPUIA64State *env = g_new0(CPUIA64State, 1);

        capture->fault_at = fault_at;
        test_init_rnat_crossing_spill(env);
        if (setjmp(capture->fault) == 0) {
            ia64_rse_spill_excess_dirty(env, 20, test_store_word, capture);
            g_assert_not_reached();
        }
        g_assert_true(capture->faulted);
        g_assert_cmpuint(capture->count, ==, fault_at);
        g_assert_cmphex(env->rse.bspstore, ==,
                        baseline_capture.address[fault_at]);
        g_assert_true(ia64_rse_partitions_valid(env));

        ia64_rse_spill_excess_dirty(env, 20, test_store_word, capture);
        g_assert_cmpuint(capture->count, ==, baseline_capture.count);
        g_assert_cmpmem(capture->address,
                        baseline_capture.count * sizeof(uint64_t),
                        baseline_capture.address,
                        baseline_capture.count * sizeof(uint64_t));
        g_assert_cmpmem(capture->value,
                        baseline_capture.count * sizeof(uint64_t),
                        baseline_capture.value,
                        baseline_capture.count * sizeof(uint64_t));
        g_assert_cmpmem(&env->rse, sizeof(env->rse),
                        &baseline.rse, sizeof(baseline.rse));
        g_assert_cmphex(env->ar[IA64_AR_BSPSTORE], ==,
                        baseline.ar[IA64_AR_BSPSTORE]);
        g_assert_cmphex(env->ar[IA64_AR_RNAT], ==,
                        baseline.ar[IA64_AR_RNAT]);
        g_assert_true(ia64_rse_partitions_valid(env));
        g_free(env);
        g_free(capture);
    }
}

static void test_alloc_spill_interrupt_retry_matrix(void)
{
    TestStoreCapture baseline_capture = {
        .fault_at = UINT32_MAX,
        .interrupt_at = UINT32_MAX,
    };
    CPUIA64State baseline;
    uint32_t baseline_spilled = 0;

    test_init_rnat_crossing_spill(&baseline);
    g_assert_cmpint(ia64_rse_spill_excess_dirty_interruptible(
                        &baseline, 20, test_store_word, NULL,
                        &baseline_capture, &baseline_spilled),
                    ==, IA64_RSE_STEP_DONE);
    g_assert_cmpuint(baseline_spilled, ==, 14);
    g_assert_cmpuint(baseline_capture.count, ==, 15);

    for (uint32_t boundary = 0; boundary <= baseline_capture.count;
         boundary++) {
        TestStoreCapture capture = {
            .fault_at = UINT32_MAX,
            .interrupt_at = boundary,
        };
        CPUIA64State env;
        uint32_t first_spilled = 0;
        uint32_t retry_spilled = 0;

        test_init_rnat_crossing_spill(&env);
        g_assert_cmpint(ia64_rse_spill_excess_dirty_interruptible(
                            &env, 20, test_store_word,
                            test_store_interruption_pending, &capture,
                            &first_spilled),
                        ==, IA64_RSE_STEP_INTERRUPTION);
        g_assert_true(capture.interrupted);
        g_assert_cmpuint(capture.count, ==, boundary);
        g_assert_true(ia64_rse_partitions_valid(&env));

        g_assert_cmpint(ia64_rse_spill_excess_dirty_interruptible(
                            &env, 20, test_store_word,
                            test_store_interruption_pending, &capture,
                            &retry_spilled),
                        ==, IA64_RSE_STEP_DONE);
        g_assert_cmpuint(first_spilled + retry_spilled, ==, 14);
        g_assert_cmpuint(capture.count, ==, baseline_capture.count);
        g_assert_cmpmem(capture.address,
                        baseline_capture.count * sizeof(uint64_t),
                        baseline_capture.address,
                        baseline_capture.count * sizeof(uint64_t));
        g_assert_cmpmem(capture.value,
                        baseline_capture.count * sizeof(uint64_t),
                        baseline_capture.value,
                        baseline_capture.count * sizeof(uint64_t));
        g_assert_cmpmem(&env.rse, sizeof(env.rse),
                        &baseline.rse, sizeof(baseline.rse));
        g_assert_true(ia64_rse_partitions_valid(&env));
    }
}

static void test_init_small_rnat_store(CPUIA64State *env)
{
    ia64_cpu_reset_synthetic_itanium2(env);
    env->rse.bol = 4;
    env->rse.current_frame_base = 4;
    env->rse.bspstore = 0x1e0;
    env->rse.bsp = ia64_rse_skip_regs(env->rse.bspstore, 4);
    env->rse.bsp_load = env->rse.bspstore;
    env->ar[IA64_AR_BSPSTORE] = env->rse.bspstore;
    env->ar[IA64_AR_BSP] = env->rse.bsp;
    env->rse.dirty = 4;
    env->rse.dirty_nat =
        (env->rse.bsp - env->rse.bspstore) / 8 - 4;
    env->rse.invalid = IA64_RSE_PHYS_STACKED_REGS - 4;
    for (uint32_t i = 0; i < IA64_STACKED_GR_COUNT; i++) {
        env->rse.stacked_gr[i] = UINT64_C(0xc0d0000000000000) | i;
    }
    ia64_rse_write_physical_nat(env, 1, true);
    ia64_rse_sync_rnat(env);
    g_assert_true(ia64_rse_partitions_valid(env));
}

static void test_mandatory_store_data_debug_retry(void)
{
    TestStoreCapture baseline_capture = {
        .fault_at = UINT32_MAX,
        .interrupt_at = UINT32_MAX,
    };
    TestStoreCapture *capture = g_new0(TestStoreCapture, 1);
    CPUIA64State baseline;
    CPUIA64State *env = g_new0(CPUIA64State, 1);

    test_init_small_rnat_store(&baseline);
    g_assert_cmpint(ia64_rse_flush_dirty_interruptible(
                        &baseline, test_store_word, NULL, &baseline_capture),
                    ==, IA64_RSE_STEP_DONE);

    capture->fault_at = 2;
    capture->interrupt_at = UINT32_MAX;
    test_init_small_rnat_store(env);
    if (setjmp(capture->fault) == 0) {
        ia64_rse_flush_dirty_interruptible(
            env, test_store_word, NULL, capture);
        g_assert_not_reached();
    }

    /* A DBR hit occurs before the matching memory store commits. */
    g_assert_true(capture->faulted);
    g_assert_cmpuint(capture->count, ==, capture->fault_at);
    g_assert_cmphex(env->rse.bspstore, ==,
                    baseline_capture.address[capture->fault_at]);
    g_assert_cmpmem(capture->address,
                    capture->count * sizeof(uint64_t),
                    baseline_capture.address,
                    capture->count * sizeof(uint64_t));
    g_assert_true(ia64_rse_partitions_valid(env));

    g_assert_cmpint(ia64_rse_flush_dirty_interruptible(
                        env, test_store_word, NULL, capture),
                    ==, IA64_RSE_STEP_DONE);
    g_assert_cmpuint(capture->count, ==, baseline_capture.count);
    g_assert_cmpmem(capture->address,
                    baseline_capture.count * sizeof(uint64_t),
                    baseline_capture.address,
                    baseline_capture.count * sizeof(uint64_t));
    g_assert_cmpmem(capture->value,
                    baseline_capture.count * sizeof(uint64_t),
                    baseline_capture.value,
                    baseline_capture.count * sizeof(uint64_t));
    g_assert_cmpmem(&env->rse, sizeof(env->rse),
                    &baseline.rse, sizeof(baseline.rse));
    g_assert_true(ia64_rse_partitions_valid(env));
    g_free(env);
    g_free(capture);
}

static void test_flushrs_interrupt_retry_matrix(void)
{
    TestStoreCapture baseline_capture = {
        .fault_at = UINT32_MAX,
        .interrupt_at = UINT32_MAX,
    };
    CPUIA64State baseline;

    test_init_small_rnat_store(&baseline);
    g_assert_cmpint(ia64_rse_flush_dirty_interruptible(
                        &baseline, test_store_word, NULL, &baseline_capture),
                    ==, IA64_RSE_STEP_DONE);
    g_assert_cmpuint(baseline_capture.count, ==, 5);

    for (uint32_t boundary = 0; boundary <= baseline_capture.count;
         boundary++) {
        TestStoreCapture capture = {
            .fault_at = UINT32_MAX,
            .interrupt_at = boundary,
        };
        CPUIA64State env;

        test_init_small_rnat_store(&env);
        g_assert_cmpint(ia64_rse_flush_dirty_interruptible(
                            &env, test_store_word,
                            test_store_interruption_pending, &capture),
                        ==, IA64_RSE_STEP_INTERRUPTION);
        g_assert_true(capture.interrupted);
        g_assert_cmpuint(capture.count, ==, boundary);
        g_assert_true(ia64_rse_partitions_valid(&env));

        g_assert_cmpint(ia64_rse_flush_dirty_interruptible(
                            &env, test_store_word,
                            test_store_interruption_pending, &capture),
                        ==, IA64_RSE_STEP_DONE);
        g_assert_cmpuint(capture.count, ==, baseline_capture.count);
        g_assert_cmpmem(capture.address,
                        baseline_capture.count * sizeof(uint64_t),
                        baseline_capture.address,
                        baseline_capture.count * sizeof(uint64_t));
        g_assert_cmpmem(capture.value,
                        baseline_capture.count * sizeof(uint64_t),
                        baseline_capture.value,
                        baseline_capture.count * sizeof(uint64_t));
        g_assert_cmpmem(&env.rse, sizeof(env.rse),
                        &baseline.rse, sizeof(baseline.rse));
        g_assert_true(ia64_rse_partitions_valid(&env));
    }
}

typedef struct TestLoadrsCapture {
    uint64_t address[16];
    uint32_t count;
    uint32_t debug_at;
    uint32_t interrupt_at;
    uint32_t polls;
    bool debug_enabled;
    bool debug_faulted;
    bool interrupted;
} TestLoadrsCapture;

static bool test_loadrs_read_word(CPUIA64State *env, uint64_t address,
                                  uint64_t *value, void *opaque)
{
    TestLoadrsCapture *capture = opaque;

    g_assert_nonnull(env);
    g_assert_nonnull(capture);
    if (capture->debug_enabled && !capture->debug_faulted &&
        capture->count == capture->debug_at) {
        capture->debug_faulted = true;
        return false;
    }
    g_assert_cmpuint(capture->count, <, G_N_ELEMENTS(capture->address));
    capture->address[capture->count++] = address;
    *value = ia64_rse_address_is_rnat_slot(address) ?
        UINT64_C(1) << 60 : UINT64_C(0xd0d0000000000000) | address;
    return true;
}

static bool test_loadrs_interruption_pending(CPUIA64State *env, void *opaque)
{
    TestLoadrsCapture *capture = opaque;

    g_assert_nonnull(env);
    g_assert_nonnull(capture);
    capture->polls++;
    if (!capture->interrupted &&
        capture->count == capture->interrupt_at) {
        capture->interrupted = true;
        return true;
    }
    return false;
}

static void test_init_loadrs_span(CPUIA64State *env)
{
    ia64_cpu_reset_synthetic_itanium2(env);
    env->rse.bsp = 0x208;
    env->rse.bspstore = env->rse.bsp;
    env->rse.bsp_load = env->rse.bsp;
    env->ar[IA64_AR_BSP] = env->rse.bsp;
    env->ar[IA64_AR_BSPSTORE] = env->rse.bspstore;
    env->rse.rsc = UINT64_C(0x28) << IA64_RSC_LOADRS_SHIFT;
    g_assert_true(ia64_rse_partitions_valid(env));
    g_assert_true(ia64_rse_loadrs_is_legal(env));
}

static void test_loadrs_interrupt_retry_matrix(void)
{
    TestLoadrsCapture baseline_capture = {
        .interrupt_at = UINT32_MAX,
    };
    CPUIA64State baseline;

    test_init_loadrs_span(&baseline);
    g_assert_cmpint(ia64_rse_execute_loadrs_interruptible(
                        &baseline, test_loadrs_read_word, NULL,
                        &baseline_capture),
                    ==, IA64_RSE_STEP_DONE);
    g_assert_cmpuint(baseline_capture.count, ==, 5);

    for (uint32_t boundary = 0; boundary <= baseline_capture.count;
         boundary++) {
        TestLoadrsCapture capture = {
            .interrupt_at = boundary,
        };
        CPUIA64State env;

        test_init_loadrs_span(&env);
        g_assert_cmpint(ia64_rse_execute_loadrs_interruptible(
                            &env, test_loadrs_read_word,
                            test_loadrs_interruption_pending, &capture),
                        ==, IA64_RSE_STEP_INTERRUPTION);
        g_assert_true(capture.interrupted);
        g_assert_cmpuint(capture.count, ==, boundary);
        g_assert_true(ia64_rse_partitions_valid(&env));

        g_assert_cmpint(ia64_rse_execute_loadrs_interruptible(
                            &env, test_loadrs_read_word,
                            test_loadrs_interruption_pending, &capture),
                        ==, IA64_RSE_STEP_DONE);
        g_assert_cmpuint(capture.count, ==, baseline_capture.count);
        g_assert_cmpmem(capture.address,
                        baseline_capture.count * sizeof(uint64_t),
                        baseline_capture.address,
                        baseline_capture.count * sizeof(uint64_t));
        g_assert_cmpmem(&env.rse, sizeof(env.rse),
                        &baseline.rse, sizeof(baseline.rse));
        g_assert_true(ia64_rse_partitions_valid(&env));
    }
}

static void test_mandatory_load_data_debug_retry(void)
{
    TestLoadrsCapture baseline_capture = {
        .interrupt_at = UINT32_MAX,
    };
    TestLoadrsCapture *capture = g_new0(TestLoadrsCapture, 1);
    CPUIA64State baseline;
    CPUIA64State *env = g_new0(CPUIA64State, 1);

    test_init_loadrs_span(&baseline);
    g_assert_cmpint(ia64_rse_execute_loadrs_interruptible(
                        &baseline, test_loadrs_read_word, NULL,
                        &baseline_capture), ==, IA64_RSE_STEP_DONE);

    capture->debug_enabled = true;
    capture->debug_at = 2;
    capture->interrupt_at = UINT32_MAX;
    test_init_loadrs_span(env);
    g_assert_cmpint(ia64_rse_execute_loadrs_interruptible(
                        env, test_loadrs_read_word, NULL, capture),
                    ==, IA64_RSE_STEP_FAULT);

    /* BSPSTORE remains above the uncommitted, breakpoint-matching load. */
    g_assert_true(capture->debug_faulted);
    g_assert_cmpuint(capture->count, ==, capture->debug_at);
    g_assert_cmphex(env->rse.bspstore, ==,
                    baseline_capture.address[capture->debug_at] + 8);
    g_assert_cmpmem(capture->address,
                    capture->count * sizeof(uint64_t),
                    baseline_capture.address,
                    capture->count * sizeof(uint64_t));
    g_assert_true(ia64_rse_partitions_valid(env));

    g_assert_cmpint(ia64_rse_execute_loadrs_interruptible(
                        env, test_loadrs_read_word, NULL, capture),
                    ==, IA64_RSE_STEP_DONE);
    g_assert_cmpuint(capture->count, ==, baseline_capture.count);
    g_assert_cmpmem(capture->address,
                    baseline_capture.count * sizeof(uint64_t),
                    baseline_capture.address,
                    baseline_capture.count * sizeof(uint64_t));
    g_assert_cmpmem(&env->rse, sizeof(env->rse),
                    &baseline.rse, sizeof(baseline.rse));
    g_assert_true(ia64_rse_partitions_valid(env));
    g_free(env);
    g_free(capture);
}

static uint64_t test_loadrs_span_for_registers(uint64_t bsp,
                                               uint32_t registers)
{
    uint64_t address = bsp;

    while (registers != 0) {
        address -= 8;
        if (!ia64_rse_address_is_rnat_slot(address)) {
            registers--;
        }
    }
    return bsp - address;
}

static void test_loadrs_over_capacity_is_preflight(void)
{
    TestLoadrsCapture capture = {
        .interrupt_at = UINT32_MAX,
    };
    CPUIA64State env;
    CPUIA64State before;
    uint64_t bytes;

    ia64_cpu_reset_synthetic_itanium2(&env);
    env.rse.bsp = 0x4000;
    env.rse.bspstore = env.rse.bsp;
    env.rse.bsp_load = env.rse.bsp;
    env.ar[IA64_AR_BSP] = env.rse.bsp;
    env.ar[IA64_AR_BSPSTORE] = env.rse.bspstore;
    bytes = test_loadrs_span_for_registers(
        env.rse.bsp, IA64_RSE_PHYS_STACKED_REGS + 1);
    g_assert_cmpuint(bytes, <=, IA64_RSC_LOADRS_MASK);
    env.rse.rsc = bytes << IA64_RSC_LOADRS_SHIFT;
    before = env;

    g_assert_false(ia64_rse_loadrs_is_legal(&env));
    g_assert_cmpint(ia64_rse_execute_loadrs_interruptible(
                        &env, test_loadrs_read_word,
                        test_loadrs_interruption_pending, &capture),
                    ==, IA64_RSE_STEP_FAULT);
    g_assert_cmpuint(capture.count, ==, 0);
    g_assert_cmpuint(capture.polls, ==, 0);
    g_assert_cmpmem(&env, sizeof(env), &before, sizeof(before));
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/ia64/rse-spine/alloc-validation-precommit",
                    test_alloc_validation_is_precommit);
    g_test_add_func("/ia64/rse-spine/alloc-commit-rrb",
                    test_alloc_commit_preserves_rename_bases);
    g_test_add_func("/ia64/rse-spine/cover-clrrrb",
                    test_cover_and_clear_rename_bases);
    g_test_add_func("/ia64/rse-spine/loadrs-legality",
                    test_loadrs_legality);
    g_test_add_func("/ia64/rse-spine/alloc-rnat-fault-retry",
                    test_alloc_spill_rnat_fault_retry_matrix);
    g_test_add_func("/ia64/rse-spine/alloc-interrupt-retry",
                    test_alloc_spill_interrupt_retry_matrix);
    g_test_add_func("/ia64/rse-spine/flushrs-interrupt-retry",
                    test_flushrs_interrupt_retry_matrix);
    g_test_add_func("/ia64/rse-spine/mandatory-store-data-debug-retry",
                    test_mandatory_store_data_debug_retry);
    g_test_add_func("/ia64/rse-spine/loadrs-interrupt-retry",
                    test_loadrs_interrupt_retry_matrix);
    g_test_add_func("/ia64/rse-spine/mandatory-load-data-debug-retry",
                    test_mandatory_load_data_debug_retry);
    g_test_add_func("/ia64/rse-spine/loadrs-over-capacity-preflight",
                    test_loadrs_over_capacity_is_preflight);
    return g_test_run();
}
