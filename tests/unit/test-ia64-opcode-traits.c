/*
 * IA-64 opcode-trait exhaustiveness tests.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "qemu/osdep.h"
#include "target/ia64/opcode-traits.h"

static void test_opcode_rows_are_exhaustive(void)
{
    unsigned dead_aliases = 0;
    unsigned open = 0;
    unsigned typed = 0;
    unsigned typed_partial = 0;

    g_assert_cmpuint(IA64_OP_COUNT, ==, 428);
    for (unsigned i = 0; i < IA64_OP_COUNT; i++) {
        const IA64OpcodeTraits *traits =
            ia64_opcode_traits_for((IA64Opcode)i);

        g_assert_nonnull(traits);
        g_assert_cmpuint(traits->opcode, ==, i);
        g_assert_nonnull(traits->name);
        g_assert_true(g_str_has_prefix(traits->name, "IA64_OP_"));
        g_assert_nonnull(traits->family);
        g_assert_nonnull(traits->family->name);

        switch (traits->lifecycle) {
        case IA64_OPCODE_LIFECYCLE_ILLEGAL:
            g_assert_cmpuint(i, ==, IA64_OP_ILLEGAL);
            g_assert_false(traits->decoder_live);
            g_assert_false(traits->legacy_oracle);
            g_assert_false(traits->reference_tcg);
            break;
        case IA64_OPCODE_LIFECYCLE_DEAD_ALIAS:
            dead_aliases++;
            g_assert_false(traits->decoder_live);
            g_assert_cmpint(traits->lowering_owner, ==,
                            IA64_OPCODE_OWNER_CANONICAL_ALIAS);
            g_assert_cmpint(traits->closure, ==,
                            IA64_OPCODE_CLOSURE_ALIAS_CANONICALIZED);
            break;
        case IA64_OPCODE_LIFECYCLE_OPEN:
            open++;
            g_assert_true(traits->decoder_live);
            g_assert_cmpint(traits->lowering_owner, ==,
                            IA64_OPCODE_OWNER_LEGACY_ORACLE);
            break;
        case IA64_OPCODE_LIFECYCLE_TYPED:
            typed++;
            g_assert_true(traits->decoder_live);
            g_assert_cmpint(traits->admission, ==,
                            IA64_OPCODE_ADMISSION_FULL);
            break;
        case IA64_OPCODE_LIFECYCLE_TYPED_PARTIAL:
            typed_partial++;
            g_assert_true(traits->decoder_live);
            g_assert_cmpint(traits->admission, ==,
                            IA64_OPCODE_ADMISSION_PARTIAL);
            break;
        default:
            g_assert_not_reached();
        }
    }

    g_assert_cmpuint(dead_aliases, ==, 42);
    /*
     * Keep the structural partition exact without making every ownership
     * migration update a stale magic number here.  The generated ledger check
     * is the exact per-opcode authority; this floor prevents an accidental
     * rollback of the currently admitted surface.
     */
    g_assert_cmpuint(open + typed + typed_partial, ==,
                     IA64_OP_COUNT - dead_aliases - 1);
    g_assert_cmpuint(typed + typed_partial, >=, 150);
    g_assert_null(ia64_opcode_traits_for((IA64Opcode)-1));
    g_assert_null(ia64_opcode_traits_for(IA64_OP_COUNT));
}

static void test_family_rows_are_well_formed(void)
{
    for (unsigned i = 0; i < IA64_OPCODE_FAMILY_COUNT; i++) {
        const IA64OpcodeFamilyTraits *family =
            &ia64_opcode_family_traits[i];

        g_assert_nonnull(family->name);
        g_assert_cmpint(family->predication, >=,
                        IA64_OPCODE_PREDICATION_NONE);
        g_assert_cmpint(family->predication, <=,
                        IA64_OPCODE_PREDICATION_SPECIAL);
        g_assert_cmpint(family->nat_rule, >=, IA64_OPCODE_NAT_NONE);
        g_assert_cmpint(family->nat_rule, <=, IA64_OPCODE_NAT_SPECIAL);
        g_assert_cmpint(family->tb_behavior, >=, IA64_OPCODE_TB_CONTINUE);
        g_assert_cmpint(family->tb_behavior, <=,
                        IA64_OPCODE_TB_INTERRUPTION_RETURN);
    }
}

static void test_return_and_rfi_ownership(void)
{
    const IA64OpcodeTraits *ret =
        ia64_opcode_traits_for(IA64_OP_BR_RET);
    const IA64OpcodeTraits *rfi =
        ia64_opcode_traits_for(IA64_OP_RFI);

    g_assert_cmpint(ret->lowering_owner, ==, IA64_OPCODE_OWNER_DIRECT_TCG);
    g_assert_cmpint(ret->helper_whitelist, ==,
                    IA64_OPCODE_HELPER_RETURN_FRAME);
    g_assert_cmpint(ret->test_owner, ==, IA64_OPCODE_TEST_RSE);
    g_assert_cmpint(ret->exception_evidence, ==, IA64_OPCODE_EVIDENCE_RSE);
    g_assert_cmpint(ret->system_evidence, ==,
                    IA64_OPCODE_EVIDENCE_SNAPSHOT);

    g_assert_cmpint(rfi->lowering_owner, ==,
                    IA64_OPCODE_OWNER_FOCUSED_HELPER);
    g_assert_cmpint(rfi->helper_whitelist, ==, IA64_OPCODE_HELPER_RFI);
    g_assert_cmpint(rfi->family->tb_behavior, ==,
                    IA64_OPCODE_TB_INTERRUPTION_RETURN);
    g_assert_true(rfi->family->may_fault & IA64_OPCODE_FAULT_RSE);
    g_assert_true(rfi->family->may_fault & IA64_OPCODE_FAULT_MEMORY);
}

static void test_rse_spine_ownership(void)
{
    static const IA64Opcode opcodes[] = {
        IA64_OP_ALLOC,
        IA64_OP_COVER,
        IA64_OP_FLUSHRS,
        IA64_OP_LOADRS,
        IA64_OP_CLRRRB,
        IA64_OP_CLRRRB_PR,
    };

    for (unsigned i = 0; i < ARRAY_SIZE(opcodes); i++) {
        const IA64OpcodeTraits *traits =
            ia64_opcode_traits_for(opcodes[i]);

        g_assert_cmpint(traits->lowering_owner, ==,
                        IA64_OPCODE_OWNER_FOCUSED_HELPER);
        g_assert_cmpint(traits->helper_whitelist, ==,
                        IA64_OPCODE_HELPER_RSE_SPINE);
        g_assert_cmpint(traits->test_owner, ==, IA64_OPCODE_TEST_RSE);
        g_assert_cmpint(traits->exception_evidence, ==,
                        IA64_OPCODE_EVIDENCE_RSE);
        g_assert_cmpint(traits->system_evidence, ==,
                        IA64_OPCODE_EVIDENCE_NO_OS);
        g_assert_cmpint(traits->admission, ==,
                        IA64_OPCODE_ADMISSION_FULL);
    }
}

int main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/ia64/opcode-traits/exhaustive",
                    test_opcode_rows_are_exhaustive);
    g_test_add_func("/ia64/opcode-traits/families",
                    test_family_rows_are_well_formed);
    g_test_add_func("/ia64/opcode-traits/return-rfi",
                    test_return_and_rfi_ownership);
    g_test_add_func("/ia64/opcode-traits/rse-spine",
                    test_rse_spine_ownership);
    return g_test_run();
}
