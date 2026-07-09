/* Included by interp.c. */

static uint32_t helper_map_fr(CPUIA64State *env, uint32_t reg)
{
    if (reg < 32) {
        return reg;
    }
    return 32 + ((reg - 32 + env->rse.rrb_fr) % (IA64_FR_COUNT - 32));
}

static void helper_write_fr_raw(CPUIA64State *env, uint32_t reg,
                                uint64_t low, uint64_t high)
{
    uint32_t mapped;

    if (reg >= IA64_FR_COUNT || reg < 2) {
        return;
    }

    mapped = helper_map_fr(env, reg);
    env->fr[mapped].raw[0] = low;
    env->fr[mapped].raw[1] = high;
    ia64_note_fr_write(env, reg);
}

static void exec_floating_load(CPUIA64State *env,
                               const IA64FloatingMemoryInstruction *decoded,
                               uint64_t address)
{
    IA64FloatReg spill;

    switch (decoded->format) {
    case IA64_FLOAT_FMT_SINGLE:
        ia64_write_fr_from_single_bits(env, decoded->freg,
                                       (uint32_t)ia64_ldst_read(env,
                                                                address, 4));
        break;
    case IA64_FLOAT_FMT_DOUBLE:
        ia64_write_fr_from_double_bits(env, decoded->freg,
                                       ia64_ldst_read(env, address, 8));
        break;
    case IA64_FLOAT_FMT_SIGNIFICAND:
        helper_write_fr_raw(env, decoded->freg,
                            ia64_ldst_read(env, address, 8),
                            0x1003e);
        break;
    case IA64_FLOAT_FMT_EXTENDED:
        helper_write_fr_raw(env, decoded->freg,
                            ia64_ldst_read(env, address, 8),
                            ia64_ldst_read(env, address + 8, 8));
        break;
    case IA64_FLOAT_FMT_SPILL_FILL:
        ia64_float_reg_from_spill(ia64_ldst_read(env, address, 8),
                                  ia64_ldst_read(env, address + 8, 8),
                                  &spill);
        helper_write_fr_raw(env, decoded->freg, spill.raw[0], spill.raw[1]);
        break;
    default:
        g_assert_not_reached();
    }
}

static void exec_floating_load_pair(CPUIA64State *env,
                                    const IA64FloatingMemoryInstruction *decoded,
                                    uint64_t address)
{
    IA64FloatingMemoryInstruction element = *decoded;

    element.kind = IA64_FLOAT_MEM_LOAD;
    element.base_update = false;
    exec_floating_load(env, &element, address);

    element.freg = decoded->freg2;
    exec_floating_load(env, &element, address + decoded->width);
}

static void exec_floating_store(CPUIA64State *env,
                                const IA64FloatingMemoryInstruction *decoded,
                                uint64_t address)
{
    uint32_t mapped = helper_map_fr(env, decoded->freg);
    uint64_t low = env->fr[mapped].raw[0];
    uint64_t high = env->fr[mapped].raw[1];
    uint64_t sign_exponent;
    uint64_t mantissa;

    switch (decoded->format) {
    case IA64_FLOAT_FMT_SINGLE:
        ia64_ldst_write(env, address, 4,
                        ia64_read_fr_as_single_bits(&env->fr[mapped]));
        break;
    case IA64_FLOAT_FMT_DOUBLE:
        ia64_ldst_write(env, address, 8,
                        ia64_read_fr_as_double_bits(&env->fr[mapped]));
        break;
    case IA64_FLOAT_FMT_SIGNIFICAND:
        ia64_ldst_write(env, address, 8, low);
        break;
    case IA64_FLOAT_FMT_EXTENDED:
        ia64_ldst_write(env, address, 8, low);
        ia64_ldst_write(env, address + 8, 8, high);
        break;
    case IA64_FLOAT_FMT_SPILL_FILL:
        ia64_float_reg_to_spill(&env->fr[mapped], &sign_exponent, &mantissa);
        ia64_ldst_write(env, address, 8, sign_exponent);
        ia64_ldst_write(env, address + 8, 8, mantissa);
        break;
    default:
        g_assert_not_reached();
    }
}

static bool exec_floating_memory(CPUIA64State *env,
                                 const IA64FloatingMemoryInstruction *decoded)
{
    uint64_t address = ia64_read_gr(env, decoded->base);
    uint64_t update;
    bool base_nat = ia64_read_gr_nat(env, decoded->base);

    switch (decoded->kind) {
    case IA64_FLOAT_MEM_LOAD:
        if (ia64_defer_floating_speculative_load(env, decoded, address,
                                                 base_nat)) {
            break;
        }
        if (base_nat) {
            ia64_exit_after_register_nat_consumption(env, MMU_DATA_LOAD,
                                                     "floating load base NaT");
        }
        exec_floating_load(env, decoded, address);
        break;
    case IA64_FLOAT_MEM_LOAD_PAIR:
        if (ia64_defer_floating_speculative_load(env, decoded, address,
                                                 base_nat)) {
            break;
        }
        if (base_nat) {
            ia64_exit_after_register_nat_consumption(
                env, MMU_DATA_LOAD, "floating load pair base NaT");
        }
        exec_floating_load_pair(env, decoded, address);
        break;
    case IA64_FLOAT_MEM_STORE:
        if (base_nat) {
            ia64_exit_after_register_nat_consumption(env, MMU_DATA_STORE,
                                                     "floating store base NaT");
        }
        exec_floating_store(env, decoded, address);
        break;
    case IA64_FLOAT_MEM_PREFETCH:
        if (base_nat) {
            ia64_exit_after_register_nat_consumption(
                env, MMU_DATA_LOAD, "floating prefetch base NaT");
        }
        break;
    default:
        g_assert_not_reached();
    }

    if (decoded->base_update) {
        if (decoded->update_from_register &&
            ia64_read_gr_nat(env, decoded->update_source)) {
            ia64_write_gr_nat(env, decoded->base, true);
        } else {
            update = decoded->update_from_register
                ? ia64_read_gr(env, decoded->update_source)
                : (uint64_t)decoded->immediate;
            ia64_write_gr(env, decoded->base, address + update);
        }
    }
    return true;
}
