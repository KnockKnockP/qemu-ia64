/* Included by interp.c. */

static uint64_t ia64_ld_le_unaligned(CPUIA64State *env, uint64_t address,
                                     uint8_t width)
{
    uint64_t value = 0;

    for (uint8_t i = 0; i < width; i++) {
        value |= (uint64_t)cpu_ldub_data_ra(env, address + i, GETPC())
            << (i * 8);
    }

    return value;
}

static bool ia64_trace_range_matches(uint64_t address, uint8_t width,
                                     uint64_t filter_start,
                                     uint64_t filter_end)
{
    uint64_t access_end = address + width - 1;

    return address <= filter_end && access_end >= filter_start;
}

typedef struct IA64LdstTraceConfig {
    int initialized;
    bool enabled;
    bool has_vaddr_filter;
    bool has_paddr_filter;
    uint64_t vaddr_filter_start;
    uint64_t vaddr_filter_end;
    uint64_t paddr_filter_start;
    uint64_t paddr_filter_end;
} IA64LdstTraceConfig;

static IA64LdstTraceConfig *ia64_ldst_trace_config(void)
{
    static IA64LdstTraceConfig config;

    if (!config.initialized) {
        const char *trace = g_getenv("VIBTANIUM_LDST_TRACE");
        const char *addr = g_getenv("VIBTANIUM_LDST_TRACE_ADDR");
        const char *size = g_getenv("VIBTANIUM_LDST_TRACE_SIZE");
        const char *paddr_env = g_getenv("VIBTANIUM_LDST_TRACE_PADDR");
        const char *psize = g_getenv("VIBTANIUM_LDST_TRACE_PSIZE");

        config.enabled = trace != NULL || addr != NULL || paddr_env != NULL;
        if (addr != NULL && *addr != '\0') {
            char *endptr = NULL;
            uint64_t parsed_size = 1;

            config.vaddr_filter_start = g_ascii_strtoull(addr, &endptr, 0);
            config.has_vaddr_filter = endptr != addr;
            if (size != NULL && *size != '\0') {
                endptr = NULL;
                parsed_size = g_ascii_strtoull(size, &endptr, 0);
                if (endptr == size || parsed_size == 0) {
                    parsed_size = 1;
                }
            }
            config.vaddr_filter_end = config.vaddr_filter_start +
                                      parsed_size - 1;
        }
        if (paddr_env != NULL && *paddr_env != '\0') {
            char *endptr = NULL;
            uint64_t parsed_size = 1;

            config.paddr_filter_start = g_ascii_strtoull(paddr_env, &endptr,
                                                         0);
            config.has_paddr_filter = endptr != paddr_env;
            if (psize != NULL && *psize != '\0') {
                endptr = NULL;
                parsed_size = g_ascii_strtoull(psize, &endptr, 0);
                if (endptr == psize || parsed_size == 0) {
                    parsed_size = 1;
                }
            }
            config.paddr_filter_end = config.paddr_filter_start +
                                      parsed_size - 1;
        }
        config.initialized = 1;
    }

    return &config;
}

static bool ia64_ldst_trace_needs_paddr(void)
{
    IA64LdstTraceConfig *config = ia64_ldst_trace_config();

    return config->enabled && config->has_paddr_filter;
}

static bool ia64_ldst_trace_matches(uint64_t vaddr, uint64_t paddr,
                                    bool has_paddr, uint8_t width)
{
    IA64LdstTraceConfig *config = ia64_ldst_trace_config();

    if (!config->enabled) {
        return false;
    }
    if (!config->has_vaddr_filter && !config->has_paddr_filter) {
        return true;
    }
    if (config->has_vaddr_filter &&
        ia64_trace_range_matches(vaddr, width, config->vaddr_filter_start,
                                 config->vaddr_filter_end)) {
        return true;
    }

    return has_paddr && config->has_paddr_filter &&
           ia64_trace_range_matches(paddr, width, config->paddr_filter_start,
                                    config->paddr_filter_end);
}

static bool ia64_ldst_trace_op_matches(const char *op)
{
    static int initialized;
    static const char *filter;

    if (!initialized) {
        filter = g_getenv("VIBTANIUM_LDST_TRACE_OP");
        initialized = 1;
    }

    return filter == NULL || *filter == '\0' || g_str_equal(filter, op);
}

static bool ia64_ldst_trace_width_matches(uint8_t width)
{
    static int initialized;
    static bool has_filter;
    static uint64_t filter;

    if (!initialized) {
        const char *value = g_getenv("VIBTANIUM_LDST_TRACE_WIDTH");

        if (value != NULL && *value != '\0') {
            char *endptr = NULL;

            filter = g_ascii_strtoull(value, &endptr, 0);
            has_filter = endptr != value;
        }
        initialized = 1;
    }

    return !has_filter || width == filter;
}

static bool ia64_ldst_trace_value_matches(uint64_t value)
{
    static int initialized;
    static bool has_exact_filter;
    static bool has_min_filter;
    static bool has_max_filter;
    static uint64_t exact_filter;
    static uint64_t min_filter;
    static uint64_t max_filter;

    if (!initialized) {
        const char *exact = g_getenv("VIBTANIUM_LDST_TRACE_VALUE");
        const char *min = g_getenv("VIBTANIUM_LDST_TRACE_VALUE_MIN");
        const char *max = g_getenv("VIBTANIUM_LDST_TRACE_VALUE_MAX");

        if (exact != NULL && *exact != '\0') {
            char *endptr = NULL;

            exact_filter = g_ascii_strtoull(exact, &endptr, 0);
            has_exact_filter = endptr != exact;
        }
        if (min != NULL && *min != '\0') {
            char *endptr = NULL;

            min_filter = g_ascii_strtoull(min, &endptr, 0);
            has_min_filter = endptr != min;
        }
        if (max != NULL && *max != '\0') {
            char *endptr = NULL;

            max_filter = g_ascii_strtoull(max, &endptr, 0);
            has_max_filter = endptr != max;
        }
        initialized = 1;
    }

    if (has_exact_filter) {
        return value == exact_filter;
    }
    if (has_min_filter && value < min_filter) {
        return false;
    }
    if (has_max_filter && value > max_filter) {
        return false;
    }

    return true;
}

static void ia64_trace_ldst(CPUIA64State *env, const char *op,
                            uint64_t address, uint8_t width, uint64_t value)
{
    IA64TranslateResult result;
    MMUAccessType access_type = g_str_equal(op, "store") ? MMU_DATA_STORE
                                                         : MMU_DATA_LOAD;
    bool has_paddr;
    uint64_t paddr;

    if (!ia64_ldst_trace_op_matches(op)) {
        return;
    }
    if (!ia64_ldst_trace_width_matches(width)) {
        return;
    }
    if (!ia64_ldst_trace_value_matches(value)) {
        return;
    }
    if (!ia64_ldst_trace_matches(address, 0, false, width) &&
        !ia64_ldst_trace_needs_paddr()) {
        return;
    }

    has_paddr = ia64_translate_address(env, address, access_type, 0, true,
                                       &result);
    paddr = has_paddr ? result.paddr : 0;
    IA64_PERF_INC(IA64_PERF_LDST_TRACE_PADDR_PROBE);

    if (!ia64_ldst_trace_matches(address, paddr, has_paddr, width)) {
        return;
    }

    trace_ia64_ldst_memory(env->ip, op, address, width, value);
    fprintf(stderr,
            "[ia64-ldst] ip=0x%016" PRIx64 " op=%s vaddr=0x%016" PRIx64
            " paddr=%s0x%016" PRIx64 " width=%u value=0x%016" PRIx64 "\n",
            env->ip, op, address, has_paddr ? "" : "?", paddr, width, value);
}

static bool ia64_ldst_decode_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_LDST_DECODE_TRACE") != NULL;
    }
    return enabled != 0;
}

static void ia64_trace_ldst_decoded(CPUIA64State *env, const char *op,
                                    uint64_t address, uint8_t width,
                                    uint64_t value,
                                    const IA64LdstImmediate *decoded)
{
    IA64TranslateResult result;
    MMUAccessType access_type = g_str_equal(op, "store") ? MMU_DATA_STORE
                                                         : MMU_DATA_LOAD;
    bool has_paddr;
    uint64_t paddr;
    uint64_t update = 0;

    if (!ia64_ldst_decode_trace_enabled() || !decoded) {
        return;
    }

    has_paddr = ia64_translate_address(env, address, access_type, 0, true,
                                       &result);
    paddr = has_paddr ? result.paddr : 0;

    if (!ia64_ldst_trace_op_matches(op) ||
        !ia64_ldst_trace_width_matches(width) ||
        !ia64_ldst_trace_value_matches(value) ||
        !ia64_ldst_trace_matches(address, paddr, has_paddr, width)) {
        return;
    }

    if (decoded->base_update) {
        update = decoded->update_from_register
            ? ia64_read_gr(env, decoded->update_source)
            : (uint64_t)decoded->immediate;
    }

    fprintf(stderr,
            "[ia64-ldst-decoded] ip=0x%016" PRIx64
            " op=%s vaddr=0x%016" PRIx64 " paddr=%s0x%016" PRIx64
            " width=%u value=0x%016" PRIx64
            " base=r%u base-value=0x%016" PRIx64
            " target=r%u source=r%u source-value=0x%016" PRIx64
            " update=%s0x%016" PRIx64 " update-source=r%u"
            " cfm=0x%016" PRIx64 " pr=0x%016" PRIx64
            " r1=0x%016" PRIx64 " r8=0x%016" PRIx64
            " r12=0x%016" PRIx64 " r13=0x%016" PRIx64
            " b0=0x%016" PRIx64 " b6=0x%016" PRIx64 "\n",
            env->ip, op, address, has_paddr ? "" : "?", paddr, width, value,
            decoded->base, ia64_read_gr(env, decoded->base),
            decoded->target, decoded->source, ia64_read_gr(env, decoded->source),
            decoded->base_update ? "" : "none:", update,
            decoded->update_source, env->cfm, env->pr,
            ia64_read_gr(env, 1), ia64_read_gr(env, 8),
            ia64_read_gr(env, 12), ia64_read_gr(env, 13),
            env->br[0], env->br[6]);
}

static bool ia64_alat_ranges_overlap(uint64_t a, uint8_t a_width,
                                     uint64_t b, uint8_t b_width)
{
    uint64_t a_end;
    uint64_t b_end;

    if (a_width == 0 || b_width == 0) {
        return false;
    }

    a_end = a + a_width - 1;
    b_end = b + b_width - 1;
    if (a_end < a || b_end < b) {
        return true;
    }

    return a <= b_end && b <= a_end;
}

static void ia64_alat_resolve_address(CPUIA64State *env, uint64_t address,
                                      MMUAccessType access_type,
                                      uint64_t *resolved, bool *physical)
{
    IA64TranslateResult result;

    IA64_PERF_INC(IA64_PERF_ALAT_RESOLVE);
    if (ia64_translate_address_no_detail(env, address, access_type, 0, true,
                                         &result)) {
        *resolved = result.paddr;
        *physical = true;
    } else {
        *resolved = address;
        *physical = false;
    }
}

static void ia64_alat_record_load(CPUIA64State *env, uint8_t target,
                                  uint64_t address, uint8_t width)
{
    uint64_t resolved;
    bool physical;

    IA64_PERF_INC(IA64_PERF_ALAT_RECORD_LOAD);
    if (target == 0 || target >= IA64_GR_COUNT) {
        return;
    }

    ia64_alat_resolve_address(env, address, MMU_DATA_LOAD,
                              &resolved, &physical);
    ia64_alat_record_gr(env, target, resolved, width, physical);
}

static void ia64_alat_invalidate_store(CPUIA64State *env, uint64_t address,
                                       uint8_t width)
{
    uint64_t resolved;
    bool physical;
    uint32_t valid_mask = env->alat.valid_mask;

    IA64_PERF_INC(IA64_PERF_ALAT_INVALIDATE_STORE);
    if (valid_mask == 0) {
        return;
    }

    ia64_alat_resolve_address(env, address, MMU_DATA_STORE,
                              &resolved, &physical);
    for (unsigned i = 0; i < IA64_ALAT_COUNT; i++) {
        IA64AlatEntry *entry = &env->alat.entries[i];

        if ((valid_mask & (1u << i)) != 0 &&
            entry->physical == physical &&
            ia64_alat_ranges_overlap(entry->address, entry->width,
                                     resolved, width)) {
            ia64_alat_set_valid(env, i, false);
        }
    }
}

static void ia64_st_le_unaligned(CPUIA64State *env, uint64_t address,
                                 uint8_t width, uint64_t value)
{
    for (uint8_t i = 0; i < width; i++) {
        cpu_stb_data_ra(env, address + i, (value >> (i * 8)) & 0xff,
                        GETPC());
    }
}

/*
 * Debug shadow of RSE backing-store spills (VIBTANIUM_RSE_SHADOW=1).
 * Every RSE spill records address->value; every RSE fill/loadrs read
 * cross-checks guest memory against the shadow.  Plain guest stores
 * invalidate overlapping entries, so a fill that reads a value the RSE
 * never spilled ("unspilled") or that diverged from the spilled value
 * ("mismatch") points at lost or corrupted stacked-register state.
 * Region-7 addresses only (kernel RBS) to bound noise.
 */
typedef struct IA64RseShadowEntry {
    uint64_t value;
    bool from_guest_store;
} IA64RseShadowEntry;

static GHashTable *ia64_rse_shadow_table;
static uint64_t ia64_rse_shadow_spills;
static uint64_t ia64_rse_shadow_checks;
static uint64_t ia64_rse_shadow_virgin;
static uint64_t ia64_rse_shadow_guest_fill;
static uint64_t ia64_rse_shadow_mismatches;
static uint64_t ia64_rse_shadow_guest_mismatches;
static int ia64_rse_shadow_logged;

static bool ia64_rse_shadow_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_RSE_SHADOW") != NULL;
        if (enabled) {
            ia64_rse_shadow_table =
                g_hash_table_new_full(g_direct_hash, g_direct_equal,
                                      NULL, g_free);
        }
    }
    return enabled != 0;
}

static bool ia64_rse_shadow_tracked(uint64_t address)
{
    return (address >> 61) == 7;
}

static void ia64_rse_shadow_set(uint64_t address, uint64_t value,
                                bool from_guest_store)
{
    IA64RseShadowEntry *entry = g_new(IA64RseShadowEntry, 1);

    entry->value = value;
    entry->from_guest_store = from_guest_store;
    g_hash_table_insert(ia64_rse_shadow_table, (gpointer)address, entry);
}

static void ia64_rse_shadow_note_spill(uint64_t address, uint64_t value)
{
    if (!ia64_rse_shadow_enabled() || !ia64_rse_shadow_tracked(address)) {
        return;
    }
    ia64_rse_shadow_set(address, value, false);
    ia64_rse_shadow_spills++;
}

static void ia64_rse_shadow_note_store(uint64_t address, uint8_t width,
                                       uint64_t value)
{
    if (!ia64_rse_shadow_enabled() || !ia64_rse_shadow_tracked(address)) {
        return;
    }
    if (width == 8 && (address & 7) == 0) {
        ia64_rse_shadow_set(address, value, true);
        return;
    }
    for (uint64_t a = address & ~7ULL; a <= ((address + width - 1) & ~7ULL);
         a += 8) {
        g_hash_table_remove(ia64_rse_shadow_table, (gpointer)a);
    }
}

static void ia64_rse_shadow_summary(void)
{
    fprintf(stderr,
            "[ia64-rse-shadow] SUMMARY checks=%" PRIu64
            " spills=%" PRIu64 " virgin=%" PRIu64
            " guest-fill=%" PRIu64 " rse-mismatch=%" PRIu64
            " guest-mismatch=%" PRIu64 "\n",
            ia64_rse_shadow_checks, ia64_rse_shadow_spills,
            ia64_rse_shadow_virgin, ia64_rse_shadow_guest_fill,
            ia64_rse_shadow_mismatches, ia64_rse_shadow_guest_mismatches);
}

static void ia64_rse_shadow_check_fill(CPUIA64State *env, uint64_t address,
                                       uint64_t value)
{
    IA64RseShadowEntry *entry;

    if (!ia64_rse_shadow_enabled() || !ia64_rse_shadow_tracked(address)) {
        return;
    }
    ia64_rse_shadow_checks++;
    if ((ia64_rse_shadow_checks & 0xffff) == 0) {
        ia64_rse_shadow_summary();
    }
    entry = g_hash_table_lookup(ia64_rse_shadow_table, (gpointer)address);
    if (entry == NULL) {
        ia64_rse_shadow_virgin++;
        return;
    }
    if (entry->value == value) {
        if (entry->from_guest_store) {
            ia64_rse_shadow_guest_fill++;
        }
        return;
    }
    if (entry->from_guest_store) {
        ia64_rse_shadow_guest_mismatches++;
    } else {
        ia64_rse_shadow_mismatches++;
    }
    if (ia64_rse_shadow_logged < 60) {
        ia64_rse_shadow_logged++;
        fprintf(stderr,
                "[ia64-rse-shadow] MISMATCH%s ip=0x%016" PRIx64
                " addr=0x%016" PRIx64 " mem=0x%016" PRIx64
                " shadow=0x%016" PRIx64 "\n",
                entry->from_guest_store ? "-GUEST" : "-RSE", env->ip,
                address, value, entry->value);
        ia64_rse_shadow_summary();
    }
}

static uint64_t ia64_ldst_read(CPUIA64State *env, uint64_t address,
                               uint8_t width)
{
    uint64_t value;

    IA64_PERF_INC(IA64_PERF_LDST_READ);
    if (width > 1 && (address & (width - 1)) != 0) {
        IA64_PERF_INC(IA64_PERF_LDST_UNALIGNED_READ);
        value = ia64_ld_le_unaligned(env, address, width);
        ia64_trace_ldst(env, "load", address, width, value);
        return value;
    }

    switch (width) {
    case 1:
        value = cpu_ldub_data_ra(env, address, GETPC());
        break;
    case 2:
        value = cpu_lduw_le_data_ra(env, address, GETPC());
        break;
    case 4:
        value = cpu_ldl_le_data_ra(env, address, GETPC());
        break;
    case 8:
        value = cpu_ldq_le_data_ra(env, address, GETPC());
        break;
    default:
        g_assert_not_reached();
    }

    ia64_trace_ldst(env, "load", address, width, value);
    return value;
}

static void ia64_ldst_write(CPUIA64State *env, uint64_t address,
                            uint8_t width, uint64_t value)
{
    IA64_PERF_INC(IA64_PERF_LDST_WRITE);
    ia64_rse_shadow_note_store(address, width, value);
    ia64_trace_ldst(env, "store", address, width, value);

    if (width > 1 && (address & (width - 1)) != 0) {
        IA64_PERF_INC(IA64_PERF_LDST_UNALIGNED_WRITE);
        ia64_st_le_unaligned(env, address, width, value);
        ia64_alat_invalidate_store(env, address, width);
        return;
    }

    switch (width) {
    case 1:
        cpu_stb_data_ra(env, address, value, GETPC());
        break;
    case 2:
        cpu_stw_le_data_ra(env, address, value, GETPC());
        break;
    case 4:
        cpu_stl_le_data_ra(env, address, value, GETPC());
        break;
    case 8:
        cpu_stq_le_data_ra(env, address, value, GETPC());
        break;
    default:
        g_assert_not_reached();
    }

    ia64_alat_invalidate_store(env, address, width);
}

static void ia64_probe_store_access(CPUIA64State *env, uint64_t address)
{
    IA64TranslateResult result;

    if (!ia64_translate_address(env, address, MMU_DATA_STORE, 0, false,
                                &result)) {
        ia64_exit_after_translation_fault(env, &result);
    }
}

static bool ia64_ldst_defer_nat_consumption(CPUIA64State *env,
                                            const IA64LdstImmediate *decoded)
{
    if (!ia64_memory_class_is_control_speculative(decoded->memory_class)) {
        return false;
    }

    ia64_write_gr_nat(env, decoded->target, true);
    ia64_alat_invalidate_gr(env, decoded->target);
    return true;
}

static G_NORETURN void ia64_exit_after_register_nat_consumption(
    CPUIA64State *env, MMUAccessType access_type, const char *detail)
{
    CPUState *cpu = env_cpu(env);

    ia64_deliver_exception(env, IA64_EXCEPTION_REGISTER_NAT_CONSUMPTION,
                           env->ip, access_type, detail);
    IA64_PERF_INC(IA64_PERF_CPU_LOOP_EXIT);
    cpu_loop_exit(cpu);
}

static bool ia64_ldst_maybe_defer_control_speculative(
    CPUIA64State *env, const IA64LdstImmediate *decoded, uint64_t address)
{
    if (!ia64_control_speculative_load_defer(env, decoded->memory_class,
                                             false, address, NULL)) {
        return false;
    }

    ia64_write_gr_nat(env, decoded->target, true);
    ia64_alat_invalidate_gr(env, decoded->target);
    return true;
}

static void ia64_ldst_apply_base_update(CPUIA64State *env,
                                        const IA64LdstImmediate *decoded,
                                        uint64_t address)
{
    uint64_t update;

    if (!decoded->base_update) {
        return;
    }

    if (decoded->update_from_register &&
        ia64_read_gr_nat(env, decoded->update_source)) {
        ia64_write_gr_nat(env, decoded->base, true);
        return;
    }

    update = decoded->update_from_register
        ? ia64_read_gr(env, decoded->update_source)
        : (uint64_t)decoded->immediate;
    ia64_write_gr(env, decoded->base, address + update);
}

static uint64_t ia64_ldst_unat_bit(uint64_t address)
{
    return UINT64_C(1) << ia64_rse_nat_collection_bit(address);
}

static void ia64_ldst_write_unat(CPUIA64State *env, uint64_t unat)
{
    env->nat.unat = unat;
    env->ar[IA64_AR_UNAT] = unat;
}

static const char *ia64_atomic_name(IA64AtomicKind kind, bool release)
{
    switch (kind) {
    case IA64_ATOMIC_CMPXCHG:
        return release ? "cmpxchg.rel" : "cmpxchg.acq";
    case IA64_ATOMIC_XCHG:
        return "xchg";
    case IA64_ATOMIC_FETCHADD:
        return release ? "fetchadd.rel" : "fetchadd.acq";
    default:
        g_assert_not_reached();
    }
}

static uint64_t ia64_width_mask(uint8_t width)
{
    switch (width) {
    case 1:
        return UINT64_C(0xff);
    case 2:
        return UINT64_C(0xffff);
    case 4:
        return UINT64_C(0xffffffff);
    case 8:
        return UINT64_MAX;
    default:
        g_assert_not_reached();
    }
}

static bool ia64_atomic_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_ATOMIC_TRACE") != NULL;
    }
    return enabled != 0;
}

static void ia64_trace_atomic(CPUIA64State *env,
                              const IA64AtomicInstruction *decoded,
                              uint64_t address, uint64_t old_value,
                              uint64_t store_value, uint64_t compare_value)
{
    const char *op = ia64_atomic_name(decoded->kind, decoded->release);

    trace_ia64_atomic_memory(env->ip, op, address, decoded->width,
                             old_value, store_value, compare_value,
                             decoded->target, decoded->source,
                             decoded->base);
    if (ia64_atomic_trace_enabled()) {
        fprintf(stderr,
                "[ia64-atomic] ip=0x%016" PRIx64 " op=%s"
                " addr=0x%016" PRIx64 " width=%u old=0x%016" PRIx64
                " store=0x%016" PRIx64 " compare=0x%016" PRIx64
                " target=r%u source=r%u base=r%u\n",
                env->ip, op, address, decoded->width, old_value, store_value,
                compare_value, decoded->target, decoded->source,
                decoded->base);
    }
}

static bool exec_m_atomic(CPUIA64State *env,
                          const IA64AtomicInstruction *decoded)
{
    uint64_t address;
    uint64_t old_value;
    uint64_t store_value = 0;
    uint64_t compare_value = 0;
    uint64_t mask = ia64_width_mask(decoded->width);
    bool write_memory = false;

    if (ia64_read_gr_nat(env, decoded->base)) {
        ia64_exit_after_register_nat_consumption(env, MMU_DATA_LOAD,
                                                 "atomic base NaT");
    }
    address = ia64_read_gr(env, decoded->base);

    IA64_PERF_INC(IA64_PERF_ATOMIC_MEMORY_OP);
    if (decoded->kind == IA64_ATOMIC_CMPXCHG) {
        /*
         * cmpxchg requires write privilege even when the compare fails and
         * no store is performed, so let access/dirty faults retire first.
         */
        ia64_probe_store_access(env, address);
    }

    old_value = ia64_ldst_read(env, address, decoded->width);

    switch (decoded->kind) {
    case IA64_ATOMIC_CMPXCHG:
        if (ia64_read_gr_nat(env, decoded->source)) {
            ia64_exit_after_register_nat_consumption(env, MMU_DATA_STORE,
                                                     "cmpxchg source NaT");
        }
        store_value = ia64_read_gr(env, decoded->source);
        compare_value = env->ar[IA64_AR_CCV] & mask;
        write_memory = (old_value & mask) == compare_value;
        break;
    case IA64_ATOMIC_XCHG:
        if (ia64_read_gr_nat(env, decoded->source)) {
            ia64_exit_after_register_nat_consumption(env, MMU_DATA_STORE,
                                                     "xchg source NaT");
        }
        store_value = ia64_read_gr(env, decoded->source);
        write_memory = true;
        break;
    case IA64_ATOMIC_FETCHADD:
        store_value = old_value + (uint64_t)decoded->immediate;
        compare_value = (uint64_t)decoded->immediate;
        write_memory = true;
        break;
    default:
        g_assert_not_reached();
    }

    if (write_memory) {
        ia64_ldst_write(env, address, decoded->width, store_value);
    }

    ia64_write_gr(env, decoded->target, old_value);
    ia64_trace_atomic(env, decoded, address, old_value, store_value,
                      compare_value);
    return true;
}

static bool exec_ldst_immediate(CPUIA64State *env,
                                const IA64LdstImmediate *decoded)
{
    uint64_t address;
    bool check_clear;
    bool check_no_clear;

    switch (decoded->kind) {
    case IA64_LDST_IMM_LOAD:
        if (ia64_read_gr_nat(env, decoded->base)) {
            if (ia64_ldst_defer_nat_consumption(env, decoded)) {
                env->gr[0] = 0;
                return true;
            }
            ia64_exit_after_register_nat_consumption(env, MMU_DATA_LOAD,
                                                     "load base NaT");
        }
        address = ia64_read_gr(env, decoded->base);
        if (decoded->target != 0) {
            uint64_t value;

            check_clear = decoded->memory_class == 8 ||
                          decoded->memory_class == 0x0a;
            check_no_clear = decoded->memory_class == 9;
            if (check_clear || check_no_clear) {
                uint64_t resolved;
                bool physical;

                ia64_alat_resolve_address(env, address, MMU_DATA_LOAD,
                                          &resolved, &physical);
                if (ia64_alat_check_gr(env, decoded->target, resolved,
                                       decoded->width, physical,
                                       check_clear)) {
                    break;
                }
            }

            if (ia64_ldst_maybe_defer_control_speculative(env, decoded,
                                                          address)) {
                break;
            }

            value = ia64_ldst_read(env, address, decoded->width);

            ia64_trace_ldst_decoded(
                env,
                ia64_ldst_immediate_is_fill(decoded) ? "fill" : "load",
                address, decoded->width, value, decoded);
            ia64_write_gr(env, decoded->target, value);
            if (ia64_ldst_immediate_is_fill(decoded)) {
                ia64_write_gr_nat(
                    env, decoded->target,
                    (env->nat.unat & ia64_ldst_unat_bit(address)) != 0);
            }
            if (decoded->memory_class == 2 || decoded->memory_class == 3 ||
                check_no_clear) {
                ia64_alat_record_load(env, decoded->target, address,
                                      decoded->width);
            }
        }
        break;
    case IA64_LDST_IMM_STORE:
    {
        uint64_t value;

        if (ia64_read_gr_nat(env, decoded->base)) {
            ia64_exit_after_register_nat_consumption(env, MMU_DATA_STORE,
                                                     "store base NaT");
        }
        if (!ia64_ldst_immediate_is_spill(decoded) &&
            ia64_read_gr_nat(env, decoded->source)) {
            ia64_exit_after_register_nat_consumption(env, MMU_DATA_STORE,
                                                     "store source NaT");
        }

        address = ia64_read_gr(env, decoded->base);
        value = ia64_read_gr(env, decoded->source);

        ia64_trace_ldst_decoded(
            env, ia64_ldst_immediate_is_spill(decoded) ? "spill" : "store",
            address, decoded->width, value, decoded);
        ia64_ldst_write(env, address, decoded->width, value);
        if (ia64_ldst_immediate_is_spill(decoded)) {
            uint64_t bit = ia64_ldst_unat_bit(address);
            uint64_t unat = env->nat.unat;

            if (ia64_read_gr_nat(env, decoded->source)) {
                unat |= bit;
            } else {
                unat &= ~bit;
            }
            ia64_ldst_write_unat(env, unat);
        }
        break;
    }
    case IA64_LDST_IMM_PREFETCH:
        if (ia64_read_gr_nat(env, decoded->base)) {
            ia64_exit_after_register_nat_consumption(env, MMU_DATA_LOAD,
                                                     "prefetch base NaT");
        }
        address = ia64_read_gr(env, decoded->base);
        break;
    default:
        g_assert_not_reached();
    }

    ia64_ldst_apply_base_update(env, decoded, address);
    env->gr[0] = 0;
    return true;
}
