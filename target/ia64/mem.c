/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "mem.h"
#include "exec/page-protection.h"
#include "perf.h"
#include "system/memory.h"
#include "trace-target_ia64.h"

#define IA64_PHYSICAL_ADDRESS_MASK UINT64_C(0x1fffffffffffffff)
#define IA64_REGIONLESS_ADDRESS_MASK UINT64_C(0x1fffffffffffffff)
#define IA64_DCR_BE_BIT UINT64_C(0x0000000000000002)
#define IA64_DCR_DM_BIT UINT64_C(0x0000000000000100)
#define IA64_DCR_DP_BIT UINT64_C(0x0000000000000200)
#define IA64_DCR_DR_BIT UINT64_C(0x0000000000001000)
#define IA64_DCR_DA_BIT UINT64_C(0x0000000000002000)
#define IA64_PTA_VE_BIT UINT64_C(0x0000000000000001)
#define IA64_PTA_VF_BIT UINT64_C(0x0000000000000100)
#define IA64_PSR_DT_BIT UINT64_C(0x0000000000020000)
#define IA64_PSR_IC_BIT UINT64_C(0x0000000000002000)
#define IA64_PSR_RT_BIT UINT64_C(0x0000000008000000)
#define IA64_PSR_IT_BIT UINT64_C(0x0000001000000000)
#define IA64_PSR_ED_BIT UINT64_C(0x0000080000000000)
#define IA64_PSR_AC_BIT UINT64_C(0x0000000000000008)
#define IA64_PSR_CPL_SHIFT 32
#define IA64_INSERTION_PPN_MASK UINT64_C(0x0003fffffffff000)
#define IA64_FIRMWARE_IDENTITY_PAGE_BITS 22
#define IA64_FIRMWARE_IDENTITY_TR_ATTR \
    (UINT64_C(1) | (UINT64_C(1) << 5) | (UINT64_C(1) << 6) | \
     (UINT64_C(3) << 9) | (UINT64_C(1) << 52))
#define IA64_VHPT_SHORT_RESERVED_MASK \
    (UINT64_C(0x2) | UINT64_C(0x000c000000000000))
#define IA64_TRANSLATION_LOOKUP_CACHE_PAGE_SHIFT 12
#define IA64_TRANSLATION_LOOKUP_CACHE_MASK \
    (IA64_TRANSLATION_LOOKUP_CACHE_COUNT - 1)
#define IA64_VHPT_REGION_BITS_MASK UINT64_C(0xe000000000000000)
#define IA64_VHPT_BASE_ADDRESS_MASK UINT64_C(0x1fffffffffff8000)
#define IA64_VHPT_VA_HASH_MASK UINT64_C(0x0007ffffffffffff)
#define IA64_HOST_TLB_MIN_PAGE_BITS 12

#if (IA64_TRANSLATION_LOOKUP_CACHE_COUNT & \
     IA64_TRANSLATION_LOOKUP_CACHE_MASK) != 0
#error "IA64_TRANSLATION_LOOKUP_CACHE_COUNT must remain a power of two"
#endif

static bool ia64_translate_address_common(CPUIA64State *env, vaddr address,
                                          MMUAccessType access_type,
                                          int mmu_idx, int cpl, bool debug,
                                          bool format_detail,
                                          IA64TranslateResult *result);
static const char *ia64_access_kind(bool instruction);

const char *ia64_translate_status_name(IA64TranslateStatus status)
{
    switch (status) {
    case IA64_TRANSLATE_OK:
        return "ok";
    case IA64_TRANSLATE_BAD_ADDRESS:
        return "bad-address";
    case IA64_TRANSLATE_UNIMPLEMENTED:
        return "unimplemented";
    case IA64_TRANSLATE_TLB_MISS:
        return "tlb-miss";
    case IA64_TRANSLATE_NOT_PRESENT:
        return "not-present";
    case IA64_TRANSLATE_ACCESS_BIT:
        return "access-bit";
    case IA64_TRANSLATE_DIRTY_BIT:
        return "dirty-bit";
    case IA64_TRANSLATE_ACCESS_DENIED:
        return "access-denied";
    default:
        return "unknown";
    }
}

uint8_t ia64_va_region(vaddr address)
{
    return address >> 61;
}

uint32_t ia64_region_id(uint64_t rr)
{
    return (rr >> 8) & 0x00ffffff;
}

bool ia64_region_vhpt_enabled(uint64_t rr)
{
    return (rr & 1) != 0;
}

uint8_t ia64_region_page_size(uint64_t rr)
{
    return (rr >> 2) & 0x3f;
}

static uint64_t ia64_mask_for_shift(unsigned shift)
{
    return shift >= 64 ? UINT64_MAX : ((UINT64_C(1) << shift) - 1);
}

uint64_t ia64_default_itir(CPUIA64State *env, vaddr address)
{
    uint64_t rr;
    uint8_t page_size;

    if (!env) {
        return 0;
    }

    rr = env->rr[ia64_va_region(address)];
    page_size = ia64_region_page_size(rr);
    return ((uint64_t)ia64_region_id(rr) << 8) | ((uint64_t)page_size << 2);
}

static bool ia64_pta_is_long_format(uint64_t pta)
{
    return ((pta >> 8) & 1) != 0;
}

uint64_t ia64_vhpt_hash_address(CPUIA64State *env, vaddr address)
{
    uint64_t pta;
    uint64_t rr;
    bool long_format;
    uint8_t pta_size;
    uint8_t page_size;
    uint64_t hpn;
    uint64_t hash_index;
    uint64_t offset;
    uint64_t mask;
    uint64_t region_bits;
    uint64_t base;

    if (!env) {
        return 0;
    }

    pta = env->cr[IA64_CR_PTA];
    rr = env->rr[ia64_va_region(address)];
    long_format = ia64_pta_is_long_format(pta);
    pta_size = (pta >> 2) & 0x3f;
    page_size = ia64_region_page_size(rr);
    hpn = page_size >= 64 ? 0 :
          (address & IA64_VHPT_VA_HASH_MASK) >> page_size;
    hash_index = long_format ? hpn ^ (ia64_region_id(rr) & 0x3ffff) : hpn;
    offset = hash_index << (long_format ? 5 : 3);
    mask = ia64_mask_for_shift(pta_size);
    region_bits = long_format ? pta & IA64_VHPT_REGION_BITS_MASK
                              : address & IA64_VHPT_REGION_BITS_MASK;
    base = pta & IA64_VHPT_BASE_ADDRESS_MASK;

    return region_bits | (base & ~mask) | (offset & mask);
}

uint64_t ia64_vhpt_tag(CPUIA64State *env, vaddr address)
{
    uint64_t rr;
    uint64_t hpn;

    if (!env) {
        return 0;
    }

    rr = env->rr[ia64_va_region(address)];
    hpn = ia64_region_page_size(rr) >= 64 ? 0 :
          (address & IA64_VHPT_VA_HASH_MASK) >> ia64_region_page_size(rr);
    return hpn ^ ((uint64_t)(ia64_region_id(rr) & 0x3ffff) << 39);
}

bool ia64_page_size_supported(uint8_t page_size)
{
    switch (page_size) {
    case 12:
    case 13:
    case 14:
    case 16:
    case 18:
    case 20:
    case 21:
    case 22:
    case 24:
    case 26:
    case 28:
        return true;
    default:
        return false;
    }
}

bool ia64_host_tlb_flush_span(vaddr address, uint8_t page_size,
                              vaddr *start, uint64_t *len)
{
    uint64_t size;

    if (page_size < IA64_HOST_TLB_MIN_PAGE_BITS || page_size >= 40) {
        return false;
    }

    size = UINT64_C(1) << page_size;
    if (start) {
        *start = address & ~(size - 1);
    }
    if (len) {
        *len = size;
    }
    return true;
}

static uint64_t ia64_page_mask(uint8_t page_size)
{
    return (UINT64_C(1) << page_size) - 1;
}

static uint64_t ia64_page_base(vaddr address, uint8_t page_size)
{
    return (address & IA64_REGIONLESS_ADDRESS_MASK) &
           ~ia64_page_mask(page_size);
}

static bool ia64_mmu_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_MMU_TRACE") != NULL;
    }
    return enabled != 0;
}

bool ia64_vhpt_walk_runtime_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_VHPT_WALK") != NULL;
    }
    return enabled != 0;
}

void ia64_firmware_identity_tlb_set(CPUIA64State *env, bool enabled)
{
    if (env) {
        env->firmware_identity_tlb = enabled;
    }
}

static const char *ia64_translation_kind(bool instruction, bool pinned)
{
    if (pinned) {
        return instruction ? "itr" : "dtr";
    }
    return instruction ? "itc" : "dtc";
}

static const char *ia64_access_kind(bool instruction)
{
    return instruction ? "instruction" : "data";
}

static bool ia64_translation_required(uint64_t psr, MMUAccessType access_type)
{
    switch (access_type) {
    case MMU_INST_FETCH:
        return (psr & IA64_PSR_IT_BIT) != 0;
    case MMU_DATA_LOAD:
    case MMU_DATA_STORE:
        return (psr & IA64_PSR_DT_BIT) != 0;
    default:
        return (psr & IA64_PSR_RT_BIT) != 0;
    }
}

static int ia64_current_privilege_level(uint64_t psr)
{
    return (psr >> IA64_PSR_CPL_SHIFT) & 0x3;
}

static bool ia64_entry_matches(const IA64TranslationEntry *entry,
                               vaddr address, uint32_t rid)
{
    return entry->valid && entry->rid == rid &&
           entry->vaddr_base == ia64_page_base(address, entry->page_size);
}

static unsigned ia64_translation_lookup_cache_index(bool instruction,
                                                    vaddr address)
{
    uint64_t guest_page = address >> IA64_TRANSLATION_LOOKUP_CACHE_PAGE_SHIFT;

    guest_page ^= guest_page >> 6;
    if (instruction) {
        guest_page ^= IA64_TRANSLATION_LOOKUP_CACHE_COUNT / 2;
    }
    return guest_page & IA64_TRANSLATION_LOOKUP_CACHE_MASK;
}

void ia64_translation_lookup_cache_flush(CPUIA64State *env)
{
    if (!env) {
        return;
    }
    memset(env->memory.lookup_cache, 0, sizeof(env->memory.lookup_cache));
}

static bool ia64_lookup_translation_cache(CPUIA64State *env,
                                          bool instruction,
                                          vaddr address,
                                          uint32_t rid,
                                          const IA64TranslationEntry **entry)
{
    IA64TranslationEntry *cached =
        &env->memory.lookup_cache[
            ia64_translation_lookup_cache_index(instruction, address)];

    if (cached->instruction == instruction &&
        ia64_entry_matches(cached, address, rid)) {
        IA64_PERF_INC(IA64_PERF_TARGET_TRANSLATE_LOOKUP_CACHE_HIT);
        *entry = cached;
        return true;
    }

    IA64_PERF_INC(IA64_PERF_TARGET_TRANSLATE_LOOKUP_CACHE_MISS);
    return false;
}

static void ia64_store_translation_cache(CPUIA64State *env,
                                         bool instruction,
                                         vaddr address,
                                         const IA64TranslationEntry *entry)
{
    if (!entry) {
        return;
    }

    env->memory.lookup_cache[
        ia64_translation_lookup_cache_index(instruction, address)] = *entry;
}

static const IA64TranslationEntry *ia64_pick_best_entry(
    const IA64TranslationEntry *best,
    const IA64TranslationEntry *entry,
    vaddr address,
    uint32_t rid)
{
    if (!ia64_entry_matches(entry, address, rid)) {
        return best;
    }

    return !best || entry->page_size < best->page_size ? entry : best;
}

static const IA64TranslationEntry *ia64_lookup_translation(CPUIA64State *env,
                                                          bool instruction,
                                                          vaddr address)
{
    uint8_t region = ia64_va_region(address);
    uint32_t rid = ia64_region_id(env->rr[region]);
    const IA64TranslationEntry *best = NULL;
    const IA64TranslationEntry *tr = instruction ? env->memory.itr
                                                 : env->memory.dtr;
    const IA64TranslationEntry *tc = instruction ? env->memory.itc
                                                 : env->memory.dtc;

    if (ia64_lookup_translation_cache(env, instruction, address, rid, &best)) {
        return best;
    }

    for (unsigned i = 0; i < IA64_ITR_COUNT; i++) {
        best = ia64_pick_best_entry(best, &tr[i], address, rid);
    }
    for (unsigned i = 0; i < IA64_TC_COUNT; i++) {
        best = ia64_pick_best_entry(best, &tc[i], address, rid);
    }
    ia64_store_translation_cache(env, instruction, address, best);
    return best;
}

static bool ia64_vhpt_walk_enabled(CPUIA64State *env,
                                   MMUAccessType access_type, uint64_t rr)
{
    uint64_t psr = ia64_env_psr(env);

    if ((env->cr[IA64_CR_PTA] & IA64_PTA_VE_BIT) == 0 ||
        !ia64_region_vhpt_enabled(rr)) {
        return false;
    }

    switch (access_type) {
    case MMU_INST_FETCH:
        return (psr & (IA64_PSR_DT_BIT | IA64_PSR_IT_BIT |
                       IA64_PSR_IC_BIT)) ==
               (IA64_PSR_DT_BIT | IA64_PSR_IT_BIT | IA64_PSR_IC_BIT);
    case MMU_DATA_LOAD:
    case MMU_DATA_STORE:
        return (psr & (IA64_PSR_DT_BIT | IA64_PSR_IC_BIT)) ==
               (IA64_PSR_DT_BIT | IA64_PSR_IC_BIT);
    default:
        return (psr & (IA64_PSR_RT_BIT | IA64_PSR_IC_BIT)) ==
               (IA64_PSR_RT_BIT | IA64_PSR_IC_BIT);
    }
}

static bool ia64_vhpt_short_entry_valid(uint64_t entry, uint64_t itir)
{
    uint8_t page_size = (itir >> 2) & 0x3f;

    if (!ia64_page_size_supported(page_size)) {
        return false;
    }

    /*
     * For present short-format entries, bit 1 and bits 50:51 are reserved.
     * Not-present entries are deliberately loose: software owns the ignored
     * payload, but the walker still installs them so the retry reports a page
     * fault rather than another TLB miss.
     */
    if ((entry & 1) == 0) {
        return true;
    }

    return (entry & IA64_VHPT_SHORT_RESERVED_MASK) == 0;
}

static bool ia64_read_vhpt_u64(CPUIA64State *env, struct AddressSpace *as,
                               hwaddr paddr, uint64_t *value)
{
    MemTxResult memtx;

    if (!as || !value) {
        return false;
    }

    if (env->cr[IA64_CR_DCR] & IA64_DCR_BE_BIT) {
        *value = address_space_ldq_be(as, paddr, MEMTXATTRS_UNSPECIFIED,
                                      &memtx);
    } else {
        *value = address_space_ldq_le(as, paddr, MEMTXATTRS_UNSPECIFIED,
                                      &memtx);
    }

    return memtx == MEMTX_OK;
}

IA64VHPTWalkStatus ia64_try_vhpt_walk(CPUIA64State *env,
                                      struct AddressSpace *as,
                                      vaddr address,
                                      MMUAccessType access_type)
{
    IA64TranslateResult vhpt_addr;
    uint64_t rr;
    uint64_t pta;
    uint64_t iha;
    uint64_t itir;
    uint64_t entry;
    bool can_deliver_vhpt_fault;
    bool instruction = access_type == MMU_INST_FETCH;

    if (!env) {
        return IA64_VHPT_WALK_MISS;
    }

    rr = env->rr[ia64_va_region(address)];
    if (!ia64_vhpt_walk_enabled(env, access_type, rr)) {
        return IA64_VHPT_WALK_MISS;
    }

    IA64_PERF_INC(IA64_PERF_VHPT_WALK);
    pta = env->cr[IA64_CR_PTA];
    if (pta & IA64_PTA_VF_BIT) {
        IA64_PERF_INC(IA64_PERF_VHPT_WALK_LONG_UNSUPPORTED);
        return IA64_VHPT_WALK_MISS;
    }
    IA64_PERF_INC(IA64_PERF_VHPT_WALK_SHORT);

    iha = ia64_vhpt_hash_address(env, address);
    itir = ia64_default_itir(env, address);
    can_deliver_vhpt_fault = (ia64_env_psr(env) & IA64_PSR_IC_BIT) != 0;

    if (!ia64_translate_address_common(env, iha, MMU_DATA_LOAD,
                                       IA64_MMU_DATA_CPL0, 0, false, false,
                                       &vhpt_addr)) {
        IA64_PERF_INC(IA64_PERF_VHPT_WALK_VADDR_MISS);
        trace_ia64_vhpt_walk("vaddr-miss", ia64_access_kind(instruction),
                             address, iha, 0, 0, itir);
        if (can_deliver_vhpt_fault &&
            vhpt_addr.status == IA64_TRANSLATE_TLB_MISS) {
            IA64_PERF_INC(IA64_PERF_VHPT_WALK_FAULT);
            return IA64_VHPT_WALK_FAULT;
        }
        return IA64_VHPT_WALK_MISS;
    }

    if (!ia64_read_vhpt_u64(env, as, vhpt_addr.paddr, &entry)) {
        IA64_PERF_INC(IA64_PERF_VHPT_WALK_READ_FAIL);
        trace_ia64_vhpt_walk("read-fail", ia64_access_kind(instruction),
                             address, iha, vhpt_addr.paddr, 0, itir);
        return IA64_VHPT_WALK_MISS;
    }

    if (!ia64_vhpt_short_entry_valid(entry, itir)) {
        IA64_PERF_INC(IA64_PERF_VHPT_WALK_INVALID);
        trace_ia64_vhpt_walk("invalid", ia64_access_kind(instruction),
                             address, iha, vhpt_addr.paddr, entry, itir);
        return IA64_VHPT_WALK_MISS;
    }

    if (!ia64_install_translation(env, instruction, false, 0, address, entry,
                                  itir)) {
        IA64_PERF_INC(IA64_PERF_VHPT_WALK_INSTALL_FAIL);
        trace_ia64_vhpt_walk("install-fail", ia64_access_kind(instruction),
                             address, iha, vhpt_addr.paddr, entry, itir);
        return IA64_VHPT_WALK_MISS;
    }

    IA64_PERF_INC(IA64_PERF_VHPT_WALK_HIT);
    trace_ia64_vhpt_walk("hit", ia64_access_kind(instruction), address, iha,
                         vhpt_addr.paddr, entry, itir);
    if (ia64_mmu_trace_enabled()) {
        fprintf(stderr,
                "[ia64-vhpt-walk] status=hit kind=%s"
                " address=0x%016" VADDR_PRIx " iha=0x%016" PRIx64
                " paddr=0x%016" HWADDR_PRIx " entry=0x%016" PRIx64
                " itir=0x%016" PRIx64 "\n",
                ia64_access_kind(instruction), address, iha, vhpt_addr.paddr,
                entry, itir);
    }
    return IA64_VHPT_WALK_INSTALLED;
}

static void ia64_trace_translation_candidate(const char *kind,
                                             unsigned index,
                                             const IA64TranslationEntry *entry)
{
    trace_ia64_translation_candidate(kind, index, entry->valid,
                                     entry->vaddr_base, entry->paddr_base,
                                     entry->raw, entry->itir, entry->rid,
                                     entry->page_size, entry->access_rights);
    if (ia64_mmu_trace_enabled()) {
        fprintf(stderr,
                "[ia64-translation-entry] kind=%s index=%u valid=%u"
                " vbase=0x%016" PRIx64 " pbase=0x%016" PRIx64
                " raw=0x%016" PRIx64 " itir=0x%016" PRIx64
                " rid=0x%x ps=%u ar=%u pl=%u present=%u"
                " accessed=%u dirty=%u\n",
                kind, index, entry->valid, entry->vaddr_base,
                entry->paddr_base, entry->raw, entry->itir, entry->rid,
                entry->page_size, entry->access_rights,
                entry->privilege_level, entry->present, entry->accessed,
                entry->dirty);
    }
}

static void ia64_trace_translation_miss(CPUIA64State *env,
                                        bool instruction,
                                        vaddr address,
                                        uint64_t rr)
{
    uint8_t region = ia64_va_region(address);
    uint32_t rid = ia64_region_id(rr);
    uint8_t page_size = ia64_region_page_size(rr);
    uint64_t itir = ia64_default_itir(env, address);
    uint64_t iha = ia64_region_vhpt_enabled(rr) ?
                   ia64_vhpt_hash_address(env, address) : 0;
    uint64_t page_base = ia64_page_base(address, page_size);
    const IA64TranslationEntry *tr = instruction ? env->memory.itr
                                                 : env->memory.dtr;
    const IA64TranslationEntry *tc = instruction ? env->memory.itc
                                                 : env->memory.dtc;
    const char *tr_kind = ia64_translation_kind(instruction, true);
    const char *tc_kind = ia64_translation_kind(instruction, false);

    trace_ia64_translation_miss(ia64_access_kind(instruction), address,
                                page_base, rr, rid, page_size, env->psr,
                                env->cr[IA64_CR_PTA], itir, iha);
    if (ia64_mmu_trace_enabled()) {
        fprintf(stderr,
                "[ia64-translation-miss] kind=%s address=0x%016" VADDR_PRIx
                " page-base=0x%016" PRIx64 " region=%u rid=0x%x"
                " rr=0x%016" PRIx64 " ps=%u psr=0x%016" PRIx64
                " pta=0x%016" PRIx64 " itir=0x%016" PRIx64
                " iha=0x%016" PRIx64 "\n",
                ia64_access_kind(instruction), address, page_base, region,
                rid, rr, page_size, env->psr, env->cr[IA64_CR_PTA],
                itir, iha);
    }

    for (unsigned i = 0; i < IA64_ITR_COUNT; i++) {
        if (tr[i].valid) {
            ia64_trace_translation_candidate(tr_kind, i, &tr[i]);
        }
    }
    for (unsigned i = 0; i < IA64_TC_COUNT; i++) {
        if (tc[i].valid) {
            ia64_trace_translation_candidate(tc_kind, i, &tc[i]);
        }
    }
}

static bool ia64_translation_allows(const IA64TranslationEntry *entry,
                                    MMUAccessType access_type,
                                    int cpl)
{
    bool read = access_type == MMU_DATA_LOAD;
    bool write = access_type == MMU_DATA_STORE;
    bool execute = access_type == MMU_INST_FETCH;
    bool privileged_enough = cpl <= entry->privilege_level;
    bool more_privileged = cpl < entry->privilege_level;

    if (entry->access_rights == 7) {
        if (execute) {
            return true;
        }
        return read && cpl == 0;
    }

    if (!privileged_enough) {
        return false;
    }

    switch (entry->access_rights) {
    case 0:
        return read;
    case 1:
        return read || execute;
    case 2:
        return read || write;
    case 3:
        return read || write || execute;
    case 4:
        return read || (write && more_privileged);
    case 5:
        return read || execute || (write && more_privileged);
    case 6:
        return read || write ||
               (execute && cpl == entry->privilege_level);
    default:
        return false;
    }
}

static int ia64_entry_prot(const IA64TranslationEntry *entry)
{
    int prot = 0;

    if (!entry->accessed) {
        return 0;
    }

    if (entry->access_rights == 7) {
        return PAGE_READ | PAGE_EXEC;
    }

    switch (entry->access_rights) {
    case 0:
    case 4:
        prot = PAGE_READ;
        break;
    case 1:
    case 5:
        prot = PAGE_READ | PAGE_EXEC;
        break;
    case 2:
    case 6:
        prot = PAGE_READ | PAGE_WRITE;
        break;
    case 3:
        prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        break;
    default:
        break;
    }
    if (!entry->dirty) {
        prot &= ~PAGE_WRITE;
    }
    return prot;
}

static void ia64_invalidate_overlapping_entries(IA64TranslationEntry *entries,
                                                unsigned count,
                                                const IA64TranslationEntry *entry,
                                                bool all_rids)
{
    uint64_t start = entry->vaddr_base;
    uint64_t end = start + (UINT64_C(1) << entry->page_size);

    for (unsigned i = 0; i < count; i++) {
        IA64TranslationEntry *existing = &entries[i];
        uint64_t existing_start;
        uint64_t existing_end;

        if (!existing->valid || (!all_rids && existing->rid != entry->rid)) {
            continue;
        }

        existing_start = existing->vaddr_base;
        existing_end = existing_start + (UINT64_C(1) << existing->page_size);
        if (start < existing_end && existing_start < end) {
            existing->valid = false;
        }
    }
}

bool ia64_install_translation(CPUIA64State *env, bool instruction,
                              bool pinned, uint8_t slot,
                              vaddr virtual_address,
                              uint64_t translation_format,
                              uint64_t itir)
{
    uint8_t region;
    uint8_t page_size = (itir >> 2) & 0x3f;
    uint64_t page_mask;
    IA64TranslationEntry entry;
    IA64TranslationEntry *tr;
    IA64TranslationEntry *tc;
    uint8_t *next_tc;

    if (!env || !ia64_page_size_supported(page_size)) {
        return false;
    }

    IA64_PERF_INC(IA64_PERF_TARGET_TRANSLATION_INSTALL);
    IA64_PERF_INC(instruction ? IA64_PERF_TARGET_TRANSLATION_INSTALL_INST :
                  IA64_PERF_TARGET_TRANSLATION_INSTALL_DATA);

    page_mask = ia64_page_mask(page_size);
    region = ia64_va_region(virtual_address);
    entry = (IA64TranslationEntry) {
        .valid = true,
        .instruction = instruction,
        .pinned = pinned,
        .vaddr_base = ia64_page_base(virtual_address, page_size),
        .paddr_base = (translation_format & IA64_INSERTION_PPN_MASK) &
                      ~page_mask,
        .raw = translation_format,
        .itir = itir,
        .rid = ia64_region_id(env->rr[region]),
        .key = (itir >> 8) & 0x00ffffff,
        .page_size = page_size,
        .memory_attribute = (translation_format >> 2) & 0x7,
        .privilege_level = (translation_format >> 7) & 0x3,
        .access_rights = (translation_format >> 9) & 0x7,
        .present = (translation_format & 1) != 0,
        .accessed = (translation_format & (1ULL << 5)) != 0,
        .dirty = (translation_format & (1ULL << 6)) != 0,
        .exception_deferral = (translation_format & (1ULL << 52)) != 0,
    };

    tr = instruction ? env->memory.itr : env->memory.dtr;
    tc = instruction ? env->memory.itc : env->memory.dtc;
    next_tc = instruction ? &env->memory.next_itc : &env->memory.next_dtc;

    if (pinned) {
        if (slot >= IA64_ITR_COUNT) {
            return false;
        }
        ia64_invalidate_overlapping_entries(tr, IA64_ITR_COUNT, &entry, false);
        ia64_invalidate_overlapping_entries(tc, IA64_TC_COUNT, &entry, false);
        tr[slot] = entry;
    } else {
        ia64_invalidate_overlapping_entries(tc, IA64_TC_COUNT, &entry, false);
        tc[*next_tc % IA64_TC_COUNT] = entry;
        *next_tc = (*next_tc + 1) % IA64_TC_COUNT;
    }
    ia64_translation_lookup_cache_flush(env);

    trace_ia64_translation_install(ia64_translation_kind(instruction, pinned),
                                   slot, virtual_address, entry.vaddr_base,
                                   entry.paddr_base, entry.raw, entry.itir,
                                   entry.rid, entry.page_size,
                                   entry.access_rights);
    if (ia64_mmu_trace_enabled()) {
        fprintf(stderr,
                "[ia64-translation-install] kind=%s slot=%u"
                " va=0x%016" VADDR_PRIx " vbase=0x%016" PRIx64
                " pbase=0x%016" PRIx64 " raw=0x%016" PRIx64
                " itir=0x%016" PRIx64 " rid=0x%x ps=%u ar=%u"
                " pl=%u present=%u accessed=%u dirty=%u\n",
                ia64_translation_kind(instruction, pinned), slot,
                virtual_address, entry.vaddr_base, entry.paddr_base,
                entry.raw, entry.itir, entry.rid, entry.page_size,
                entry.access_rights, entry.privilege_level, entry.present,
                entry.accessed, entry.dirty);
    }
    return true;
}

static bool ia64_firmware_identity_region(uint8_t region)
{
    return region == 0 || region == 6 || region == 7;
}

bool ia64_firmware_identity_tlb_fill(CPUIA64State *env, vaddr address,
                                     MMUAccessType access_type, int mmu_idx,
                                     IA64TranslateResult *result)
{
    uint8_t region;
    uint64_t rr;
    uint64_t page_base;
    uint64_t translation;
    uint64_t itir;
    bool instruction = access_type == MMU_INST_FETCH;

    if (!env || !env->firmware_identity_tlb) {
        return false;
    }
    if (access_type != MMU_INST_FETCH &&
        access_type != MMU_DATA_LOAD &&
        access_type != MMU_DATA_STORE) {
        return false;
    }
    if (ia64_current_privilege_level(env->psr) != 0) {
        return false;
    }

    region = ia64_va_region(address);
    rr = env->rr[region];
    if (!ia64_firmware_identity_region(region) ||
        ia64_region_vhpt_enabled(rr)) {
        return false;
    }

    page_base = ia64_page_base(address, IA64_FIRMWARE_IDENTITY_PAGE_BITS);
    translation = (page_base & IA64_INSERTION_PPN_MASK) |
                  IA64_FIRMWARE_IDENTITY_TR_ATTR;
    itir = (uint64_t)IA64_FIRMWARE_IDENTITY_PAGE_BITS << 2;

    if (!ia64_install_translation(env, instruction, false, 0, address,
                                  translation, itir)) {
        return false;
    }

    if (ia64_mmu_trace_enabled()) {
        fprintf(stderr,
                "[ia64-firmware-identity-tlb] kind=%s"
                " address=0x%016" VADDR_PRIx " page-base=0x%016" PRIx64
                " paddr=0x%016" PRIx64 " itir=0x%016" PRIx64 "\n",
                ia64_access_kind(instruction), address, page_base,
                page_base & IA64_INSERTION_PPN_MASK, itir);
    }

    return ia64_translate_address_no_detail(env, address, access_type,
                                            mmu_idx, false, result);
}

static IA64TranslationEntry ia64_purge_probe(CPUIA64State *env, vaddr address,
                                             uint8_t page_size)
{
    if (!ia64_page_size_supported(page_size)) {
        page_size = ia64_region_page_size(env->rr[ia64_va_region(address)]);
    }
    return (IA64TranslationEntry) {
        .valid = true,
        .vaddr_base = ia64_page_base(address, page_size),
        .page_size = page_size,
        .rid = ia64_region_id(env->rr[ia64_va_region(address)]),
    };
}

/* ptc.l / ptc.g / ptc.ga: purge matching dynamic instruction/data TLB entries. */
void ia64_purge_translation_cache(CPUIA64State *env, vaddr address,
                                  uint8_t page_size, bool all_rids)
{
    IA64TranslationEntry probe;

    if (!env) {
        return;
    }
    IA64_PERF_INC(IA64_PERF_TARGET_TRANSLATION_PURGE_CACHE);
    probe = ia64_purge_probe(env, address, page_size);
    ia64_invalidate_overlapping_entries(env->memory.itc, IA64_TC_COUNT, &probe,
                                        all_rids);
    ia64_invalidate_overlapping_entries(env->memory.dtc, IA64_TC_COUNT, &probe,
                                        all_rids);
    ia64_translation_lookup_cache_flush(env);
}

/* ptr.i / ptr.d: purge a matching pinned instruction/data translation register. */
void ia64_purge_translation_register(CPUIA64State *env, bool instruction,
                                     vaddr address, uint8_t page_size)
{
    IA64TranslationEntry probe;

    if (!env) {
        return;
    }
    IA64_PERF_INC(IA64_PERF_TARGET_TRANSLATION_PURGE_REGISTER);
    probe = ia64_purge_probe(env, address, page_size);
    if (instruction) {
        ia64_invalidate_overlapping_entries(env->memory.itr, IA64_ITR_COUNT,
                                            &probe, false);
    } else {
        ia64_invalidate_overlapping_entries(env->memory.dtr, IA64_DTR_COUNT,
                                            &probe, false);
    }
    ia64_translation_lookup_cache_flush(env);
}

/* ptc.e: purge the entire dynamic translation cache. */
void ia64_purge_all_translation_cache(CPUIA64State *env)
{
    if (!env) {
        return;
    }
    IA64_PERF_INC(IA64_PERF_TARGET_TRANSLATION_PURGE_ALL);
    for (unsigned i = 0; i < IA64_TC_COUNT; i++) {
        env->memory.itc[i].valid = false;
        env->memory.dtc[i].valid = false;
    }
    ia64_translation_lookup_cache_flush(env);
}

bool ia64_translate_data_non_access(CPUIA64State *env, vaddr address,
                                    hwaddr *paddr)
{
    IA64TranslateResult result;

    if (!ia64_translate_address_no_detail(env, address, MMU_DATA_LOAD, 0,
                                          true, &result)) {
        return false;
    }
    if (paddr) {
        *paddr = result.paddr;
    }
    return true;
}

bool ia64_translate_address(CPUIA64State *env, vaddr address,
                            MMUAccessType access_type, int mmu_idx,
                            bool debug, IA64TranslateResult *result)
{
    return ia64_translate_address_common(
        env, address, access_type, mmu_idx,
        ia64_current_privilege_level(env->psr), debug, true, result);
}

bool ia64_translate_address_no_detail(CPUIA64State *env, vaddr address,
                                      MMUAccessType access_type, int mmu_idx,
                                      bool debug, IA64TranslateResult *result)
{
    return ia64_translate_address_common(
        env, address, access_type, mmu_idx,
        ia64_current_privilege_level(env->psr), debug, false, result);
}

bool ia64_translate_address_with_cpl(CPUIA64State *env, vaddr address,
                                     MMUAccessType access_type, int mmu_idx,
                                     int cpl, bool debug,
                                     IA64TranslateResult *result)
{
    return ia64_translate_address_common(env, address, access_type, mmu_idx,
                                         cpl, debug, true, result);
}

static bool ia64_translate_address_common(CPUIA64State *env, vaddr address,
                                          MMUAccessType access_type,
                                          int mmu_idx, int cpl, bool debug,
                                          bool format_detail,
                                          IA64TranslateResult *result)
{
    bool instruction = access_type == MMU_INST_FETCH;
    bool needs_translation = ia64_translation_required(env->psr, access_type);
    const IA64TranslationEntry *entry;
    uint64_t rr;

    cpl &= 0x3;
    if (format_detail) {
        memset(result, 0, sizeof(*result));
    } else {
        result->status = IA64_TRANSLATE_OK;
        result->paddr = 0;
        result->prot = 0;
        result->identity = false;
        result->exception_deferral = false;
        result->message[0] = '\0';
    }
    result->vaddr = address;
    result->region = ia64_va_region(address);
    rr = env->rr[result->region];
    result->vhpt_enabled = ia64_region_vhpt_enabled(rr);
    result->access_type = access_type;
    result->mmu_idx = mmu_idx;
    result->debug = debug;
    result->page_size = 12;

    IA64_PERF_INC(IA64_PERF_TARGET_TRANSLATE);
    if (!format_detail) {
        IA64_PERF_INC(IA64_PERF_TARGET_TRANSLATE_NO_DETAIL);
    }
    if (ia64_perf_enabled()) {
        ia64_perf_count_access_type(access_type);
    }
    if (debug) {
        IA64_PERF_INC(IA64_PERF_TARGET_TRANSLATE_DEBUG);
    }

    if (!needs_translation) {
        IA64_PERF_INC(IA64_PERF_TARGET_TRANSLATE_PHYSICAL);
        result->status = IA64_TRANSLATE_OK;
        result->paddr = address & IA64_PHYSICAL_ADDRESS_MASK;
        result->prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        result->identity = result->paddr == address;
        if (format_detail) {
            snprintf(result->message, sizeof(result->message),
                     result->identity
                     ? "physical identity translation address=0x%016" VADDR_PRIx
                     : "physical mode region-bit strip address=0x%016" VADDR_PRIx
                       " paddr=0x%016" HWADDR_PRIx,
                     address, result->paddr);
        }
        goto record;
    }

    entry = ia64_lookup_translation(env, instruction, address);
    IA64_PERF_INC(IA64_PERF_TARGET_TRANSLATE_LOOKUP);
    if (!entry) {
        result->status = IA64_TRANSLATE_TLB_MISS;
        ia64_trace_translation_miss(env, instruction, address, rr);
        if (format_detail) {
            snprintf(result->message, sizeof(result->message),
                     "%s %s TLB miss address=0x%016" VADDR_PRIx
                     " region=%u rid=0x%x",
                     instruction ? "instruction" : "data",
                     result->vhpt_enabled ? "VHPT" : "alternate", address,
                     result->region, ia64_region_id(rr));
        }
        goto record;
    }

    result->page_size = entry->page_size;
    result->paddr = entry->paddr_base | (address & ia64_page_mask(entry->page_size));
    result->prot = ia64_entry_prot(entry);
    result->identity = result->paddr == address;
    result->exception_deferral = entry->exception_deferral;

    if (!entry->present) {
        result->status = IA64_TRANSLATE_NOT_PRESENT;
        if (format_detail) {
            snprintf(result->message, sizeof(result->message),
                     "%s translation not present address=0x%016" VADDR_PRIx
                     " paddr=0x%016" HWADDR_PRIx,
                     instruction ? "instruction" : "data", address,
                     result->paddr);
        }
        goto record;
    }

    if (!debug && !entry->accessed) {
        result->status = IA64_TRANSLATE_ACCESS_BIT;
        if (format_detail) {
            snprintf(result->message, sizeof(result->message),
                     "%s translation access bit clear address=0x%016" VADDR_PRIx
                     " ar=%u pl=%u cpl=%d",
                     instruction ? "instruction" : "data", address,
                     entry->access_rights, entry->privilege_level, cpl);
        }
        goto record;
    }

    if (!ia64_translation_allows(entry, access_type, cpl)) {
        result->status = IA64_TRANSLATE_ACCESS_DENIED;
        if (format_detail) {
            snprintf(result->message, sizeof(result->message),
                     "%s translation access denied address=0x%016" VADDR_PRIx
                     " ar=%u pl=%u cpl=%d",
                     instruction ? "instruction" : "data", address,
                     entry->access_rights, entry->privilege_level, cpl);
        }
        goto record;
    }

    if (!debug && access_type == MMU_DATA_STORE && !entry->dirty) {
        result->status = IA64_TRANSLATE_DIRTY_BIT;
        if (format_detail) {
            snprintf(result->message, sizeof(result->message),
                     "data translation dirty bit clear address=0x%016" VADDR_PRIx
                     " ar=%u pl=%u cpl=%d",
                     address, entry->access_rights, entry->privilege_level,
                     cpl);
        }
        goto record;
    }

    result->status = IA64_TRANSLATE_OK;
    if (format_detail) {
        snprintf(result->message, sizeof(result->message),
                 "%s translation address=0x%016" VADDR_PRIx
                 " paddr=0x%016" HWADDR_PRIx " ps=%u rid=0x%x ar=%u",
                 instruction ? "instruction" : "data", address, result->paddr,
                 entry->page_size, entry->rid, entry->access_rights);
    }

record:
    env->memory.last_vaddr = result->vaddr;
    env->memory.last_paddr = result->paddr;
    env->memory.last_region = result->region;
    env->memory.last_status = result->status;
    env->memory.last_page_size = result->page_size;
    env->memory.identity_region0_only = false;

    if (ia64_perf_enabled()) {
        ia64_perf_count_translate_status(result->status);
    }

    return result->status == IA64_TRANSLATE_OK;
}

void ia64_format_translate_result(const IA64TranslateResult *result,
                                  char *buf, size_t buflen)
{
    snprintf(buf, buflen,
             "status=%s vaddr=0x%016" VADDR_PRIx
             " paddr=0x%016" HWADDR_PRIx " region=%u prot=0x%x"
             " access=%d mmu=%d page-size=%u debug=%s identity=%s"
             " message=\"%s\"",
             ia64_translate_status_name(result->status), result->vaddr,
             result->paddr, result->region, result->prot,
             result->access_type, result->mmu_idx, result->page_size,
             result->debug ? "yes" : "no",
             result->identity ? "yes" : "no", result->message);
}

bool ia64_memory_class_is_control_speculative(uint8_t memory_class)
{
    return memory_class == 1 || memory_class == 3;
}

static bool ia64_current_itlb_exception_deferral(CPUIA64State *env)
{
    IA64TranslateResult result;

    if ((ia64_env_psr(env) & IA64_PSR_IT_BIT) == 0) {
        return false;
    }

    return ia64_translate_address_no_detail(env, env->ip, MMU_INST_FETCH,
                                            0, true, &result) &&
           result.exception_deferral;
}

bool ia64_control_speculative_load_fault_deferred(
    CPUIA64State *env, const IA64TranslateResult *result)
{
    uint64_t psr;
    uint64_t dcr;
    bool recovery_model;

    if (!env || !result) {
        return false;
    }

    psr = ia64_env_psr(env);
    dcr = env->cr[IA64_CR_DCR];

    if ((psr & IA64_PSR_IC_BIT) == 0) {
        return true;
    }

    recovery_model = (psr & IA64_PSR_IT_BIT) != 0 &&
                     ia64_current_itlb_exception_deferral(env);

    switch (result->status) {
    case IA64_TRANSLATE_BAD_ADDRESS:
    case IA64_TRANSLATE_UNIMPLEMENTED:
        return true;
    case IA64_TRANSLATE_TLB_MISS:
        return recovery_model && (dcr & IA64_DCR_DM_BIT) != 0;
    case IA64_TRANSLATE_NOT_PRESENT:
        return recovery_model && (dcr & IA64_DCR_DP_BIT) != 0;
    case IA64_TRANSLATE_ACCESS_BIT:
        return recovery_model && (dcr & IA64_DCR_DA_BIT) != 0;
    case IA64_TRANSLATE_ACCESS_DENIED:
        return recovery_model && (dcr & IA64_DCR_DR_BIT) != 0;
    default:
        return false;
    }
}

bool ia64_data_access_alignment_fault(CPUIA64State *env, vaddr address,
                                      uint8_t size, bool strict)
{
    uint8_t alignment;

    if (!env || size <= 1) {
        return false;
    }

    alignment = size >= 16 ? 16 : size;
    if ((address & (alignment - 1)) == 0) {
        return false;
    }

    /*
     * Ordinary unaligned references may be supported while PSR.ac is clear.
     * Semaphores and 16-byte references are always strict, and every IA-64
     * implementation must fault a datum that crosses a 4 KiB boundary.
     */
    return strict || size >= 16 ||
           (ia64_env_psr(env) & IA64_PSR_AC_BIT) != 0 ||
           (address & 0xfff) + size > 0x1000;
}

bool ia64_control_speculative_load_defer(CPUIA64State *env,
                                         uint8_t memory_class,
                                         bool base_nat, vaddr address,
                                         uint8_t width,
                                         IA64TranslateResult *fault)
{
    IA64TranslateResult local_fault;

    if (!env || !ia64_memory_class_is_control_speculative(memory_class)) {
        return false;
    }

    if (base_nat) {
        return true;
    }

    if ((ia64_env_psr(env) & IA64_PSR_ED_BIT) != 0) {
        ia64_env_set_psr(env, ia64_env_psr(env) & ~IA64_PSR_ED_BIT);
        return true;
    }

    if (ia64_data_access_alignment_fault(env, address, width, false)) {
        return true;
    }

    if (ia64_translate_address_no_detail(env, address, MMU_DATA_LOAD,
                                         0, false, &local_fault)) {
        return false;
    }

    if (fault) {
        *fault = local_fault;
    }
    return ia64_control_speculative_load_fault_deferred(env, &local_fault);
}
