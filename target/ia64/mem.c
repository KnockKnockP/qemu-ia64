/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "mem.h"
#include "exec/page-protection.h"
#include "trace-target_ia64.h"

#define IA64_PHYSICAL_ADDRESS_MASK UINT64_C(0x1fffffffffffffff)
#define IA64_REGIONLESS_ADDRESS_MASK UINT64_C(0x1fffffffffffffff)
#define IA64_PSR_DT_BIT UINT64_C(0x0000000000020000)
#define IA64_PSR_RT_BIT UINT64_C(0x0000000008000000)
#define IA64_PSR_IT_BIT UINT64_C(0x0000001000000000)
#define IA64_PSR_CPL_SHIFT 32
#define IA64_INSERTION_PPN_MASK UINT64_C(0x0003fffffffff000)
#define IA64_VHPT_REGION_BITS_MASK UINT64_C(0xe000000000000000)
#define IA64_VHPT_BASE_ADDRESS_MASK UINT64_C(0x1fffffffffff8000)
#define IA64_VHPT_VA_HASH_MASK UINT64_C(0x0007ffffffffffff)

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

    for (unsigned i = 0; i < IA64_ITR_COUNT; i++) {
        best = ia64_pick_best_entry(best, &tr[i], address, rid);
    }
    for (unsigned i = 0; i < IA64_TC_COUNT; i++) {
        best = ia64_pick_best_entry(best, &tc[i], address, rid);
    }
    return best;
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
    probe = ia64_purge_probe(env, address, page_size);
    ia64_invalidate_overlapping_entries(env->memory.itc, IA64_TC_COUNT, &probe,
                                        all_rids);
    ia64_invalidate_overlapping_entries(env->memory.dtc, IA64_TC_COUNT, &probe,
                                        all_rids);
}

/* ptr.i / ptr.d: purge a matching pinned instruction/data translation register. */
void ia64_purge_translation_register(CPUIA64State *env, bool instruction,
                                     vaddr address, uint8_t page_size)
{
    IA64TranslationEntry probe;

    if (!env) {
        return;
    }
    probe = ia64_purge_probe(env, address, page_size);
    if (instruction) {
        ia64_invalidate_overlapping_entries(env->memory.itr, IA64_ITR_COUNT,
                                            &probe, false);
    } else {
        ia64_invalidate_overlapping_entries(env->memory.dtr, IA64_DTR_COUNT,
                                            &probe, false);
    }
}

/* ptc.e: purge the entire dynamic translation cache. */
void ia64_purge_all_translation_cache(CPUIA64State *env)
{
    if (!env) {
        return;
    }
    for (unsigned i = 0; i < IA64_TC_COUNT; i++) {
        env->memory.itc[i].valid = false;
        env->memory.dtc[i].valid = false;
    }
}

bool ia64_translate_data_non_access(CPUIA64State *env, vaddr address,
                                    hwaddr *paddr)
{
    IA64TranslateResult result;

    if (!ia64_translate_address(env, address, MMU_DATA_LOAD, 0, true,
                                &result)) {
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
    return ia64_translate_address_with_cpl(
        env, address, access_type, mmu_idx,
        ia64_current_privilege_level(env->psr), debug, result);
}

bool ia64_translate_address_with_cpl(CPUIA64State *env, vaddr address,
                                     MMUAccessType access_type, int mmu_idx,
                                     int cpl, bool debug,
                                     IA64TranslateResult *result)
{
    bool instruction = access_type == MMU_INST_FETCH;
    bool needs_translation = ia64_translation_required(env->psr, access_type);
    const IA64TranslationEntry *entry;
    uint64_t rr;

    cpl &= 0x3;
    memset(result, 0, sizeof(*result));
    result->vaddr = address;
    result->region = ia64_va_region(address);
    rr = env->rr[result->region];
    result->vhpt_enabled = ia64_region_vhpt_enabled(rr);
    result->access_type = access_type;
    result->mmu_idx = mmu_idx;
    result->debug = debug;
    result->page_size = 12;

    if (!needs_translation) {
        result->status = IA64_TRANSLATE_OK;
        result->paddr = address & IA64_PHYSICAL_ADDRESS_MASK;
        result->prot = PAGE_READ | PAGE_WRITE | PAGE_EXEC;
        result->identity = result->paddr == address;
        snprintf(result->message, sizeof(result->message),
                 result->identity
                 ? "physical identity translation address=0x%016" VADDR_PRIx
                 : "physical mode region-bit strip address=0x%016" VADDR_PRIx
                   " paddr=0x%016" HWADDR_PRIx,
                 address, result->paddr);
        goto record;
    }

    entry = ia64_lookup_translation(env, instruction, address);
    if (!entry) {
        result->status = IA64_TRANSLATE_TLB_MISS;
        ia64_trace_translation_miss(env, instruction, address, rr);
        snprintf(result->message, sizeof(result->message),
                 "%s %s TLB miss address=0x%016" VADDR_PRIx
                 " region=%u rid=0x%x",
                 instruction ? "instruction" : "data",
                 result->vhpt_enabled ? "VHPT" : "alternate", address,
                 result->region, ia64_region_id(rr));
        goto record;
    }

    result->page_size = entry->page_size;
    result->paddr = entry->paddr_base | (address & ia64_page_mask(entry->page_size));
    result->prot = ia64_entry_prot(entry);
    result->identity = result->paddr == address;

    if (!entry->present) {
        result->status = IA64_TRANSLATE_NOT_PRESENT;
        snprintf(result->message, sizeof(result->message),
                 "%s translation not present address=0x%016" VADDR_PRIx
                 " paddr=0x%016" HWADDR_PRIx,
                 instruction ? "instruction" : "data", address, result->paddr);
        goto record;
    }

    if (!ia64_translation_allows(entry, access_type, cpl)) {
        result->status = IA64_TRANSLATE_ACCESS_DENIED;
        snprintf(result->message, sizeof(result->message),
                 "%s translation access denied address=0x%016" VADDR_PRIx
                 " ar=%u pl=%u cpl=%d",
                 instruction ? "instruction" : "data", address,
                 entry->access_rights, entry->privilege_level, cpl);
        goto record;
    }

    result->status = IA64_TRANSLATE_OK;
    snprintf(result->message, sizeof(result->message),
             "%s translation address=0x%016" VADDR_PRIx
             " paddr=0x%016" HWADDR_PRIx " ps=%u rid=0x%x ar=%u",
             instruction ? "instruction" : "data", address, result->paddr,
             entry->page_size, entry->rid, entry->access_rights);

record:
    env->memory.last_vaddr = result->vaddr;
    env->memory.last_paddr = result->paddr;
    env->memory.last_region = result->region;
    env->memory.last_status = result->status;
    env->memory.last_page_size = result->page_size;
    env->memory.identity_region0_only = false;

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
