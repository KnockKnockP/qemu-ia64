/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IA64_CPU_H
#define IA64_CPU_H

#include "cpu-qom.h"
#include "exec/cpu-common.h"
#include "exec/cpu-interrupt.h"
#include "profile.h"

#define IA64_GR_COUNT 128
#define IA64_STATIC_GR_COUNT 32
#define IA64_MAX_STACKED_REGS (IA64_GR_COUNT - IA64_STATIC_GR_COUNT)
#define IA64_STACKED_GR_COUNT 4096
#define IA64_RSE_NAT_WORDS ((IA64_STACKED_GR_COUNT + 63) / 64)
#define IA64_FR_COUNT 128
#define IA64_PR_COUNT 64
#define IA64_BR_COUNT 8
#define IA64_AR_COUNT 128
#define IA64_CR_COUNT 128
#define IA64_RR_COUNT 8
#define IA64_DBR_COUNT 8
#define IA64_IBR_COUNT 8
#define IA64_PKR_COUNT 16
#define IA64_CPUID_COUNT 5
#define IA64_ITR_COUNT 8
#define IA64_DTR_COUNT 8
#define IA64_TC_VMSTATE_COUNT 32
#define IA64_TC_COUNT 128
#define IA64_TRANSLATION_LOOKUP_CACHE_COUNT 64
#define IA64_ALAT_COUNT 32
#define IA64_PMC_COUNT 256
#define IA64_PMD_COUNT 256
#define IA64_CFM_MASK UINT64_C(0x0000003fffffffff)
#define IA64_IFS_VALID_BIT UINT64_C(0x8000000000000000)
#define IA64_PSR_IC_BIT UINT64_C(0x0000000000002000)
#define IA64_PSR_LP_BIT UINT64_C(0x0000000002000000)
#define IA64_PSR_TB_BIT UINT64_C(0x0000000004000000)
#define IA64_PSR_RT_BIT UINT64_C(0x0000000008000000)
#define IA64_PSR_CPL_SHIFT 32
#define IA64_PSR_CPL_MASK UINT64_C(0x0000000300000000)
#define IA64_PSR_DA_BIT UINT64_C(0x0000004000000000)
#define IA64_PSR_DD_BIT UINT64_C(0x0000008000000000)
#define IA64_PSR_RI_SHIFT 41
#define IA64_PSR_RI_MASK UINT64_C(0x0000060000000000)
#define IA64_TB_PSR_DT_BIT UINT64_C(0x0000000000020000)
#define IA64_TB_PSR_IT_BIT UINT64_C(0x0000001000000000)
#define IA64_TB_PSR_BN_BIT UINT64_C(0x0000100000000000)
#define IA64_TB_PSR_CPL_SHIFT 32
#define IA64_TB_PSR_CPL_MASK UINT64_C(0x0000000300000000)
#define IA64_TB_FLAG_DT (1u << 0)
#define IA64_TB_FLAG_IT (1u << 1)
#define IA64_TB_FLAG_CPL_SHIFT 2
#define IA64_TB_FLAG_CPL_MASK (3u << IA64_TB_FLAG_CPL_SHIFT)
#define IA64_TB_FLAG_BN (1u << 4)
#define IA64_TB_FLAG_RI_SHIFT 5
#define IA64_TB_FLAG_RI_MASK (3u << IA64_TB_FLAG_RI_SHIFT)
#define IA64_TB_FLAG_BENCHMARK (1u << 7)
#define IA64_TB_FLAG_PROFILE (1u << 8)
#define IA64_TB_FLAG_GROUP_START (1u << 9)
#define IA64_TB_FLAG_TYPED_GROUP (1u << 10)

#define IA64_INSN_START_GROUP_START (UINT64_C(1) << 0)
#define IA64_INSN_START_TYPED_GROUP (UINT64_C(1) << 1)
#define IA64_ISR_X_BIT 32
#define IA64_ISR_W_BIT 33
#define IA64_ISR_R_BIT 34
#define IA64_ISR_NA_BIT 35
#define IA64_ISR_CODE_MASK UINT64_C(0x000000000000ffff)
#define IA64_ISR_CODE_REGISTER_NAT_CONSUMPTION UINT64_C(0x10)
#define IA64_ISR_SP_BIT 36
#define IA64_ISR_RS_BIT 37
#define IA64_ISR_IR_BIT 38
#define IA64_ISR_NI_BIT 39
#define IA64_ISR_EI_SHIFT 41
#define IA64_ISR_EI_MASK UINT64_C(0x0000060000000000)
#define IA64_ISR_ED_BIT 43

#define IA64_RSC_MODE_MASK UINT64_C(0x3)
#define IA64_RSC_PL_SHIFT 2
#define IA64_RSC_PL_MASK UINT64_C(0xc)
#define IA64_RSC_BE_BIT UINT64_C(0x10)
#define IA64_RSC_LOADRS_SHIFT 16
#define IA64_RSC_LOADRS_MASK UINT64_C(0x3fff)

/*
 * AR.ITC advances at a fixed declared rate backed by the QEMU virtual clock,
 * so guest time tracks real time regardless of emulation speed.  100 MHz
 * divides nanoseconds exactly (10 ns per tick) and matches the frequency the
 * firmware advertises (SAL_FREQ_BASE 100 MHz with a 1/1 PAL ITC ratio).
 */
#define IA64_ITC_FREQUENCY_HZ 100000000
#define IA64_ITC_NS_PER_TICK 10
/* UEFI event trigger times are expressed in 100 ns units. */
#define IA64_ITC_TICKS_PER_100NS 10

typedef enum IA64MmuIndex {
    IA64_MMU_PHYSICAL = 0,
    IA64_MMU_DATA_CPL0 = 1,
    IA64_MMU_DATA_CPL1 = 2,
    IA64_MMU_DATA_CPL2 = 3,
    IA64_MMU_DATA_CPL3 = 4,
    IA64_MMU_INST_CPL0 = 5,
    IA64_MMU_INST_CPL1 = 6,
    IA64_MMU_INST_CPL2 = 7,
    IA64_MMU_INST_CPL3 = 8,
    /*
     * RSE backing-store references are governed by PSR.rt and RSC.pl, not
     * PSR.dt and PSR.cpl.  Keep the access level in the softmmu index so a
     * cached translation never silently survives an RSC.pl change.
     */
    IA64_MMU_RSE_CPL0 = 9,
    IA64_MMU_RSE_CPL1 = 10,
    IA64_MMU_RSE_CPL2 = 11,
    IA64_MMU_RSE_CPL3 = 12,
    IA64_MMU_INDEX_COUNT = 13,
} IA64MmuIndex;

#define IA64_MMU_ALL_IDXMAP ((uint32_t)((1u << IA64_MMU_INDEX_COUNT) - 1u))

static inline unsigned ia64_psr_ri(uint64_t psr)
{
    return (psr & IA64_PSR_RI_MASK) >> IA64_PSR_RI_SHIFT;
}

static inline uint64_t ia64_psr_with_ri(uint64_t psr, unsigned ri)
{
    return (psr & ~IA64_PSR_RI_MASK) |
           (((uint64_t)ri << IA64_PSR_RI_SHIFT) & IA64_PSR_RI_MASK);
}

static inline unsigned ia64_tcg_psr_cpl(uint64_t psr)
{
    return (psr & IA64_TB_PSR_CPL_MASK) >> IA64_TB_PSR_CPL_SHIFT;
}

static inline uint32_t ia64_tcg_tb_flags_from_psr(uint64_t psr)
{
    uint32_t flags = ia64_tcg_psr_cpl(psr) << IA64_TB_FLAG_CPL_SHIFT;

    if (psr & IA64_TB_PSR_DT_BIT) {
        flags |= IA64_TB_FLAG_DT;
    }
    if (psr & IA64_TB_PSR_IT_BIT) {
        flags |= IA64_TB_FLAG_IT;
    }
    if (psr & IA64_TB_PSR_BN_BIT) {
        flags |= IA64_TB_FLAG_BN;
    }
    flags |= ia64_psr_ri(psr) << IA64_TB_FLAG_RI_SHIFT;
    return flags;
}

static inline unsigned ia64_tcg_tb_flags_cpl(uint32_t flags)
{
    return (flags & IA64_TB_FLAG_CPL_MASK) >> IA64_TB_FLAG_CPL_SHIFT;
}

static inline unsigned ia64_tcg_tb_flags_ri(uint32_t flags)
{
    return (flags & IA64_TB_FLAG_RI_MASK) >> IA64_TB_FLAG_RI_SHIFT;
}

static inline int ia64_tcg_mmu_index_for_psr(uint64_t psr, bool ifetch)
{
    bool translated = ifetch ? (psr & IA64_TB_PSR_IT_BIT) != 0
                             : (psr & IA64_TB_PSR_DT_BIT) != 0;

    if (!translated) {
        return IA64_MMU_PHYSICAL;
    }
    return (ifetch ? IA64_MMU_INST_CPL0 : IA64_MMU_DATA_CPL0) +
           ia64_tcg_psr_cpl(psr);
}

static inline int ia64_tcg_data_mmu_index_for_tb_flags(uint32_t flags)
{
    if ((flags & IA64_TB_FLAG_DT) == 0) {
        return IA64_MMU_PHYSICAL;
    }
    return IA64_MMU_DATA_CPL0 + ia64_tcg_tb_flags_cpl(flags);
}

static inline unsigned ia64_rsc_pl(uint64_t rsc)
{
    return (rsc & IA64_RSC_PL_MASK) >> IA64_RSC_PL_SHIFT;
}

static inline int ia64_rse_mmu_index(uint64_t psr, uint64_t rsc)
{
    if ((psr & IA64_PSR_RT_BIT) == 0) {
        return IA64_MMU_PHYSICAL;
    }
    return IA64_MMU_RSE_CPL0 + ia64_rsc_pl(rsc);
}

static inline bool ia64_mmu_index_is_rse(int mmu_idx)
{
    return mmu_idx >= IA64_MMU_RSE_CPL0 &&
           mmu_idx <= IA64_MMU_RSE_CPL3;
}

static inline unsigned ia64_rse_mmu_index_cpl(int mmu_idx)
{
    g_assert(ia64_mmu_index_is_rse(mmu_idx));
    return mmu_idx - IA64_MMU_RSE_CPL0;
}

enum IA64ApplicationRegister {
    IA64_AR_KR0 = 0,
    IA64_AR_RSC = 16,
    IA64_AR_BSP = 17,
    IA64_AR_BSPSTORE = 18,
    IA64_AR_RNAT = 19,
    IA64_AR_CCV = 32,
    IA64_AR_UNAT = 36,
    IA64_AR_FPSR = 40,
    IA64_AR_ITC = 44,
    IA64_AR_PFS = 64,
    IA64_AR_LC = 65,
    IA64_AR_EC = 66,
};

enum IA64ControlRegister {
    IA64_CR_DCR = 0,
    IA64_CR_ITM = 1,
    IA64_CR_IVA = 2,
    IA64_CR_PTA = 8,
    IA64_CR_IPSR = 16,
    IA64_CR_ISR = 17,
    IA64_CR_IIP = 19,
    IA64_CR_IFA = 20,
    IA64_CR_ITIR = 21,
    IA64_CR_IIPA = 22,
    IA64_CR_IFS = 23,
    IA64_CR_IIM = 24,
    IA64_CR_IHA = 25,
    IA64_CR_LID = 64,
    IA64_CR_IVR = 65,
    IA64_CR_TPR = 66,
    IA64_CR_EOI = 67,
    IA64_CR_IRR0 = 68,
    IA64_CR_IRR1 = 69,
    IA64_CR_IRR2 = 70,
    IA64_CR_IRR3 = 71,
    IA64_CR_ITV = 72,
    IA64_CR_PMV = 73,
    IA64_CR_CMCV = 74,
    IA64_CR_LRR0 = 80,
    IA64_CR_LRR1 = 81,
};

typedef struct IA64FloatReg {
    /*
     * IA-64 floating-point registers are architecturally wider than 64 bits.
     * This is raw placeholder storage until Phase 3 is validated against the
     * exact internal format needed by decoding and execution.
     */
    uint64_t raw[2];
} IA64FloatReg;

typedef struct IA64RSEState {
    /*
     * Decoded/cached view of the Register Stack Engine. Future execution code
     * must keep this in sync with AR.RSC, AR.BSP, AR.BSPSTORE, and AR.RNAT.
     */
    uint64_t rsc;
    uint64_t bsp;
    uint64_t bspstore;
    uint64_t bsp_load;
    uint64_t rnat;
    uint64_t loadrs;
    uint32_t sof;
    uint32_t sol;
    uint32_t sor;
    uint32_t rrb_gr;
    uint32_t rrb_fr;
    uint32_t rrb_pr;
    uint32_t current_frame_base;
    /* Architectural RSE.BOF index within the 96-register physical window. */
    uint32_t bol;
    /*
     * Architectural 96-register physical-file partitions (SDM Vol. 2,
     * chapter 6).  stacked_gr[] remains a larger migration-compatible
     * implementation ring, but only the 96-register window described by
     * these counters is physically resident.  dirty/dirty_nat may be
     * negative while a br.ret/rfi target frame is incomplete; in that state
     * BSPSTORE lies above BSP until mandatory loads commit each missing word.
     */
    int32_t dirty;
    int32_t dirty_nat;
    int32_t clean;
    int32_t clean_nat;
    int32_t invalid;
    bool cfle;
    /* Transient tag while the current memory reference is issued by RSE. */
    bool reference;
    uint32_t pending_fill_count;
    uint64_t pending_fill_ip;
    /*
     * Transient simplified clean-partition marker. It is reconstructed by
     * executing flushrs/mov ar.bspstore, so keep snapshots compatible by not
     * serializing it in vmstate_rse.
     */
    uint32_t clean_count;
    /*
     * Logical (architectural-name) view of stacked-register NaTs and the
     * registers whose logical value/NaT must be copied back to the physical
     * RSE file.  env->gr[32..127] holds the corresponding values.  These are
     * transient caches, not additional migration authority.
     */
    uint64_t logical_nat[2];
    uint64_t logical_dirty[2];
    uint64_t stacked_gr[IA64_STACKED_GR_COUNT];
    uint64_t stacked_nat[IA64_RSE_NAT_WORDS];
} IA64RSEState;

typedef struct IA64NaTState {
    /*
     * gr_nat[0] holds the visible static-register NaTs.  Bits 16 through 31
     * of gr_nat[1] hold the inactive bank's GR16-GR31 NaTs; those fields are
     * exchanged whenever PSR.bn changes.  Stacked-register physical NaTs live
     * with the RSE state because the implementation has more physical stacked
     * slots than the 96 architectural stacked register numbers.
     */
    uint64_t gr_nat[2];
    uint64_t unat;
    uint64_t rnat;
} IA64NaTState;

typedef struct IA64InterruptState {
    /*
     * Minimal local-SAPIC-facing state. Pending external interrupts are
     * reflected through CR.IRR*, accepted through CR.IVR, and completed through
     * CR.EOI; pending_interruption tracks the currently accepted vector.
     * timer_compare_latched suppresses repeated ITM delivery until the guest
     * programs the timer again.
     */
    uint64_t pending_interruption;
    uint64_t pending_vector;
    uint8_t timer_compare_latched;
    uint8_t pending;
} IA64InterruptState;

typedef struct IA64TranslationEntry {
    bool valid;
    bool instruction;
    bool pinned;
    uint64_t vaddr_base;
    uint64_t paddr_base;
    uint64_t raw;
    uint64_t itir;
    uint32_t rid;
    uint32_t key;
    uint8_t page_size;
    uint8_t memory_attribute;
    uint8_t privilege_level;
    uint8_t access_rights;
    bool present;
    bool accessed;
    bool dirty;
    bool exception_deferral;
} IA64TranslationEntry;

typedef struct IA64MemorySkeletonState {
    /*
     * Frontier-oriented MMU state. QEMU owns the host TLB; this target state
     * stores IA-64 translation registers/cache entries built by itr/itc so the
     * target can resolve guest virtual pages before calling tlb_set_page().
     */
    uint64_t last_vaddr;
    uint64_t last_paddr;
    uint8_t last_region;
    uint8_t last_status;
    uint8_t last_page_size;
    bool identity_region0_only;
    IA64TranslationEntry itr[IA64_ITR_COUNT];
    IA64TranslationEntry dtr[IA64_DTR_COUNT];
    IA64TranslationEntry itc[IA64_TC_COUNT];
    IA64TranslationEntry dtc[IA64_TC_COUNT];
    uint8_t next_itc;
    uint8_t next_dtc;
    /*
     * Transient direct-mapped cache for the target-side TR/TC lookup result.
     * It is cleared whenever modeled translation state changes and is not
     * serialized.
     */
    IA64TranslationEntry lookup_cache[IA64_TRANSLATION_LOOKUP_CACHE_COUNT];
} IA64MemorySkeletonState;

typedef enum IA64ExceptionKind {
    IA64_EXCEPTION_NONE,
    IA64_EXCEPTION_VHPT_TRANSLATION,
    IA64_EXCEPTION_INSTRUCTION_TLB_MISS,
    IA64_EXCEPTION_DATA_TLB_MISS,
    IA64_EXCEPTION_DATA_NESTED_TLB,
    IA64_EXCEPTION_ALTERNATE_INSTRUCTION_TLB_MISS,
    IA64_EXCEPTION_ALTERNATE_DATA_TLB_MISS,
    IA64_EXCEPTION_DIRTY_BIT,
    IA64_EXCEPTION_INSTRUCTION_ACCESS_BIT,
    IA64_EXCEPTION_DATA_ACCESS_BIT,
    IA64_EXCEPTION_INSTRUCTION_ACCESS_RIGHTS,
    IA64_EXCEPTION_DATA_ACCESS_RIGHTS,
    IA64_EXCEPTION_ILLEGAL_OPERATION,
    IA64_EXCEPTION_PAGE_FAULT,
    IA64_EXCEPTION_GENERAL_EXCEPTION,
    IA64_EXCEPTION_BREAK,
    IA64_EXCEPTION_EXTERNAL_INTERRUPT,
    IA64_EXCEPTION_DISABLED_FP_LOW,
    IA64_EXCEPTION_DISABLED_FP_HIGH,
    IA64_EXCEPTION_REGISTER_NAT_CONSUMPTION,
    IA64_EXCEPTION_UNALIGNED_DATA_REFERENCE,
    /* Post-instruction traps; appended to preserve serialized kind values. */
    IA64_EXCEPTION_LOWER_PRIVILEGE_TRANSFER,
    IA64_EXCEPTION_TAKEN_BRANCH_TRAP,
} IA64ExceptionKind;

typedef struct IA64ExceptionRecord {
    uint32_t kind;
    vaddr ip;
    vaddr address;
    int32_t access_type;
    uint64_t vector;
    /* OR-ed into CR.ISR at delivery (ISR.code bits, e.g. fp-high=2). */
    uint64_t isr_code;
    bool pending;
    uint8_t message[160];
} IA64ExceptionRecord;

typedef struct IA64AlatEntry {
    bool valid;
    uint8_t target;
    uint8_t width;
    bool physical;
    uint64_t address;
} IA64AlatEntry;

typedef struct IA64AlatState {
    IA64AlatEntry entries[IA64_ALAT_COUNT];
    uint8_t next;
    /* Transient summaries, reconstructed from entries after migration. */
    uint32_t valid_mask;
    uint64_t gr_mask[2];
    uint8_t gr_refcount[IA64_GR_COUNT];
} IA64AlatState;

/*
 * Hidden ordinary-source overlay for eagerly retired translated results.
 * The first write to a GR/NaT or PR preserves its source-visibility-epoch
 * entry value here; later ordinary reads in the same epoch select the saved
 * value.  Explicitly forwarded sources must bypass this overlay.  It is
 * migrated together with an explicit typed owner so an epoch can span a TB,
 * page, restore, or migration boundary without entering the shadow-unaware
 * coexistence engine.
 */
typedef struct IA64IssueGroupState {
    uint64_t saved_gr[IA64_GR_COUNT];
    uint64_t saved_nat[IA64_GR_COUNT];
    uint64_t saved_gr_mask[2];
    uint64_t saved_br[IA64_BR_COUNT];
    uint64_t saved_pr;
    /* Ordinary entry image and branch-only forwarding for AR.PFS. */
    uint64_t saved_pfs;
    /* Physical PR bits explicitly forwarded from eligible nonbranch writers. */
    uint64_t branch_pr_forward_mask;
    /* BR writes have the same ordinary-vs-branch visibility split as PR. */
    uint8_t saved_br_mask;
    uint8_t branch_br_forward_mask;
    bool pr_saved;
    bool pfs_saved;
    bool branch_pfs_forwarded;
    /* True while a split typed region owns the open visibility epoch. */
    bool typed_active;
} IA64IssueGroupState;

typedef enum IA64CPUModel {
    IA64_CPU_MODEL_ITANIUM2,
} IA64CPUModel;

struct CPUArchState;
typedef bool (*IA64PlatformBreakHandler)(struct CPUArchState *env,
                                         uint64_t immediate);

typedef struct CPUArchState {
    /* r0 is architecturally hardwired to zero; writes must be ignored. */
    uint64_t gr[IA64_GR_COUNT];
    uint64_t banked_gr[16];

    /* Raw placeholder storage for f0..f127. f0/f1 constants are not modeled. */
    IA64FloatReg fr[IA64_FR_COUNT];

    /* Predicate registers p0..p63, stored as one bitset. p0 resets true. */
    uint64_t pr;

    uint64_t br[IA64_BR_COUNT];

    /*
     * Application and control registers are stored densely by architectural
     * number. Only a small subset has named constants so far.
     */
    uint64_t ar[IA64_AR_COUNT];
    uint64_t cr[IA64_CR_COUNT];

    /* Indexed system-register placeholders. */
    uint64_t rr[IA64_RR_COUNT];
    uint64_t dbr[IA64_DBR_COUNT];
    uint64_t ibr[IA64_IBR_COUNT];
    uint64_t pkr[IA64_PKR_COUNT];
    uint64_t cpuid[IA64_CPUID_COUNT];
    uint64_t itr[IA64_ITR_COUNT];
    uint64_t dtr[IA64_DTR_COUNT];
    uint64_t pmc[IA64_PMC_COUNT];
    uint64_t pmd[IA64_PMD_COUNT];

    uint64_t ip;
    /*
     * Internal retirement state used to populate CR.IIPA on a collected
     * interruption.  It is distinct from CR.IIPA because handler software may
     * read and write that control register while PSR.ic is clear.
     */
    uint64_t last_successful_bundle;
    IA64IssueGroupState issue_group;
    uint64_t psr;
    /*
     * A guest PSR.ic transition has executed but has not yet crossed a data or
     * instruction serialization boundary.  Visible PSR.ic still controls
     * interruption-resource collection; this bit controls ISR.ni and the
     * special Data Nested TLB selection during the in-flight interval.
     */
    bool psr_ic_inflight;
    uint8_t ri;
    bool ri_dirty;
    /*
     * True when the next instruction begins a new source-visibility epoch.
     * This is an execution frontier, not proof that an encoded stop preceded
     * every exception or control-transfer path that can establish it.
     */
    bool instruction_group_start;
    /*
     * Transient translated-memory breadcrumb.  insn_start records the issue
     * group frontier at bundle entry, while a fault in slot 1 or 2 may need
     * the more precise frontier published immediately before the access.
     */
    bool instruction_group_dirty;
    uint64_t cfm;

    IA64RSEState rse;
    IA64NaTState nat;
    IA64InterruptState interrupt;
    IA64MemorySkeletonState memory;
    IA64ExceptionRecord exception;
    IA64AlatState alat;

    /*
     * Transient interpreter breadcrumb for data faults.  It lets interruption
     * delivery report ISR.sp/ISR.ed for speculative loads without refetching
     * guest instruction bytes after a SoftMMU exit.
     */
    bool current_slot_valid;
    uint8_t current_slot_ri;
    uint8_t current_slot_type;
    uint64_t current_slot_ip;
    uint64_t current_slot_raw;

    /*
     * ar[IA64_AR_ITC] caches the clock-backed ITC value and is refreshed by
     * ia64_itc_sync().  itc_offset holds "ITC minus virtual-clock ticks" so
     * guest writes to AR.ITC persist on top of the backing clock.  Both are
     * transient: vmstate serializes the synced ar[] value and re-derives the
     * offset on load.  itc_clock_backed sits inside the reset region so a
     * bare reset (unit tests on stack-allocated envs) deterministically
     * falls back to a fully manual AR.ITC; the system CPU reset hook turns
     * it back on after creating the ITM deadline timer.
     */
    int64_t itc_offset;
    bool itc_clock_backed;

    /*
     * Firmware-owned early TLB miss assist. IA-64 firmware/SAL can service
     * identity misses until the guest installs its own IVT; disable this when
     * software writes CR.IVA and takes ownership of miss delivery.
     */
    bool firmware_identity_tlb;

    /*
     * Perf-only transient set by a fault-induced cpu_loop_exit and consumed
     * by the next TB translation. It is not serialized.
     */
    bool fault_exit_pending_tb_translate;

    struct {} end_reset_fields;

    /*
     * Optional machine-owned monitor for platform debug-service breaks.
     * This is host policy rather than architectural CPU state, so reset and
     * migration must not treat it as guest-visible state.
     */
    IA64PlatformBreakHandler platform_break_handler;

    /*
     * QEMU virtual-clock deadline timer for CR.ITM, owned by the CPU.  NULL
     * outside system emulation (unit tests); while NULL, AR.ITC stays fully
     * manual and no deadline is armed.
     */
    QEMUTimer *itm_timer;
} CPUIA64State;

struct ArchCPU {
    CPUState parent_obj;

    CPUIA64State env;
    IA64CPUModel model;

    /*
     * Transient, explicitly bracketed throughput benchmark state.  This is
     * intentionally outside CPUIA64State: it is host instrumentation, not
     * architectural state, and must not migrate with a guest snapshot.
     */
    bool benchmark_active;
    bool benchmark_requested;
    uint64_t benchmark_retired_bundles;
    uint64_t benchmark_elapsed_ns;
    uint64_t benchmark_host_cycles;
    int64_t benchmark_start_ns;
    int64_t benchmark_start_host_cycles;
    IA64ProductionProfile production_profile;
};

/* Restore only the translated/interpreted execution frontier metadata. */
static inline void ia64_env_set_source_visibility_frontier(
    CPUIA64State *env, bool starts_epoch)
{
    env->instruction_group_start = starts_epoch;
    env->instruction_group_dirty = false;
}

static inline void ia64_env_clear_ordinary_source_overlay(CPUIA64State *env)
{
    env->issue_group.saved_gr_mask[0] = 0;
    env->issue_group.saved_gr_mask[1] = 0;
    env->issue_group.saved_br_mask = 0;
    env->issue_group.branch_br_forward_mask = 0;
    env->issue_group.pr_saved = false;
    env->issue_group.branch_pr_forward_mask = 0;
    env->issue_group.pfs_saved = false;
    env->issue_group.branch_pfs_forwarded = false;
    env->issue_group.typed_active = false;
}

/* Establish a fresh ordinary-source epoch after a real architectural event. */
static inline void ia64_env_begin_source_visibility_epoch(CPUIA64State *env)
{
    ia64_env_clear_ordinary_source_overlay(env);
    ia64_env_set_source_visibility_frontier(env, true);
}

static inline void ia64_env_set_psr(CPUIA64State *env, uint64_t psr)
{
    if (((env->psr ^ psr) & IA64_TB_PSR_BN_BIT) != 0) {
        const uint64_t banked_mask = UINT64_C(0x00000000ffff0000);
        uint64_t visible = env->nat.gr_nat[0] & banked_mask;
        uint64_t inactive = env->nat.gr_nat[1] & banked_mask;

        env->nat.gr_nat[0] =
            (env->nat.gr_nat[0] & ~banked_mask) | inactive;
        env->nat.gr_nat[1] =
            (env->nat.gr_nat[1] & ~banked_mask) | visible;
    }
    env->psr = psr;
    env->ri = ia64_psr_ri(psr);
    env->ri_dirty = false;
}

/* Apply an architected guest PSR write without conflating host-side restores. */
static inline void ia64_env_write_psr_guest(CPUIA64State *env, uint64_t psr)
{
    if ((env->psr ^ psr) & IA64_PSR_IC_BIT) {
        env->psr_ic_inflight = true;
    }
    ia64_env_set_psr(env, psr);
}

static inline void ia64_env_serialize_psr_ic(CPUIA64State *env)
{
    env->psr_ic_inflight = false;
}

/* Reset/debug replacement and implicit architectural serialization. */
static inline void ia64_env_replace_psr(CPUIA64State *env, uint64_t psr)
{
    ia64_env_set_psr(env, psr);
    ia64_env_serialize_psr_ic(env);
}

static inline uint64_t ia64_env_psr(CPUIA64State *env)
{
    return env->ri_dirty ? ia64_psr_with_ri(env->psr, env->ri) : env->psr;
}

static inline unsigned ia64_env_ri(CPUIA64State *env)
{
    return env->ri_dirty ? env->ri : ia64_psr_ri(env->psr);
}

static inline void ia64_env_set_ri(CPUIA64State *env, unsigned ri)
{
    env->ri = ri & 3;
    env->ri_dirty = true;
}

static inline void ia64_env_sync_psr_ri(CPUIA64State *env)
{
    if (env->ri_dirty) {
        ia64_env_set_psr(env, ia64_psr_with_ri(env->psr, env->ri));
    }
}

/*
 * insn_start data is bundle-granular.  Helpers that execute individual slots
 * (the interpreter loop and the fast load/store helpers) publish the
 * executing slot in env->ri before any faulting access; that is more precise
 * than the translation-time value recorded for the bundle.
 */
static inline unsigned ia64_env_restore_ri(const CPUIA64State *env,
                                           unsigned data_ri)
{
    return (env->ri_dirty ? env->ri : data_ri) & 3;
}

/*
 * Consume the slot-precise issue-group frontier published around a translated
 * memory access.  With no active override, bundle-granular insn_start data is
 * authoritative.
 */
static inline void ia64_env_restore_source_visibility(
    CPUIA64State *env, uint64_t data_state)
{
    if (!env->instruction_group_dirty) {
        env->instruction_group_start =
            (data_state & IA64_INSN_START_GROUP_START) != 0;
        env->issue_group.typed_active =
            (data_state & IA64_INSN_START_TYPED_GROUP) != 0;
    }

    env->instruction_group_dirty = false;
}

#define CPU_RESOLVING_TYPE TYPE_IA64_CPU

void ia64_translate_init(void);
void ia64_translate_code(CPUState *cs, TranslationBlock *tb, int *max_insns,
                         vaddr pc, void *host_pc);

void ia64_cpu_dump_state(CPUState *cs, FILE *f, int flags);
hwaddr ia64_cpu_get_phys_addr_debug(CPUState *cs, vaddr addr);
bool ia64_cpu_tlb_fill(CPUState *cs, vaddr address, int size,
                       MMUAccessType access_type, int mmu_idx,
                       bool probe, uintptr_t retaddr);
int ia64_cpu_gdb_read_register(CPUState *cs, GByteArray *mem_buf, int n);
int ia64_cpu_gdb_write_register(CPUState *cs, uint8_t *mem_buf, int n);

extern const VMStateDescription vmstate_ia64_cpu;

#endif
