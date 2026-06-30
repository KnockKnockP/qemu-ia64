/* SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef IA64_CPU_H
#define IA64_CPU_H

#include "cpu-qom.h"
#include "exec/cpu-common.h"
#include "exec/cpu-interrupt.h"

#define IA64_GR_COUNT 128
#define IA64_STATIC_GR_COUNT 32
#define IA64_STACKED_GR_COUNT 4096
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
#define IA64_PSR_RI_SHIFT 41
#define IA64_PSR_RI_MASK UINT64_C(0x0000060000000000)
#define IA64_TB_PSR_DT_BIT UINT64_C(0x0000000000020000)
#define IA64_TB_PSR_IT_BIT UINT64_C(0x0000001000000000)
#define IA64_TB_PSR_CPL_SHIFT 32
#define IA64_TB_PSR_CPL_MASK UINT64_C(0x0000000300000000)
#define IA64_TB_FLAG_DT (1u << 0)
#define IA64_TB_FLAG_IT (1u << 1)
#define IA64_TB_FLAG_CPL_SHIFT 2
#define IA64_TB_FLAG_CPL_MASK (3u << IA64_TB_FLAG_CPL_SHIFT)
#define IA64_ISR_X_BIT 32
#define IA64_ISR_W_BIT 33
#define IA64_ISR_R_BIT 34
#define IA64_ISR_EI_SHIFT 41
#define IA64_ISR_EI_MASK UINT64_C(0x0000060000000000)

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
    IA64_MMU_INDEX_COUNT = 9,
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
    return flags;
}

static inline unsigned ia64_tcg_tb_flags_cpl(uint32_t flags)
{
    return (flags & IA64_TB_FLAG_CPL_MASK) >> IA64_TB_FLAG_CPL_SHIFT;
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
    uint64_t rnat;
    uint64_t loadrs;
    uint32_t sof;
    uint32_t sol;
    uint32_t sor;
    uint32_t rrb_gr;
    uint32_t rrb_fr;
    uint32_t rrb_pr;
    uint32_t current_frame_base;
    /*
     * Transient simplified clean-partition marker. It is reconstructed by
     * executing flushrs/mov ar.bspstore, so keep snapshots compatible by not
     * serializing it in vmstate_rse.
     */
    uint32_t clean_count;
    uint64_t stacked_gr[IA64_STACKED_GR_COUNT];
} IA64RSEState;

typedef struct IA64NaTState {
    /*
     * Placeholder NaT state. gr_nat carries one bit for each general register;
     * UNAT/RNAT are mirrored into the application register file during reset.
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
     */
    uint64_t pending_interruption;
    uint64_t pending_vector;
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
} IA64ExceptionKind;

typedef struct IA64ExceptionRecord {
    uint32_t kind;
    vaddr ip;
    vaddr address;
    int32_t access_type;
    uint64_t vector;
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
    /* Transient validity bitmap, reconstructed from entries after migration. */
    uint32_t valid_mask;
} IA64AlatState;

typedef enum IA64CPUModel {
    IA64_CPU_MODEL_ITANIUM2,
} IA64CPUModel;

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
    uint64_t psr;
    uint64_t cfm;

    IA64RSEState rse;
    IA64NaTState nat;
    IA64InterruptState interrupt;
    IA64MemorySkeletonState memory;
    IA64ExceptionRecord exception;
    IA64AlatState alat;

    /*
     * Perf-only transient set by a fault-induced cpu_loop_exit and consumed
     * by the next TB translation. It is not serialized.
     */
    bool fault_exit_pending_tb_translate;

    struct {} end_reset_fields;
} CPUIA64State;

struct ArchCPU {
    CPUState parent_obj;

    CPUIA64State env;
    IA64CPUModel model;
};

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
