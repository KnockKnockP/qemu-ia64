/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "accel/tcg/cpu-ldst.h"
#include "exec/cputlb.h"
#include "bundle.h"
#include "cpu.h"
#include "exception.h"
#include "exec-smoke.h"
#include "exec/helper-proto.h"
#include "hw/core/cpu.h"
#include "hw/ia64/efi.h"
#include "hw/ia64/efi-storage.h"
#include "hw/ia64/vibtanium.h"
#include "mem.h"
#include "perf.h"
#include "qemu/error-report.h"
#include "system/memory.h"
#include "tcg-skeleton.h"
#include "trace-target_ia64.h"

static void ia64_progress_trace_event(CPUIA64State *env, const char *event,
                                      uint64_t aux0, uint64_t aux1);
static void ia64_progress_trace_bundle(CPUIA64State *env);

void HELPER(perf_tb_exec)(void)
{
    IA64_PERF_INC(IA64_PERF_TB_EXECUTED);
}

void HELPER(perf_direct_branch_fallback)(void)
{
    IA64_PERF_INC(IA64_PERF_TCG_BRANCH_DIRECT_FALLBACK);
}

void HELPER(perf_tcg_ldst_fallback)(void)
{
    IA64_PERF_INC(IA64_PERF_TCG_LDST_FALLBACK);
}

void HELPER(perf_tb_exit_main_loop)(void)
{
    IA64_PERF_INC(IA64_PERF_TB_EXIT_MAIN_LOOP);
}

void HELPER(perf_tb_exit_chained)(void)
{
    IA64_PERF_INC(IA64_PERF_TB_EXIT_CHAINED);
}

void HELPER(perf_tb_exit_lookup_ptr)(void)
{
    IA64_PERF_INC(IA64_PERF_TB_EXIT_LOOKUP_PTR);
}

void HELPER(firmware_call_gate)(CPUIA64State *env, uint64_t gate_ip)
{
    CPUState *cpu = env_cpu(env);

    IA64_PERF_INC(IA64_PERF_BUNDLE_EXECUTED);
    IA64_PERF_INC(IA64_PERF_TCG_FIRMWARE_CALL_GATE_FAST);

    /*
     * Firmware service helpers can legitimately perform guest memory and MMIO
     * accesses.  The full bundle interpreter used the same relaxed I/O mode.
     */
    cpu->neg.can_do_io = true;
    env->ip = gate_ip;
    env->cr[IA64_CR_IIP] = gate_ip;

    ia64_progress_trace_bundle(env);

    if (!vibtanium_efi_dispatch_gate(env, gate_ip)) {
        IA64_PERF_INC(IA64_PERF_TCG_FIRMWARE_CALL_GATE_FALLBACK);
        cpu_abort(cpu,
                  "IA-64 firmware call-gate fast path missed "
                  "IP=0x%016" PRIx64 "\n",
                  gate_ip);
    }
}

#define IA64_LINUX_BREAK_SYSCALL UINT64_C(0x100000)
#define IA64_PSR_I_BIT UINT64_C(0x0000000000004000)
#define IA64_PSR_BN_BIT UINT64_C(0x0000100000000000)
#define IA64_PSR_CPL_SHIFT 32
#define IA64_PSR_CPL_MASK UINT64_C(0x0000000300000000)

static bool ia64_syscall_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_SYSCALL_TRACE") != NULL;
    }
    return enabled != 0;
}

static const char *ia64_linux_syscall_name(uint64_t nr)
{
    switch (nr) {
    case 1025: return "exit";
    case 1026: return "read";
    case 1027: return "write";
    case 1028: return "open";
    case 1029: return "close";
    case 1030: return "creat";
    case 1031: return "link";
    case 1032: return "unlink";
    case 1033: return "execve";
    case 1034: return "chdir";
    case 1037: return "mknod";
    case 1038: return "chmod";
    case 1039: return "chown";
    case 1040: return "lseek";
    case 1041: return "getpid";
    case 1042: return "getppid";
    case 1043: return "mount";
    case 1046: return "getuid";
    case 1049: return "access";
    case 1054: return "rename";
    case 1055: return "mkdir";
    case 1057: return "dup";
    case 1058: return "pipe";
    case 1060: return "brk";
    case 1062: return "getgid";
    case 1065: return "ioctl";
    case 1066: return "fcntl";
    case 1067: return "umask";
    case 1070: return "dup2";
    case 1081: return "setsid";
    case 1089: return "select";
    case 1090: return "poll";
    case 1091: return "symlink";
    case 1092: return "readlink";
    case 1103: return "statfs";
    case 1104: return "fstatfs";
    case 1126: return "wait4";
    case 1128: return "clone";
    case 1130: return "uname";
    case 1144: return "getdents";
    case 1146: return "readv";
    case 1147: return "writev";
    case 1151: return "mmap";
    case 1152: return "munmap";
    case 1155: return "mprotect";
    case 1172: return "mmap2";
    case 1177: return "rt_sigaction";
    case 1178: return "rt_sigpending";
    case 1179: return "rt_sigprocmask";
    case 1180: return "rt_sigqueueinfo";
    case 1181: return "rt_sigreturn";
    case 1182: return "rt_sigsuspend";
    case 1183: return "rt_sigtimedwait";
    case 1184: return "getcwd";
    case 1190: return "socket";
    case 1191: return "bind";
    case 1192: return "connect";
    case 1193: return "listen";
    case 1194: return "accept";
    case 1195: return "getsockname";
    case 1196: return "getpeername";
    case 1197: return "socketpair";
    case 1198: return "send";
    case 1199: return "sendto";
    case 1200: return "recv";
    case 1201: return "recvfrom";
    case 1202: return "shutdown";
    case 1203: return "setsockopt";
    case 1204: return "getsockopt";
    case 1205: return "sendmsg";
    case 1206: return "recvmsg";
    case 1210: return "stat";
    case 1211: return "lstat";
    case 1212: return "fstat";
    case 1213: return "clone2";
    case 1214: return "getdents64";
    case 1216: return "readahead";
    case 1229: return "tkill";
    case 1230: return "futex";
    case 1233: return "set_tid_address";
    case 1236: return "exit_group";
    case 1243: return "epoll_create";
    case 1244: return "epoll_ctl";
    case 1245: return "epoll_wait";
    case 1254: return "clock_gettime";
    case 1257: return "fstatfs64";
    case 1258: return "statfs64";
    case 1270: return "waitid";
    case 1277: return "inotify_init";
    case 1278: return "inotify_add_watch";
    case 1279: return "inotify_rm_watch";
    case 1281: return "openat";
    case 1282: return "mkdirat";
    case 1283: return "mknodat";
    case 1286: return "newfstatat";
    case 1291: return "readlinkat";
    case 1305: return "epoll_pwait";
    case 1307: return "signalfd";
    case 1313: return "signalfd4";
    case 1315: return "epoll_create1";
    case 1318: return "inotify_init1";
    case 1327: return "open_by_handle_at";
    default: return "unknown";
    }
}

static bool ia64_trace_guest_read_u8(CPUIA64State *env, uint64_t address,
                                     uint8_t *value, char *status,
                                     size_t status_size)
{
    IA64TranslateResult result;
    CPUState *cs = env_cpu(env);
    vaddr saved_vaddr = env->memory.last_vaddr;
    hwaddr saved_paddr = env->memory.last_paddr;
    uint8_t saved_region = env->memory.last_region;
    uint8_t saved_status = env->memory.last_status;
    uint8_t saved_page_size = env->memory.last_page_size;
    bool saved_identity_region0_only = env->memory.identity_region0_only;
    MemTxResult mem_result;

    if (!ia64_translate_address(env, address, MMU_DATA_LOAD, 0, true,
                                &result)) {
        snprintf(status, status_size, "translate:%s",
                 ia64_translate_status_name(result.status));
        goto fail;
    }

    mem_result = address_space_read(cs->as, result.paddr,
                                    MEMTXATTRS_UNSPECIFIED, value, 1);
    if (mem_result != MEMTX_OK) {
        snprintf(status, status_size, "mem:%d", mem_result);
        goto fail;
    }

    env->memory.last_vaddr = saved_vaddr;
    env->memory.last_paddr = saved_paddr;
    env->memory.last_region = saved_region;
    env->memory.last_status = saved_status;
    env->memory.last_page_size = saved_page_size;
    env->memory.identity_region0_only = saved_identity_region0_only;
    return true;

fail:
    env->memory.last_vaddr = saved_vaddr;
    env->memory.last_paddr = saved_paddr;
    env->memory.last_region = saved_region;
    env->memory.last_status = saved_status;
    env->memory.last_page_size = saved_page_size;
    env->memory.identity_region0_only = saved_identity_region0_only;
    return false;
}

static void ia64_trace_guest_c_string(CPUIA64State *env, uint64_t address,
                                      char *buf, size_t buflen)
{
    char status[48] = "ok";
    size_t out = 0;

    if (buflen == 0) {
        return;
    }
    if (address == 0) {
        g_strlcpy(buf, "<null>", buflen);
        return;
    }

    buf[out++] = '"';
    for (unsigned i = 0; i < 160 && out + 5 < buflen; i++) {
        uint8_t ch;

        if (!ia64_trace_guest_read_u8(env, address + i, &ch, status,
                                      sizeof(status))) {
            out += snprintf(buf + out, buflen - out, "<unreadable:%s>",
                            status);
            break;
        }
        if (ch == 0) {
            break;
        }
        if (ch == '\\' || ch == '"') {
            buf[out++] = '\\';
            buf[out++] = ch;
        } else if (ch >= 0x20 && ch <= 0x7e) {
            buf[out++] = ch;
        } else {
            out += snprintf(buf + out, buflen - out, "\\x%02x", ch);
        }
    }
    if (out + 2 < buflen) {
        buf[out++] = '"';
    }
    buf[out] = '\0';
}

static void ia64_trace_guest_bytes_escaped(CPUIA64State *env,
                                           uint64_t address, uint64_t max_len,
                                           char *buf, size_t buflen)
{
    char status[48] = "ok";
    size_t out = 0;

    if (buflen == 0) {
        return;
    }
    if (address == 0) {
        g_strlcpy(buf, "<null>", buflen);
        return;
    }

    buf[out++] = '"';
    for (uint64_t i = 0; i < max_len && out + 5 < buflen; i++) {
        uint8_t ch;

        if (!ia64_trace_guest_read_u8(env, address + i, &ch, status,
                                      sizeof(status))) {
            out += snprintf(buf + out, buflen - out, "<unreadable:%s>",
                            status);
            break;
        }
        if (ch == 0) {
            buf[out++] = '\\';
            buf[out++] = '0';
        } else if (ch == '\\' || ch == '"') {
            buf[out++] = '\\';
            buf[out++] = ch;
        } else if (ch >= 0x20 && ch <= 0x7e) {
            buf[out++] = ch;
        } else {
            out += snprintf(buf + out, buflen - out, "\\x%02x", ch);
        }
    }
    if (out + 2 < buflen) {
        buf[out++] = '"';
    }
    buf[out] = '\0';
}

static bool ia64_trace_guest_read_u16(CPUIA64State *env, uint64_t address,
                                      uint16_t *value, char *status,
                                      size_t status_size)
{
    uint8_t byte0;
    uint8_t byte1;

    if (!ia64_trace_guest_read_u8(env, address, &byte0, status,
                                  status_size) ||
        !ia64_trace_guest_read_u8(env, address + 1, &byte1, status,
                                  status_size)) {
        return false;
    }

    *value = (uint16_t)byte0 | ((uint16_t)byte1 << 8);
    return true;
}

static bool ia64_trace_guest_read_u32(CPUIA64State *env, uint64_t address,
                                      uint32_t *value, char *status,
                                      size_t status_size)
{
    uint8_t byte[4];

    for (unsigned i = 0; i < ARRAY_SIZE(byte); i++) {
        if (!ia64_trace_guest_read_u8(env, address + i, &byte[i], status,
                                      status_size)) {
            return false;
        }
    }

    *value = (uint32_t)byte[0] |
             ((uint32_t)byte[1] << 8) |
             ((uint32_t)byte[2] << 16) |
             ((uint32_t)byte[3] << 24);
    return true;
}

static bool ia64_trace_guest_read_u64(CPUIA64State *env, uint64_t address,
                                      uint64_t *value, char *status,
                                      size_t status_size)
{
    IA64TranslateResult result;
    CPUState *cs = env_cpu(env);
    vaddr saved_vaddr = env->memory.last_vaddr;
    hwaddr saved_paddr = env->memory.last_paddr;
    uint8_t saved_region = env->memory.last_region;
    uint8_t saved_status = env->memory.last_status;
    uint8_t saved_page_size = env->memory.last_page_size;
    bool saved_identity_region0_only = env->memory.identity_region0_only;
    MemTxResult mem_result;
    uint64_t raw;

    if (!ia64_translate_address(env, address, MMU_DATA_LOAD, 0, true,
                                &result)) {
        snprintf(status, status_size, "translate:%s",
                 ia64_translate_status_name(result.status));
        goto fail;
    }

    mem_result = address_space_read(cs->as, result.paddr,
                                    MEMTXATTRS_UNSPECIFIED,
                                    &raw, sizeof(raw));
    if (mem_result != MEMTX_OK) {
        snprintf(status, status_size, "mem:%d", mem_result);
        goto fail;
    }

    env->memory.last_vaddr = saved_vaddr;
    env->memory.last_paddr = saved_paddr;
    env->memory.last_region = saved_region;
    env->memory.last_status = saved_status;
    env->memory.last_page_size = saved_page_size;
    env->memory.identity_region0_only = saved_identity_region0_only;
    *value = le64_to_cpu(raw);
    return true;

fail:
    env->memory.last_vaddr = saved_vaddr;
    env->memory.last_paddr = saved_paddr;
    env->memory.last_region = saved_region;
    env->memory.last_status = saved_status;
    env->memory.last_page_size = saved_page_size;
    env->memory.identity_region0_only = saved_identity_region0_only;
    return false;
}

static void ia64_trace_execve_vector(CPUIA64State *env, const char *label,
                                     uint64_t vector, unsigned max_items)
{
    char status[48] = "ok";
    char rendered[160];

    fprintf(stderr, " %s=0x%016" PRIx64, label, vector);
    if (vector == 0) {
        return;
    }

    for (unsigned i = 0; i < max_items; i++) {
        uint64_t item;

        if (!ia64_trace_guest_read_u64(env, vector + i * sizeof(item),
                                       &item, status, sizeof(status))) {
            fprintf(stderr, " %s[%u]=<unreadable:%s>", label, i, status);
            return;
        }
        if (item == 0) {
            fprintf(stderr, " %s[%u]=NULL", label, i);
            return;
        }
        ia64_trace_guest_c_string(env, item, rendered, sizeof(rendered));
        fprintf(stderr, " %s[%u]=0x%016" PRIx64 ":%s",
                label, i, item, rendered);
    }
}

static bool ia64_linux_syscall_arg_is_path(uint64_t nr, unsigned arg_index,
                                           const char **label)
{
    switch (nr) {
    case 1028: /* open */
    case 1033: /* execve */
    case 1034: /* chdir */
    case 1049: /* access */
    case 1055: /* mkdir */
    case 1092: /* readlink */
    case 1103: /* statfs */
    case 1210: /* stat */
    case 1211: /* lstat */
    case 1258: /* statfs64 */
        if (arg_index == 0) {
            *label = "path";
            return true;
        }
        return false;
    case 1043: /* mount */
        if (arg_index == 0) {
            *label = "source";
            return true;
        }
        if (arg_index == 1) {
            *label = "target";
            return true;
        }
        if (arg_index == 2) {
            *label = "fstype";
            return true;
        }
        return false;
    case 1281: /* openat */
    case 1282: /* mkdirat */
    case 1291: /* readlinkat */
    case 1327: /* open_by_handle_at */
        if (arg_index == 1) {
            *label = "path";
            return true;
        }
        return false;
    default:
        return false;
    }
}

static void ia64_trace_linux_syscall_paths(CPUIA64State *env,
                                           const char *mnemonic,
                                           uint64_t nr)
{
    uint64_t arg[6];
    char rendered[192];
    bool shifted_m_gate = g_str_equal(mnemonic, "break.m");
    bool any = false;

    for (unsigned i = 0; i < ARRAY_SIZE(arg); i++) {
        arg[i] = ia64_read_gr(env, 32 + i + (shifted_m_gate ? 1 : 0));
    }

    for (unsigned i = 0; i < ARRAY_SIZE(arg); i++) {
        const char *label = NULL;

        if (!ia64_linux_syscall_arg_is_path(nr, i, &label)) {
            continue;
        }
        if (!any) {
            fprintf(stderr, " paths");
            any = true;
        }
        ia64_trace_guest_c_string(env, arg[i], rendered, sizeof(rendered));
        fprintf(stderr, " %s=0x%016" PRIx64 ":%s", label, arg[i], rendered);
    }
}

static void ia64_trace_linux_syscall_socket_details(CPUIA64State *env,
                                                    const char *mnemonic,
                                                    uint64_t nr)
{
    uint64_t arg[6];
    bool shifted_m_gate = g_str_equal(mnemonic, "break.m");

    for (unsigned i = 0; i < ARRAY_SIZE(arg); i++) {
        arg[i] = ia64_read_gr(env, 32 + i + (shifted_m_gate ? 1 : 0));
    }

    switch (nr) {
    case 1190: /* socket */
    {
        uint64_t type = arg[1];

        fprintf(stderr,
                " socket domain=%" PRIu64 " type=0x%016" PRIx64
                " base_type=%" PRIu64 " cloexec=%u nonblock=%u"
                " protocol=%" PRIu64,
                arg[0], type, type & 0xf, (type & 02000000) != 0,
                (type & 00004000) != 0, arg[2]);
        break;
    }
    case 1191: /* bind */
    {
        char status[48] = "ok";
        uint16_t family;

        fprintf(stderr,
                " bind fd=%" PRIu64 " addr=0x%016" PRIx64
                " addrlen=%" PRIu64,
                arg[0], arg[1], arg[2]);
        if (arg[1] == 0 ||
            !ia64_trace_guest_read_u16(env, arg[1], &family, status,
                                       sizeof(status))) {
            fprintf(stderr, " sockaddr=<unreadable:%s>", status);
            break;
        }
        fprintf(stderr, " sockaddr_family=%u", family);
        if (family == 16 && arg[2] >= 12) {
            uint32_t nl_pid;
            uint32_t nl_groups;

            if (ia64_trace_guest_read_u32(env, arg[1] + 4, &nl_pid, status,
                                          sizeof(status)) &&
                ia64_trace_guest_read_u32(env, arg[1] + 8, &nl_groups,
                                          status, sizeof(status))) {
                fprintf(stderr,
                        " sockaddr_nl pid=%" PRIu32
                        " groups=0x%08" PRIx32,
                        nl_pid, nl_groups);
            } else {
                fprintf(stderr, " sockaddr_nl=<unreadable:%s>", status);
            }
        } else if (family == 1 && arg[2] > 2) {
            char path[176];

            ia64_trace_guest_c_string(env, arg[1] + 2, path, sizeof(path));
            fprintf(stderr, " sockaddr_un path=%s", path);
        }
        break;
    }
    case 1203: /* setsockopt */
    {
        char status[48] = "ok";
        uint32_t optval;

        fprintf(stderr,
                " setsockopt fd=%" PRIu64 " level=%" PRIu64
                " opt=%" PRIu64 " optval=0x%016" PRIx64
                " optlen=%" PRIu64,
                arg[0], arg[1], arg[2], arg[3], arg[4]);
        if (arg[3] != 0 && arg[4] >= 4 &&
            ia64_trace_guest_read_u32(env, arg[3], &optval, status,
                                      sizeof(status))) {
            fprintf(stderr, " optval_u32=%" PRIu32, optval);
        }
        break;
    }
    default:
        break;
    }
}

static void ia64_trace_linux_syscall_break(CPUIA64State *env,
                                           const char *mnemonic,
                                           uint64_t iim, uint64_t next_ip)
{
    uint64_t nr;
    uint64_t cpl;

    if (!ia64_syscall_trace_enabled() || iim != IA64_LINUX_BREAK_SYSCALL) {
        return;
    }

    nr = ia64_read_gr(env, 15);
    cpl = (env->psr & IA64_PSR_CPL_MASK) >> IA64_PSR_CPL_SHIFT;
    fprintf(stderr,
            "[ia64-syscall] %s nr=%" PRIu64 "(%s) ip=0x%016" PRIx64
            " next=0x%016" PRIx64 " cpl=%" PRIu64
            " current=0x%016" PRIx64
            " psr=0x%016" PRIx64 " cfm=0x%016" PRIx64
            " pr=0x%016" PRIx64 " r8=0x%016" PRIx64
            " r10=0x%016" PRIx64 " r15=0x%016" PRIx64
            " r32=0x%016" PRIx64 " r33=0x%016" PRIx64
            " r34=0x%016" PRIx64 " r35=0x%016" PRIx64
            " r36=0x%016" PRIx64 " r37=0x%016" PRIx64
            " r38=0x%016" PRIx64 " r39=0x%016" PRIx64
            " b0=0x%016" PRIx64 " b6=0x%016" PRIx64
            " b7=0x%016" PRIx64 " bsp=0x%016" PRIx64
            " bspstore=0x%016" PRIx64,
            mnemonic, nr, ia64_linux_syscall_name(nr), env->ip, next_ip,
            cpl, ia64_read_gr(env, 13), env->psr, env->cfm, env->pr,
            ia64_read_gr(env, 8), ia64_read_gr(env, 10), nr,
            ia64_read_gr(env, 32),
            ia64_read_gr(env, 33), ia64_read_gr(env, 34),
            ia64_read_gr(env, 35), ia64_read_gr(env, 36),
            ia64_read_gr(env, 37), ia64_read_gr(env, 38),
            ia64_read_gr(env, 39), env->br[0], env->br[6], env->br[7],
            env->ar[IA64_AR_BSP], env->ar[IA64_AR_BSPSTORE]);
    ia64_trace_linux_syscall_paths(env, mnemonic, nr);
    ia64_trace_linux_syscall_socket_details(env, mnemonic, nr);
    fprintf(stderr, "\n");
}

static unsigned ia64_helper_psr_cpl(uint64_t psr)
{
    return (psr & IA64_PSR_CPL_MASK) >> IA64_PSR_CPL_SHIFT;
}

static void ia64_count_privilege_transition(uint64_t old_psr,
                                            uint64_t new_psr)
{
    unsigned old_cpl = ia64_helper_psr_cpl(old_psr);
    unsigned new_cpl = ia64_helper_psr_cpl(new_psr);

    if (old_cpl == new_cpl) {
        return;
    }

    IA64_PERF_INC(IA64_PERF_TRANSITION_PRIVILEGE_CHANGE);
    if (old_cpl == 3 && new_cpl < 3) {
        IA64_PERF_INC(IA64_PERF_TRANSITION_USER_TO_KERNEL);
    } else if (old_cpl < 3 && new_cpl == 3) {
        IA64_PERF_INC(IA64_PERF_TRANSITION_KERNEL_TO_USER);
    }
}

static void ia64_count_bank_transition(uint64_t old_psr, uint64_t new_psr)
{
    bool old_bank = (old_psr & IA64_PSR_BN_BIT) != 0;
    bool new_bank = (new_psr & IA64_PSR_BN_BIT) != 0;

    if (old_bank == new_bank) {
        return;
    }

    IA64_PERF_INC(IA64_PERF_TRANSITION_BANK_SWITCH);
    IA64_PERF_INC(new_bank ? IA64_PERF_TRANSITION_BANK_SWITCH_TO_BANK1 :
                             IA64_PERF_TRANSITION_BANK_SWITCH_TO_BANK0);
}

static void ia64_count_interrupt_unmask(uint64_t old_psr, uint64_t new_psr,
                                        CPUIA64State *env)
{
    if ((old_psr & IA64_PSR_I_BIT) == 0 &&
        (new_psr & IA64_PSR_I_BIT) != 0 &&
        ia64_external_interrupt_pending(env)) {
        IA64_PERF_INC(IA64_PERF_INTERRUPT_UNMASK_PENDING);
    }
}

static void ia64_count_psr_transition(CPUIA64State *env, uint64_t old_psr,
                                      uint64_t new_psr)
{
    ia64_count_privilege_transition(old_psr, new_psr);
    ia64_count_bank_transition(old_psr, new_psr);
    ia64_count_interrupt_unmask(old_psr, new_psr, env);
}

static void abort_unsupported_slot(CPUIA64State *env,
                                   const IA64DecodedBundle *decoded,
                                   int slot)
{
    char bundle_text[192];
    char slot_text[256];

    ia64_format_decoded_bundle(decoded, bundle_text, sizeof(bundle_text));
    ia64_format_slot_class(decoded, slot, slot_text, sizeof(slot_text));
    IA64_PERF_INC(IA64_PERF_UNSUPPORTED_ABORT);

    cpu_abort(env_cpu(env),
              "IA-64 execution frontier at IP=0x%016" PRIx64
              ": unsupported instruction %s; bundle %s\n",
              env->ip, slot_text, bundle_text);
}

static void abort_zero_branch(CPUIA64State *env,
                              const IA64DecodedBundle *decoded,
                              int slot)
{
    char bundle_text[192];
    char slot_text[256];

    ia64_format_decoded_bundle(decoded, bundle_text, sizeof(bundle_text));
    ia64_format_slot_class(decoded, slot, slot_text, sizeof(slot_text));
    IA64_PERF_INC(IA64_PERF_ZERO_BRANCH_ABORT);

    cpu_abort(env_cpu(env),
              "IA-64 execution frontier at IP=0x%016" PRIx64
              ": branch target became zero in %s; bundle %s\n",
              env->ip, slot_text, bundle_text);
}

static void ia64_deliver_break(CPUIA64State *env, const char *mnemonic,
                               uint64_t iim, uint64_t *next_ip)
{
    char detail[64];
    uint64_t old_psr = env->psr;

    snprintf(detail, sizeof(detail), "%s iim=0x%" PRIx64, mnemonic, iim);
    IA64_PERF_INC(IA64_PERF_OP_BREAK);
    IA64_PERF_INC(IA64_PERF_TRANSITION_BREAK);
    if (iim == IA64_LINUX_BREAK_SYSCALL) {
        IA64_PERF_INC(IA64_PERF_TRANSITION_BREAK_SYSCALL);
    }
    ia64_trace_linux_syscall_break(env, mnemonic, iim, *next_ip);
    ia64_deliver_break_interruption(env, iim, next_ip, detail);
    ia64_count_psr_transition(env, old_psr, env->psr);
    ia64_progress_trace_event(env, mnemonic, iim, *next_ip);
}

static void ia64_deliver_translation_fault(CPUIA64State *env,
                                           const IA64TranslateResult *result)
{
    ia64_deliver_exception(env, ia64_exception_for_translate_result(result),
                           result->vaddr, result->access_type,
                           result->message);
}

enum {
    EFI_BOOT_SERVICE_BASE = 0,
    EFI_RUNTIME_SERVICE_BASE =
        EFI_BOOT_SERVICE_BASE + VIBTANIUM_EFI_BOOT_SERVICE_COUNT,
    EFI_CON_OUT_SERVICE_BASE =
        EFI_RUNTIME_SERVICE_BASE + VIBTANIUM_EFI_RUNTIME_SERVICE_COUNT,
    EFI_CON_IN_SERVICE_BASE =
        EFI_CON_OUT_SERVICE_BASE + VIBTANIUM_EFI_CON_OUT_SERVICE_COUNT,
    EFI_BLOCK_IO_SERVICE_BASE =
        EFI_CON_IN_SERVICE_BASE + VIBTANIUM_EFI_CON_IN_SERVICE_COUNT,
    EFI_SIMPLE_FILE_SYSTEM_SERVICE_BASE =
        EFI_BLOCK_IO_SERVICE_BASE + VIBTANIUM_EFI_BLOCK_IO_SERVICE_COUNT,
    EFI_FILE_SERVICE_BASE =
        EFI_SIMPLE_FILE_SYSTEM_SERVICE_BASE +
        VIBTANIUM_EFI_SIMPLE_FILE_SYSTEM_SERVICE_COUNT,
    EFI_SERVICE_DESCRIPTOR_COUNT =
        EFI_FILE_SERVICE_BASE + VIBTANIUM_EFI_FILE_SERVICE_COUNT,
};

#define EFI_MAX_INSTALLED_PROTOCOLS 64
#define EFI_MAX_FILE_HANDLES 64
#define EFI_MAX_EVENTS 64
#define EFI_MAX_PAGE_ALLOCATIONS 64
#define EFI_MAX_PATH_CHARS 512
#define EFI_MAX_FILE_READ_BYTES (128 * 1024 * 1024)
#define EFI_PAGE_SIZE UINT64_C(4096)
#define EFI_MEMORY_DESCRIPTOR_SIZE UINT64_C(40)
#define EFI_MEMORY_DESCRIPTOR_VERSION 1
#define EFI_GUEST_RAM_TOP UINT64_C(0x20000000)
#define EFI_LINUX_APPEND_BASE UINT64_C(0x03fff000)
#define EFI_LINUX_APPEND_SIZE UINT64_C(0x00001000)
#define EFI_PAGE_ALLOC_BASE UINT64_C(0x03000000)
#define EFI_PAGE_ALLOC_SIZE (EFI_LINUX_APPEND_BASE - EFI_PAGE_ALLOC_BASE)
#define EFI_RUNTIME_GRANULE_BASE UINT64_C(0x00000000)
#define EFI_RUNTIME_GRANULE_SIZE UINT64_C(0x01000000)
#define EFI_LOW_CONVENTIONAL_BASE EFI_RUNTIME_GRANULE_SIZE
#define EFI_LOW_CONVENTIONAL_PAGES UINT64_C(0)
#define EFI_HIGH_CONVENTIONAL_BASE UINT64_C(0x04000000)
#define EFI_HIGH_CONVENTIONAL_PAGES \
    ((EFI_GUEST_RAM_TOP - EFI_HIGH_CONVENTIONAL_BASE) / EFI_PAGE_SIZE)
#define EFI_DEFAULT_LOADER_IMAGE_PAGES \
    ((VIBTANIUM_EFI_STACK_BASE - VIBTANIUM_EFI_APP_BASE) / EFI_PAGE_SIZE)
#define IA64_REGION_OFFSET_MASK UINT64_C(0x1fffffffffffffff)
#define IA64_FIRMWARE_STATUS_SUCCESS UINT64_C(0)
#define IA64_FIRMWARE_STATUS_UNIMPLEMENTED UINT64_C(0xffffffffffffffff)
#define IA64_FIRMWARE_STATUS_INVALID_ARGUMENT UINT64_C(0xfffffffffffffffe)
#define IA64_FIRMWARE_STATUS_REQUIRES_MEMORY UINT64_C(0xfffffffffffffff7)
#define IA64_FIRMWARE_DEFAULT_BASE_FREQUENCY UINT64_C(100000000)
#define IA64_PAL_VERSION UINT64_C(0x0000002300000000)
#define IA64_PAL_CACHE_LEVELS UINT64_C(2)
#define IA64_PAL_UNIQUE_CACHES UINT64_C(2)
#define IA64_PAL_DATA_OR_UNIFIED_CACHE_TYPE UINT64_C(2)
#define IA64_PROCESSOR_IDENTIFIER_REGISTER_COUNT UINT64_C(5)
#define IA64_IMPLEMENTED_PERF_MON_REGISTER_COUNT UINT64_C(8)
#define IA64_MAXIMUM_PERF_MON_REGISTER_COUNT UINT64_C(256)
#define IA64_MINIMUM_PHYSICAL_STACKED_REGISTERS UINT64_C(96)
#define IA64_MINIMUM_TRANSLATION_REGISTER_COUNT UINT64_C(8)

enum {
    EFI_RESERVED_MEMORY_TYPE = 0,
    EFI_LOADER_CODE = 1,
    EFI_LOADER_DATA = 2,
    EFI_BOOT_SERVICES_CODE = 3,
    EFI_BOOT_SERVICES_DATA = 4,
    EFI_RUNTIME_SERVICES_CODE = 5,
    EFI_RUNTIME_SERVICES_DATA = 6,
    EFI_CONVENTIONAL_MEMORY = 7,
    EFI_ACPI_RECLAIM_MEMORY = 9,
    EFI_MEMORY_MAPPED_IO_PORT_SPACE = 12,
};

typedef enum IA64PalProcedureId {
    IA64_PAL_CACHE_FLUSH = 1,
    IA64_PAL_CACHE_INFO = 2,
    IA64_PAL_CACHE_INIT = 3,
    IA64_PAL_CACHE_SUMMARY = 4,
    IA64_PAL_MEMORY_ATTRIBUTES = 5,
    IA64_PAL_PTCE_INFO = 6,
    IA64_PAL_VIRTUAL_MEMORY_INFO = 7,
    IA64_PAL_VIRTUAL_MEMORY_SUMMARY = 8,
    IA64_PAL_BUS_GET_FEATURES = 9,
    IA64_PAL_BUS_SET_FEATURES = 10,
    IA64_PAL_DEBUG_INFO = 11,
    IA64_PAL_FIXED_ADDRESS = 12,
    IA64_PAL_FREQUENCY_BASE = 13,
    IA64_PAL_FREQUENCY_RATIOS = 14,
    IA64_PAL_PERFORMANCE_MONITOR_INFO = 15,
    IA64_PAL_PLATFORM_ADDR = 16,
    IA64_PAL_PROCESSOR_GET_FEATURES = 17,
    IA64_PAL_PROCESSOR_SET_FEATURES = 18,
    IA64_PAL_RSE_INFO = 19,
    IA64_PAL_VERSION_PROC = 20,
    IA64_PAL_MACHINE_CHECK_CLEAR_LOG = 21,
    IA64_PAL_MACHINE_CHECK_DRAIN = 22,
    IA64_PAL_MACHINE_CHECK_EXPECTED = 23,
    IA64_PAL_MACHINE_CHECK_DYNAMIC_STATE = 24,
    IA64_PAL_MACHINE_CHECK_REGISTER_MEMORY = 27,
    IA64_PAL_HALT = 28,
    IA64_PAL_HALT_LIGHT = 29,
    IA64_PAL_CACHE_LINE_INIT = 31,
    IA64_PAL_VIRTUAL_MEMORY_PAGE_SIZE = 34,
    IA64_PAL_REGISTER_INFO = 39,
    IA64_PAL_PREFETCH_VISIBILITY = 41,
    IA64_PAL_LOGICAL_TO_PHYSICAL = 42,
    IA64_PAL_CACHE_SHARED_INFO = 43,
    IA64_PAL_SHUTDOWN = 44,
    IA64_PAL_COPY_PAL = 256,
    IA64_PAL_HALT_INFO = 257,
    IA64_PAL_TEST_PROC = 258,
    IA64_PAL_CACHE_READ = 259,
    IA64_PAL_CACHE_WRITE = 260,
    IA64_PAL_VIRTUAL_MEMORY_TR_READ = 261,
    IA64_PAL_GET_PSTATE = 262,
    IA64_PAL_SET_PSTATE = 263,
    IA64_PAL_BRAND_INFO = 274,
    IA64_PAL_MACHINE_CHECK_ERROR_INJECT = 276,
} IA64PalProcedureId;

typedef enum IA64SalProcedureId {
    IA64_SAL_SET_VECTORS = 0x01000000,
    IA64_SAL_GET_STATE_INFO = 0x01000001,
    IA64_SAL_GET_STATE_INFO_SIZE = 0x01000002,
    IA64_SAL_CLEAR_STATE_INFO = 0x01000003,
    IA64_SAL_MACHINE_CHECK_RENDEZVOUS = 0x01000004,
    IA64_SAL_MACHINE_CHECK_SET_PARAMETERS = 0x01000005,
    IA64_SAL_REGISTER_PHYSICAL_ADDRESS = 0x01000006,
    IA64_SAL_VERSION_PROC = 0x01000007,
    IA64_SAL_CACHE_FLUSH = 0x01000008,
    IA64_SAL_CACHE_INIT = 0x01000009,
    IA64_SAL_PCI_CONFIG_READ = 0x01000010,
    IA64_SAL_PCI_CONFIG_WRITE = 0x01000011,
    IA64_SAL_FREQUENCY_BASE = 0x01000012,
} IA64SalProcedureId;

enum {
    EFI_ALLOCATE_ANY_PAGES = 0,
    EFI_ALLOCATE_MAX_ADDRESS = 1,
    EFI_ALLOCATE_ADDRESS = 2,
};

#define EFI_MEMORY_UC UINT64_C(0x0000000000000001)
#define EFI_MEMORY_WB UINT64_C(0x0000000000000008)
#define EFI_MEMORY_RUNTIME UINT64_C(0x8000000000000000)
#define EFI_UNSPECIFIED_TIMEZONE 0x07ff
#define IA64_KERNEL_PAGE_OFFSET UINT64_C(0xe000000000000000)
#define EFI_TIMER_CANCEL   0
#define EFI_TIMER_PERIODIC 1
#define EFI_TIMER_RELATIVE 2

typedef struct EfiInstalledProtocol {
    bool in_use;
    uint64_t handle;
    uint8_t guid[16];
    uint64_t interface;
} EfiInstalledProtocol;

typedef struct EfiGuestFile {
    bool in_use;
    uint64_t address;
    bool is_directory;
    char path[EFI_MAX_PATH_CHARS];
    uint8_t *data;
    size_t size;
    uint64_t position;
} EfiGuestFile;

typedef struct EfiGuestEvent {
    bool in_use;
    uint64_t handle;
    uint32_t type;
    bool signaled;
    bool timer_active;
    bool timer_periodic;
    uint64_t timer_period;
    uint64_t timer_due;
} EfiGuestEvent;

typedef struct EfiPageAllocation {
    bool in_use;
    uint64_t address;
    uint64_t pages;
    uint32_t type;
} EfiPageAllocation;

typedef struct EfiMemoryRange {
    uint32_t type;
    uint64_t address;
    uint64_t pages;
    uint64_t attributes;
} EfiMemoryRange;

static VibtaniumEfiBlockDevice efi_boot_media;
static char *efi_boot_media_name;
static bool efi_boot_media_valid;
static uint64_t efi_pool_next = VIBTANIUM_EFI_POOL_BASE;
static uint64_t efi_page_alloc_next = EFI_PAGE_ALLOC_BASE;
static uint64_t efi_memory_map_key = 1;
static uint64_t efi_dynamic_handle_next = UINT64_C(0x00073000);
static uint64_t efi_next_event_handle = VIBTANIUM_EFI_CON_IN_WAIT_EVENT + 1;
static uint64_t efi_loaded_image_base = VIBTANIUM_EFI_APP_BASE;
static uint64_t efi_loaded_image_pages = EFI_DEFAULT_LOADER_IMAGE_PAGES;
static uint32_t efi_high_monotonic_count;
static bool efi_conin_enter_pending = true;
static char *efi_linux_cmdline_append;
static bool efi_linux_cmdline_append_done;
static EfiInstalledProtocol efi_installed_protocols[EFI_MAX_INSTALLED_PROTOCOLS];
static EfiGuestFile efi_guest_files[EFI_MAX_FILE_HANDLES];
static EfiGuestEvent efi_guest_events[EFI_MAX_EVENTS];
static EfiPageAllocation efi_page_allocations[EFI_MAX_PAGE_ALLOCATIONS];

static const uint8_t efi_loaded_image_guid[16] = {
    0xa1, 0x31, 0x1b, 0x5b, 0x62, 0x95, 0xd2, 0x11,
    0x8e, 0x3f, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
};

static const uint8_t efi_simple_text_output_guid[16] = {
    0xc2, 0x77, 0x74, 0x38, 0xc7, 0x69, 0xd2, 0x11,
    0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
};

static const uint8_t efi_simple_text_input_guid[16] = {
    0xc1, 0x77, 0x74, 0x38, 0xc7, 0x69, 0xd2, 0x11,
    0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
};

static const uint8_t efi_device_path_guid[16] = {
    0x91, 0x6e, 0x57, 0x09, 0x3f, 0x6d, 0xd2, 0x11,
    0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
};

static const uint8_t efi_block_io_guid[16] = {
    0x21, 0x5b, 0x4e, 0x96, 0x59, 0x64, 0xd2, 0x11,
    0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
};

static const uint8_t efi_simple_file_system_guid[16] = {
    0x22, 0x5b, 0x4e, 0x96, 0x59, 0x64, 0xd2, 0x11,
    0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
};

static const uint8_t efi_file_info_guid[16] = {
    0x92, 0x6e, 0x57, 0x09, 0x3f, 0x6d, 0xd2, 0x11,
    0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b,
};

#define IA64_PSR_IT_BIT UINT64_C(0x0000001000000000)

typedef enum IA64LinuxAppendResult {
    IA64_LINUX_APPEND_NOT_READY,
    IA64_LINUX_APPEND_APPLIED,
    IA64_LINUX_APPEND_ALREADY_PRESENT,
    IA64_LINUX_APPEND_TOO_LATE,
} IA64LinuxAppendResult;

typedef struct IA64FirmwareResult {
    uint64_t status;
    uint64_t ret0;
    uint64_t ret1;
    uint64_t ret2;
} IA64FirmwareResult;

static uint64_t ia64_region_offset(uint64_t address)
{
    return address & IA64_REGION_OFFSET_MASK;
}

static bool efi_gate_address_is_valid_alias(uint64_t address)
{
    uint64_t region = address & ~IA64_REGION_OFFSET_MASK;

    return region == 0 || region == IA64_KERNEL_PAGE_OFFSET;
}

static uint64_t efi_service_descriptor_address(unsigned service_index)
{
    return VIBTANIUM_EFI_DESCRIPTOR_BASE + (uint64_t)service_index * 16;
}

static uint64_t efi_service_gate_address(unsigned service_index)
{
    return VIBTANIUM_EFI_CALL_GATE_BASE +
           (uint64_t)service_index * IA64_BUNDLE_SIZE;
}

static bool efi_gate_service_index(uint64_t gate_ip, unsigned *index)
{
    uint64_t offset;

    if (!efi_gate_address_is_valid_alias(gate_ip)) {
        return false;
    }
    gate_ip = ia64_region_offset(gate_ip);
    if (gate_ip < VIBTANIUM_EFI_CALL_GATE_BASE) {
        return false;
    }

    offset = gate_ip - VIBTANIUM_EFI_CALL_GATE_BASE;
    if ((offset & (IA64_BUNDLE_SIZE - 1)) != 0) {
        return false;
    }
    offset /= IA64_BUNDLE_SIZE;
    if (offset >= EFI_SERVICE_DESCRIPTOR_COUNT) {
        return false;
    }

    *index = offset;
    return true;
}

static bool efi_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_EFI_TRACE") != NULL;
    }
    return enabled != 0;
}

static bool ia64_progress_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_IA64_PROGRESS") != NULL;
    }
    return enabled != 0;
}

static uint64_t ia64_progress_trace_interval(void)
{
    static int initialized;
    static uint64_t interval;

    if (!initialized) {
        const char *value = g_getenv("VIBTANIUM_IA64_PROGRESS_INTERVAL");

        interval = UINT64_C(0x100000);
        if (value != NULL && *value != '\0') {
            char *endptr = NULL;
            uint64_t parsed = g_ascii_strtoull(value, &endptr, 0);

            if (endptr != value && parsed != 0) {
                interval = parsed;
            }
        }
        initialized = 1;
    }

    return interval;
}

static bool ia64_progress_trace_ip_matches(uint64_t ip)
{
    static int initialized;
    static bool min_enabled;
    static bool max_enabled;
    static uint64_t min_ip;
    static uint64_t max_ip;

    if (!initialized) {
        const char *min = g_getenv("VIBTANIUM_IA64_PROGRESS_IP_MIN");
        const char *max = g_getenv("VIBTANIUM_IA64_PROGRESS_IP_MAX");

        if (min != NULL && *min != '\0') {
            char *endptr = NULL;

            min_ip = g_ascii_strtoull(min, &endptr, 0);
            min_enabled = endptr != min;
        }
        if (max != NULL && *max != '\0') {
            char *endptr = NULL;

            max_ip = g_ascii_strtoull(max, &endptr, 0);
            max_enabled = endptr != max;
        }
        initialized = 1;
    }

    if (min_enabled && ip < min_ip) {
        return false;
    }
    if (max_enabled && ip > max_ip) {
        return false;
    }

    return true;
}

static void ia64_progress_trace_bundle(CPUIA64State *env)
{
    static uint64_t count;
    static uint64_t matched_count;
    uint64_t interval;

    if (!ia64_progress_trace_enabled()) {
        return;
    }

    count++;
    if (!ia64_progress_trace_ip_matches(env->ip)) {
        return;
    }

    matched_count++;
    interval = ia64_progress_trace_interval();
    if ((matched_count % interval) != 0) {
        return;
    }

    trace_ia64_progress_bundle(count, env->ip, env->psr, env->cfm,
                               env->ar[IA64_AR_LC], env->ar[IA64_AR_EC],
                               env->ar[IA64_AR_BSPSTORE], env->br[0]);
    fprintf(stderr,
            "[ia64-progress] bundles=%" PRIu64 " ip=0x%016" PRIx64
            " psr=0x%016" PRIx64 " cfm=0x%016" PRIx64
            " lc=0x%016" PRIx64 " ec=0x%016" PRIx64
            " bspstore=0x%016" PRIx64 " b0=0x%016" PRIx64
            " itc=0x%016" PRIx64 " itm=0x%016" PRIx64
            " itv=0x%016" PRIx64 " tpr=0x%016" PRIx64
            " ivr=0x%016" PRIx64 " irr0=0x%016" PRIx64
            " irr1=0x%016" PRIx64 " irr2=0x%016" PRIx64
            " irr3=0x%016" PRIx64 " intr-pending=%u"
            " intr-active=%" PRIu64 " intr-vector=0x%016" PRIx64 "\n",
            count, env->ip, env->psr, env->cfm, env->ar[IA64_AR_LC],
            env->ar[IA64_AR_EC], env->ar[IA64_AR_BSPSTORE], env->br[0],
            env->ar[IA64_AR_ITC], env->cr[IA64_CR_ITM],
            env->cr[IA64_CR_ITV], env->cr[IA64_CR_TPR],
            env->cr[IA64_CR_IVR], env->cr[IA64_CR_IRR0],
            env->cr[IA64_CR_IRR1], env->cr[IA64_CR_IRR2],
            env->cr[IA64_CR_IRR3], env->interrupt.pending,
            env->interrupt.pending_interruption,
            env->interrupt.pending_vector);
}

static void ia64_progress_trace_event(CPUIA64State *env, const char *event,
                                      uint64_t value, uint64_t next_ip)
{
    static uint64_t event_count;

    if (!ia64_progress_trace_enabled()) {
        return;
    }

    event_count++;
    if (event_count > 16 && (event_count & UINT64_C(0xffff)) != 0) {
        return;
    }

    trace_ia64_progress_event(event, env->ip, value, next_ip, env->psr,
                              env->cfm);
    fprintf(stderr,
            "[ia64-progress] event=%s ip=0x%016" PRIx64
            " value=0x%016" PRIx64 " next=0x%016" PRIx64
            " psr=0x%016" PRIx64 " cfm=0x%016" PRIx64 "\n",
            event, env->ip, value, next_ip, env->psr, env->cfm);
}

static bool ia64_state_trace_matches(uint64_t ip)
{
    static int initialized;
    static bool enabled;
    static uint64_t filter_start;
    static uint64_t filter_end;

    if (!initialized) {
        const char *addr = g_getenv("VIBTANIUM_STATE_TRACE_IP");
        const char *size = g_getenv("VIBTANIUM_STATE_TRACE_SIZE");

        if (addr != NULL && *addr != '\0') {
            char *endptr = NULL;
            uint64_t parsed_size = IA64_BUNDLE_SIZE;

            filter_start = g_ascii_strtoull(addr, &endptr, 0);
            enabled = endptr != addr;
            if (size != NULL && *size != '\0') {
                endptr = NULL;
                parsed_size = g_ascii_strtoull(size, &endptr, 0);
                if (endptr == size || parsed_size == 0) {
                    parsed_size = IA64_BUNDLE_SIZE;
                }
            }
            filter_end = filter_start + parsed_size - 1;
        }
        initialized = 1;
    }

    return enabled && ip >= filter_start && ip <= filter_end;
}

static uint64_t ia64_state_trace_limit(void)
{
    static int initialized;
    static uint64_t limit;

    if (!initialized) {
        const char *value = g_getenv("VIBTANIUM_STATE_TRACE_LIMIT");

        limit = 512;
        if (value != NULL && *value != '\0') {
            char *endptr = NULL;
            uint64_t parsed = g_ascii_strtoull(value, &endptr, 0);

            if (endptr != value) {
                limit = parsed;
            }
        }
        initialized = 1;
    }

    return limit;
}

static void ia64_state_trace_bundle(CPUIA64State *env)
{
    static uint64_t count;

    if (!ia64_state_trace_matches(env->ip)) {
        return;
    }
    if (count >= ia64_state_trace_limit()) {
        return;
    }
    count++;

    fprintf(stderr,
            "[ia64-state] count=%" PRIu64 " ip=0x%016" PRIx64
            " psr=0x%016" PRIx64 " cfm=0x%016" PRIx64
            " pr=0x%016" PRIx64 " b0=0x%016" PRIx64
            " r8=0x%016" PRIx64
            " r12=0x%016" PRIx64
            " r13=0x%016" PRIx64
            " r14=0x%016" PRIx64 " r15=0x%016" PRIx64
            " r16=0x%016" PRIx64 " r17=0x%016" PRIx64
            " r18=0x%016" PRIx64 " r19=0x%016" PRIx64
            " r20=0x%016" PRIx64 " r21=0x%016" PRIx64
            " r22=0x%016" PRIx64 " r29=0x%016" PRIx64
            " r30=0x%016" PRIx64 " r31=0x%016" PRIx64
            " r32=0x%016" PRIx64 " r33=0x%016" PRIx64
            " r34=0x%016" PRIx64 " r35=0x%016" PRIx64
            " r36=0x%016" PRIx64 " r37=0x%016" PRIx64
            " r38=0x%016" PRIx64 " r39=0x%016" PRIx64
            " r40=0x%016" PRIx64 " r41=0x%016" PRIx64
            " r42=0x%016" PRIx64 " r43=0x%016" PRIx64
            " r44=0x%016" PRIx64 " r45=0x%016" PRIx64
            " r46=0x%016" PRIx64 " r47=0x%016" PRIx64
            " r48=0x%016" PRIx64 " r49=0x%016" PRIx64
            " bsp=0x%016" PRIx64 " bspstore=0x%016" PRIx64
            " ifa=0x%016" PRIx64 " itir=0x%016" PRIx64
            " iha=0x%016" PRIx64 " ipsr=0x%016" PRIx64
            " iip=0x%016" PRIx64 " ifs=0x%016" PRIx64
            " isr=0x%016" PRIx64 "\n",
            count, env->ip, env->psr, env->cfm, env->pr, env->br[0],
            ia64_read_gr(env, 8),
            ia64_read_gr(env, 12),
            ia64_read_gr(env, 13),
            ia64_read_gr(env, 14), ia64_read_gr(env, 15),
            ia64_read_gr(env, 16), ia64_read_gr(env, 17),
            ia64_read_gr(env, 18), ia64_read_gr(env, 19),
            ia64_read_gr(env, 20), ia64_read_gr(env, 21),
            ia64_read_gr(env, 22), ia64_read_gr(env, 29),
            ia64_read_gr(env, 30), ia64_read_gr(env, 31),
            ia64_read_gr(env, 32), ia64_read_gr(env, 33),
            ia64_read_gr(env, 34), ia64_read_gr(env, 35),
            ia64_read_gr(env, 36), ia64_read_gr(env, 37),
            ia64_read_gr(env, 38), ia64_read_gr(env, 39),
            ia64_read_gr(env, 40), ia64_read_gr(env, 41),
            ia64_read_gr(env, 42), ia64_read_gr(env, 43),
            ia64_read_gr(env, 44), ia64_read_gr(env, 45),
            ia64_read_gr(env, 46), ia64_read_gr(env, 47),
            ia64_read_gr(env, 48), ia64_read_gr(env, 49),
            env->ar[IA64_AR_BSP], env->ar[IA64_AR_BSPSTORE],
            env->cr[IA64_CR_IFA], env->cr[IA64_CR_ITIR],
            env->cr[IA64_CR_IHA], env->cr[IA64_CR_IPSR],
            env->cr[IA64_CR_IIP], env->cr[IA64_CR_IFS],
            env->cr[IA64_CR_ISR]);
}

static void ia64_finish_bundle(CPUIA64State *env, uint64_t next_ip,
                               unsigned next_ri)
{
    env->psr = ia64_psr_with_ri(env->psr, next_ri);
    env->ip = next_ip;
    if (ia64_advance_itc_and_check_timer(env, 1)) {
        ia64_latch_timer_interrupt(env);
        cpu_set_interrupt(env_cpu(env), CPU_INTERRUPT_HARD);
    }
}

static bool ia64_tcg_can_chain(CPUIA64State *env)
{
    CPUState *cpu = env_cpu(env);

    return cpu->interrupt_request == 0 &&
           !qatomic_read(&cpu->exit_request);
}

static uint32_t ia64_lookup_ptr_chain_ok(CPUIA64State *env)
{
    bool chain_ok = ia64_tcg_can_chain(env);

    IA64_PERF_INC(chain_ok ? IA64_PERF_TB_EXIT_LOOKUP_PTR :
                             IA64_PERF_TB_EXIT_MAIN_LOOP);
    return chain_ok ? 1 : 0;
}

void vibtanium_efi_set_linux_cmdline_append(const char *append)
{
    g_autofree char *trimmed = append ? g_strdup(append) : NULL;

    g_free(efi_linux_cmdline_append);
    efi_linux_cmdline_append = NULL;
    if (trimmed) {
        g_strstrip(trimmed);
        if (trimmed[0]) {
            efi_linux_cmdline_append = g_strdup(trimmed);
        }
    }
    efi_linux_cmdline_append_done = efi_linux_cmdline_append == NULL;
}

static bool ia64_linux_cmdline_contains_token(const char *command_line,
                                              const char *token)
{
    g_autofree char *haystack = g_ascii_strdown(command_line, -1);
    g_autofree char *needle = g_ascii_strdown(token, -1);

    return haystack && needle && strstr(haystack, needle);
}

static bool ia64_linux_cmdline_looks_like_elilo(const char *command_line)
{
    return strstr(command_line, "BOOT_IMAGE=") ||
           ia64_linux_cmdline_contains_token(command_line, "initrd=") ||
           ia64_linux_cmdline_contains_token(command_line, "root=") ||
           strstr(command_line, " ro");
}

static IA64LinuxAppendResult ia64_try_apply_linux_cmdline_append(
    CPUIA64State *env)
{
    g_autoptr(GString) existing = NULL;
    g_autoptr(GString) combined = NULL;
    const char *separator;
    uint64_t boot_param;
    uint64_t command_line;
    size_t prefix_len;
    bool terminated = false;

    if (!efi_linux_cmdline_append || efi_linux_cmdline_append_done) {
        return IA64_LINUX_APPEND_ALREADY_PRESENT;
    }
    if (env->psr & IA64_PSR_IT_BIT) {
        return IA64_LINUX_APPEND_TOO_LATE;
    }

    boot_param = ia64_read_gr(env, 28);
    if (boot_param == 0 || (boot_param & 7) != 0 ||
        boot_param + 8 > EFI_GUEST_RAM_TOP) {
        return IA64_LINUX_APPEND_NOT_READY;
    }

    command_line = cpu_ldq_le_data_ra(env, boot_param, GETPC());
    if (command_line == 0 || command_line >= EFI_GUEST_RAM_TOP) {
        return IA64_LINUX_APPEND_NOT_READY;
    }

    existing = g_string_new(NULL);
    for (unsigned i = 0; i < 1024 && command_line + i < EFI_GUEST_RAM_TOP; i++) {
        uint8_t ch = cpu_ldub_data_ra(env, command_line + i, GETPC());

        if (ch == 0) {
            terminated = true;
            break;
        }
        if (ch < 0x20 || ch > 0x7e) {
            return IA64_LINUX_APPEND_NOT_READY;
        }
        g_string_append_c(existing, (char)ch);
    }

    if (!terminated || existing->len == 0 ||
        !ia64_linux_cmdline_looks_like_elilo(existing->str)) {
        return IA64_LINUX_APPEND_NOT_READY;
    }
    if (strstr(existing->str, efi_linux_cmdline_append)) {
        trace_ia64_linux_cmdline_append(env->ip, boot_param, command_line,
                                        "already-present", existing->str);
        warn_report("vibtanium Linux cmdline append already present: \"%s\"",
                    existing->str);
        return IA64_LINUX_APPEND_ALREADY_PRESENT;
    }

    separator = strstr(existing->str, " -- ");
    combined = g_string_new(NULL);
    if (separator) {
        prefix_len = separator - existing->str;
        g_string_append_len(combined, existing->str, prefix_len);
        g_string_append_c(combined, ' ');
        g_string_append(combined, efi_linux_cmdline_append);
        g_string_append(combined, separator);
    } else {
        g_string_append(combined, existing->str);
        g_string_append_c(combined, ' ');
        g_string_append(combined, efi_linux_cmdline_append);
    }

    if (combined->len + 1 > EFI_LINUX_APPEND_SIZE) {
        trace_ia64_linux_cmdline_append(env->ip, boot_param, command_line,
                                        "too-long", combined->str);
        warn_report("vibtanium Linux cmdline append too long: %zu bytes",
                    combined->len + 1);
        return IA64_LINUX_APPEND_TOO_LATE;
    }

    for (unsigned i = 0; i < combined->len; i++) {
        cpu_stb_data_ra(env, EFI_LINUX_APPEND_BASE + i,
                        (uint8_t)combined->str[i], GETPC());
    }
    cpu_stb_data_ra(env, EFI_LINUX_APPEND_BASE + combined->len, 0, GETPC());
    cpu_stq_le_data_ra(env, boot_param, EFI_LINUX_APPEND_BASE, GETPC());
    trace_ia64_linux_cmdline_append(env->ip, boot_param, command_line,
                                    "applied", combined->str);
    warn_report("vibtanium Linux cmdline append -> \"%s\"", combined->str);
    return IA64_LINUX_APPEND_APPLIED;
}

static void ia64_maybe_apply_linux_cmdline_append(CPUIA64State *env)
{
    IA64LinuxAppendResult result;

    if (efi_linux_cmdline_append_done) {
        return;
    }

    result = ia64_try_apply_linux_cmdline_append(env);
    if (result != IA64_LINUX_APPEND_NOT_READY) {
        efi_linux_cmdline_append_done = true;
    }
}

static const char *efi_service_group_name(unsigned service_index,
                                          unsigned *group_index)
{
    if (service_index < EFI_RUNTIME_SERVICE_BASE) {
        *group_index = service_index - EFI_BOOT_SERVICE_BASE;
        return "boot";
    }
    if (service_index < EFI_CON_OUT_SERVICE_BASE) {
        *group_index = service_index - EFI_RUNTIME_SERVICE_BASE;
        return "runtime";
    }
    if (service_index < EFI_CON_IN_SERVICE_BASE) {
        *group_index = service_index - EFI_CON_OUT_SERVICE_BASE;
        return "conout";
    }
    if (service_index < EFI_BLOCK_IO_SERVICE_BASE) {
        *group_index = service_index - EFI_CON_IN_SERVICE_BASE;
        return "conin";
    }
    if (service_index < EFI_SIMPLE_FILE_SYSTEM_SERVICE_BASE) {
        *group_index = service_index - EFI_BLOCK_IO_SERVICE_BASE;
        return "blockio";
    }
    if (service_index < EFI_FILE_SERVICE_BASE) {
        *group_index = service_index - EFI_SIMPLE_FILE_SYSTEM_SERVICE_BASE;
        return "simplefs";
    }
    *group_index = service_index - EFI_FILE_SERVICE_BASE;
    return "file";
}

static void efi_trace_service(CPUIA64State *env, unsigned service_index,
                              uint64_t result)
{
    unsigned group_index = 0;
    const char *group;
    const char *status = vibtanium_efi_status_name(result);

    group = efi_service_group_name(service_index, &group_index);
    trace_ia64_efi_service(env->ip, group, group_index, status,
                           ia64_read_gr(env, 32), ia64_read_gr(env, 33),
                           ia64_read_gr(env, 34), ia64_read_gr(env, 35),
                           ia64_read_gr(env, 36));
    if (!efi_trace_enabled()) {
        return;
    }

    fprintf(stderr,
            "[efi] ip=0x%016" PRIx64 " service=%s[%u] status=%s "
            "r32=0x%016" PRIx64 " r33=0x%016" PRIx64
            " r34=0x%016" PRIx64 " r35=0x%016" PRIx64
            " r36=0x%016" PRIx64 "\n",
            env->ip, group, group_index, status, ia64_read_gr(env, 32),
            ia64_read_gr(env, 33), ia64_read_gr(env, 34),
            ia64_read_gr(env, 35), ia64_read_gr(env, 36));
}

static IA64FirmwareResult firmware_success(uint64_t ret0, uint64_t ret1,
                                           uint64_t ret2)
{
    return (IA64FirmwareResult) {
        .status = IA64_FIRMWARE_STATUS_SUCCESS,
        .ret0 = ret0,
        .ret1 = ret1,
        .ret2 = ret2,
    };
}

static IA64FirmwareResult firmware_status(uint64_t status)
{
    return (IA64FirmwareResult) {
        .status = status,
    };
}

static const char *firmware_status_name(uint64_t status)
{
    switch (status) {
    case IA64_FIRMWARE_STATUS_SUCCESS:
        return "ok";
    case IA64_FIRMWARE_STATUS_UNIMPLEMENTED:
        return "unimplemented";
    case IA64_FIRMWARE_STATUS_INVALID_ARGUMENT:
        return "invalid-argument";
    case IA64_FIRMWARE_STATUS_REQUIRES_MEMORY:
        return "requires-memory";
    default:
        return "unknown";
    }
}

static const char *pal_procedure_name(uint64_t function_id)
{
    switch (function_id) {
    case IA64_PAL_CACHE_FLUSH:
        return "PAL_CACHE_FLUSH";
    case IA64_PAL_CACHE_INFO:
        return "PAL_CACHE_INFO";
    case IA64_PAL_CACHE_INIT:
        return "PAL_CACHE_INIT";
    case IA64_PAL_CACHE_SUMMARY:
        return "PAL_CACHE_SUMMARY";
    case IA64_PAL_MEMORY_ATTRIBUTES:
        return "PAL_MEM_ATTRIB";
    case IA64_PAL_PTCE_INFO:
        return "PAL_PTCE_INFO";
    case IA64_PAL_VIRTUAL_MEMORY_INFO:
        return "PAL_VM_INFO";
    case IA64_PAL_VIRTUAL_MEMORY_SUMMARY:
        return "PAL_VM_SUMMARY";
    case IA64_PAL_BUS_GET_FEATURES:
        return "PAL_BUS_GET_FEATURES";
    case IA64_PAL_BUS_SET_FEATURES:
        return "PAL_BUS_SET_FEATURES";
    case IA64_PAL_DEBUG_INFO:
        return "PAL_DEBUG_INFO";
    case IA64_PAL_FIXED_ADDRESS:
        return "PAL_FIXED_ADDR";
    case IA64_PAL_FREQUENCY_BASE:
        return "PAL_FREQ_BASE";
    case IA64_PAL_FREQUENCY_RATIOS:
        return "PAL_FREQ_RATIOS";
    case IA64_PAL_PERFORMANCE_MONITOR_INFO:
        return "PAL_PERF_MON_INFO";
    case IA64_PAL_PLATFORM_ADDR:
        return "PAL_PLATFORM_ADDR";
    case IA64_PAL_PROCESSOR_GET_FEATURES:
        return "PAL_PROC_GET_FEATURES";
    case IA64_PAL_PROCESSOR_SET_FEATURES:
        return "PAL_PROC_SET_FEATURES";
    case IA64_PAL_RSE_INFO:
        return "PAL_RSE_INFO";
    case IA64_PAL_VERSION_PROC:
        return "PAL_VERSION";
    case IA64_PAL_MACHINE_CHECK_CLEAR_LOG:
        return "PAL_MC_CLEAR_LOG";
    case IA64_PAL_MACHINE_CHECK_DRAIN:
        return "PAL_MC_DRAIN";
    case IA64_PAL_MACHINE_CHECK_EXPECTED:
        return "PAL_MC_EXPECTED";
    case IA64_PAL_MACHINE_CHECK_DYNAMIC_STATE:
        return "PAL_MC_DYNAMIC_STATE";
    case IA64_PAL_MACHINE_CHECK_REGISTER_MEMORY:
        return "PAL_MC_REGISTER_MEM";
    case IA64_PAL_HALT:
        return "PAL_HALT";
    case IA64_PAL_HALT_LIGHT:
        return "PAL_HALT_LIGHT";
    case IA64_PAL_CACHE_LINE_INIT:
        return "PAL_CACHE_LINE_INIT";
    case IA64_PAL_VIRTUAL_MEMORY_PAGE_SIZE:
        return "PAL_VM_PAGE_SIZE";
    case IA64_PAL_PREFETCH_VISIBILITY:
        return "PAL_PREFETCH_VISIBILITY";
    case IA64_PAL_LOGICAL_TO_PHYSICAL:
        return "PAL_LOGICAL_TO_PHYSICAL";
    case IA64_PAL_CACHE_SHARED_INFO:
        return "PAL_CACHE_SHARED_INFO";
    case IA64_PAL_SHUTDOWN:
        return "PAL_SHUTDOWN";
    case IA64_PAL_COPY_PAL:
        return "PAL_COPY_PAL";
    case IA64_PAL_HALT_INFO:
        return "PAL_HALT_INFO";
    case IA64_PAL_TEST_PROC:
        return "PAL_TEST_PROC";
    case IA64_PAL_CACHE_READ:
        return "PAL_CACHE_READ";
    case IA64_PAL_CACHE_WRITE:
        return "PAL_CACHE_WRITE";
    case IA64_PAL_VIRTUAL_MEMORY_TR_READ:
        return "PAL_VM_TR_READ";
    case IA64_PAL_GET_PSTATE:
        return "PAL_GET_PSTATE";
    case IA64_PAL_SET_PSTATE:
        return "PAL_SET_PSTATE";
    case IA64_PAL_BRAND_INFO:
        return "PAL_BRAND_INFO";
    case IA64_PAL_MACHINE_CHECK_ERROR_INJECT:
        return "PAL_MC_ERROR_INJECT";
    default:
        return "PAL_UNKNOWN";
    }
}

static const char *sal_procedure_name(uint64_t function_id)
{
    switch (function_id) {
    case IA64_SAL_SET_VECTORS:
        return "SAL_SET_VECTORS";
    case IA64_SAL_GET_STATE_INFO:
        return "SAL_GET_STATE_INFO";
    case IA64_SAL_GET_STATE_INFO_SIZE:
        return "SAL_GET_STATE_INFO_SIZE";
    case IA64_SAL_CLEAR_STATE_INFO:
        return "SAL_CLEAR_STATE_INFO";
    case IA64_SAL_MACHINE_CHECK_RENDEZVOUS:
        return "SAL_MC_RENDEZ";
    case IA64_SAL_MACHINE_CHECK_SET_PARAMETERS:
        return "SAL_MC_SET_PARAMS";
    case IA64_SAL_REGISTER_PHYSICAL_ADDRESS:
        return "SAL_REGISTER_PHYSICAL_ADDR";
    case IA64_SAL_VERSION_PROC:
        return "SAL_VERSION";
    case IA64_SAL_CACHE_FLUSH:
        return "SAL_CACHE_FLUSH";
    case IA64_SAL_CACHE_INIT:
        return "SAL_CACHE_INIT";
    case IA64_SAL_PCI_CONFIG_READ:
        return "SAL_PCI_CONFIG_READ";
    case IA64_SAL_PCI_CONFIG_WRITE:
        return "SAL_PCI_CONFIG_WRITE";
    case IA64_SAL_FREQUENCY_BASE:
        return "SAL_FREQ_BASE";
    default:
        return "SAL_UNKNOWN";
    }
}

static uint64_t pal_supported_page_size_mask(void)
{
    return (UINT64_C(1) << 12) |
           (UINT64_C(1) << 14) |
           (UINT64_C(1) << 16) |
           (UINT64_C(1) << 21) |
           (UINT64_C(1) << 24) |
           (UINT64_C(1) << 28);
}

static uint64_t pal_cache_info1(void)
{
    const uint64_t unified = 1;
    const uint64_t associativity = UINT64_C(1) << 8;
    const uint64_t line_size_64 = UINT64_C(6) << 16;
    const uint64_t stride_64 = UINT64_C(6) << 24;
    const uint64_t store_latency = UINT64_C(1) << 32;
    const uint64_t load_latency = UINT64_C(1) << 40;

    return unified | associativity | line_size_64 | stride_64 |
           store_latency | load_latency;
}

static uint64_t pal_cache_info2(uint64_t level)
{
    const uint64_t size = level == 0 ? 32 * 1024 : 256 * 1024;
    const uint64_t tag_least_bit = 6;
    const uint64_t tag_most_bit = 43;

    return size | (tag_least_bit << 40) | (tag_most_bit << 48);
}

static IA64FirmwareResult pal_cache_info(uint64_t level, uint64_t type)
{
    if (level >= IA64_PAL_CACHE_LEVELS ||
        type != IA64_PAL_DATA_OR_UNIFIED_CACHE_TYPE) {
        return firmware_status(IA64_FIRMWARE_STATUS_INVALID_ARGUMENT);
    }
    return firmware_success(pal_cache_info1(), pal_cache_info2(level), 0);
}

static uint64_t pal_vm_summary1(void)
{
    const uint64_t hardware_walker = 1;
    const uint64_t physical_address_size = 44;
    const uint64_t key_size = 24;
    const uint64_t hash_tag_id = 18;
    const uint64_t unique_translation_caches = 1;
    const uint64_t translation_cache_levels = 1;

    return hardware_walker |
           (physical_address_size << 1) |
           (key_size << 8) |
           ((uint64_t)IA64_PKR_COUNT << 16) |
           (hash_tag_id << 24) |
           (IA64_MINIMUM_TRANSLATION_REGISTER_COUNT << 32) |
           (IA64_MINIMUM_TRANSLATION_REGISTER_COUNT << 40) |
           (unique_translation_caches << 48) |
           (translation_cache_levels << 56);
}

static uint64_t pal_vm_summary2(void)
{
    const uint64_t implemented_va_msb = 50;
    const uint64_t region_identifier_size = 18;

    return implemented_va_msb | (region_identifier_size << 8);
}

static uint64_t pal_single_processor_logical_overview(void)
{
    const uint64_t logical_processors = 1;
    const uint64_t threads_per_core = 1;
    const uint64_t cores_per_processor = 1;
    const uint64_t physical_processor_id = 0;

    return logical_processors | (threads_per_core << 16) |
           (cores_per_processor << 32) | (physical_processor_id << 48);
}

static void firmware_guest_write_bytes(CPUIA64State *env, uint64_t address,
                                       const uint8_t *bytes, size_t size)
{
    for (size_t i = 0; i < size; i++) {
        cpu_stb_data_ra(env, address + i, bytes[i], GETPC());
    }
}

static IA64FirmwareResult pal_brand_info(CPUIA64State *env,
                                         uint64_t selector,
                                         uint64_t buffer)
{
    uint8_t brand[128];
    const char *name = "Vibtanium IA-64";

    if (selector != 0 || buffer == 0) {
        return firmware_status(IA64_FIRMWARE_STATUS_REQUIRES_MEMORY);
    }

    memset(brand, 0, sizeof(brand));
    memcpy(brand, name, MIN(strlen(name), sizeof(brand) - 1));
    firmware_guest_write_bytes(env, buffer, brand, sizeof(brand));
    return firmware_success(0, 0, 0);
}

static IA64FirmwareResult dispatch_pal(CPUIA64State *env,
                                       uint64_t function_id,
                                       uint64_t arg0, uint64_t arg1)
{
    switch (function_id) {
    case IA64_PAL_CACHE_FLUSH:
    case IA64_PAL_CACHE_INIT:
    case IA64_PAL_CACHE_LINE_INIT:
    case IA64_PAL_PROCESSOR_GET_FEATURES:
    case IA64_PAL_PROCESSOR_SET_FEATURES:
    case IA64_PAL_BUS_GET_FEATURES:
    case IA64_PAL_BUS_SET_FEATURES:
    case IA64_PAL_MACHINE_CHECK_CLEAR_LOG:
    case IA64_PAL_MACHINE_CHECK_DRAIN:
    case IA64_PAL_MACHINE_CHECK_EXPECTED:
    case IA64_PAL_MACHINE_CHECK_DYNAMIC_STATE:
    case IA64_PAL_MACHINE_CHECK_REGISTER_MEMORY:
    case IA64_PAL_HALT:
    case IA64_PAL_HALT_LIGHT:
    case IA64_PAL_FIXED_ADDRESS:
    case IA64_PAL_PLATFORM_ADDR:
    case IA64_PAL_SHUTDOWN:
        return firmware_success(0, 0, 0);
    case IA64_PAL_COPY_PAL:
    case IA64_PAL_TEST_PROC:
    case IA64_PAL_CACHE_READ:
    case IA64_PAL_CACHE_WRITE:
    case IA64_PAL_VIRTUAL_MEMORY_TR_READ:
    case IA64_PAL_GET_PSTATE:
    case IA64_PAL_SET_PSTATE:
    case IA64_PAL_MACHINE_CHECK_ERROR_INJECT:
        return firmware_status(IA64_FIRMWARE_STATUS_UNIMPLEMENTED);
    case IA64_PAL_CACHE_INFO:
        return pal_cache_info(arg0, arg1);
    case IA64_PAL_CACHE_SUMMARY:
        return firmware_success(IA64_PAL_CACHE_LEVELS,
                                IA64_PAL_UNIQUE_CACHES, 0);
    case IA64_PAL_MEMORY_ATTRIBUTES:
        return firmware_success(0, 0, 0);
    case IA64_PAL_VIRTUAL_MEMORY_SUMMARY:
        return firmware_success(pal_vm_summary1(), pal_vm_summary2(), 0);
    case IA64_PAL_VIRTUAL_MEMORY_INFO:
        return firmware_success(pal_supported_page_size_mask(), 61, 0);
    case IA64_PAL_VIRTUAL_MEMORY_PAGE_SIZE:
        return firmware_success(pal_supported_page_size_mask(),
                                pal_supported_page_size_mask(), 0);
    case IA64_PAL_PTCE_INFO:
        return firmware_success(1, 4096, 0);
    case IA64_PAL_REGISTER_INFO:
        return firmware_success(IA64_AR_COUNT, IA64_CR_COUNT,
                                IA64_PROCESSOR_IDENTIFIER_REGISTER_COUNT);
    case IA64_PAL_RSE_INFO:
        return firmware_success(IA64_MINIMUM_PHYSICAL_STACKED_REGISTERS,
                                0, 0);
    case IA64_PAL_VERSION_PROC:
        return firmware_success(IA64_PAL_VERSION, IA64_PAL_VERSION, 0);
    case IA64_PAL_DEBUG_INFO:
        return firmware_success(8, 8, 0);
    case IA64_PAL_FREQUENCY_BASE:
        return firmware_success(IA64_FIRMWARE_DEFAULT_BASE_FREQUENCY, 0, 0);
    case IA64_PAL_FREQUENCY_RATIOS:
        return firmware_success(UINT64_C(0x0000000100000001),
                                UINT64_C(0x0000000100000001),
                                UINT64_C(0x0000000100000064));
    case IA64_PAL_PERFORMANCE_MONITOR_INFO:
        return firmware_success(IA64_IMPLEMENTED_PERF_MON_REGISTER_COUNT,
                                IA64_MAXIMUM_PERF_MON_REGISTER_COUNT, 0);
    case IA64_PAL_PREFETCH_VISIBILITY:
        return firmware_success(1, 0, 0);
    case IA64_PAL_LOGICAL_TO_PHYSICAL:
        return arg0 == 0 || arg0 == UINT64_MAX
               ? firmware_success(pal_single_processor_logical_overview(),
                                  0, 0)
               : firmware_status(IA64_FIRMWARE_STATUS_INVALID_ARGUMENT);
    case IA64_PAL_HALT_INFO:
        return firmware_success(UINT64_C(1000) | (UINT64_C(1000) << 16) |
                                (UINT64_C(10) << 32) |
                                (UINT64_C(1) << 60) |
                                (UINT64_C(1) << 61), 0, 0);
    case IA64_PAL_BRAND_INFO:
        return pal_brand_info(env, arg0, arg1);
    default:
        return firmware_status(IA64_FIRMWARE_STATUS_UNIMPLEMENTED);
    }
}

static bool pal_uses_static_calling_convention(uint64_t function_id)
{
    return !ia64_pal_uses_stacked_calling_convention(function_id);
}

static IA64FirmwareResult dispatch_sal(uint64_t function_id)
{
    switch (function_id) {
    case IA64_SAL_GET_STATE_INFO:
    case IA64_SAL_CLEAR_STATE_INFO:
    case IA64_SAL_CACHE_FLUSH:
    case IA64_SAL_CACHE_INIT:
    case IA64_SAL_SET_VECTORS:
    case IA64_SAL_MACHINE_CHECK_RENDEZVOUS:
    case IA64_SAL_MACHINE_CHECK_SET_PARAMETERS:
    case IA64_SAL_REGISTER_PHYSICAL_ADDRESS:
        return firmware_success(0, 0, 0);
    case IA64_SAL_GET_STATE_INFO_SIZE:
        return firmware_success(0, 0, 0);
    case IA64_SAL_VERSION_PROC:
        return firmware_success(UINT64_C(0x0000000200000009), 0, 0);
    case IA64_SAL_FREQUENCY_BASE:
        return firmware_success(IA64_FIRMWARE_DEFAULT_BASE_FREQUENCY, 0, 0);
    case IA64_SAL_PCI_CONFIG_READ:
    case IA64_SAL_PCI_CONFIG_WRITE:
    default:
        return firmware_status(IA64_FIRMWARE_STATUS_UNIMPLEMENTED);
    }
}

static void firmware_trace_call(CPUIA64State *env, const char *source,
                                const char *function, uint64_t function_id,
                                uint64_t arg0, uint64_t arg1,
                                uint64_t arg2,
                                IA64FirmwareResult result)
{
    const char *status = firmware_status_name(result.status);

    trace_ia64_firmware_call(env->ip, source, function, status, function_id,
                             arg0, arg1, result.ret0, result.ret1,
                             result.ret2);
    if (!efi_trace_enabled()) {
        return;
    }

    fprintf(stderr,
            "[ia64-firmware] ip=0x%016" PRIx64 " source=%s function=%s"
            " id=0x%016" PRIx64 " status=%s arg0=0x%016" PRIx64
            " arg1=0x%016" PRIx64 " arg2=0x%016" PRIx64
            " ret0=0x%016" PRIx64 " ret1=0x%016" PRIx64
            " ret2=0x%016" PRIx64 "\n",
            env->ip, source, function, function_id, status, arg0, arg1, arg2,
            result.ret0, result.ret1, result.ret2);
}

static void firmware_invalidate_result_alat(CPUIA64State *env)
{
    uint32_t valid_mask = env->alat.valid_mask;

    if (valid_mask == 0) {
        return;
    }

    for (unsigned i = 0; i < IA64_ALAT_COUNT; i++) {
        IA64AlatEntry *entry = &env->alat.entries[i];

        if ((valid_mask & (1u << i)) != 0 &&
            entry->target >= 8 && entry->target <= 11) {
            ia64_alat_set_valid(env, i, false);
        }
    }
}

static void firmware_write_result(CPUIA64State *env,
                                  IA64FirmwareResult result,
                                  bool stacked_return)
{
    env->gr[8] = result.status;
    env->gr[9] = result.ret0;
    env->gr[10] = result.ret1;
    env->gr[11] = result.ret2;
    firmware_invalidate_result_alat(env);
    env->gr[0] = 0;

    if (stacked_return) {
        ia64_return_from_call_frame(env, env->br[0]);
    } else {
        env->ip = env->br[0] & ~0xfULL;
        env->cr[IA64_CR_IIP] = env->ip;
    }
}

static void ia64_perf_count_pal_call(uint64_t function_id)
{
    static uint64_t reported_other[8];
    static unsigned reported_other_count;

    if (!ia64_perf_enabled()) {
        return;
    }

    switch (function_id) {
    case IA64_PAL_CACHE_FLUSH:
    case IA64_PAL_CACHE_INIT:
    case IA64_PAL_CACHE_LINE_INIT:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_CACHE_MAINT);
        break;
    case IA64_PAL_HALT:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_HALT);
        break;
    case IA64_PAL_HALT_LIGHT:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_HALT_LIGHT);
        break;
    case IA64_PAL_CACHE_INFO:
    case IA64_PAL_CACHE_SUMMARY:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_CACHE_INFO);
        break;
    case IA64_PAL_MEMORY_ATTRIBUTES:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_MEMORY_ATTRIBUTES);
        break;
    case IA64_PAL_PTCE_INFO:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_PTCE_INFO);
        break;
    case IA64_PAL_RSE_INFO:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_RSE_INFO);
        break;
    case IA64_PAL_VIRTUAL_MEMORY_INFO:
    case IA64_PAL_VIRTUAL_MEMORY_SUMMARY:
    case IA64_PAL_VIRTUAL_MEMORY_PAGE_SIZE:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_VM_PAGE_SIZE);
        break;
    case IA64_PAL_BUS_GET_FEATURES:
    case IA64_PAL_BUS_SET_FEATURES:
    case IA64_PAL_PROCESSOR_GET_FEATURES:
    case IA64_PAL_PROCESSOR_SET_FEATURES:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_FEATURES);
        break;
    case IA64_PAL_DEBUG_INFO:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_DEBUG);
        break;
    case IA64_PAL_FREQUENCY_BASE:
    case IA64_PAL_FREQUENCY_RATIOS:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_FREQUENCY);
        break;
    case IA64_PAL_PERFORMANCE_MONITOR_INFO:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_PERF_MONITOR);
        break;
    case IA64_PAL_FIXED_ADDRESS:
    case IA64_PAL_PLATFORM_ADDR:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_FIXED_PLATFORM);
        break;
    case IA64_PAL_VERSION_PROC:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_VERSION);
        break;
    case IA64_PAL_REGISTER_INFO:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_REGISTER_INFO);
        break;
    case IA64_PAL_PREFETCH_VISIBILITY:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_PREFETCH);
        break;
    case IA64_PAL_LOGICAL_TO_PHYSICAL:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_LOGICAL_TO_PHYSICAL);
        break;
    case IA64_PAL_CACHE_SHARED_INFO:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_CACHE_SHARED);
        break;
    case IA64_PAL_SHUTDOWN:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_SHUTDOWN);
        break;
    case IA64_PAL_COPY_PAL:
    case IA64_PAL_TEST_PROC:
    case IA64_PAL_CACHE_READ:
    case IA64_PAL_CACHE_WRITE:
    case IA64_PAL_VIRTUAL_MEMORY_TR_READ:
    case IA64_PAL_GET_PSTATE:
    case IA64_PAL_SET_PSTATE:
    case IA64_PAL_MACHINE_CHECK_ERROR_INJECT:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_OTHER);
        break;
    case IA64_PAL_HALT_INFO:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_HALT_INFO);
        break;
    case IA64_PAL_BRAND_INFO:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_BRAND);
        break;
    case IA64_PAL_MACHINE_CHECK_CLEAR_LOG:
    case IA64_PAL_MACHINE_CHECK_DRAIN:
    case IA64_PAL_MACHINE_CHECK_EXPECTED:
    case IA64_PAL_MACHINE_CHECK_DYNAMIC_STATE:
    case IA64_PAL_MACHINE_CHECK_REGISTER_MEMORY:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_MACHINE_CHECK);
        break;
    default:
        for (unsigned i = 0; i < reported_other_count; i++) {
            if (reported_other[i] == function_id) {
                goto count_other;
            }
        }
        if (reported_other_count < ARRAY_SIZE(reported_other)) {
            fprintf(stderr,
                    "[ia64-perf] firmware.pal.other_id.%u=0x%016" PRIx64
                    "\n",
                    reported_other_count, function_id);
            reported_other[reported_other_count++] = function_id;
        }
count_other:
        ia64_perf_count(IA64_PERF_FIRMWARE_PAL_OTHER);
        break;
    }
}

static bool dispatch_firmware_gate(CPUIA64State *env, uint64_t gate_ip)
{
    uint64_t physical;
    IA64FirmwareResult result;
    uint64_t function_id;
    uint64_t arg0;
    uint64_t arg1;
    uint64_t arg2;

    if (!efi_gate_address_is_valid_alias(gate_ip)) {
        return false;
    }
    physical = ia64_region_offset(gate_ip);

    if (physical == VIBTANIUM_EFI_PAL_PROC) {
        bool static_call;

        IA64_PERF_INC(IA64_PERF_FIRMWARE_PAL);
        function_id = ia64_read_gr(env, 28);
        static_call = pal_uses_static_calling_convention(function_id);
        if (static_call) {
            arg0 = ia64_read_gr(env, 29);
            arg1 = ia64_read_gr(env, 30);
            arg2 = ia64_read_gr(env, 31);
        } else {
            /*
             * PAL stacked calls copy arguments to out0-out3 before br.call;
             * at the gate they are visible as the callee's in0-in3.
             */
            function_id = ia64_read_gr(env, 32);
            arg0 = ia64_read_gr(env, 33);
            arg1 = ia64_read_gr(env, 34);
            arg2 = ia64_read_gr(env, 35);
        }
        ia64_perf_count_pal_call(function_id);
        result = dispatch_pal(env, function_id, arg0, arg1);
        firmware_trace_call(env, "pal", pal_procedure_name(function_id),
                            function_id, arg0, arg1, arg2, result);
        firmware_write_result(env, result, !static_call);
        return true;
    }

    if (physical == VIBTANIUM_EFI_SAL_PROC) {
        IA64_PERF_INC(IA64_PERF_FIRMWARE_SAL);
        function_id = ia64_read_gr(env, 32);
        arg0 = ia64_read_gr(env, 33);
        arg1 = ia64_read_gr(env, 34);
        arg2 = ia64_read_gr(env, 35);
        result = dispatch_sal(function_id);
        firmware_trace_call(env, "sal", sal_procedure_name(function_id),
                            function_id, arg0, arg1, arg2, result);
        firmware_write_result(env, result, true);
        return true;
    }

    return false;
}

static void efi_guest_stq(CPUIA64State *env, uint64_t address, uint64_t value)
{
    cpu_stq_le_data_ra(env, address, value, GETPC());
}

static void efi_guest_stl(CPUIA64State *env, uint64_t address, uint32_t value)
{
    cpu_stl_le_data_ra(env, address, value, GETPC());
}

static void efi_guest_stw(CPUIA64State *env, uint64_t address, uint16_t value)
{
    cpu_stw_le_data_ra(env, address, value, GETPC());
}

static void efi_guest_stb(CPUIA64State *env, uint64_t address, uint8_t value)
{
    cpu_stb_data_ra(env, address, value, GETPC());
}

static uint64_t efi_guest_ldq(CPUIA64State *env, uint64_t address)
{
    return cpu_ldq_le_data_ra(env, address, GETPC());
}

static uint8_t efi_guest_ldb(CPUIA64State *env, uint64_t address)
{
    return cpu_ldub_data_ra(env, address, GETPC());
}

static void efi_guest_read_bytes(CPUIA64State *env, uint64_t address,
                                 void *buffer, size_t size)
{
    uint8_t *bytes = buffer;

    for (size_t i = 0; i < size; i++) {
        bytes[i] = efi_guest_ldb(env, address + i);
    }
}

static void efi_guest_write_bytes(CPUIA64State *env, uint64_t address,
                                  const void *buffer, size_t size)
{
    const uint8_t *bytes = buffer;

    for (size_t i = 0; i < size; i++) {
        efi_guest_stb(env, address + i, bytes[i]);
    }
}

static bool efi_guid_bytes_equal(const uint8_t a[16], const uint8_t b[16])
{
    return memcmp(a, b, 16) == 0;
}

static void efi_guest_read_guid(CPUIA64State *env, uint64_t address,
                                uint8_t guid[16])
{
    efi_guest_read_bytes(env, address, guid, 16);
}

static uint32_t efi_crc32(const uint8_t *data, size_t size)
{
    uint32_t crc = 0xffffffff;

    for (size_t i = 0; i < size; i++) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; bit++) {
            crc = (crc & 1) ? (crc >> 1) ^ 0xedb88320U : crc >> 1;
        }
    }

    return ~crc;
}

static uint64_t efi_pool_alloc_raw(uint64_t size)
{
    uint64_t address = QEMU_ALIGN_UP(efi_pool_next, 16);
    uint64_t next = QEMU_ALIGN_UP(address + MAX(size, UINT64_C(1)), 16);

    if (next < address ||
        next > VIBTANIUM_EFI_POOL_BASE + VIBTANIUM_EFI_POOL_SIZE) {
        return 0;
    }

    efi_pool_next = next;
    return address;
}

static bool efi_page_range_end(uint64_t address, uint64_t pages,
                               uint64_t *end)
{
    uint64_t size;

    if (pages == 0 || address % EFI_PAGE_SIZE != 0 ||
        pages > UINT64_MAX / EFI_PAGE_SIZE) {
        return false;
    }

    size = pages * EFI_PAGE_SIZE;
    if (address > UINT64_MAX - size) {
        return false;
    }

    *end = address + size;
    return true;
}

static bool efi_page_range_in_region(uint64_t address, uint64_t pages,
                                     uint64_t base, uint64_t region_pages)
{
    uint64_t end;
    uint64_t region_end;

    if (!efi_page_range_end(address, pages, &end) ||
        !efi_page_range_end(base, region_pages, &region_end)) {
        return false;
    }

    return address >= base && end <= region_end;
}

static bool efi_page_ranges_overlap(uint64_t a, uint64_t a_pages,
                                    uint64_t b, uint64_t b_pages)
{
    uint64_t a_end;
    uint64_t b_end;

    if (!efi_page_range_end(a, a_pages, &a_end) ||
        !efi_page_range_end(b, b_pages, &b_end)) {
        return true;
    }

    return a < b_end && b < a_end;
}

static bool efi_page_range_usable(uint64_t address, uint64_t pages)
{
    if (efi_page_range_in_region(address, pages,
                                 EFI_PAGE_ALLOC_BASE,
                                 EFI_PAGE_ALLOC_SIZE / EFI_PAGE_SIZE)) {
        return true;
    }
    if (efi_page_range_in_region(address, pages,
                                 EFI_LOW_CONVENTIONAL_BASE,
                                 EFI_LOW_CONVENTIONAL_PAGES)) {
        return true;
    }
    return efi_page_range_in_region(address, pages,
                                    EFI_HIGH_CONVENTIONAL_BASE,
                                    EFI_HIGH_CONVENTIONAL_PAGES);
}

static bool efi_page_range_available(uint64_t address, uint64_t pages)
{
    uint64_t end;

    if (!efi_page_range_end(address, pages, &end) ||
        end > EFI_GUEST_RAM_TOP || !efi_page_range_usable(address, pages)) {
        return false;
    }

    for (unsigned i = 0; i < EFI_MAX_PAGE_ALLOCATIONS; i++) {
        EfiPageAllocation *alloc = &efi_page_allocations[i];

        if (alloc->in_use &&
            efi_page_ranges_overlap(address, pages,
                                    alloc->address, alloc->pages)) {
            return false;
        }
    }

    return true;
}

static bool efi_record_page_allocation(uint64_t address, uint64_t pages,
                                       uint32_t type)
{
    for (unsigned i = 0; i < EFI_MAX_PAGE_ALLOCATIONS; i++) {
        EfiPageAllocation *alloc = &efi_page_allocations[i];

        if (!alloc->in_use) {
            alloc->in_use = true;
            alloc->address = address;
            alloc->pages = pages;
            alloc->type = type;
            efi_memory_map_key++;
            return true;
        }
    }

    return false;
}

static bool efi_find_free_pages(uint64_t pages, uint64_t max_address,
                                uint64_t *address)
{
    static const struct {
        uint64_t base;
        uint64_t pages;
    } regions[] = {
        { EFI_PAGE_ALLOC_BASE, EFI_PAGE_ALLOC_SIZE / EFI_PAGE_SIZE },
        { EFI_HIGH_CONVENTIONAL_BASE, EFI_HIGH_CONVENTIONAL_PAGES },
        { EFI_LOW_CONVENTIONAL_BASE, EFI_LOW_CONVENTIONAL_PAGES },
    };
    uint64_t allocation_end;

    if (!efi_page_range_end(0, pages, &allocation_end)) {
        return false;
    }

    for (unsigned region = 0; region < ARRAY_SIZE(regions); region++) {
        uint64_t region_base = regions[region].base;
        uint64_t region_end = region_base + regions[region].pages * EFI_PAGE_SIZE;
        uint64_t limit_end = region_end;
        uint64_t cursor = region_base;

        if (region == 0) {
            cursor = MAX(QEMU_ALIGN_UP(efi_page_alloc_next, EFI_PAGE_SIZE),
                         region_base);
        }
        if (max_address < region_base) {
            continue;
        }
        if (max_address < region_end - 1) {
            limit_end = max_address + 1;
        }

        while (cursor <= limit_end &&
               allocation_end <= limit_end - cursor) {
            if (efi_page_range_available(cursor, pages)) {
                *address = cursor;
                if (region == 0) {
                    efi_page_alloc_next = cursor + allocation_end;
                }
                return true;
            }
            cursor += EFI_PAGE_SIZE;
        }
    }

    return false;
}

static uint64_t efi_allocate_pages(CPUIA64State *env)
{
    uint64_t allocate_type = ia64_read_gr(env, 32);
    uint64_t memory_type = ia64_read_gr(env, 33);
    uint64_t pages = ia64_read_gr(env, 34);
    uint64_t memory = ia64_read_gr(env, 35);
    uint64_t address;
    uint64_t max_address = EFI_GUEST_RAM_TOP - 1;

    if (memory == 0 || pages == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    switch (allocate_type) {
    case EFI_ALLOCATE_ANY_PAGES:
        if (!efi_find_free_pages(pages, max_address, &address)) {
            return VIBTANIUM_EFI_OUT_OF_RESOURCES;
        }
        break;
    case EFI_ALLOCATE_MAX_ADDRESS:
        max_address = efi_guest_ldq(env, memory);
        if (!efi_find_free_pages(pages, max_address, &address)) {
            efi_guest_stq(env, memory, 0);
            return VIBTANIUM_EFI_OUT_OF_RESOURCES;
        }
        break;
    case EFI_ALLOCATE_ADDRESS:
        address = efi_guest_ldq(env, memory);
        if (!efi_page_range_available(address, pages)) {
            return VIBTANIUM_EFI_NOT_FOUND;
        }
        break;
    default:
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    if (!efi_record_page_allocation(address, pages, memory_type)) {
        return VIBTANIUM_EFI_OUT_OF_RESOURCES;
    }
    efi_guest_stq(env, memory, address);
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_free_pages(CPUIA64State *env)
{
    uint64_t address = ia64_read_gr(env, 32);
    uint64_t pages = ia64_read_gr(env, 33);

    for (unsigned i = 0; i < EFI_MAX_PAGE_ALLOCATIONS; i++) {
        EfiPageAllocation *alloc = &efi_page_allocations[i];

        if (alloc->in_use && alloc->address == address &&
            alloc->pages == pages) {
            memset(alloc, 0, sizeof(*alloc));
            efi_memory_map_key++;
            return VIBTANIUM_EFI_SUCCESS;
        }
    }

    return VIBTANIUM_EFI_INVALID_PARAMETER;
}

static unsigned efi_emit_memory_descriptor(CPUIA64State *env, uint64_t map,
                                           unsigned index,
                                           const EfiMemoryRange *range)
{
    uint64_t descriptor;

    if (range->pages == 0) {
        return index;
    }

    if (map != 0) {
        descriptor = map + index * EFI_MEMORY_DESCRIPTOR_SIZE;
        efi_guest_stl(env, descriptor, range->type);
        efi_guest_stl(env, descriptor + 4, 0);
        efi_guest_stq(env, descriptor + 8, range->address);
        efi_guest_stq(env, descriptor + 16, 0);
        efi_guest_stq(env, descriptor + 24, range->pages);
        efi_guest_stq(env, descriptor + 32, range->attributes);
    }

    return index + 1;
}

static const EfiPageAllocation *efi_next_allocation_in_range(uint64_t cursor,
                                                            uint64_t end)
{
    const EfiPageAllocation *best = NULL;

    for (unsigned i = 0; i < EFI_MAX_PAGE_ALLOCATIONS; i++) {
        EfiPageAllocation *alloc = &efi_page_allocations[i];
        uint64_t alloc_end;

        if (!alloc->in_use ||
            !efi_page_range_end(alloc->address, alloc->pages, &alloc_end) ||
            alloc_end <= cursor || alloc->address >= end) {
            continue;
        }
        if (!best || alloc->address < best->address) {
            best = alloc;
        }
    }

    return best;
}

static unsigned efi_emit_split_conventional(CPUIA64State *env, uint64_t map,
                                            unsigned index, uint64_t base,
                                            uint64_t pages)
{
    uint64_t cursor = base;
    uint64_t end = base + pages * EFI_PAGE_SIZE;

    while (cursor < end) {
        const EfiPageAllocation *alloc =
            efi_next_allocation_in_range(cursor, end);
        uint64_t alloc_end;

        if (!alloc) {
            EfiMemoryRange conventional = {
                .type = EFI_CONVENTIONAL_MEMORY,
                .address = cursor,
                .pages = (end - cursor) / EFI_PAGE_SIZE,
                .attributes = EFI_MEMORY_WB,
            };
            return efi_emit_memory_descriptor(env, map, index,
                                              &conventional);
        }

        if (alloc->address > cursor) {
            EfiMemoryRange conventional = {
                .type = EFI_CONVENTIONAL_MEMORY,
                .address = cursor,
                .pages = (alloc->address - cursor) / EFI_PAGE_SIZE,
                .attributes = EFI_MEMORY_WB,
            };
            index = efi_emit_memory_descriptor(env, map, index,
                                               &conventional);
        }

        if (!efi_page_range_end(alloc->address, alloc->pages, &alloc_end)) {
            break;
        }
        if (alloc_end > end) {
            alloc_end = end;
        }
        if (alloc_end > cursor) {
            EfiMemoryRange allocation = {
                .type = alloc->type,
                .address = MAX(alloc->address, cursor),
                .pages = (alloc_end - MAX(alloc->address, cursor)) /
                         EFI_PAGE_SIZE,
                .attributes = EFI_MEMORY_WB,
            };
            index = efi_emit_memory_descriptor(env, map, index, &allocation);
            cursor = alloc_end;
        } else {
            cursor += EFI_PAGE_SIZE;
        }
    }

    return index;
}

static unsigned efi_emit_runtime_and_loader(CPUIA64State *env, uint64_t map,
                                            unsigned index,
                                            const EfiMemoryRange *runtime,
                                            const EfiMemoryRange *loader,
                                            bool *loader_emitted)
{
    uint64_t runtime_end;
    uint64_t loader_end;

    *loader_emitted = false;

    if (!efi_page_range_end(runtime->address, runtime->pages, &runtime_end) ||
        !efi_page_range_end(loader->address, loader->pages, &loader_end) ||
        loader->address >= runtime_end ||
        loader_end <= runtime->address) {
        return efi_emit_memory_descriptor(env, map, index, runtime);
    }

    if (runtime->address < loader->address) {
        EfiMemoryRange before = *runtime;

        before.pages = (loader->address - runtime->address) / EFI_PAGE_SIZE;
        index = efi_emit_memory_descriptor(env, map, index, &before);
    }

    index = efi_emit_memory_descriptor(env, map, index, loader);
    *loader_emitted = true;

    if (loader_end < runtime_end) {
        EfiMemoryRange after = *runtime;

        after.address = loader_end;
        after.pages = (runtime_end - loader_end) / EFI_PAGE_SIZE;
        index = efi_emit_memory_descriptor(env, map, index, &after);
    }

    return index;
}

static unsigned efi_emit_memory_map(CPUIA64State *env, uint64_t map)
{
    unsigned index = 0;
    bool loader_emitted;
    const EfiMemoryRange runtime_firmware = {
        .type = EFI_RUNTIME_SERVICES_DATA,
        .address = EFI_RUNTIME_GRANULE_BASE,
        .pages = EFI_RUNTIME_GRANULE_SIZE / EFI_PAGE_SIZE,
        .attributes = EFI_MEMORY_WB | EFI_MEMORY_RUNTIME,
    };
    const EfiMemoryRange loader_image = {
        .type = EFI_LOADER_CODE,
        .address = efi_loaded_image_base,
        .pages = efi_loaded_image_pages,
        .attributes = EFI_MEMORY_WB,
    };
    const EfiMemoryRange firmware_work = {
        .type = EFI_BOOT_SERVICES_DATA,
        .address = VIBTANIUM_EFI_STACK_BASE,
        .pages = 0x100,
        .attributes = EFI_MEMORY_WB,
    };
    const EfiMemoryRange pool = {
        .type = EFI_BOOT_SERVICES_DATA,
        .address = VIBTANIUM_EFI_POOL_BASE,
        .pages = VIBTANIUM_EFI_POOL_SIZE / EFI_PAGE_SIZE,
        .attributes = EFI_MEMORY_WB,
    };
    const EfiMemoryRange page_arena = {
        .type = EFI_BOOT_SERVICES_DATA,
        .address = EFI_PAGE_ALLOC_BASE,
        .pages = EFI_PAGE_ALLOC_SIZE / EFI_PAGE_SIZE,
        .attributes = EFI_MEMORY_WB,
    };
    const EfiMemoryRange linux_append = {
        .type = EFI_ACPI_RECLAIM_MEMORY,
        .address = EFI_LINUX_APPEND_BASE,
        .pages = EFI_LINUX_APPEND_SIZE / EFI_PAGE_SIZE,
        .attributes = EFI_MEMORY_WB,
    };
    const EfiMemoryRange io_port_space = {
        .type = EFI_MEMORY_MAPPED_IO_PORT_SPACE,
        .address = VIBTANIUM_IO_PORT_BASE,
        .pages = VIBTANIUM_IO_PORT_SIZE / EFI_PAGE_SIZE,
        .attributes = EFI_MEMORY_UC | EFI_MEMORY_RUNTIME,
    };

    index = efi_emit_runtime_and_loader(env, map, index, &runtime_firmware,
                                        &loader_image, &loader_emitted);
    index = efi_emit_split_conventional(env, map, index,
                                        EFI_LOW_CONVENTIONAL_BASE,
                                        EFI_LOW_CONVENTIONAL_PAGES);
    if (!loader_emitted) {
        index = efi_emit_memory_descriptor(env, map, index, &loader_image);
    }
    index = efi_emit_memory_descriptor(env, map, index, &firmware_work);
    index = efi_emit_memory_descriptor(env, map, index, &pool);
    index = efi_emit_memory_descriptor(env, map, index, &page_arena);
    index = efi_emit_memory_descriptor(env, map, index, &linux_append);
    index = efi_emit_split_conventional(env, map, index,
                                        EFI_HIGH_CONVENTIONAL_BASE,
                                        EFI_HIGH_CONVENTIONAL_PAGES);
    index = efi_emit_memory_descriptor(env, map, index, &io_port_space);
    return index;
}

void vibtanium_efi_register_loaded_image(uint64_t image_base,
                                         uint64_t image_size)
{
    uint64_t aligned_base;
    uint64_t image_end;
    uint64_t aligned_end;

    if (image_size == 0 || image_base > UINT64_MAX - image_size) {
        efi_loaded_image_base = VIBTANIUM_EFI_APP_BASE;
        efi_loaded_image_pages = EFI_DEFAULT_LOADER_IMAGE_PAGES;
        efi_memory_map_key++;
        return;
    }

    image_end = image_base + image_size;
    if (image_end > UINT64_MAX - (EFI_PAGE_SIZE - 1)) {
        efi_loaded_image_base = VIBTANIUM_EFI_APP_BASE;
        efi_loaded_image_pages = EFI_DEFAULT_LOADER_IMAGE_PAGES;
        efi_memory_map_key++;
        return;
    }

    aligned_base = image_base & ~(EFI_PAGE_SIZE - 1);
    aligned_end = QEMU_ALIGN_UP(image_end, EFI_PAGE_SIZE);
    if (image_base == VIBTANIUM_EFI_APP_BASE) {
        efi_loaded_image_base = VIBTANIUM_EFI_APP_BASE;
        efi_loaded_image_pages = EFI_DEFAULT_LOADER_IMAGE_PAGES;
    } else {
        efi_loaded_image_base = aligned_base;
        efi_loaded_image_pages = (aligned_end - aligned_base) / EFI_PAGE_SIZE;
    }
    efi_memory_map_key++;
}

static uint64_t efi_get_memory_map(CPUIA64State *env)
{
    uint64_t memory_map_size = ia64_read_gr(env, 32);
    uint64_t memory_map = ia64_read_gr(env, 33);
    uint64_t map_key = ia64_read_gr(env, 34);
    uint64_t descriptor_size = ia64_read_gr(env, 35);
    uint64_t descriptor_version = ia64_read_gr(env, 36);
    uint64_t provided = 0;
    uint64_t required = (uint64_t)efi_emit_memory_map(env, 0) *
                        EFI_MEMORY_DESCRIPTOR_SIZE;

    if (memory_map_size == 0 || map_key == 0 || descriptor_size == 0 ||
        descriptor_version == 0) {
        trace_ia64_efi_memory_map(env->ip, provided, required,
                                  efi_memory_map_key, "invalid-parameter");
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    provided = efi_guest_ldq(env, memory_map_size);
    efi_guest_stq(env, memory_map_size, required);
    efi_guest_stq(env, descriptor_size, EFI_MEMORY_DESCRIPTOR_SIZE);
    efi_guest_stl(env, descriptor_version, EFI_MEMORY_DESCRIPTOR_VERSION);

    if (memory_map == 0 || provided < required) {
        trace_ia64_efi_memory_map(env->ip, provided, required,
                                  efi_memory_map_key, "buffer-too-small");
        return VIBTANIUM_EFI_BUFFER_TOO_SMALL;
    }

    efi_emit_memory_map(env, memory_map);
    efi_guest_stq(env, map_key, efi_memory_map_key);
    trace_ia64_efi_memory_map(env->ip, provided, required,
                              efi_memory_map_key, "success");
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_exit_boot_services(CPUIA64State *env)
{
    uint64_t image_handle = ia64_read_gr(env, 32);
    uint64_t map_key = ia64_read_gr(env, 33);

    if (image_handle != VIBTANIUM_EFI_IMAGE_HANDLE ||
        map_key != efi_memory_map_key) {
        trace_ia64_efi_exit_boot_services(env->ip, image_handle, map_key,
                                          efi_memory_map_key,
                                          "invalid-parameter");
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    trace_ia64_efi_exit_boot_services(env->ip, image_handle, map_key,
                                      efi_memory_map_key, "success");
    return VIBTANIUM_EFI_SUCCESS;
}

void vibtanium_efi_register_boot_media(
    const VibtaniumEfiBlockDevice *boot_media)
{
    for (unsigned i = 0; i < EFI_MAX_FILE_HANDLES; i++) {
        g_clear_pointer(&efi_guest_files[i].data, g_free);
        memset(&efi_guest_files[i], 0, sizeof(efi_guest_files[i]));
    }
    memset(efi_installed_protocols, 0, sizeof(efi_installed_protocols));
    memset(efi_guest_events, 0, sizeof(efi_guest_events));
    memset(efi_page_allocations, 0, sizeof(efi_page_allocations));
    efi_pool_next = VIBTANIUM_EFI_POOL_BASE;
    efi_page_alloc_next = EFI_PAGE_ALLOC_BASE;
    efi_memory_map_key = 1;
    efi_dynamic_handle_next = UINT64_C(0x00073000);
    efi_next_event_handle = VIBTANIUM_EFI_CON_IN_WAIT_EVENT + 1;
    efi_loaded_image_base = VIBTANIUM_EFI_APP_BASE;
    efi_loaded_image_pages = EFI_DEFAULT_LOADER_IMAGE_PAGES;
    efi_high_monotonic_count = 0;
    efi_conin_enter_pending = true;

    g_clear_pointer(&efi_boot_media_name, g_free);
    memset(&efi_boot_media, 0, sizeof(efi_boot_media));
    efi_boot_media_valid = false;

    if (!boot_media) {
        return;
    }

    efi_boot_media = *boot_media;
    efi_boot_media_name = g_strdup(boot_media->name);
    efi_boot_media.name = efi_boot_media_name;
    efi_boot_media_valid = boot_media->read != NULL;
}

static uint64_t efi_preinstalled_interface(uint64_t handle,
                                           const uint8_t guid[16])
{
    if (handle == VIBTANIUM_EFI_IMAGE_HANDLE &&
        efi_guid_bytes_equal(guid, efi_loaded_image_guid)) {
        return VIBTANIUM_EFI_LOADED_IMAGE;
    }

    if (handle != VIBTANIUM_EFI_BOOT_DEVICE_HANDLE) {
        return 0;
    }

    if (efi_guid_bytes_equal(guid, efi_simple_text_output_guid)) {
        return VIBTANIUM_EFI_CON_OUT;
    }
    if (efi_guid_bytes_equal(guid, efi_simple_text_input_guid)) {
        return VIBTANIUM_EFI_CON_IN;
    }
    if (efi_guid_bytes_equal(guid, efi_device_path_guid)) {
        return VIBTANIUM_EFI_DEVICE_PATH;
    }
    if (efi_boot_media_valid && efi_guid_bytes_equal(guid, efi_block_io_guid)) {
        return VIBTANIUM_EFI_BLOCK_IO;
    }
    if (efi_boot_media_valid &&
        efi_guid_bytes_equal(guid, efi_simple_file_system_guid)) {
        return VIBTANIUM_EFI_SIMPLE_FILE_SYSTEM;
    }

    return 0;
}

static EfiInstalledProtocol *efi_find_installed_protocol(uint64_t handle,
                                                         const uint8_t guid[16])
{
    for (unsigned i = 0; i < EFI_MAX_INSTALLED_PROTOCOLS; i++) {
        if (efi_installed_protocols[i].in_use &&
            efi_installed_protocols[i].handle == handle &&
            efi_guid_bytes_equal(efi_installed_protocols[i].guid, guid)) {
            return &efi_installed_protocols[i];
        }
    }
    return NULL;
}

static uint64_t efi_resolve_interface(uint64_t handle, const uint8_t guid[16],
                                      uint64_t *interface)
{
    EfiInstalledProtocol *installed;
    uint64_t preinstalled = efi_preinstalled_interface(handle, guid);

    if (preinstalled != 0) {
        *interface = preinstalled;
        return VIBTANIUM_EFI_SUCCESS;
    }

    installed = efi_find_installed_protocol(handle, guid);
    if (installed) {
        *interface = installed->interface;
        return VIBTANIUM_EFI_SUCCESS;
    }

    *interface = 0;
    return VIBTANIUM_EFI_NOT_FOUND;
}

static uint64_t efi_handle_protocol(CPUIA64State *env)
{
    uint64_t handle = ia64_read_gr(env, 32);
    uint64_t protocol = ia64_read_gr(env, 33);
    uint64_t interface = ia64_read_gr(env, 34);
    uint8_t guid[16];
    uint64_t interface_address;
    uint64_t status;

    if (protocol == 0 || interface == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    efi_guest_read_guid(env, protocol, guid);
    status = efi_resolve_interface(handle, guid, &interface_address);
    if (status == VIBTANIUM_EFI_SUCCESS) {
        efi_guest_stq(env, interface, interface_address);
        return status;
    }

    efi_guest_stq(env, interface, 0);
    return status;
}

static bool efi_add_unique_handle(uint64_t *handles, unsigned capacity,
                                  unsigned *count, uint64_t handle)
{
    for (unsigned i = 0; i < *count; i++) {
        if (handles[i] == handle) {
            return true;
        }
    }

    if (*count < capacity) {
        handles[*count] = handle;
    }
    (*count)++;
    return *count <= capacity;
}

static unsigned efi_locate_handles_for_protocol(CPUIA64State *env,
                                                uint64_t protocol,
                                                uint64_t *handles,
                                                unsigned capacity)
{
    uint8_t guid[16];
    unsigned count = 0;

    efi_guest_read_guid(env, protocol, guid);

    if (efi_guid_bytes_equal(guid, efi_loaded_image_guid)) {
        efi_add_unique_handle(handles, capacity, &count,
                              VIBTANIUM_EFI_IMAGE_HANDLE);
    }

    if (efi_guid_bytes_equal(guid, efi_simple_text_output_guid) ||
        efi_guid_bytes_equal(guid, efi_simple_text_input_guid) ||
        efi_guid_bytes_equal(guid, efi_device_path_guid) ||
        (efi_boot_media_valid &&
         (efi_guid_bytes_equal(guid, efi_block_io_guid) ||
          efi_guid_bytes_equal(guid, efi_simple_file_system_guid)))) {
        efi_add_unique_handle(handles, capacity, &count,
                              VIBTANIUM_EFI_BOOT_DEVICE_HANDLE);
    }

    for (unsigned i = 0; i < EFI_MAX_INSTALLED_PROTOCOLS; i++) {
        if (efi_installed_protocols[i].in_use &&
            efi_guid_bytes_equal(efi_installed_protocols[i].guid, guid)) {
            efi_add_unique_handle(handles, capacity, &count,
                                  efi_installed_protocols[i].handle);
        }
    }

    return count;
}

static uint64_t efi_locate_handle(CPUIA64State *env)
{
    uint64_t search_type = ia64_read_gr(env, 32);
    uint64_t protocol = ia64_read_gr(env, 33);
    uint64_t size_ptr = ia64_read_gr(env, 35);
    uint64_t buffer = ia64_read_gr(env, 36);
    uint64_t handles[4];
    unsigned count;
    uint64_t required;
    uint64_t provided;

    if (search_type != 2 || protocol == 0 || size_ptr == 0) {
        return VIBTANIUM_EFI_UNSUPPORTED;
    }

    count = efi_locate_handles_for_protocol(env, protocol, handles,
                                            ARRAY_SIZE(handles));
    required = count * sizeof(uint64_t);
    provided = efi_guest_ldq(env, size_ptr);
    efi_guest_stq(env, size_ptr, required);
    if (count == 0) {
        return VIBTANIUM_EFI_NOT_FOUND;
    }

    if (buffer == 0 || provided < required) {
        return VIBTANIUM_EFI_BUFFER_TOO_SMALL;
    }

    for (unsigned i = 0; i < count; i++) {
        efi_guest_stq(env, buffer + i * sizeof(uint64_t), handles[i]);
    }
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_install_protocol_interface(CPUIA64State *env)
{
    uint64_t handle_ptr = ia64_read_gr(env, 32);
    uint64_t protocol = ia64_read_gr(env, 33);
    uint64_t interface_type = ia64_read_gr(env, 34);
    uint64_t interface = ia64_read_gr(env, 35);
    uint64_t handle;
    uint8_t guid[16];

    if (handle_ptr == 0 || protocol == 0 || interface == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    handle = efi_guest_ldq(env, handle_ptr);
    if (handle == 0) {
        handle = efi_dynamic_handle_next++;
        efi_guest_stq(env, handle_ptr, handle);
    }
    efi_guest_read_guid(env, protocol, guid);
    if (efi_preinstalled_interface(handle, guid) != 0 ||
        efi_find_installed_protocol(handle, guid) != NULL) {
        return VIBTANIUM_EFI_ACCESS_DENIED;
    }

    for (unsigned i = 0; i < EFI_MAX_INSTALLED_PROTOCOLS; i++) {
        if (!efi_installed_protocols[i].in_use) {
            efi_installed_protocols[i].in_use = true;
            efi_installed_protocols[i].handle = handle;
            memcpy(efi_installed_protocols[i].guid, guid, sizeof(guid));
            efi_installed_protocols[i].interface = interface;
            (void)interface_type;
            return VIBTANIUM_EFI_SUCCESS;
        }
    }

    return VIBTANIUM_EFI_OUT_OF_RESOURCES;
}

static uint64_t efi_uninstall_protocol_interface(CPUIA64State *env)
{
    uint64_t handle = ia64_read_gr(env, 32);
    uint64_t protocol = ia64_read_gr(env, 33);
    uint64_t interface = ia64_read_gr(env, 34);
    uint8_t guid[16];
    EfiInstalledProtocol *installed;

    if (handle == 0 || protocol == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    efi_guest_read_guid(env, protocol, guid);
    installed = efi_find_installed_protocol(handle, guid);
    if (!installed || (interface != 0 && installed->interface != interface)) {
        return VIBTANIUM_EFI_NOT_FOUND;
    }

    memset(installed, 0, sizeof(*installed));
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_locate_protocol(CPUIA64State *env)
{
    uint64_t protocol = ia64_read_gr(env, 32);
    uint64_t interface = ia64_read_gr(env, 34);
    uint64_t handles[8];
    unsigned count;

    if (protocol == 0 || interface == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    count = efi_locate_handles_for_protocol(env, protocol, handles,
                                            ARRAY_SIZE(handles));
    if (count == 0) {
        efi_guest_stq(env, interface, 0);
        return VIBTANIUM_EFI_NOT_FOUND;
    }

    ia64_write_gr(env, 32, handles[0]);
    ia64_write_gr(env, 33, protocol);
    ia64_write_gr(env, 34, interface);
    return efi_handle_protocol(env);
}

static uint64_t efi_close_protocol(CPUIA64State *env)
{
    uint64_t handle = ia64_read_gr(env, 32);
    uint64_t protocol = ia64_read_gr(env, 33);
    uint8_t guid[16];
    uint64_t interface_address;

    if (handle == 0 || protocol == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    efi_guest_read_guid(env, protocol, guid);
    return efi_resolve_interface(handle, guid, &interface_address);
}

static uint64_t efi_calculate_crc32(CPUIA64State *env)
{
    uint64_t data = ia64_read_gr(env, 32);
    uint64_t size = ia64_read_gr(env, 33);
    uint64_t crc_ptr = ia64_read_gr(env, 34);
    g_autofree uint8_t *bytes = NULL;

    if (data == 0 || crc_ptr == 0 || size > EFI_MAX_FILE_READ_BYTES) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    bytes = g_malloc(size ? size : 1);
    efi_guest_read_bytes(env, data, bytes, size);
    efi_guest_stl(env, crc_ptr, efi_crc32(bytes, size));
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_copy_mem(CPUIA64State *env)
{
    uint64_t destination = ia64_read_gr(env, 32);
    uint64_t source = ia64_read_gr(env, 33);
    uint64_t length = ia64_read_gr(env, 34);
    g_autofree uint8_t *bytes = NULL;

    if (length > EFI_MAX_FILE_READ_BYTES) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    bytes = g_malloc(length ? length : 1);
    efi_guest_read_bytes(env, source, bytes, length);
    efi_guest_write_bytes(env, destination, bytes, length);
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_set_mem(CPUIA64State *env)
{
    uint64_t buffer = ia64_read_gr(env, 32);
    uint64_t size = ia64_read_gr(env, 33);
    uint8_t value = ia64_read_gr(env, 34);

    if (size > EFI_MAX_FILE_READ_BYTES) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    for (uint64_t i = 0; i < size; i++) {
        efi_guest_stb(env, buffer + i, value);
    }
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_allocate_pool(CPUIA64State *env)
{
    uint64_t size = ia64_read_gr(env, 33);
    uint64_t buffer = ia64_read_gr(env, 34);
    uint64_t address;

    if (buffer == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    address = efi_pool_alloc_raw(size);
    if (address == 0) {
        efi_guest_stq(env, buffer, 0);
        return VIBTANIUM_EFI_OUT_OF_RESOURCES;
    }

    efi_guest_stq(env, buffer, address);
    return VIBTANIUM_EFI_SUCCESS;
}

static void efi_write_file_protocol(CPUIA64State *env, uint64_t address)
{
    efi_guest_stq(env, address, VIBTANIUM_EFI_PROTOCOL_REVISION);
    for (unsigned i = 0; i < VIBTANIUM_EFI_FILE_SERVICE_COUNT; i++) {
        efi_guest_stq(env, address + 8 + i * sizeof(uint64_t),
                      VIBTANIUM_EFI_DESCRIPTOR_BASE +
                      (EFI_FILE_SERVICE_BASE + i) * IA64_BUNDLE_SIZE);
    }
}

static EfiGuestFile *efi_find_file(uint64_t address)
{
    for (unsigned i = 0; i < EFI_MAX_FILE_HANDLES; i++) {
        if (efi_guest_files[i].in_use && efi_guest_files[i].address == address) {
            return &efi_guest_files[i];
        }
    }
    return NULL;
}

static EfiGuestFile *efi_create_file_node(CPUIA64State *env, const char *path,
                                          bool is_directory, uint8_t *data,
                                          size_t size)
{
    uint64_t address = efi_pool_alloc_raw(8 + 10 * sizeof(uint64_t));

    if (address == 0) {
        g_free(data);
        return NULL;
    }

    for (unsigned i = 0; i < EFI_MAX_FILE_HANDLES; i++) {
        EfiGuestFile *file = &efi_guest_files[i];

        if (file->in_use) {
            continue;
        }

        memset(file, 0, sizeof(*file));
        file->in_use = true;
        file->address = address;
        file->is_directory = is_directory;
        g_strlcpy(file->path, path ? path : "", sizeof(file->path));
        file->data = data;
        file->size = size;
        efi_write_file_protocol(env, address);
        return file;
    }

    g_free(data);
    return NULL;
}

static uint64_t efi_storage_status_to_efi(VibtaniumEfiStorageStatus status)
{
    switch (status) {
    case VIBTANIUM_EFI_STORAGE_OK:
        return VIBTANIUM_EFI_SUCCESS;
    case VIBTANIUM_EFI_STORAGE_READ_ERROR:
    case VIBTANIUM_EFI_STORAGE_INVALID_FILESYSTEM:
        return VIBTANIUM_EFI_DEVICE_ERROR;
    case VIBTANIUM_EFI_STORAGE_UNSUPPORTED:
        return VIBTANIUM_EFI_UNSUPPORTED;
    case VIBTANIUM_EFI_STORAGE_NO_ISO9660:
    case VIBTANIUM_EFI_STORAGE_NOT_FOUND:
    default:
        return VIBTANIUM_EFI_NOT_FOUND;
    }
}

static void efi_read_utf16_path(CPUIA64State *env, uint64_t address,
                                char *out, size_t out_size)
{
    size_t n = 0;

    if (out_size == 0) {
        return;
    }

    for (unsigned i = 0; i < EFI_MAX_PATH_CHARS - 1 && n + 1 < out_size; i++) {
        uint16_t ch = cpu_lduw_le_data_ra(env, address + i * 2, GETPC());

        if (ch == 0) {
            break;
        }
        if (ch == '\\') {
            out[n++] = '/';
        } else if (ch < 0x80) {
            out[n++] = ch;
        } else {
            out[n++] = '?';
        }
    }
    out[n] = '\0';
}

static void efi_join_normalized_path(const char *base, const char *name,
                                     char *out, size_t out_size)
{
    char combined[EFI_MAX_PATH_CHARS * 2];
    char **parts;
    size_t out_len = 0;

    if (out_size == 0) {
        return;
    }
    out[0] = '\0';

    if (!name || name[0] == '\0') {
        g_strlcpy(combined, base ? base : "", sizeof(combined));
    } else if (name[0] == '/') {
        g_strlcpy(combined, name, sizeof(combined));
    } else if (base && base[0] != '\0') {
        g_snprintf(combined, sizeof(combined), "%s/%s", base, name);
    } else {
        g_strlcpy(combined, name, sizeof(combined));
    }

    parts = g_strsplit(combined, "/", -1);
    for (char **part = parts; *part; part++) {
        if ((*part)[0] == '\0' || g_strcmp0(*part, ".") == 0) {
            continue;
        }
        if (g_strcmp0(*part, "..") == 0) {
            char *slash = strrchr(out, '/');

            if (slash) {
                *slash = '\0';
                out_len = strlen(out);
            } else {
                out[0] = '\0';
                out_len = 0;
            }
            continue;
        }
        if (out_len != 0 && out_len + 1 < out_size) {
            out[out_len++] = '/';
            out[out_len] = '\0';
        }
        g_strlcpy(out + out_len, *part, out_size - out_len);
        out_len = strlen(out);
    }
    g_strfreev(parts);
}

static const char *efi_file_base_name(const char *path)
{
    const char *slash;

    if (!path || path[0] == '\0') {
        return "\\";
    }

    slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static void efi_write_utf16_ascii(CPUIA64State *env, uint64_t address,
                                  const char *text)
{
    while (*text) {
        efi_guest_stw(env, address, (uint8_t)*text++);
        address += 2;
    }
    efi_guest_stw(env, address, 0);
}

static uint64_t efi_simplefs_open_volume(CPUIA64State *env)
{
    uint64_t this_ptr = ia64_read_gr(env, 32);
    uint64_t root_out = ia64_read_gr(env, 33);
    EfiGuestFile *root;

    if (this_ptr != VIBTANIUM_EFI_SIMPLE_FILE_SYSTEM || root_out == 0 ||
        !efi_boot_media_valid) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    root = efi_create_file_node(env, "", true, NULL, 0);
    if (!root) {
        return VIBTANIUM_EFI_OUT_OF_RESOURCES;
    }

    efi_guest_stq(env, root_out, root->address);
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_file_open(CPUIA64State *env)
{
    uint64_t this_ptr = ia64_read_gr(env, 32);
    uint64_t new_handle_out = ia64_read_gr(env, 33);
    uint64_t name_ptr = ia64_read_gr(env, 34);
    uint64_t open_mode = ia64_read_gr(env, 35);
    EfiGuestFile *parent = efi_find_file(this_ptr);
    char name[EFI_MAX_PATH_CHARS];
    char path[EFI_MAX_PATH_CHARS];
    char storage_path[EFI_MAX_PATH_CHARS + 2];
    Error *local_err = NULL;
    VibtaniumEfiStorageReport report = {
        .status = VIBTANIUM_EFI_STORAGE_NOT_FOUND,
        .message = "path has not been opened",
    };
    VibtaniumEfiFile storage_file;
    g_autofree char *source = g_malloc0(384);
    uint8_t *data = NULL;
    size_t size = 0;
    EfiGuestFile *file;

    if (!parent || new_handle_out == 0 || name_ptr == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }
    if ((open_mode & UINT64_C(0x2)) != 0) {
        return VIBTANIUM_EFI_WRITE_PROTECTED;
    }

    efi_read_utf16_path(env, name_ptr, name, sizeof(name));
    efi_join_normalized_path(parent->path, name, path, sizeof(path));
    g_snprintf(storage_path, sizeof(storage_path), "/%s", path);
    trace_ia64_efi_file_open_request(env->ip, this_ptr, new_handle_out, name,
                                     open_mode, parent->path, storage_path);

    efi_guest_stq(env, new_handle_out, 0);
    if (efi_trace_enabled()) {
        fprintf(stderr,
                "[efi-file] open request this=0x%016" PRIx64
                " out=0x%016" PRIx64 " name='%s' mode=0x%" PRIx64
                " parent='%s' path='%s'\n",
                this_ptr, new_handle_out, name, open_mode, parent->path,
                storage_path);
    }

    if (!efi_boot_media_valid) {
        return VIBTANIUM_EFI_NOT_FOUND;
    }

    if (vibtanium_efi_iso9660_find_path(&efi_boot_media, storage_path,
                                        &storage_file, &report,
                                        &local_err)) {
        if (storage_file.is_directory) {
            file = efi_create_file_node(env, path, true, NULL, 0);
            if (!file) {
                return VIBTANIUM_EFI_OUT_OF_RESOURCES;
            }

            efi_guest_stq(env, new_handle_out, file->address);
            trace_ia64_efi_file_open_result(env->ip, storage_path,
                                            "success-directory",
                                            file->address, 0, "directory");
            if (efi_trace_enabled()) {
                fprintf(stderr, "[efi-file] open dir='%s' handle=0x%016"
                        PRIx64 "\n",
                        path, file->address);
            }
            return VIBTANIUM_EFI_SUCCESS;
        }

        if (vibtanium_efi_iso9660_read_file(&efi_boot_media, &storage_file,
                                            &data, &size, &report,
                                            &local_err)) {
            g_snprintf(source, 384, "%s:%s",
                       efi_boot_media.name ? efi_boot_media.name : "<unnamed>",
                       storage_path);
        }
    }
    error_free(local_err);
    local_err = NULL;

    if (!data &&
        !vibtanium_efi_cdrom_read_path(&efi_boot_media, storage_path, &data,
                                       &size, source, 384, &report,
                                       &local_err)) {
        uint64_t status = efi_storage_status_to_efi(report.status);

        trace_ia64_efi_file_open_result(
            env->ip, storage_path, vibtanium_efi_storage_status_name(report.status),
            0, 0, report.message);
        if (efi_trace_enabled()) {
            fprintf(stderr, "[efi-file] open path='%s' status=%s\n",
                    storage_path,
                    vibtanium_efi_storage_status_name(report.status));
        }
        error_free(local_err);
        return status;
    }

    if (efi_trace_enabled()) {
        fprintf(stderr, "[efi-file] open path='%s' size=0x%" PRIx64
                " source=%s\n",
                storage_path, (uint64_t)size, source);
    }

    file = efi_create_file_node(env, path, false, data, size);
    if (!file) {
        efi_guest_stq(env, new_handle_out, 0);
        return VIBTANIUM_EFI_OUT_OF_RESOURCES;
    }

    efi_guest_stq(env, new_handle_out, file->address);
    trace_ia64_efi_file_open_result(env->ip, storage_path, "success",
                                    file->address, size, source);
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_file_close(CPUIA64State *env)
{
    EfiGuestFile *file = efi_find_file(ia64_read_gr(env, 32));

    if (file) {
        g_clear_pointer(&file->data, g_free);
        memset(file, 0, sizeof(*file));
    }
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_file_read(CPUIA64State *env)
{
    EfiGuestFile *file = efi_find_file(ia64_read_gr(env, 32));
    uint64_t size_ptr = ia64_read_gr(env, 33);
    uint64_t buffer = ia64_read_gr(env, 34);
    uint64_t requested;
    uint64_t remaining;
    uint64_t actual;

    if (!file || size_ptr == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }
    if (file->is_directory) {
        return VIBTANIUM_EFI_UNSUPPORTED;
    }

    requested = efi_guest_ldq(env, size_ptr);
    if (requested > EFI_MAX_FILE_READ_BYTES) {
        requested = EFI_MAX_FILE_READ_BYTES;
    }
    remaining = file->position < file->size ? file->size - file->position : 0;
    actual = MIN(requested, remaining);
    if (actual > 0) {
        if (buffer == 0) {
            return VIBTANIUM_EFI_INVALID_PARAMETER;
        }
        efi_guest_write_bytes(env, buffer, file->data + file->position,
                              actual);
        file->position += actual;
    }
    if (efi_trace_enabled()) {
        fprintf(stderr, "[efi-file] read path='%s' requested=0x%" PRIx64
                " actual=0x%" PRIx64 " position=0x%" PRIx64 "\n",
                file->path, requested, actual, file->position);
    }
    trace_ia64_efi_file_read(env->ip, file->path, requested, actual,
                             file->position);
    efi_guest_stq(env, size_ptr, actual);
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_file_get_position(CPUIA64State *env)
{
    EfiGuestFile *file = efi_find_file(ia64_read_gr(env, 32));
    uint64_t pos_out = ia64_read_gr(env, 33);

    if (!file || pos_out == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }
    if (file->is_directory) {
        return VIBTANIUM_EFI_UNSUPPORTED;
    }
    efi_guest_stq(env, pos_out, file->position);
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_file_set_position(CPUIA64State *env)
{
    EfiGuestFile *file = efi_find_file(ia64_read_gr(env, 32));
    uint64_t position = ia64_read_gr(env, 33);

    if (!file) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }
    if (file->is_directory) {
        return position == 0 ? VIBTANIUM_EFI_SUCCESS
                             : VIBTANIUM_EFI_UNSUPPORTED;
    }
    if (position == UINT64_MAX) {
        position = file->size;
    }
    if (position > file->size) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }
    file->position = position;
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_file_get_info(CPUIA64State *env)
{
    EfiGuestFile *file = efi_find_file(ia64_read_gr(env, 32));
    uint64_t info_type = ia64_read_gr(env, 33);
    uint64_t size_ptr = ia64_read_gr(env, 34);
    uint64_t buffer = ia64_read_gr(env, 35);
    uint8_t guid[16];
    const char *name;
    uint64_t name_bytes;
    uint64_t required;
    uint64_t provided;

    if (!file || info_type == 0 || size_ptr == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    efi_guest_read_guid(env, info_type, guid);
    if (!efi_guid_bytes_equal(guid, efi_file_info_guid)) {
        return VIBTANIUM_EFI_UNSUPPORTED;
    }

    name = efi_file_base_name(file->path);
    name_bytes = (strlen(name) + 1) * 2;
    required = 80 + name_bytes;
    provided = efi_guest_ldq(env, size_ptr);
    efi_guest_stq(env, size_ptr, required);
    if (buffer == 0 || provided < required) {
        return VIBTANIUM_EFI_BUFFER_TOO_SMALL;
    }

    for (uint64_t i = 0; i < required; i++) {
        efi_guest_stb(env, buffer + i, 0);
    }
    efi_guest_stq(env, buffer, required);
    efi_guest_stq(env, buffer + 8, file->size);
    efi_guest_stq(env, buffer + 16, file->size);
    efi_guest_stq(env, buffer + 72, file->is_directory ? 0x10 : 0x1);
    efi_write_utf16_ascii(env, buffer + 80, name);
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_dispatch_file(CPUIA64State *env, unsigned index)
{
    switch (index) {
    case 0:
        return efi_file_open(env);
    case 1:
        return efi_file_close(env);
    case 2:
        efi_file_close(env);
        return VIBTANIUM_EFI_WRITE_PROTECTED;
    case 3:
        return efi_file_read(env);
    case 4:
        return VIBTANIUM_EFI_WRITE_PROTECTED;
    case 5:
        return efi_file_get_position(env);
    case 6:
        return efi_file_set_position(env);
    case 7:
        return efi_file_get_info(env);
    case 8:
        return VIBTANIUM_EFI_WRITE_PROTECTED;
    case 9:
        return VIBTANIUM_EFI_SUCCESS;
    default:
        return VIBTANIUM_EFI_UNSUPPORTED;
    }
}

static uint64_t efi_dispatch_simple_file_system(CPUIA64State *env,
                                                unsigned index)
{
    switch (index) {
    case 0:
        return efi_simplefs_open_volume(env);
    default:
        return VIBTANIUM_EFI_UNSUPPORTED;
    }
}

static uint64_t efi_dispatch_block_io(CPUIA64State *env, unsigned index)
{
    uint64_t this_ptr = ia64_read_gr(env, 32);
    uint32_t block_size = efi_boot_media.block_size
        ? efi_boot_media.block_size
        : 2048;

    if (this_ptr != VIBTANIUM_EFI_BLOCK_IO || !efi_boot_media_valid) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    switch (index) {
    case 0:
        return VIBTANIUM_EFI_SUCCESS;
    case 1: {
        uint64_t media_id = ia64_read_gr(env, 33);
        uint64_t lba = ia64_read_gr(env, 34);
        uint64_t buffer_size = ia64_read_gr(env, 35);
        uint64_t buffer = ia64_read_gr(env, 36);
        uint64_t offset = lba * block_size;
        Error *local_err = NULL;
        g_autofree uint8_t *data = NULL;
        int ret;

        if (media_id != 1 || buffer_size > EFI_MAX_FILE_READ_BYTES ||
            (buffer_size != 0 && buffer == 0) ||
            (block_size != 0 && (buffer_size % block_size) != 0) ||
            (lba != 0 && offset / lba != block_size)) {
            return VIBTANIUM_EFI_INVALID_PARAMETER;
        }
        data = g_malloc(buffer_size ? buffer_size : 1);
        ret = efi_boot_media.read(efi_boot_media.opaque, offset, buffer_size,
                                  data, &local_err);
        if (ret < 0) {
            error_free(local_err);
            return VIBTANIUM_EFI_DEVICE_ERROR;
        }
        if (buffer_size != 0) {
            efi_guest_write_bytes(env, buffer, data, buffer_size);
        }
        return VIBTANIUM_EFI_SUCCESS;
    }
    case 2:
        return VIBTANIUM_EFI_WRITE_PROTECTED;
    case 3:
        return VIBTANIUM_EFI_SUCCESS;
    default:
        return VIBTANIUM_EFI_UNSUPPORTED;
    }
}

static EfiGuestEvent *efi_find_event(uint64_t handle)
{
    if (handle == VIBTANIUM_EFI_CON_IN_WAIT_EVENT) {
        static EfiGuestEvent conin_event;

        conin_event = (EfiGuestEvent) {
            .in_use = true,
            .handle = VIBTANIUM_EFI_CON_IN_WAIT_EVENT,
            .type = 0,
            .signaled = efi_conin_enter_pending,
            .timer_active = false,
        };
        return &conin_event;
    }

    for (unsigned i = 0; i < EFI_MAX_EVENTS; i++) {
        if (efi_guest_events[i].in_use &&
            efi_guest_events[i].handle == handle) {
            return &efi_guest_events[i];
        }
    }
    return NULL;
}

static uint64_t efi_create_event(CPUIA64State *env)
{
    uint64_t raw_type = ia64_read_gr(env, 32);
    uint64_t event_out = ia64_read_gr(env, 36);
    uint32_t type;

    if (!vibtanium_efi_decode_uint32_arg(raw_type, &type) ||
        event_out == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    for (unsigned i = 0; i < EFI_MAX_EVENTS; i++) {
        EfiGuestEvent *event = &efi_guest_events[i];

        if (event->in_use) {
            continue;
        }

        memset(event, 0, sizeof(*event));
        event->in_use = true;
        event->handle = efi_next_event_handle++;
        event->type = type;
        efi_guest_stq(env, event_out, event->handle);
        return VIBTANIUM_EFI_SUCCESS;
    }

    efi_guest_stq(env, event_out, 0);
    return VIBTANIUM_EFI_OUT_OF_RESOURCES;
}

static uint64_t efi_set_timer(CPUIA64State *env)
{
    uint64_t handle = ia64_read_gr(env, 32);
    uint64_t timer_type = ia64_read_gr(env, 33);
    uint64_t trigger_time = ia64_read_gr(env, 34);
    EfiGuestEvent *event = efi_find_event(handle);

    if (!event || handle == VIBTANIUM_EFI_CON_IN_WAIT_EVENT) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    switch (timer_type) {
    case EFI_TIMER_CANCEL:
        event->timer_active = false;
        event->timer_periodic = false;
        event->timer_period = 0;
        event->timer_due = 0;
        event->signaled = false;
        return VIBTANIUM_EFI_SUCCESS;
    case EFI_TIMER_PERIODIC:
    case EFI_TIMER_RELATIVE:
        event->timer_active = true;
        event->timer_periodic = timer_type == EFI_TIMER_PERIODIC;
        event->timer_period = trigger_time;
        event->timer_due = env->ar[IA64_AR_ITC] + trigger_time;
        event->signaled = trigger_time == 0;
        return VIBTANIUM_EFI_SUCCESS;
    default:
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }
}

static bool efi_event_timer_due(CPUIA64State *env, EfiGuestEvent *event)
{
    return event->timer_active &&
           vibtanium_efi_timer_due(env->ar[IA64_AR_ITC], event->timer_due);
}

static void efi_event_consume(CPUIA64State *env, EfiGuestEvent *event)
{
    if (!event || event->handle == VIBTANIUM_EFI_CON_IN_WAIT_EVENT) {
        return;
    }

    if (efi_event_timer_due(env, event)) {
        if (event->timer_periodic && event->timer_period != 0) {
            do {
                event->timer_due += event->timer_period;
            } while (vibtanium_efi_timer_due(env->ar[IA64_AR_ITC],
                                             event->timer_due));
        } else {
            event->timer_active = false;
            event->timer_periodic = false;
            event->timer_period = 0;
            event->timer_due = 0;
        }
    }
    event->signaled = false;
}

static bool efi_event_is_ready(CPUIA64State *env, EfiGuestEvent *event)
{
    if (!event) {
        return false;
    }
    if (event->handle == VIBTANIUM_EFI_CON_IN_WAIT_EVENT) {
        return efi_conin_enter_pending;
    }
    if (efi_event_timer_due(env, event)) {
        event->signaled = true;
    }
    return event->signaled;
}

static bool efi_timer_before(uint64_t now, uint64_t left, uint64_t right)
{
    return left - now < right - now;
}

static bool efi_event_next_timer(CPUIA64State *env, EfiGuestEvent *event,
                                 uint64_t *due)
{
    if (!event || event->handle == VIBTANIUM_EFI_CON_IN_WAIT_EVENT ||
        !event->timer_active) {
        return false;
    }

    if (efi_event_timer_due(env, event)) {
        *due = env->ar[IA64_AR_ITC];
    } else {
        *due = event->timer_due;
    }
    return true;
}

static void efi_write_event_index(CPUIA64State *env, uint64_t index_out,
                                  uint64_t index)
{
    efi_guest_stq(env, index_out, index);
}

static bool efi_wait_timer_candidate(CPUIA64State *env, EfiGuestEvent *event,
                                     uint64_t index, uint64_t *timer_index,
                                     uint64_t *timer_due)
{
    uint64_t due;

    if (!efi_event_next_timer(env, event, &due)) {
        return false;
    }

    if (*timer_index == UINT64_MAX ||
        efi_timer_before(env->ar[IA64_AR_ITC], due, *timer_due)) {
        *timer_index = index;
        *timer_due = due;
    }
    return true;
}

static void efi_block_until_timer(CPUIA64State *env, uint64_t timer_due)
{
    if (!vibtanium_efi_timer_due(env->ar[IA64_AR_ITC], timer_due)) {
        env->ar[IA64_AR_ITC] = timer_due;
    }
}

static uint64_t efi_wait_ready_event(CPUIA64State *env, uint64_t count,
                                     uint64_t events, uint64_t index_out,
                                     bool *found_ready,
                                     uint64_t *timer_index,
                                     uint64_t *timer_due)
{
    for (uint64_t i = 0; i < count; i++) {
        uint64_t handle = efi_guest_ldq(env, events + i * sizeof(uint64_t));
        EfiGuestEvent *event = efi_find_event(handle);

        if (!event) {
            return VIBTANIUM_EFI_INVALID_PARAMETER;
        }
        if (efi_event_is_ready(env, event)) {
            efi_write_event_index(env, index_out, i);
            efi_event_consume(env, event);
            *found_ready = true;
            return VIBTANIUM_EFI_SUCCESS;
        }
        efi_wait_timer_candidate(env, event, i, timer_index, timer_due);
    }
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_wait_for_event(CPUIA64State *env)
{
    uint64_t count = ia64_read_gr(env, 32);
    uint64_t events = ia64_read_gr(env, 33);
    uint64_t index_out = ia64_read_gr(env, 34);
    uint64_t timer_index = UINT64_MAX;
    uint64_t timer_due = 0;
    bool found_ready = false;
    uint64_t status;

    if (count == 0 || count > EFI_MAX_EVENTS || events == 0 ||
        index_out == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    status = efi_wait_ready_event(env, count, events, index_out,
                                  &found_ready, &timer_index, &timer_due);
    if (status != VIBTANIUM_EFI_SUCCESS || found_ready) {
        return status;
    }

    if (timer_index != UINT64_MAX) {
        uint64_t handle;
        EfiGuestEvent *event;

        efi_block_until_timer(env, timer_due);
        handle = efi_guest_ldq(env, events + timer_index * sizeof(uint64_t));
        event = efi_find_event(handle);
        if (!event || !efi_event_is_ready(env, event)) {
            return VIBTANIUM_EFI_NOT_READY;
        }
        efi_write_event_index(env, index_out, timer_index);
        efi_event_consume(env, event);
        return VIBTANIUM_EFI_SUCCESS;
    }

    return VIBTANIUM_EFI_NOT_READY;
}

static uint64_t efi_signal_event(CPUIA64State *env)
{
    EfiGuestEvent *event = efi_find_event(ia64_read_gr(env, 32));

    if (!event || event->handle == VIBTANIUM_EFI_CON_IN_WAIT_EVENT) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    event->signaled = true;
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_close_event(CPUIA64State *env)
{
    EfiGuestEvent *event = efi_find_event(ia64_read_gr(env, 32));

    if (!event || event->handle == VIBTANIUM_EFI_CON_IN_WAIT_EVENT) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    memset(event, 0, sizeof(*event));
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_check_event(CPUIA64State *env)
{
    EfiGuestEvent *event = efi_find_event(ia64_read_gr(env, 32));

    if (!event) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }
    return efi_event_is_ready(env, event) ? VIBTANIUM_EFI_SUCCESS
                                          : VIBTANIUM_EFI_NOT_READY;
}

static uint64_t efi_dispatch_boot_service(CPUIA64State *env, unsigned index)
{
    switch (index) {
    case 0:
        return 4; /* RaiseTPL returns the previous TPL, not EFI_STATUS. */
    case 1:
    case 6:
    case VIBTANIUM_EFI_BOOT_STALL_INDEX:
    case VIBTANIUM_EFI_BOOT_SET_WATCHDOG_INDEX:
        return VIBTANIUM_EFI_SUCCESS;
    case VIBTANIUM_EFI_BOOT_ALLOCATE_PAGES_INDEX:
        return efi_allocate_pages(env);
    case VIBTANIUM_EFI_BOOT_FREE_PAGES_INDEX:
        return efi_free_pages(env);
    case VIBTANIUM_EFI_BOOT_GET_MEMORY_MAP_INDEX:
        return efi_get_memory_map(env);
    case 5:
        return efi_allocate_pool(env);
    case 7:
        return efi_create_event(env);
    case 8:
        return efi_set_timer(env);
    case 9:
        return efi_wait_for_event(env);
    case 10:
        return efi_signal_event(env);
    case 11:
        return efi_close_event(env);
    case 12:
        return efi_check_event(env);
    case VIBTANIUM_EFI_BOOT_INSTALL_PROTOCOL_INDEX:
        return efi_install_protocol_interface(env);
    case VIBTANIUM_EFI_BOOT_UNINSTALL_PROTOCOL_INDEX:
        return efi_uninstall_protocol_interface(env);
    case VIBTANIUM_EFI_BOOT_HANDLE_PROTOCOL_INDEX:
        return efi_handle_protocol(env);
    case VIBTANIUM_EFI_BOOT_LOCATE_HANDLE_INDEX:
        return efi_locate_handle(env);
    case VIBTANIUM_EFI_BOOT_EXIT_BOOT_SERVICES_INDEX:
        return efi_exit_boot_services(env);
    case VIBTANIUM_EFI_BOOT_OPEN_PROTOCOL_INDEX:
        return efi_handle_protocol(env);
    case VIBTANIUM_EFI_BOOT_CLOSE_PROTOCOL_INDEX:
        return efi_close_protocol(env);
    case VIBTANIUM_EFI_BOOT_LOCATE_PROTOCOL_INDEX:
        return efi_locate_protocol(env);
    case VIBTANIUM_EFI_BOOT_CALCULATE_CRC32_INDEX:
        return efi_calculate_crc32(env);
    case VIBTANIUM_EFI_BOOT_COPY_MEM_INDEX:
        return efi_copy_mem(env);
    case VIBTANIUM_EFI_BOOT_SET_MEM_INDEX:
        return efi_set_mem(env);
    default:
        return VIBTANIUM_EFI_UNSUPPORTED;
    }
}

static void efi_write_time(CPUIA64State *env, uint64_t time)
{
    efi_guest_stw(env, time, 2026);
    efi_guest_stb(env, time + 2, 6);
    efi_guest_stb(env, time + 3, 26);
    efi_guest_stb(env, time + 4, 0);
    efi_guest_stb(env, time + 5, 0);
    efi_guest_stb(env, time + 6, 0);
    efi_guest_stb(env, time + 7, 0);
    efi_guest_stl(env, time + 8, 0);
    efi_guest_stw(env, time + 12, EFI_UNSPECIFIED_TIMEZONE);
    efi_guest_stb(env, time + 14, 0);
    efi_guest_stb(env, time + 15, 0);
}

static void efi_write_time_capabilities(CPUIA64State *env,
                                        uint64_t capabilities)
{
    efi_guest_stl(env, capabilities, 1);
    efi_guest_stl(env, capabilities + 4, 50000000);
    efi_guest_stb(env, capabilities + 8, 0);
}

static bool efi_runtime_range_contains(uint64_t base, uint64_t pages,
                                       uint64_t address)
{
    uint64_t size;
    uint64_t end;

    if (pages > UINT64_MAX / EFI_PAGE_SIZE) {
        return false;
    }
    size = pages * EFI_PAGE_SIZE;
    if (base > UINT64_MAX - size) {
        return false;
    }
    end = base + size;
    return address >= base && address < end;
}

static uint64_t efi_runtime_virtual_address(CPUIA64State *env,
                                            uint64_t memory_map_size,
                                            uint64_t descriptor_size,
                                            uint64_t memory_map,
                                            uint64_t physical)
{
    if (memory_map != 0 && descriptor_size >= EFI_MEMORY_DESCRIPTOR_SIZE &&
        memory_map_size >= EFI_MEMORY_DESCRIPTOR_SIZE) {
        uint64_t limit = memory_map_size - EFI_MEMORY_DESCRIPTOR_SIZE;

        for (uint64_t offset = 0; offset <= limit; offset += descriptor_size) {
            uint64_t descriptor = memory_map + offset;
            uint64_t attributes = efi_guest_ldq(env, descriptor + 32);
            uint64_t phys = efi_guest_ldq(env, descriptor + 8);
            uint64_t virt = efi_guest_ldq(env, descriptor + 16);
            uint64_t pages = efi_guest_ldq(env, descriptor + 24);

            if ((attributes & EFI_MEMORY_RUNTIME) != 0 && virt != 0 &&
                efi_runtime_range_contains(phys, pages, physical)) {
                return virt + (physical - phys);
            }
        }
    }

    return IA64_KERNEL_PAGE_OFFSET + ia64_region_offset(physical);
}

static void efi_runtime_convert_service_descriptors(CPUIA64State *env,
                                                    uint64_t memory_map_size,
                                                    uint64_t descriptor_size,
                                                    uint64_t memory_map)
{
    for (unsigned i = 0; i < VIBTANIUM_EFI_RUNTIME_SERVICE_COUNT; i++) {
        unsigned service_index = EFI_RUNTIME_SERVICE_BASE + i;
        uint64_t descriptor = efi_service_descriptor_address(service_index);
        uint64_t gate = efi_service_gate_address(service_index);

        efi_guest_stq(env, descriptor,
                      efi_runtime_virtual_address(env, memory_map_size,
                                                  descriptor_size, memory_map,
                                                  gate));
        efi_guest_stq(env, descriptor + 8,
                      efi_runtime_virtual_address(env, memory_map_size,
                                                  descriptor_size, memory_map,
                                                  VIBTANIUM_EFI_SYSTEM_TABLE));
    }
}

static uint64_t efi_runtime_get_time(CPUIA64State *env)
{
    uint64_t time = ia64_read_gr(env, 32);
    uint64_t capabilities = ia64_read_gr(env, 33);

    if (time == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    efi_write_time(env, time);
    if (capabilities != 0) {
        efi_write_time_capabilities(env, capabilities);
    }
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_runtime_get_wakeup_time(CPUIA64State *env)
{
    uint64_t enabled = ia64_read_gr(env, 32);
    uint64_t pending = ia64_read_gr(env, 33);
    uint64_t time = ia64_read_gr(env, 34);

    if (enabled == 0 || pending == 0 || time == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    efi_guest_stb(env, enabled, 0);
    efi_guest_stb(env, pending, 0);
    efi_write_time(env, time);
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_runtime_set_virtual_address_map(CPUIA64State *env)
{
    uint64_t memory_map_size = ia64_read_gr(env, 32);
    uint64_t descriptor_size = ia64_read_gr(env, 33);
    uint64_t descriptor_version = ia64_read_gr(env, 34);
    uint64_t memory_map = ia64_read_gr(env, 35);

    if (descriptor_version != EFI_MEMORY_DESCRIPTOR_VERSION ||
        descriptor_size < EFI_MEMORY_DESCRIPTOR_SIZE ||
        (memory_map == 0 && memory_map_size != 0)) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    efi_runtime_convert_service_descriptors(env, memory_map_size,
                                            descriptor_size, memory_map);
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_runtime_convert_pointer(CPUIA64State *env)
{
    uint64_t pointer = ia64_read_gr(env, 33);
    uint64_t physical;

    if (pointer == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    physical = efi_guest_ldq(env, pointer);
    if (physical != 0) {
        efi_guest_stq(env, pointer,
                      IA64_KERNEL_PAGE_OFFSET + ia64_region_offset(physical));
    }
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_runtime_get_next_high_mono_count(CPUIA64State *env)
{
    uint64_t count = ia64_read_gr(env, 32);

    if (count == 0) {
        return VIBTANIUM_EFI_INVALID_PARAMETER;
    }

    efi_guest_stl(env, count, efi_high_monotonic_count++);
    return VIBTANIUM_EFI_SUCCESS;
}

static uint64_t efi_dispatch_runtime_service(CPUIA64State *env, unsigned index)
{
    switch (index) {
    case 0: /* GetTime */
        return efi_runtime_get_time(env);
    case 1: /* SetTime */
        return ia64_read_gr(env, 32) != 0 ? VIBTANIUM_EFI_SUCCESS
                                          : VIBTANIUM_EFI_INVALID_PARAMETER;
    case 2: /* GetWakeupTime */
        return efi_runtime_get_wakeup_time(env);
    case 3: /* SetWakeupTime */
        return VIBTANIUM_EFI_SUCCESS;
    case 4: /* SetVirtualAddressMap */
        return efi_runtime_set_virtual_address_map(env);
    case 5: /* ConvertPointer */
        return efi_runtime_convert_pointer(env);
    case 6: /* GetVariable */
    case 7: /* GetNextVariableName */
        return VIBTANIUM_EFI_NOT_FOUND;
    case 8: /* SetVariable */
        return VIBTANIUM_EFI_SUCCESS;
    case 9: /* GetNextHighMonotonicCount */
        return efi_runtime_get_next_high_mono_count(env);
    case 10: /* ResetSystem */
        return VIBTANIUM_EFI_SUCCESS;
    default:
        return VIBTANIUM_EFI_UNSUPPORTED;
    }
}

static void efi_console_output_string(CPUIA64State *env)
{
    uint64_t text = ia64_read_gr(env, 33);
    GString *line;

    if (text == 0) {
        return;
    }

    line = g_string_new(NULL);
    for (unsigned i = 0; i < 4096; i++) {
        uint16_t ch = cpu_lduw_le_data_ra(env, text + i * 2, GETPC());

        if (ch == 0) {
            break;
        }
        if (ch == '\r') {
            continue;
        }
        g_string_append_c(line, ch < 0x80 ? (char)ch : '?');
    }
    if (line->len != 0) {
        fprintf(stderr, "%s", line->str);
    }
    g_string_free(line, true);
}

static uint64_t efi_dispatch_console_out(CPUIA64State *env, unsigned index)
{
    uint64_t columns = ia64_read_gr(env, 34);
    uint64_t rows = ia64_read_gr(env, 35);

    switch (index) {
    case 0: /* Reset */
        return VIBTANIUM_EFI_SUCCESS;
    case 1: /* OutputString */
        efi_console_output_string(env);
        return VIBTANIUM_EFI_SUCCESS;
    case 2: /* TestString */
        return VIBTANIUM_EFI_SUCCESS;
    case 3: /* QueryMode */
        if (columns == 0 || rows == 0) {
            return VIBTANIUM_EFI_INVALID_PARAMETER;
        }
        efi_guest_stq(env, columns, 80);
        efi_guest_stq(env, rows, 25);
        return VIBTANIUM_EFI_SUCCESS;
    case 4: /* SetMode */
    case 5: /* SetAttribute */
    case 6: /* ClearScreen */
    case 7: /* SetCursorPosition */
    case 8: /* EnableCursor */
        return VIBTANIUM_EFI_SUCCESS;
    default:
        return VIBTANIUM_EFI_UNSUPPORTED;
    }
}

static uint64_t efi_dispatch_console_in(CPUIA64State *env, unsigned index)
{
    uint64_t key = ia64_read_gr(env, 33);

    switch (index) {
    case 0: /* Reset */
        efi_conin_enter_pending = true;
        return VIBTANIUM_EFI_SUCCESS;
    case 1: /* ReadKeyStroke */
        if (key == 0) {
            return VIBTANIUM_EFI_INVALID_PARAMETER;
        }
        if (!efi_conin_enter_pending) {
            return VIBTANIUM_EFI_NOT_READY;
        }
        efi_guest_stw(env, key, 0);
        efi_guest_stw(env, key + 2, '\r');
        efi_conin_enter_pending = false;
        return VIBTANIUM_EFI_SUCCESS;
    default:
        return VIBTANIUM_EFI_UNSUPPORTED;
    }
}

bool vibtanium_efi_dispatch_gate(CPUIA64State *env, uint64_t gate_ip)
{
    unsigned service_index;
    uint64_t result = VIBTANIUM_EFI_UNSUPPORTED;

    if (!env) {
        return false;
    }
    if (!efi_gate_service_index(gate_ip, &service_index)) {
        return dispatch_firmware_gate(env, gate_ip);
    }

    IA64_PERF_INC(IA64_PERF_FIRMWARE_EFI);
    if (service_index < EFI_RUNTIME_SERVICE_BASE) {
        result = efi_dispatch_boot_service(env,
                                           service_index -
                                           EFI_BOOT_SERVICE_BASE);
    } else if (service_index < EFI_CON_OUT_SERVICE_BASE) {
        result = efi_dispatch_runtime_service(env,
                                              service_index -
                                              EFI_RUNTIME_SERVICE_BASE);
    } else if (service_index >= EFI_CON_OUT_SERVICE_BASE &&
               service_index < EFI_CON_IN_SERVICE_BASE) {
        result = efi_dispatch_console_out(env,
                                          service_index -
                                          EFI_CON_OUT_SERVICE_BASE);
    } else if (service_index >= EFI_CON_IN_SERVICE_BASE &&
               service_index < EFI_BLOCK_IO_SERVICE_BASE) {
        result = efi_dispatch_console_in(env,
                                         service_index -
                                         EFI_CON_IN_SERVICE_BASE);
    } else if (service_index >= EFI_BLOCK_IO_SERVICE_BASE &&
               service_index < EFI_SIMPLE_FILE_SYSTEM_SERVICE_BASE) {
        result = efi_dispatch_block_io(env,
                                       service_index -
                                       EFI_BLOCK_IO_SERVICE_BASE);
    } else if (service_index >= EFI_SIMPLE_FILE_SYSTEM_SERVICE_BASE &&
               service_index < EFI_FILE_SERVICE_BASE) {
        result = efi_dispatch_simple_file_system(
            env, service_index - EFI_SIMPLE_FILE_SYSTEM_SERVICE_BASE);
    } else if (service_index >= EFI_FILE_SERVICE_BASE &&
               service_index < EFI_SERVICE_DESCRIPTOR_COUNT) {
        result = efi_dispatch_file(env,
                                   service_index - EFI_FILE_SERVICE_BASE);
    }

    ia64_write_gr(env, 8, result);
    efi_trace_service(env, service_index, result);
    ia64_return_from_call_frame(env, env->br[0]);
    return true;
}

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

static void ia64_alat_invalidate_target(CPUIA64State *env, uint8_t target)
{
    uint32_t valid_mask = env->alat.valid_mask;

    if (valid_mask == 0) {
        return;
    }

    for (unsigned i = 0; i < IA64_ALAT_COUNT; i++) {
        if ((valid_mask & (1u << i)) != 0 &&
            env->alat.entries[i].target == target) {
            ia64_alat_set_valid(env, i, false);
        }
    }
}

static void ia64_alat_record_load(CPUIA64State *env, uint8_t target,
                                  uint64_t address, uint8_t width)
{
    IA64AlatEntry *entry;
    unsigned index;

    IA64_PERF_INC(IA64_PERF_ALAT_RECORD_LOAD);
    if (target == 0 || target >= IA64_GR_COUNT) {
        return;
    }

    ia64_alat_invalidate_target(env, target);
    index = env->alat.next % IA64_ALAT_COUNT;
    entry = &env->alat.entries[index];
    env->alat.next = (env->alat.next + 1) % IA64_ALAT_COUNT;

    memset(entry, 0, sizeof(*entry));
    entry->target = target;
    entry->width = width;
    ia64_alat_resolve_address(env, address, MMU_DATA_LOAD,
                              &entry->address, &entry->physical);
    ia64_alat_set_valid(env, index, true);
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

static void ia64_exec_flushrs(CPUIA64State *env)
{
    uint32_t dirty = ia64_rse_num_regs(env->rse.bspstore, env->rse.bsp);
    uint32_t first_slot;
    uint64_t address = env->rse.bspstore;

    IA64_PERF_INC(IA64_PERF_OP_RSE_FLUSHRS);
    if (dirty == 0 || env->rse.bspstore == 0) {
        env->rse.clean_count = MIN(env->rse.clean_count,
                                   env->rse.current_frame_base);
        return;
    }

    first_slot = ia64_rse_dirty_partition_first_slot(env, dirty);
    for (uint32_t i = 0; i < dirty; i++) {
        address = ia64_rse_reg_address(address);
        ia64_ldst_write(env, address, 8,
                        env->rse.stacked_gr[
                            ia64_rse_wrap_slot(first_slot + i)]);
        address += 8;
    }

    env->rse.bspstore = address;
    env->rse.bsp = address;
    env->rse.clean_count = env->rse.current_frame_base;
    env->ar[IA64_AR_BSPSTORE] = address;
    env->ar[IA64_AR_BSP] = address;
}

static uint64_t ia64_rse_read_backing_store_register(CPUIA64State *env,
                                                     uint64_t address,
                                                     void *opaque)
{
    return ia64_ldst_read(env, address, 8);
}

static bool ia64_rse_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_RSE_TRACE") != NULL;
    }
    return enabled != 0;
}

static void ia64_rse_sync_ar_after_fill(CPUIA64State *env)
{
    env->ar[IA64_AR_BSP] = env->rse.bsp;
    env->ar[IA64_AR_BSPSTORE] = env->rse.bspstore;
    env->ar[IA64_AR_RNAT] = env->rse.rnat;
}

/*
 * Mandatory RSE fill after a frame is restored (br.ret, or rfi with a valid
 * CR.IFS).  Each register of the restored frame is either still resident in the
 * physical stacked register file ("dirty": its backing-store address is at or
 * above AR.BSPSTORE) or was already spilled to the backing store ("clean":
 * below AR.BSPSTORE).  Reload exactly the clean registers from memory and leave
 * the resident ones untouched.
 *
 * This per-register clean/dirty decision -- keyed off the architectural
 * AR.BSPSTORE boundary rather than a reconstructed scalar count -- is what makes
 * a context switch correct: switch_to flushes the outgoing task and repoints
 * AR.BSPSTORE/AR.RNAT at the incoming task's backing store, so the restored
 * frame's preserved registers come back from the new task's spilled image
 * instead of leaking stale physical-stack contents from the previous task (or
 * from an as-yet-unfilled brand-new thread).  Ordinary intra-task call/return
 * leaves AR.BSPSTORE far below the frame, so nothing is reloaded and the live
 * register file keeps being used.
 */
static void ia64_rse_fill_restored_frame(CPUIA64State *env, uint32_t count)
{
    uint64_t bspstore = env->rse.bspstore;
    uint64_t frame_base = env->rse.bsp;
    uint64_t address;
    uint32_t filled = 0;
    bool trace = ia64_rse_trace_enabled();

    IA64_PERF_INC(IA64_PERF_OP_RSE_FILL_RESTORED);
    if (count == 0 || bspstore == 0 || frame_base == 0) {
        return;
    }
    count = MIN(count, (uint32_t)IA64_STACKED_GR_COUNT);
    address = ia64_rse_reg_address(ia64_rse_skip_regs(frame_base, 0));
    if (address >= bspstore) {
        return;
    }

    for (uint32_t i = 0; i < count; i++) {
        if (address >= bspstore) {
            /* This register and every higher one are still resident. */
            break;
        }
        env->rse.stacked_gr[
            ia64_rse_wrap_slot(env->rse.current_frame_base + i)] =
            ia64_ldst_read(env, address, 8);
        filled++;
        address = ia64_rse_reg_address(address + 8);
    }

    if (filled == 0) {
        return;
    }
    IA64_PERF_INC(IA64_PERF_OP_RSE_FILL_RESTORED_MEM);
    IA64_PERF_ADD(IA64_PERF_OP_RSE_FILL_RESTORED_REG, filled);

    /* The reloaded registers are now resident; lower the store pointer. */
    env->rse.bspstore = frame_base;
    env->rse.clean_count = MIN(env->rse.clean_count,
                               env->rse.current_frame_base);
    ia64_rse_sync_ar_after_fill(env);

    if (trace) {
        fprintf(stderr,
                "[ia64-rse] ip=0x%016" PRIx64
                " fill-restored count=%u filled=%u"
                " bspstore=0x%016" PRIx64 " bsp=0x%016" PRIx64 "\n",
                env->ip, count, filled, env->rse.bspstore, env->rse.bsp);
    }
}

static void ia64_rse_maybe_fill_restored_frame(CPUIA64State *env,
                                               uint32_t count)
{
    if (count == 0 || env->rse.bspstore == 0 || env->rse.bsp == 0 ||
        env->rse.bsp >= env->rse.bspstore) {
        return;
    }
    ia64_rse_fill_restored_frame(env, count);
}

static void ia64_exec_loadrs(CPUIA64State *env)
{
    uint64_t bytes = (env->rse.rsc >> 16) & 0x3fff;
    uint64_t end = env->rse.bsp;
    uint64_t start;
    uint32_t count;
    uint32_t before;

    IA64_PERF_INC(IA64_PERF_OP_RSE_LOADRS);
    if (end == 0 || end < bytes) {
        return;
    }

    start = end - bytes;
    count = ia64_rse_num_regs(start, end);
    before = ia64_rse_num_regs(env->rse.bspstore, env->rse.bsp);
    if (count != 0) {
        ia64_rse_load_dirty_partition(env, start, end,
                                      ia64_rse_read_backing_store_register,
                                      NULL);
    }
    ia64_rse_set_dirty_partition(env, start, end);
    if (ia64_rse_trace_enabled()) {
        fprintf(stderr,
                "[ia64-rse] ip=0x%016" PRIx64
                " loadrs bytes=0x%016" PRIx64 " count=%u"
                " dirty-before=%u bspstore=0x%016" PRIx64
                " bsp=0x%016" PRIx64 " start=0x%016" PRIx64
                " end=0x%016" PRIx64 "\n",
                env->ip, bytes, count, before, env->rse.bspstore,
                env->rse.bsp, start, end);
    }
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
    uint64_t address = ia64_read_gr(env, decoded->base);
    uint64_t old_value = ia64_ldst_read(env, address, decoded->width);
    uint64_t store_value = 0;
    uint64_t compare_value = 0;
    uint64_t mask = ia64_width_mask(decoded->width);
    bool write_memory = false;

    IA64_PERF_INC(IA64_PERF_ATOMIC_MEMORY_OP);
    switch (decoded->kind) {
    case IA64_ATOMIC_CMPXCHG:
        store_value = ia64_read_gr(env, decoded->source);
        compare_value = env->ar[IA64_AR_CCV] & mask;
        write_memory = (old_value & mask) == compare_value;
        break;
    case IA64_ATOMIC_XCHG:
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
    uint64_t address = ia64_read_gr(env, decoded->base);
    uint64_t update;

    switch (decoded->kind) {
    case IA64_LDST_IMM_LOAD:
        if (decoded->target != 0) {
            uint64_t value = ia64_ldst_read(env, address, decoded->width);

            ia64_trace_ldst_decoded(env, "load", address, decoded->width,
                                    value, decoded);
            ia64_write_gr(env, decoded->target, value);
            if (decoded->memory_class == 2 || decoded->memory_class == 3) {
                ia64_alat_record_load(env, decoded->target, address,
                                      decoded->width);
            }
        }
        break;
    case IA64_LDST_IMM_STORE:
    {
        uint64_t value = ia64_read_gr(env, decoded->source);

        ia64_trace_ldst_decoded(env, "store", address, decoded->width,
                                value, decoded);
        ia64_ldst_write(env, address, decoded->width, value);
        break;
    }
    case IA64_LDST_IMM_PREFETCH:
        break;
    default:
        g_assert_not_reached();
    }

    if (decoded->base_update) {
        update = decoded->update_from_register
            ? ia64_read_gr(env, decoded->update_source)
            : (uint64_t)decoded->immediate;
        ia64_write_gr(env, decoded->base, address + update);
    }
    env->gr[0] = 0;
    return true;
}

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
}

static void exec_floating_load(CPUIA64State *env,
                               const IA64FloatingMemoryInstruction *decoded,
                               uint64_t address)
{
    IA64FloatReg spill;

    switch (decoded->format) {
    case IA64_FLOAT_FMT_SINGLE:
        helper_write_fr_raw(env, decoded->freg,
                            ia64_ldst_read(env, address, 4),
                            0x1003e);
        break;
    case IA64_FLOAT_FMT_DOUBLE:
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
        ia64_ldst_write(env, address, 4, low);
        break;
    case IA64_FLOAT_FMT_DOUBLE:
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

    switch (decoded->kind) {
    case IA64_FLOAT_MEM_LOAD:
        exec_floating_load(env, decoded, address);
        break;
    case IA64_FLOAT_MEM_LOAD_PAIR:
        exec_floating_load_pair(env, decoded, address);
        break;
    case IA64_FLOAT_MEM_STORE:
        exec_floating_store(env, decoded, address);
        break;
    case IA64_FLOAT_MEM_PREFETCH:
        break;
    default:
        g_assert_not_reached();
    }

    if (decoded->base_update) {
        update = decoded->update_from_register
            ? ia64_read_gr(env, decoded->update_source)
            : (uint64_t)decoded->immediate;
        ia64_write_gr(env, decoded->base, address + update);
    }
    return true;
}

static bool exec_counted_store_loop(CPUIA64State *env,
                                    const IA64CountedStoreLoop *loop,
                                    uint64_t *next_ip)
{
    uint64_t loop_count = env->ar[IA64_AR_LC];
    uint64_t iterations;
    uint64_t address;
    uint64_t value;
    uint64_t update;

    if (!env || !loop || !next_ip || loop_count == UINT64_MAX) {
        return false;
    }

    IA64_PERF_INC(IA64_PERF_COUNTED_STORE_LOOP);
    iterations = loop_count + 1;
    address = ia64_read_gr(env, loop->store.base);
    value = ia64_read_gr(env, loop->store.source);
    update = (uint64_t)loop->store.immediate;

    for (uint64_t i = 0; i < iterations; i++) {
        ia64_ldst_write(env, address, loop->store.width, value);
        address += update;
    }

    ia64_write_gr(env, loop->store.base, address);
    env->ar[IA64_AR_LC] = 0;
    *next_ip = loop->fallthrough_ip;
    env->gr[0] = 0;
    return true;
}

static bool exec_false_predicated_side_effect(CPUIA64State *env,
                                              const IA64DecodedBundle *decoded,
                                              int slot)
{
    IA64SlotType type = decoded->info->slot_type[slot];
    uint64_t raw = decoded->slot[slot];
    IA64CompareInstruction cmp;
    IA64PredicateTestInstruction pred_test;

    if (ia64_decode_compare(type, raw, &cmp) &&
        cmp.write_kind == IA64_PRED_WRITE_UNCONDITIONAL) {
        if (!ia64_exec_compare_qualified(env, &cmp, false)) {
            abort_unsupported_slot(env, decoded, slot);
        }
        return true;
    }

    if (ia64_decode_predicate_test(type, raw, &pred_test) &&
        pred_test.write_kind == IA64_PRED_WRITE_UNCONDITIONAL) {
        if (!ia64_exec_predicate_test_qualified(env, &pred_test, false)) {
            abort_unsupported_slot(env, decoded, slot);
        }
        return true;
    }

    return false;
}

/*
 * Diagnostic: log do_execve() filenames so a userspace exec loop can be
 * identified. do_execve() in the Debian 3.2.0-4-itanium kernel is at a fixed
 * address; gated behind VIBTANIUM_EXECVE_TRACE so it costs nothing by default.
 */
static void ia64_trace_execve(CPUIA64State *env)
{
    static int enabled = -1;
    char path[176];
    uint64_t argv;
    uint64_t envp;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_EXECVE_TRACE") != NULL;
    }
    if (enabled == 0 || env->ip != UINT64_C(0xa0000001002072e0)) {
        return;
    }
    ia64_trace_guest_c_string(env, ia64_read_gr(env, 32), path, sizeof(path));
    argv = ia64_read_gr(env, 33);
    envp = ia64_read_gr(env, 34);
    fprintf(stderr, "[ia64-execve] do_execve path=%s current=0x%016" PRIx64
            " b0=0x%016" PRIx64,
            path, ia64_read_gr(env, 13), env->br[0]);
    ia64_trace_execve_vector(env, "argv", argv, 4);
    ia64_trace_execve_vector(env, "envp", envp, 2);
    fprintf(stderr, "\n");
}

/*
 * Diagnostic: the break-based syscall tracer only catches the early dynamic
 * loader, because glibc switches to the lightweight `epc` fast-system-call
 * gate (`__kernel_syscall_via_epc`) once AT_SYSINFO is wired up. main()'s
 * syscalls (open/ioctl/dup2/execve/...) therefore never hit the break path.
 * Trace them at the fixed gate entry where r15 holds the syscall number and
 * out0..out7 (r32..) hold the arguments, mirroring the break tracer so the
 * full per-process syscall stream is visible. Gated behind the same
 * VIBTANIUM_SYSCALL_TRACE knob, IP-checked so it is free when disabled.
 */
static void ia64_trace_epc_syscall(CPUIA64State *env)
{
    uint64_t nr;
    uint64_t cpl;

    if (!ia64_syscall_trace_enabled() ||
        env->ip != UINT64_C(0xa000000000040a00)) {
        return;
    }

    nr = ia64_read_gr(env, 15);
    cpl = (env->psr & IA64_PSR_CPL_MASK) >> IA64_PSR_CPL_SHIFT;
    fprintf(stderr,
            "[ia64-syscall] epc nr=%" PRIu64 "(%s) ip=0x%016" PRIx64
            " cpl=%" PRIu64 " current=0x%016" PRIx64
            " r32=0x%016" PRIx64 " r33=0x%016" PRIx64
            " r34=0x%016" PRIx64 " r35=0x%016" PRIx64 " b0=0x%016" PRIx64,
            nr, ia64_linux_syscall_name(nr), env->ip, cpl,
            ia64_read_gr(env, 13),
            ia64_read_gr(env, 32), ia64_read_gr(env, 33),
            ia64_read_gr(env, 34), ia64_read_gr(env, 35), env->br[0]);
    ia64_trace_linux_syscall_paths(env, "epc", nr);
    ia64_trace_linux_syscall_socket_details(env, "epc", nr);
    fprintf(stderr, "\n");
}

/*
 * Diagnostic: log the syscall return value. Both the break and epc heavy
 * paths funnel through ia64_ret_from_syscall, where r8 = return value and
 * r10 = 0 (success) / -1 (error). Pairing this with the entry traces above
 * shows exactly which syscall fails and with what errno.
 */
static void ia64_trace_syscall_return(CPUIA64State *env)
{
    uint64_t r8;
    uint64_t r10;

    if (!ia64_syscall_trace_enabled() ||
        env->ip != UINT64_C(0xa00000010000baa0)) {
        return;
    }

    r8 = ia64_read_gr(env, 8);
    r10 = ia64_read_gr(env, 10);
    fprintf(stderr,
            "[ia64-syscall] ret ip=0x%016" PRIx64
            " current=0x%016" PRIx64 " r8=0x%016" PRIx64
            " r10=0x%016" PRIx64 "\n",
            env->ip, ia64_read_gr(env, 13), r8, r10);
}

static bool ia64_uevent_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_UEVENT_TRACE") != NULL;
    }
    return enabled != 0;
}

#define IA64_TRACE_KERNEL_CALL_SLOTS 64

typedef enum IA64TraceKernelCallTag {
    IA64_TRACE_KERNEL_CALL_NONE = 0,
    IA64_TRACE_KERNEL_CALL_RECVMSG,
    IA64_TRACE_KERNEL_CALL_SENDMSG,
    IA64_TRACE_KERNEL_CALL_SEND,
    IA64_TRACE_KERNEL_CALL_RECV,
    IA64_TRACE_KERNEL_CALL_EPOLL_WAIT,
    IA64_TRACE_KERNEL_CALL_EPOLL_CTL,
    IA64_TRACE_KERNEL_CALL_WAIT4,
    IA64_TRACE_KERNEL_CALL_KILL,
    IA64_TRACE_KERNEL_CALL_POLL,
    IA64_TRACE_KERNEL_CALL_CLOCK_GETTIME,
    IA64_TRACE_KERNEL_CALL_MKNOD,
    IA64_TRACE_KERNEL_CALL_MKNODAT,
    IA64_TRACE_KERNEL_CALL_DOFORK,
    IA64_TRACE_KERNEL_CALL_NETLINK_RECVMSG,
    IA64_TRACE_KERNEL_CALL_NETLINK_SENDMSG,
    IA64_TRACE_KERNEL_CALL_NETLINK_UNICAST,
    IA64_TRACE_KERNEL_CALL_NETLINK_ATTACHSKB,
    IA64_TRACE_KERNEL_CALL_NETLINK_SENDSKB,
    IA64_TRACE_KERNEL_CALL_NETLINK_BROADCAST_FILTERED,
} IA64TraceKernelCallTag;

typedef struct IA64TraceKernelCall {
    bool active;
    IA64TraceKernelCallTag tag;
    uint64_t current;
    uint64_t return_ip;
    uint64_t arg[8];
} IA64TraceKernelCall;

static IA64TraceKernelCall ia64_uevent_kernel_calls[
    IA64_TRACE_KERNEL_CALL_SLOTS];

static IA64TraceKernelCall *ia64_trace_kernel_call_slot(uint64_t current,
                                                        IA64TraceKernelCallTag tag,
                                                        bool allocate)
{
    IA64TraceKernelCall *free_slot = NULL;

    for (unsigned i = 0; i < ARRAY_SIZE(ia64_uevent_kernel_calls); i++) {
        IA64TraceKernelCall *slot = &ia64_uevent_kernel_calls[i];

        if (slot->active && slot->current == current && slot->tag == tag) {
            return slot;
        }
        if (!slot->active && free_slot == NULL) {
            free_slot = slot;
        }
    }

    if (!allocate || free_slot == NULL) {
        return NULL;
    }

    memset(free_slot, 0, sizeof(*free_slot));
    free_slot->active = true;
    free_slot->tag = tag;
    free_slot->current = current;
    return free_slot;
}

static IA64TraceKernelCall *ia64_trace_kernel_call_return_slot(uint64_t current,
                                                               uint64_t ip)
{
    for (unsigned i = 0; i < ARRAY_SIZE(ia64_uevent_kernel_calls); i++) {
        IA64TraceKernelCall *slot = &ia64_uevent_kernel_calls[i];

        if (slot->active && slot->current == current &&
            slot->return_ip == ip) {
            return slot;
        }
    }
    return NULL;
}

static void ia64_trace_record_kernel_call(CPUIA64State *env,
                                          IA64TraceKernelCallTag tag)
{
    IA64TraceKernelCall *slot;
    uint64_t current = ia64_read_gr(env, 13);

    slot = ia64_trace_kernel_call_slot(current, tag, true);
    if (slot == NULL) {
        return;
    }

    slot->return_ip = env->br[0];
    for (unsigned i = 0; i < ARRAY_SIZE(slot->arg); i++) {
        slot->arg[i] = ia64_read_gr(env, 32 + i);
    }
}

static void ia64_trace_epoll_event(CPUIA64State *env, uint64_t event,
                                   const char *label)
{
    char status[48] = "ok";
    uint32_t events;
    uint64_t data;

    if (event == 0) {
        fprintf(stderr, " %s=<null>", label);
        return;
    }
    if (!ia64_trace_guest_read_u32(env, event, &events, status,
                                   sizeof(status)) ||
        !ia64_trace_guest_read_u64(env, event + 8, &data, status,
                                   sizeof(status))) {
        fprintf(stderr, " %s=<unreadable:%s>", label, status);
        return;
    }
    fprintf(stderr,
            " %s={events=0x%08" PRIx32 " data=0x%016" PRIx64
            " data_fd=%" PRIu64 "}",
            label, events, data, data & UINT64_C(0xffffffff));
}

static void ia64_trace_epoll_events(CPUIA64State *env, uint64_t events_addr,
                                    uint64_t count)
{
    count = MIN(count, UINT64_C(8));
    for (uint64_t i = 0; i < count; i++) {
        char label[24];

        snprintf(label, sizeof(label), "event%" PRIu64, i);
        ia64_trace_epoll_event(env, events_addr + i * UINT64_C(16), label);
    }
}

static uint64_t ia64_trace_socket_sk(CPUIA64State *env, uint64_t sock)
{
    char status[48] = "ok";
    uint64_t sk = 0;

    /*
     * Linux 3.2 ia64 struct socket layout:
     * state/type/pad, flags, wq, file, sk, ops.
     */
    if (sock != 0) {
        ia64_trace_guest_read_u64(env, sock + 32, &sk, status,
                                  sizeof(status));
    }
    return sk;
}

static void ia64_trace_timespec(CPUIA64State *env, uint64_t timespec,
                                const char *label)
{
    char status[48] = "ok";
    uint64_t tv_sec;
    uint64_t tv_nsec;

    if (timespec == 0) {
        fprintf(stderr, " %s=<null>", label);
        return;
    }
    if (!ia64_trace_guest_read_u64(env, timespec, &tv_sec, status,
                                   sizeof(status)) ||
        !ia64_trace_guest_read_u64(env, timespec + 8, &tv_nsec, status,
                                   sizeof(status))) {
        fprintf(stderr, " %s=<unreadable:%s>", label, status);
        return;
    }
    fprintf(stderr, " %s={sec=%" PRIu64 " nsec=%" PRIu64 "}",
            label, tv_sec, tv_nsec);
}

static void ia64_trace_pollfds(CPUIA64State *env, uint64_t ufds,
                               uint64_t nfds)
{
    char status[48] = "ok";

    nfds = MIN(nfds, UINT64_C(4));
    for (uint64_t i = 0; i < nfds; i++) {
        uint64_t pollfd = ufds + i * UINT64_C(8);
        uint32_t fd;
        uint16_t events;
        uint16_t revents;

        if (!ia64_trace_guest_read_u32(env, pollfd, &fd, status,
                                       sizeof(status)) ||
            !ia64_trace_guest_read_u16(env, pollfd + 4, &events, status,
                                       sizeof(status)) ||
            !ia64_trace_guest_read_u16(env, pollfd + 6, &revents, status,
                                       sizeof(status))) {
            fprintf(stderr, " pollfd%" PRIu64 "=<unreadable:%s>",
                    i, status);
            return;
        }
        fprintf(stderr,
                " pollfd%" PRIu64 "={fd=%" PRIu32 " events=0x%04" PRIx16
                " revents=0x%04" PRIx16 "}",
                i, fd, events, revents);
    }
}

static void ia64_trace_msghdr_name(CPUIA64State *env, uint64_t msg)
{
    char status[48] = "ok";
    uint64_t name;
    uint32_t namelen;
    uint16_t family;
    uint32_t nl_pid;
    uint32_t nl_groups;

    if (!ia64_trace_guest_read_u64(env, msg, &name, status, sizeof(status)) ||
        !ia64_trace_guest_read_u32(env, msg + 8, &namelen, status,
                                   sizeof(status))) {
        fprintf(stderr, " msg_name=<unreadable:%s>", status);
        return;
    }
    fprintf(stderr, " msg_name=0x%016" PRIx64 " msg_namelen=%" PRIu32,
            name, namelen);
    if (name == 0 || namelen < 12) {
        return;
    }
    if (!ia64_trace_guest_read_u16(env, name, &family, status,
                                   sizeof(status)) ||
        !ia64_trace_guest_read_u32(env, name + 4, &nl_pid, status,
                                   sizeof(status)) ||
        !ia64_trace_guest_read_u32(env, name + 8, &nl_groups, status,
                                   sizeof(status))) {
        fprintf(stderr, " sockaddr_nl=<unreadable:%s>", status);
        return;
    }
    fprintf(stderr,
            " sockaddr_nl={family=%" PRIu16 " pid=%" PRIu32
            " groups=0x%08" PRIx32 "}",
            family, nl_pid, nl_groups);
}

static void ia64_trace_msghdr_iovs(CPUIA64State *env, uint64_t msg,
                                   unsigned max_iovs, uint64_t max_each)
{
    char status[48] = "ok";
    uint64_t msg_iov;
    uint64_t msg_iovlen;

    if (!ia64_trace_guest_read_u64(env, msg + 16, &msg_iov, status,
                                   sizeof(status)) ||
        !ia64_trace_guest_read_u64(env, msg + 24, &msg_iovlen, status,
                                   sizeof(status))) {
        fprintf(stderr, " msghdr=<unreadable:%s>", status);
        return;
    }

    fprintf(stderr, " msg_iov=0x%016" PRIx64 " msg_iovlen=%" PRIu64,
            msg_iov, msg_iovlen);
    if (msg_iov == 0 || msg_iovlen == 0) {
        return;
    }

    for (unsigned i = 0; i < max_iovs && i < msg_iovlen; i++) {
        uint64_t iov = msg_iov + i * 16;
        uint64_t iov_base;
        uint64_t iov_len;
        char payload[512];

        if (!ia64_trace_guest_read_u64(env, iov, &iov_base, status,
                                       sizeof(status)) ||
            !ia64_trace_guest_read_u64(env, iov + 8, &iov_len, status,
                                       sizeof(status))) {
            fprintf(stderr, " iov%u=<unreadable:%s>", i, status);
            return;
        }
        ia64_trace_guest_bytes_escaped(env, iov_base, MIN(iov_len, max_each),
                                       payload, sizeof(payload));
        fprintf(stderr,
                " iov%u_base=0x%016" PRIx64 " iov%u_len=%" PRIu64
                " iov%u_payload=%s",
                i, iov_base, i, iov_len, i, payload);
    }
}

static void ia64_trace_recvmsg_payload(CPUIA64State *env,
                                       IA64TraceKernelCall *slot,
                                       int64_t retval)
{
    char status[48] = "ok";
    uint64_t msg = slot->arg[1];
    uint64_t msg_iov;
    uint64_t msg_iovlen;
    uint64_t iov_base;
    uint64_t iov_len;
    char payload[512];

    if (retval <= 0) {
        return;
    }
    if (!ia64_trace_guest_read_u64(env, msg + 16, &msg_iov, status,
                                   sizeof(status)) ||
        !ia64_trace_guest_read_u64(env, msg + 24, &msg_iovlen, status,
                                   sizeof(status))) {
        fprintf(stderr, " msghdr=<unreadable:%s>", status);
        return;
    }
    fprintf(stderr, " msg_iov=0x%016" PRIx64 " msg_iovlen=%" PRIu64,
            msg_iov, msg_iovlen);
    if (msg_iov == 0 || msg_iovlen == 0) {
        return;
    }
    if (!ia64_trace_guest_read_u64(env, msg_iov, &iov_base, status,
                                   sizeof(status)) ||
        !ia64_trace_guest_read_u64(env, msg_iov + 8, &iov_len, status,
                                   sizeof(status))) {
        fprintf(stderr, " iov=<unreadable:%s>", status);
        return;
    }
    ia64_trace_guest_bytes_escaped(env, iov_base,
                                   MIN((uint64_t)retval, UINT64_C(220)),
                                   payload, sizeof(payload));
    fprintf(stderr, " iov_base=0x%016" PRIx64 " iov_len=%" PRIu64
            " payload=%s",
            iov_base, iov_len, payload);
}

static void ia64_trace_uevent_netlink(CPUIA64State *env)
{
    IA64TraceKernelCall *call;

    if (!ia64_uevent_trace_enabled()) {
        return;
    }

    call = ia64_trace_kernel_call_return_slot(ia64_read_gr(env, 13), env->ip);
    if (call != NULL) {
        int64_t retval = (int64_t)ia64_read_gr(env, 8);

        switch (call->tag) {
        case IA64_TRACE_KERNEL_CALL_RECVMSG:
            fprintf(stderr,
                    "[ia64-uevent] sys_recvmsg ret ip=0x%016" PRIx64
                    " current=0x%016" PRIx64 " fd=%" PRIu64
                    " msg=0x%016" PRIx64 " flags=0x%016" PRIx64
                    " r8=0x%016" PRIx64 " r10=0x%016" PRIx64,
                    env->ip, call->current, call->arg[0], call->arg[1],
                    call->arg[2], ia64_read_gr(env, 8),
                    ia64_read_gr(env, 10));
            ia64_trace_recvmsg_payload(env, call, retval);
            fprintf(stderr, "\n");
            break;
        case IA64_TRACE_KERNEL_CALL_SENDMSG:
            fprintf(stderr,
                    "[ia64-uevent] sys_sendmsg ret ip=0x%016" PRIx64
                    " current=0x%016" PRIx64 " fd=%" PRIu64
                    " msg=0x%016" PRIx64 " flags=0x%016" PRIx64
                    " r8=0x%016" PRIx64 " r10=0x%016" PRIx64 "\n",
                    env->ip, call->current, call->arg[0], call->arg[1],
                    call->arg[2], ia64_read_gr(env, 8),
                    ia64_read_gr(env, 10));
            break;
        case IA64_TRACE_KERNEL_CALL_SEND:
        {
            char payload[128];

            ia64_trace_guest_bytes_escaped(env, call->arg[1],
                                           MIN(call->arg[2], UINT64_C(32)),
                                           payload, sizeof(payload));
            fprintf(stderr,
                    "[ia64-uevent] sys_send ret ip=0x%016" PRIx64
                    " current=0x%016" PRIx64 " fd=%" PRIu64
                    " buf=0x%016" PRIx64 " len=%" PRIu64
                    " flags=0x%016" PRIx64 " payload=%s"
                    " r8=0x%016" PRIx64 " r10=0x%016" PRIx64 "\n",
                    env->ip, call->current, call->arg[0], call->arg[1],
                    call->arg[2], call->arg[3], payload,
                    ia64_read_gr(env, 8), ia64_read_gr(env, 10));
            break;
        }
        case IA64_TRACE_KERNEL_CALL_RECV:
        {
            char payload[128];

            if (retval > 0) {
                ia64_trace_guest_bytes_escaped(env, call->arg[1],
                                               MIN((uint64_t)retval,
                                                   UINT64_C(32)),
                                               payload, sizeof(payload));
            } else {
                g_strlcpy(payload, "<none>", sizeof(payload));
            }
            fprintf(stderr,
                    "[ia64-uevent] sys_recv ret ip=0x%016" PRIx64
                    " current=0x%016" PRIx64 " fd=%" PRIu64
                    " buf=0x%016" PRIx64 " len=%" PRIu64
                    " flags=0x%016" PRIx64 " payload=%s"
                    " r8=0x%016" PRIx64 " r10=0x%016" PRIx64 "\n",
                    env->ip, call->current, call->arg[0], call->arg[1],
                    call->arg[2], call->arg[3], payload,
                    ia64_read_gr(env, 8), ia64_read_gr(env, 10));
            break;
        }
        case IA64_TRACE_KERNEL_CALL_EPOLL_WAIT:
        {
            char events[512];
            uint64_t event_bytes = 0;

            if (retval > 0) {
                event_bytes = MIN((uint64_t)retval * UINT64_C(16),
                                  UINT64_C(128));
                ia64_trace_guest_bytes_escaped(env, call->arg[1], event_bytes,
                                               events, sizeof(events));
            } else {
                g_strlcpy(events, "<none>", sizeof(events));
            }
            fprintf(stderr,
                    "[ia64-uevent] sys_epoll_wait ret ip=0x%016" PRIx64
                    " current=0x%016" PRIx64 " epfd=%" PRIu64
                    " events=0x%016" PRIx64 " maxevents=%" PRIu64
                    " timeout=%" PRIu64 " event_bytes=%" PRIu64
                    " event_payload=%s r8=0x%016" PRIx64
                    " r10=0x%016" PRIx64 "\n",
                    env->ip, call->current, call->arg[0], call->arg[1],
                    call->arg[2], call->arg[3], event_bytes, events,
                    ia64_read_gr(env, 8), ia64_read_gr(env, 10));
            if (retval > 0) {
                fprintf(stderr, "[ia64-uevent] sys_epoll_wait events"
                        " current=0x%016" PRIx64, call->current);
                ia64_trace_epoll_events(env, call->arg[1], retval);
                fprintf(stderr, "\n");
            }
            break;
        }
        case IA64_TRACE_KERNEL_CALL_EPOLL_CTL:
            fprintf(stderr,
                    "[ia64-uevent] sys_epoll_ctl ret ip=0x%016" PRIx64
                    " current=0x%016" PRIx64 " epfd=%" PRIu64
                    " op=%" PRIu64 " fd=%" PRIu64
                    " event=0x%016" PRIx64
                    " r8=0x%016" PRIx64 " r10=0x%016" PRIx64 "\n",
                    env->ip, call->current, call->arg[0], call->arg[1],
                    call->arg[2], call->arg[3], ia64_read_gr(env, 8),
                    ia64_read_gr(env, 10));
            break;
        case IA64_TRACE_KERNEL_CALL_WAIT4:
            fprintf(stderr,
                    "[ia64-uevent] sys_wait4 ret ip=0x%016" PRIx64
                    " current=0x%016" PRIx64 " pid=0x%016" PRIx64
                    " stat_addr=0x%016" PRIx64 " options=0x%016" PRIx64
                    " ru=0x%016" PRIx64 " r8=0x%016" PRIx64
                    " r10=0x%016" PRIx64 "\n",
                    env->ip, call->current, call->arg[0], call->arg[1],
                    call->arg[2], call->arg[3], ia64_read_gr(env, 8),
                    ia64_read_gr(env, 10));
            break;
        case IA64_TRACE_KERNEL_CALL_KILL:
            fprintf(stderr,
                    "[ia64-uevent] sys_kill ret ip=0x%016" PRIx64
                    " current=0x%016" PRIx64 " pid=0x%016" PRIx64
                    " sig=0x%016" PRIx64 " r8=0x%016" PRIx64
                    " r10=0x%016" PRIx64 "\n",
                    env->ip, call->current, call->arg[0], call->arg[1],
                    ia64_read_gr(env, 8), ia64_read_gr(env, 10));
            break;
        case IA64_TRACE_KERNEL_CALL_POLL:
            fprintf(stderr,
                    "[ia64-uevent] sys_poll ret ip=0x%016" PRIx64
                    " current=0x%016" PRIx64 " ufds=0x%016" PRIx64
                    " nfds=%" PRIu64 " timeout=%" PRIu64
                    " r8=0x%016" PRIx64 " r10=0x%016" PRIx64,
                    env->ip, call->current, call->arg[0], call->arg[1],
                    call->arg[2], ia64_read_gr(env, 8),
                    ia64_read_gr(env, 10));
            if (retval >= 0) {
                ia64_trace_pollfds(env, call->arg[0], call->arg[1]);
            }
            fprintf(stderr, "\n");
            break;
        case IA64_TRACE_KERNEL_CALL_CLOCK_GETTIME:
            fprintf(stderr,
                    "[ia64-uevent] sys_clock_gettime ret ip=0x%016" PRIx64
                    " current=0x%016" PRIx64 " which_clock=%" PRIu64
                    " tp=0x%016" PRIx64 " r8=0x%016" PRIx64
                    " r10=0x%016" PRIx64,
                    env->ip, call->current, call->arg[0], call->arg[1],
                    ia64_read_gr(env, 8), ia64_read_gr(env, 10));
            if (retval == 0) {
                ia64_trace_timespec(env, call->arg[1], "tp");
            }
            fprintf(stderr, "\n");
            break;
        case IA64_TRACE_KERNEL_CALL_MKNOD:
        {
            char path[176];

            ia64_trace_guest_c_string(env, call->arg[0], path, sizeof(path));
            fprintf(stderr,
                    "[ia64-uevent] sys_mknod ret ip=0x%016" PRIx64
                    " current=0x%016" PRIx64 " path=%s mode=0%llo"
                    " dev=0x%016" PRIx64 " r8=0x%016" PRIx64
                    " r10=0x%016" PRIx64 "\n",
                    env->ip, call->current, path,
                    (unsigned long long)call->arg[1], call->arg[2],
                    ia64_read_gr(env, 8), ia64_read_gr(env, 10));
            break;
        }
        case IA64_TRACE_KERNEL_CALL_MKNODAT:
        {
            char path[176];

            ia64_trace_guest_c_string(env, call->arg[1], path, sizeof(path));
            fprintf(stderr,
                    "[ia64-uevent] sys_mknodat ret ip=0x%016" PRIx64
                    " current=0x%016" PRIx64 " dfd=%" PRIu64
                    " path=%s mode=0%llo dev=0x%016" PRIx64
                    " r8=0x%016" PRIx64 " r10=0x%016" PRIx64 "\n",
                    env->ip, call->current, call->arg[0], path,
                    (unsigned long long)call->arg[2], call->arg[3],
                    ia64_read_gr(env, 8), ia64_read_gr(env, 10));
            break;
        }
        case IA64_TRACE_KERNEL_CALL_DOFORK:
            fprintf(stderr,
                    "[ia64-uevent] do_fork ret ip=0x%016" PRIx64
                    " current=0x%016" PRIx64 " clone_flags=0x%016" PRIx64
                    " stack=0x%016" PRIx64 " r8=0x%016" PRIx64
                    " r10=0x%016" PRIx64 "\n",
                    env->ip, call->current, call->arg[0], call->arg[1],
                    ia64_read_gr(env, 8), ia64_read_gr(env, 10));
            break;
        case IA64_TRACE_KERNEL_CALL_NETLINK_RECVMSG:
            fprintf(stderr,
                    "[ia64-uevent] netlink_recvmsg ret ip=0x%016" PRIx64
                    " current=0x%016" PRIx64 " kiocb=0x%016" PRIx64
                    " sock=0x%016" PRIx64 " sk=0x%016" PRIx64
                    " msg=0x%016" PRIx64 " len=%" PRIu64
                    " flags=0x%016" PRIx64 " r8=0x%016" PRIx64
                    " r10=0x%016" PRIx64 "\n",
                    env->ip, call->current, call->arg[0], call->arg[1],
                    ia64_trace_socket_sk(env, call->arg[1]), call->arg[2],
                    call->arg[3], call->arg[4], ia64_read_gr(env, 8),
                    ia64_read_gr(env, 10));
            break;
        case IA64_TRACE_KERNEL_CALL_NETLINK_SENDMSG:
            fprintf(stderr,
                    "[ia64-uevent] netlink_sendmsg ret ip=0x%016" PRIx64
                    " current=0x%016" PRIx64 " kiocb=0x%016" PRIx64
                    " sock=0x%016" PRIx64 " sk=0x%016" PRIx64
                    " msg=0x%016" PRIx64 " len=%" PRIu64
                    " r8=0x%016" PRIx64 " r10=0x%016" PRIx64 "\n",
                    env->ip, call->current, call->arg[0], call->arg[1],
                    ia64_trace_socket_sk(env, call->arg[1]), call->arg[2],
                    call->arg[3], ia64_read_gr(env, 8),
                    ia64_read_gr(env, 10));
            break;
        case IA64_TRACE_KERNEL_CALL_NETLINK_UNICAST:
            fprintf(stderr,
                    "[ia64-uevent] netlink_unicast ret ip=0x%016" PRIx64
                    " current=0x%016" PRIx64 " ssk=0x%016" PRIx64
                    " skb=0x%016" PRIx64 " pid=%" PRIu64
                    " nonblock=0x%016" PRIx64 " r8=0x%016" PRIx64
                    " r10=0x%016" PRIx64 "\n",
                    env->ip, call->current, call->arg[0], call->arg[1],
                    call->arg[2], call->arg[3], ia64_read_gr(env, 8),
                    ia64_read_gr(env, 10));
            break;
        case IA64_TRACE_KERNEL_CALL_NETLINK_ATTACHSKB:
            fprintf(stderr,
                    "[ia64-uevent] netlink_attachskb ret ip=0x%016" PRIx64
                    " current=0x%016" PRIx64 " sk=0x%016" PRIx64
                    " skb=0x%016" PRIx64 " timeo=0x%016" PRIx64
                    " ssk=0x%016" PRIx64 " r8=0x%016" PRIx64
                    " r10=0x%016" PRIx64 "\n",
                    env->ip, call->current, call->arg[0], call->arg[1],
                    call->arg[2], call->arg[3], ia64_read_gr(env, 8),
                    ia64_read_gr(env, 10));
            break;
        case IA64_TRACE_KERNEL_CALL_NETLINK_SENDSKB:
            fprintf(stderr,
                    "[ia64-uevent] netlink_sendskb ret ip=0x%016" PRIx64
                    " current=0x%016" PRIx64 " sk=0x%016" PRIx64
                    " skb=0x%016" PRIx64 " r8=0x%016" PRIx64
                    " r10=0x%016" PRIx64 "\n",
                    env->ip, call->current, call->arg[0], call->arg[1],
                    ia64_read_gr(env, 8), ia64_read_gr(env, 10));
            break;
        case IA64_TRACE_KERNEL_CALL_NETLINK_BROADCAST_FILTERED:
            fprintf(stderr,
                    "[ia64-uevent] netlink_broadcast_filtered ret"
                    " ip=0x%016" PRIx64 " current=0x%016" PRIx64
                    " ssk=0x%016" PRIx64 " skb=0x%016" PRIx64
                    " pid=%" PRIu64 " group=%" PRIu64
                    " allocation=0x%016" PRIx64 " filter=0x%016" PRIx64
                    " data=0x%016" PRIx64 " r8=0x%016" PRIx64
                    " r10=0x%016" PRIx64 "\n",
                    env->ip, call->current, call->arg[0], call->arg[1],
                    call->arg[2], call->arg[3], call->arg[4], call->arg[5],
                    call->arg[6], ia64_read_gr(env, 8),
                    ia64_read_gr(env, 10));
            break;
        default:
            break;
        }
        call->active = false;
        return;
    }

    if (env->ip == UINT64_C(0xa0000001003d7ee0)) {
        fprintf(stderr,
            "[ia64-uevent] kobject_uevent_env kobj=0x%016" PRIx64
            " action=%" PRIu64 " envp=0x%016" PRIx64
            " current=0x%016" PRIx64 " b0=0x%016" PRIx64 "\n",
            ia64_read_gr(env, 32), ia64_read_gr(env, 33),
            ia64_read_gr(env, 34), ia64_read_gr(env, 13), env->br[0]);
        return;
    }

    if (env->ip == UINT64_C(0xa0000001000929a0)) {
        fprintf(stderr,
                "[ia64-uevent] do_exit current=0x%016" PRIx64
                " code=0x%016" PRIx64 " b0=0x%016" PRIx64 "\n",
                ia64_read_gr(env, 13), ia64_read_gr(env, 32), env->br[0]);
        return;
    }

    if (env->ip == UINT64_C(0xa000000100087360)) {
        ia64_trace_record_kernel_call(env, IA64_TRACE_KERNEL_CALL_DOFORK);
        fprintf(stderr,
                "[ia64-uevent] do_fork entry current=0x%016" PRIx64
                " clone_flags=0x%016" PRIx64 " stack=0x%016" PRIx64
                " regs=0x%016" PRIx64 " stack_size=0x%016" PRIx64
                " parent_tid=0x%016" PRIx64 " child_tid=0x%016" PRIx64
                " b0=0x%016" PRIx64 "\n",
                ia64_read_gr(env, 13), ia64_read_gr(env, 32),
                ia64_read_gr(env, 33), ia64_read_gr(env, 34),
                ia64_read_gr(env, 35), ia64_read_gr(env, 36),
                ia64_read_gr(env, 37), env->br[0]);
        return;
    }

    if (env->ip == UINT64_C(0xa0000001005f9630)) {
        ia64_trace_record_kernel_call(env, IA64_TRACE_KERNEL_CALL_RECVMSG);
        fprintf(stderr,
                "[ia64-uevent] sys_recvmsg entry current=0x%016" PRIx64
                " fd=%" PRIu64 " msg=0x%016" PRIx64
                " flags=0x%016" PRIx64 " b0=0x%016" PRIx64 "\n",
                ia64_read_gr(env, 13), ia64_read_gr(env, 32),
                ia64_read_gr(env, 33), ia64_read_gr(env, 34), env->br[0]);
        return;
    }

    if (env->ip == UINT64_C(0xa0000001005f9200)) {
        ia64_trace_record_kernel_call(env, IA64_TRACE_KERNEL_CALL_SENDMSG);
        fprintf(stderr,
                "[ia64-uevent] sys_sendmsg entry current=0x%016" PRIx64
                " fd=%" PRIu64 " msg=0x%016" PRIx64
                " flags=0x%016" PRIx64 " b0=0x%016" PRIx64,
                ia64_read_gr(env, 13), ia64_read_gr(env, 32),
                ia64_read_gr(env, 33), ia64_read_gr(env, 34), env->br[0]);
        ia64_trace_msghdr_name(env, ia64_read_gr(env, 33));
        ia64_trace_msghdr_iovs(env, ia64_read_gr(env, 33), 2, 220);
        fprintf(stderr, "\n");
        return;
    }

    if (env->ip == UINT64_C(0xa0000001005f8970)) {
        char payload[128];

        ia64_trace_record_kernel_call(env, IA64_TRACE_KERNEL_CALL_SEND);
        ia64_trace_guest_bytes_escaped(env, ia64_read_gr(env, 33),
                                       MIN(ia64_read_gr(env, 34),
                                           UINT64_C(32)),
                                       payload, sizeof(payload));
        fprintf(stderr,
                "[ia64-uevent] sys_send entry current=0x%016" PRIx64
                " fd=%" PRIu64 " buf=0x%016" PRIx64 " len=%" PRIu64
                " flags=0x%016" PRIx64 " payload=%s"
                " b0=0x%016" PRIx64 "\n",
                ia64_read_gr(env, 13), ia64_read_gr(env, 32),
                ia64_read_gr(env, 33), ia64_read_gr(env, 34),
                ia64_read_gr(env, 35), payload, env->br[0]);
        return;
    }

    if (env->ip == UINT64_C(0xa0000001005f8c00)) {
        ia64_trace_record_kernel_call(env, IA64_TRACE_KERNEL_CALL_RECV);
        fprintf(stderr,
                "[ia64-uevent] sys_recv entry current=0x%016" PRIx64
                " fd=%" PRIu64 " buf=0x%016" PRIx64 " len=%" PRIu64
                " flags=0x%016" PRIx64 " b0=0x%016" PRIx64 "\n",
                ia64_read_gr(env, 13), ia64_read_gr(env, 32),
                ia64_read_gr(env, 33), ia64_read_gr(env, 34),
                ia64_read_gr(env, 35), env->br[0]);
        return;
    }

    if (env->ip == UINT64_C(0xa000000100286880)) {
        ia64_trace_record_kernel_call(env, IA64_TRACE_KERNEL_CALL_EPOLL_WAIT);
        fprintf(stderr,
                "[ia64-uevent] sys_epoll_wait entry current=0x%016" PRIx64
                " epfd=%" PRIu64 " events=0x%016" PRIx64
                " maxevents=%" PRIu64 " timeout=%" PRIu64
                " b0=0x%016" PRIx64 "\n",
                ia64_read_gr(env, 13), ia64_read_gr(env, 32),
                ia64_read_gr(env, 33), ia64_read_gr(env, 34),
                ia64_read_gr(env, 35), env->br[0]);
        return;
    }

    if (env->ip == UINT64_C(0xa0000001002857d0)) {
        uint64_t event = ia64_read_gr(env, 35);

        ia64_trace_record_kernel_call(env, IA64_TRACE_KERNEL_CALL_EPOLL_CTL);
        fprintf(stderr,
                "[ia64-uevent] sys_epoll_ctl entry current=0x%016" PRIx64
                " epfd=%" PRIu64 " op=%" PRIu64 " fd=%" PRIu64
                " event=0x%016" PRIx64 " b0=0x%016" PRIx64,
                ia64_read_gr(env, 13), ia64_read_gr(env, 32),
                ia64_read_gr(env, 33), ia64_read_gr(env, 34), event,
                env->br[0]);
        if (event != 0 && ia64_read_gr(env, 33) != 2) {
            ia64_trace_epoll_event(env, event, "event");
        }
        fprintf(stderr, "\n");
        return;
    }

    if (env->ip == UINT64_C(0xa0000001000947d0)) {
        ia64_trace_record_kernel_call(env, IA64_TRACE_KERNEL_CALL_WAIT4);
        fprintf(stderr,
                "[ia64-uevent] sys_wait4 entry current=0x%016" PRIx64
                " pid=0x%016" PRIx64 " stat_addr=0x%016" PRIx64
                " options=0x%016" PRIx64 " ru=0x%016" PRIx64
                " b0=0x%016" PRIx64 "\n",
                ia64_read_gr(env, 13), ia64_read_gr(env, 32),
                ia64_read_gr(env, 33), ia64_read_gr(env, 34),
                ia64_read_gr(env, 35), env->br[0]);
        return;
    }

    if (env->ip == UINT64_C(0xa0000001000ae3d0)) {
        ia64_trace_record_kernel_call(env, IA64_TRACE_KERNEL_CALL_KILL);
        fprintf(stderr,
                "[ia64-uevent] sys_kill entry current=0x%016" PRIx64
                " pid=0x%016" PRIx64 " sig=0x%016" PRIx64
                " b0=0x%016" PRIx64 "\n",
                ia64_read_gr(env, 13), ia64_read_gr(env, 32),
                ia64_read_gr(env, 33), env->br[0]);
        return;
    }

    if (env->ip == UINT64_C(0xa0000001002233a0)) {
        ia64_trace_record_kernel_call(env, IA64_TRACE_KERNEL_CALL_POLL);
        fprintf(stderr,
                "[ia64-uevent] sys_poll entry current=0x%016" PRIx64
                " ufds=0x%016" PRIx64 " nfds=%" PRIu64
                " timeout=%" PRIu64 " b0=0x%016" PRIx64,
                ia64_read_gr(env, 13), ia64_read_gr(env, 32),
                ia64_read_gr(env, 33), ia64_read_gr(env, 34), env->br[0]);
        ia64_trace_pollfds(env, ia64_read_gr(env, 32),
                           ia64_read_gr(env, 33));
        fprintf(stderr, "\n");
        return;
    }

    if (env->ip == UINT64_C(0xa0000001000c66f0)) {
        ia64_trace_record_kernel_call(
            env, IA64_TRACE_KERNEL_CALL_CLOCK_GETTIME);
        fprintf(stderr,
                "[ia64-uevent] sys_clock_gettime entry"
                " current=0x%016" PRIx64 " which_clock=%" PRIu64
                " tp=0x%016" PRIx64 " b0=0x%016" PRIx64 "\n",
                ia64_read_gr(env, 13), ia64_read_gr(env, 32),
                ia64_read_gr(env, 33), env->br[0]);
        return;
    }

    if (env->ip == UINT64_C(0xa00000010021ad80)) {
        char path[176];

        ia64_trace_record_kernel_call(env, IA64_TRACE_KERNEL_CALL_MKNOD);
        ia64_trace_guest_c_string(env, ia64_read_gr(env, 32), path,
                                  sizeof(path));
        fprintf(stderr,
                "[ia64-uevent] sys_mknod entry current=0x%016" PRIx64
                " path=%s mode=0%llo dev=0x%016" PRIx64
                " b0=0x%016" PRIx64 "\n",
                ia64_read_gr(env, 13), path,
                (unsigned long long)ia64_read_gr(env, 33),
                ia64_read_gr(env, 34), env->br[0]);
        return;
    }

    if (env->ip == UINT64_C(0xa00000010021a8a0)) {
        char path[176];

        ia64_trace_record_kernel_call(env, IA64_TRACE_KERNEL_CALL_MKNODAT);
        ia64_trace_guest_c_string(env, ia64_read_gr(env, 33), path,
                                  sizeof(path));
        fprintf(stderr,
                "[ia64-uevent] sys_mknodat entry current=0x%016" PRIx64
                " dfd=%" PRIu64 " path=%s mode=0%llo"
                " dev=0x%016" PRIx64 " b0=0x%016" PRIx64 "\n",
                ia64_read_gr(env, 13), ia64_read_gr(env, 32), path,
                (unsigned long long)ia64_read_gr(env, 34),
                ia64_read_gr(env, 35), env->br[0]);
        return;
    }

    if (env->ip == UINT64_C(0xa000000100675e70)) {
        uint64_t sock = ia64_read_gr(env, 33);

        ia64_trace_record_kernel_call(
            env, IA64_TRACE_KERNEL_CALL_NETLINK_RECVMSG);
        fprintf(stderr,
                "[ia64-uevent] netlink_recvmsg entry current=0x%016" PRIx64
                " kiocb=0x%016" PRIx64 " sock=0x%016" PRIx64
                " sk=0x%016" PRIx64 " msg=0x%016" PRIx64
                " len=%" PRIu64 " flags=0x%016" PRIx64
                " b0=0x%016" PRIx64,
                ia64_read_gr(env, 13), ia64_read_gr(env, 32), sock,
                ia64_trace_socket_sk(env, sock), ia64_read_gr(env, 34),
                ia64_read_gr(env, 35), ia64_read_gr(env, 36), env->br[0]);
        ia64_trace_msghdr_name(env, ia64_read_gr(env, 34));
        fprintf(stderr, "\n");
        return;
    }

    if (env->ip == UINT64_C(0xa00000010067a360)) {
        uint64_t sock = ia64_read_gr(env, 33);

        ia64_trace_record_kernel_call(
            env, IA64_TRACE_KERNEL_CALL_NETLINK_SENDMSG);
        fprintf(stderr,
                "[ia64-uevent] netlink_sendmsg entry current=0x%016" PRIx64
                " kiocb=0x%016" PRIx64 " sock=0x%016" PRIx64
                " sk=0x%016" PRIx64 " msg=0x%016" PRIx64
                " len=%" PRIu64 " b0=0x%016" PRIx64,
                ia64_read_gr(env, 13), ia64_read_gr(env, 32), sock,
                ia64_trace_socket_sk(env, sock), ia64_read_gr(env, 34),
                ia64_read_gr(env, 35), env->br[0]);
        ia64_trace_msghdr_name(env, ia64_read_gr(env, 34));
        ia64_trace_msghdr_iovs(env, ia64_read_gr(env, 34), 2, 220);
        fprintf(stderr, "\n");
        return;
    }

    if (env->ip == UINT64_C(0xa000000100679b10)) {
        ia64_trace_record_kernel_call(
            env, IA64_TRACE_KERNEL_CALL_NETLINK_UNICAST);
        fprintf(stderr,
                "[ia64-uevent] netlink_unicast entry current=0x%016" PRIx64
                " ssk=0x%016" PRIx64 " skb=0x%016" PRIx64
                " pid=%" PRIu64 " nonblock=0x%016" PRIx64
                " b0=0x%016" PRIx64 "\n",
                ia64_read_gr(env, 13), ia64_read_gr(env, 32),
                ia64_read_gr(env, 33), ia64_read_gr(env, 34),
                ia64_read_gr(env, 35), env->br[0]);
        return;
    }

    if (env->ip == UINT64_C(0xa000000100679600)) {
        ia64_trace_record_kernel_call(
            env, IA64_TRACE_KERNEL_CALL_NETLINK_ATTACHSKB);
        fprintf(stderr,
                "[ia64-uevent] netlink_attachskb entry current=0x%016" PRIx64
                " sk=0x%016" PRIx64 " skb=0x%016" PRIx64
                " timeo=0x%016" PRIx64 " ssk=0x%016" PRIx64
                " b0=0x%016" PRIx64 "\n",
                ia64_read_gr(env, 13), ia64_read_gr(env, 32),
                ia64_read_gr(env, 33), ia64_read_gr(env, 34),
                ia64_read_gr(env, 35), env->br[0]);
        return;
    }

    if (env->ip == UINT64_C(0xa000000100679a50)) {
        ia64_trace_record_kernel_call(
            env, IA64_TRACE_KERNEL_CALL_NETLINK_SENDSKB);
        fprintf(stderr,
                "[ia64-uevent] netlink_sendskb entry current=0x%016" PRIx64
                " sk=0x%016" PRIx64 " skb=0x%016" PRIx64
                " b0=0x%016" PRIx64 "\n",
                ia64_read_gr(env, 13), ia64_read_gr(env, 32),
                ia64_read_gr(env, 33), env->br[0]);
        return;
    }

    if (env->ip == UINT64_C(0xa0000001005fba40)) {
        fprintf(stderr,
                "[ia64-uevent] sock_def_readable current=0x%016" PRIx64
                " sk=0x%016" PRIx64 " len=%" PRIu64
                " b0=0x%016" PRIx64 "\n",
                ia64_read_gr(env, 13), ia64_read_gr(env, 32),
                ia64_read_gr(env, 33), env->br[0]);
        return;
    }

    if (env->ip == UINT64_C(0xa000000100285150)) {
        fprintf(stderr,
                "[ia64-uevent] ep_poll_callback current=0x%016" PRIx64
                " wait=0x%016" PRIx64 " mode=0x%016" PRIx64
                " sync=0x%016" PRIx64 " key=0x%016" PRIx64
                " b0=0x%016" PRIx64 "\n",
                ia64_read_gr(env, 13), ia64_read_gr(env, 32),
                ia64_read_gr(env, 33), ia64_read_gr(env, 34),
                ia64_read_gr(env, 35), env->br[0]);
        return;
    }

    if (env->ip == UINT64_C(0xa000000100677690)) {
        fprintf(stderr,
            "[ia64-uevent] netlink_broadcast entry ssk=0x%016" PRIx64
            " skb=0x%016" PRIx64 " pid=%" PRIu64 " group=%" PRIu64
            " allocation=0x%016" PRIx64 " current=0x%016" PRIx64
            " b0=0x%016" PRIx64 "\n",
            ia64_read_gr(env, 32), ia64_read_gr(env, 33),
            ia64_read_gr(env, 34), ia64_read_gr(env, 35),
            ia64_read_gr(env, 36), ia64_read_gr(env, 13), env->br[0]);
        return;
    }

    if (env->ip == UINT64_C(0xa000000100676d80)) {
        ia64_trace_record_kernel_call(
            env, IA64_TRACE_KERNEL_CALL_NETLINK_BROADCAST_FILTERED);
        fprintf(stderr,
                "[ia64-uevent] netlink_broadcast_filtered entry"
                " ssk=0x%016" PRIx64 " skb=0x%016" PRIx64
            " pid=%" PRIu64 " group=%" PRIu64
            " allocation=0x%016" PRIx64 " filter=0x%016" PRIx64
            " data=0x%016" PRIx64 " current=0x%016" PRIx64
            " b0=0x%016" PRIx64 "\n",
            ia64_read_gr(env, 32), ia64_read_gr(env, 33),
            ia64_read_gr(env, 34), ia64_read_gr(env, 35),
            ia64_read_gr(env, 36), ia64_read_gr(env, 37),
            ia64_read_gr(env, 38), ia64_read_gr(env, 13), env->br[0]);
        return;
    }
}

static void ia64_count_fast_tcg_ops(uint32_t slot_count, uint32_t op_counts,
                                    bool count_bundle)
{
    if (count_bundle) {
        IA64_PERF_INC(IA64_PERF_TCG_FAST_BUNDLE);
    }
    IA64_PERF_ADD(IA64_PERF_TCG_FAST_SLOT, slot_count);
    IA64_PERF_ADD(IA64_PERF_TCG_FAST_NOP,
                  ia64_perf_fast_count(op_counts,
                                       IA64_PERF_FAST_COUNT_NOP_SHIFT));
    IA64_PERF_ADD(IA64_PERF_TCG_FAST_ALU_ADD,
                  ia64_perf_fast_count(op_counts,
                                       IA64_PERF_FAST_COUNT_ALU_ADD_SHIFT));
    IA64_PERF_ADD(IA64_PERF_TCG_FAST_ALU_LOGIC,
                  ia64_perf_fast_count(op_counts,
                                       IA64_PERF_FAST_COUNT_ALU_LOGIC_SHIFT));
    IA64_PERF_ADD(IA64_PERF_TCG_FAST_ADDL,
                  ia64_perf_fast_count(op_counts,
                                       IA64_PERF_FAST_COUNT_ADDL_SHIFT));
    IA64_PERF_ADD(IA64_PERF_TCG_FAST_COMPARE,
                  ia64_perf_fast_count(op_counts,
                                       IA64_PERF_FAST_COUNT_COMPARE_SHIFT));
    IA64_PERF_ADD(IA64_PERF_TCG_FAST_INTEGER_MISC,
                  ia64_perf_fast_count(op_counts,
                                       IA64_PERF_FAST_COUNT_INTEGER_MISC_SHIFT));
    IA64_PERF_ADD(IA64_PERF_TCG_LDST_LOAD,
                  ia64_perf_fast_count(op_counts,
                                       IA64_PERF_FAST_COUNT_LDST_LOAD_SHIFT));
    IA64_PERF_ADD(IA64_PERF_TCG_LDST_STORE,
                  ia64_perf_fast_count(op_counts,
                                       IA64_PERF_FAST_COUNT_LDST_STORE_SHIFT));
}

void HELPER(start_fast_bundle)(CPUIA64State *env, uint32_t slot_count,
                               uint32_t op_counts)
{
    CPUState *cpu = env_cpu(env);

    IA64_PERF_INC(IA64_PERF_BUNDLE_EXECUTED);
    ia64_count_fast_tcg_ops(slot_count, op_counts, true);

    cpu->neg.can_do_io = true;
    ia64_trace_execve(env);
    ia64_trace_epc_syscall(env);
    ia64_trace_syscall_return(env);
    ia64_trace_uevent_netlink(env);
    ia64_maybe_apply_linux_cmdline_append(env);
    ia64_progress_trace_bundle(env);
    ia64_state_trace_bundle(env);
}

void HELPER(finish_fast_bundle)(CPUIA64State *env, uint64_t next_ip,
                                uint64_t dest_mask)
{
    for (unsigned reg = 1; reg < 64; reg++) {
        if (dest_mask & (1ULL << reg)) {
            ia64_alat_invalidate_gr(env, reg);
        }
    }
    env->gr[0] = 0;
    ia64_finish_bundle(env, next_ip, 0);
}

void HELPER(finish_fast_store)(CPUIA64State *env, uint64_t address,
                               uint32_t width)
{
    ia64_alat_invalidate_store(env, address, width);
}

static void ia64_flush_qemu_tlb_for_page(CPUState *cpu, vaddr address,
                                         uint8_t page_size)
{
    vaddr start;
    uint64_t len;

    /*
     * QEMU's softmmu TLB is keyed by virtual page and mmu_idx; IA-64 RIDs live
     * in target RR/TC state.  Any modeled TC/TR change for a VA can therefore
     * stale a direct qemu_ld/qemu_st mapping even when the new RID is distinct.
     */
    if (ia64_host_tlb_flush_span(address, page_size, &start, &len)) {
        tlb_flush_range_by_mmuidx(cpu, start, len, IA64_MMU_ALL_IDXMAP,
                                  TARGET_LONG_BITS);
        IA64_PERF_INC(IA64_PERF_QEMU_TLB_FLUSH_RANGE);
        return;
    }

    tlb_flush(cpu);
    IA64_PERF_INC(IA64_PERF_QEMU_TLB_FLUSH_FULL);
}

uint32_t HELPER(finish_direct_branch_bundle)(CPUIA64State *env,
                                             uint64_t next_ip,
                                             uint32_t taken,
                                             uint32_t prefix_slot_count,
                                             uint32_t prefix_op_counts,
                                             uint64_t prefix_dest_mask)
{
    CPUState *cpu = env_cpu(env);
    bool chain_ok;

    IA64_PERF_INC(IA64_PERF_BUNDLE_EXECUTED);
    IA64_PERF_INC(IA64_PERF_TCG_BRANCH_DIRECT_TRANSLATED);
    ia64_count_fast_tcg_ops(prefix_slot_count, prefix_op_counts, false);
    IA64_PERF_INC(IA64_PERF_OP_BRANCH_DIRECT);
    IA64_PERF_INC(taken ? IA64_PERF_BRANCH_TAKEN :
                           IA64_PERF_BRANCH_FALLTHROUGH);
    IA64_PERF_INC(IA64_PERF_TB_EXIT_DIRECT_BRANCH);

    cpu->neg.can_do_io = true;
    ia64_trace_execve(env);
    ia64_trace_uevent_netlink(env);
    ia64_maybe_apply_linux_cmdline_append(env);
    ia64_progress_trace_bundle(env);
    ia64_state_trace_bundle(env);

    for (unsigned reg = 1; reg < 64; reg++) {
        if (prefix_dest_mask & (1ULL << reg)) {
            ia64_alat_invalidate_gr(env, reg);
        }
    }
    env->gr[0] = 0;
    ia64_finish_bundle(env, next_ip, 0);

    chain_ok = ia64_tcg_can_chain(env);
    IA64_PERF_INC(chain_ok ? IA64_PERF_TB_EXIT_CHAINED :
                             IA64_PERF_TB_EXIT_MAIN_LOOP);
    return chain_ok ? 1 : 0;
}

typedef enum IA64PlannedSlotResult {
    IA64_PLANNED_SLOT_GENERIC,
    IA64_PLANNED_SLOT_CONTINUE,
    IA64_PLANNED_SLOT_BREAK,
} IA64PlannedSlotResult;

static IA64PlannedSlotResult exec_predecoded_slot(
    CPUIA64State *env, const IA64DecodedBundle *decoded, int slot,
    IA64SlotType type, uint64_t raw, IA64TcgFallbackPlanOp op,
    uint64_t *next_ip, unsigned *next_ri)
{
    switch (op) {
    case IA64_TCG_FALLBACK_PLAN_GENERIC:
        return IA64_PLANNED_SLOT_GENERIC;
    case IA64_TCG_FALLBACK_PLAN_ALLOC:
        IA64_PERF_INC(IA64_PERF_OP_ALLOC);
        ia64_exec_m34_alloc(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_MOV_FROM_BRANCH:
        IA64_PERF_INC(IA64_PERF_OP_BRANCH_REGISTER);
        ia64_exec_i_mov_from_branch(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_MOV_TO_BRANCH:
        IA64_PERF_INC(IA64_PERF_OP_BRANCH_REGISTER);
        ia64_exec_i_mov_to_branch(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_MOV_TO_APPLICATION:
        IA64_PERF_INC(IA64_PERF_OP_APPLICATION_REGISTER);
        ia64_exec_mov_to_application(env, type, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_MOV_FROM_APPLICATION:
        IA64_PERF_INC(IA64_PERF_OP_APPLICATION_REGISTER);
        ia64_exec_mov_from_application(env, type, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_MOV_TO_APPLICATION_IMM:
        IA64_PERF_INC(IA64_PERF_OP_APPLICATION_REGISTER);
        ia64_exec_mov_to_application_immediate(env, type, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_EXTRACT: {
        IA64ExtractInstruction extract;

        if (!ia64_decode_extract(type, raw, &extract) ||
            !ia64_exec_extract(env, &extract)) {
            return IA64_PLANNED_SLOT_GENERIC;
        }
        IA64_PERF_INC(IA64_PERF_OP_EXTRACT_DEPOSIT);
        return IA64_PLANNED_SLOT_CONTINUE;
    }
    case IA64_TCG_FALLBACK_PLAN_DEPOSIT: {
        IA64DepositInstruction deposit;

        if (!ia64_decode_deposit(type, raw, &deposit) ||
            !ia64_exec_deposit(env, &deposit)) {
            return IA64_PLANNED_SLOT_GENERIC;
        }
        IA64_PERF_INC(IA64_PERF_OP_EXTRACT_DEPOSIT);
        return IA64_PLANNED_SLOT_CONTINUE;
    }
    case IA64_TCG_FALLBACK_PLAN_INTEGER_EXTEND: {
        IA64IntegerExtendInstruction int_ext;

        if (!ia64_decode_integer_extend(type, raw, &int_ext) ||
            !ia64_exec_integer_extend(env, &int_ext)) {
            return IA64_PLANNED_SLOT_GENERIC;
        }
        IA64_PERF_INC(IA64_PERF_OP_SHIFT_EXTEND);
        return IA64_PLANNED_SLOT_CONTINUE;
    }
    case IA64_TCG_FALLBACK_PLAN_FLOATING_MEMORY: {
        IA64FloatingMemoryInstruction fldst;

        if (!ia64_decode_floating_memory(type, raw, &fldst) ||
            !exec_floating_memory(env, &fldst)) {
            return IA64_PLANNED_SLOT_GENERIC;
        }
        IA64_PERF_INC(IA64_PERF_OP_FLOAT_MEMORY);
        return IA64_PLANNED_SLOT_CONTINUE;
    }
    case IA64_TCG_FALLBACK_PLAN_LDST_IMMEDIATE: {
        IA64LdstImmediate ldst;

        if (!ia64_decode_ldst_immediate(type, raw, &ldst) ||
            !exec_ldst_immediate(env, &ldst)) {
            return IA64_PLANNED_SLOT_GENERIC;
        }
        switch (ldst.kind) {
        case IA64_LDST_IMM_LOAD:
            IA64_PERF_INC(IA64_PERF_OP_LOAD);
            break;
        case IA64_LDST_IMM_STORE:
            IA64_PERF_INC(IA64_PERF_OP_STORE);
            break;
        case IA64_LDST_IMM_PREFETCH:
            IA64_PERF_INC(IA64_PERF_OP_PREFETCH);
            break;
        default:
            break;
        }
        return IA64_PLANNED_SLOT_CONTINUE;
    }
    case IA64_TCG_FALLBACK_PLAN_COMPARE: {
        IA64CompareInstruction cmp;

        if (!ia64_decode_compare(type, raw, &cmp) ||
            !ia64_exec_compare(env, &cmp)) {
            return IA64_PLANNED_SLOT_GENERIC;
        }
        IA64_PERF_INC(IA64_PERF_OP_COMPARE);
        return IA64_PLANNED_SLOT_CONTINUE;
    }
    case IA64_TCG_FALLBACK_PLAN_PREDICATE_TEST: {
        IA64PredicateTestInstruction pred_test;

        if (!ia64_decode_predicate_test(type, raw, &pred_test) ||
            !ia64_exec_predicate_test(env, &pred_test)) {
            return IA64_PLANNED_SLOT_GENERIC;
        }
        IA64_PERF_INC(IA64_PERF_OP_PREDICATE_TEST);
        if (pred_test.kind == IA64_PRED_TEST_NAT) {
            IA64_PERF_INC(IA64_PERF_OP_NAT_TEST);
        }
        return IA64_PLANNED_SLOT_CONTINUE;
    }
    case IA64_TCG_FALLBACK_PLAN_ALU_ADD:
        IA64_PERF_INC(IA64_PERF_OP_ALU);
        ia64_exec_alu_add(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_ALU_SUB:
        IA64_PERF_INC(IA64_PERF_OP_ALU);
        ia64_exec_alu_sub(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_ALU_LOGIC:
        IA64_PERF_INC(IA64_PERF_OP_ALU);
        ia64_exec_alu_logic(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_ALU_ADDP4:
        IA64_PERF_INC(IA64_PERF_OP_ALU);
        ia64_exec_alu_addp4(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_ALU_SHLADD:
        IA64_PERF_INC(IA64_PERF_OP_ALU);
        ia64_exec_alu_shladd(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_I_PACKED_I2:
        IA64_PERF_INC(IA64_PERF_OP_ALU);
        ia64_exec_i_packed_i2(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_I_MUX:
        IA64_PERF_INC(IA64_PERF_OP_ALU);
        ia64_exec_i_mux(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_I_BIT_COUNT:
        IA64_PERF_INC(IA64_PERF_OP_ALU);
        ia64_exec_i_bit_count(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_I_VARIABLE_SHIFT:
        IA64_PERF_INC(IA64_PERF_OP_ALU);
        ia64_exec_i_variable_shift(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_ADDL:
        IA64_PERF_INC(IA64_PERF_OP_ADDL);
        ia64_exec_addl(env, raw);
        return IA64_PLANNED_SLOT_CONTINUE;
    case IA64_TCG_FALLBACK_PLAN_BRANCH_RELATIVE: {
        bool branch_taken = false;

        IA64_PERF_INC(IA64_PERF_OP_BRANCH_DIRECT);
        ia64_exec_b_branch_relative(env, raw, env->ip, next_ip,
                                    &branch_taken);
        if (*next_ip == 0) {
            abort_zero_branch(env, decoded, slot);
        }
        if (branch_taken || *next_ip != env->ip + IA64_BUNDLE_SIZE) {
            IA64_PERF_INC(IA64_PERF_BRANCH_TAKEN);
            return IA64_PLANNED_SLOT_BREAK;
        }
        IA64_PERF_INC(IA64_PERF_BRANCH_FALLTHROUGH);
        return IA64_PLANNED_SLOT_CONTINUE;
    }
    case IA64_TCG_FALLBACK_PLAN_BRANCH_CALL_RELATIVE:
        IA64_PERF_INC(IA64_PERF_OP_BRANCH_CALL);
        IA64_PERF_INC(IA64_PERF_BRANCH_TAKEN);
        ia64_exec_b_call_relative(env, raw, env->ip, next_ip);
        if (*next_ip == 0) {
            abort_zero_branch(env, decoded, slot);
        }
        return IA64_PLANNED_SLOT_BREAK;
    case IA64_TCG_FALLBACK_PLAN_BRANCH_INDIRECT: {
        uint8_t branch_major = ia64_slot_major_opcode(raw);
        uint8_t branch_x6 = (raw >> 27) & 0x3f;
        bool rfi = branch_major == 0x0 && branch_x6 == 0x08;
        bool rfi_valid_ifs =
            rfi && (env->cr[IA64_CR_IFS] & IA64_IFS_VALID_BIT) != 0;
        bool br_ret = branch_major == 0x0 && branch_x6 == 0x21;
        bool cover = branch_major == 0x0 && branch_x6 == 0x02;
        bool epc = branch_major == 0x0 && branch_x6 == 0x10;
        uint64_t old_psr = env->psr;

        IA64_PERF_INC(IA64_PERF_OP_BRANCH_INDIRECT);
        IA64_PERF_INC(IA64_PERF_BRANCH_TAKEN);
        if (cover) {
            IA64_PERF_INC(IA64_PERF_TRANSITION_COVER);
        }
        if (epc) {
            IA64_PERF_INC(IA64_PERF_TRANSITION_EPC);
        }
        ia64_exec_b_indirect_branch(env, raw, env->ip, next_ip);
        if (br_ret) {
            ia64_rse_maybe_fill_restored_frame(env,
                                               (env->cfm >> 7) & 0x7f);
        }
        if (rfi_valid_ifs) {
            IA64_PERF_INC(IA64_PERF_TRANSITION_RFI_VALID_IFS);
            ia64_rse_maybe_fill_restored_frame(env, env->rse.sof);
        }
        if (rfi) {
            IA64_PERF_INC(IA64_PERF_TRANSITION_RFI);
            IA64_PERF_INC(ia64_helper_psr_cpl(env->psr) == 3 ?
                          IA64_PERF_TRANSITION_RFI_TO_USER :
                          IA64_PERF_TRANSITION_RFI_TO_KERNEL);
            *next_ri = ia64_psr_ri(env->psr);
        }
        ia64_count_psr_transition(env, old_psr, env->psr);
        if (*next_ip == 0) {
            abort_zero_branch(env, decoded, slot);
        }
        return IA64_PLANNED_SLOT_BREAK;
    }
    case IA64_TCG_FALLBACK_PLAN_BRANCH_PREDICT_OR_NOP:
        IA64_PERF_INC(IA64_PERF_OP_BRANCH_PREDICT);
        return IA64_PLANNED_SLOT_CONTINUE;
    default:
        return IA64_PLANNED_SLOT_GENERIC;
    }
}

static void ia64_exec_bundle_impl(CPUIA64State *env,
                                  uint32_t tmpl,
                                  uint64_t slot0,
                                  uint64_t slot1,
                                  uint64_t slot2,
                                  uint32_t fallback_plan)
{
    CPUState *cpu = env_cpu(env);
    IA64DecodedBundle decoded;
    uint64_t next_ip = env->ip + IA64_BUNDLE_SIZE;
    unsigned start_slot = ia64_psr_ri(env->psr);
    unsigned next_ri = 0;
    uint32_t planned_slot_count = 0;
    uint32_t planned_bailout_count = 0;

    IA64_PERF_INC(IA64_PERF_HELPER_EXEC_BUNDLE);
    IA64_PERF_INC(IA64_PERF_BUNDLE_EXECUTED);

    /*
     * This target still interprets complete IA-64 bundles inside one C helper.
     * Nested memory helpers therefore cannot hand QEMU a translated-code return
     * address for cpu_io_recompile().  Allow helper-owned I/O directly until the
     * translator grows per-instruction memory ops.
     */
    cpu->neg.can_do_io = true;

    ia64_trace_execve(env);
    ia64_trace_epc_syscall(env);
    ia64_trace_syscall_return(env);
    ia64_trace_uevent_netlink(env);
    ia64_maybe_apply_linux_cmdline_append(env);

    decoded.tmpl = tmpl & 0x1f;
    decoded.slot[0] = slot0 & IA64_SLOT_MASK;
    decoded.slot[1] = slot1 & IA64_SLOT_MASK;
    decoded.slot[2] = slot2 & IA64_SLOT_MASK;
    decoded.info = ia64_template_info(decoded.tmpl);
    decoded.valid = decoded.info->valid;

    if (ia64_perf_enabled()) {
        ia64_perf_count_tcg_fallback_reason(
            ia64_tcg_fallback_reason_for_bundle(&decoded, env->ip));
    }

    if (!decoded.valid) {
        abort_unsupported_slot(env, &decoded, 0);
    }

    ia64_progress_trace_bundle(env);
    ia64_state_trace_bundle(env);

    if (vibtanium_efi_dispatch_gate(env, env->ip)) {
        IA64_PERF_INC(IA64_PERF_HELPER_EFI_DISPATCH);
        return;
    }

    {
        IA64CountedStoreLoop store_loop;

        if (start_slot == 0 &&
            ia64_decode_counted_store_loop(&decoded, env->ip, &store_loop) &&
            exec_counted_store_loop(env, &store_loop, &next_ip)) {
            IA64_PERF_INC(IA64_PERF_OP_STORE);
            ia64_finish_bundle(env, next_ip, 0);
            return;
        }
    }

    if (start_slot >= IA64_SLOT_COUNT) {
        start_slot = 0;
    }

    for (int slot = start_slot; slot < IA64_SLOT_COUNT; slot++) {
        IA64SlotType type = decoded.info->slot_type[slot];
        uint64_t raw = decoded.slot[slot];
        uint8_t qp = ia64_slot_predicate(raw);
        IA64LdstImmediate ldst;
        IA64FloatingMemoryInstruction fldst;
        IA64AtomicInstruction atomic;
        IA64CompareInstruction cmp;
        IA64PredicateTestInstruction pred_test;
        IA64ExtractInstruction extract;
        IA64DepositInstruction deposit;
        IA64IntegerExtendInstruction int_ext;

        env->psr = ia64_psr_with_ri(env->psr, slot);
        IA64_PERF_INC(IA64_PERF_INTERP_SLOT_ITERATION);
        if (ia64_perf_enabled()) {
            ia64_perf_count_slot_type(type);
        }

        if (decoded.info->long_immediate && slot == 1) {
            uint8_t x_qp = ia64_slot_predicate(decoded.slot[2]);

            if (ia64_read_pr(env, x_qp)) {
                IA64_PERF_INC(IA64_PERF_INTERP_LONG_IMMEDIATE);
                if (!ia64_exec_lx_movl(env, decoded.slot[1],
                                       decoded.slot[2]) &&
                    !ia64_exec_lx_nop_or_hint(env, decoded.slot[1],
                                              decoded.slot[2])) {
                    abort_unsupported_slot(env, &decoded, 1);
                }
            }
            slot++;
            continue;
        }

        if (!ia64_read_pr(env, qp)) {
            IA64_PERF_INC(IA64_PERF_INTERP_PREDICATED_FALSE);
            if (exec_false_predicated_side_effect(env, &decoded, slot)) {
                IA64_PERF_INC(IA64_PERF_INTERP_FALSE_PRED_SIDE_EFFECT);
                continue;
            }
            if (!(type == IA64_SLOT_TYPE_B &&
                  ia64_slot_major_opcode(raw) == 0x4 &&
                  (((raw >> 6) & 0x7) == 2 || ((raw >> 6) & 0x7) == 3))) {
                continue;
            }
        }
        IA64_PERF_INC(IA64_PERF_INTERP_SLOT_EXECUTED);
        if (fallback_plan != 0) {
            IA64TcgFallbackPlanOp planned_op =
                ia64_tcg_fallback_plan_slot(fallback_plan, slot);

            if (planned_op != IA64_TCG_FALLBACK_PLAN_GENERIC) {
                IA64PlannedSlotResult planned =
                    exec_predecoded_slot(env, &decoded, slot, type, raw,
                                         planned_op, &next_ip, &next_ri);

                if (planned != IA64_PLANNED_SLOT_GENERIC) {
                    planned_slot_count++;
                    if (planned == IA64_PLANNED_SLOT_CONTINUE) {
                        continue;
                    }
                    break;
                }
                planned_bailout_count++;
            }
        }
        if (ia64_exec_smoke_slot_supported(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_SMOKE);
            continue;
        }
        if (ia64_slot_is_i_nop(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_NOP);
            continue;
        }
        if (ia64_slot_is_i_break(type, raw)) {
            uint64_t iim = ia64_i_break_immediate(raw);

            ia64_deliver_break(env, "break.i", iim, &next_ip);
            break;
        }
        if (ia64_slot_is_m34_alloc(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_ALLOC);
            ia64_exec_m34_alloc(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mov_ip(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_MOV_IP);
            ia64_exec_i_mov_ip(env, raw, env->ip);
            continue;
        }
        if (ia64_slot_is_i_mov_from_branch(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_BRANCH_REGISTER);
            ia64_exec_i_mov_from_branch(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mov_to_branch(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_BRANCH_REGISTER);
            ia64_exec_i_mov_to_branch(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mov_from_predicate(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_PREDICATE_REGISTER);
            ia64_exec_i_mov_from_predicate(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mov_to_predicate(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_PREDICATE_REGISTER);
            ia64_exec_i_mov_to_predicate(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mov_to_rotating_predicate_immediate(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_PREDICATE_REGISTER);
            ia64_exec_i_mov_to_rotating_predicate_immediate(env, raw);
            continue;
        }
        if (ia64_slot_is_mov_to_application(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_APPLICATION_REGISTER);
            ia64_exec_mov_to_application(env, type, raw);
            continue;
        }
        if (ia64_slot_is_mov_from_application(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_APPLICATION_REGISTER);
            ia64_exec_mov_from_application(env, type, raw);
            continue;
        }
        if (ia64_slot_is_mov_to_application_immediate(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_APPLICATION_REGISTER);
            ia64_exec_mov_to_application_immediate(env, type, raw);
            continue;
        }
        if (ia64_slot_is_check_speculative(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_SPECULATION_CHECK);
            ia64_exec_check_speculative(env, type, raw, env->ip, &next_ip);
            if (next_ip == 0) {
                abort_zero_branch(env, &decoded, slot);
            }
            if (next_ip != env->ip + IA64_BUNDLE_SIZE) {
                break;
            }
            continue;
        }
        if (ia64_slot_is_m_check_advanced(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_SPECULATION_CHECK);
            ia64_exec_m_check_advanced(env, raw, env->ip, &next_ip);
            if (next_ip == 0) {
                abort_zero_branch(env, &decoded, slot);
            }
            if (next_ip != env->ip + IA64_BUNDLE_SIZE) {
                break;
            }
            continue;
        }
        if (ia64_slot_is_m_processor_mask(type, raw)) {
            uint64_t old_psr = env->psr;

            if (ia64_exec_m_processor_mask(env, raw)) {
                IA64_PERF_INC(IA64_PERF_OP_PROCESSOR_MASK);
                ia64_count_psr_transition(env, old_psr, env->psr);
                continue;
            }
        }
        if (ia64_slot_is_m_mov_from_processor_status(type, raw) &&
            ia64_exec_m_mov_from_processor_status(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_PROCESSOR_STATUS);
            continue;
        }
        if (ia64_slot_is_m_mov_to_processor_status(type, raw)) {
            uint64_t old_psr = env->psr;

            if (ia64_exec_m_mov_to_processor_status(env, raw)) {
                IA64_PERF_INC(IA64_PERF_OP_PROCESSOR_STATUS);
                ia64_count_psr_transition(env, old_psr, env->psr);
                continue;
            }
        }
        if (ia64_slot_is_m_break(type, raw)) {
            uint64_t iim = ia64_m_break_immediate(raw);

            ia64_deliver_break(env, "break.m", iim, &next_ip);
            break;
        }
        if (ia64_slot_is_b_break(type, raw)) {
            uint64_t iim = ia64_b_break_immediate(raw);

            ia64_deliver_break(env, "break.b", iim, &next_ip);
            break;
        }
        if (ia64_slot_is_m_mov_to_region_register(type, raw) &&
            ia64_exec_m_mov_to_region_register(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_REGION_REGISTER);
            /*
             * QEMU's host TLB is keyed by virtual page and mmu_idx, while
             * IA-64 RIDs live inside RR state used by target-side lookup.
             * Drop cached host translations when a region register changes.
             */
            tlb_flush(cpu);
            IA64_PERF_INC(IA64_PERF_QEMU_TLB_FLUSH_FULL);
            continue;
        }
        if (ia64_slot_is_m_mov_from_region_register(type, raw) &&
            ia64_exec_m_mov_from_region_register(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_REGION_REGISTER);
            continue;
        }
        if (ia64_slot_is_m_mov_to_control(type, raw) &&
            ia64_exec_m_mov_to_control(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_CONTROL_REGISTER);
            continue;
        }
        if (ia64_slot_is_m_mov_from_control(type, raw) &&
            ia64_exec_m_mov_from_control(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_CONTROL_REGISTER);
            continue;
        }
        if (ia64_slot_is_m_mov_from_processor_identifier(type, raw) &&
            ia64_exec_m_mov_from_processor_identifier(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_PROCESSOR_ID);
            continue;
        }
        if (ia64_slot_is_m_mov_to_indexed_system_register(type, raw) &&
            ia64_exec_m_mov_to_indexed_system_register(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_INDEXED_SYSTEM_REGISTER);
            continue;
        }
        if (ia64_slot_is_m_mov_from_indexed_system_register(type, raw) &&
            ia64_exec_m_mov_from_indexed_system_register(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_INDEXED_SYSTEM_REGISTER);
            continue;
        }
        if (ia64_slot_is_m_insert_translation(type, raw) &&
            ia64_exec_m_insert_translation(env, raw)) {
            uint8_t ps = (env->cr[IA64_CR_ITIR] >> 2) & 0x3f;

            IA64_PERF_INC(IA64_PERF_OP_INSERT_TRANSLATION);
            ia64_flush_qemu_tlb_for_page(cpu, env->cr[IA64_CR_IFA], ps);
            continue;
        }
        if (ia64_slot_is_m_probe(type, raw)) {
            IA64TranslateResult fault;
            IA64ProbeStatus status =
                ia64_exec_m_probe_checked(env, raw, &fault);

            if (status == IA64_PROBE_FAULT) {
                IA64_PERF_INC(IA64_PERF_OP_PROBE_TRANSLATION);
                ia64_deliver_translation_fault(env, &fault);
                return;
            }
            if (status == IA64_PROBE_OK) {
                IA64_PERF_INC(IA64_PERF_OP_PROBE_TRANSLATION);
                continue;
            }
        }
        if (ia64_slot_is_m_virtual_translation(type, raw)) {
            IA64TranslateResult fault;
            IA64VirtualTranslationStatus status =
                ia64_exec_m_virtual_translation_checked(env, raw, &fault);

            if (status == IA64_VIRTUAL_TRANSLATION_FAULT) {
                IA64_PERF_INC(IA64_PERF_OP_VIRTUAL_TRANSLATION);
                ia64_deliver_translation_fault(env, &fault);
                return;
            }
            if (status == IA64_VIRTUAL_TRANSLATION_OK) {
                IA64_PERF_INC(IA64_PERF_OP_VIRTUAL_TRANSLATION);
                continue;
            }
        }
        if (ia64_slot_is_m_purge_translation(type, raw) &&
            ia64_exec_m_purge_translation(env, raw)) {
            uint8_t px6 = (raw >> 27) & 0x3f;
            uint8_t ps = (ia64_read_gr(env, (raw >> 13) & 0x7f) >> 2) & 0x3f;

            IA64_PERF_INC(IA64_PERF_OP_PURGE_TRANSLATION);
            /*
             * The modeled translation-cache/register entries were invalidated;
             * drop the matching host softmmu TLB so stale cached pages re-fill.
             * Flush exactly the purged ia64 page range: ia64 pages can be larger
             * than TARGET_PAGE_SIZE, so a single host-page flush would leave
             * stale mappings whose physical page is later reused and corrupted
             * (seen as a slab free_block NULL deref). A range flush over just the
             * page -- rather than a full tlb_flush on every ptc.l -- also avoids
             * the re-fault storm during library mmap/mprotect that makes
             * userspace crawl. ptc.e and unusual page sizes fall back to a full
             * flush.
             */
            if (px6 != 0x34) {
                ia64_flush_qemu_tlb_for_page(
                    cpu, ia64_read_gr(env, (raw >> 20) & 0x7f), ps);
            } else {
                tlb_flush(cpu);
                IA64_PERF_INC(IA64_PERF_QEMU_TLB_FLUSH_FULL);
            }
            continue;
        }
        if (ia64_slot_is_m_invala(type, raw) &&
            ia64_exec_m_invala(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_INVALA);
            continue;
        }
        if (ia64_slot_is_m_flushrs(type, raw)) {
            ia64_exec_flushrs(env);
            continue;
        }
        if (ia64_slot_is_m_loadrs(type, raw)) {
            ia64_exec_loadrs(env);
            continue;
        }
        if (ia64_slot_is_m_system_noop(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_SYSTEM_NOOP);
            continue;
        }
        if (ia64_slot_is_m_setf(type, raw) && ia64_exec_m_setf(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_SETF_GETF);
            continue;
        }
        if (ia64_slot_is_m_getf(type, raw) && ia64_exec_m_getf(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_SETF_GETF);
            continue;
        }
        if (ia64_decode_m_atomic(type, raw, &atomic) &&
            exec_m_atomic(env, &atomic)) {
            IA64_PERF_INC(IA64_PERF_OP_ATOMIC);
            continue;
        }
        if (ia64_decode_extract(type, raw, &extract) &&
            ia64_exec_extract(env, &extract)) {
            IA64_PERF_INC(IA64_PERF_OP_EXTRACT_DEPOSIT);
            continue;
        }
        if (ia64_decode_deposit(type, raw, &deposit) &&
            ia64_exec_deposit(env, &deposit)) {
            IA64_PERF_INC(IA64_PERF_OP_EXTRACT_DEPOSIT);
            continue;
        }
        if (ia64_slot_is_i_shift_right_pair(type, raw) &&
            ia64_exec_i_shift_right_pair(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_SHIFT_EXTEND);
            continue;
        }
        if (ia64_decode_integer_extend(type, raw, &int_ext) &&
            ia64_exec_integer_extend(env, &int_ext)) {
            IA64_PERF_INC(IA64_PERF_OP_SHIFT_EXTEND);
            continue;
        }
        if (ia64_slot_is_f_reciprocal_approx(type, raw) &&
            ia64_exec_f_reciprocal_approx(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_FLOAT);
            continue;
        }
        if (ia64_slot_is_f_misc(type, raw) &&
            ia64_exec_f_misc(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_FLOAT);
            continue;
        }
        if (ia64_slot_is_f_multiply_add(type, raw) &&
            ia64_exec_f_multiply_add(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_FLOAT);
            continue;
        }
        if (ia64_slot_is_f_select_or_xma(type, raw) &&
            ia64_exec_f_select_or_xma(env, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_FLOAT);
            continue;
        }
        if (ia64_decode_floating_memory(type, raw, &fldst) &&
            exec_floating_memory(env, &fldst)) {
            IA64_PERF_INC(IA64_PERF_OP_FLOAT_MEMORY);
            continue;
        }
        if (ia64_decode_ldst_immediate(type, raw, &ldst) &&
            exec_ldst_immediate(env, &ldst)) {
            switch (ldst.kind) {
            case IA64_LDST_IMM_LOAD:
                IA64_PERF_INC(IA64_PERF_OP_LOAD);
                break;
            case IA64_LDST_IMM_STORE:
                IA64_PERF_INC(IA64_PERF_OP_STORE);
                break;
            case IA64_LDST_IMM_PREFETCH:
                IA64_PERF_INC(IA64_PERF_OP_PREFETCH);
                break;
            default:
                break;
            }
            continue;
        }
        if (ia64_decode_compare(type, raw, &cmp) &&
            ia64_exec_compare(env, &cmp)) {
            IA64_PERF_INC(IA64_PERF_OP_COMPARE);
            continue;
        }
        if (ia64_decode_predicate_test(type, raw, &pred_test) &&
            ia64_exec_predicate_test(env, &pred_test)) {
            IA64_PERF_INC(IA64_PERF_OP_PREDICATE_TEST);
            if (pred_test.kind == IA64_PRED_TEST_NAT) {
                IA64_PERF_INC(IA64_PERF_OP_NAT_TEST);
            }
            continue;
        }
        if (ia64_slot_is_alu_add(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_ALU);
            ia64_exec_alu_add(env, raw);
            continue;
        }
        if (ia64_slot_is_alu_sub(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_ALU);
            ia64_exec_alu_sub(env, raw);
            continue;
        }
        if (ia64_slot_is_alu_logic(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_ALU);
            ia64_exec_alu_logic(env, raw);
            continue;
        }
        if (ia64_slot_is_alu_addp4(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_ALU);
            ia64_exec_alu_addp4(env, raw);
            continue;
        }
        if (ia64_slot_is_alu_shladd(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_ALU);
            ia64_exec_alu_shladd(env, raw);
            continue;
        }
        if (ia64_slot_is_i_packed_i2(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_ALU);
            ia64_exec_i_packed_i2(env, raw);
            continue;
        }
        if (ia64_slot_is_i_mux(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_ALU);
            ia64_exec_i_mux(env, raw);
            continue;
        }
        if (ia64_slot_is_i_bit_count(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_ALU);
            ia64_exec_i_bit_count(env, raw);
            continue;
        }
        if (ia64_slot_is_i_variable_shift(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_ALU);
            ia64_exec_i_variable_shift(env, raw);
            continue;
        }
        if (ia64_slot_is_addl(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_ADDL);
            ia64_exec_addl(env, raw);
            continue;
        }
        if (ia64_slot_is_b_branch_relative(type, raw)) {
            bool branch_taken = false;

            IA64_PERF_INC(IA64_PERF_OP_BRANCH_DIRECT);
            ia64_exec_b_branch_relative(env, raw, env->ip, &next_ip,
                                        &branch_taken);
            if (next_ip == 0) {
                abort_zero_branch(env, &decoded, slot);
            }
            if (branch_taken || next_ip != env->ip + IA64_BUNDLE_SIZE) {
                IA64_PERF_INC(IA64_PERF_BRANCH_TAKEN);
                break;
            }
            IA64_PERF_INC(IA64_PERF_BRANCH_FALLTHROUGH);
            continue;
        }
        if (ia64_slot_is_b_call_relative(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_BRANCH_CALL);
            IA64_PERF_INC(IA64_PERF_BRANCH_TAKEN);
            ia64_exec_b_call_relative(env, raw, env->ip, &next_ip);
            if (next_ip == 0) {
                abort_zero_branch(env, &decoded, slot);
            }
            break;
        }
        if (ia64_slot_is_b_indirect_branch(type, raw)) {
            uint8_t branch_major = ia64_slot_major_opcode(raw);
            uint8_t branch_x6 = (raw >> 27) & 0x3f;
            bool rfi = branch_major == 0x0 && branch_x6 == 0x08;
            bool rfi_valid_ifs =
                rfi && (env->cr[IA64_CR_IFS] & IA64_IFS_VALID_BIT) != 0;
            bool br_ret = branch_major == 0x0 && branch_x6 == 0x21;
            bool cover = branch_major == 0x0 && branch_x6 == 0x02;
            bool epc = branch_major == 0x0 && branch_x6 == 0x10;
            uint64_t old_psr = env->psr;

            IA64_PERF_INC(IA64_PERF_OP_BRANCH_INDIRECT);
            IA64_PERF_INC(IA64_PERF_BRANCH_TAKEN);
            if (cover) {
                IA64_PERF_INC(IA64_PERF_TRANSITION_COVER);
            }
            if (epc) {
                IA64_PERF_INC(IA64_PERF_TRANSITION_EPC);
            }
            ia64_exec_b_indirect_branch(env, raw, env->ip, &next_ip);
            if (br_ret) {
                ia64_rse_maybe_fill_restored_frame(env,
                                                   (env->cfm >> 7) & 0x7f);
            }
            if (rfi_valid_ifs) {
                IA64_PERF_INC(IA64_PERF_TRANSITION_RFI_VALID_IFS);
                ia64_rse_maybe_fill_restored_frame(env, env->rse.sof);
            }
            if (rfi) {
                IA64_PERF_INC(IA64_PERF_TRANSITION_RFI);
                IA64_PERF_INC(ia64_helper_psr_cpl(env->psr) == 3 ?
                              IA64_PERF_TRANSITION_RFI_TO_USER :
                              IA64_PERF_TRANSITION_RFI_TO_KERNEL);
                next_ri = ia64_psr_ri(env->psr);
            }
            ia64_count_psr_transition(env, old_psr, env->psr);
            if (next_ip == 0) {
                abort_zero_branch(env, &decoded, slot);
            }
            break;
        }
        if (ia64_slot_is_b_predict_or_nop(type, raw)) {
            IA64_PERF_INC(IA64_PERF_OP_BRANCH_PREDICT);
            continue;
        }
        if (decoded.info->long_immediate && type == IA64_SLOT_TYPE_X) {
            abort_unsupported_slot(env, &decoded, 1);
        }

        abort_unsupported_slot(env, &decoded, slot);
    }

    IA64_PERF_ADD(IA64_PERF_TCG_FALLBACK_PLAN_SLOT, planned_slot_count);
    IA64_PERF_ADD(IA64_PERF_TCG_FALLBACK_PLAN_BAILOUT, planned_bailout_count);
    ia64_finish_bundle(env, next_ip, next_ri);
}

void HELPER(exec_bundle)(CPUIA64State *env,
                         uint32_t tmpl,
                         uint64_t slot0,
                         uint64_t slot1,
                         uint64_t slot2,
                         uint32_t fallback_plan)
{
    ia64_exec_bundle_impl(env, tmpl, slot0, slot1, slot2, fallback_plan);
}

uint32_t HELPER(exec_bundle_lookup_ptr)(CPUIA64State *env,
                                        uint32_t tmpl,
                                        uint64_t slot0,
                                        uint64_t slot1,
                                        uint64_t slot2,
                                        uint32_t fallback_plan)
{
    ia64_exec_bundle_impl(env, tmpl, slot0, slot1, slot2, fallback_plan);
    return ia64_lookup_ptr_chain_ok(env);
}
