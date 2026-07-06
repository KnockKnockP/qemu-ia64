/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "qemu/osdep.h"
#include "accel/tcg/cpu-ldst.h"
#include "bundle.h"
#include "cpu.h"
#include "debug-trace.h"
#include "insn.h"
#include "hw/core/cpu.h"
#include "mem.h"
#include "system/memory.h"
#include "tcg-classify.h"
#include "trace-target_ia64.h"

#define IA64_LINUX_BREAK_SYSCALL UINT64_C(0x100000)
#define IA64_PSR_CPL_SHIFT 32
#define IA64_PSR_CPL_MASK UINT64_C(0x0000000300000000)

static bool ia64_debug_env_enabled(const char *name)
{
    const char *value = g_getenv(name);

    return value != NULL && *value != '\0';
}

bool ia64_debug_hooks_active(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = ia64_debug_env_enabled("VIBTANIUM_EXECVE_TRACE") ||
                  ia64_debug_env_enabled("VIBTANIUM_SYSCALL_TRACE") ||
                  ia64_debug_env_enabled("VIBTANIUM_SYSCALL_ERRTRACE") ||
                  ia64_debug_env_enabled("VIBTANIUM_STAT_DUMP") ||
                  ia64_debug_env_enabled("VIBTANIUM_UEVENT_TRACE") ||
                  ia64_debug_env_enabled("VIBTANIUM_IA64_PROGRESS") ||
                  ia64_debug_env_enabled("VIBTANIUM_BUNDLE_TRACE_IP") ||
                  ia64_debug_env_enabled("VIBTANIUM_STATE_TRACE_IP");
    }
    return enabled != 0;
}

static bool ia64_syscall_trace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_SYSCALL_TRACE") != NULL;
    }
    return enabled != 0;
}

/*
 * Low-noise variant: record each syscall's arguments at entry, then at the
 * ret_from_syscall hook print *only* the syscalls that failed (r10 == -1),
 * paired with their name/args/errno. This survives a full noisy boot without
 * drowning in successful calls, and pinpoints a mis-emulated syscall path.
 * Gated behind its own knob so it is free when disabled.
 */
static bool ia64_syscall_errtrace_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_SYSCALL_ERRTRACE") != NULL;
    }
    return enabled != 0;
}

/*
 * VIBTANIUM_STAT_DUMP=1: at every stat/lstat/fstat/newfstatat return, dump the
 * st_dev/st_ino/st_nlink/st_mode the kernel copied to userspace. Used to catch
 * the FTS_CWDFD "cannot search" failure: gnulib compares newfstatat(path) vs
 * fstat(fd) dev/ino; if the kernel stat copy-out is mis-emulated the two
 * disagree and find aborts even though every syscall "succeeds".
 */
static bool ia64_stat_dump_enabled(void)
{
    static int enabled = -1;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_STAT_DUMP") != NULL;
    }
    return enabled != 0;
}

typedef struct IA64SyscallTrack {
    bool valid;
    uint64_t user_tp;      /* r13 at the user gate (thread pointer) */
    uint64_t nr;
    uint64_t arg[4];
    uint64_t ip;
} IA64SyscallTrack;

/*
 * A syscall's user-mode gate entry (r13 = user thread pointer) and its
 * kernel-mode ret_from_syscall hook (r13 = kernel `current`) carry different
 * r13 values, so we cannot pair them by thread pointer. But a *synchronous*
 * syscall (the failing openat/fchdir/ioctl/etc. we care about) does not sleep:
 * on the single vCPU its gate entry is immediately followed by its own return
 * with no other user gate entry in between. So the most-recent entry is the
 * one returning. One global slot is therefore sufficient and correct for the
 * error-pairing we need.
 */
static IA64SyscallTrack ia64_last_syscall;

static void ia64_syscall_track_record(CPUIA64State *env, uint64_t nr)
{
    ia64_last_syscall.valid = true;
    ia64_last_syscall.user_tp = ia64_read_gr(env, 13);
    ia64_last_syscall.nr = nr;
    ia64_last_syscall.arg[0] = ia64_read_gr(env, 32);
    ia64_last_syscall.arg[1] = ia64_read_gr(env, 33);
    ia64_last_syscall.arg[2] = ia64_read_gr(env, 34);
    ia64_last_syscall.arg[3] = ia64_read_gr(env, 35);
    ia64_last_syscall.ip = env->ip;
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

static bool ia64_trace_ip_list_contains(uint64_t ip, const uint64_t *known,
                                        size_t known_count,
                                        const char *env_name)
{
    const char *override;

    for (size_t i = 0; i < known_count; i++) {
        if (ip == known[i]) {
            return true;
        }
    }

    override = g_getenv(env_name);
    while (override && *override) {
        char *end = NULL;
        uint64_t value = g_ascii_strtoull(override, &end, 0);

        if (end != override && ip == value) {
            return true;
        }
        if (end == override) {
            override++;
        } else {
            override = end;
        }
        while (*override == ',' || *override == ';' ||
               g_ascii_isspace(*override)) {
            override++;
        }
    }

    return false;
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

static void ia64_trace_linux_syscall_execve_vectors(CPUIA64State *env,
                                                    uint64_t nr)
{
    if (nr != 1033) {
        return;
    }

    ia64_trace_execve_vector(env, "argv", ia64_read_gr(env, 33), 6);
    ia64_trace_execve_vector(env, "envp", ia64_read_gr(env, 34), 4);
}

static void ia64_trace_linux_syscall_paths(CPUIA64State *env,
                                           uint64_t nr)
{
    uint64_t arg[6];
    char rendered[192];
    bool any = false;

    for (unsigned i = 0; i < ARRAY_SIZE(arg); i++) {
        arg[i] = ia64_read_gr(env, 32 + i);
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
                                                    uint64_t nr)
{
    uint64_t arg[6];

    for (unsigned i = 0; i < ARRAY_SIZE(arg); i++) {
        arg[i] = ia64_read_gr(env, 32 + i);
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

void ia64_trace_linux_syscall_break(CPUIA64State *env,
                                           const char *mnemonic,
                                           uint64_t iim, uint64_t next_ip)
{
    uint64_t nr;
    uint64_t cpl;

    if (iim != IA64_LINUX_BREAK_SYSCALL) {
        return;
    }

    nr = ia64_read_gr(env, 15);
    if (ia64_syscall_errtrace_enabled() || ia64_stat_dump_enabled()) {
        ia64_syscall_track_record(env, nr);
    }
    if (!ia64_syscall_trace_enabled()) {
        return;
    }
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
    ia64_trace_linux_syscall_paths(env, nr);
    ia64_trace_linux_syscall_execve_vectors(env, nr);
    ia64_trace_linux_syscall_socket_details(env, nr);
    fprintf(stderr, "\n");
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

void ia64_progress_trace_bundle(CPUIA64State *env)
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
    fflush(stderr);
}

void ia64_progress_trace_event(CPUIA64State *env, const char *event,
                                      uint64_t value, uint64_t source_ip,
                                      unsigned source_ri, uint64_t next_ip)
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
            "[ia64-progress] event=%s source=0x%016" PRIx64
            " sri=%u"
            " ip=0x%016" PRIx64
            " value=0x%016" PRIx64 " next=0x%016" PRIx64
            " psr=0x%016" PRIx64 " cfm=0x%016" PRIx64 "\n",
            event, source_ip, source_ri, env->ip, value, next_ip, env->psr,
            env->cfm);
}

void ia64_progress_trace_break_slot(CPUIA64State *env,
                                           const IA64DecodedBundle *decoded,
                                           int slot,
                                           const char *mnemonic,
                                           uint64_t iim)
{
    static uint64_t break_slot_count;
    char bundle_text[192];
    char slot_text[256];
    IA64TranslateResult inst_result = {0};
    uint8_t live_bytes[IA64_BUNDLE_SIZE];
    bool have_live_bytes = false;
    MemTxResult memtx = MEMTX_ERROR;

    if (!ia64_progress_trace_enabled()) {
        return;
    }

    break_slot_count++;
    if (break_slot_count > 16 && (break_slot_count & UINT64_C(0xffff)) != 0) {
        return;
    }

    if (ia64_translate_address(
            env, env->ip, MMU_INST_FETCH,
            ia64_tcg_mmu_index_for_psr(env->psr, true), true,
            &inst_result)) {
        memtx = address_space_read(env_cpu(env)->as, inst_result.paddr,
                                   MEMTXATTRS_UNSPECIFIED, live_bytes,
                                   sizeof(live_bytes));
        have_live_bytes = memtx == MEMTX_OK;
    }

    ia64_format_decoded_bundle(decoded, bundle_text, sizeof(bundle_text));
    ia64_format_slot_class(decoded, slot, slot_text, sizeof(slot_text));
    fprintf(stderr,
            "[ia64-break-slot] event=%s source=0x%016" PRIx64
            " sri=%u value=0x%016" PRIx64
            " psr=0x%016" PRIx64 " cfm=0x%016" PRIx64
            " %s bundle %s\n",
            mnemonic, env->ip, ia64_env_ri(env), iim, ia64_env_psr(env),
            env->cfm, slot_text, bundle_text);
    if (inst_result.status == IA64_TRANSLATE_OK) {
        fprintf(stderr,
                "[ia64-break-live] source=0x%016" PRIx64
                " mmu=%d paddr=0x%016" HWADDR_PRIx " memtx=%d bytes=",
                env->ip, inst_result.mmu_idx, inst_result.paddr, memtx);
        if (have_live_bytes) {
            for (unsigned i = 0; i < sizeof(live_bytes); i++) {
                fprintf(stderr, "%02x", live_bytes[i]);
            }
        } else {
            fprintf(stderr, "unavailable");
        }
        fputc('\n', stderr);
    } else {
        char detail[160];

        ia64_format_translate_result(&inst_result, detail, sizeof(detail));
        fprintf(stderr,
                "[ia64-break-live] source=0x%016" PRIx64
                " translate-failed %s\n",
                env->ip, detail);
    }
    fflush(stderr);
}

static bool ia64_bundle_trace_matches(uint64_t ip)
{
    static int initialized;
    static bool enabled;
    static uint64_t filter_start;
    static uint64_t filter_end;

    if (!initialized) {
        const char *addr = g_getenv("VIBTANIUM_BUNDLE_TRACE_IP");
        const char *size = g_getenv("VIBTANIUM_BUNDLE_TRACE_SIZE");

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

static uint64_t ia64_bundle_trace_limit(void)
{
    static int initialized;
    static uint64_t limit;

    if (!initialized) {
        const char *value = g_getenv("VIBTANIUM_BUNDLE_TRACE_LIMIT");

        limit = value != NULL && *value != '\0' ?
                g_ascii_strtoull(value, NULL, 0) : UINT64_MAX;
        initialized = 1;
    }
    return limit;
}

void ia64_bundle_trace_decoded(CPUIA64State *env,
                                      const IA64DecodedBundle *decoded,
                                      unsigned start_slot)
{
    static uint64_t count;
    char bundle_text[192];

    if (!ia64_bundle_trace_matches(env->ip)) {
        return;
    }

    if (count >= ia64_bundle_trace_limit()) {
        return;
    }
    count++;

    ia64_format_decoded_bundle(decoded, bundle_text, sizeof(bundle_text));
    fprintf(stderr,
            "[ia64-bundle] ip=0x%016" PRIx64 " start-ri=%u psr=0x%016" PRIx64
            " tmpl=0x%02x slot0=0x%011" PRIx64
            " slot1=0x%011" PRIx64 " slot2=0x%011" PRIx64
            " %s\n",
            env->ip, start_slot, env->psr, decoded->tmpl, decoded->slot[0],
            decoded->slot[1], decoded->slot[2], bundle_text);
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

void ia64_state_trace_bundle(CPUIA64State *env)
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
            " itc=0x%016" PRIx64 " itm=0x%016" PRIx64
            " itv=0x%016" PRIx64 " tpr=0x%016" PRIx64
            " ivr=0x%016" PRIx64
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
            env->ar[IA64_AR_ITC], env->cr[IA64_CR_ITM],
            env->cr[IA64_CR_ITV], env->cr[IA64_CR_TPR],
            env->cr[IA64_CR_IVR],
            env->cr[IA64_CR_IFA], env->cr[IA64_CR_ITIR],
            env->cr[IA64_CR_IHA], env->cr[IA64_CR_IPSR],
            env->cr[IA64_CR_IIP], env->cr[IA64_CR_IFS],
            env->cr[IA64_CR_ISR]);
}


/*
 * Diagnostic: log execve() filenames so a userspace exec loop can be
 * identified. Known fixed kernel entry points are listed here, and
 * VIBTANIUM_EXECVE_IPS accepts a comma-separated override list for new guests.
 */
void ia64_trace_execve(CPUIA64State *env)
{
    static const uint64_t known_execve_ips[] = {
        UINT64_C(0xa0000001002072e0), /* Debian 3.2.0-4-itanium do_execve */
        UINT64_C(0xe0000000044b7bc0), /* CentOS 3.9 ia64 sys_execve */
    };
    static int enabled = -1;
    char path[176];
    uint64_t argv;
    uint64_t envp;

    if (enabled < 0) {
        enabled = g_getenv("VIBTANIUM_EXECVE_TRACE") != NULL;
    }
    if (enabled == 0 ||
        !ia64_trace_ip_list_contains(env->ip, known_execve_ips,
                                     ARRAY_SIZE(known_execve_ips),
                                     "VIBTANIUM_EXECVE_IPS")) {
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
void ia64_trace_epc_syscall(CPUIA64State *env)
{
    static const uint64_t known_epc_ips[] = {
        UINT64_C(0xa000000000040a00), /* Debian 3.2.0-4-itanium gate */
    };
    uint64_t nr;
    uint64_t cpl;

    if (!ia64_trace_ip_list_contains(env->ip, known_epc_ips,
                                     ARRAY_SIZE(known_epc_ips),
                                     "VIBTANIUM_SYSCALL_EPC_IPS")) {
        return;
    }

    nr = ia64_read_gr(env, 15);
    if (ia64_syscall_errtrace_enabled() || ia64_stat_dump_enabled()) {
        ia64_syscall_track_record(env, nr);
    }
    if (!ia64_syscall_trace_enabled()) {
        return;
    }
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
    ia64_trace_linux_syscall_paths(env, nr);
    ia64_trace_linux_syscall_execve_vectors(env, nr);
    ia64_trace_linux_syscall_socket_details(env, nr);
    fprintf(stderr, "\n");
}

/*
 * Diagnostic: log the syscall return value. Both the break and epc heavy
 * paths funnel through ia64_ret_from_syscall, where r8 = return value and
 * r10 = 0 (success) / -1 (error). Pairing this with the entry traces above
 * shows exactly which syscall fails and with what errno.
 */
void ia64_trace_syscall_return(CPUIA64State *env)
{
    static const uint64_t known_return_ips[] = {
        UINT64_C(0xa00000010000baa0), /* Debian 3.2.0-4-itanium */
        UINT64_C(0xe00000000440ea60), /* CentOS 3.9 ia64 */
    };
    uint64_t r8;
    uint64_t r10;

    if (!ia64_trace_ip_list_contains(env->ip, known_return_ips,
                                     ARRAY_SIZE(known_return_ips),
                                     "VIBTANIUM_SYSCALL_RET_IPS")) {
        return;
    }

    r8 = ia64_read_gr(env, 8);
    r10 = ia64_read_gr(env, 10);

    /*
     * At this hook (ia64_ret_from_syscall) r8 still holds the *raw* kernel
     * return value: negative in the [-4095, -1] MAX_ERRNO window means the
     * syscall failed with errno = -r8. (r10 here is a scratch value, not the
     * 0/-1 error flag that only exists after the userspace fixup.)
     */
    if (ia64_syscall_errtrace_enabled() &&
        (int64_t)r8 < 0 && (int64_t)r8 >= -4095) {
        uint64_t current = ia64_read_gr(env, 13);
        int64_t err = -(int64_t)r8;
        IA64SyscallTrack *t = ia64_last_syscall.valid ? &ia64_last_syscall : NULL;

        if (t != NULL) {
            fprintf(stderr,
                    "[ia64-syscall-err] nr=%" PRIu64 "(%s) errno=%" PRId64
                    " a0=0x%016" PRIx64 " a1=0x%016" PRIx64
                    " a2=0x%016" PRIx64 " a3=0x%016" PRIx64
                    " user_tp=0x%016" PRIx64 " kcurrent=0x%016" PRIx64 "\n",
                    t->nr, ia64_linux_syscall_name(t->nr), err,
                    t->arg[0], t->arg[1], t->arg[2], t->arg[3],
                    t->user_tp, current);
        } else {
            fprintf(stderr,
                    "[ia64-syscall-err] nr=? errno=%" PRId64
                    " kcurrent=0x%016" PRIx64 "\n",
                    err, current);
        }
    }

    if (ia64_stat_dump_enabled() && ia64_last_syscall.valid &&
        (int64_t)r8 >= 0) {
        uint64_t nr = ia64_last_syscall.nr;
        uint64_t buf = 0;
        const char *name = NULL;

        switch (nr) {
        case 1210: name = "stat";       buf = ia64_last_syscall.arg[1]; break;
        case 1211: name = "lstat";      buf = ia64_last_syscall.arg[1]; break;
        case 1212: name = "fstat";      buf = ia64_last_syscall.arg[1]; break;
        case 1286: name = "newfstatat"; buf = ia64_last_syscall.arg[2]; break;
        default: break;
        }
        if (name != NULL && buf != 0) {
            uint64_t words[6] = {0};

            if (cpu_memory_rw_debug(env_cpu(env), buf, words,
                                    sizeof(words), false) == 0) {
                /* ia64 struct stat: dev@0 ino@8 nlink@16 mode(lo)/uid(hi)@24 */
                fprintf(stderr,
                        "[ia64-stat] %s buf=0x%016" PRIx64
                        " st_dev=0x%016" PRIx64 " st_ino=0x%016" PRIx64
                        " st_nlink=0x%016" PRIx64 " st_mode=0%o"
                        " a0=0x%016" PRIx64 "\n",
                        name, buf, words[0], words[1], words[2],
                        (unsigned)(words[3] & 0xffffffff),
                        ia64_last_syscall.arg[0]);
            }
        }
    }

    if (!ia64_syscall_trace_enabled()) {
        return;
    }
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

void ia64_trace_uevent_netlink(CPUIA64State *env)
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
