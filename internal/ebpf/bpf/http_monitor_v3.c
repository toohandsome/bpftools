#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/socket.h>
#include <linux/types.h>

char LICENSE[] SEC("license") = "GPL";

/* Tracepoint 上下文结构体定义 */
// Correct tracepoint raw ctx layouts: include trace_entry header
struct trace_entry {
    unsigned short type;
    unsigned char flags;
    unsigned char preempt_count;
    int pid;
};

struct trace_event_raw_sys_enter {
    struct trace_entry ent;
    long id;
    unsigned long args[6];
};

struct trace_event_raw_sys_exit {
    struct trace_entry ent;
    long id;
    long ret;
};

/* 自定义结构体 */
struct syscall_args {
    void *buf;
    __u32 len;
    int fd;
    __u8 syscall_type; // 0=recv/recvfrom, 1=read, 2=recvmsg
};

struct http_event {
    __u32 pid;
    char  comm[16];
    __u32 len;
    __u32 orig_len;
    __s32 fd;
    __u8  direction; // 0 = send, 1 = recv
    __u8  pad[3];    // 显式填充对齐
    char  data[4096]; // HTTP 载荷样本（扩大到 4096）
};

/* 常量定义 */
#define MAX_HTTP_DATA_LEN 4096
#define HTTP_METHOD_CHECK_LEN 32
#define MAX_PID_FILTER_ENTRIES 1024
#define RING_BUFFER_SIZE (1 << 23)  // 8MB
#define MAX_ACTIVE_SYSCALLS 10240
#define MAX_CAPTURE_LEN 4096
#define MAX_HTTP_STREAMS 32768

/* 计数器索引 */
#define COUNTER_TOTAL_SEND 0
#define COUNTER_TOTAL_RECV 1
#define COUNTER_HTTP_SEND 2
#define COUNTER_HTTP_RECV 3
#define COUNTER_ERRORS 4
#define COUNTER_HTTP_CHECKS 5
#define COUNTER_HTTP_MATCH 6
#define COUNTER_READ_FAILS 7
#define COUNTER_READ_SUCCESS 8
#define COUNTER_SEND_BUFF_NULL 9
#define COUNTER_RECV_ARGS_NULL 10
#define COUNTER_RECV_BUF_NULL 11

/* Map 定义 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RING_BUFFER_SIZE);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ACTIVE_SYSCALLS);
    __type(key, __u64);  // tid
    __type(value, struct syscall_args);
} active_syscalls SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_PID_FILTER_ENTRIES);
    __type(key, __u32);  // pid
    __type(value, __u8); // 1 = monitor, 0 = ignore
} pid_filter SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 12);
    __type(key, __u32);
    __type(value, __u64);
} counters SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} filter_enabled SEC(".maps");

// 新增：按 (pid, fd, direction) 跟踪已识别为 HTTP 的流，放行后续非起始片段
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_HTTP_STREAMS);
    __type(key, __u64);  // key = (pid<<33) | ((u32)fd<<1) | (dir&1)
    __type(value, __u8); // 1 = seen HTTP
} http_streams SEC(".maps");

/* 内联函数定义 */
static __always_inline void increment_counter(__u32 counter_idx) {
    __u32 key = counter_idx;
    __u64 *counter = bpf_map_lookup_elem(&counters, &key);
    if (counter) {
        (*counter) += 1;
    }
}

static __always_inline __u64 make_stream_key(__u32 pid, int fd, __u8 direction) {
    __u64 k = 0;
    k |= ((__u64)pid) << 33;
    k |= (((__u64)((__u32)fd)) << 1);
    k |= (direction & 1);
    return k;
}

/* 新增：检查文件描述符是否为socket */
static __always_inline int is_socket_fd(int fd) {
    // 简单的启发式检查：大部分网络socket的fd值都 > 2
    // 而且通常不会太大（< 65536）
    if (fd < 3 || fd > 65535) {
        return 0;
    }
    // TODO: 在未来的版本中，可以通过bpf_probe_read读取
    // /proc/self/fd/X 的链接目标来确认是否为 socket:[inode]
    return 1;
}

static __always_inline int is_token_char(char c) {
    if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')) return 1;
    if (c >= '0' && c <= '9') return 1;
    if (c == '-') return 1;
    return 0;
}

static __always_inline int detect_header_prefix(const char *buf, int len) {
    // 检测形如 "Header-Name:" 的前缀（无前导空格），用于捕获拆包后以 header 起始的片段
    int token_len = 0;
    #pragma clang loop unroll(full)
    for (int i = 0; i < HTTP_METHOD_CHECK_LEN; i++) {
        if (i >= len) break;
        char c = buf[i];
        if (c == ':') {
            return token_len >= 2; // 至少 2 个 token 字符
        }
        if (!is_token_char(c)) {
            return 0;
        }
        token_len++;
    }
    return 0;
}

static __always_inline int is_http_start_fast(const char *buf, int len) {
    increment_counter(COUNTER_HTTP_CHECKS);
    if (len < 4) return 0;

    // HTTP response like "HTTP/1.1 ..."
    if (buf[0] == 'H' && len >= 4 && buf[1] == 'T' && buf[2] == 'T' && buf[3] == 'P') {
        increment_counter(COUNTER_HTTP_MATCH);
        return 1;
    }

    // For request methods, check token individually and require trailing space for those tokens
    if (buf[0] == 'G') {
        int m = (len >= 4 && buf[1] == 'E' && buf[2] == 'T' && buf[3] == ' ');
        if (m) increment_counter(COUNTER_HTTP_MATCH);
        return m;
    }
    if (buf[0] == 'P') {
        if (len >= 5 && buf[1] == 'O' && buf[2] == 'S' && buf[3] == 'T' && buf[4] == ' ') { increment_counter(COUNTER_HTTP_MATCH); return 1; }
        if (len >= 4 && buf[1] == 'U' && buf[2] == 'T' && buf[3] == ' ') { increment_counter(COUNTER_HTTP_MATCH); return 1; } // PUT 
        if (len >= 6 && buf[1] == 'A' && buf[2] == 'T' && buf[3] == 'C' && buf[4] == 'H' && buf[5] == ' ') { increment_counter(COUNTER_HTTP_MATCH); return 1; } // PATCH 
        return 0;
    }
    if (buf[0] == 'D') {
        int m = (len >= 7 && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'E' && buf[4] == 'T' && buf[5] == 'E' && buf[6] == ' ');
        if (m) increment_counter(COUNTER_HTTP_MATCH);
        return m;
    }
    if (buf[0] == 'H') {
        int m = (len >= 5 && buf[1] == 'E' && buf[2] == 'A' && buf[3] == 'D' && buf[4] == ' ');
        if (m) increment_counter(COUNTER_HTTP_MATCH);
        return m;
    }
    if (buf[0] == 'O') {
        int m = (len >= 8 && buf[1] == 'P' && buf[2] == 'T' && buf[3] == 'I' && buf[4] == 'O' && buf[5] == 'N' && buf[6] == 'S' && buf[7] == ' ');
        if (m) increment_counter(COUNTER_HTTP_MATCH);
        return m;
    }
    if (buf[0] == 'C') {
        int m = (len >= 8 && buf[1] == 'O' && buf[2] == 'N' && buf[3] == 'N' && buf[4] == 'E' && buf[5] == 'C' && buf[6] == 'T' && buf[7] == ' ');
        if (m) increment_counter(COUNTER_HTTP_MATCH);
        return m;
    }
    if (buf[0] == 'T') {
        int m = (len >= 6 && buf[1] == 'R' && buf[2] == 'A' && buf[3] == 'C' && buf[4] == 'E' && buf[5] == ' ');
        if (m) increment_counter(COUNTER_HTTP_MATCH);
        return m;
    }

    return 0;
}

static __always_inline int should_monitor_pid(__u32 pid) {
    __u32 key = 0;
    __u8 *enabled = bpf_map_lookup_elem(&filter_enabled, &key);
    if (!enabled || *enabled == 0) {
        return 1; // 默认监控所有进程
    }
    
    __u8 *monitor = bpf_map_lookup_elem(&pid_filter, &pid);
    return monitor ? (*monitor == 1) : 0;
}

static __always_inline int process_http_data(void *buf, __u32 copy_len_in, __u32 orig_len_in, __u32 pid,
                                           __s32 fd, __u8 direction, __u8 syscall_type, const char *first_bytes, int first_len) {
    if (!buf || copy_len_in == 0) {
        increment_counter(COUNTER_ERRORS);
        return 0;
    }

    // 在复制前先判断是否看起来像 HTTP，避免无谓的 ringbuf 压力
    int is_http = is_http_start_fast(first_bytes, first_len);

    // 仅在网络接收路径（recv/recvfrom/recvmsg）上，额外放宽为 Header-Token: 前缀识别
    // syscall_type: 0=recv/recvfrom, 1=read, 2=recvmsg
    if (!is_http && (syscall_type == 0 || syscall_type == 2)) {
        if (detect_header_prefix(first_bytes, first_len)) {
            increment_counter(COUNTER_HTTP_MATCH);
            is_http = 1;
        }
    }

    // 对于已识别为 HTTP 的流，放行后续片段；否则要求首片段匹配 HTTP 起始
    __u64 sk = make_stream_key(pid, fd, direction);
    if (!is_http) {
        __u8 *seen = bpf_map_lookup_elem(&http_streams, &sk);
        if (!seen || *seen == 0) {
            // 若本方向未见过 HTTP，再检查对端方向（同 pid+fd，方向取反）是否已确认是 HTTP
            __u64 sk_other = make_stream_key(pid, fd, direction ^ 1);
            __u8 *seen_other = bpf_map_lookup_elem(&http_streams, &sk_other);
            if (!seen_other || *seen_other == 0) {
                return 0;
            }
        }
        // seen==1 或对端 seen==1 则继续复制本片段
    } else {
        __u8 one = 1;
        // 本方向标记为已识别 HTTP
        bpf_map_update_elem(&http_streams, &sk, &one, BPF_ANY);
        // 同时将对端方向也标记为已识别，以便放行响应/请求的后续片段
        __u64 sk_other = make_stream_key(pid, fd, direction ^ 1);
        bpf_map_update_elem(&http_streams, &sk_other, &one, BPF_ANY);
    }

    struct http_event *e = bpf_ringbuf_reserve(&events, sizeof(struct http_event), 0);
    if (!e) {
        increment_counter(COUNTER_ERRORS);
        return 0;
    }

    // 填充事件数据
    e->pid = pid;
    if (bpf_get_current_comm(&e->comm, sizeof(e->comm)) != 0) {
        bpf_ringbuf_discard(e, 0);
        increment_counter(COUNTER_ERRORS);
        return 0;
    }
    
    e->fd = fd;
    e->direction = direction;
    e->orig_len = orig_len_in;

    // 使用最小值裁剪，确保 0 < copy_len <= MAX_HTTP_DATA_LEN
    // 改为使用 var &= const 的模式，便于 verifier 证明 R2 的上界
    __u32 copy_len;
    // copy_len_in 已经在入口检查确保非 0，这里用减一再掩码再加一，使范围变为 [1..MAX_HTTP_DATA_LEN]
    copy_len = copy_len_in - 1;
    copy_len &= (MAX_HTTP_DATA_LEN - 1);
    copy_len += 1;

    // 再次与目标缓冲区大小比较，便于 verifier 证明边界
    if (copy_len > sizeof(e->data)) {
        copy_len = sizeof(e->data);
    }
    e->len = copy_len;

    long ret = bpf_probe_read_user(e->data, copy_len, buf);
    if (ret != 0) {
        bpf_ringbuf_discard(e, 0);
        increment_counter(COUNTER_ERRORS);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);

    // 更新 HTTP 计数器
    if (direction == 0) {
        increment_counter(COUNTER_HTTP_SEND);
    } else {
        increment_counter(COUNTER_HTTP_RECV);
    }

    return 1;
}

/* 统一的接收退出处理函数 */
static __always_inline int handle_recv_exit(struct trace_event_raw_sys_exit *ctx) {
    // Stronger: guard directly on 64-bit signed return
    __s64 r64 = (__s64)ctx->ret;
    if (r64 <= 0) {
        return 0;
    }

    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;

    struct syscall_args *args = bpf_map_lookup_elem(&active_syscalls, &tid);
    if (!args) {
        return 0;
    }

    // Ensure saved user buffer pointer exists
    if (!args->buf) {
        // Clean up and return
        bpf_map_delete_elem(&active_syscalls, &tid);
        return 0;
    }

    // Copy out fields BEFORE deleting the map entry to avoid using invalidated pointer
    void *ubuf = args->buf;
    __u32 saved_len = args->len;
    __u8 stype = args->syscall_type;
    int fd = args->fd;

    // 不进行严格的用户指针范围检查，以兼容五级页表的更高地址空间

    // Now delete the entry exactly once
    bpf_map_delete_elem(&active_syscalls, &tid);

    // If this came from read(2), it's more likely to be non-socket or duplicate in presence of recv*, so keep but we already ensured only one processing due to delete-above.
    (void)stype;

    // 固定读取 32 字节用于方法/头部检测
    char first[HTTP_METHOD_CHECK_LEN] = {};
    long ret = bpf_probe_read_user(first, sizeof(first), ubuf);
    if (ret != 0) {
        increment_counter(COUNTER_ERRORS);
        increment_counter(COUNTER_READ_FAILS);
        return 0;
    }

    increment_counter(COUNTER_READ_SUCCESS);

    // 使用最小值裁剪 payload 长度，并保持与 enter 保存长度一致
    __u32 bounded_ret = (__u32)r64;
    if (bounded_ret > MAX_HTTP_DATA_LEN) {
        bounded_ret = MAX_HTTP_DATA_LEN;
    }
    if (saved_len > 0 && bounded_ret > saved_len) {
        bounded_ret = saved_len;
    }
    if (bounded_ret == 0) {
        bounded_ret = 1;
    }

    process_http_data(ubuf, bounded_ret, (__u32)r64, pid, fd, 1, stype, first, (int)sizeof(first));
    
    return 0;
}

/* Forward declarations to satisfy calls before definitions */
static __always_inline int handle_send_enter(struct trace_event_raw_sys_enter *ctx);
static __always_inline int handle_recv_enter(struct trace_event_raw_sys_enter *ctx);
static __always_inline int handle_recv_exit(struct trace_event_raw_sys_exit *ctx);
static __always_inline int handle_sendmsg_enter(struct trace_event_raw_sys_enter *ctx);
static __always_inline int handle_recvmsg_enter(struct trace_event_raw_sys_enter *ctx);
static __always_inline int handle_recvmsg_exit(struct trace_event_raw_sys_exit *ctx);

/* Unified send enter handler */
static __always_inline int handle_send_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;

    increment_counter(COUNTER_TOTAL_SEND);

    if (!should_monitor_pid(pid)) {
        return 0;
    }

    int fd = (int)ctx->args[0];
    void *buff = (void *)(unsigned long)ctx->args[1];
    __s64 sz64 = (__s64)ctx->args[2];
    if (sz64 <= 0) {
        return 0;
    }
    __u32 len = (__u32)sz64;
    if (len > MAX_CAPTURE_LEN) {
        len = MAX_CAPTURE_LEN;
    }
    if (!buff || len == 0) {
        if (!buff) increment_counter(COUNTER_SEND_BUFF_NULL);
        return 0;
    }

    char first[HTTP_METHOD_CHECK_LEN] = {};
    long ret = bpf_probe_read_user(first, sizeof(first), buff);
    if (ret != 0) {
        increment_counter(COUNTER_ERRORS);
        increment_counter(COUNTER_READ_FAILS);
        return 0;
    }

    increment_counter(COUNTER_READ_SUCCESS);

    process_http_data(buff, len, len, pid, fd, 0, 3, first, (int)sizeof(first));
    return 0;
}

/* Unified recv enter handler */
static __always_inline int handle_recv_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;

    increment_counter(COUNTER_TOTAL_RECV);

    if (!should_monitor_pid(pid)) {
        return 0;
    }

    void *ubuf = (void *)(unsigned long)ctx->args[1];
    __u32 size = (__u32)ctx->args[2];

    if (size > MAX_CAPTURE_LEN) {
        size = MAX_CAPTURE_LEN;
    }
    if (!ubuf || size == 0) {
        if (!ubuf) increment_counter(COUNTER_RECV_BUF_NULL);
        return 0;
    }

    // 逐字段赋值，避免结构体初始化语法
    struct syscall_args args = {};
    args.buf = ubuf;
    args.len = size;
    args.fd = (int)ctx->args[0];
    args.syscall_type = 0;

    long ret = bpf_map_update_elem(&active_syscalls, &tid, &args, BPF_ANY);
    if (ret != 0) {
        increment_counter(COUNTER_ERRORS);
    }

    return 0;
}

/* Special read enter handler for read() - be more selective */
static __always_inline int handle_read_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;

    increment_counter(COUNTER_TOTAL_RECV);

    if (!should_monitor_pid(pid)) {
        return 0;
    }

    // For read(), be extra selective - check if fd is likely a socket
    int fd = (int)ctx->args[0];
    if (!is_socket_fd(fd)) {
        return 0;
    }

    void *ubuf = (void *)(unsigned long)ctx->args[1];
    __u32 size = (__u32)ctx->args[2];

    if (size > MAX_CAPTURE_LEN) {
        size = MAX_CAPTURE_LEN;
    }
    if (!ubuf || size == 0) {
        if (!ubuf) increment_counter(COUNTER_RECV_BUF_NULL);
        return 0;
    }

    // 逐字段赋值
    struct syscall_args args = {};
    args.buf = ubuf;
    args.len = size;
    args.fd = fd;
    args.syscall_type = 1;

    long ret = bpf_map_update_elem(&active_syscalls, &tid, &args, BPF_ANY);
    if (ret != 0) {
        increment_counter(COUNTER_ERRORS);
    }

    return 0;
}

/* Special send enter handler for write() - be more selective */
static __always_inline int handle_write_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;

    increment_counter(COUNTER_TOTAL_SEND);

    if (!should_monitor_pid(pid)) {
        return 0;
    }

    // For write(), be extra selective - check if fd is likely a socket
    int fd = (int)ctx->args[0];
    // 临时完全禁用socket过滤，允许所有write调用被监控，方便调试
    // if (!is_socket_fd(fd)) {
    //     return 0;
    // }

    void *buff = (void *)(unsigned long)ctx->args[1];
    __s64 sz64 = (__s64)ctx->args[2];
    if (sz64 <= 0) {
        return 0;
    }
    __u32 len = (__u32)sz64;
    if (len > MAX_CAPTURE_LEN) {
        len = MAX_CAPTURE_LEN;
    }
    if (!buff || len == 0) {
        if (!buff) increment_counter(COUNTER_SEND_BUFF_NULL);
        return 0;
    }

    char first[HTTP_METHOD_CHECK_LEN] = {};
    long ret = bpf_probe_read_user(first, sizeof(first), buff);
    if (ret != 0) {
        increment_counter(COUNTER_ERRORS);
        increment_counter(COUNTER_READ_FAILS);
        return 0;
    }

    increment_counter(COUNTER_READ_SUCCESS);

    process_http_data(buff, len, len, pid, fd, 0, 3, first, (int)sizeof(first));
    return 0;
}

/* Minimal msghdr/iovec for userspace layout extraction */
struct iovec_compat {
    void *iov_base;
    unsigned long iov_len;
};
struct msghdr_compat {
    void *msg_name;
    int   msg_namelen;
    struct iovec_compat *msg_iov;
    unsigned long msg_iovlen;
    void *msg_control;
    unsigned long msg_controllen;
    unsigned int msg_flags;
};

/* sendmsg enter handler */
static __always_inline int handle_sendmsg_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;

    increment_counter(COUNTER_TOTAL_SEND);

    if (!should_monitor_pid(pid)) {
        return 0;
    }

    int fd = (int)ctx->args[0];
    struct msghdr_compat *msg = (struct msghdr_compat *)(unsigned long)ctx->args[1];
    if (!msg) {
        increment_counter(COUNTER_SEND_BUFF_NULL);
        return 0;
    }

    struct msghdr_compat hdr = {};
    if (bpf_probe_read_user(&hdr, sizeof(hdr), msg) != 0) {
        increment_counter(COUNTER_ERRORS);
        return 0;
    }
    if (!hdr.msg_iov || hdr.msg_iovlen == 0) {
        return 0;
    }

    struct iovec_compat iov0 = {};
    if (bpf_probe_read_user(&iov0, sizeof(iov0), hdr.msg_iov) != 0) {
        increment_counter(COUNTER_ERRORS);
        return 0;
    }

    void *buff = iov0.iov_base;
    __s64 sz64 = (__s64)iov0.iov_len;
    if (!buff || sz64 <= 0) {
        if (!buff) increment_counter(COUNTER_SEND_BUFF_NULL);
        return 0;
    }

    __u32 len = (__u32)sz64;
    if (len > MAX_CAPTURE_LEN) {
        len = MAX_CAPTURE_LEN;
    }

    char first[HTTP_METHOD_CHECK_LEN] = {};
    if (bpf_probe_read_user(first, sizeof(first), buff) != 0) {
        increment_counter(COUNTER_ERRORS);
        increment_counter(COUNTER_READ_FAILS);
        return 0;
    }
    increment_counter(COUNTER_READ_SUCCESS);

    process_http_data(buff, len, len, pid, fd, 0, 3, first, (int)sizeof(first));
    return 0;
}

/* recvmsg enter handler - simplified to avoid verifier issues */
static __always_inline int handle_recvmsg_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;

    increment_counter(COUNTER_TOTAL_RECV);

    if (!should_monitor_pid(pid)) {
        return 0;
    }

    // 逐字段赋值，避免结构体初始化语法
    struct syscall_args args = {};
    args.buf = (void*)ctx->args[1];  // 保存用户态 msghdr 指针，供 exit 使用
    args.len = MAX_CAPTURE_LEN;
    args.fd = (int)ctx->args[0];
    args.syscall_type = 2;  // recvmsg type

    long ret = bpf_map_update_elem(&active_syscalls, &tid, &args, BPF_ANY);
    if (ret != 0) {
        increment_counter(COUNTER_ERRORS);
    }
    
    return 0;
}

/* recvmsg exit handler - handles msghdr parsing at exit time */
static __always_inline int handle_recvmsg_exit(struct trace_event_raw_sys_exit *ctx) {
    // Check return value first
    __s64 r64 = (__s64)ctx->ret;
    if (r64 <= 0) {
        return 0;
    }

    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;

    struct syscall_args *args = bpf_map_lookup_elem(&active_syscalls, &tid);
    if (!args || args->syscall_type != 2) {
        // Clean up if exists
        if (args) {
            bpf_map_delete_elem(&active_syscalls, &tid);
        }
        return 0;
    }

    // Save and delete entry early to avoid stale pointers
    void *msg_ptr = args->buf;
    int fd = args->fd;
    bpf_map_delete_elem(&active_syscalls, &tid);
    if (!msg_ptr) {
        increment_counter(COUNTER_RECV_BUF_NULL);
        return 0;
    }

    // 读取 msghdr 结构
    struct msghdr_compat mh = {};
    if (bpf_probe_read_user(&mh, sizeof(mh), msg_ptr) != 0) {
        increment_counter(COUNTER_ERRORS);
        increment_counter(COUNTER_READ_FAILS);
        return 0;
    }

    // 读取第一个 iovec
    if (!mh.msg_iov || mh.msg_iovlen == 0) {
        return 0;
    }
    struct iovec_compat iov0 = {};
    if (bpf_probe_read_user(&iov0, sizeof(iov0), mh.msg_iov) != 0) {
        increment_counter(COUNTER_ERRORS);
        increment_counter(COUNTER_READ_FAILS);
        return 0;
    }

    void *buff = iov0.iov_base;
    __s64 sz64 = (__s64)iov0.iov_len;
    if (!buff || sz64 <= 0) {
        increment_counter(COUNTER_RECV_BUF_NULL);
        return 0;
    }

    // 按返回值和捕获上限裁剪读取长度
    __u32 bounded_ret = (r64 > 0) ? (__u32)r64 : 0;
    if (bounded_ret > MAX_CAPTURE_LEN) {
        bounded_ret = MAX_CAPTURE_LEN;
    }
    __u32 len = (__u32)sz64;
    if (len > bounded_ret) {
        len = bounded_ret;
    }

    // 读取前几个字节做 HTTP 快速判断
    char first[HTTP_METHOD_CHECK_LEN] = {};
    if (bpf_probe_read_user(first, sizeof(first), buff) != 0) {
        increment_counter(COUNTER_ERRORS);
        increment_counter(COUNTER_READ_FAILS);
        return 0;
    }
    increment_counter(COUNTER_READ_SUCCESS);

    // 发送到 ringbuf（方向=1 表示接收/响应）
    process_http_data(buff, len, (unsigned)r64, pid, fd, 1, 2, first, (int)sizeof(first));
    
    return 0;
}

/* Tracepoint 处理函数 */
SEC("tracepoint/syscalls/sys_enter_sendto")
int tp_sys_enter_sendto(struct trace_event_raw_sys_enter *ctx) {
    return handle_send_enter(ctx);
}

SEC("tracepoint/syscalls/sys_enter_send")
int tp_sys_enter_send(struct trace_event_raw_sys_enter *ctx) {
    return handle_send_enter(ctx);
}

SEC("tracepoint/syscalls/sys_enter_write")
int tp_sys_enter_write(struct trace_event_raw_sys_enter *ctx) {
    // 之前为了减少非网络流量噪声而跳过，但像 wget 可能使用 write 向套接字发送数据
    // 这里复用统一的发送处理逻辑，以捕获通过 write(2) 发送的 HTTP 请求
    return handle_write_enter(ctx);
}

SEC("tracepoint/syscalls/sys_exit_write")
int tp_sys_exit_write(struct trace_event_raw_sys_exit *ctx) {
    // 添加write exit处理，确保能捕获所有write操作的数据
    __s64 r64 = (__s64)ctx->ret;
    if (r64 <= 0) {
        return 0;
    }
    // write成功后无需额外处理，数据已在enter时捕获
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tp_sys_enter_recvfrom(struct trace_event_raw_sys_enter *ctx) {
    return handle_recv_enter(ctx);
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int tp_sys_exit_recvfrom(struct trace_event_raw_sys_exit *ctx) {
    return handle_recv_exit(ctx);
}

SEC("tracepoint/syscalls/sys_enter_recv")
int tp_sys_enter_recv(struct trace_event_raw_sys_enter *ctx) {
    return handle_recv_enter(ctx);
}

SEC("tracepoint/syscalls/sys_exit_recv")
int tp_sys_exit_recv(struct trace_event_raw_sys_exit *ctx) {
    return handle_recv_exit(ctx);
}

SEC("tracepoint/syscalls/sys_enter_read")
int tp_sys_enter_read(struct trace_event_raw_sys_enter *ctx) {
    // 复用统一的接收进入处理逻辑，以捕获通过 read(2) 接收的 HTTP 响应
    return handle_read_enter(ctx);
}

SEC("tracepoint/syscalls/sys_exit_read")
int tp_sys_exit_read(struct trace_event_raw_sys_exit *ctx) {
    // 复用统一的接收退出处理逻辑，以捕获通过 read(2) 接收的 HTTP 响应
    return handle_recv_exit(ctx);
}

// SEC sections for sendmsg/recvmsg
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int tp_sys_enter_sendmsg(struct trace_event_raw_sys_enter *ctx) {
    return handle_sendmsg_enter(ctx);
}

SEC("tracepoint/syscalls/sys_enter_recvmsg")
int tp_sys_enter_recvmsg(struct trace_event_raw_sys_enter *ctx) {
    return handle_recvmsg_enter(ctx);
}

SEC("tracepoint/syscalls/sys_exit_recvmsg")
int tp_sys_exit_recvmsg(struct trace_event_raw_sys_exit *ctx) {
    return handle_recvmsg_exit(ctx);
}

/* writev enter handler */
static __always_inline int handle_writev_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;

    increment_counter(COUNTER_TOTAL_SEND);

    if (!should_monitor_pid(pid)) {
        return 0;
    }

    int fd = (int)ctx->args[0]; 
     if (!is_socket_fd(fd)) {
         return 0;
     }

    struct iovec_compat *iov = (struct iovec_compat*)(unsigned long)ctx->args[1];
    __s64 iovcnt64 = (__s64)ctx->args[2];
    if (!iov || iovcnt64 <= 0) {
        return 0;
    }

    struct iovec_compat iov0 = {};
    if (bpf_probe_read_user(&iov0, sizeof(iov0), iov) != 0) {
        increment_counter(COUNTER_ERRORS);
        return 0;
    }

    void *buff = iov0.iov_base;
    __s64 sz64 = (__s64)iov0.iov_len;
    if (!buff || sz64 <= 0) {
        if (!buff) increment_counter(COUNTER_SEND_BUFF_NULL);
        return 0;
    }

    __u32 len = (__u32)sz64;
    if (len > MAX_CAPTURE_LEN) {
        len = MAX_CAPTURE_LEN;
    }

    char first[HTTP_METHOD_CHECK_LEN] = {};
    if (bpf_probe_read_user(first, sizeof(first), buff) != 0) {
        increment_counter(COUNTER_ERRORS);
        increment_counter(COUNTER_READ_FAILS);
        return 0;
    }
    increment_counter(COUNTER_READ_SUCCESS);

    process_http_data(buff, len, len, pid, fd, 0, 5, first, (int)sizeof(first));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_writev")
int tp_sys_enter_writev(struct trace_event_raw_sys_enter *ctx) {
    return handle_writev_enter(ctx);
}

SEC("tracepoint/syscalls/sys_exit_writev")
int tp_sys_exit_writev(struct trace_event_raw_sys_exit *ctx) {
    // 添加writev exit处理，确保能捕获所有writev操作的数据
    __s64 r64 = (__s64)ctx->ret;
    if (r64 <= 0) {
        return 0;
    }
    // writev成功后无需额外处理，数据已在enter时捕获
    return 0;
}

/* readv handlers (recv direction) */
static __always_inline int handle_readv_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;

    increment_counter(COUNTER_TOTAL_RECV);

    if (!should_monitor_pid(pid)) {
        return 0;
    }

    // Save iovec pointer and fd; length will be bounded at exit by return value
    struct syscall_args args = {};
    args.buf = (void*)ctx->args[1]; // const struct iovec *iov
    args.len = MAX_CAPTURE_LEN;     // upper bound; actual will be min(ret, iov0.len)
    args.fd = (int)ctx->args[0];
    args.syscall_type = 4;          // readv type

    __u64 key = tid;
    long ret = bpf_map_update_elem(&active_syscalls, &key, &args, BPF_ANY);
    if (ret != 0) {
        increment_counter(COUNTER_ERRORS);
    }
    return 0;
}

static __always_inline int handle_readv_exit(struct trace_event_raw_sys_exit *ctx) {
    // signed return value
    __s64 r64 = (__s64)ctx->ret;
    if (r64 <= 0) {
        return 0;
    }

    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;

    struct syscall_args *args = bpf_map_lookup_elem(&active_syscalls, &tid);
    if (!args || args->syscall_type != 4) {
        if (args == NULL) {
            increment_counter(COUNTER_RECV_ARGS_NULL);
        }
        return 0;
    }

    void *iov_ptr = args->buf;
    int fd = args->fd;

    // delete early to avoid reuse
    bpf_map_delete_elem(&active_syscalls, &tid);

    if (!iov_ptr) {
        increment_counter(COUNTER_RECV_BUF_NULL);
        return 0;
    }

    // read first iovec
    struct iovec_compat iov0 = {};
    if (bpf_probe_read_user(&iov0, sizeof(iov0), iov_ptr) != 0) {
        increment_counter(COUNTER_ERRORS);
        increment_counter(COUNTER_READ_FAILS);
        return 0;
    }

    void *buff = iov0.iov_base;
    __s64 sz64 = (__s64)iov0.iov_len;
    if (!buff || sz64 <= 0) {
        increment_counter(COUNTER_RECV_BUF_NULL);
        return 0;
    }

    __u32 bounded = (__u32)r64;
    if (bounded > MAX_CAPTURE_LEN) {
        bounded = MAX_CAPTURE_LEN;
    }
    if ((__u32)sz64 > 0 && bounded > (__u32)sz64) {
        bounded = (__u32)sz64;
    }
    if (bounded == 0) {
        bounded = 1;
    }

    char first[HTTP_METHOD_CHECK_LEN] = {};
    if (bpf_probe_read_user(first, sizeof(first), buff) != 0) {
        increment_counter(COUNTER_ERRORS);
        increment_counter(COUNTER_READ_FAILS);
        return 0;
    }

    increment_counter(COUNTER_READ_SUCCESS);

    // direction=1 (recv), syscall_type=4 (readv)
    process_http_data(buff, bounded, (__u32)r64, pid, fd, 1, 4, first, (int)sizeof(first));
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_readv")
int tp_sys_enter_readv(struct trace_event_raw_sys_enter *ctx) {
    return handle_readv_enter(ctx);
}

SEC("tracepoint/syscalls/sys_exit_readv")
int tp_sys_exit_readv(struct trace_event_raw_sys_exit *ctx) {
    return handle_readv_exit(ctx);
}

/* sendfile handlers (send direction) */
static __always_inline int handle_sendfile_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;

    increment_counter(COUNTER_TOTAL_SEND);

    if (!should_monitor_pid(pid)) {
        return 0;
    }

    int out_fd = (int)ctx->args[0];  // 输出文件描述符（通常是socket）
    int in_fd = (int)ctx->args[1];   // 输入文件描述符
    void *offset_ptr = (void *)(unsigned long)ctx->args[2];  // offset指针
    __u64 count = (__u64)ctx->args[3];  // 传输字节数

    // 检查输出fd是否为socket
    if (!is_socket_fd(out_fd)) {
        return 0;
    }

    // sendfile通常用于发送文件，我们标记该流以便后续数据包能被捕获
    __u64 sk = make_stream_key(pid, out_fd, 0);  // direction=0 (send)
    __u8 one = 1;
    bpf_map_update_elem(&http_streams, &sk, &one, BPF_ANY);
    
    // 同时标记接收方向，以便捕获完整对话
    __u64 sk_recv = make_stream_key(pid, out_fd, 1);
    bpf_map_update_elem(&http_streams, &sk_recv, &one, BPF_ANY);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_sendfile")
int tp_sys_enter_sendfile(struct trace_event_raw_sys_enter *ctx) {
    return handle_sendfile_enter(ctx);
}

SEC("tracepoint/syscalls/sys_enter_sendfile64")
int tp_sys_enter_sendfile64(struct trace_event_raw_sys_enter *ctx) {
    return handle_sendfile_enter(ctx);
}