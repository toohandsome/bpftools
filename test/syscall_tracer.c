#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/ptrace.h>
#include <linux/sched.h>

char LICENSE[] SEC("license") = "GPL";

#define TARGET_PID 750849
// 临时禁用PID过滤，监控所有进程
#define ENABLE_PID_FILTER 0
#define MAX_DATA_LEN 4096

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

struct syscall_event {
    __u32 pid;
    __u32 fd;
    __u32 len;
    __u32 ret_val;
    __u8 is_write; // 1=write, 0=read
    __u8 is_special; // 1=special syscall (len=0 but ret>0), 0=normal
    char comm[16];
    char data[MAX_DATA_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB
} events SEC(".maps");

struct syscall_args {
    __u32 fd;
    __u64 buf_addr;  // 使用地址而不是指针
    __u32 len;
    __u8 is_write;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);  // tid
    __type(value, struct syscall_args);
} active_calls SEC(".maps");

static __always_inline int should_trace_pid(__u32 pid) {
#if ENABLE_PID_FILTER
    return pid == TARGET_PID;
#else
    // 只监控名称包含"java"或"elasticsearch"的进程
    char comm[16];
    if (bpf_get_current_comm(&comm, sizeof(comm)) != 0) {
        return 0;
    }
    
    // 检查进程名是否包含相关关键词
    for (int i = 0; i < 12; i++) { // "elasticsearch"长度检查
        if (comm[i] == 0) break;
        if (comm[i] == 'j' && comm[i+1] == 'a' && comm[i+2] == 'v' && comm[i+3] == 'a') {
            return 1;
        }
        if (comm[i] == 'e' && comm[i+1] == 'l' && comm[i+2] == 'a' && comm[i+3] == 's') {
            return 1;
        }
    }
    return 0;
#endif
}
static __always_inline void submit_event(__u32 pid, __u32 fd, __u64 buf_addr, __u32 len, __u32 ret_val, __u8 is_write) {
    struct syscall_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return;
    }

    e->pid = pid;
    e->fd = fd;
    e->len = len;
    e->ret_val = ret_val;
    e->is_write = is_write;
    
    // 检测特殊系统调用（len=0但ret_val>0）
    e->is_special = (len == 0 && ret_val > 0) ? 1 : 0;
    
    if (bpf_get_current_comm(&e->comm, sizeof(e->comm)) != 0) {
        bpf_ringbuf_discard(e, 0);
        return;
    }

    // 对所有成功的系统调用读取数据
    if (buf_addr && ret_val > 0) {
        void *buf = (void*)(unsigned long)buf_addr;
        __u32 read_len = ret_val;
        
        // 使用eBPF要求的严格边界检查模式
        read_len &= 511;  // 限制为最大511字节
        
        if (read_len > 0) {
            bpf_probe_read_user(e->data, read_len, buf);
        }
    }
    
    bpf_ringbuf_submit(e, 0);
}

// write系统调用enter处理
SEC("tracepoint/syscalls/sys_enter_write")
int trace_write_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;
    
    if (!should_trace_pid(pid)) {
        return 0;
    }

    struct syscall_args args = {};
    args.fd = (int)ctx->args[0];
    args.buf_addr = (__u64)ctx->args[1];
    args.len = (__u32)ctx->args[2];
    args.is_write = 1;
    
    bpf_map_update_elem(&active_calls, &tid, &args, BPF_ANY);
    return 0;
}

// write系统调用exit处理
SEC("tracepoint/syscalls/sys_exit_write")
int trace_write_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;
    
    if (!should_trace_pid(pid)) {
        return 0;
    }

    struct syscall_args *args = bpf_map_lookup_elem(&active_calls, &tid);
    if (!args) {
        return 0;
    }

    __s64 ret = (__s64)ctx->ret;
    if (ret > 0) {
        // 在write exit时读取数据，因为这时数据已经被写入了
        submit_event(pid, args->fd, args->buf_addr, args->len, (__u32)ret, 1);
    }
    
    bpf_map_delete_elem(&active_calls, &tid);
    return 0;
}

// read系统调用enter处理
SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;
    
    if (!should_trace_pid(pid)) {
        return 0;
    }

    struct syscall_args args = {};
    args.fd = (int)ctx->args[0];
    args.buf_addr = (__u64)ctx->args[1];
    args.len = (__u32)ctx->args[2];
    args.is_write = 0;
    
    bpf_map_update_elem(&active_calls, &tid, &args, BPF_ANY);
    return 0;
}

// read系统调用exit处理
SEC("tracepoint/syscalls/sys_exit_read")
int trace_read_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;
    
    if (!should_trace_pid(pid)) {
        return 0;
    }

    struct syscall_args *args = bpf_map_lookup_elem(&active_calls, &tid);
    if (!args) {
        return 0;
    }

    __s64 ret = (__s64)ctx->ret;
    if (ret > 0) {
        submit_event(pid, args->fd, args->buf_addr, args->len, (__u32)ret, 0);
    }
    
    bpf_map_delete_elem(&active_calls, &tid);
    return 0;
}

// 添加send系统调用监控
SEC("tracepoint/syscalls/sys_enter_send")
int trace_send_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;
    
    if (!should_trace_pid(pid)) {
        return 0;
    }

    struct syscall_args args = {};
    args.fd = (int)ctx->args[0];
    args.buf_addr = (__u64)ctx->args[1];
    args.len = (__u32)ctx->args[2];
    args.is_write = 1;
    
    bpf_map_update_elem(&active_calls, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_send")
int trace_send_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;
    
    if (!should_trace_pid(pid)) {
        return 0;
    }

    struct syscall_args *args = bpf_map_lookup_elem(&active_calls, &tid);
    if (!args) {
        return 0;
    }

    __s64 ret = (__s64)ctx->ret;
    if (ret > 0) {
        submit_event(pid, args->fd, args->buf_addr, args->len, (__u32)ret, 1);
    }
    
    bpf_map_delete_elem(&active_calls, &tid);
    return 0;
}

// 添加sendto系统调用监控
SEC("tracepoint/syscalls/sys_enter_sendto")
int trace_sendto_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;
    
    if (!should_trace_pid(pid)) {
        return 0;
    }

    struct syscall_args args = {};
    args.fd = (int)ctx->args[0];
    args.buf_addr = (__u64)ctx->args[1];
    args.len = (__u32)ctx->args[2];
    args.is_write = 1;
    
    bpf_map_update_elem(&active_calls, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendto")
int trace_sendto_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;
    
    if (!should_trace_pid(pid)) {
        return 0;
    }

    struct syscall_args *args = bpf_map_lookup_elem(&active_calls, &tid);
    if (!args) {
        return 0;
    }

    __s64 ret = (__s64)ctx->ret;
    if (ret > 0) {
        submit_event(pid, args->fd, args->buf_addr, args->len, (__u32)ret, 1);
    }
    
    bpf_map_delete_elem(&active_calls, &tid);
    return 0;
}

// 添加sendmsg系统调用监控
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_sendmsg_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;
    
    if (!should_trace_pid(pid)) {
        return 0;
    }

    struct syscall_args args = {};
    args.fd = (int)ctx->args[0];
    // sendmsg使用msghdr结构，我们先记录调用
    args.buf_addr = 0;
    args.len = 0;
    args.is_write = 1;
    
    bpf_map_update_elem(&active_calls, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendmsg")
int trace_sendmsg_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;
    
    if (!should_trace_pid(pid)) {
        return 0;
    }

    struct syscall_args *args = bpf_map_lookup_elem(&active_calls, &tid);
    if (!args) {
        return 0;
    }

    __s64 ret = (__s64)ctx->ret;
    if (ret > 0) {
        submit_event(pid, args->fd, 0, 0, (__u32)ret, 1);
    }
    
    bpf_map_delete_elem(&active_calls, &tid);
    return 0;
}

// 添加writev系统调用监控
SEC("tracepoint/syscalls/sys_enter_writev")
int trace_writev_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;
    
    if (!should_trace_pid(pid)) {
        return 0;
    }

    struct syscall_args args = {};
    args.fd = (int)ctx->args[0];
    // writev使用iovec数组，我们先记录调用
    args.buf_addr = 0;
    args.len = 0;
    args.is_write = 1;
    
    bpf_map_update_elem(&active_calls, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_writev")
int trace_writev_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;
    
    if (!should_trace_pid(pid)) {
        return 0;
    }

    struct syscall_args *args = bpf_map_lookup_elem(&active_calls, &tid);
    if (!args) {
        return 0;
    }

    __s64 ret = (__s64)ctx->ret;
    if (ret > 0) {
        submit_event(pid, args->fd, 0, 0, (__u32)ret, 1);
    }
    
    bpf_map_delete_elem(&active_calls, &tid);
    return 0;
}

// 添加readv系统调用监控
SEC("tracepoint/syscalls/sys_enter_readv")
int trace_readv_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;
    
    if (!should_trace_pid(pid)) {
        return 0;
    }

    struct syscall_args args = {};
    args.fd = (int)ctx->args[0];
    args.buf_addr = 0;
    args.len = 0;
    args.is_write = 0;
    
    bpf_map_update_elem(&active_calls, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_readv")
int trace_readv_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;
    
    if (!should_trace_pid(pid)) {
        return 0;
    }

    struct syscall_args *args = bpf_map_lookup_elem(&active_calls, &tid);
    if (!args) {
        return 0;
    }

    __s64 ret = (__s64)ctx->ret;
    if (ret > 0) {
        submit_event(pid, args->fd, 0, 0, (__u32)ret, 0);
    }
    
    bpf_map_delete_elem(&active_calls, &tid);
    return 0;
}

// 添加sendfile系统调用监控
SEC("tracepoint/syscalls/sys_enter_sendfile")
int trace_sendfile_enter(struct trace_event_raw_sys_enter *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;
    
    if (!should_trace_pid(pid)) {
        return 0;
    }

    struct syscall_args args = {};
    args.fd = (int)ctx->args[0]; // out_fd
    args.buf_addr = 0;
    args.len = 0;
    args.is_write = 1;
    
    bpf_map_update_elem(&active_calls, &tid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_sendfile")
int trace_sendfile_exit(struct trace_event_raw_sys_exit *ctx) {
    __u64 tid = bpf_get_current_pid_tgid();
    __u32 pid = tid >> 32;
    
    if (!should_trace_pid(pid)) {
        return 0;
    }

    struct syscall_args *args = bpf_map_lookup_elem(&active_calls, &tid);
    if (!args) {
        return 0;
    }

    __s64 ret = (__s64)ctx->ret;
    if (ret > 0) {
        submit_event(pid, args->fd, 0, 0, (__u32)ret, 1);
    }
    
    bpf_map_delete_elem(&active_calls, &tid);
    return 0;
}