// src/program.bpf.c
// eBPF kernel-space program for tracing process execution
// Uses libbpf and CO-RE for portability across kernel versions

// Include vmlinux.h for kernel type definitions
// This is generated from kernel BTF and provides ALL kernel types
// It replaces the need for individual kernel headers
#include "vmlinux.h"

// libbpf helper macros for CO-RE and BPF operations
#include <bpf/bpf_helpers.h>

// CO-RE helper macros for reading kernel structures safely
// BPF_CORE_READ handles field offset relocations automatically
#include <bpf/bpf_core_read.h>

// Tracing-specific helpers for attaching to tracepoints
#include <bpf/bpf_tracing.h>

// Our shared definitions
#include "common.h"

// Declare the license - GPL is required for most BPF helper functions
// This MUST be present or the verifier will reject the program
char LICENSE[] SEC("license") = "GPL";

// Ring buffer map for sending events to user space
// Ring buffers are more efficient than perf buffers for high-throughput
// The size (256KB here) should be tuned based on expected event rate
struct {
    // Specify this is a ring buffer type map
    __uint(type, BPF_MAP_TYPE_RINGBUF);

    // Size in bytes - must be power of 2 and page-aligned
    // 256 * 1024 = 256KB, enough for ~1000 events in buffer
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

// Tracepoint program attached to sys_enter_execve
// SEC() macro specifies the attachment point
// Format: "tp/<category>/<tracepoint_name>"
SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    struct event *e;

    // Get the current task_struct using CO-RE
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // Reserve space in the ring buffer for our event
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        // Buffer full, drop this event
        // In production, you might want to track dropped events
        return 0;
    }

    // Get the current PID (process ID)
    // bpf_get_current_pid_tgid() returns (pid << 32 | tgid)
    // We want the lower 32 bits (tgid in kernel = pid in userspace)
    e->pid = bpf_get_current_pid_tgid() >> 32;

    // Get the current UID (user ID)
    // Similar to above, uid_gid returns (gid << 32 | uid)
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Get the process command name (e.g., "bash", "ls")
    // This copies TASK_COMM_LEN bytes to our event structure
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Read the filename argument from the execve syscall
    // ctx->args[0] contains the pointer to the filename string
    // We use bpf_probe_read_user_str for user-space strings
    // This safely handles page faults and returns bytes read
    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename_ptr);

    // Submit the event to the ring buffer
    // 0 = flags (none needed)
    // This makes the event visible to user space
    bpf_ringbuf_submit(e, 0);

    return 0;
}
