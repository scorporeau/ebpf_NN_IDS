// include/common.h
// Common definitions shared between eBPF and user-space programs
// This file is included by both program.bpf.c and main.c

#ifndef __COMMON_H
#define __COMMON_H

#define NET_INTERFACE "enx6c0b5ef61e49" //PUT YOUR NETWORK INTERFACE NAME HERE

// Maximum length for command name storage
// Linux TASK_COMM_LEN is 16, we use the same
#define TASK_COMM_LEN 16

// Maximum length for filename storage
// Keep this reasonable to avoid stack overflow in eBPF
#define MAX_FILENAME_LEN 256

// IP protocol ID for ethernet layer
#define ETH_P_IP 0x0800

// Event structure passed from eBPF to user space via ring buffer
// This structure MUST be aligned properly for both kernel and user space
struct event {
    // Process ID of the executing process
    __u32 pid;

    // User ID of the process owner
    __u32 uid;

    // Command name (executable name, truncated to 16 chars)
    char comm[TASK_COMM_LEN];

    // Full filename/path of the executed binary
    char filename[MAX_FILENAME_LEN];
};

// structure for network events from eBPF to user space
struct netevent {
    __u32 src_ip;       // Source IP (IPv4)
    __u32 dst_ip;       // Destination IP
    __u16 src_port;     // Source port
    __u16 dst_port;     // Destination port
    __u8 protocol;      // IPPROTO_TCP (6), IPPROTO_UDP (17)
    __u32 packet_size;  // bytes
    __u32 pid;          // Process that owns the socket
};

#endif /* __COMMON_H */
