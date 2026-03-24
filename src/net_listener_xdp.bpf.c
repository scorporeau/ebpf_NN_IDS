// eBPF kernel program to trace all network packets (& output them for now)

// Include vmlinux.h for kernel type definitions
// This is generated from kernel BTF and provides ALL kernel types
// It replaces the need for individual kernel headers
#include "vmlinux.h"

// libbpf helper macros for CO-RE and BPF operations
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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

// Create a ring buffer map (as in the event catcher program) to send the packet information to the user space
struct {
    // Specify this is a ring buffer type map
    __uint(type, BPF_MAP_TYPE_RINGBUF);

    // Size in bytes - must be power of 2 and page-aligned
    // TODO: find a real good size (512*1024 is random lol)
    __uint(max_entries, 512 * 1024);
} events_ring SEC(".maps");


//if doing tailing (docs.ebpf.io), we have to create a structure progs taht is storing pointers to the different ebpf programs.
// struct {
//     __uint(type, BPF_MAP_TYPE_PROG_ARRAY); 
//     __uint(max_entries, 256);
//     __type(key, u32);
//     __type(value, u32);
// } progs SEC(".maps");


//parsing function (to parse the packet & output protocol, etc.)
// BE CAREFUL TO CATCH ERRORS CODES
static inline int parse_pack(struct xdp_md *ctx, struct netevent *e)
{
    // retrieving packet data & size
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    //check the eth header
    struct ethhdr *eth = data;
    if (eth + 1 > data_end) {
        return -1; // error, packet too short
    }

    //check if its IP protocol
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return -2; // not an IP packet
    }

    //get ip header
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip + 1 > data_end) {
        return -3; // error, packet too short for IP header
    }

    e->dst_ip = ip->daddr;
    e->src_ip = ip->saddr;

    //get protocol (TCP, UDP or something else)
    // IP protocol list : https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
    if (ip->protocol == IPPROTO_TCP) {
        e->protocol = 6; // TCP
        struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if (tcp + 1 > data_end) {
            return -4; // error, packet too short for TCP header
        }
        e->src_port = bpf_ntohs(tcp->source);
        e->dst_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        e->protocol = 17; // UDP
        struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if (udp + 1 > data_end) {
            return -5; // error, packet too short for UDP header
        }
        e->src_port = bpf_ntohs(udp->source);
        e->dst_port = bpf_ntohs(udp->dest);
    } else {
        e->protocol = ip->protocol; // other protocol

        e-> src_port = 0;
        e-> dst_port = 0;
    }

}


//TODO : modify following script to do XDP instead of tracepoint
SEC("xdp")
int xdp_trace_net_event(struct xdp_md *ctx)
{
    struct netevent *e;
    struct iphdr iph_data;
    struct tcphdr tcph_data;
    struct udphdr udph_data;

    // Reserve space in the ring buffer for our event structure
    e = bpf_ringbuf_reserve(&events_ring, sizeof(*e), 0);
    if (!e) {
        return XDP_PASS;
        // Ring buffer is full, pass the packet through
    }

    //parse the packet into the event structure
    if (parse_pack(ctx, e) < 0) {
        bpf_ringbuf_discard(e, 0); // Discard the reserved event if parsing failed
        return XDP_PASS; // Pass the packet through
    }
    
    e->src_ip = iph_data.saddr;
    e->dst_ip = iph_data.daddr;
    e->protocol = iph_data.protocol;
    
    // Parse TCP/UDP based on protocol
    if (e->protocol == IPPROTO_TCP) {
        e->src_port = ((tcph_data.source & 0xFF) << 8) | ((tcph_data.source >> 8) & 0xFF);
        e->dst_port = ((tcph_data.dest & 0xFF) << 8) | ((tcph_data.dest >> 8) & 0xFF);
    } else if (e->protocol == IPPROTO_UDP) {
        e->src_port = ((udph_data.source & 0xFF) << 8) | ((udph_data.source >> 8) & 0xFF);
        e->dst_port = ((udph_data.dest & 0xFF) << 8) | ((udph_data.dest >> 8) & 0xFF);
    }

submit:
    bpf_ringbuf_submit(e, 0);
    return 0;
}