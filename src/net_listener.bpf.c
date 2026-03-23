// eBPF kernel program to trace all network packets (& output them for now)

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

// Create a ring buffer map (as in the event catcher program) to send the packet information to the user space
struct {
    // Specify this is a ring buffer type map
    __uint(type, BPF_MAP_TYPE_RINGBUF);

    // Size in bytes - must be power of 2 and page-aligned
    // TODO: find a real good size (512*1024 is random lol)
    __uint(max_entries, 512 * 1024);
} events_ring SEC(".maps");


SEC("tp/net/net_dev_start_xmit")
int trace_net_dev_start_xmit(struct trace_event_raw_net_dev_start_xmit *ctx)
{
    struct netevent *e;
    struct iphdr iph_data;
    struct tcphdr tcph_data;
    struct udphdr udph_data;
    void *skb_data;

    e = bpf_ringbuf_reserve(&events_ring, sizeof(*e), 0);
    if (!e) {
        return 0;
    }
    // Access the sk_buff structure from tracepoint
    struct sk_buff *skb = ctx->skbaddr;
    
    // Get packet data start (kernel pointer)
    BPF_CORE_READ_INTO(&skb_data, skb, data);
    BPF_CORE_READ_INTO(&e->packet_size, skb, len);
    
    // Use the network_offset from context to find the IP header
    void *ip_header = skb_data + ctx->network_offset;
    
    // Read IP header from kernel memory using bpf_probe_read_kernel
    if (bpf_probe_read_kernel(&iph_data, sizeof(iph_data), ip_header) < 0) {
        goto submit;
    }
    
    e->src_ip = iph_data.saddr;
    e->dst_ip = iph_data.daddr;
    e->protocol = iph_data.protocol;
    
    // Use transport_offset if available
    if (ctx->transport_offset_valid) {
        void *transport_header = skb_data + ctx->transport_offset;
        
        // Parse TCP/UDP based on protocol
        if (e->protocol == IPPROTO_TCP) {
            if (bpf_probe_read_kernel(&tcph_data, sizeof(tcph_data), 
                                      transport_header) < 0) {
                goto submit;
            }
            e->src_port = ((tcph_data.source & 0xFF) << 8) | ((tcph_data.source >> 8) & 0xFF);
            e->dst_port = ((tcph_data.dest & 0xFF) << 8) | ((tcph_data.dest >> 8) & 0xFF);
        } else if (e->protocol == IPPROTO_UDP) {
            if (bpf_probe_read_kernel(&udph_data, sizeof(udph_data), 
                                      transport_header) < 0) {
                goto submit;
            }
            e->src_port = ((udph_data.source & 0xFF) << 8) | ((udph_data.source >> 8) & 0xFF);
            e->dst_port = ((udph_data.dest & 0xFF) << 8) | ((udph_data.dest >> 8) & 0xFF);
        }
    }

submit:
    bpf_ringbuf_submit(e, 0);
    return 0;
}