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


SEC("tracepoint/net/netif_receive_skb")
int trace_netif_receive_skb(struct trace_event_raw_net_dev_template *ctx)
{
    __u64 t0 = bpf_ktime_get_ns();  

    struct netevent *e;
    struct iphdr ip_data = {};
    struct tcphdr tcp_data = {};
    struct udphdr udp_data = {};
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr; //retrieving 

    // Reserve space in the ring buffer
    e = bpf_ringbuf_reserve(&events_ring, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    __u64 t1 = bpf_ktime_get_ns(); // -------- start parsing

    //initialize event structure with packet information contained in the __sk_buff structure
    e->packet_size = ctx->len;

    // Read skb->head and skb->network_header to locate the IP header
    // skb->mac_header points to Ethernet, network_header points past it to IP
    unsigned char *head          = NULL;
    __u16          net_offset    = 0;
    __u16          transp_offset = 0;

    BPF_CORE_READ_INTO(&head,          skb, head);
    BPF_CORE_READ_INTO(&net_offset,    skb, network_header);
    BPF_CORE_READ_INTO(&transp_offset, skb, transport_header);
    if (!head || net_offset == 0)
    {
        goto discard; // can't locate headers, skip without reserving ringbuf
    }

    // Read IP header
    if (bpf_probe_read_kernel(&ip_data, sizeof(ip_data),head + net_offset) < 0)
    {
        goto discard; // not IP
    }
    if (ip_data.version != 4) {
        goto discard;
    }
    e->src_ip = ip_data.saddr;
    e->dst_ip = ip_data.daddr;
    e->protocol = ip_data.protocol;


    // Read & parse protocols
    if (ip_data.protocol == IPPROTO_TCP) {
        //TCP handling
        if (bpf_probe_read_kernel(&tcp_data, sizeof(tcp_data), head + net_offset + transp_offset) < 0) {
            e->protocol = 204; // ERROR: Packet too short for TCP header
            goto submit;
        }
        //retrieving ports
        e->src_port = bpf_ntohs(tcp_data.source);
        e->dst_port = bpf_ntohs(tcp_data.dest);
    } else if (ip_data.protocol == IPPROTO_UDP) {
        //UDP handling
        if (bpf_probe_read_kernel(&udp_data, sizeof(udp_data), head + net_offset + transp_offset) < 0) {
            e->protocol = 205; // ERROR: Packet too short for UDP header
            goto submit;
        }
        e->src_port = bpf_ntohs(udp_data.source);
        e->dst_port = bpf_ntohs(udp_data.dest);
    } else {
        //other protocol
        //no ports
        e-> src_port = 0;
        e-> dst_port = 0;
    }
    
    __u64 t2 = bpf_ktime_get_ns();
    e->t_parsing = ((t2 - t1) >= 0xFFFF ? 0xFFFF : (__u16) t2-t1);
    e->t_tot = ((t2 - t0) >= 0xFFFF ? 0xFFFF : (__u16) t2-t0);
    e->t_classification = 0; //not relevant here
    e->decision = 0; //not relevant here
submit:
    bpf_ringbuf_submit(e, 0);
    return 0;
discard:
    bpf_ringbuf_discard(e, 0);
    return 0;
}