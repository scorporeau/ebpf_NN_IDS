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

#ifndef SILENT
// Create a ring buffer map (as in the event catcher program) to send the packet information to the user space
struct {
    // Specify this is a ring buffer type map
    __uint(type, BPF_MAP_TYPE_RINGBUF);

    // Size in bytes - must be power of 2 and page-aligned
    // TODO: find a real good size (512*1024 is random lol)
    __uint(max_entries, 512 * 1024);
} events_ring SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} drop_counter SEC(".maps");
#endif


static inline int parse_pack(struct trace_event_raw_net_dev_template *ctx, struct netevent *e) {
    //initialize event structure with packet information contained in the __sk_buff structure
    struct iphdr ip_data = {};
    struct tcphdr tcp_data = {};
    struct udphdr udp_data = {};
    struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr; 
    //https://docs.kernel.org/networking/skbuff.html
    //http://oldvger.kernel.org/~davem/skb.html
    __builtin_memset(e, 0, sizeof(*e)); //initializing netevent to zero

    if (!skb) {
        return -1; // error, no skb
    }
    __u16 network_header = BPF_CORE_READ(skb, network_header);
    __u16 transport_header = BPF_CORE_READ(skb, transport_header);
    char *head = BPF_CORE_READ(skb, head); //head of the skbuff structure
    e->packet_size = BPF_CORE_READ(skb, data_len); //retrieve data lenght in the buffer. len = buffer length != data length

    // Read IP header
    if (bpf_probe_read_kernel(&ip_data, sizeof(ip_data), head + network_header) < 0)
    {
        return -2; // not IP, drop
    }
    if (ip_data.version != 4) {
        return -2; // not IPv4
    }
    e->src_ip = ip_data.saddr;
    e->dst_ip = ip_data.daddr;
    e->protocol = ip_data.protocol;


    // Read & parse protocols
    if (ip_data.protocol == IPPROTO_TCP) {
        //TCP handling
        if (bpf_probe_read_kernel(&tcp_data, sizeof(tcp_data), head + transport_header) < 0) {
            return -4; // error, packet too short for TCP header
        }
        //retrieving ports
        e->src_port = bpf_ntohs(tcp_data.source);
        e->dst_port = bpf_ntohs(tcp_data.dest);
    } else if (ip_data.protocol == IPPROTO_UDP) {
        //UDP handling
        if (bpf_probe_read_kernel(&udp_data, sizeof(udp_data), head + transport_header) < 0) {
            return -5; // ERROR: Packet too short for UDP header
        }
        e->src_port = bpf_ntohs(udp_data.source);
        e->dst_port = bpf_ntohs(udp_data.dest);
    } else {
        //other protocol
        //no ports
        e-> src_port = 0;
        e-> dst_port = 0;
    }

    return 0;
}

SEC("tracepoint/net/netif_receive_skb")
int trace_netif_receive_skb(struct trace_event_raw_net_dev_template *ctx)
{
    __u64 t0 = bpf_ktime_get_ns();  
    __u32 key = -1;
    struct netevent *e;

    #ifndef SILENT
    //reserve space in the ring buffer
    e = bpf_ringbuf_reserve(&events_ring, sizeof(*e), 0);
    if (!e) {
        key = 0;
        goto discard;
    }
    #else
    // if we're in silent mode, we don't care about the ring buffer, so we have to use this trick to avoid uninitialized variable
    struct netevent e_dummy;
    e = &e_dummy;
    #endif

    __u64 t1 = bpf_ktime_get_ns(); // -------- start parsing

    //Parse the packet & retrieve the error
    int err = parse_pack(ctx, e);
    
    
    __u64 t2 = bpf_ktime_get_ns();
    e->t_parsing = ((t2 - t1) >= 0xFFFF ? 0xFFFF : (__u16) t2-t1);
    e->t_tot = ((t2 - t0) >= 0xFFFF ? 0xFFFF : (__u16) t2-t0);
    e->t_classification = 0; //not relevant here
    e->decision = 0; //not relevant here

    if (err == -1) {
        // Packet too short for eth header
        key = 1;
        goto discard;
    } else if (err == -2) {
        key = 2; // Not an IP packet
        goto discard;
    } else if (err == -3) {
        key = 3; // Packet too short for IP header
        goto discard;
    } else if (err == -4) {
        key = 4; // Packet too short for TCP header
        goto discard;
    } else if (err == -5) {
        key = 5; // Packet too short for UDP header
        goto discard;
    } else if (err < 0) {
        key = 6; // Other parsing error
        goto discard;
    }

#ifdef SILENT
submit:
discard:
    return 0;
#else
submit:
    bpf_ringbuf_submit(e, 0);
    return 0;
discard:
    if (e) {
        bpf_ringbuf_discard(e, 0);
    }
    if (key >= 0) {
        __u64 *cnt = bpf_map_lookup_elem(&drop_counter, &key);
        if (cnt) {
            __sync_fetch_and_add(cnt, 1);
        }
    }
    return 0;
#endif
}