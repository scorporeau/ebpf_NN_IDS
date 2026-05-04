// vmlinux include first (to define types __u32, and more)
#include "vmlinux.h"

//bpf includes
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

//project common definitions
#include "common.h"


char LICENSE[] SEC("license") = "GPL";

#ifndef SILENT
// Create a ring buffer map (as in the event catcher program) to send the packet information to the user space
struct {
    // Specify this is a ring buffer type map
    __uint(type, BPF_MAP_TYPE_RINGBUF);

    // Size in bytes - must be power of 2 and page-aligned
    // TODO: find a real good size (512*1024 is random lol)
    __uint(max_entries, 512 * 1024);// 512 kB
} events_ring SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u64);
} drop_counter SEC(".maps");
#endif

//if doing tailing (docs.ebpf.io), we have to create a structure progs taht is storing pointers to the different ebpf programs.
// struct {
//     __uint(type, BPF_MAP_TYPE_PROG_ARRAY); 
//     __uint(max_entries, 256);
//     __type(key, u32);
//     __type(value, u32);
// } progs SEC(".maps");


//parsing function retrieve information parsed by the kernel
static inline int parse_pack(struct __sk_buff *skb, struct netevent *e) {
    //initialize event structure with packet information contained in the __sk_buff structure
    // Get pointers to the start and end of the packet data.
    void *data_end = (void*)(long)skb->data_end; 
    void *data = (void*)(long)skb->data;
    e->packet_size = data_end - data; //retrieve packet size

    struct ethhdr *eth_data;
    struct iphdr *ip_data;
    struct tcphdr *tcp_data;
    struct udphdr *udp_data;

    //checking eth layer
    eth_data = data;
    if (eth_data + 1 > data_end) {
        return -1; // error, packet too short for eth header
    }

    //checking if its IP 
    if (eth_data->h_proto != bpf_htons(ETH_P_IP)) {
        return -2; // not an IP packet
    }

    //checking IP layer
    ip_data = data + sizeof(struct ethhdr);
    if (ip_data + 1 > data_end) {
        return -3; // error, packet too short for IP header
    }
    if (ip_data->version != 4) {
        return -2; // not IPv4
    }
    e->src_ip = ip_data->saddr;
    e->dst_ip = ip_data->daddr;
    e->protocol = ip_data->protocol;

    //parsing protocols
    if (ip_data->protocol == IPPROTO_TCP) {
        //TCP handling
        tcp_data = (void*)ip_data + ip_data->ihl * 4;
        if (tcp_data + 1 > data_end) {
            return -4; //too short for TCP
        }
        //retrieving ports
        e->src_port = bpf_ntohs(tcp_data->source);
        e->dst_port = bpf_ntohs(tcp_data->dest);
    } else if (ip_data->protocol == IPPROTO_UDP) {
        //UDP handling
        udp_data = (void*)ip_data + ip_data->ihl * 4;
        if (udp_data + 1 > data_end) {
            return -5; //too short for UDP
        }
        e->src_port = bpf_ntohs(udp_data->source);
        e->dst_port = bpf_ntohs(udp_data->dest);
    } else {
        //other protocol
        //no ports
        e-> src_port = 0;
        e-> dst_port = 0;
    }

    return 0;
}


SEC("tc/ingress")
int tc_trace_net_event(struct __sk_buff *skb)
{
    __u64 t0 = bpf_ktime_get_ns();
    struct netevent *e;
    __u32 key = -1;
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
    __u64 t1 = bpf_ktime_get_ns();

    //parsing packet for IPs and ports informations (forced in TC)
    int err = parse_pack(skb, e);
    
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
    return TCX_PASS;
#else
submit:
    bpf_ringbuf_submit(e, 0);
    return TCX_PASS;
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
    return TCX_PASS;
#endif
}