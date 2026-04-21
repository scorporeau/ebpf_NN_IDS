// vmlinux include first (to define types __u32, and more)
#include "vmlinux.h"

//bpf includes
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

//project common definitions
#include "common.h"


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
            return -4;
        }
        //retrieving ports
        e->src_port = bpf_ntohs(tcp_data->source);
        e->dst_port = bpf_ntohs(tcp_data->dest);
    } else if (ip_data->protocol == IPPROTO_UDP) {
        //UDP handling
        udp_data = (void*)ip_data + ip_data->ihl * 4;
        if (udp_data + 1 > data_end) {
            return -5;
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
    //reserve space in the ring buffer
    e = bpf_ringbuf_reserve(&events_ring, sizeof(*e), 0);
    if (!e) {
        // ERROR: ringbuf null, pass packet
        return TCX_PASS;
    }
    __u64 t1 = bpf_ktime_get_ns();

    //parsing packet for IPs and ports informations (forced in TC)
    int err = parse_pack(skb, e);
    
    __u64 t2 = bpf_ktime_get_ns();
    e->t_parsing = ((t2 - t1) >= 0xFFFF ? 0xFFFF : (__u16) t2-t1);
    e->t_tot = ((t2 - t0) >= 0xFFFF ? 0xFFFF : (__u16) t2-t0);
    e->t_classification = 0; //not relevant here
    e->decision = 0; //not relevant here

    if (err == -1) {
        e->protocol = 201; // Packet too short
        goto submit;
    } else if (err == -2) {
        // e->protocol = 202; // Not an IP packet
        // goto submit;
        goto discard;
    } else if (err == -3) {
        e->protocol = 203; // Packet too short for IP header
        goto submit;
    } else if (err == -4) {
        e->protocol = 204; // Packet too short for TCP header
        goto submit;
    } else if (err == -5) {
        e->protocol = 205; // Packet too short for UDP header
        goto submit;
    } else if (err < 0) {
        e->protocol = 244; // Other parsing error
        goto submit;
    }

submit:
    bpf_ringbuf_submit(e, 0);
    return TCX_PASS;
discard:
    bpf_ringbuf_discard(e, 0);
    return TCX_PASS;
}