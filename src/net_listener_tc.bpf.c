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


//there is no parsing function, since the parsing is done by the kernel.

SEC("tc/ingress")
int tc_trace_net_event(struct __sk_buff *skb)
{
    struct netevent *e;
    struct iphdr ip_data;
    struct tcphdr tcp_data;
    struct udphdr udp_data;


    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;


    //reserve space in the ring buffer
    e = bpf_ringbuf_reserve(&events_ring, sizeof(*e), 0);
    if (!e) {
        // ERROR: ringbuf null, pass packet
        return TCX_PASS;
    }

    //initialize event structure with packet information contained in the __sk_buff structure
    //and the pid directly from the kernel
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->packet_size = skb->len;

    //parsing packet for IPs and ports informations (forced in TC)
    if (skb->protocol != bpf_htons(ETH_P_IP)) {
        // ERROR: not an IP packet, discard event
        //e->protocol = 202;
        //goto submit;// Not an IP packet
        goto discard;
    }

    //IPs retrieving, using bpf_skb_load_bytes because we cannot directly access the packet data in TC (unlike in XDP) (should not be a problem, IDK)
    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &ip_data, sizeof(ip_data)) < 0) {
        e->protocol = 203;// ERROR: Packet too short for IP header
        goto submit;
    }
    e->src_ip = ip_data.saddr;
    e->dst_ip = ip_data.daddr;
    e->protocol = ip_data.protocol;


    __u32 transport_offset = sizeof(struct ethhdr) + ip_data.ihl * 4;

    if (ip_data.protocol == IPPROTO_TCP) {
        //TCP handling
        if (bpf_skb_load_bytes(skb, transport_offset, &tcp_data, sizeof(tcp_data)) < 0) {
            e->protocol = 204; // ERROR: Packet too short for TCP header
            goto submit;
        }
        //retrieving ports
        e->src_port = bpf_ntohs(tcp_data.source);
        e->dst_port = bpf_ntohs(tcp_data.dest);


    } else if (ip_data.protocol == IPPROTO_UDP) {
        //UDP handling
        if (bpf_skb_load_bytes(skb, transport_offset, &udp_data, sizeof(udp_data)) < 0) {
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


    

submit:
    bpf_ringbuf_submit(e, 0);
    return TCX_PASS;
discard:
    bpf_ringbuf_discard(e, 0);
    return TCX_PASS;
}