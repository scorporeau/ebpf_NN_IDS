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
    struct iphdr *ip_data;
    struct tcphdr *tcp_data;
    struct udphdr *udp_data;

    //reserve space in the ring buffer
    e = bpf_ringbuf_reserve(&events_ring, sizeof(*e), 0);
    if (!e) {
        //ringbuf null, pass packet
        return TCX_PASS;   
    }


    //initialize event structure with packet information contained in the __sk_buff structure
    //and the pid directly from the kernel
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->packet_size = skb->len;


    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    //parsing packet for IPs and ports informations (forced in TC)
    if (skb->protocol == bpf_htons(ETH_P_IP)) {
        //IPs retrieving
        ip_data = data + sizeof(struct ethhdr);
        if (ip_data + 1 > data_end) {
            e->protocol = 203; // Packet too short for IP header
            goto submit;
        }
        e->src_ip = ip_data->saddr;
        e->dst_ip = ip_data->daddr; 

        if (ip_data->protocol == IPPROTO_TCP) {
            //TCP handling
            e->protocol = 6;
            struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if (tcp + 1 > data_end) {
                e->protocol = 204; // Packet too short for TCP header
                goto submit;
            }
            //retrieving ports
            e->src_port = bpf_ntohs(tcp->source);
            e->dst_port = bpf_ntohs(tcp->dest);


        } else if (ip_data->protocol == IPPROTO_UDP) {
            //UDP handling
            e->protocol = 17;
            struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if (udp + 1 > data_end) {
                e->protocol = 205; // Packet too short for UDP header
                goto submit;
            }
            e->src_port = bpf_ntohs(udp->source);
            e->dst_port = bpf_ntohs(udp->dest);


        } else {
            //other protocol
            e->protocol = ip_data->protocol;
            //no ports
            e-> src_port = 0;
            e-> dst_port = 0;
        }
    } else {
        // not an IP packet, not sending anything to the user space.
        bpf_ringbuf_discard(e, 0);
        return TCX_PASS;
    }

    

submit:
    bpf_ringbuf_submit(e, 0);
    return TCX_PASS;
}