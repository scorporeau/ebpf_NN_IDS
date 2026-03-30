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

// Create a LRU hash maps to count the number of packets and total bytes for each source-destination IP pair
// LRU = Least Recent Used, delete most unused entries once the map is full.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    // Maximum number of entries in the map (adjust as needed)
    __uint(max_entries, 4096);
    // Key is a __u64 of combined source_ip, dest_ip
    __type(key, __u64);
    // Value is a struct ip_count containing the count and total bytes
    __type(value, struct ip_count);
} ip_count_map SEC(".maps");


//if doing tailing (docs.ebpf.io), we have to create a structure progs taht is storing pointers to the different ebpf programs.
// struct {
//     __uint(type, BPF_MAP_TYPE_PROG_ARRAY); 
//     __uint(max_entries, 256);
//     __type(key, u32);
//     __type(value, u32);
// } progs SEC(".maps");


// parse the packet located in the context, and fill the map with the right structure.
static inline int parse_update(struct xdp_md *ctx, __u64 *key, __u32 *pkt_size)
{
    // retrieving packet data & size
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;



    //1 check the eth header
    struct ethhdr *eth = data;
    if (eth + 1 > data_end) {
        return -1; // error, packet too short
    }

    //2 check if its IP protocol
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return -2; // not an IP packet
    }

    //3 get ip header
    struct iphdr *ip = data + sizeof(struct ethhdr);
    if (ip + 1 > data_end) {
        return -3; // error, packet too short for IP header
    }

    //4 converting ipsource, ipdest to the key of the map (combining them into a single 64 bit int)
    *key = ((__u64)ip->saddr << 32) | ip->daddr;
    *pkt_size = (__u32)(data_end - data);

    //don't need to parse protocol, since we are only counting IPs and size.

    return 0; // success
}

//XDP network listener main function
SEC("xdp")
int xdp_trace_net_event(struct xdp_md *ctx)
{
    __u64 key;
    __u32 pkt_size;

    //parse the packet and get the key and packet size
    int ret = parse_update(ctx, &key, &pkt_size);
    //handle errors
    if (ret < 0) {
        //create a special IP pair for error counting. Let's use 0.5.18.18 + 15.18.X.X (0, then ERROR letters placement in the alphabet, then error code)
        //All the range of destination IPs addresses produced by this code are HP datacenters in the silicon valley. Note that there is no real connection to these IPs.
        int dest_ip_error;
        switch (ret) {
            case -1:
                dest_ip_error = 0x0100120f;
                break; //too short for eth header
            case -2:
                dest_ip_error = 0x0200120f; //not IP packet
                break;
            case -3:
                dest_ip_error = 0x0300120f; //too short for IP header
                break;
            default:
                dest_ip_error = 0xFF00120f; //unknown error
        }
        
        key = ((__u64)bpf_htonl(0x00051212) << 32) | (__u64)dest_ip_error; //ERRO.ERRO key
        pkt_size = 0;

    } else {
        //no error, do nothing because key and pkt_size are already filled by parse_update
    }
    // heavily inspired by
    // https://docs.kernel.org/bpf/map_hash.html#bpf-map-type-lru-hash-and-variants
    struct ip_count *ipc = bpf_map_lookup_elem(&ip_count_map, &key);
    if (ipc) {
        __sync_fetch_and_add(&ipc->count, 1);
        __sync_fetch_and_add(&ipc->tot_bytes, pkt_size);
    } else {
        struct ip_count new_ipc = { 1, pkt_size };
        bpf_map_update_elem(&ip_count_map, &key, &new_ipc, BPF_NOEXIST);
    }


    return XDP_PASS;

}