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
#include "ml_dt.h"
#include "common.h"

// Declare the license - GPL is required for most BPF helper functions
// This MUST be present or the verifier will reject the program
char LICENSE[] SEC("license") = "GPL";

// Create a LRU hash maps to count the number of packets and total bytes for each source-destination IP pair
// LRU = Least Recent Used, delete most unused entries once the map is full.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(value, struct dt_node);
    __type(key, __u32); //key is always a __u32 (docs.ebpf.io)
    __uint(max_entries, DT_NODE_NB); //can store 2*DT_NODE_NB+1 to enable hot_updates (first node will have an unreferenced feature index and be "the boolean")
} dt_nodes_array SEC(".maps");

//Flow LRU hashmap, to process per-flow features (mean_packet_size & time_since_last_packet)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    // Maximum number of entries in the map (adjust as needed)
    __uint(max_entries, 2048);
    // Key is a __u128 of combined source_ip (32), source_port(16), dest_ip (32), dest_port (16), plus 32 filler bits. (not optimal)
    __type(key, __u128);
    // Value is a struct ip_count containing the count and total bytes
    __type(value, struct flow_info);
} flow_info_map SEC(".maps");


// Create a ring buffer map that will be used only if DEBUG == true
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024*16); //16KB
} events_ring SEC(".maps");




// parse the packet located in the context, and fill flow_info_map and the feature vector with the required information.
static inline int parse_update(struct xdp_md *ctx, struct feature_vector *fv, struct iphdr *ip_debug)
{
    // retrieving packet data, size and timestamp
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 time_now = bpf_ktime_get_ns();

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

    //3bis : debug if ip_debug != NULL ( if DEBUG == true)
    if (ip_debug) {
        //copy ip info to ip_debug
        ip_debug->saddr = ip->saddr;
        ip_debug->daddr = ip->daddr;
    }

    //4 fill feature vector (with features that does not require flow info)
    fv->protocol = ip->protocol;
    fv->packet_size = (__u16)(data_end - data);
    //retrieving ports (TCP or UDP only)
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if (tcp + 1 > data_end) {
            return -4; // error, packet too short for TCP header
        }
        fv->source_port = bpf_ntohs(tcp->source);
        fv->dest_port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
        if (udp + 1 > data_end) {
            return -5; // error, packet too short for UDP header
        }
        fv->source_port = bpf_ntohs(udp->source);
        fv->dest_port = bpf_ntohs(udp->dest);
    } else {
        fv->source_port = 0;
        fv->dest_port = 0;
    }

    //5 retrieve & update flow information, then fill the rest of feature vector.
    __u128 flow_key = ((__u128)ip->saddr << 96) | ((__u128)fv->source_port << 80) | ((__u128)ip->daddr << 48) | ((__u128)fv->dest_port << 32);
    struct flow_info *fi = bpf_map_lookup_elem(&flow_info_map, &flow_key);
    if (fi) {
        // flow already created (one packet already seen)
        //process time since last packet. !! convert to ms and __u32
        __u64 tsl = (time_now - fi->last_seen) / 1000000;
        //handle time longer than max value of __u32 (49.7 days), by capping it to the max value.
        if (tsl > 0xFFFFFFFF) {
            fv->time_since_last_packet = 0xFFFFFFFF;
        } else {
            fv->time_since_last_packet = (__u32)tsl;
        }
        fi->last_seen = time_now;
        //process (new) mean packet size
        __sync_fetch_and_add(&fi->count, 1);
        __sync_fetch_and_add(&fi->tot_bytes, fv->packet_size);
        fv->mean_packet_size = (__u16)(fi->tot_bytes / fi->count);

        
    } else {
        //create the new flow entry
        struct flow_info new_fi = { time_now, fv->packet_size, 1 };
        bpf_map_update_elem(&flow_info_map, &flow_key, &new_fi, BPF_NOEXIST);
        fv->time_since_last_packet = 0xFFFFFFFF; //max value, never seen this flow before
        fv->mean_packet_size = fv->packet_size; //only one packet seen
    }
    return 0; // success
}



//XDP network listener main function
SEC("xdp")
int xdp_trace_net_event(struct xdp_md *ctx)
{
    //1: parse the packet and update feature vector.
    struct feature_vector fv = {0}; //initialize feature vector to 0 to avoid issues when encountering errors
    int ret;
    struct iphdr ipd= (struct iphdr){0}; //initialize ipd to 0 to avoid issues when encountering errors
    if (DEBUG) {
        //with debug ip info extraction
        ret = parse_update(ctx, &fv, &ipd); 
    } else {
        //without debug ip ingfo extraction
        ret = parse_update(ctx, &fv, NULL); 
    }
    
    
    

    //handle errors
    switch (ret) {
        case -2:
            //Not IP packet (this is not a bad packet, passing it.)
            goto passsilent;
            break;
        case 0:
            //success, do nothing (feature vector will be analyzed by the decision tree for drop or pass decision.)
            break;
        default:
            //any other error (too short for eth header, too short for IP header, too short for TCP/UDP header) = bad packet, drop it.
            goto drop;
    }

    //2: packet processing (decision tree).
    __u8 i = 0; //index of the root node of the tree. u8 since it prevents the verifier to think it can be enormous while testing.
    int pass = true; //default decision = pass;
    struct dt_node *node;
    __u64 feature_value;
    __u8 f_i;

    //have to use a bpf loop helper function in order to allow the ebpf program to understand taht my loop is short
    for (__u8 j = 0; j <= DT_NODE_NB; j++) {
        node = bpf_map_lookup_elem(&dt_nodes_array, &i);
        //if node undefined (tree not initialized), index too big (arrived @ end of the DT),or arrived at a leaf (2nd MSB = 0): we apply the current decision.
        //  !node                                            !node                             node->feature & 0b10000000 == 0         
        if (!node || ((node->feature & 0b01000000) == 0) || (i > DT_NODE_NB)) {
            if (pass) {
                goto pass;
            } else {
                goto drop;
            }
        }

        //else, node is defined AND current node is not a leaf, we need to process decision and update the index.
        f_i = node->feature & 0b00111111; //feature index is the 6 LSB
        switch (f_i) {
            case 0:
                feature_value = fv.source_port;
                break;
            case 1: 
                feature_value = fv.dest_port;
                break;
            case 2:
                feature_value = fv.protocol;
                break;
            case 3:
                feature_value = fv.packet_size;
                break;
            case 4:
                feature_value = fv.time_since_last_packet;
                break;
            case 5:
                feature_value = fv.mean_packet_size;
                break;
            default:
                //invalid feature index, should not happen. in this case, let's pass the packet.
                goto pass;
        }
        if (feature_value <= node->threshold) {
            //go left
            pass = node->feature & 0b10000000;
            i = 2*i + 1;
        } else {
            //go right
            pass = !(node->feature & 0b10000000);
            i = 2*i + 2;
        }
    }


drop:
    if (DEBUG) {
        //create debug info and send it to the user space via ring buffer
        struct debug_info *d = bpf_ringbuf_reserve(&events_ring, sizeof(struct debug_info), 0);
        if (d) {
            d->src_ip = ipd.saddr;
            d->dst_ip = ipd.daddr;
            d->src_port = fv.source_port;
            d->dst_port = fv.dest_port;
            d->packet_size = fv.packet_size;
            d->protocol = fv.protocol;
            d->decision = false; //drop
            bpf_ringbuf_submit(d, 0);
        }
    }
dropsilent:
    return XDP_PASS; //Not actually dropping packets, might cause issue with testing DT (drop all UDP)
pass:
    if (DEBUG) {
        //create debug info and send it to the user space via ring buffer.
        struct debug_info *d = bpf_ringbuf_reserve(&events_ring, sizeof(struct debug_info), 0);
        if (d) {
            d->src_ip = ipd.saddr;
            d->dst_ip = ipd.daddr;
            d->src_port = fv.source_port;
            d->dst_port = fv.dest_port;
            d->packet_size = fv.packet_size;
            d->protocol = fv.protocol;
            d->decision = true; //pass
            bpf_ringbuf_submit(d, 0);
        }
    }
passsilent:
    return XDP_PASS;
}