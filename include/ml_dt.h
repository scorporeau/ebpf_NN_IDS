//Decision tree handling for IDS implementation in ebpf

#ifndef __ML_DT_H
#define __ML_DT_H

//#define DT_NODE_NB 64 //actual number of nodes in the implemented decision tree (will reserve array space for DT_NODE_NB nodes, etc ...).
#define TIMEOUT_RINGBUF_POLL 50 //ms, timeout for ring buffer wait in case of empty buffer.
#define DEBUG //if true, we create a ringbuffer to print logs to the user space.


//REMOVED DT NODES STRUCT
//for optimization we will use 3 bytes (24 bits) for threshold, 6 bits for feature ID and 2 bits for pass left / pass right for a total of 32 bits. (4 Bytes)
//TTTTTTTT TTTTTTTT TTTTTTTT IIIIIILR
//node.thresh : node >> 8
//node.f_id   : (node & 0x000000FC) >> 2
//node.pass_l : (node & 0x00000002) >> 1
//node_pass_r : node & 0x00000001

// note that a node filled with zeros is undefined and considered as a leaf (applying decision of previous node path (left or right drop/pass)). Since a node with 0 as a value has no sense in a DT (I think)

struct feature_vector {
    //does not have any IPs, since it can be filtered easily by some other known IDSs.
    __u16 source_port;
    __u16 dest_port;
    __u8 protocol;
    __u16 packet_size;
    __u32 time_since_last_packet; //per flow, in ms (bpf_ktime_get_ns, converted to ms). Max value = 49.7 days.
    __u16 mean_packet_size; //per flow
}; //tot size = 2+2+1+2+8+2 = 17 Bytes. max 30 vectors can be stored in the 512B stack. Usually we process them one at a time so its not a problem.


#endif /* ML_DT_H */