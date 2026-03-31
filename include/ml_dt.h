//Decision tree handling for IDS implementation in ebpf

#ifndef ML_DT_H
#define ML_DT_H

#include "vmlinux.h"

#define NODE_NB 64 //actual number of nodes in the implemented decision tree (will reserve array space for NODE_NB nodes, etc ...)

//decision tree node structure for ebpf.
// child nodes indexes should be normalized in the array instead of referenced here in order to reduce stack usage (max 512 bytes in ebpf).
// for this, we have to implement (nearly) complete trees (https://codemia.io/knowledge-hub/path/efficient_array_storage_for_binary_tree) or store somewhere tree shape information & how to retrieve child and parent nodes. Which one is more efficient ? maybe we need to test it.
struct dt_node {
    //threshold for the decision (__u32 as it is the max size of features)
    __u32 threshold; 
    //index of the feature to split on.
    //Also, because we need less than 8 bites to store feature #, the two MSB can be used to flag leaves, and decision (pass left or pass right).
    //first bit : 1 = pass left, 0 = pass right. second bit : 0 = leaf/undefined node, 1 = defined node.
    __u8 feature;
}; //40 bits = 5 bytes. Max nodes 102 (512 bytes stack) (is there padding?)

#define FEATURE_NB 6 //current number of features
struct feature_vector {
    //does not have any IPs, since it can be filtered easily by some other known IDSs.
    __u16 source_port;
    __u16 dest_port;
    __u8 protocol;
    __u16 packet_size;
    __u32 time_since_last_packet; //for the same flow, in ms (bpf_ktime_get_ns, converted to ms). Max value = 49.7 days.
    __u16 mean_packet_size; //for the same flow
}; //tot size = 2+2+1+2+8+2 = 17 Bytes. max 30 vectors can be stored in the 512B stack. Usually we process them one at a time so its not a problem.




#endif /* ML_DT_H */