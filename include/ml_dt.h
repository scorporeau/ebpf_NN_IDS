//Decision tree handling for IDS implementation in ebpf

#ifndef ML_DT_H
#define ML_DT_H

#include "vmlinux.h"

#define NODE_NB 32 //actual number of nodes in the implemented decision tree (will reserve array space for NODE_NB nodes, etc ...)

//decision tree node structure for ebpf.
// child nodes indexes should be normalized in the array instead of referenced here in order to reduce stack usage (max 512 bytes in ebpf).
// for this, we have to implement (nearly) complete trees (https://codemia.io/knowledge-hub/path/efficient_array_storage_for_binary_tree) or store somewhere tree shape information & how to retrieve child and parent nodes. Which one is more efficient ? maybe we need to test it.
struct dt_node {

    __u32 threshold; //threshold for the decision (__u32 as it is the max size of features)
    __u8 feature; //feature to split on (index)
}; //40 bits = 5 bytes. Max nodes 102 (512 bytes stack)

struct feature_vector {
    //does not have any IPs, since it can be filtered easily by some other known IDSs.
    __u16 source_port;
    __u16 dest_port;
    __u8 protocol;
    __u16 packet_size;
    __u32 time_since_last_packet; //for the same flow
    __u16 mean_packet_size; //for the same flow
}; //tot size = 2+2+1+2+4+2 = 13 Bytes. max 39 vectors can be stored in the 512B stack.




#endif /* ML_DT_H */