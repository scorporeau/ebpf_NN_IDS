//Decision tree handling for IDS implementation in ebpf

#ifndef __ML_DT_H
#define __ML_DT_H

#define DT_NODE_NB 128 //actual number of nodes in the implemented decision tree (will reserve array space for DT_NODE_NB nodes, etc ...). 0<DT_NODE_NB<256 to fit in the __u8 structure.
#define TIMEOUT_RINGBUF_POLL 50 //ms, timeout for ring buffer wait in case of empty buffer.
#define DEBUG true //if true, we create a ringbuffer to print logs to the user space.


//decision tree node structure for ebpf.
// child nodes indexes should be normalized in the array instead of referenced here in order to reduce stack usage (max 512 bytes in ebpf).
// for this, we have to implement (nearly) complete trees (https://codemia.io/knowledge-hub/path/efficient_array_storage_for_binary_tree) or store somewhere tree shape information & how to retrieve child and parent nodes. Which one is more efficient ? maybe we need to test it.
struct dt_node {
    //threshold for the decision (__u32 as it is the max size of features)
    __u32 threshold; 
    //index of the feature to split on.
    //Also, because we need less than 8 bites to store feature #, the two MSB can be used to flag leaves, and decision (pass left or pass right).
    //first bit : pass left, 2nd bit: pass right, 3rd bit: 0 = leaf/undefined node, 1 = defined node.
    __u8 feature;
}; //40 bits = 5 bytes. Max nodes 102 (512 bytes stack) (is there padding?)

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