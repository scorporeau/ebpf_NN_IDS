#ifndef __FEATURES_H
#define __FEATURES_H


//features binaries IDs.
//Features currently used are stored in a __u64. 32 LSBs are for packet features, 32 MSBs are for Flow features.
//This vector is created with binary ands and theses values Thus, we can have 64 max features, 32 flow-features and 32 packet-features.
//example vector with 3 features : #define FEATURES (F_S_PORT & F_D_PORT & F_PROTOCOL)

//Theses definitions are not affected by the maximum number of features supported per decision tree (which is 64 at the 29th of june)

//features range on the 64 bit vector
#define F_RANGE_PACKET  0x00000000FFFFFFFF
#define F_RANGE_FLOW    0xFFFFFFFF00000000


//packet features
#define F_S_PORT    ((__u64)1 << 0) //feature 0
#define F_D_PORT    ((__u64)1 << 1) //feature 1
#define F_PROTOCOL  ((__u64)1 << 2) //...
#define F_PKT_SIZE  ((__u64)1 << 3)
#define F_D_IP      ((__u64)1 << 4)
#define F_S_IP      ((__u64)1 << 5)

//flow features STD NOT IMPLEMENTED (need too much computations in the ebpf)
#define F_IAT_MEAN  (((__u64)1 << 0) << 32) //feature 32
#define F_IAT_TOT   (((__u64)1 << 1) << 32) //feature 33
#define F_IAT_STD   (((__u64)1 << 2) << 32)
#define F_SIZE_MEAN (((__u64)1 << 3) << 32)
#define F_SIZE_TOT  (((__u64)1 << 4) << 32)
#define F_SIZE_STD  (((__u64)1 << 5) << 32)
#define F_PKT_NB    (((__u64)1 << 6) << 32)
#define F_IAT       (((__u64)1 << 7) << 32)

#endif