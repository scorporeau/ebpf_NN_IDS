#ifndef __FEATURES_H
#define __FEATURES_H


//features binaries IDs.
//Features currently used are stored in a __u64. 32 LSBs are for packet features, 32 MSBs are for Flow features.
//This vector is created with binary ands and theses values Thus, we can have 64 max features, 32 flow-features and 32 packet-features.
//example vector with 3 features : #define FEATURES (F_S_PORT & F_D_PORT & F_PROTOCOL)

//features range on the 64 bit vector
#define F_RANGE_PACKET  0x00000000FFFFFFFF
#define F_RANGE_FLOW    0xFFFFFFFF00000000


//packet features
#define F_S_PORT    (1 << 0) //feature 0
#define F_D_PORT    (1 << 1) //feature 1
#define F_PROTOCOL  (1 << 2) //...
#define F_PKT_SIZE  (1 << 3)
#define F_D_IP      (1 << 4)
#define F_S_IP      (1 << 5)

//flow features STD NOT IMPLEMENTED (need too much computations in the ebpf)
#define F_IAT_MEAN  ((1 << 0) << 32) //feature 32
#define F_IAT_TOT   ((1 << 1) << 32) //feature 33
#define F_IAT_STD   ((1 << 2) << 32)
#define F_SIZE_MEAN ((1 << 3) << 32)
#define F_SIZE_TOT  ((1 << 4) << 32)
#define F_SIZE_STD  ((1 << 5) << 32)
#define F_PKT_NB    ((1 << 6) << 32)
#define F_IAT       ((1 << 7) << 32)

#endif