#ifndef __FEATURES_H
#define __FEATURES_H


//features binaries IDs.
//Features currently used are stored in a __u128. 64 LSBs are for packet features, 64 MSBs are for Flow features.
//This vector is created with binary ands and theses values Thus, we can have 128 max features, 64 flow-features and 64 packet-features.
//example vector with 3 features : __u64 fv = F_S_PORT & F_D_PORT & F_PROTOCOL;

//features range
#define F_RANGE_PACKET  0xFFFFFFFF
#define F_RANGE_FLOW    (0xFFFFFFFF << 64)


//packet features
#define F_S_PORT    (1 << 0) //feature 0
#define F_D_PORT    (1 << 1) //feature 1
#define F_PROTOCOL  (1 << 2) //...
#define F_PKT_SIZE  (1 << 3)
#define F_D_IP      (1 << 4)
#define F_S_IP      (1 << 5)

//flow features STD NOT IMPLEMENTED (need too much computations in the ebpf)
#define F_IAT_MEAN  ((1 << 0) << 64) //feature 64
#define F_IAT_TOT   ((1 << 1) << 64) //feature 65
#define F_IAT_STD   ((1 << 2) << 64)
#define F_SIZE_MEAN ((1 << 3) << 64)
#define F_SIZE_TOT  ((1 << 4) << 64)
#define F_SIZE_STD  ((1 << 5) << 64)
#define F_PKT_NB    ((1 << 6) << 64)
#define F_IAT       ((1 << 7) << 64)

#endif