# Introduction

This is an attempt to create an IDS (Intrusion Detection System) based on eBPF in order to run it on smartNICs.

Zhang et al. (2024) [1] have done a similar work, this is an attemp to go more in depth on the eBPF script to use it in production, their code was a proof-of concept.

The motivation comes from the statement of Bachl et al., 2022 [2] that an ML based IDS can be implemented on eBPF (with some challenges such as the non turing completeness of eBPF) and are (20%) faster than the same IDS implemented on the user space.

# Run the project


First, you have to install the required dependencies (might depends of your OS, I used ubuntu 22.04)

`apt install libbpf-dev make gcc`

Then, you can rune the `make` command that compile all C code (eBPF kernel space code, and C user space code).
The code is outputed in the `/build` directory.

Then, to run any of your script, you can execute the binary file. The binary of file `first_main.usr.c` has to be run with `sudo ./build/first_main` (the code need admin privileges to execute the eBPF program).

# Coding new programs


There is some rules on this project. First, we have to be conscious of how does eBPF works  [3,4] , and clearly separate kernel space / user space scripts.

All the C code has to be located under /src, and named .bpf.c and .usr.c for respectively the kernel space eBPF code and user space code.

Kernel code is the eBPF code, so it has to ise eBPF coding rules (no infinite loops : there is a max number of instructions, etc). The user space and kernel space code can communicate via the eBPF maps.

## User space code

The code is not running on the kernel space unless called with a user space code :

<blockquote>
#include "first.skel.h"

[...]

skel = first_bpf__open();

[...]

err = first_bpf__load(skel);

[...]

err = first_bpf__attach(skel);
</blockquote>

extract of [first_main.usr.c](/src/first_main.usr.c)

`first` here is the name of the program, but has to be replaces by the name of your .bpf.c program.

Note that this code is written according to the first.bpf.c script, but you have to rename the functions and import according to your file name.
 
## Kernel space code

The kernel space code must be written according to the libbpf documentation found online [3,4].


# Project steps

## 1) Comparing XDP and TC

In this project, we will be parsing network packets to do IDS. Since ~99% of the packets won't be dropped, they will be parsed 2 times in case of using XDP.

The first benchmark is a performance comparison between XDP and TC for parsing network packets, considering 100% transmission. Such as [2], we will run experiments of the # of packets passed through our script for a fixed time. They compared between user-space and TC, I'll compare perf between XDP and TC.

For this benchmark, we will use the scripts `net_listener` and `net_listener_xdp` that simply forward the packets information to the user space, and prints them.


# References
[1] Real-Time Intrusion Detection and Prevention  with Neural Network in Kernel using eBPF *Junyu Zhang, Pengfei Chen, Zilong He, Hongyang Chen, and Xiaoyun Li*, 2024 https://ieeexplore.ieee.org/document/10646951/

[2] A flow-based IDS using Machine Learning in eBPF http://arxiv.org/abs/2102.09980

[3] libbpf documentation https://libbpf.readthedocs.io/en/latest/

[4] https://docs.kernel.org/bpf/libbpf/index.html

[5] oneuptime eBPF coding tutorial with libbpf https://oneuptime.com/blog/post/2026-01-07-ebpf-libbpf-portable-development/view

[6] linux kernel events https://www.kernel.org/doc/html/v5.4/trace/events.html