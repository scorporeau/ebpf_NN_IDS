# Introduction
This project attemps to benchmark some eBPF's XDP capabilities, especially XDP offload and driver modes.
More specefically, it benchmarks ML-based IDS (Intrusion Detection System) using eBPF in order to run it on smartNICs.

The motivation comes from the statement of Bachl et al., 2022 [2] that an ML based IDS can be implemented on eBPF (with some challenges such as the non turing completeness of eBPF) and are (20%) faster than the same IDS implemented on the user space. However, we still take into account TODO DEMISTIFICATION that are more dubitative about the ability of eBPF to be significantly faster thant classical user-space code.

## Quick technology presentation

![life of an eBPF program through the user and kernel space](figs/eBPF%20life.png "life of an eBPF program through the user and kernel space")

eBPF is a kernel feature that is able to run user-provided code into the kernel, at different hooks. It is particularely useful in networking.












# How to run this project

## install dependencies
Under Ubuntu / debian, you'll need to install the following :
`apt install make gcc clang`

Then, you have to generate the vmlinux.h file that contains all information about your kernel.
`bpftool btf dump file /sys/kernel/btf/vmlinux format c > include/vmlinux.h`


You also have to install libbpf, but we will have to recompile locally libbpf from source, since the version available with apt might be outdated (v0.5 in our kernel sources).
In order to do that, you simply have to download the zip file from the [libbpf github](https://github.com/libbpf/libbpf) and follow the instructions on the readme.

## build



Once everything is set up, simply run the `make` command in the root directory, it will compile everything into the newly created `./build` directory.
| make option | behavior |
| ----------- | -------- |
| silent | disable ringbuffer structures that passes information to user space |
| noktime | silent + no use of `bpf_ktime_get_ns` syscall (unsupported by some hardware) |
| NET_INTERFACE=eth0 | define the used network interface (libbpf user-space only) |

The `build` directory should look something like this :

```text
build
├── dt_xdp
├── dt_xdp.bpf.o
├── dt_xdp.skel.h
├── dummy_xdp.bpf.o
├── dummy_xdp_drv
├── dummy_xdp_hw
├── dummy_xdp_skb
├── dummy_xdp.skel.h
├── net_listener
├── net_listener.bpf.o
├── net_listener.skel.h
├── net_listener_tc
├── net_listener_tc.bpf.o
├── net_listener_tc.skel.h
├── net_listener_xdp.bpf.o
├── net_listener_xdp_drv
├── net_listener_xdp_hw
├── net_listener_xdp_skb
├── net_listener_xdp.skel.h
└── vmlinux.h
```

If anything is missing, all the clues needed for debugging should be outputted by `make`. Usually, you will also see some warnings coming from our C code.

The .o objects files are used directly with `bpftool`, and all the others files are used with `libbpf`.

## Run with bpftool
bpftool is a tool for inspection and simple manipulation of eBPF programs and maps. (bpftool man page)

`bpftool` needs more user inputs to run XDP programs, but I think it is a good way to understand the basics about eBPF programs. Anyway, I did not achieve to load XPD offloaded with the current `netronome` and `libbpf` software versions (even though `bpftool` uses `libbpf` calls under the hood).

bpftool uses directly the eBPF machinecode `.o` files to attach and load it into the kernel. The table belows resume how to use pinning in bpftool to load and attach programs.

| step | `bpftool` corresponding(s) command(s) |
| ---- | ------------------------------- |
| load & verify eBPF program | `bpftool prog load <bpf>.o /sys/fs/bpf/<whatever> type xdp` |
| load & verify eBPF program (hw offload) | `bpftool prog load <bpf>.o /sys/fs/bpf/<whatever> type xdp offload_dev <net_interface>` |
| attach eBPF program | `bpftool net attach <mode> pinned /sys/fs/bpf/<whatever> dev <net_interface>` |
| detach | `bpftool net detach <mode> dev <net_interface>` |
| unload | `rm /sys/fs/bpf/<whatever>` |


## Run with libbpf (deprecated)
`make` compile and produce all the code needed for libbpf usage.in the `build` directory, you can find, among the files already described for the bpftool usage, the compiled user-space program that usually attach and load the corresponding bpf kernel-space code, while handling the reading of debug maps (if )




# ML parameters
The ML-based eBPF scripts need to use some parameters. Since we did not wanted to hardcode parameters in the script itself, they are provided in the `ML` folder.

## DT
The current used-parameters of the DT are located under `ML/DT`.

`dt_features.h` holds information about the current features used for the DT. They cannot be changed until a new compilation of the project. It is used by both bpftool and libbpf, since it is mandatory for creating the data structures.

`dt_params.h` contains the parameters of the DT. It is only used while running "in libbpf mode" to load parameters at the beggining.

`update_params.sh` allow to hot-update the parameters of te DT while the eBPF script is running. Since the "bpftool" approach does not load automatically the parameters, you'll have to initialize the parameters with it too.

If you want to use DT parameters from our example folder,
just overwrite the current `dt_features.h dt_params.h update_params.sh` files under `ML/DT` with the corresponding files present in `ML/DT/examples`




# eBPF code

## kernel-space eBPF code

## user-space

### bpftool
`bpftool` usage is resumed nicely in their manual page. It misses some features such as polling ringbuffers or advanced maps modification.
There are also more ways to attach or load programs than the ones presented in the table before.

### libbpf
`libbpf` allows to code user-space code in C. This code can automatically load, attach and detach the eBPF kernel-space code.
Here is a quick explanation of the basics of `libbpf` user-space code, you can also look at our `.usr.c` code for more advanced code.

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

# Future work

In the future, there is plenty of work that still has to be done.

benchmark properly a NN

RF well implemented

