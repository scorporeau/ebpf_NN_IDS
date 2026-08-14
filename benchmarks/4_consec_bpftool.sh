#!/bin/bash

# This script attach & load the provided bpf objects in all modes (SKB(generic) then DRV(driver) then HW(offload))
# the attach & loading is done via bpftool binary
HELP="loading & attaching provided .o xdp objects while lsitening for iperf3 on the provided interface. Outputs metrics in a outputs folder (will be created automatically)
args:
network interface
ip addr
xdp .o objects
Note: offload is auto-detected via 'ethtool -i' (netronome firmware reports 'bpf')"


# retrieve net interface name from 1st arg
if [ -z "$1" ]; then
    echo "$HELP"
    exit 1
else
    IFACE=$1
fi

# retrieve IP address from 2nd arg (need to be bounded to the interface already provided)
if [ -z "$2" ]; then
    echo "$HELP"
    exit 1
else
    IP_ADDR=$2
fi

# Auto-detect offload boolean via ethtool -i driver/firmware info
# If the ethtool output contains the string "bpf" (case-insensitive)
# we consider the NIC in bpf/offload mode (OFFL=1), otherwise 0.
if ethtool -i "$IFACE" 2>/dev/null | grep -qi 'bpf'; then
    OFFL=1
else
    OFFL=0
fi

#retrieving ebpf objects from 3rd+ args
# objects start at argument 3 now (iface, ip, [objs...])
if [ -z "$3" ]; then
    OBJS=("no_ebpf")
else
    shift 2
    OBJS=("$@" "no_ebpf")
fi
#warn message because m yscript is not perfect
echo "please run this script from the build directory"


#deleting old output files
echo "Sorry, deleting old outputs if they exist... (press ctrl C in the next 3s to cancel)"
sleep 3
rm -r output

#creating folders & file
mkdir output
touch output/config.txt


#output network configuration in config.txt file for test reliability
echo "----------ip a" >> output/config.txt
ip a >> output/config.txt
echo "----------ethtool -k" >> output/config.txt
ethtool -k $IFACE >> output/config.txt
echo "----------ethtool -i" >> output/config.txt
ethtool -i $IFACE >> output/config.txt
echo "----------lshw -c network" >> output/config.txt
lshw -c network >> output/config.txt

# add xdpoffload to modes only if OFFL is set to 1
if [ "$OFFL" -eq 1 ] ; then
    MODE_LIST="xdpgeneric xdpdrv xdpoffload"
else
    MODE_LIST="xdpgeneric xdpdrv"
fi
echo "-----modes list : $MODE_LIST"
echo "-----progs list : ${OBJS[@]}"


for BPF_OBJ in "${OBJS[@]}"; do
    if [ "$BPF_OBJ" == "no_ebpf" ]; then
        echo "Benchmark without any eBPF script attached ..."
        touch "./output/iperf_$BPF_OBJ.txt"
        echo "waiting for iperf3 client to connect ..."
        iperf3 -s -V --one-off --timestamps --bind $IP_ADDR >> "./output/iperf_$BPF_OBJ.txt"
        echo "iperf3 finished running !"
    else
        # loop for each program & mode
        for MODE in $MODE_LIST; do
            echo "loading & attaching object $BPF_OBJ in $MODE"

            #LOAD
            if [ "$MODE" == "xdpoffload" ]; then
                sudo bpftool prog load $BPF_OBJ /sys/fs/bpf/bpf_bench4 type xdp offload_dev $IFACE
            else
                sudo bpftool prog load $BPF_OBJ /sys/fs/bpf/bpf_bench4 type xdp
            fi

            #LOAD ML PARAMETERS INTO MAP (if needed)
            if [[ "$BPF_OBJ" == *dt* ]]; then
                echo "Detected dt object '$BPF_OBJ'."
                sudo bpftool map
                read -p "Enter dt_nodes map_id: " MAP_ID
                if [ -z "$MAP_ID" ]; then
                    echo "map_id is required for dt objects."
                    exit 1
                fi
                bash ../ML/DT/update_params.sh "$MAP_ID"
                echo "----- updated the map :"
                sudo bpftool map dump id $MAP_ID
            fi

            #ATTACH
            sudo bpftool net attach $MODE pinned /sys/fs/bpf/bpf_bench4 dev $IFACE

            #IPERF
            #the eBPF program is now running, let's run the iperf AND flamegraph. (will not be interesting for xdpoffload ?) TODO Flamegraph handling
            #run the server for only one connection (since each one will be outputted to a different file)
            touch "./output/iperf_$BPF_OBJ $MODE.txt"
            echo "waiting for iperf3 client to connect ..."
            iperf3 -s -V --one-off --timestamps --bind $IP_ADDR >> "./output/iperf_$BPF_OBJ $MODE.txt"
            echo "iperf3 finished running ! Detaching ebpf script"

            #DETACH
            sudo bpftool net detach $MODE dev $IFACE
            sudo rm -f /sys/fs/bpf/bpf_bench4
        done
    fi
done