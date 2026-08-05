#!/bin/bash

# This script attach & load the provided bpf objects in all modes (SKB(generic) then DRV(driver) then HW(offload))
# the attach & loading is done via bpftool binary

# retrieve net interface name from 1st arg
if [ -z "$1" ]; then
    echo "Please provide the network interface name as the first argument."
    exit 1
else
    IFACE=$1
fi

# retrieve IP address from 2nd arg (need to be bounded to the interface already provided)
if [ -z "$2" ]; then
    echo "Please provide the IP address binded to the interface $IFACE."
    exit 1
else
    IP_ADDR=$2
fi

#retrieving ebpf objects from 3rd+ args
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
echo "------ip a" >> output/config.txt
ip a >> output/config.txt
echo "------ethtool -k" >> output/config.txt
ethtool -k $IFACE >> output/config.txt
echo "------ethtool -i" >> output/config.txt
ethtool -i $IFACE >> output/config.txt
echo "------lshw -c network" >> output/config.txt
lshw -c network >> output/config.txt


for BPF_OBJ in $OBJS; do
    if [ "$BPF_OBJ" == "no_ebpf" ]; then
        echo "Benchmark without any eBPF script attached ..."
        touch "./output/iperf_$BPF_OBJ.txt"
        echo "waiting for iperf3 client to connect ..."
        iperf3 -s -V --one-off --bind $IP_ADDR -i 10 >> "./output/iperf_$BPF_OBJ.txt"
        echo "iperf3 finished running !"
    else
        for MODE in xdpgeneric xdpdrv xdpoffload; do
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
            iperf3 -s -V --one-off --bind $IP_ADDR -i 10 >> "./output/iperf_$BPF_OBJ $MODE.txt"
            echo "iperf3 finished running ! Detaching ebpf script"

            #DETACH
            sudo bpftool net detach $MODE dev $IFACE
            sudo rm -f /sys/fs/bpf/bpf_bench4
        done
    fi
done