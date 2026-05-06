#!/bin/bash


#This script aims to run on the server-side.
#The goal is to consecutively run iperf3 benchmarks with net_listener, net_listener_tc and net_listener_xdp scripts attached the the same interface.

#retrieve net interface name from 1st arg
if [ -z "$1" ]; then
    echo "Please provide the network interface name as the first argument."
    exit 1
else
    IFACE=$1
fi

#retrieve IP address from 2nd arg (need to be bounded to the interface already provided)
if [ -z "$2" ]; then
    echo "Please provide the IP address binded to the interface $IFACE."
    exit 1
else
    IP_ADDR=$2
fi

#retrieving suffix_name for output files (no_gro for example)
if [ -z "$3" ]; then
    SUFFIX_NAME=""
else
    SUFFIX_NAME="_$3"
fi

#retrieving ebpf script names from 3rd+ args
if [ -z "$4" ]; then
    SCRIPTS=("no_ebpf")
else
    shift 3
    SCRIPTS=("$@" "no_ebpf")
fi

#deleting old output files
echo "Sorry, deleting old outputs if they exist..."
rm -r output

#creating folders & file
mkdir output
mkdir output/iperf
mkdir output/ebpf
touch output/config.txt


#output network configuration in config.txt file for test reliability
ip a >> output/config.txt
ethtool -k $IFACE >> output/config.txt
lshw -c network >> output/config.txt



#loop for each ebpf script provided + no_ebpf (which is not a script, just nothing attached)
for BPF_SCRIPT in "${SCRIPTS[@]}"; do
    echo "Running iperf3 with $BPF_SCRIPT attached..."

    #attach & run ebpf script (if != no_ebpf)
    if [ "$BPF_SCRIPT" != "no_ebpf" ]; then
        touch "./output/ebpf/$BPF_SCRIPT$SUFFIX_NAME.csv"
        ../build/$BPF_SCRIPT 1 0 1 | ts >> "./output/ebpf/$BPF_SCRIPT$SUFFIX_NAME.csv" &
        PID_BPF=$!
    fi

    #run the server for only one connection (since each one will be outputted to a different file)
    touch "./output/iperf/$BPF_SCRIPT$SUFFIX_NAME.txt"
    iperf3 -s -V --one-off --bind $IP_ADDR | ts >> "./output/iperf/$BPF_SCRIPT$SUFFIX_NAME.txt" #&
    #PID_IPERF=$!

    #wait for iperf3 to finish
    #echo "... Waiting for iperf3 (listening on $IP_ADDR) to finish..."
    #wait $PID_IPERF
    echo "iperf3 finished for $BPF_SCRIPT."

    #kill ebpf script if it was launched
    if [ "$BPF_SCRIPT" != "no_ebpf" ]; then
        echo "Killing $BPF_SCRIPT with pid $PID_BPF..."
        kill $PID_BPF
        wait $PID_BPF
    fi
done


exit 0