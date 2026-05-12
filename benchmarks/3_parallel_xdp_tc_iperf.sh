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


echo "Attaching tc and xdp scripts to $IFACE..."
../build/net_listener_tc 1 0 1 >> "./output/ebpf/net_listener_tc$SUFFIX_NAME.csv" & #not using ts as before since the PID obtained is the one from ts and not net_listener script.
PID_TC=$!
../build/net_listener_xdp 1 0 1 >> "./output/ebpf/net_listener_xdp$SUFFIX_NAME.csv" &
PID_XDP=$!

echo "Running iperf3, waiting for clien to connect..."
touch "./output/iperf/iperf$SUFFIX_NAME.txt"
iperf3 -s -V --one-off --bind $IP_ADDR >> "./output/iperf/iperf$SUFFIX_NAME.txt"

echo "output of diff command for output files"
diff "./output/ebpf/net_listener_tc$SUFFIX_NAME.csv" "./output/ebpf/net_listener_xdp$SUFFIX_NAME.csv"

echo "Client finished, killing processes $PID_TC and $PID_XDP..."
kill $PID_TC
kill $PID_XDP
wait $PID_TC
wait $PID_XDP

exit 0