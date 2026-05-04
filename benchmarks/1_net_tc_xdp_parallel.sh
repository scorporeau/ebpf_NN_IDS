#! /bin/bash
#This script runs both tc and xdp version of net_listener in parallel and compares their outputs line by line.

#create child processes for tc and xdp
../build/net_listener_tc 0 > tc_out.txt &
PID_TC=$!
../build/net_listener_xdp 0 > xdp_out.txt &
PID_XDP=$!

#wait for given time (or 10s if undef)
if [ -z "$1" ]; then
    TIME=10
else
    TIME=$1
fi
sleep $TIME


#kill both processes
kill $PID_TC
kill $PID_XDP

#wait for processes to finish
wait $PID_TC
wait $PID_XDP

#for now, exiting
exit 0

