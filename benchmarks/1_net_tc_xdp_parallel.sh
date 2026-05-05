#! /bin/bash
#This script runs both tc and xdp version of net_listener in parallel and compares their outputs line by line.

#create child processes for tc and xdp (not in csv for human reading and without timestamps for diff)
../build/net_listener_tc 0 0 0 > tc_out.txt &
PID_TC=$!
../build/net_listener_xdp 0 0 0 > xdp_out.txt &
PID_XDP=$!

#wait for given time (or 10s if undef)
if [ -z "$1" ]; then
    TIME=10
else
    TIME=$1
fi
echo "Running for $TIME seconds..."
sleep $TIME
echo "Killing processes..."

#kill both processes
kill $PID_TC
kill $PID_XDP

#wait for processes to finish
wait $PID_TC
wait $PID_XDP

echo "------ diff output : ------"
#print output of diff between tc_out.txt and xdp_out.txt
diff tc_out.txt xdp_out.txt

#deleting output files (only if no 2nd argument provided)
if [ -z "$2" ]; then
    rm tc_out.txt xdp_out.txt
fi

#exiting
echo "------- end of diff -------"
exit 0