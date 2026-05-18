#!/bin/bash

#This script simply run indefinitely iperf3 clients with any given parameters. it aims to be run on the client machine, preventing user for re-running iperf3 every 10 seconds.

while true; do
    iperf3 $@
    sleep 5
done