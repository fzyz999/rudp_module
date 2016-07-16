#!/bin/bash
for i in `seq 1 10`
do
	echo $i > /proc/net/rudp_server
done
