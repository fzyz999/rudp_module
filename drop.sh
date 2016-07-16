#!/bin/bash
tc qdisc del dev lo root
tc qdisc add dev lo root netem loss 10%
