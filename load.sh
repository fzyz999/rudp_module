#!/bin/bash
insmod rudpsock.ko srcport=8080 dstport=8000
insmod rudpsock2.ko srcport=8000 dstport=8080
lsmod | grep rudp
