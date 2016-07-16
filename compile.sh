#!/bin/bash
sed 's/rudp/rudp2/g' rudpsock.c > rudpsock2.c
make clean && make
