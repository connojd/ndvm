#!/bin/bash

ip link set eth0 up
sleep 1
dhcpcd --waitip
/usr/bin/ndvm-client
