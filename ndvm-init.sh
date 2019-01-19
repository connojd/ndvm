#!/bin/dash

ip link set eth0 up
sleep 3
dhcpcd --waitip 4

while true
do
    sleep 1
done
