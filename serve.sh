#!/bin/bash

./flush.sh

sudo ip addr add 192.168.191.102/24 broadcast + dev enp5s0
sudo ip link set enp5s0 up
sudo systemctl start lighttpd
