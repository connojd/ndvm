#!/bin/bash

sudo ip link set enp2s0 down
sudo ip addr flush enp2s0

sudo ip link set enp5s0 down
sudo ip addr flush enp5s0

sudo systemctl stop lighttpd
sudo systemctl stop NetworkManager
