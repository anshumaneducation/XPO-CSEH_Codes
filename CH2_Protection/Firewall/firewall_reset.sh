#!/bin/bash
# Script to reset all iptables rules

echo "Resetting all iptables rules to default..."

# Flush all rules
sudo iptables -F

# Reset default policies
sudo iptables -P INPUT ACCEPT
sudo iptables -P FORWARD ACCEPT
sudo iptables -P OUTPUT ACCEPT

echo "All rules have been reset."
