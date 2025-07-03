# Summary of the Script's Actions:

#     Blocking Incoming Traffic from a Specific IP:
#         The script blocks any incoming traffic from the IP 192.168.1.100. You can change this IP to any address you want to block.

#     Allowing Incoming Traffic from a Trusted IP:
#         The script allows incoming traffic from the IP 192.168.1.50. You can change this IP to any address you want to trust.

# Use Cases:

#     Blocking Malicious IPs: If you know a certain IP address is sending unwanted or malicious traffic to your system, you can block it to prevent any further access.
#     Allowing Trusted IPs: If you have a specific server or trusted device (e.g., a monitoring system or internal network), you can ensure it has access to your system while blocking others.



#!/bin/bash
# Script to block or allow traffic based on IP addresses
# Usage: ./firewall_ip_filter.sh blocked_ip1 blocked_ip2 ...

echo "Setting up IP address filtering..."

# Loop through all command-line arguments (IPs)
for BLOCKED_IP in "$@"; do
    sudo iptables -A INPUT -s "$BLOCKED_IP" -j DROP
    echo "Blocked IP address: $BLOCKED_IP"
done


