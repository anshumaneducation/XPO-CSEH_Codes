# Summary:

#     Allowed: TCP traffic, HTTP traffic (port 80), and UDP traffic.
#     Blocked: ICMP traffic (ping requests).

# This script now:

#     Allows essential protocols (TCP for most services, HTTP for web traffic, and UDP for applications like DNS or VoIP).
#     Blocks ping requests (ICMP) for increased security against discovery.


#!/bin/bash
# Script to filter traffic based on protocols
# Usage: ./firewall_protocol_filter.sh protocol_name
# Block all other protocols except the specified protocol

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 protocol_name"
    exit 1
fi

PROTOCOL_NAME=$1

echo "Setting up protocol-based firewall rules..."
echo "Allowing only $PROTOCOL_NAME traffic and blocking all others..."

# Allow traffic for the specified protocol
sudo iptables -A INPUT -p "$PROTOCOL_NAME" -j ACCEPT
echo "Allowed $PROTOCOL_NAME traffic."

# Block all other protocols
sudo iptables -A INPUT -p ! "$PROTOCOL_NAME" -j DROP
echo "Blocked all other protocols except $PROTOCOL_NAME."
