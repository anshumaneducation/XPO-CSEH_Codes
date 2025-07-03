#     Blocked SMTP traffic on port 25:
#         Blocks incoming traffic on port 25, preventing SMTP traffic (used for email sending).

#     Blocked HTTP traffic on port 80:
#         Blocks incoming HTTP traffic (typically used for web browsing over HTTP) on port 80.

#     Dropped traffic on port 8080:
#         Drops any incoming traffic on port 8080, which may be used by applications running on non-standard HTTP ports.

#     Allowed HTTPS traffic on port 443:
#         Allows incoming HTTPS traffic (secure web traffic) on port 443.

# Summary:

#     Blocked: SMTP (port 25) and HTTP (port 80).
#     Dropped: Traffic on port 8080.
#     Allowed: HTTPS (port 443).




#!/bin/bash
# Script to filter traffic based on ports
# take port numbers as arguments
# Usage: ./firewall_port_filter.sh port1 port2 ...
# Example: ./firewall_port_filter.sh 25 80 8080 443
echo "Setting up port-based firewall rules..."
if [ "$#" -lt 1 ]; then
    echo "Usage: $0 port1 port2 ..."
    exit 1
fi
# Loop through all command-line arguments (ports)& block them
for PORT in "$@"; do
    sudo iptables -A INPUT -p tcp --dport "$PORT" -j DROP
    echo "Blocked traffic on port $PORT."
done


