# Summary of What the Script Does:

#     Outbound Traffic: Allows all outgoing traffic by default.
#     Inbound Traffic:
#         Blocks all incoming traffic by default (for security).
#         Specifically allows incoming traffic on:
#             Port 22 (SSH) for remote login.
#             Port 80 (HTTP) for non-secure web traffic.
#             Port 443 (HTTPS) for secure web traffic.
#         Allows all traffic from the localhost (loopback) interface, enabling local communication within your machine.
#         Allows traffic related to established connections (e.g., responses to outgoing requests like visiting a website or an ongoing SSH session).

# Potential Use Case:

#     Security for a server where you want to ensure only certain ports (like SSH, HTTP, and HTTPS) are open for incoming connections, while blocking all others. Outgoing traffic is not restricted, meaning you can still access websites or make external requests without any problems.



#!/bin/bash
# Script to set up basic inbound and outbound firewall rules
# takes argument as IN or OUT for inbound or outbound rules block it 
echo "Setting up basic inbound and outbound firewall rules..."
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 IN|OUT"
    exit 1
fi
RULE_TYPE=$1
if [[ "$RULE_TYPE" != "IN" && "$RULE_TYPE" != "OUT" ]]; then
    echo "Invalid argument. Use IN for inbound rules or OUT for outbound rules."
    exit 1
fi

#!/bin/bash
# Script to set up basic inbound and outbound firewall rules
# Takes argument as IN or OUT for inbound or outbound rules to block

echo "Setting up basic inbound and outbound firewall rules..."

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 IN|OUT"
    exit 1
fi

RULE_TYPE=$1

if [[ "$RULE_TYPE" != "IN" && "$RULE_TYPE" != "OUT" ]]; then
    echo "Invalid argument. Use IN for inbound rules or OUT for outbound rules."
    exit 1
fi

if [ "$RULE_TYPE" == "IN" ]; then
    # Block all inbound traffic
    sudo iptables -A INPUT -j DROP
    echo "Blocked all inbound traffic."
elif [ "$RULE_TYPE" == "OUT" ]; then
    # Block all outbound traffic
    sudo iptables -A OUTPUT -j DROP
    echo "Blocked all outbound traffic."
fi

