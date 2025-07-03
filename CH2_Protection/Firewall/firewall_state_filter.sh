#Verified:

#Testing and Troubleshooting:

   # After running this script, try opening a new website. It should be blocked.
   # Important: If you run this on a remote machine, ensure you have a way to revert the changes or access the machine via some other means (e.g., physical console or rescue mode), as this will block any new outbound connections.

   #The script allows only established or related traffic while blocking all new incoming connection attempts.
#This is a basic security measure often used to prevent unauthorized access while allowing responses to requests that your machine initiated.


#!/bin/bash
# Script to filter traffic based on connection state
# Usage: ./firewall_conntrack.sh state1 state2 ...
# Block all specified connection states

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 state1 state2 ..."
    exit 1
fi

echo "Setting up connection state-based firewall rules..."

# Loop through all command-line arguments (states)
for STATE in "$@"; do
    sudo iptables -A INPUT -m conntrack --ctstate "$STATE" -j DROP
    echo "Blocked traffic for connection state: $STATE"
done

