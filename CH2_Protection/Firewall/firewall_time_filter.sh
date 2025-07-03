#     Block Incoming Traffic:
#         sudo iptables -A INPUT -m time --timestart 20:00 --timestop 06:00 --days Mon,Tue,Wed,Thu,Fri -j DROP
#         This rule blocks incoming traffic during the specified time period.

#     Block Outgoing Traffic:
#         sudo iptables -A OUTPUT -m time --timestart 20:00 --timestop 06:00 --days Mon,Tue,Wed,Thu,Fri -j DROP
#         This rule blocks outgoing traffic during the specified time period.

# Summary:

#     Blocked Incoming Traffic: Between 8 PM and 6 AM Everyday.
#     Blocked Outgoing Traffic: Between 8 PM and 6 AM Everyday.

## To see time setting `timedatectl`
#!/bin/bash
# Script to set up time-based firewall rules for India (UTC +5:30)
#!/bin/bash

# Usage: ./firewall_time_filter.sh from_time to_time
# Example: ./firewall_time_filter.sh 14:30 00:30

# Check if both arguments are provided
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 from_time to_time"
    echo "Example: $0 14:30 00:30"
    exit 1
fi

from_time=$1
to_time=$2

echo "Setting up time-based rules from $from_time to $to_time"

# Block incoming traffic between the specified times
sudo iptables -A INPUT -m time --timestart "$from_time" --timestop "$to_time" -j DROP
echo "Blocked incoming traffic between $from_time and $to_time."

# Block outgoing traffic between the specified times
sudo iptables -A OUTPUT -m time --timestart "$from_time" --timestop "$to_time" -j DROP
echo "Blocked outgoing traffic between $from_time and $to_time."
