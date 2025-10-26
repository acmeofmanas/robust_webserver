#!/bin/bash
# latency_checker.sh
# A simple Bash script to check network latency and packet loss against multiple targets.

# --- CONFIGURATION ---
# List of hosts to test (space-separated)
TARGETS="8.8.8.8 1.1.1.1 google.com amazon.com"

# Number of ICMP packets to send to each target
PING_COUNT=5

# Separator line for readability
SEP="----------------------------------------------------------------------"

# --- FUNCTIONS ---

# Function to display usage information
show_help() {
    echo "Usage: $0 [HOST1 HOST2 ...]"
    echo ""
    echo "Pings a list of specified hosts (or default targets) and reports latency statistics."
    echo "Default Targets: $TARGETS"
    echo "Ping Count: $PING_COUNT"
    echo ""
    echo "Example: $0 microsoft.com 192.168.1.1"
}

# Function to run the ping test and process results
run_test() {
    local host="$1"
    echo "Testing Host: $host (Sending $PING_COUNT packets)..."

    # Use 'ping -c $PING_COUNT' for the specified count.
    # We pipe the output to a temporary file to parse it cleanly.
    # Note: Using '-W 2' sets a 2-second timeout per probe.
    PING_OUTPUT=$(ping -c "$PING_COUNT" -W 2 "$host" 2>&1)
    PING_EXIT_CODE=$?

    if [ $PING_EXIT_CODE -ne 0 ] && ! echo "$PING_OUTPUT" | grep -q "min/avg/max"; then
        # Check if the host is unreachable/unknown
        echo "  [ERROR] Host unreachable or unknown."
        echo "  Check host name or network connectivity."
        return
    fi

    # 1. Extract Packet Loss
    # Find the line containing "packets transmitted" and extract the percentage.
    PACKET_LOSS=$(echo "$PING_OUTPUT" | grep 'transmitted' | awk -F', ' '{print $3}' | awk '{print $1}')
    if [ -z "$PACKET_LOSS" ]; then
        PACKET_LOSS="100.0%"
    fi

    # 2. Extract Latency Statistics (min/avg/max/mdev)
    # Find the line starting with "round-trip min/avg/max/mdev"
    STATS_LINE=$(echo "$PING_OUTPUT" | grep 'min/avg/max')

    if [ -n "$STATS_LINE" ]; then
        # Extract the min/avg/max/mdev values (in ms)
        LATENCY_STATS=$(echo "$STATS_LINE" | awk -F'[/=]' '{print $NF}' | awk '{print $1}')

        # Split the stats into individual variables
        IFS='/' read -r MIN_LATENCY AVG_LATENCY MAX_LATENCY STD_DEV <<< "$LATENCY_STATS"

        # 3. Print Formatted Results
        printf "  %s\n" "$SEP"
        printf "  %-12s: %-10s\n" "Host" "$host"
        printf "  %-12s: %-10s\n" "Packet Loss" "$PACKET_LOSS"
        printf "  %-12s: %-10s\n" "Min Latency" "${MIN_LATENCY:-N/A} ms"
        printf "  %-12s: %-10s\n" "Avg Latency" "${AVG_LATENCY:-N/A} ms"
        printf "  %-12s: %-10s\n" "Max Latency" "${MAX_LATENCY:-N/A} ms"
        printf "  %-12s: %-10s\n" "Std Dev" "${STD_DEV:-N/A} ms"
        printf "  %s\n" "$SEP"
    else
        # This handles cases where packets were sent but 100% loss occurred or ping failed differently
        echo "  [FAIL] Failed to receive statistics. Packet Loss: $PACKET_LOSS"
        echo "  %s\n" "$SEP"
    fi
}

# --- MAIN EXECUTION ---

# Check if the user provided arguments
if [ "$#" -gt 0 ]; then
    if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
        show_help
        exit 0
    fi
    TARGETS="$@"
fi

echo "--- Network Latency Check Started ---"
echo "Testing $PING_COUNT ICMP packets per host."
echo "$SEP"

# Iterate over the target hosts and run the test
for target in $TARGETS; do
    run_test "$target"
done

echo "--- Network Latency Check Complete ---"
echo "$SEP"

# EOF

