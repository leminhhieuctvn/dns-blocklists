#!/bin/bash

# Script to create a hosts file format from doh_combined.txt
# Adds localhost entries at the top and prepends 0.0.0.0 to each domain

set -e

INPUT_FILE="output/doh/doh_combined.txt"
OUTPUT_FILE="output/doh/doh_combined_hosts.txt"

# Check if input file exists
if [ ! -f "$INPUT_FILE" ]; then
    echo "Error: $INPUT_FILE not found!"
    exit 1
fi

# Create the output file with localhost entries at the top
cat > "$OUTPUT_FILE" << 'EOF'
===============================================================

127.0.0.1 localhost
127.0.0.1 localhost.localdomain
127.0.0.1 local
255.255.255.255 broadcasthost
::1 localhost
::1 ip6-localhost
::1 ip6-loopback
fe80::1%lo0 localhost
ff00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts
0.0.0.0 0.0.0.0

EOF

# Append each domain from the input file with 0.0.0.0 prepended
while IFS= read -r domain || [ -n "$domain" ]; do
    # Skip empty lines
    if [ -n "$domain" ]; then
        echo "0.0.0.0 $domain" >> "$OUTPUT_FILE"
    fi
done < "$INPUT_FILE"

echo "Generated hosts file: $OUTPUT_FILE"
echo "Total entries: $(wc -l < "$OUTPUT_FILE")"
