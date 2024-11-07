#!/bin/bash

set -euo pipefail  # Enable strict error handling

# Function to display usage
usage() {
    echo "Usage: $0 [-p password]"
    echo "Checks if a password has been exposed in known data breaches"
    echo
    echo "Options:"
    echo "  -p    Provide password directly (not recommended)"
    echo "If no password is provided, script will prompt securely"
    exit 1
}

# Function to clean up and exit
cleanup() {
    if [ -n "${TMPFILE:-}" ]; then
        rm -f "$TMPFILE"
    fi
}

# Set up trap for cleanup
trap cleanup EXIT

# Process command line arguments
password=""
while getopts "hp:" opt; do
    case $opt in
        h) usage ;;
        p) password="$OPTARG" ;;
        *) usage ;;
    esac
done

# If password wasn't provided via args, prompt for it
if [ -z "$password" ]; then
    echo -n "Enter password to check: "
    read -rs password
    echo
fi

# Validate input
if [ -z "$password" ]; then
    echo "Error: Password cannot be empty" >&2
    exit 1
fi

# Create temporary file with secure permissions
TMPFILE=$(mktemp)
chmod 600 "$TMPFILE"

# Calculate hash
hash=$(echo -n "$password" | openssl sha1 2>/dev/null | awk '{print $NF}')
unset password  # Clear password from memory

upperCase=$(echo "$hash" | tr '[:lower:]' '[:upper:]')
prefix="${upperCase:0:5}"
suffix="${upperCase:5}"

# Fetch and check breach data
if ! response=$(curl -sf --retry 3 --retry-delay 2 "https://api.pwnedpasswords.com/range/$prefix"); then
    echo "Error: Failed to connect to HaveIBeenPwned API" >&2
    exit 1
fi

# Store response in temporary file
echo "$response" > "$TMPFILE"

# Check if password hash exists in breach database
if result=$(grep -i "${suffix}" "$TMPFILE"); then
    # Clean the count by removing any hidden characters and trimming whitespace
    count=$(echo "$result" | cut -d':' -f2 | tr -d '\r\n' | tr -d '[:space:]')
    if [ -n "$count" ]; then
        echo "WARNING: This password has been exposed in data breaches!"
        echo "It appears $count times in known breaches."
        echo "Recommendation: Please choose a different password."
    else
        echo "WARNING: This password has been exposed in data breaches!"
        echo "Unable to determine the exact count of breaches."
        echo "Recommendation: Please choose a different password."
    fi
    exit 1
else
    echo "Password not found in known data breaches."
    echo "Note: This doesn't guarantee the password is secure, just that it hasn't been exposed in known breaches."
    exit 0
fi
