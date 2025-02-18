#!/bin/bash

# Automated Phishing Link Detector

# Check if URL is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <URL>"
    exit 1
fi

URL="$1"

# Function to expand shortened URLs
expand_url() {
    EXPANDED=$(curl -Ls -o /dev/null -w %{url_effective} "$URL")
    echo "Expanded URL: $EXPANDED"
    echo "$EXPANDED"
}

# Function to check OpenPhish database
check_openphish() {
    echo "Checking OpenPhish database..."
    RESPONSE=$(curl -s https://openphish.com/feed.txt | grep -F "$URL")
    if [ ! -z "$RESPONSE" ]; then
        echo "⚠️ Warning: This URL is in OpenPhish database!"
    else
        echo "✅ Safe: Not found in OpenPhish database."
    fi
}

# Function to check PhishTank database
check_phishtank() {
    echo "Checking PhishTank database..."
    RESPONSE=$(curl -s https://data.phishtank.com/data/online-valid.csv | grep -F "$URL")
    if [ ! -z "$RESPONSE" ]; then
        echo "⚠️ Warning: This URL is in PhishTank database!"
    else
        echo "✅ Safe: Not found in PhishTank database."
    fi
}

# Function to check Google Safe Browsing API
check_google_safebrowsing() {
    API_KEY="YOUR_GOOGLE_API_KEY"
    RESPONSE=$(curl -s -X POST "https://safebrowsing.googleapis.com/v4/threatMatches:find?key=$API_KEY" \
        -H "Content-Type: application/json" \
        -d '{"client": {"clientId": "bash-script", "clientVersion": "1.0"}, "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"], "platformTypes": ["ANY_PLATFORM"], "threatEntryTypes": ["URL"], "threatEntries": [{"url": "'$URL'"}]}}')
    if echo "$RESPONSE" | grep -q "matches"; then
        echo "⚠️ Warning: This URL is flagged by Google Safe Browsing!"
    else
        echo "✅ Safe: Not flagged by Google Safe Browsing."
    fi
}

# Function to get WHOIS domain info
check_whois() {
    DOMAIN=$(echo "$URL" | awk -F[/:] '{print $4}')
    echo "Checking WHOIS information for $DOMAIN..."
    whois "$DOMAIN" | grep -E 'Creation Date|Registrar|Updated Date' | head -3
}

# Function to check SSL certificate details
check_ssl() {
    DOMAIN=$(echo "$URL" | awk -F[/:] '{print $4}')
    echo "Checking SSL certificate for $DOMAIN..."
    echo | openssl s_client -servername "$DOMAIN" -connect "$DOMAIN":443 2>/dev/null | openssl x509 -noout -dates
}

# Function to scan URL content for phishing indicators
scan_url() {
    echo "Scanning URL content for phishing indicators..."
    CONTENT=$(curl -s "$URL")
    if echo "$CONTENT" | grep -qiE "login|password|bank|verify|update"; then
        echo "⚠️ Suspicious: The webpage contains phishing-related keywords."
    else
        echo "✅ Safe: No obvious phishing keywords detected."
    fi
}

# Main Execution
EXPANDED_URL=$(expand_url)
check_openphish
check_phishtank
check_google_safebrowsing
check_whois
check_ssl
scan_url
