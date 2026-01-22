#!/bin/bash

# ENVIRONMENT & VALIDATION

if [ ! -f .env ]; then
    echo " Missing .env file"
    exit 1
fi

source .env

if [[ -z "$VT_API_KEY" || -z "$OTX_API_KEY" ]]; then
    echo " API keys not set in .env"
    exit 1
fi

# CSV OUTPUT SET

CSV_FILE="$HOME/threat_intel_report.csv"
if [ ! -f "$CSV_FILE" ]; then
    echo "Type,Input,Severity,OTX_Pulses,VT_Detections,VT_Vendors,Last_Analysis,Country,Owner,First_Seen" > "$CSV_FILE"
fi

# UTILITY FUNCTIONS

format_timestamp() {
    ts="$1"
    if [[ "$ts" =~ ^[0-9]+$ ]]; then
        if [[ "$OSTYPE" == "darwin"* ]]; then
            date -r "$ts" "+%Y-%m-%d"
        else
            date -d @"$ts" "+%Y-%m-%d"
        fi
    else
        echo "Unknown"
    fi
}

calculate_severity() {
    score=$(( (vt_detections * 3) + otx_pulses ))
    if (( score >= 15 )); then echo "Critical"
    elif (( score >= 8 )); then echo "High"
    elif (( score >= 4 )); then echo "Medium"
    elif (( score >= 1 )); then echo "Low"
    else echo "Informational"
    fi
}

# API FUNCTIONS

get_otx() {
    curl -s -H "X-OTX-API-KEY: $OTX_API_KEY" \
    "https://otx.alienvault.com/api/v1/indicators/$1/$2/general"
}

get_vt() {
    curl -s -H "x-apikey: $VT_API_KEY" \
    "https://www.virustotal.com/api/v3/$1"
}

# USER INPUT SELECTION

echo "Select IOC type:"
echo "1) IP Address"
echo "2) Domain"
echo "3) URL"
echo "4) File Hash"
echo "5) File Upload"
read -p "> " choice

case "$choice" in
1)
    read -p "Enter IP: " input
    ioc_type="IPv4"
    vt_endpoint="ip_addresses/$input"
    ;;
2)
    read -p "Enter Domain: " input
    ioc_type="domain"
    vt_endpoint="domains/$input"
    ;;
3)
    read -p "Enter URL: " input
    ioc_type="url"
    encoded=$(echo -n "$input" | base64 | tr -d '=' | tr '/+' '_-')
    vt_endpoint="urls/$encoded"
    ;;
4)
    read -p "Enter File Hash: " input
    ioc_type="file"
    vt_endpoint="files/$input"
    ;;
5)
    read -p "Enter File Path: " filepath
    [[ ! -f "$filepath" ]] && echo " File not found" && exit 1
    input=$(shasum -a 256 "$filepath" | awk '{print $1}')
    ioc_type="file"
    vt_endpoint="files/$input"
    ;;
*)
    echo " Invalid option"
    exit 1
    ;;
esac

# DATA FETCHING

otx_json=$(get_otx "$ioc_type" "$input")
vt_json=$(get_vt "$vt_endpoint")

# DATA EXTRACTION

otx_pulses=$(echo "$otx_json" | jq '.pulse_info.count // 0')
vt_detections=$(echo "$vt_json" | jq '.data.attributes.last_analysis_stats.malicious // 0')
vt_flagged=$(echo "$vt_json" | jq -r '[.data.attributes.last_analysis_results[] | select(.category=="malicious") | .engine_name] | join(", ")')
vt_last_scan=$(format_timestamp "$(echo "$vt_json" | jq -r '.data.attributes.last_analysis_date // 0')")
vt_categories=$(echo "$vt_json" | jq -r '.data.attributes.categories | keys | join(", ")')
vt_tags=$(echo "$vt_json" | jq -r '.data.attributes.tags | join(", ")')

country=$(echo "$vt_json" | jq -r '.data.attributes.country // .data.attributes.registrar // "Unknown"')
owner=$(echo "$vt_json" | jq -r '.data.attributes.as_owner // .data.attributes.whois // "Unknown"' | head -c 100)
first_seen=$(format_timestamp "$(echo "$vt_json" | jq -r '.data.attributes.first_seen // .data.attributes.creation_date // 0')")

severity=$(calculate_severity)

# STRUCTURED OUTPUT

echo
echo "============================================================"
echo "                THREAT INTELLIGENCE REPORT"
echo "============================================================"
echo
echo "IOC INFORMATION"
echo "------------------------------------------------------------"
echo "Type            : $ioc_type"
echo "Value           : $input"
echo
echo "RISK ASSESSMENT"
echo "------------------------------------------------------------"
echo "Severity        : $severity"
echo "OTX Pulses      : $otx_pulses"
echo "VT Detections   : $vt_detections"
echo
echo "OTX INTELLIGENCE (COMMUNITY CONTEXT)"
echo "------------------------------------------------------------"

if [ "$otx_pulses" -gt 0 ]; then
    echo "$otx_json" | jq -r '
    .pulse_info.pulses[:3][] |
    "• Pulse Name   : \(.name)\n  Description  : \(.description)\n  Tags         : \(.tags | join(", "))\n  Reference    : https://otx.alienvault.com/pulse/\(.id)\n"
    '
else
    echo "No OTX pulses associated with this IOC."
fi

echo
echo "VIRUSTOTAL INTELLIGENCE (ENGINE VERDICTS)"
echo "------------------------------------------------------------"
echo "Detections      : $vt_detections engines"
echo "Flagged By      : ${vt_flagged:-None}"
echo "Last Analysis   : $vt_last_scan"
echo "Categories      : ${vt_categories:-None}"
echo "Tags            : ${vt_tags:-None}"

echo
echo "IOC METADATA"
echo "------------------------------------------------------------"
echo "Country/Owner   : $country"
echo "ASN/Registrar   : $owner"
echo "First Seen      : $first_seen"

echo
echo "FINAL ANALYST VERDICT"
echo "------------------------------------------------------------"

if [[ "$severity" == "Critical" || "$severity" == "High" ]]; then
    echo "This IOC is heavily detected and referenced across"
    echo "multiple threat intelligence sources. Immediate"
    echo "investigation and containment is recommended."
else
    echo "This IOC shows limited or contextual detection."
    echo "Monitoring or documentation is recommended."
fi

echo
echo "============================================================"

# CSV SAVE

echo "$ioc_type,$input,$severity,$otx_pulses,$vt_detections,\"$vt_flagged\",$vt_last_scan,\"$country\",\"$owner\",$first_seen" >> "$CSV_FILE"
echo " Report saved to $CSV_FILE"

