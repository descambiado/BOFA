
#!/bin/bash

# WiFi Shadow Mapper - Hidden Network Discovery Tool
# Developed by @descambiado for BOFA Suite
# Revolutionary tool for discovering phantom SSIDs and hidden networks

VERSION="1.0.0"
AUTHOR="@descambiado"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_banner() {
    echo -e "${CYAN}============================================================${NC}"
    echo -e "${CYAN}📡 WiFi Shadow Mapper - Hidden Network Discovery${NC}"
    echo -e "${CYAN}============================================================${NC}"
    echo -e "${YELLOW}Version: $VERSION | Author: $AUTHOR${NC}"
    echo -e "${YELLOW}Revolutionary passive discovery of phantom SSIDs${NC}"
    echo -e "${CYAN}============================================================${NC}"
}

print_help() {
    echo -e "${GREEN}Usage: $0 [OPTIONS]${NC}"
    echo
    echo -e "${YELLOW}Options:${NC}"
    echo -e "  -i, --interface IFACE    Network interface to use"
    echo -e "  -t, --time SECONDS       Scanning time (default: 60)"
    echo -e "  -c, --channel CHANNEL    Specific channel to monitor (1-13)"
    echo -e "  -o, --output FILE        Output results to file"
    echo -e "  -v, --verbose            Verbose output"
    echo -e "  -h, --help               Show this help"
    echo
    echo -e "${YELLOW}Examples:${NC}"
    echo -e "  $0 -i wlan0 -t 120 -v"
    echo -e "  $0 -i wlan0 -c 6 -o hidden_networks.txt"
    echo
    echo -e "${RED}⚠️  Root privileges required for monitor mode${NC}"
}

check_dependencies() {
    local deps=("iwconfig" "iw" "tshark" "airmon-ng")
    local missing=()
    
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            missing+=("$dep")
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${RED}❌ Missing dependencies: ${missing[*]}${NC}"
        echo -e "${YELLOW}Install with: sudo apt install wireless-tools iw tshark aircrack-ng${NC}"
        exit 1
    fi
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}❌ This script requires root privileges for monitor mode${NC}"
        echo -e "${YELLOW}Run with: sudo $0${NC}"
        exit 1
    fi
}

setup_monitor_mode() {
    local interface=$1
    local original_mode
    
    echo -e "${BLUE}🔧 Setting up monitor mode on $interface...${NC}"
    
    # Check if interface exists
    if ! ip link show "$interface" &> /dev/null; then
        echo -e "${RED}❌ Interface $interface not found${NC}"
        return 1
    fi
    
    # Store original mode
    original_mode=$(iwconfig "$interface" 2>/dev/null | grep -o "Mode:[^[:space:]]*" | cut -d: -f2)
    
    # Kill interfering processes
    airmon-ng check kill &> /dev/null
    
    # Enable monitor mode
    ip link set "$interface" down
    iw dev "$interface" set type monitor
    ip link set "$interface" up
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Monitor mode enabled on $interface${NC}"
        echo "$original_mode" > "/tmp/wifi_shadow_original_mode_$interface"
        return 0
    else
        echo -e "${RED}❌ Failed to enable monitor mode${NC}"
        return 1
    fi
}

restore_interface() {
    local interface=$1
    local original_mode_file="/tmp/wifi_shadow_original_mode_$interface"
    
    echo -e "${BLUE}🔧 Restoring interface $interface...${NC}"
    
    ip link set "$interface" down
    iw dev "$interface" set type managed
    ip link set "$interface" up
    
    # Restart NetworkManager if available
    if systemctl is-active --quiet NetworkManager; then
        systemctl restart NetworkManager
    fi
    
    # Clean up temp file
    [[ -f "$original_mode_file" ]] && rm -f "$original_mode_file"
    
    echo -e "${GREEN}✅ Interface restored${NC}"
}

detect_hidden_networks() {
    local interface=$1
    local scan_time=$2
    local channel=$3
    local verbose=$4
    local temp_file="/tmp/wifi_shadow_capture_$$"
    
    echo -e "${BLUE}🕵️  Starting passive network discovery...${NC}"
    echo -e "${YELLOW}   Interface: $interface${NC}"
    echo -e "${YELLOW}   Duration: ${scan_time}s${NC}"
    [[ -n "$channel" ]] && echo -e "${YELLOW}   Channel: $channel${NC}"
    
    # Channel hopping or fixed channel
    if [[ -n "$channel" ]]; then
        iw dev "$interface" set channel "$channel"
        echo -e "${BLUE}🎯 Monitoring channel $channel${NC}"
    else
        echo -e "${BLUE}🔄 Channel hopping enabled${NC}"
        # Start channel hopping in background
        channel_hop "$interface" &
        local hop_pid=$!
    fi
    
    # Start packet capture
    echo -e "${BLUE}📡 Capturing beacon frames...${NC}"
    
    timeout "$scan_time" tshark -i "$interface" -Y "wlan.fc.type_subtype == 0x08" \
        -T fields -e wlan.sa -e wlan.bssid -e wlan_mgt.ssid -e radiotap.channel.freq \
        -e wlan.fcs.status -e radiotap.dbm_antsignal > "$temp_file" 2>/dev/null &
    
    local capture_pid=$!
    
    # Progress indicator
    for ((i=1; i<=scan_time; i++)); do
        printf "\r${BLUE}⏳ Scanning... ${i}/${scan_time}s${NC}"
        sleep 1
    done
    echo
    
    # Stop channel hopping if it was started
    [[ -n "$hop_pid" ]] && kill "$hop_pid" 2>/dev/null
    
    # Process captured data
    process_captured_data "$temp_file" "$verbose"
    
    # Cleanup
    rm -f "$temp_file"
}

channel_hop() {
    local interface=$1
    local channels=(1 2 3 4 5 6 7 8 9 10 11 12 13)
    
    while true; do
        for ch in "${channels[@]}"; do
            iw dev "$interface" set channel "$ch" 2>/dev/null
            sleep 0.5
        done
    done
}

process_captured_data() {
    local temp_file=$1
    local verbose=$2
    local hidden_count=0
    local visible_count=0
    
    echo -e "\n${BLUE}📊 Analyzing captured beacon frames...${NC}"
    
    # Arrays to store network data
    declare -A networks
    declare -A hidden_networks
    declare -A signal_strength
    declare -A channels
    
    # Process each line from tshark output
    while IFS=$'\t' read -r src_mac bssid ssid freq fcs_status signal; do
        # Skip empty lines
        [[ -z "$bssid" ]] && continue
        
        # Extract channel from frequency
        local channel=""
        case "$freq" in
            2412) channel=1 ;;
            2417) channel=2 ;;
            2422) channel=3 ;;
            2427) channel=4 ;;
            2432) channel=5 ;;
            2437) channel=6 ;;
            2442) channel=7 ;;
            2447) channel=8 ;;
            2452) channel=9 ;;
            2457) channel=10 ;;
            2462) channel=11 ;;
            2467) channel=12 ;;
            2472) channel=13 ;;
        esac
        
        # Store network information
        channels["$bssid"]=$channel
        signal_strength["$bssid"]=$signal
        
        if [[ -z "$ssid" || "$ssid" == "" ]]; then
            # Hidden network detected
            hidden_networks["$bssid"]=1
            hidden_count=$((hidden_count + 1))
            
            [[ "$verbose" == "true" ]] && echo -e "${RED}👻 Hidden: $bssid (Ch:$channel, Signal:${signal}dBm)${NC}"
        else
            # Visible network
            networks["$bssid"]="$ssid"
            visible_count=$((visible_count + 1))
            
            [[ "$verbose" == "true" ]] && echo -e "${GREEN}📶 Visible: $ssid ($bssid)${NC}"
        fi
        
    done < "$temp_file"
    
    # Results summary
    echo -e "\n${CYAN}🎯 DISCOVERY RESULTS${NC}"
    echo -e "${CYAN}===================${NC}"
    echo -e "${GREEN}📶 Visible Networks: $visible_count${NC}"
    echo -e "${RED}👻 Hidden Networks: $hidden_count${NC}"
    
    # Detailed hidden networks report
    if [[ $hidden_count -gt 0 ]]; then
        echo -e "\n${RED}🔍 PHANTOM NETWORKS DETECTED:${NC}"
        echo -e "${RED}=============================${NC}"
        
        for bssid in "${!hidden_networks[@]}"; do
            local ch="${channels[$bssid]:-Unknown}"
            local sig="${signal_strength[$bssid]:-N/A}"
            echo -e "${YELLOW}BSSID: ${bssid}${NC}"
            echo -e "${YELLOW}  Channel: ${ch}${NC}"
            echo -e "${YELLOW}  Signal: ${sig}dBm${NC}"
            echo -e "${YELLOW}  Status: Hidden SSID${NC}"
            
            # Attempt to detect network type based on patterns
            analyze_hidden_network "$bssid" "$ch" "$sig"
            echo
        done
        
        # Advanced analysis
        perform_advanced_analysis "${!hidden_networks[@]}"
    fi
    
    # Store results globally for output
    HIDDEN_COUNT=$hidden_count
    VISIBLE_COUNT=$visible_count
}

analyze_hidden_network() {
    local bssid=$1
    local channel=$2
    local signal=$3
    
    # Vendor analysis based on MAC OUI
    local oui=$(echo "$bssid" | cut -d: -f1-3 | tr '[:lower:]' '[:upper:]')
    local vendor="Unknown"
    
    case "$oui" in
        "00:50:56"|"00:0C:29"|"00:05:69") vendor="VMware" ;;
        "08:00:27") vendor="VirtualBox" ;;
        "00:1B:21"|"00:26:08") vendor="Apple" ;;
        "00:23:6C"|"00:26:B0") vendor="Cisco" ;;
        "00:13:10"|"00:40:96") vendor="Linksys" ;;
        "00:50:F2") vendor="Microsoft" ;;
    esac
    
    echo -e "${CYAN}  Vendor: ${vendor}${NC}"
    
    # Security analysis
    if [[ "$signal" -gt -50 ]]; then
        echo -e "${RED}  Threat Level: HIGH (Strong signal, close proximity)${NC}"
    elif [[ "$signal" -gt -70 ]]; then
        echo -e "${YELLOW}  Threat Level: MEDIUM (Moderate signal)${NC}"
    else
        echo -e "${GREEN}  Threat Level: LOW (Weak signal)${NC}"
    fi
    
    # Suggest investigation techniques
    echo -e "${BLUE}  Investigation: Monitor for probe requests, deauth attacks${NC}"
}

perform_advanced_analysis() {
    local hidden_bssids=("$@")
    
    echo -e "${CYAN}🧠 ADVANCED ANALYSIS${NC}"
    echo -e "${CYAN}===================${NC}"
    
    # Pattern analysis
    local same_vendor_count=0
    local suspicious_channels=()
    
    for bssid in "${hidden_bssids[@]}"; do
        local ch="${channels[$bssid]}"
        [[ "$ch" == "6" || "$ch" == "11" ]] && suspicious_channels+=("$ch")
    done
    
    if [[ ${#suspicious_channels[@]} -gt 1 ]]; then
        echo -e "${RED}⚠️  Multiple hidden networks on common channels${NC}"
        echo -e "${RED}   Possible coordinated surveillance setup${NC}"
    fi
    
    # Timing analysis
    echo -e "${BLUE}💡 RECOMMENDATIONS:${NC}"
    echo -e "${BLUE}   • Monitor probe requests for SSID leakage${NC}"
    echo -e "${BLUE}   • Use passive analysis tools for deeper inspection${NC}"
    echo -e "${BLUE}   • Check for unusual beacon intervals${NC}"
    echo -e "${BLUE}   • Correlate with known threat intelligence${NC}"
}

save_results() {
    local output_file=$1
    
    if [[ -n "$output_file" ]]; then
        echo -e "\n${BLUE}💾 Saving results to $output_file...${NC}"
        
        {
            echo "# WiFi Shadow Mapper Results"
            echo "# Generated: $(date)"
            echo "# Scan Duration: ${SCAN_TIME}s"
            echo "# Interface: $INTERFACE"
            echo ""
            echo "SUMMARY:"
            echo "  Visible Networks: $VISIBLE_COUNT"
            echo "  Hidden Networks: $HIDDEN_COUNT"
            echo ""
            
            if [[ $HIDDEN_COUNT -gt 0 ]]; then
                echo "HIDDEN NETWORKS DETECTED:"
                for bssid in "${!hidden_networks[@]}"; do
                    echo "  BSSID: $bssid"
                    echo "  Channel: ${channels[$bssid]}"
                    echo "  Signal: ${signal_strength[$bssid]}dBm"
                    echo ""
                done
            fi
        } > "$output_file"
        
        echo -e "${GREEN}✅ Results saved successfully${NC}"
    fi
}

cleanup() {
    echo -e "\n${BLUE}🧹 Cleaning up...${NC}"
    [[ -n "$INTERFACE" ]] && restore_interface "$INTERFACE"
    exit 0
}

# Main script
main() {
    local interface=""
    local scan_time=60
    local channel=""
    local output_file=""
    local verbose=false
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -i|--interface)
                interface="$2"
                shift 2
                ;;
            -t|--time)
                scan_time="$2"
                shift 2
                ;;
            -c|--channel)
                channel="$2"
                shift 2
                ;;
            -o|--output)
                output_file="$2"
                shift 2
                ;;
            -v|--verbose)
                verbose=true
                shift
                ;;
            -h|--help)
                print_banner
                print_help
                exit 0
                ;;
            *)
                echo -e "${RED}❌ Unknown option: $1${NC}"
                print_help
                exit 1
                ;;
        esac
    done
    
    # Validate arguments
    if [[ -z "$interface" ]]; then
        echo -e "${RED}❌ Network interface required${NC}"
        print_help
        exit 1
    fi
    
    # Set global variables for cleanup
    INTERFACE="$interface"
    SCAN_TIME="$scan_time"
    
    # Set up signal handlers
    trap cleanup SIGINT SIGTERM
    
    print_banner
    
    echo -e "\n${BLUE}🔍 Initializing WiFi Shadow Mapper...${NC}"
    
    # Dependency and privilege checks
    check_dependencies
    check_root
    
    # Setup monitor mode
    if ! setup_monitor_mode "$interface"; then
        exit 1
    fi
    
    # Perform discovery
    detect_hidden_networks "$interface" "$scan_time" "$channel" "$verbose"
    
    # Save results if requested
    [[ -n "$output_file" ]] && save_results "$output_file"
    
    echo -e "\n${CYAN}🎯 WiFi Shadow Mapping Complete!${NC}"
    echo -e "${YELLOW}⚠️  Use findings responsibly and ethically${NC}"
    
    # Cleanup
    restore_interface "$interface"
}

# Handle script execution
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
