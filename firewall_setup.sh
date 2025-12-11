#!/bin/bash
#
# Firewall Setup Script for Chain of Product (CoP) Infrastructure
# Run this script on each VM with the appropriate role
#
# Usage: ./firewall_setup.sh <role> [options]
#
# Roles:
#   database     - Database VM (MySQL)
#   server       - Main Server VM
#   groupserver  - Group Server VM
#   client       - Client VM
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_usage() {
    echo "Usage: $0 <role> [options]"
    echo ""
    echo "Roles:"
    echo "  database      - Database VM (allows MySQL from specified IPs)"
    echo "  server        - Main Server VM (allows HTTPS on port 8000)"
    echo "  groupserver   - Group Server VM (allows HTTPS on port 8001 from Main Server)"
    echo "  client        - Client VM (outgoing only)"
    echo ""
    echo "Options (depend on role):"
    echo "  database:     $0 database <MAIN_SERVER_IP> <GROUP_SERVER_IP>"
    echo "  server:       $0 server"
    echo "  groupserver:  $0 groupserver <MAIN_SERVER_IP>"
    echo "  client:       $0 client"
    echo ""
    echo "Examples:"
    echo "  $0 database 10.0.1.20 10.0.1.30"
    echo "  $0 server"
    echo "  $0 groupserver 10.0.1.20"
    echo "  $0 client"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}Error: Please run as root (use sudo)${NC}"
        exit 1
    fi
}

setup_database_firewall() {
    MAIN_SERVER_IP=$1
    GROUP_SERVER_IP=$2

    if [ -z "$MAIN_SERVER_IP" ] || [ -z "$GROUP_SERVER_IP" ]; then
        echo -e "${RED}Error: Database role requires MAIN_SERVER_IP and GROUP_SERVER_IP${NC}"
        echo "Usage: $0 database <MAIN_SERVER_IP> <GROUP_SERVER_IP>"
        exit 1
    fi

    echo -e "${YELLOW}Setting up firewall for DATABASE VM${NC}"
    echo "Allowing MySQL (3306) from: $MAIN_SERVER_IP, $GROUP_SERVER_IP"

    # Reset and set defaults
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing

    # Allow MySQL only from Main Server and Group Server
    ufw allow from $MAIN_SERVER_IP to any port 3306 proto tcp comment 'MySQL from Main Server'
    ufw allow from $GROUP_SERVER_IP to any port 3306 proto tcp comment 'MySQL from Group Server'

    # Allow SSH for management
    ufw allow 22/tcp comment 'SSH'

    # Enable firewall
    ufw --force enable

    echo -e "${GREEN}Database firewall configured successfully${NC}"
}

setup_server_firewall() {
    echo -e "${YELLOW}Setting up firewall for MAIN SERVER VM${NC}"
    echo "Allowing HTTPS (8000) from anywhere"

    # Reset and set defaults
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing

    # Allow HTTPS API from anywhere (clients)
    ufw allow 8000/tcp comment 'CoP Main Server API'

    # Allow SSH for management
    ufw allow 22/tcp comment 'SSH'

    # Enable firewall
    ufw --force enable

    echo -e "${GREEN}Main Server firewall configured successfully${NC}"
}

setup_groupserver_firewall() {
    MAIN_SERVER_IP=$1

    if [ -z "$MAIN_SERVER_IP" ]; then
        echo -e "${RED}Error: Group Server role requires MAIN_SERVER_IP${NC}"
        echo "Usage: $0 groupserver <MAIN_SERVER_IP>"
        exit 1
    fi

    echo -e "${YELLOW}Setting up firewall for GROUP SERVER VM${NC}"
    echo "Allowing HTTPS (8001) only from: $MAIN_SERVER_IP"

    # Reset and set defaults
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing

    # Allow Group Server API only from Main Server
    ufw allow from $MAIN_SERVER_IP to any port 8001 proto tcp comment 'Group API from Main Server'

    # Allow SSH for management
    ufw allow 22/tcp comment 'SSH'

    # Enable firewall
    ufw --force enable

    echo -e "${GREEN}Group Server firewall configured successfully${NC}"
}

setup_client_firewall() {
    echo -e "${YELLOW}Setting up firewall for CLIENT VM${NC}"
    echo "Denying all incoming, allowing all outgoing"

    # Reset and set defaults
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing

    # Allow SSH for management
    ufw allow 22/tcp comment 'SSH'

    # Enable firewall
    ufw --force enable

    echo -e "${GREEN}Client firewall configured successfully${NC}"
}

show_status() {
    echo ""
    echo -e "${YELLOW}Current firewall status:${NC}"
    ufw status verbose
    echo ""
    echo -e "${YELLOW}Firewall rules:${NC}"
    ufw status numbered
}

# Main script
if [ -z "$1" ]; then
    print_usage
    exit 1
fi

check_root

ROLE=$1
shift

case $ROLE in
    database)
        setup_database_firewall "$@"
        ;;
    server)
        setup_server_firewall
        ;;
    groupserver)
        setup_groupserver_firewall "$@"
        ;;
    client)
        setup_client_firewall
        ;;
    status)
        show_status
        exit 0
        ;;
    *)
        echo -e "${RED}Unknown role: $ROLE${NC}"
        print_usage
        exit 1
        ;;
esac

show_status

echo ""
echo -e "${GREEN}Firewall setup complete!${NC}"
echo ""
echo "To check status later: sudo ufw status verbose"
echo "To disable firewall:   sudo ufw disable"
echo "To view rules:         sudo ufw status numbered"