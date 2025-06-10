#!/bin/bash
echo "[+] Installing an Enhanced Stealth Tunnel..."

if [[ $EUID -ne 0 ]]; then
   echo "[!] Root rights are required"
   exit 1
fi

apt-get update -qq
apt-get install -y python3 python3-pip iptables iproute2 tcpdump

pip3 install cryptography scapy

mkdir -p /opt/enhanced-stealth-tunnel
cd /opt/enhanced-stealth-tunnel

echo "[+] Enhanced Stealth Tunnel is installed!"
echo "[+] Example:"
echo "    python3 enhanced_stealth_tunnel.py --generate-config"
echo "    python3 enhanced_stealth_tunnel.py -c enhanced_tunnel_config.json"
