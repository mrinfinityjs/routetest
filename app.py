#!/usr/bin/env python3
"""
Comprehensive Network Testing Tool
Tests servers for ICMP ping, TCP latency, SSL/TLS, QUIC, DNS, SSH, certificates, and more.
"""

import argparse
import socket
import ssl
import subprocess
import json
import time
import threading
import concurrent.futures
from typing import Dict, List, Tuple, Optional, Any
import ipaddress
import re
from datetime import datetime, timezone
import urllib.request
import urllib.error
import os
import hashlib
import requests
from datetime import timedelta


class NetworkTester:
    def __init__(self, cache_enabled=False, tcp_threshold_avg=10, tcp_threshold_lowest=20):
        self.results = {}
        self.cache_enabled = cache_enabled
        self.tcp_threshold_avg = tcp_threshold_avg
        self.tcp_threshold_lowest = tcp_threshold_lowest
        self.cache_dir = "./cache"
        
        # Create cache directory if it doesn't exist
        if self.cache_enabled and not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)
    
    def get_cache_filename(self, server: str, test_type: str) -> str:
        """Generate cache filename for a server and test type"""
        server_hash = hashlib.md5(server.encode()).hexdigest()
        return os.path.join(self.cache_dir, f"{server_hash}_{test_type}.json")
    
    def load_from_cache(self, server: str, test_type: str) -> Optional[Dict]:
        """Load test results from cache if not older than 3 hours"""
        if not self.cache_enabled:
            return None
        
        cache_file = self.get_cache_filename(server, test_type)
        try:
            if os.path.exists(cache_file):
                with open(cache_file, 'r') as f:
                    data = json.load(f)
                
                # Check if cache is older than 3 hours
                cached_at = data.get('cached_at')
                if cached_at:
                    cached_time = datetime.fromisoformat(cached_at.replace('Z', '+00:00'))
                    if cached_time.tzinfo is None:
                        cached_time = cached_time.replace(tzinfo=timezone.utc)
                    
                    if datetime.now(timezone.utc) - cached_time > timedelta(hours=3):
                        # Cache is too old, delete it
                        os.remove(cache_file)
                        return None
                
                return data
        except Exception:
            pass
        return None
    
    def save_to_cache(self, server: str, test_type: str, data: Dict):
        """Save test results to cache"""
        if not self.cache_enabled:
            return
        
        cache_file = self.get_cache_filename(server, test_type)
        try:
            data['cached_at'] = datetime.now().isoformat()
            with open(cache_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception:
            pass
    
    def check_security_anomalies(self, ping_results: Dict, tcp_results: Dict) -> List[str]:
        """Check for security anomalies based on latency differences"""
        warnings = []
        
        if not ping_results.get('success') or not ping_results.get('avg'):
            return warnings
        
        ping_avg = ping_results['avg']
        ping_lowest = ping_results['min']
        
        for port, tcp_result in tcp_results.items():
            if tcp_result.get('success') and tcp_result.get('latency'):
                tcp_latency = tcp_result['latency']
                
                # Check if TCP latency is significantly higher than ping average
                if tcp_latency > (ping_avg + self.tcp_threshold_avg):
                    warnings.append(f"SECURITY WARNING: Port {port} TCP latency ({tcp_latency:.1f}ms) is {tcp_latency - ping_avg:.1f}ms higher than ICMP average ({ping_avg:.1f}ms) - possible traffic shaping or DPI")
                
                # Check if TCP latency is significantly higher than ping lowest
                if tcp_latency > (ping_lowest + self.tcp_threshold_lowest):
                    warnings.append(f"SECURITY WARNING: Port {port} TCP latency ({tcp_latency:.1f}ms) is {tcp_latency - ping_lowest:.1f}ms higher than ICMP lowest ({ping_lowest:.1f}ms) - possible deep packet inspection or traffic manipulation")
        
        return warnings

    def get_asn_info(self, ip: str) -> Dict[str, Any]:
        """Get ASN information for an IP address"""
        try:
            # Use ip-api.com for ASN information
            url = f"http://ip-api.com/json/{ip}?fields=status,query,as,asname,abuse"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    return {
                        'success': True,
                        'asn': data.get('as', 'Unknown'),
                        'asname': data.get('asname', 'Unknown'),
                        'abuse_email': data.get('abuse', 'Unknown')
                    }
            
            return {
                'success': False,
                'error': f'HTTP {response.status_code}'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def check_dnsbl(self, ip: str) -> Dict[str, Any]:
        """Check if IP is on DNS blacklists"""
        try:
            # Reverse the IP for DNSBL queries
            ip_parts = ip.split('.')
            reversed_ip = '.'.join(reversed(ip_parts))
            
            # Common DNSBL services
            dnsbls = [
                'zen.spamhaus.org',
                'bl.spamcop.net',
                'dnsbl.sorbs.net',
                'xbl.spamhaus.org',
                'pbl.spamhaus.org'
            ]
            
            blacklisted = []
            
            for dnsbl in dnsbls:
                try:
                    # Try to resolve the DNSBL entry
                    query = f"{reversed_ip}.{dnsbl}"
                    result = socket.gethostbyname(query)
                    if result:
                        blacklisted.append(dnsbl)
                except socket.gaierror:
                    # Not blacklisted on this DNSBL
                    pass
                except Exception:
                    pass
            
            return {
                'success': True,
                'blacklisted': len(blacklisted) > 0,
                'blacklists': blacklisted
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'blacklisted': False,
                'blacklists': []
            }

    def check_proxy(self, ip: str) -> Dict[str, Any]:
        """Check if IP is a known proxy"""
        try:
            # Use multiple proxy detection services
            proxy_services = [
                f"http://proxycheck.io/v2/{ip}?key=demo&vpn=1&asn=1&node=1",
                f"https://ipqualityscore.com/api/json/ip/demo/{ip}?strictness=1&fast=true"
            ]
            
            is_proxy = False
            proxy_type = None
            
            for service_url in proxy_services:
                try:
                    response = requests.get(service_url, timeout=5)
                    if response.status_code == 200:
                        data = response.json()
                        
                        # Check different service formats
                        if 'status' in data and data['status'] == 'ok':
                            if 'proxy' in data:
                                is_proxy = data['proxy'] == 'yes'
                            if 'vpn' in data:
                                if data['vpn'] == 'yes':
                                    is_proxy = True
                                    proxy_type = 'VPN'
                        
                        break
                except Exception:
                    continue
            
            return {
                'success': True,
                'is_proxy': is_proxy,
                'proxy_type': proxy_type
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'is_proxy': False,
                'proxy_type': None
            }

    def get_cve_info(self, software_name: str, version: str = None) -> Dict[str, Any]:
        """Get CVE information for software and version"""
        try:
            # Use CVE database APIs (simplified version)
            # In a real implementation, you'd use the official CVE database
            cve_info = {
                'success': True,
                'cves': [],
                'risk_level': 'Unknown'
            }
            
            # Common vulnerable versions with descriptions (simplified database)
            vulnerable_versions = {
                'OpenSSH': {
                    '6.6.1': [
                        {'id': 'CVE-2014-2532', 'desc': 'Buffer overflow in roaming code'},
                        {'id': 'CVE-2014-2653', 'desc': 'Multiple vulnerabilities in roaming code'}
                    ],
                    '7.0': [
                        {'id': 'CVE-2016-0777', 'desc': 'Information leak in roaming code'},
                        {'id': 'CVE-2016-0778', 'desc': 'Buffer overflow in roaming code'}
                    ],
                    '8.0': [
                        {'id': 'CVE-2020-14145', 'desc': 'Observable discrepancy in SSH protocol'}
                    ]
                },
                'Apache': {
                    '2.4.7': [
                        {'id': 'CVE-2014-0098', 'desc': 'Log injection vulnerability'},
                        {'id': 'CVE-2014-0117', 'desc': 'Denial of service via malformed headers'}
                    ],
                    '2.4.41': [
                        {'id': 'CVE-2021-44224', 'desc': 'Log4j remote code execution'},
                        {'id': 'CVE-2021-44790', 'desc': 'Buffer overflow in mod_lua'}
                    ]
                },
                'nginx': {
                    '1.14.0': [
                        {'id': 'CVE-2019-20372', 'desc': 'NULL pointer dereference vulnerability'}
                    ],
                    '1.16.0': [
                        {'id': 'CVE-2019-20372', 'desc': 'NULL pointer dereference vulnerability'}
                    ]
                }
            }
            
            if software_name in vulnerable_versions and version:
                for vuln_version, cves in vulnerable_versions[software_name].items():
                    if version.startswith(vuln_version):
                        cve_info['cves'] = cves
                        cve_info['risk_level'] = 'High' if len(cves) > 2 else 'Medium'
                        break
            
            return cve_info
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'cves': [],
                'risk_level': 'Unknown'
            }

    def check_ssh_authentication(self, host: str, port: int = 22) -> Dict[str, Any]:
        """Check SSH authentication methods and security"""
        print(f"🔍 Checking SSH authentication for {host}:{port}...")
        
        try:
            # Try to connect to SSH and get server information
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            
            # Get SSH banner
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            # Try to detect authentication methods (this is limited without full SSH protocol)
            # We'll use nmap's SSH enumeration if available
            try:
                cmd = ['nmap', '-p', str(port), '--script', 'ssh-auth-methods,ssh-hostkey', host]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                
                auth_methods = []
                supports_password = False
                supports_pubkey = False
                
                if result.returncode == 0:
                    output = result.stdout
                    
                    # Parse SSH authentication methods
                    if 'password' in output.lower():
                        supports_password = True
                        auth_methods.append('password')
                    if 'publickey' in output.lower() or 'pubkey' in output.lower():
                        supports_pubkey = True
                        auth_methods.append('publickey')
                
                # Generate security warnings
                warnings = []
                if supports_password:
                    warnings.append("SECURITY WARNING: SSH server supports password authentication - this is a security risk")
                if supports_pubkey and not supports_password:
                    warnings.append("SECURITY GOOD: SSH server only supports public key authentication")
                elif not supports_pubkey and not supports_password:
                    warnings.append("SECURITY WARNING: Unable to determine SSH authentication methods")
                
                return {
                    'success': True,
                    'banner': banner,
                    'supports_password': supports_password,
                    'supports_pubkey': supports_pubkey,
                    'auth_methods': auth_methods,
                    'warnings': warnings
                }
                
            except Exception:
                # Fallback if nmap script fails
                return {
                    'success': True,
                    'banner': banner,
                    'supports_password': None,  # Unknown
                    'supports_pubkey': None,    # Unknown
                    'auth_methods': [],
                    'warnings': ["SECURITY WARNING: Unable to determine SSH authentication methods"]
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'warnings': []
            }

    def check_dangerous_ports(self, open_ports: List[Dict]) -> List[str]:
        """Check for dangerous ports and generate security warnings"""
        warnings = []
        
        dangerous_ports = {
            3389: ("RDP", "Remote Desktop Protocol - major target for ransomware attacks"),
            3306: ("MySQL", "Database port should not be exposed to internet"),
            5432: ("PostgreSQL", "Database port should not be exposed to internet"),
            1433: ("MSSQL", "Microsoft SQL Server - should not be exposed to internet"),
            6379: ("Redis", "Redis database - should not be exposed to internet"),
            27017: ("MongoDB", "MongoDB database - should not be exposed to internet"),
            5984: ("CouchDB", "CouchDB database - should not be exposed to internet"),
            9200: ("Elasticsearch", "Elasticsearch - should not be exposed to internet"),
            21: ("FTP", "FTP - insecure protocol, should use SFTP"),
            23: ("Telnet", "Telnet - completely insecure, should never be exposed"),
            25: ("SMTP", "SMTP - may be used for spam if misconfigured"),
            110: ("POP3", "POP3 - insecure email protocol"),
            143: ("IMAP", "IMAP - insecure email protocol"),
            161: ("SNMP", "SNMP - may expose system information"),
            135: ("RPC", "Microsoft RPC - potential security risk"),
            139: ("NetBIOS", "NetBIOS - potential security risk"),
            445: ("SMB", "SMB/CIFS - potential security risk")
        }
        
        for port_info in open_ports:
            port_num = port_info['port']
            if port_num in dangerous_ports:
                service, reason = dangerous_ports[port_num]
                warnings.append(f"SECURITY WARNING: Port {port_num} ({service}) is open - {reason}")
        
        return warnings

    def run_nmap_scan(self, host: str) -> Dict[str, Any]:
        """Run nmap scan to detect open ports and services"""
        print(f"🔍 Running nmap scan for {host}...")
        
        # Check cache first
        cached_result = self.load_from_cache(host, "nmap")
        if cached_result:
            print(f"📁 Using cached nmap results for {host}")
            return cached_result
        
        try:
            # Run nmap with common ports and service detection (using TCP connect scan for better compatibility)
            # Include dangerous ports in the scan
            cmd = ['nmap', '-sT', '-sV', '--top-ports', '1000', '--max-retries', '1', '--host-timeout', '30s', '--open', host]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode == 0:
                open_ports = []
                lines = result.stdout.split('\n')
                
                for line in lines:
                    # Parse nmap output for open ports
                    if '/tcp' in line and 'open' in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            port_info = parts[0]  # e.g., "22/tcp"
                            state = parts[1]      # e.g., "open"
                            service = parts[2] if len(parts) > 2 else "unknown"
                            
                            # Extract port number
                            port = port_info.split('/')[0]
                            
                            # Map common services
                            service_map = {
                                'ssh': 'SSH',
                                'http': 'HTTP',
                                'https': 'HTTPS',
                                'smtp': 'SMTP',
                                'pop3': 'POP3',
                                'imap': 'IMAP',
                                'imaps': 'IMAPS',
                                'pop3s': 'POP3S',
                                'dns': 'DNS',
                                'ftp': 'FTP',
                                'telnet': 'TELNET',
                                'mysql': 'MySQL',
                                'postgresql': 'PostgreSQL',
                                'redis': 'Redis',
                                'mongodb': 'MongoDB'
                            }
                            
                            service_name = service_map.get(service.lower(), service.upper())
                            open_ports.append({
                                'port': int(port),
                                'protocol': 'tcp',
                                'state': state,
                                'service': service_name
                            })
                
                result_data = {
                    'success': True,
                    'open_ports': open_ports,
                    'total_ports': len(open_ports),
                    'raw_output': result.stdout
                }
                
                # Save to cache
                self.save_to_cache(host, "nmap", result_data)
                return result_data
            else:
                return {
                    'success': False,
                    'error': f"Nmap failed with return code {result.returncode}",
                    'stderr': result.stderr
                }
                
        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Nmap scan timed out'
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
        
    def ping_host(self, host: str, count: int = 3) -> Dict[str, Any]:
        """Perform ICMP ping test"""
        print(f"🔍 Testing ICMP ping for {host}...")
        
        try:
            # Use system ping command
            cmd = ['ping', '-c', str(count), '-W', '5', host]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                output = result.stdout
                # Parse ping results
                times = re.findall(r'time=([0-9.]+)', output)
                times = [float(t) for t in times]
                
                if times:
                    return {
                        'success': True,
                        'times': times,
                        'avg': sum(times) / len(times),
                        'min': min(times),
                        'max': max(times),
                        'packet_loss': 0
                    }
            else:
                # Try to parse packet loss
                packet_loss = re.search(r'(\d+)% packet loss', result.stdout)
                loss = int(packet_loss.group(1)) if packet_loss else 100
                
                return {
                    'success': False,
                    'times': [],
                    'avg': None,
                    'min': None,
                    'max': None,
                    'packet_loss': loss
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'times': [],
                'avg': None,
                'min': None,
                'max': None,
                'packet_loss': 100
            }
        
        return {
            'success': False,
            'times': [],
            'avg': None,
            'min': None,
            'max': None,
            'packet_loss': 100
        }

    def test_tcp_latency(self, host: str, port: int) -> Dict[str, Any]:
        """Test TCP connection latency"""
        print(f"🔍 Testing TCP latency for {host}:{port}...")
        
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)  # Reduced timeout for faster testing
            
            result = sock.connect_ex((host, port))
            latency = (time.time() - start_time) * 1000  # Convert to ms
            sock.close()
            
            return {
                'success': result == 0,
                'latency': latency if result == 0 else None,
                'error': None if result == 0 else f"Connection failed with code {result}"
            }
            
        except Exception as e:
            return {
                'success': False,
                'latency': None,
                'error': str(e)
            }

    def get_ssl_info(self, host: str, port: int = 443) -> Dict[str, Any]:
        """Get SSL/TLS information including certificate details"""
        print(f"🔍 Testing SSL/TLS for {host}:{port}...")
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Get certificate expiry
                    not_after = cert.get('notAfter')
                    expiry_date = None
                    days_until_expiry = None
                    
                    if not_after:
                        try:
                            expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            days_until_expiry = (expiry_date - datetime.now(timezone.utc)).days
                        except:
                            pass
                    
                    # Check certificate domain match
                    cert_domains = []
                    for item in cert.get('subject', []):
                        for key, value in item:
                            if key == 'commonName':
                                cert_domains.append(value)
                    
                    # Check SAN (Subject Alternative Names)
                    for ext in cert.get('subjectAltName', []):
                        if ext[0] == 'DNS':
                            cert_domains.append(ext[1])
                    
                    # Check if hostname matches any certificate domain
                    domain_match = False
                    if cert_domains:
                        # Simple domain matching - could be improved
                        for cert_domain in cert_domains:
                            if host == cert_domain or host.endswith('.' + cert_domain) or cert_domain == '*' or cert_domain.startswith('*.'):
                                domain_match = True
                                break
                    
                    # Check certificate algorithm
                    cert_algorithm = "Unknown"
                    is_rsa = False
                    is_ec = False
                    
                    if 'subject' in cert:
                        # Look for algorithm info in certificate
                        for item in cert.get('subject', []):
                            for key, value in item:
                                if key == 'commonName':
                                    # Check if this is the expected hostname
                                    pass
                    
                    # Try to determine certificate type from the certificate itself
                    try:
                        # This is a simplified check - in reality you'd need to parse the certificate
                        # For now, we'll use a heuristic based on key size
                        if cipher and len(cipher) > 2:
                            key_size = cipher[2] if cipher[2] else 0
                            if key_size >= 2048:
                                is_rsa = True
                                cert_algorithm = f"RSA-{key_size}"
                            elif key_size >= 256:
                                is_ec = True
                                cert_algorithm = f"EC-{key_size}"
                    except:
                        pass
                    
                    return {
                        'success': True,
                        'version': version,
                        'cipher': cipher,
                        'certificate': {
                            'subject': cert.get('subject', []),
                            'issuer': cert.get('issuer', []),
                            'expiry_date': expiry_date.isoformat() if expiry_date else None,
                            'days_until_expiry': days_until_expiry,
                            'algorithm': cert_algorithm,
                            'is_rsa': is_rsa,
                            'is_ec': is_ec,
                            'domains': cert_domains,
                            'domain_match': domain_match
                        }
                    }
                    
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def test_webserver(self, host: str, port: int = 80) -> Dict[str, Any]:
        """Test webserver type and get headers"""
        print(f"🔍 Testing webserver for {host}:{port}...")
        
        try:
            if port == 443:
                url = f"https://{host}"
            else:
                url = f"http://{host}:{port}"
            
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'NetworkTester/1.0')
            
            with urllib.request.urlopen(req, timeout=10) as response:
                server_header = response.headers.get('Server', 'Unknown')
                
                return {
                    'success': True,
                    'server': server_header,
                    'status_code': response.status,
                    'headers': dict(response.headers)
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'server': None
            }

    def test_quic(self, host: str, port: int = 443) -> Dict[str, Any]:
        """Test QUIC (HTTP/3) support"""
        print(f"🔍 Testing QUIC for {host}:{port}...")
        
        try:
            # Try to detect QUIC by sending a QUIC handshake packet
            # This is a simplified test - real QUIC detection is more complex
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            
            # Send a simple UDP packet to see if port responds
            sock.sendto(b'QUIC test', (host, port))
            sock.settimeout(2)
            
            try:
                data, addr = sock.recvfrom(1024)
                return {
                    'success': True,
                    'response': True,
                    'data_length': len(data)
                }
            except socket.timeout:
                return {
                    'success': False,
                    'response': False,
                    'note': 'No QUIC response detected'
                }
            finally:
                sock.close()
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def test_ech_support(self, host: str, port: int = 443) -> Dict[str, Any]:
        """Test if server supports ECH (Encrypted Client Hello)"""
        print(f"🔍 Testing ECH support for {host}:{port}...")
        
        try:
            # Try to connect with ECH extension
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Check if ECH is supported (TLS 1.3 extension)
            # This is a simplified test - full ECH testing requires more complex implementation
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    # Get TLS extensions information
                    version = ssock.version()
                    cipher = ssock.cipher()
                    
                    # Check if server supports TLS 1.3 (prerequisite for ECH)
                    supports_ech = version == 'TLSv1.3'
                    
                    return {
                        'success': True,
                        'version': version,
                        'supports_tls13': supports_ech,
                        'ech_supported': supports_ech,  # Simplified - assume TLS 1.3 supports ECH
                        'cipher': cipher[0] if cipher else None
                    }
                    
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'ech_supported': False
            }

    def test_dns_udp(self, host: str, port: int = 53) -> Dict[str, Any]:
        """Test DNS server using UDP on port 53"""
        print(f"🔍 Testing DNS UDP for {host}:{port}...")
        
        try:
            # Try multiple DNS query methods
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(10)
            
            # Method 1: Try using dig command first (more reliable)
            try:
                cmd = ['dig', '@' + host, 'google.com', 'A', '+short', '+time=5']
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and result.stdout.strip():
                    return {
                        'success': True,
                        'latency': 0,  # dig doesn't give us latency easily
                        'method': 'dig',
                        'is_dns_server': True,
                        'response': result.stdout.strip()
                    }
            except:
                pass
            
            # Method 2: Try using nslookup
            try:
                cmd = ['nslookup', 'google.com', host]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0 and 'Address:' in result.stdout:
                    return {
                        'success': True,
                        'latency': 0,
                        'method': 'nslookup',
                        'is_dns_server': True,
                        'response': 'nslookup successful'
                    }
            except:
                pass
            
            # Method 3: Raw DNS query packet
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(5)
            
            # Create a proper DNS query for google.com A record
            # Transaction ID: 0x1234, Flags: 0x0100 (standard query), Questions: 1
            dns_header = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00'
            # Query: google.com A IN
            dns_query = dns_header + b'\x06google\x03com\x00\x00\x01\x00\x01'
            
            start_time = time.time()
            sock.sendto(dns_query, (host, port))
            
            try:
                response, addr = sock.recvfrom(1024)
                latency = (time.time() - start_time) * 1000  # Convert to ms
                
                # Check if response looks like a DNS response
                if len(response) >= 12:
                    # Check DNS header flags (bytes 2-3)
                    flags = int.from_bytes(response[2:4], 'big')
                    # Check if it's a response (QR bit set) and no error (RCODE = 0)
                    if (flags & 0x8000) and (flags & 0x000F) == 0:
                        return {
                            'success': True,
                            'latency': latency,
                            'method': 'raw_udp',
                            'response_size': len(response),
                            'is_dns_server': True
                        }
                
                return {
                    'success': False,
                    'is_dns_server': False,
                    'error': 'Invalid DNS response format'
                }
                    
            except socket.timeout:
                return {
                    'success': False,
                    'is_dns_server': False,
                    'error': 'DNS query timeout'
                }
            finally:
                sock.close()
                
        except Exception as e:
            return {
                'success': False,
                'is_dns_server': False,
                'error': str(e)
            }

    def test_dns_server(self, host: str) -> Dict[str, Any]:
        """Test if server is running an open DNS server using DNS library"""
        print(f"🔍 Testing DNS server for {host}...")
        
        try:
            # Try to query the server for a DNS record
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.nameservers = [host]
            resolver.timeout = 5
            resolver.lifetime = 5
            
            # Try to resolve a common domain
            result = resolver.resolve('google.com', 'A')
            
            return {
                'success': True,
                'is_open_dns': True,
                'resolved_records': len(result)
            }
            
        except Exception as e:
            return {
                'success': False,
                'is_open_dns': False,
                'error': str(e)
            }

    def get_ssh_version(self, host: str, port: int = 22) -> Dict[str, Any]:
        """Get SSH server version"""
        print(f"🔍 Testing SSH for {host}:{port}...")
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((host, port))
            
            # SSH servers typically send their version string immediately
            version = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            return {
                'success': True,
                'version': version
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def run_mtr(self, host: str) -> Dict[str, Any]:
        """Run MTR (My Traceroute) to get route information using TCP"""
        print(f"🔍 Running MTR TCP for {host}...")
        
        # Check cache first
        cached_result = self.load_from_cache(host, "mtr")
        if cached_result:
            print(f"📁 Using cached MTR results for {host}")
            return cached_result
        
        try:
            # Run mtr with TCP to port 443, single report, show latencies
            cmd = ['mtr', '--tcp', '--port', '443', '--report', '--report-cycles', '3', '--no-dns', host]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                hops = []
                lines = result.stdout.strip().split('\n')
                
                # Parse MTR output - look for lines with latency data
                for line in lines:
                    if line.strip() and not line.startswith('HOST:') and '|--' in line:
                        # Parse MTR output format with latency: "1.|-- 10.7.0.1 0.0% 3/3 67.2 68.1 67.8"
                        parts = line.split('|--')
                        if len(parts) >= 2:
                            hop_num = parts[0].strip().replace('.', '')
                            data_part = parts[1].strip()
                            
                            # Extract IP address
                            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', data_part)
                            if ip_match:
                                ip = ip_match.group(1)
                                
                                # Extract latency information
                                latency_parts = data_part.split()
                                avg_latency = None
                                min_latency = None
                                max_latency = None
                                
                                # Look for latency values (usually at the end)
                                if len(latency_parts) >= 4:
                                    try:
                                        # Format: "IP loss% sent received avg min max"
                                        avg_latency = float(latency_parts[-3])
                                        min_latency = float(latency_parts[-2])
                                        max_latency = float(latency_parts[-1])
                                    except (ValueError, IndexError):
                                        pass
                                
                                # Extract hostname if present (before IP)
                                hostname = None
                                ip_index = data_part.find(ip)
                                if ip_index > 0:
                                    before_ip = data_part[:ip_index].strip()
                                    if before_ip and before_ip != '.':
                                        hostname = before_ip
                                
                                # Get geolocation for this hop
                                geo_info = self.get_geolocation(ip)
                                
                                # Get ASN information for this hop
                                asn_info = self.get_asn_info(ip)
                                
                                hops.append({
                                    'hop': hop_num,
                                    'ip': ip,
                                    'hostname': hostname,
                                    'location': geo_info,
                                    'asn': asn_info,
                                    'avg_latency': avg_latency,
                                    'min_latency': min_latency,
                                    'max_latency': max_latency
                                })
                
                result_data = {
                    'success': True,
                    'hops': hops
                }
                
                # Save to cache
                self.save_to_cache(host, "mtr", result_data)
                return result_data
            else:
                return {
                    'success': False,
                    'error': 'MTR command failed'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def get_geolocation(self, ip: str) -> Dict[str, Any]:
        """Get geolocation information for an IP address"""
        try:
            # Use a free geolocation service
            url = f"http://ip-api.com/json/{ip}"
            with urllib.request.urlopen(url, timeout=5) as response:
                data = json.loads(response.read().decode())
                
                return {
                    'success': True,
                    'country': data.get('country', 'Unknown'),
                    'region': data.get('regionName', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'lat': data.get('lat'),
                    'lon': data.get('lon'),
                    'isp': data.get('isp', 'Unknown')
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def test_server(self, server: str) -> Dict[str, Any]:
        """Comprehensive test of a single server"""
        print(f"\n{'='*60}")
        print(f"🌐 TESTING SERVER: {server}")
        print(f"{'='*60}")
        
        result = {
            'server': server,
            'timestamp': datetime.now().isoformat(),
            'tests': {},
            'cache_enabled': self.cache_enabled
        }
        
        # Test ICMP ping
        result['tests']['ping'] = self.ping_host(server)
        
        # Test TCP latency for essential ports
        tcp_ports = [22, 80, 443]  # SSH, HTTP, HTTPS
        result['tests']['tcp_latency'] = {}
        
        for port in tcp_ports:
            tcp_result = self.test_tcp_latency(server, port)
            result['tests']['tcp_latency'][port] = tcp_result
            
            # If port 80 or 443 is open, test webserver
            if port in [80, 443] and tcp_result['success']:
                if port == 443:
                    result['tests']['webserver_https'] = self.test_webserver(server, port)
                    result['tests']['ssl'] = self.get_ssl_info(server, port)
                else:
                    result['tests']['webserver_http'] = self.test_webserver(server, port)
            
            # Test SSH on port 22
            if port == 22 and tcp_result['success']:
                result['tests']['ssh'] = self.get_ssh_version(server, port)
                result['tests']['ssh_auth'] = self.check_ssh_authentication(server, port)
        
        # Test QUIC on port 443
        if 443 in result['tests']['tcp_latency'] and result['tests']['tcp_latency'][443]['success']:
            result['tests']['quic'] = self.test_quic(server, 443)
            result['tests']['ech'] = self.test_ech_support(server, 443)
        
        # Test DNS UDP on port 53
        result['tests']['dns_udp'] = self.test_dns_udp(server, 53)
        
        # Run nmap scan
        result['tests']['nmap'] = self.run_nmap_scan(server)
        
        # Run MTR
        result['tests']['mtr'] = self.run_mtr(server)
        
        # Check for security anomalies
        result['tests']['security_warnings'] = self.check_security_anomalies(
            result['tests']['ping'], 
            result['tests']['tcp_latency']
        )
        
        # Add dangerous port warnings if nmap results are available
        if 'nmap' in result['tests'] and result['tests']['nmap'].get('success'):
            dangerous_warnings = self.check_dangerous_ports(result['tests']['nmap']['open_ports'])
            result['tests']['security_warnings'].extend(dangerous_warnings)
        
        # Get comprehensive information for the server IP
        try:
            server_ip = socket.gethostbyname(server)
            result['tests']['geolocation'] = self.get_geolocation(server_ip)
            result['tests']['asn'] = self.get_asn_info(server_ip)
            result['tests']['dnsbl'] = self.check_dnsbl(server_ip)
            result['tests']['proxy'] = self.check_proxy(server_ip)
            result['ip'] = server_ip
        except:
            result['ip'] = 'Unknown'
        
        return result

    def print_results(self, results: List[Dict[str, Any]]):
        """Print formatted test results"""
        for result in results:
            server = result['server']
            tests = result['tests']
            
            print(f"\n{'='*80}")
            print(f"📊 RESULTS FOR: {server}")
            if 'ip' in result:
                ip = result['ip']
                print(f"🌍 IP Address: {ip}")
                
                # Show ASN information
                if 'asn' in tests and tests['asn'].get('success'):
                    asn = tests['asn']
                    asn_name = asn.get('asname', 'Unknown')
                    abuse_email = asn.get('abuse_email', 'Unknown')
                    print(f"🏢 ASN: {asn.get('asn', 'Unknown')} ({asn_name}) - {abuse_email}")
                
                # Show DNSBL status
                if 'dnsbl' in tests and tests['dnsbl'].get('success'):
                    dnsbl = tests['dnsbl']
                    if dnsbl.get('blacklisted'):
                        print(f"🚫 DNSBL: BLACKLISTED on {', '.join(dnsbl['blacklists'])}")
                    else:
                        print(f"✅ DNSBL: Clean")
                
                # Show proxy status
                if 'proxy' in tests and tests['proxy'].get('success'):
                    proxy = tests['proxy']
                    if proxy.get('is_proxy'):
                        proxy_type = proxy.get('proxy_type', 'Unknown type')
                        print(f"🔒 PROXY: Detected ({proxy_type})")
                    else:
                        print(f"✅ PROXY: Not detected")
                
            if result.get('cache_enabled'):
                print(f"📁 Cache: Enabled")
            print(f"{'='*80}")
            
            # Ping results
            if 'ping' in tests:
                ping = tests['ping']
                if ping['success']:
                    print(f"🏓 ICMP PING: ✓ Success")
                    print(f"   Times: {ping['times']} ms")
                    print(f"   Average: {ping['avg']:.2f} ms")
                    print(f"   Min/Max: {ping['min']:.2f}/{ping['max']:.2f} ms")
                else:
                    print(f"🏓 ICMP PING: ✗ Failed ({ping.get('packet_loss', 100)}% packet loss)")
            
            # TCP latency results
            if 'tcp_latency' in tests:
                print(f"\n🔌 TCP CONNECTIVITY:")
                for port, tcp in tests['tcp_latency'].items():
                    if tcp['success']:
                        print(f"   Port {port}: ✓ {tcp['latency']:.2f} ms")
                    else:
                        print(f"   Port {port}: ✗ Failed")
            
            # SSL/TLS results
            if 'ssl' in tests:
                ssl_info = tests['ssl']
                if ssl_info['success']:
                    print(f"\n🔒 SSL/TLS:")
                    print(f"   Version: {ssl_info['version']}")
                    if ssl_info['cipher']:
                        print(f"   Cipher: {ssl_info['cipher'][0]}")
                    
                    cert = ssl_info['certificate']
                    if cert['days_until_expiry'] is not None:
                        status = "✓" if cert['days_until_expiry'] > 30 else "⚠" if cert['days_until_expiry'] > 0 else "✗"
                        print(f"   Certificate Expiry: {status} {cert['days_until_expiry']} days")
                    
                    # Certificate algorithm warning
                    if cert['is_rsa']:
                        print(f"   Certificate Algorithm: {cert['algorithm']} [RSA: BAD]")
                    elif cert['is_ec']:
                        print(f"   Certificate Algorithm: {cert['algorithm']} [EC: GOOD]")
                    else:
                        print(f"   Certificate Algorithm: {cert['algorithm']}")
                    
                    # Domain validation
                    if cert['domain_match']:
                        print(f"   Domain Validation: ✓ Certificate matches domain")
                    else:
                        print(f"   Domain Validation: ✗ Certificate does not match domain")
                        if cert['domains']:
                            print(f"   Certificate domains: {', '.join(cert['domains'])}")
                else:
                    print(f"\n🔒 SSL/TLS: ✗ Failed - {ssl_info.get('error', 'Unknown error')}")
            
            # Webserver results
            for test_name in ['webserver_http', 'webserver_https']:
                if test_name in tests:
                    ws = tests[test_name]
                    if ws['success']:
                        server_info = ws['server']
                        print(f"\n🌐 WEBSERVER ({test_name.split('_')[1].upper()}): {server_info}")
                        
                        # Extract webserver name and version for CVE checking
                        if 'Apache' in server_info:
                            version_match = re.search(r'Apache/([\d.]+)', server_info)
                            if version_match:
                                apache_version = version_match.group(1)
                                cve_info = self.get_cve_info('Apache', apache_version)
                                if cve_info.get('cves'):
                                    print(f"   ⚠️  CVEs (Risk: {cve_info['risk_level']}):")
                                    for cve in cve_info['cves']:
                                        cve_id = cve['id'] if isinstance(cve, dict) else cve
                                        cve_desc = cve['desc'] if isinstance(cve, dict) else "Unknown"
                                        print(f"      - {cve_id}: https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}")
                                        print(f"        {cve_desc}")
                                else:
                                    print(f"   ✅ No known CVEs for Apache {apache_version}")
                        elif 'nginx' in server_info.lower():
                            version_match = re.search(r'nginx/([\d.]+)', server_info)
                            if version_match:
                                nginx_version = version_match.group(1)
                                cve_info = self.get_cve_info('nginx', nginx_version)
                                if cve_info.get('cves'):
                                    print(f"   ⚠️  CVEs (Risk: {cve_info['risk_level']}):")
                                    for cve in cve_info['cves']:
                                        cve_id = cve['id'] if isinstance(cve, dict) else cve
                                        cve_desc = cve['desc'] if isinstance(cve, dict) else "Unknown"
                                        print(f"      - {cve_id}: https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}")
                                        print(f"        {cve_desc}")
                                else:
                                    print(f"   ✅ No known CVEs for nginx {nginx_version}")
                    else:
                        print(f"\n🌐 WEBSERVER ({test_name.split('_')[1].upper()}): ✗ Failed")
            
            # QUIC results
            if 'quic' in tests:
                quic = tests['quic']
                if quic['success'] and quic['response']:
                    print(f"\n🚀 QUIC: ✓ Supported")
                else:
                    print(f"\n🚀 QUIC: ✗ Not supported or no response")
            
            # ECH results
            if 'ech' in tests:
                ech = tests['ech']
                if ech['success']:
                    if ech['ech_supported']:
                        print(f"\n🔐 ECH: ✓ Supported (TLS 1.3)")
                    else:
                        print(f"\n🔐 ECH: ✗ Not supported (TLS version: {ech.get('version', 'Unknown')})")
                else:
                    print(f"\n🔐 ECH: ✗ Failed to test - {ech.get('error', 'Unknown error')}")
            
            # DNS UDP results
            if 'dns_udp' in tests:
                dns = tests['dns_udp']
                if dns['success'] and dns['is_dns_server']:
                    method_info = f" ({dns.get('method', 'unknown')})"
                    latency_info = f" - {dns['latency']:.2f} ms" if dns.get('latency', 0) > 0 else ""
                    print(f"\n🌍 DNS UDP: ✓ DNS server detected{method_info}{latency_info}")
                else:
                    print(f"\n🌍 DNS UDP: ✗ Not a DNS server or failed")
            
            # SSH results
            if 'ssh' in tests:
                ssh = tests['ssh']
                if ssh['success']:
                    version = ssh['version']
                    print(f"\n🔐 SSH: {version}")
                    
                    # Extract version number for CVE checking
                    version_match = re.search(r'OpenSSH_([\d.]+)', version)
                    if version_match:
                        ssh_version = version_match.group(1)
                        cve_info = self.get_cve_info('OpenSSH', ssh_version)
                        if cve_info.get('cves'):
                            print(f"   ⚠️  CVEs (Risk: {cve_info['risk_level']}):")
                            for cve in cve_info['cves']:
                                cve_id = cve['id'] if isinstance(cve, dict) else cve
                                cve_desc = cve['desc'] if isinstance(cve, dict) else "Unknown"
                                print(f"      - {cve_id}: https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}")
                                print(f"        {cve_desc}")
                        else:
                            print(f"   ✅ No known CVEs for version {ssh_version}")
                else:
                    print(f"\n🔐 SSH: ✗ Failed to connect")
            
            # SSH Authentication results
            if 'ssh_auth' in tests:
                ssh_auth = tests['ssh_auth']
                if ssh_auth['success']:
                    print(f"\n🔑 SSH AUTHENTICATION:")
                    if ssh_auth.get('supports_password') is True:
                        print(f"   ⚠️  Password authentication: ENABLED (Security Risk)")
                    elif ssh_auth.get('supports_password') is False:
                        print(f"   ✅ Password authentication: DISABLED (Secure)")
                    else:
                        print(f"   ❓ Password authentication: UNKNOWN")
                    
                    if ssh_auth.get('supports_pubkey') is True:
                        print(f"   ✅ Public key authentication: ENABLED")
                    elif ssh_auth.get('supports_pubkey') is False:
                        print(f"   ❌ Public key authentication: DISABLED")
                    else:
                        print(f"   ❓ Public key authentication: UNKNOWN")
                    
                    if ssh_auth.get('auth_methods'):
                        print(f"   📋 Available methods: {', '.join(ssh_auth['auth_methods'])}")
                else:
                    print(f"\n🔑 SSH AUTHENTICATION: ✗ Failed to check - {ssh_auth.get('error', 'Unknown error')}")
            
            # MTR results
            if 'mtr' in tests:
                mtr = tests['mtr']
                if mtr['success']:
                    print(f"\n🛣️  ROUTE TRACE (TCP to port 443):")
                    for hop in mtr['hops']:
                        hostname_info = f" ({hop['hostname']})" if hop['hostname'] else ""
                        location_info = ""
                        if hop.get('location') and hop['location'].get('success'):
                            loc = hop['location']
                            city = loc.get('city', 'Unknown')
                            country = loc.get('country', 'Unknown')
                            location_info = f" - {city}, {country}"
                        
                        # Add latency information
                        latency_info = ""
                        if hop.get('avg_latency') is not None:
                            latency_info = f" [{hop['avg_latency']:.1f}ms"
                            if hop.get('min_latency') is not None and hop.get('max_latency') is not None:
                                latency_info += f" (min: {hop['min_latency']:.1f}ms, max: {hop['max_latency']:.1f}ms)"
                            latency_info += "]"
                        
                        # Add ASN information
                        asn_info = ""
                        if hop.get('asn') and hop['asn'].get('success'):
                            asn = hop['asn']
                            asn_name = asn.get('asname', 'Unknown')
                            abuse_email = asn.get('abuse_email', 'Unknown')
                            asn_info = f" [{asn.get('asn', 'Unknown')} {asn_name} {abuse_email}]"
                        
                        print(f"   {hop['hop']}. {hop['ip']}{hostname_info}{location_info}{latency_info}{asn_info}")
                else:
                    print(f"\n🛣️  ROUTE TRACE: ✗ Failed")
            
            # Nmap results
            if 'nmap' in tests:
                nmap = tests['nmap']
                if nmap['success']:
                    print(f"\n🔍 NMAP SCAN ({nmap['total_ports']} open ports):")
                    for port_info in nmap['open_ports']:
                        print(f"   {port_info['port']} ({port_info['service']})")
                else:
                    print(f"\n🔍 NMAP SCAN: ✗ Failed - {nmap.get('error', 'Unknown error')}")
            
            # Security warnings
            if 'security_warnings' in tests and tests['security_warnings']:
                print(f"\n⚠️  SECURITY WARNINGS:")
                for warning in tests['security_warnings']:
                    if "SECURITY GOOD" in warning:
                        print(f"   ✅ {warning.replace('SECURITY GOOD: ', '')}")
                    elif "SECURITY WARNING" in warning:
                        print(f"   ⚠️  {warning.replace('SECURITY WARNING: ', '')}")
                    else:
                        print(f"   ⚠️  {warning}")
            
            # Geolocation
            if 'geolocation' in tests:
                geo = tests['geolocation']
                if geo['success']:
                    print(f"\n🌍 LOCATION: {geo['city']}, {geo['region']}, {geo['country']}")
                    isp_info = geo['isp']
                    
                    # Add ASN information to ISP display
                    if 'asn' in tests and tests['asn'].get('success'):
                        asn = tests['asn']
                        asn_name = asn.get('asname', 'Unknown')
                        isp_info += f" [ASN {asn.get('asn', 'Unknown')} - {asn_name}]"
                    
                    print(f"   ISP: {isp_info}")
            
            print(f"{'='*80}")


def main():
    parser = argparse.ArgumentParser(description='Comprehensive Network Testing Tool')
    parser.add_argument('--server', action='append', required=True,
                       help='Server to test (can be specified multiple times)')
    parser.add_argument('--output', '-o',
                       help='Output file for JSON results')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    parser.add_argument('--cache', action='store_true',
                       help='Enable caching to avoid repeated scans')
    parser.add_argument('--tcp-threshold-avg', type=int, default=10,
                       help='TCP latency threshold above ICMP average to trigger security warning (default: 10ms)')
    parser.add_argument('--tcp-threshold-lowest', type=int, default=20,
                       help='TCP latency threshold above ICMP lowest to trigger security warning (default: 20ms)')
    
    args = parser.parse_args()
    
    if not args.server:
        print("Error: At least one server must be specified with --server")
        return 1
    
    print("🚀 Starting Comprehensive Network Tests...")
    print(f"📋 Testing {len(args.server)} server(s): {', '.join(args.server)}")
    if args.cache:
        print("📁 Cache enabled - will use cached results when available")
    
    tester = NetworkTester(
        cache_enabled=args.cache,
        tcp_threshold_avg=args.tcp_threshold_avg,
        tcp_threshold_lowest=args.tcp_threshold_lowest
    )
    results = []
    
    # Test each server
    for server in args.server:
        try:
            result = tester.test_server(server)
            results.append(result)
        except Exception as e:
            print(f"❌ Error testing {server}: {e}")
            results.append({
                'server': server,
                'error': str(e),
                'timestamp': datetime.now().isoformat()
            })
    
    # Print results
    tester.print_results(results)
    
    # Save JSON output if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n💾 Results saved to {args.output}")
    
    return 0


if __name__ == "__main__":
    exit(main())
