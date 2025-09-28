# Network Testing Suite

A comprehensive Python suite for network testing and security analysis. Includes two main tools:

1. **ping.py** - Advanced ping monitoring tool with ICMP support
2. **sec-check.py** - Comprehensive network security testing tool

## Overview

### ping.py
Advanced ping monitoring tool that continuously pings multiple servers and provides detailed statistics including lowest latency, averages, and performance tracking.

### sec-check.py  
Comprehensive network security testing tool that performs:
- ICMP ping testing with latency analysis
- TCP latency testing for essential ports
- SSL/TLS analysis with certificate validation
- SSH security assessment
- Port scanning with service detection
- CVE vulnerability checking
- DNSBL and proxy detection
- ASN information lookup
- Route tracing with geolocation
- Security warnings and threat intelligence

## Features

- **ICMP Ping Testing**: 3 pings per server with latency statistics
- **TCP Latency Testing**: Tests essential ports (22 SSH, 80 HTTP, 443 HTTPS)
- **SSL/TLS Analysis**: 
  - TLS version and cipher suite detection
  - Certificate expiry checking
  - RSA vs EC certificate algorithm detection with security warnings
  - Domain validation (checks if certificate matches requested domain)
- **Webserver Detection**: Identifies server type (Apache, Nginx, etc.)
- **QUIC Testing**: Tests for HTTP/3 support on port 443 UDP
- **DNS UDP Testing**: Tests for DNS server on port 53 using UDP
- **SSH Security Analysis**:
  - SSH version detection
  - Authentication method detection (password vs public key)
  - Security warnings for password authentication
- **Port Scanning**: Comprehensive nmap scan to detect all open ports
- **Security Warnings**:
  - TCP latency anomalies (potential DPI/traffic shaping)
  - Dangerous port detection (RDP, databases, insecure protocols)
  - SSH authentication security assessment
- **MTR Route Tracing**: Shows network path with latencies and geolocation
- **Caching System**: Avoids repeated scans with intelligent caching
- **Geolocation**: Shows server location and ISP information

## Installation

### Prerequisites

**System Requirements:**
- Python 3.6 or higher
- Linux/macOS (Windows support limited)
- Root/administrator access for some features

**System Tools Required:**
- `ping` command (usually pre-installed)
- `mtr` (My Traceroute)
- `nmap` (Network mapper)
- `dig` (DNS lookup tool)

### Step 1: Install System Dependencies

**For Arch/Manjaro:**
```bash
sudo pacman -S mtr nmap bind-tools
```

**For Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install mtr-tiny nmap dnsutils
```

**For CentOS/RHEL/Fedora:**
```bash
sudo yum install mtr nmap bind-utils
# or for newer versions:
sudo dnf install mtr nmap bind-utils
```

**For macOS:**
```bash
brew install mtr nmap bind
```

### Step 2: Install Python Dependencies

**Using pip:**
```bash
pip install -r requirements.txt
```

**Using uv (recommended):**
```bash
uv pip install -r requirements.txt
```

**Manual installation:**
```bash
pip install dnspython>=2.3.0 requests>=2.25.0
```

### Step 3: Verify Installation

Test that all tools are working:
```bash
# Check ping
ping -c 1 google.com

# Check mtr
mtr --version

# Check nmap
nmap --version

# Check dig
dig google.com

# Test Python scripts
python3 ping.py --help
python3 sec-check.py --help
```

### Step 4: Set Up Permissions

Some features may require elevated permissions:
```bash
# For ICMP ping (Linux)
sudo setcap cap_net_raw+ep $(which python3)

# For nmap (if not run as root)
sudo setcap cap_net_raw,cap_net_admin+ep $(which nmap)
```

## Usage

### ping.py - Advanced Ping Monitoring

**Basic Usage:**
```bash
python3 ping.py --list ./server_lists/list.txt
```

**Custom Configuration:**
```bash
python3 ping.py --list ./server_lists/list.txt --max_remember_average 50
```

### sec-check.py - Security Testing Tool

**Basic Usage:**
```bash
python3 sec-check.py --server "example.com"
```

**Multiple Servers:**
```bash
python3 sec-check.py --server "cyphrix.org" --server "server2.cyphrix.org"
```

**Save Results to JSON:**
```bash
python3 sec-check.py --server "example.com" --output results.json
```

**Enable Caching (Recommended):**
```bash
python3 sec-check.py --server "example.com" --cache
```

**Custom Security Thresholds:**
```bash
python3 sec-check.py --server "example.com" --tcp-threshold-avg 15 --tcp-threshold-lowest 25
```

**Verbose Output:**
```bash
python3 sec-check.py --server "example.com" --verbose
```

## Example Output

```
================================================================================
📊 RESULTS FOR: google.com
🌍 IP Address: 142.250.191.14
================================================================================
🏓 ICMP PING: ✓ Success
   Times: [12.3, 11.8, 12.1] ms
   Average: 12.07 ms
   Min/Max: 11.8/12.3 ms

🔌 TCP CONNECTIVITY:
   Port 22: ✗ Failed
   Port 80: ✓ 45.2 ms
   Port 443: ✓ 43.8 ms
   Port 53: ✗ Failed

🔒 SSL/TLS:
   Version: TLSv1.3
   Cipher: TLS_AES_256_GCM_SHA384
   Certificate Expiry: ✓ 87 days
   Certificate Algorithm: EC-256 [EC: GOOD]

🌐 WEBSERVER (HTTPS): gws

🚀 QUIC: ✓ Supported

🌍 DNS UDP: ✓ DNS server detected (75.94 ms)

🔐 SSH: SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
   ⚠️  CVEs (Risk: Medium):
      - CVE-2014-2532: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-2532
        Buffer overflow in roaming code
      - CVE-2014-2653: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-2653
        Multiple vulnerabilities in roaming code

🔑 SSH AUTHENTICATION:
   ⚠️  Password authentication: ENABLED (Security Risk)
   ✅ Public key authentication: ENABLED
   📋 Available methods: password, publickey

🔍 NMAP SCAN (3 open ports):
   22 (SSH)
   80 (HTTP)
   443 (SSL/HTTP)

🛣️  ROUTE TRACE (TCP to port 443):
   1. 10.7.0.1 - Unknown, Unknown [63.4ms (min: 64.0ms, max: 0.3ms)]
   2. 147.135.45.252 - Hillsboro, United States [64.3ms (min: 66.8ms, max: 1.3ms)]
   3. 142.250.191.14 - Mountain View, United States [73.4ms (min: 73.6ms, max: 0.1ms)]

⚠️  SECURITY WARNINGS:
   ⚠️  Port 3389 (RDP) is open - Remote Desktop Protocol - major target for ransomware attacks
   ⚠️  Port 3306 (MySQL) is open - Database port should not be exposed to internet

🌍 LOCATION: Mountain View, California, United States
   ISP: Google LLC [ASN AS15169 - Google LLC]
================================================================================
```

## Security Notes

- **RSA Certificates**: Marked as `[RSA: BAD]` due to security concerns with older RSA algorithms
- **EC Certificates**: Marked as `[EC: GOOD]` for modern elliptic curve cryptography
- **Certificate Expiry**: Shows days until expiration with status indicators
- **SSH Authentication**: Warns about password authentication, recommends public key only
- **Dangerous Ports**: Flags high-risk ports like RDP (3389), databases (3306, 5432), and insecure protocols
- **Traffic Analysis**: Detects potential DPI or traffic shaping based on latency anomalies

## Requirements

- Python 3.6+
- dnspython (for DNS testing)
- System tools: ping, mtr
- Internet connection for geolocation and external DNS queries

## Troubleshooting

1. **Permission denied for ping**: Run with sudo or ensure your user has ping privileges
2. **MTR not found**: Install mtr package for your distribution
3. **DNS resolution fails**: Check your DNS settings and internet connectivity
4. **SSL errors**: Some servers may have strict SSL policies that block automated testing

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This software is provided for educational and testing purposes only. Users are responsible for ensuring they have proper authorization before testing any network infrastructure. The authors are not responsible for any misuse of this software.
