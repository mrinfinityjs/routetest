#!/usr/bin/env python3
"""
Pingify - Advanced ping monitoring tool with ICMP support
"""

import threading
import math
import subprocess
import time
import argparse
import sys
import os
from collections import deque
from typing import Dict, List, Tuple, Optional


def ping_ip(ip_address: str, timeout: int = 3) -> Optional[float]:
    """
    Send a single ICMP ping to an IP address and return the latency in milliseconds.
    
    Args:
        ip_address: The IP address to ping (without port)
        timeout: Timeout in seconds for the ping
        
    Returns:
        Latency in milliseconds if successful, None if failed
    """
    try:
        # Use ping command with appropriate flags for different OS
        if os.name == 'nt':  # Windows
            cmd = ['ping', '-n', '1', '-w', str(timeout * 1000), ip_address]
        else:  # Linux/Unix/macOS
            cmd = ['ping', '-c', '1', '-W', str(timeout), ip_address]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 2)
        
        if result.returncode == 0:
            # Parse the output to extract latency
            output = result.stdout
            if 'time=' in output:
                # Extract time value (format varies by OS)
                for line in output.split('\n'):
                    if 'time=' in line:
                        # Extract time value
                        time_part = line.split('time=')[1].split()[0]
                        # Remove 'ms' if present
                        time_part = time_part.replace('ms', '')
                        try:
                            return float(time_part)
                        except ValueError:
                            continue
        return None
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, ValueError):
        return None


def update_latency(servers_data: dict, lock: threading.RLock, server_addr: str, new_latency: float, max_remember: int = 100):
    """
    Records a new latency measurement for a given server and maintains history.
    
    Args:
        servers_data: The dictionary holding all server latency data.
        lock: The threading lock to ensure thread safety.
        server_addr: The address of the server to update.
        new_latency: The new latency measurement (in milliseconds).
        max_remember: Maximum number of ping results to remember per server.
    """
    with lock:
        if server_addr not in servers_data:
            # First time seeing this server, create a new entry.
            servers_data[server_addr] = {
                'lowest': new_latency,
                'latest': new_latency,
                'history': deque([new_latency], maxlen=max_remember)
            }
        else:
            # Server exists, so update its stats.
            stats = servers_data[server_addr]
            stats['latest'] = new_latency
            stats['history'].append(new_latency)
            
            # If the new latency is better, update the lowest record.
            if new_latency < stats['lowest']:
                stats['lowest'] = new_latency


def lowest_latency_server(servers_data: dict, lock: threading.RLock) -> Tuple[Optional[str], Optional[float]]:
    """
    Finds and returns the server with the overall lowest latency.
    
    Args:
        servers_data: The dictionary holding all server latency data.
        lock: The threading lock to ensure thread safety.
        
    Returns:
        A tuple of (server_address, lowest_latency) or (None, None) if empty.
    """
    with lock:
        if not servers_data:
            return None, None  # No servers being tracked.
        
        # Use Python's built-in min() function with a custom key
        # to find the server with the lowest latency efficiently.
        best_server_addr, best_stats = min(
            servers_data.items(),
            key=lambda item: item[1]['lowest']
        )
        
        return best_server_addr, best_stats['lowest']


def average_latency_lowest(servers_data: dict, lock: threading.RLock, how_many: int = 3) -> Tuple[Optional[str], Optional[float]]:
    """
    Finds the server with the lowest average latency using the last few recorded pings.
    
    Args:
        servers_data: The dictionary holding all server latency data.
        lock: The threading lock to ensure thread safety.
        how_many: Number of recent pings to average (default 3).
        
    Returns:
        A tuple of (server_address, average_latency) or (None, None) if no data.
    """
    with lock:
        if not servers_data:
            return None, None
        
        best_server = None
        best_average = float('inf')
        
        for server_addr, stats in servers_data.items():
            history = list(stats['history'])
            
            # Need at least how_many pings to calculate average
            if len(history) >= how_many:
                # Get the last how_many pings
                recent_pings = history[-how_many:]
                average = sum(recent_pings) / len(recent_pings)
                
                if average < best_average:
                    best_average = average
                    best_server = server_addr
        
        return best_server, best_average if best_server else None


def load_ip_list(file_path: str) -> List[str]:
    """
    Load IP addresses from a text file.
    
    Args:
        file_path: Path to the file containing IP addresses (one per line).
        
    Returns:
        List of IP addresses.
    """
    try:
        with open(file_path, 'r') as f:
            ips = []
            for line in f:
                ip = line.strip()
                if ip and not ip.startswith('#'):  # Skip empty lines and comments
                    ips.append(ip)
            return ips
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return []
    except Exception as e:
        print(f"Error reading file '{file_path}': {e}")
        return []


def ping_servers(servers_data: dict, lock: threading.RLock, ip_list: List[str], max_remember: int):
    """
    Continuously ping all servers in the IP list.
    
    Args:
        servers_data: The dictionary holding all server latency data.
        lock: The threading lock to ensure thread safety.
        ip_list: List of IP addresses to ping.
        max_remember: Maximum number of ping results to remember per server.
    """
    print(f"Starting to ping {len(ip_list)} servers...")
    
    while True:
        for ip in ip_list:
            latency = ping_ip(ip)
            if latency is not None:
                update_latency(servers_data, lock, ip, latency, max_remember)
                print(f"✓ {ip}: {latency:.2f}ms")
            else:
                print(f"✗ {ip}: Failed")
        
        print("-" * 40)
        time.sleep(2)  # Wait 2 seconds before next round


def print_stats(servers_data: dict, lock: threading.RLock):
    """
    Print current statistics for all servers.
    
    Args:
        servers_data: The dictionary holding all server latency data.
        lock: The threading lock to ensure thread safety.
    """
    with lock:
        if not servers_data:
            print("No server data available.")
            return
        
        print("\n📊 Current Statistics:")
        print("-" * 60)
        print(f"{'Server':<20} {'Latest':<10} {'Lowest':<10} {'Avg(3)':<10} {'Total Pings':<12}")
        print("-" * 60)
        
        for server, stats in servers_data.items():
            latest = stats['latest']
            lowest = stats['lowest']
            history = list(stats['history'])
            avg_3 = sum(history[-3:]) / min(3, len(history)) if len(history) >= 3 else sum(history) / len(history) if history else 0
            
            print(f"{server:<20} {latest:<10.2f} {lowest:<10.2f} {avg_3:<10.2f} {len(history):<12}")
        
        # Find and display best servers
        best_server, best_latency = lowest_latency_server(servers_data, lock)
        best_avg_server, best_avg_latency = average_latency_lowest(servers_data, lock, 3)
        
        print("\n🏆 Best Servers:")
        if best_server:
            print(f"   Lowest latency: {best_server} ({best_latency:.2f}ms)")
        if best_avg_server:
            print(f"   Best average (last 3): {best_avg_server} ({best_avg_latency:.2f}ms)")
        
        print("-" * 60)


def main():
    """Main application entry point."""
    parser = argparse.ArgumentParser(description='Pingify - Advanced ping monitoring tool')
    parser.add_argument('--list', default='./server_lists/list.txt',
                       help='Path to IP list file (default: ./server_lists/list.txt)')
    parser.add_argument('--max_remember_average', type=int, default=100,
                       help='Maximum number of pings to remember per server (default: 100)')
    
    args = parser.parse_args()
    
    # Load IP list
    ip_list = load_ip_list(args.list)
    if not ip_list:
        print("No IP addresses loaded. Exiting.")
        sys.exit(1)
    
    print(f"Loaded {len(ip_list)} IP addresses from {args.list}")
    for ip in ip_list:
        print(f"  - {ip}")
    
    # Initialize data structures
    servers = {}
    lock = threading.RLock()
    
    print(f"\nStarting ping monitoring with max_remember_average={args.max_remember_average}")
    print("Press Ctrl+C to stop and see final statistics.\n")
    
    try:
        # Start ping monitoring in a separate thread
        ping_thread = threading.Thread(
            target=ping_servers,
            args=(servers, lock, ip_list, args.max_remember_average),
            daemon=True
        )
        ping_thread.start()
        
        # Main loop to display stats periodically
        while True:
            time.sleep(10)  # Update stats every 10 seconds
            print_stats(servers, lock)
            
    except KeyboardInterrupt:
        print("\n\n🛑 Stopping ping monitoring...")
        print_stats(servers, lock)
        print("Goodbye! 👋")


if __name__ == "__main__":
    main()