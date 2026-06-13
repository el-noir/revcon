---
name: pcap_analyzer
description: Parses .pcap network capture files to extract IOCs (IPs, domains, URLs, DNS queries, HTTP headers) and correlate them with static analysis findings from Ghidra.
version: 1.0.0
metadata:
  hermes:
    tags: [reversing, network, pcap, forensics, ioc]
    category: re
---
# PCAP Network Analyzer Skill

## When to Use
Use this skill when the user provides a `.pcap` or `.pcapng` file captured during dynamic execution of a malware sample. This allows correlation between what Ghidra shows statically (e.g., `connect()` calls, hardcoded IPs) and actual network behavior.
Trigger: user says "analyze this pcap", "check the network traffic", or when the main agent finds network-related imports.

## Prerequisites
- A `.pcap` or `.pcapng` file must be provided.
- This skill runs inside the Modal cloud sandbox.
- Uses `scapy` (available via pwntools) and `dpkt` (install dynamically with `pip install dpkt`).

## Python Implementation Template
```python
# pip install dpkt if not available
try:
    import dpkt
except ImportError:
    import subprocess
    subprocess.check_call(["pip", "install", "dpkt"])
    import dpkt

import socket
import sys
from collections import defaultdict

pcap_path = "<INSERT_PCAP_PATH>"

dns_queries = []
http_requests = []
tcp_connections = set()
udp_connections = set()
tls_sni = []
unique_ips = set()

def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

with open(pcap_path, 'rb') as f:
    try:
        pcap = dpkt.pcap.Reader(f)
    except ValueError:
        f.seek(0)
        pcap = dpkt.pcapng.Reader(f)
    
    for timestamp, buf in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except dpkt.NeedData:
            continue
        
        if not isinstance(eth.data, dpkt.ip.IP):
            continue
        
        ip = eth.data
        src_ip = inet_to_str(ip.src)
        dst_ip = inet_to_str(ip.dst)
        unique_ips.add(src_ip)
        unique_ips.add(dst_ip)
        
        # TCP Analysis
        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            tcp_connections.add((src_ip, tcp.sport, dst_ip, tcp.dport))
            
            # HTTP Detection
            try:
                if tcp.dport == 80 or tcp.sport == 80:
                    http = dpkt.http.Request(tcp.data)
                    host = http.headers.get('host', dst_ip)
                    ua = http.headers.get('user-agent', 'N/A')
                    http_requests.append({
                        'method': http.method,
                        'host': host,
                        'uri': http.uri,
                        'user_agent': ua,
                        'dst_ip': dst_ip
                    })
            except (dpkt.UnpackError, dpkt.NeedData):
                pass
            
            # TLS SNI Detection
            try:
                if tcp.dport == 443 and len(tcp.data) > 0:
                    tls = dpkt.ssl.TLSRecord(tcp.data)
                    if tls.type == 22:  # Handshake
                        handshake = dpkt.ssl.TLSHandshake(tls.data)
                        if handshake.type == 1:  # ClientHello
                            # Extract SNI from extensions
                            hello = handshake.data
                            if hasattr(hello, 'extensions'):
                                for ext in hello.extensions:
                                    if ext[0] == 0:  # SNI extension
                                        sni_data = ext[1]
                                        sni_name = sni_data[5:].decode('ascii', errors='ignore')
                                        tls_sni.append(sni_name)
            except (dpkt.UnpackError, dpkt.NeedData, AttributeError):
                pass
        
        # UDP / DNS Analysis
        elif isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            udp_connections.add((src_ip, udp.sport, dst_ip, udp.dport))
            
            if udp.dport == 53 or udp.sport == 53:
                try:
                    dns = dpkt.dns.DNS(udp.data)
                    for q in dns.qd:
                        dns_queries.append(q.name)
                    for a in dns.an:
                        if a.type == dpkt.dns.DNS_A:
                            dns_queries.append(f"{a.name} -> {inet_to_str(a.rdata)}")
                except (dpkt.UnpackError, dpkt.NeedData):
                    pass

# === OUTPUT REPORT ===
print("=" * 60)
print("PCAP ANALYSIS REPORT")
print("=" * 60)

print(f"\n[UNIQUE IPs] ({len(unique_ips)} found)")
for ip in sorted(unique_ips):
    # Skip private/local IPs
    if not ip.startswith(('10.', '192.168.', '127.')):
        print(f"  ► {ip}")

print(f"\n[DNS QUERIES] ({len(dns_queries)} found)")
for q in sorted(set(dns_queries)):
    print(f"  ► {q}")

print(f"\n[HTTP REQUESTS] ({len(http_requests)} found)")
for req in http_requests:
    print(f"  ► {req['method']} http://{req['host']}{req['uri']}")
    print(f"    User-Agent: {req['user_agent']}")

print(f"\n[TLS SNI HOSTNAMES] ({len(tls_sni)} found)")
for sni in sorted(set(tls_sni)):
    print(f"  ► {sni}")

print(f"\n[TCP CONNECTIONS] ({len(tcp_connections)} unique)")
for conn in sorted(tcp_connections, key=lambda x: x[3]):
    print(f"  ► {conn[0]}:{conn[1]} -> {conn[2]}:{conn[3]}")

print("\n" + "=" * 60)
print("END OF REPORT")
```

## Reporting Format
Present the IOCs in a structured format organized by type (DNS, HTTP, TLS, raw TCP). Highlight any suspicious indicators: non-standard ports, raw IP connections without DNS, unusual user-agents, or connections to known malicious infrastructure.
