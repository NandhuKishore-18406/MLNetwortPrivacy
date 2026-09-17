import json
import os
import socket
import subprocess
import time

INTERFACE = "wlan0"

# Mapping from IANA IP protocol numbers to human-readable names
PROTOCOL_MAP = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    132: "SCTP",
}

# In-memory IP-to-Domain cache mapping IP addresses to domain names
DNS_CACHE = {}


def resolve_reverse_dns(ip):
    """
    Attempts reverse DNS lookup for an IP address if missing from live capture.
    """
    if not ip or ip.startswith("127.") or ip == "::1":
        return None
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return None


class FlowAggregator:
    """
    Aggregates individual parsed packets into bidirectional network flows (sessions).
    Calculates detailed statistical metrics matching the target flow schema.
    """
    def __init__(self, idle_timeout=15.0, active_timeout=60.0):
        self.idle_timeout = idle_timeout
        self.active_timeout = active_timeout
        self.flows = {}

    def get_flow_key(self, packet):
        """
        Generates a normalized bidirectional 5-tuple key:
        (min_ip, max_ip, min_port, max_port, protocol)
        """
        ip1 = packet["source_ip"] or ""
        ip2 = packet["destination_ip"] or ""
        port1 = packet["source_port"] or 0
        port2 = packet["destination_port"] or 0
        proto = packet["protocol"] or "UNKNOWN"

        if (ip1, port1) <= (ip2, port2):
            return (ip1, ip2, port1, port2, proto)
        else:
            return (ip2, ip1, port2, port1, proto)

    def process_packet(self, packet):
        """
        Processes a normalized packet dictionary.
        Returns a tuple: (active_flow_dict, list_of_expired_flow_dicts)
        """
        if not packet or not packet["source_ip"] or not packet["destination_ip"]:
            return None, [self.get_formatted_flow(f) for f in self.get_expired_flows(current_time=packet.get("timestamp") if packet else None)]

        now = packet["timestamp"] or time.time()
        key = self.get_flow_key(packet)
        pkt_size = packet["packet_size"] or 0
        domain = packet["domain_name"]

        if key not in self.flows:
            # Initialize a new flow tracking state
            self.flows[key] = {
                "source_ip": packet["source_ip"],
                "destination_ip": packet["destination_ip"],
                "source_port": packet["source_port"],
                "destination_port": packet["destination_port"],
                "protocol": packet["protocol"],
                "domain_name": domain,
                "start_time": now,
                "end_time": now,
                "duration": 0.0,
                "packet_count": 1,
                "total_bytes": pkt_size,
                "bytes_sent": pkt_size,
                "bytes_received": 0,
                "packet_sizes": [pkt_size],
                "avg_packet_size": float(pkt_size),
                "min_packet_size": pkt_size,
                "max_packet_size": pkt_size,
                "packets_per_second": 1.0,
                "bytes_per_second": float(pkt_size),
            }
        else:
            flow = self.flows[key]
            flow["end_time"] = now
            duration = max(0.0, now - flow["start_time"])
            flow["duration"] = round(duration, 4)
            flow["packet_count"] += 1
            flow["total_bytes"] += pkt_size
            flow["packet_sizes"].append(pkt_size)

            if domain and not flow["domain_name"]:
                flow["domain_name"] = domain

            # Check if packet source matches initial flow source_ip & source_port
            is_sent = (packet["source_ip"], packet["source_port"]) == (flow["source_ip"], flow["source_port"])
            if is_sent:
                flow["bytes_sent"] += pkt_size
            else:
                flow["bytes_received"] += pkt_size

            # Recalculate statistical metrics
            pkt_count = flow["packet_count"]
            tot_bytes = flow["total_bytes"]
            sizes = flow["packet_sizes"]

            flow["avg_packet_size"] = round(tot_bytes / pkt_count, 2)
            flow["min_packet_size"] = min(sizes)
            flow["max_packet_size"] = max(sizes)

            if duration > 0:
                flow["packets_per_second"] = round(pkt_count / duration, 2)
                flow["bytes_per_second"] = round(tot_bytes / duration, 2)
            else:
                flow["packets_per_second"] = float(pkt_count)
                flow["bytes_per_second"] = float(tot_bytes)

        expired = self.get_expired_flows(current_time=now)
        active_formatted = self.get_formatted_flow(self.flows.get(key))
        expired_formatted = [self.get_formatted_flow(f) for f in expired]
        return active_formatted, expired_formatted

    def get_formatted_flow(self, flow):
        """
        Formats internal flow tracking state into the exact target schema dictionary.
        """
        if not flow:
            return None
        return {
            "source_ip": flow["source_ip"],
            "destination_ip": flow["destination_ip"],
            "source_port": flow["source_port"],
            "destination_port": flow["destination_port"],
            "protocol": flow["protocol"],
            "domain_name": flow["domain_name"],
            "start_time": flow["start_time"],
            "end_time": flow["end_time"],
            "duration": flow["duration"],
            "packet_count": flow["packet_count"],
            "total_bytes": flow["total_bytes"],
            "bytes_sent": flow["bytes_sent"],
            "bytes_received": flow["bytes_received"],
            "avg_packet_size": flow["avg_packet_size"],
            "min_packet_size": flow["min_packet_size"],
            "max_packet_size": flow["max_packet_size"],
            "packets_per_second": flow["packets_per_second"],
            "bytes_per_second": flow["bytes_per_second"],
        }

    def get_expired_flows(self, current_time=None):
        """
        Flushes and returns flows that have exceeded idle_timeout or active_timeout.
        """
        if current_time is None:
            current_time = time.time()

        expired = []
        keys_to_remove = []

        for key, flow in self.flows.items():
            idle_time = current_time - flow["end_time"]
            active_time = current_time - flow["start_time"]

            if idle_time >= self.idle_timeout or active_time >= self.active_timeout:
                expired.append(flow)
                keys_to_remove.append(key)

        for key in keys_to_remove:
            del self.flows[key]

        return expired


def parse_packet(line):
    """
    Parses a single raw pipe-delimited output line from TShark into a normalized dictionary.

    Expected field order (15 fields):
    0: frame.time_epoch
    1: ip.src
    2: ip.dst
    3: ipv6.src
    4: ipv6.dst
    5: ip.proto
    6: ipv6.nxt
    7: tcp.srcport
    8: tcp.dstport
    9: udp.srcport
    10: udp.dstport
    11: frame.len
    12: dns.qry.name
    13: tls.handshake.extensions_server_name
    14: http.host
    """
    # Remove trailing newlines and split by field separator
    fields = line.rstrip("\r\n").split("|")

    # Drop lines that don't contain exactly the 15 expected fields
    if len(fields) != 15:
        return None

    (
        timestamp_raw,
        ipv4_src,
        ipv4_dst,
        ipv6_src,
        ipv6_dst,
        ipv4_proto,
        ipv6_proto,
        tcp_src,
        tcp_dst,
        udp_src,
        udp_dst,
        packet_size_raw,
        dns_query,
        tls_sni,
        http_host,
    ) = fields

    # 1. Parse timestamp (float)
    timestamp = None
    if timestamp_raw:
        try:
            timestamp = float(timestamp_raw.split(",")[0])
        except ValueError:
            timestamp = None

    # 2. Extract IP Addresses (IPv4 prioritized, IPv6 fallback)
    # TShark can return comma-separated values if multiple IP layers exist; take the first value
    source_ip = ipv4_src or ipv6_src or None
    if source_ip:
        source_ip = source_ip.split(",")[0]

    dest_ip = ipv4_dst or ipv6_dst or None
    if dest_ip:
        dest_ip = dest_ip.split(",")[0]

    # 3. Extract Protocol (Convert numeric IP protocol to human-readable string e.g. 'TCP', 'UDP')
    protocol_raw = ipv4_proto or ipv6_proto or None
    protocol = None
    if protocol_raw:
        try:
            proto_num = int(protocol_raw.split(",")[0])
            protocol = PROTOCOL_MAP.get(proto_num, f"IP-{proto_num}")
        except ValueError:
            protocol = None

    # 4. Extract Transport Ports (TCP prioritized, UDP fallback)
    source_port_raw = tcp_src or udp_src or None
    source_port = None
    if source_port_raw:
        try:
            source_port = int(source_port_raw.split(",")[0])
        except ValueError:
            source_port = None

    dest_port_raw = tcp_dst or udp_dst or None
    dest_port = None
    if dest_port_raw:
        try:
            dest_port = int(dest_port_raw.split(",")[0])
        except ValueError:
            dest_port = None

    # 5. Extract Packet Size in bytes (int)
    packet_size = None
    if packet_size_raw:
        try:
            packet_size = int(packet_size_raw.split(",")[0])
        except ValueError:
            packet_size = None

    # 6. Extract Domain Name (DNS query name, TLS SNI hostname, or HTTP Host header)
    domain_name = dns_query or tls_sni or http_host or None
    if domain_name:
        domain_name = domain_name.split(",")[0].strip()
        # Save domain to cache for both IP endpoints
        if dest_ip:
            DNS_CACHE[dest_ip] = domain_name
        if source_ip:
            DNS_CACHE[source_ip] = domain_name
    else:
        # Fallback 1: In-memory DNS cache from previous packets
        domain_name = DNS_CACHE.get(dest_ip) or DNS_CACHE.get(source_ip)
        
        # Fallback 2: Reverse DNS lookup if IP is not cached yet
        if not domain_name and dest_ip:
            rdns = resolve_reverse_dns(dest_ip)
            if rdns:
                domain_name = rdns
                DNS_CACHE[dest_ip] = rdns

    # Return normalized packet dictionary structure
    return {
        "timestamp": timestamp,
        "source_ip": source_ip,
        "destination_ip": dest_ip,
        "protocol": protocol,
        "source_port": source_port,
        "destination_port": dest_port,
        "packet_size": packet_size,
        "domain_name": domain_name,
    }


def packetcapture(interface=INTERFACE):
    """
    Spawns the TShark subprocess to capture live traffic from the specified interface
    and outputs normalized packet dictionaries.
    """
    # Build base command
    command = ["tshark"]

    # Prepend sudo if running as non-root user on Linux/Unix
    if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() != 0:
        command.insert(0, "sudo")

    command.extend([
        "-i", interface,
        "-l",  # Flush stdout after each packet (enables real-time processing)
        "-T", "fields",
        "-E", "separator=|",
        "-e", "frame.time_epoch",
        "-e", "ip.src",
        "-e", "ip.dst",
        "-e", "ipv6.src",
        "-e", "ipv6.dst",
        "-e", "ip.proto",
        "-e", "ipv6.nxt",
        "-e", "tcp.srcport",
        "-e", "tcp.dstport",
        "-e", "udp.srcport",
        "-e", "udp.dstport",
        "-e", "frame.len",
        "-e", "dns.qry.name",
        "-e", "tls.handshake.extensions_server_name",
        "-e", "http.host",
    ])

    try:
        # Use stderr=subprocess.PIPE to capture diagnostic/error messages from TShark or sudo
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
    except FileNotFoundError:
        print("Error: 'sudo' or 'tshark' executable was not found. Make sure TShark is installed.")
        return
    except Exception as e:
        print(f"Failed to launch TShark process: {e}")
        return

    print(f"TShark started on interface '{interface}'. Waiting for packets...\n")
    aggregator = FlowAggregator(idle_timeout=15.0, active_timeout=60.0)

    try:
        # Read lines from TShark's stdout stream in real time
        for line in process.stdout:
            packet = parse_packet(line)
            if packet is not None:
                active_flow, expired_flows = aggregator.process_packet(packet)

                print(f"[PACKET] {packet['source_ip']}:{packet['source_port']} -> {packet['destination_ip']}:{packet['destination_port']} ({packet['protocol']}) | Domain: {packet['domain_name']} | Size: {packet['packet_size']}B")

                # Log when a flow finishes or expires with pretty-printed JSON schema
                for exp in expired_flows:
                    print("\n---> [FLOW EXPIRED/COMPLETED]")
                    print(json.dumps(exp, indent=4))
                    print()
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    finally:
        # Ensure TShark subprocess is terminated when python loop exits
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()

    # Check if TShark process exited with an error code
    if process.returncode is not None and process.returncode != 0:
        stderr_output = process.stderr.read().strip() if process.stderr else ""
        print(f"\nTShark exited unexpectedly with code {process.returncode}.")
        
        if stderr_output:
            print(f"TShark Error Output:\n  {stderr_output}\n")

        # Provide actionable troubleshooting steps based on common TShark/sudo errors
        if "password is required" in stderr_output or "Permission denied" in stderr_output:
            print("Troubleshooting Permission Error:")
            print("  Option A (Recommended for uv): Run with sudo:")
            print("  -> sudo uv run python -m mlproject_main")
            print("  or:")
            print("  -> sudo .venv/bin/python src/mlproject_main/__init__.py")
            print("  Option B: Allow non-root capture with dumpcap (then use 'uv run'):")
            print("  -> sudo usermod -aG wireshark $USER && sudo setcap cap_net_raw,cap_net_admin=eip /usr/bin/dumpcap")
        elif "No such device" in stderr_output or "There is no interface" in stderr_output:
            print("Troubleshooting Interface Error:")
            print(f"  Interface '{interface}' was not found on your system.")
            print("  List available interfaces with: 'ip link' or 'tshark -D'")


def main():
    print("NetPrivacy Monitor - Packet Capture Layer")
    print(f"Monitoring Interface: {INTERFACE}")
    print("Press CTRL+C to stop.\n")

    packetcapture()


if __name__ == "__main__":
    main()