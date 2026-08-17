"""
Shadow Network Analyzer - Capture Engine
------------------------------------------
Handles live packet sniffing via Scapy (IPv4, IPv6, ARP, TCP, UDP, ICMP),
deep header parsing, statistics tracking, bandwidth monitoring, and security anomaly detection.
Supports Windows, macOS, and Linux seamlessly.
"""

import threading
import time
import csv
import io
import os
import ipaddress
from collections import deque, defaultdict
from datetime import datetime

from scapy.all import (
    sniff, IP, IPv6, ARP, TCP, UDP, ICMP, ICMPv6EchoRequest, ICMPv6EchoReply,
    Ether, Raw, get_if_list, conf
)


MAX_STORED_PACKETS = 2500          # ring buffer size for dashboard
PORT_SCAN_WINDOW_SECONDS = 10       # sliding window for scan detection
PORT_SCAN_UNIQUE_PORT_THRESHOLD = 15  # distinct dst ports from 1 src in window = alert
FLOOD_PACKET_THRESHOLD = 200        # packets from 1 src in window = alert


def has_bpf_permission():
    """Check if Python has read/write access to macOS /dev/bpf0 raw device."""
    if os.name == 'posix':
        try:
            if os.path.exists('/dev/bpf0'):
                with open('/dev/bpf0', 'rb'):
                    return True
        except PermissionError:
            return False
        except Exception:
            return True
    return True


def ensure_bpf_permissions():
    """Attempt to request macOS elevation to grant read/write access to /dev/bpf* if needed."""
    if os.name == 'posix' and os.path.exists('/dev/bpf0'):
        if not has_bpf_permission():
            try:
                # Trigger native macOS Administrator Password prompt
                cmd = "osascript -e 'do shell script \"chmod 666 /dev/bpf*\" with administrator privileges' >/dev/null 2>&1"
                os.system(cmd)
                return has_bpf_permission()
            except Exception:
                return False
    return True


def _classify_ip(ip_str):
    """Classify IP address into LAN, WAN, Loopback, or Multicast."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        if ip_obj.is_loopback:
            return "Loopback"
        elif ip_obj.is_private:
            return "LAN (Private)"
        elif ip_obj.is_multicast:
            return "Multicast"
        else:
            return "WAN (Public)"
    except Exception:
        return "Local Network"


def _safe_ascii(raw_bytes, limit=80):
    """Render raw payload bytes as a printable preview string."""
    if not raw_bytes:
        return ""
    snippet = raw_bytes[:limit]
    out = []
    for b in snippet:
        out.append(chr(b) if 32 <= b <= 126 else ".")
    suffix = "..." if len(raw_bytes) > limit else ""
    return "".join(out) + suffix


def _hex_dump(raw_bytes, max_bytes=256):
    """Format binary payload as a standard Wireshark/tcpdump style hex + ASCII dump."""
    if not raw_bytes:
        return "No binary payload"
    snippet = raw_bytes[:max_bytes]
    lines = []
    for i in range(0, len(snippet), 16):
        chunk = snippet[i:i+16]
        hex_part = " ".join(f"{b:02X}" for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04X}  {hex_part:<48}  |{ascii_part}|")
    if len(raw_bytes) > max_bytes:
        lines.append(f"... ({len(raw_bytes) - max_bytes} bytes omitted)")
    return "\n".join(lines)


class CaptureEngine:
    def __init__(self, max_packets=MAX_STORED_PACKETS):
        self.lock = threading.Lock()
        self.packets = deque(maxlen=max_packets)   # most recent first
        self.packet_map = {}                       # id -> packet dict for modal inspection
        self.protocol_counts = defaultdict(int)
        self.top_talkers = defaultdict(int)        # src_ip -> packet count
        self.total_captured = 0
        self.total_bytes = 0
        self.packet_counter = 0
        self.alerts = deque(maxlen=200)

        self._running = False
        self._sniff_thread = None
        self._stop_event = threading.Event()
        self.interface = None
        self.started_at = None

        # Bandwidth & PPS calculation (rolling window)
        self._recent_timestamps = deque()  # (time.time(), bytes)

        # Anomaly detection state
        self._recent_events = defaultdict(list)  # src_ip -> list[(timestamp, dst_port)]

    def available_interfaces(self):
        """Return formatted list of network interfaces."""
        try:
            raw_ifaces = get_if_list()
        except Exception:
            raw_ifaces = []

        default_if = None
        try:
            default_if = str(conf.iface)
        except Exception:
            pass

        def humanize(iface):
            if iface == "lo0" or "loopback" in iface.lower():
                return f"Loopback / Localhost ({iface})"
            elif iface == "en0" or "wi-fi" in iface.lower() or "wlan" in iface.lower():
                return f"Wi-Fi Network ({iface})"
            elif iface.startswith("en") or "ethernet" in iface.lower():
                return f"Ethernet / Adapter ({iface})"
            return iface

        result = []
        seen = set()

        if default_if and default_if in raw_ifaces:
            result.append({"id": default_if, "name": f"★ {humanize(default_if)} (Primary Active)"})
            seen.add(default_if)

        for iface in raw_ifaces:
            if iface not in seen:
                result.append({"id": iface, "name": humanize(iface)})
                seen.add(iface)

        result.append({"id": "[DEMO] Simulated Traffic", "name": "⚡ [DEMO] Simulated Traffic Mode"})
        return result

    def start(self, interface=None, bpf_filter=None):
        if self._running:
            return False

        # Ensure permissions on macOS
        if os.name == 'posix' and not has_bpf_permission():
            ensure_bpf_permissions()

        self.interface = interface
        self._stop_event.clear()
        self._running = True
        self.started_at = datetime.now()
        self._sniff_thread = threading.Thread(
            target=self._sniff_loop, args=(interface, bpf_filter), daemon=True
        )
        self._sniff_thread.start()
        return True

    def stop(self):
        if not self._running:
            return False
        self._stop_event.set()
        self._running = False
        return True

    def reset(self):
        with self.lock:
            self.packets.clear()
            self.packet_map.clear()
            self.protocol_counts.clear()
            self.top_talkers.clear()
            self.total_captured = 0
            self.total_bytes = 0
            self.packet_counter = 0
            self.alerts.clear()
            self._recent_events.clear()
            self._recent_timestamps.clear()

    def is_running(self):
        return self._running

    def _sniff_loop(self, interface, bpf_filter):
        if interface == "[DEMO] Simulated Traffic":
            self._run_simulation()
            return

        # Sanitize BPF Filter
        clean_filter = None
        if bpf_filter and str(bpf_filter).strip():
            f_str = str(bpf_filter).strip()
            if f_str.isdigit():
                clean_filter = f"port {f_str}"
            elif any(f_str.lower().startswith(kw) for kw in ["port", "tcp", "udp", "ip", "host", "net"]):
                clean_filter = f_str
            else:
                clean_filter = f_str

        # Resolve clean interface name
        iface_param = None
        if interface and interface.lower() != "default":
            # If user passed "en0" or raw interface id
            iface_param = interface

        try:
            sniff(
                iface=iface_param,
                filter=clean_filter,
                prn=self._handle_packet,
                store=False,
                stop_filter=lambda p: self._stop_event.is_set(),
            )
        except Exception as exc:
            err_msg = str(exc)
            if "Permission denied" in err_msg or "/dev/bpf" in err_msg or "Operation not permitted" in err_msg:
                user_msg = (
                    "🚨 PERMISSION NEEDED: macOS requires Administrator permission to access raw sockets.\n"
                    "• Option 1: Run 'sudo ./fix_mac_permissions.sh' in Terminal.\n"
                    "• Option 2: Run server with sudo -> 'sudo ./venv/bin/python app.py'\n"
                    "• Option 3: Select '[DEMO] Simulated Traffic' in the Interface dropdown."
                )
            elif "syntax error" in err_msg.lower() or "filter" in err_msg.lower() or "bpf" in err_msg.lower():
                user_msg = (
                    f"⚠️ BPF FILTER SYNTAX ERROR ('{bpf_filter}'): {exc}.\n"
                    "Use standard tcpdump syntax (e.g. 'tcp port 80', 'port 443', or leave blank)."
                )
            else:
                user_msg = f"⚠️ Capture error: {exc}"

            with self.lock:
                self.alerts.appendleft({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "level": "error",
                    "message": user_msg,
                })
            self._running = False

    def _run_simulation(self):
        import random
        from scapy.all import IP, TCP, UDP, ICMP, Raw, Ether

        sources = ["192.168.1.10", "192.168.1.15", "10.0.0.45", "172.16.0.22", "192.168.1.99"]
        destinations = ["142.250.190.46", "1.1.1.1", "8.8.8.8", "192.168.1.1", "104.21.34.11"]
        payloads = [
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            b"POST /api/v1/login HTTP/1.1\r\nHost: auth.net\r\nContent-Type: application/json\r\n\r\n{\"user\":\"admin\",\"pass\":\"secret\"}",
            b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03\x00\x1f\x00\x00",
            b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n",
            b"DNS Query: google.com (Type A, Class IN)",
        ]

        scan_counter = 0
        scanner_ip = "192.168.1.99"

        with self.lock:
            self.alerts.appendleft({
                "time": datetime.now().strftime("%H:%M:%S"),
                "level": "info",
                "message": "ℹ️ Demo mode activated: Generating simulated network traffic.",
            })

        while not self._stop_event.is_set():
            time.sleep(random.uniform(0.08, 0.25))
            if random.random() < 0.14:
                scan_counter += 1
                pkt = Ether() / IP(src=scanner_ip, dst="192.168.1.1") / TCP(
                    sport=random.randint(1024, 65535), dport=scan_counter * 9 + random.randint(1, 4), flags="S"
                )
            else:
                proto = random.choices(["TCP", "UDP", "ICMP", "OTHER"], weights=[60, 25, 10, 5])[0]
                src = random.choice(sources)
                dst = random.choice(destinations)
                if proto == "TCP":
                    pkt = (
                        Ether()
                        / IP(src=src, dst=dst)
                        / TCP(sport=random.randint(1024, 65535), dport=random.choice([80, 443, 22, 8080, 3306]), flags="PA")
                        / Raw(random.choice(payloads))
                    )
                elif proto == "UDP":
                    pkt = (
                        Ether()
                        / IP(src=src, dst=dst)
                        / UDP(sport=random.randint(1024, 65535), dport=random.choice([53, 123, 500, 4500]))
                        / Raw(b"UDP DNS / NTP / Syslog binary packet contents...")
                    )
                elif proto == "ICMP":
                    pkt = Ether() / IP(src=src, dst=dst) / ICMP()
                else:
                    pkt = Ether() / IP(src=src, dst=dst)

            self._handle_packet(pkt)

    def _handle_packet(self, pkt):
        ts = datetime.now()
        now_sec = time.time()

        src_ip = dst_ip = "Unknown"
        ip_ver = 4
        ttl = None
        ip_id = None

        # Extract Network Layer (IPv4, IPv6, ARP)
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            ip_ver = 4
            ttl = ip_layer.ttl
            ip_id = ip_layer.id
        elif pkt.haslayer(IPv6):
            ip6_layer = pkt[IPv6]
            src_ip = ip6_layer.src
            dst_ip = ip6_layer.dst
            ip_ver = 6
            ttl = getattr(ip6_layer, 'hlim', None)
        elif pkt.haslayer(ARP):
            arp_layer = pkt[ARP]
            src_ip = arp_layer.psrc
            dst_ip = arp_layer.pdst
            ip_ver = 4
        else:
            # Fallback Ethernet/raw frame
            return

        length = len(pkt)

        # Layer 2 MAC addresses
        src_mac = dst_mac = "—"
        if pkt.haslayer(Ether):
            src_mac = pkt[Ether].src
            dst_mac = pkt[Ether].dst

        src_type = _classify_ip(src_ip)
        dst_type = _classify_ip(dst_ip)

        # Layer 4 Protocol & Details
        proto_name = "OTHER"
        src_port = dst_port = None
        flags_str = ""
        seq = ack = window = None

        if pkt.haslayer(TCP):
            proto_name = "TCP"
            tcp_layer = pkt[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            flags_str = str(tcp_layer.flags)
            seq = tcp_layer.seq
            ack = tcp_layer.ack
            window = tcp_layer.window
        elif pkt.haslayer(UDP):
            proto_name = "UDP"
            udp_layer = pkt[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
        elif pkt.haslayer(ICMP) or pkt.haslayer(ICMPv6EchoRequest) or pkt.haslayer(ICMPv6EchoReply):
            proto_name = "ICMP"
        elif pkt.haslayer(ARP):
            proto_name = "ARP"

        # Payload & Hex Dump
        raw_payload = b""
        if pkt.haslayer(Raw):
            raw_payload = bytes(pkt[Raw].load)

        payload_preview = _safe_ascii(raw_payload)
        hex_dump_str = _hex_dump(raw_payload)

        with self.lock:
            self.packet_counter += 1
            pkt_id = self.packet_counter

            record = {
                "id": pkt_id,
                "time": ts.strftime("%H:%M:%S.%f")[:-3],
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "src_type": src_type,
                "dst_type": dst_type,
                "protocol": proto_name,
                "src_port": src_port,
                "dst_port": dst_port,
                "flags": flags_str,
                "seq": seq,
                "ack": ack,
                "window": window,
                "ttl": ttl,
                "ip_version": ip_ver,
                "ip_id": ip_id,
                "length": length,
                "payload": payload_preview,
                "hex_dump": hex_dump_str,
            }

            self.packets.appendleft(record)
            self.packet_map[pkt_id] = record
            if len(self.packet_map) > MAX_STORED_PACKETS * 1.5:
                sorted_keys = sorted(self.packet_map.keys())
                for k in sorted_keys[:MAX_STORED_PACKETS]:
                    del self.packet_map[k]

            self.protocol_counts[proto_name] += 1
            self.top_talkers[src_ip] += 1
            self.total_captured += 1
            self.total_bytes += length
            self._recent_timestamps.append((now_sec, length))

            self._detect_anomalies(src_ip, dst_port, ts)

    def _detect_anomalies(self, src_ip, dst_port, ts):
        now_ts = ts.timestamp()
        window_start = now_ts - PORT_SCAN_WINDOW_SECONDS

        events = self._recent_events[src_ip]
        events.append((now_ts, dst_port))

        while events and events[0][0] < window_start:
            events.pop(0)

        unique_ports = {p for _, p in events if p is not None}
        packet_count = len(events)

        if len(unique_ports) >= PORT_SCAN_UNIQUE_PORT_THRESHOLD:
            self._raise_alert(
                "warning",
                f"🚨 Port scan detected from {src_ip}: {len(unique_ports)} distinct ports targeted in {PORT_SCAN_WINDOW_SECONDS}s.",
                dedupe_key=f"scan:{src_ip}",
            )
        elif packet_count >= FLOOD_PACKET_THRESHOLD:
            self._raise_alert(
                "warning",
                f"⚡ Traffic flood detected from {src_ip}: {packet_count} packets in {PORT_SCAN_WINDOW_SECONDS}s.",
                dedupe_key=f"flood:{src_ip}",
            )

    def _raise_alert(self, level, message, dedupe_key=None):
        now = time.time()
        if dedupe_key:
            last = getattr(self, "_last_alert_time", {})
            if dedupe_key in last and now - last[dedupe_key] < 15:
                return
            if not hasattr(self, "_last_alert_time"):
                self._last_alert_time = {}
            self._last_alert_time[dedupe_key] = now

        self.alerts.appendleft({
            "time": datetime.now().strftime("%H:%M:%S"),
            "level": level,
            "message": message,
        })

    def get_packets(self, protocol=None, ip=None, limit=200):
        with self.lock:
            items = list(self.packets)

        if protocol and protocol.upper() != "ALL":
            p_upper = protocol.upper()
            if p_upper == "HTTP":
                items = [p for p in items if p["src_port"] == 80 or p["dst_port"] == 80]
            elif p_upper == "HTTPS":
                items = [p for p in items if p["src_port"] == 443 or p["dst_port"] == 443]
            elif p_upper == "DNS":
                items = [p for p in items if p["src_port"] == 53 or p["dst_port"] == 53]
            elif p_upper == "SSH":
                items = [p for p in items if p["src_port"] == 22 or p["dst_port"] == 22]
            else:
                items = [p for p in items if p["protocol"] == p_upper]

        if ip:
            items = [p for p in items if ip in p["src_ip"] or ip in p["dst_ip"]]

        return items[:limit]

    def get_packet_by_id(self, pkt_id):
        with self.lock:
            return self.packet_map.get(int(pkt_id))

    def get_stats(self):
        now_sec = time.time()
        with self.lock:
            proto_counts = dict(self.protocol_counts)
            total = self.total_captured
            total_bytes = self.total_bytes
            top = sorted(self.top_talkers.items(), key=lambda x: x[1], reverse=True)[:5]
            running = self._running
            started_at = self.started_at.strftime("%H:%M:%S") if self.started_at else None

            # Calculate PPS & KB/s over last 3 seconds
            cutoff = now_sec - 3.0
            while self._recent_timestamps and self._recent_timestamps[0][0] < cutoff:
                self._recent_timestamps.popleft()

            recent_pkts = len(self._recent_timestamps)
            recent_bytes = sum(b for _, b in self._recent_timestamps)
            pps = round(recent_pkts / 3.0, 1) if recent_pkts else 0.0
            kbps = round((recent_bytes * 8 / 1024) / 3.0, 1) if recent_bytes else 0.0

        bpf_ok = has_bpf_permission()

        return {
            "total_packets": total,
            "total_bytes": total_bytes,
            "protocol_counts": proto_counts,
            "top_talkers": [{"ip": ip, "count": c} for ip, c in top],
            "running": running,
            "started_at": started_at,
            "interface": self.interface,
            "pps": pps,
            "kbps": kbps,
            "bpf_permitted": bpf_ok,
        }

    def get_alerts(self):
        with self.lock:
            return list(self.alerts)

    def export_csv(self):
        with self.lock:
            items = list(self.packets)

        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(
            [
                "ID", "Time", "Source IP", "Src Type", "Destination IP", "Dst Type",
                "Protocol", "Src Port", "Dst Port", "TCP Flags", "Length (Bytes)", "Payload Preview"
            ]
        )
        for p in items:
            writer.writerow([
                p["id"], p["time"], p["src_ip"], p["src_type"], p["dst_ip"], p["dst_type"],
                p["protocol"], p["src_port"], p["dst_port"], p["flags"], p["length"], p["payload"],
            ])
        return buf.getvalue()
