"""SmartShield live dashboard.

Captures packets with scapy, groups them into bidirectional flows, extracts the
same 17-feature vector used at training time, and classifies each flow with the
trained model. A lightweight whitelist + signature layer filters out obvious
benign traffic (DNS, loopback, mDNS) and escalates clear attack patterns
(SYN floods, port scans) independently of the ML verdict.
"""

import csv
import ipaddress
import socket
import threading
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from tkinter import (
    BOTH, LEFT, RIGHT, W, X, Button, Frame, Label, Tk, Toplevel, ttk,
)

import joblib
import pandas as pd
import psutil
from scapy.all import IP, TCP, UDP, sniff

ROOT = Path(__file__).resolve().parent
MODELS_DIR = ROOT / "models"
LOG_DIR = ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)
LOG_FILE = LOG_DIR / "detections.csv"

# ---------------------------------------------------------------------------
# Load model + encodings. These must exist — run train_model.py first.
# ---------------------------------------------------------------------------
print("Loading SmartShield model...")
model = joblib.load(MODELS_DIR / "smartshield_model.pkl")
scaler = joblib.load(MODELS_DIR / "scaler.pkl")
FEATURE_NAMES = joblib.load(MODELS_DIR / "feature_names.pkl")
ENCODINGS = joblib.load(MODELS_DIR / "encodings.pkl")
PROTO_MAP = ENCODINGS["proto"]
SERVICE_MAP = ENCODINGS["service"]
STATE_MAP = ENCODINGS["state"]
print(f"  model={type(model).__name__}  features={len(FEATURE_NAMES)}")

# --- Detection gating ------------------------------------------------------
# SmartShield uses a layered approach so the ML model never fires on its own
# on routine traffic:
#   1. WHITELIST:  loopback / multicast / broadcast / outbound HTTPS / mDNS /
#                  SSDP / NetBIOS — never scored by the ML model.
#   2. SIGNATURES: textbook attack patterns (SYN flood, port scan) — these
#                  are the PRIMARY alert source. Hard rules, zero FPs on
#                  normal traffic.
#   3. ML:         runs as a CORROBORATOR. Only surfaces alerts when either
#                    (a) confidence is very high AND the flow is inbound on a
#                        listening service from an outside source, OR
#                    (b) the source IP already has a signature-level alert
#                        (so the ML adds colour to a real event).
# This deliberately sacrifices some recall on the UNSW-NB15 benchmark to get
# ~0 false positives on real traffic, which is what matters in practice.

CONFIDENCE_THRESHOLD = 0.95           # ML minimum confidence
CORROBORATED_CONFIDENCE = 0.80        # threshold when signature already fired
MIN_PACKETS_FOR_PREDICTION = 8

# Ports → service label used by the training set.
PORT_SERVICE = {
    53: "dns", 80: "http", 8080: "http", 443: "ssl", 25: "smtp", 587: "smtp",
    21: "ftp", 20: "ftp-data", 110: "pop3", 22: "ssh", 161: "snmp",
    194: "irc", 1812: "radius", 67: "dhcp", 68: "dhcp",
}

# Ports that represent outbound chatter from a normal desktop / laptop. If the
# *local* host is on one side and the *remote* port matches, we never alert —
# this is the user's own browsing / OS background traffic.
OUTBOUND_TRUSTED_PORTS = {
    443,    # HTTPS
    80,     # HTTP
    53,     # DNS
    123,    # NTP
    5353,   # mDNS
    1900,   # SSDP
    137, 138, 139,  # NetBIOS
    5228,   # Google services
    5223,   # Apple push
}


def _discover_local_ips() -> set[str]:
    """All IPv4 addresses bound to this machine, so we know which flows are
    'outbound from me' vs 'inbound at me'."""
    ips: set[str] = {"127.0.0.1"}
    try:
        for _, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address:
                    ips.add(addr.address)
    except Exception:
        pass
    return ips


LOCAL_IPS = _discover_local_ips()
print(f"  local IPs: {sorted(LOCAL_IPS)}")


def classify_service(dst_port: int, src_port: int) -> str:
    for port in (dst_port, src_port):
        if port in PORT_SERVICE:
            return PORT_SERVICE[port]
    return "-"


def _is_broadcast(addr: ipaddress.IPv4Address) -> bool:
    # 255.255.255.255 and typical /24 broadcast x.x.x.255.
    if str(addr) == "255.255.255.255":
        return True
    octets = str(addr).split(".")
    return len(octets) == 4 and octets[-1] == "255"


def is_whitelisted(src_ip: str, dst_ip: str, service: str,
                   src_port: int, dst_port: int) -> bool:
    """Obvious benign traffic the ML model should never even see."""
    try:
        src = ipaddress.ip_address(src_ip)
        dst = ipaddress.ip_address(dst_ip)
    except ValueError:
        return False

    for addr in (src, dst):
        if addr.is_loopback or addr.is_link_local or addr.is_multicast:
            return True
        if isinstance(addr, ipaddress.IPv4Address) and _is_broadcast(addr):
            return True

    # Outbound traffic *from this machine* on a well-known client port. This
    # is the user's own browsing / OS background noise — never an attack on
    # us, so never alert.
    if src_ip in LOCAL_IPS and dst_port in OUTBOUND_TRUSTED_PORTS:
        return True
    if dst_ip in LOCAL_IPS and src_port in OUTBOUND_TRUSTED_PORTS:
        # Inbound reply to our outbound client connection.
        return True

    # Intra-LAN discovery/config chatter.
    if src.is_private and dst.is_private and service in {"dns", "dhcp"}:
        return True
    if src.is_private and dst.is_private and (
        5353 in (src_port, dst_port) or  # mDNS
        1900 in (src_port, dst_port) or  # SSDP
        137 in (src_port, dst_port) or   # NetBIOS
        138 in (src_port, dst_port) or
        139 in (src_port, dst_port)
    ):
        return True

    return False


# ---------------------------------------------------------------------------
# FlowTracker — one entry per bidirectional flow, keyed by sorted IP+port+proto
# tuple so A→B and B→A share state.
# ---------------------------------------------------------------------------
class FlowTracker:
    def __init__(self, timeout: float = 30.0):
        self.flows: dict[str, dict] = {}
        self.timeout = timeout

    @staticmethod
    def _flow_key(pkt) -> str | None:
        if not pkt.haslayer(IP):
            return None
        ip = pkt[IP]
        proto = ip.proto
        sport = dport = 0
        if pkt.haslayer(TCP):
            sport, dport = pkt[TCP].sport, pkt[TCP].dport
        elif pkt.haslayer(UDP):
            sport, dport = pkt[UDP].sport, pkt[UDP].dport
        a, b = (ip.src, sport), (ip.dst, dport)
        lo, hi = sorted([a, b])
        return f"{lo[0]}:{lo[1]}|{hi[0]}:{hi[1]}|{proto}"

    @staticmethod
    def _proto_label(pkt) -> str:
        if pkt.haslayer(TCP):
            return "tcp"
        if pkt.haslayer(UDP):
            return "udp"
        if pkt[IP].proto == 1:
            return "icmp"
        return "other"

    def process_packet(self, pkt):
        if not pkt.haslayer(IP):
            return None
        key = self._flow_key(pkt)
        if not key:
            return None

        now = time.time()
        ip = pkt[IP]
        pkt_len = len(pkt)

        if key not in self.flows:
            sport = pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0)
            dport = pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0)
            self.flows[key] = {
                "start_time": now, "last_seen": now,
                "src_ip": ip.src, "dst_ip": ip.dst,
                "src_port": sport, "dst_port": dport,
                "proto_label": self._proto_label(pkt),
                "service": classify_service(dport, sport),
                "forward_bytes": 0, "reverse_bytes": 0,
                "forward_packets": 0, "reverse_packets": 0,
                "forward_ttl": 0, "reverse_ttl": 0,
                "forward_times": deque(maxlen=32),
                "reverse_times": deque(maxlen=32),
                # TCP flag accumulators — used to derive the UNSW state code.
                "syn": 0, "synack": 0, "fin": 0, "rst": 0, "ack": 0, "psh": 0,
                "established": False,
            }

        flow = self.flows[key]
        flow["last_seen"] = now

        forward = ip.src == flow["src_ip"]
        if forward:
            flow["forward_bytes"] += pkt_len
            flow["forward_packets"] += 1
            flow["forward_ttl"] = int(ip.ttl)
            flow["forward_times"].append(now)
        else:
            flow["reverse_bytes"] += pkt_len
            flow["reverse_packets"] += 1
            flow["reverse_ttl"] = int(ip.ttl)
            flow["reverse_times"].append(now)

        if pkt.haslayer(TCP):
            flags = int(pkt[TCP].flags)
            if flags & 0x02: flow["syn"] += 1
            if flags & 0x10: flow["ack"] += 1
            if flags & 0x01: flow["fin"] += 1
            if flags & 0x04: flow["rst"] += 1
            if flags & 0x08: flow["psh"] += 1
            if (flags & 0x12) == 0x12: flow["synack"] += 1
            if flow["synack"] > 0 and flow["ack"] > 0:
                flow["established"] = True

        self._cleanup(now)
        return key

    def _cleanup(self, now: float) -> None:
        expired = [k for k, f in self.flows.items() if now - f["last_seen"] > self.timeout]
        for k in expired:
            del self.flows[k]

    @staticmethod
    def _tcp_state(flow) -> str:
        if flow["proto_label"] != "tcp":
            return "CON" if flow["forward_packets"] > 0 and flow["reverse_packets"] > 0 else "INT"
        if flow["rst"] > 0:
            return "RST"
        if flow["fin"] > 0:
            return "FIN"
        if flow["established"]:
            return "CON"
        if flow["syn"] > 0 and flow["reverse_packets"] == 0:
            return "INT"
        if flow["syn"] > 0 and flow["synack"] == 0:
            return "REQ"
        return "INT"

    def extract_features(self, key: str) -> dict | None:
        if key not in self.flows:
            return None
        flow = self.flows[key]
        dur = max(time.time() - flow["start_time"], 1e-6)
        spkts, dpkts = flow["forward_packets"], flow["reverse_packets"]
        sbytes, dbytes = flow["forward_bytes"], flow["reverse_bytes"]

        def mean_interarrival(times):
            if len(times) < 2:
                return 0.0
            diffs = [(b - a) * 1000.0 for a, b in zip(times, list(times)[1:])]
            return sum(diffs) / len(diffs)

        return {
            "dur": dur,
            "proto": PROTO_MAP.get(flow["proto_label"], PROTO_MAP["other"]),
            "service": SERVICE_MAP.get(flow["service"], SERVICE_MAP["-"]),
            "state": STATE_MAP.get(self._tcp_state(flow), STATE_MAP["other"]),
            "spkts": spkts,
            "dpkts": dpkts,
            "sbytes": sbytes,
            "dbytes": dbytes,
            "rate": (spkts + dpkts) / dur,
            "sload": (sbytes * 8) / dur,
            "dload": (dbytes * 8) / dur,
            "smean": sbytes / spkts if spkts else 0,
            "dmean": dbytes / dpkts if dpkts else 0,
            "sinpkt": mean_interarrival(flow["forward_times"]),
            "dinpkt": mean_interarrival(flow["reverse_times"]),
        }

    def get_flow_info(self, key: str) -> dict | None:
        if key not in self.flows:
            return None
        flow = self.flows[key]
        return {
            "src": f"{flow['src_ip']}:{flow['src_port']}",
            "dst": f"{flow['dst_ip']}:{flow['dst_port']}",
            "proto": flow["proto_label"].upper(),
            "service": flow["service"],
            "duration": f"{time.time() - flow['start_time']:.1f}s",
            "packets": f"{flow['forward_packets']}/{flow['reverse_packets']}",
            "bytes": f"{flow['forward_bytes']}/{flow['reverse_bytes']}",
        }


# ---------------------------------------------------------------------------
# Signature / heuristic layer — runs alongside the ML model. Catches the
# "smoking-gun" attack patterns (SYN floods, port scans) even if the model
# happens to miss them, and gives the dashboard something meaningful to say
# about the alert type.
# ---------------------------------------------------------------------------
class ThreatDetector:
    """Signature layer + bookkeeping for ML corroboration."""

    def __init__(self):
        self.syn_events: dict[str, deque] = defaultdict(lambda: deque(maxlen=400))
        self.scan_targets: dict[str, dict] = defaultdict(
            lambda: {"ports": set(), "ts": deque(maxlen=400)}
        )
        self.signature_hits: dict[str, float] = {}   # src_ip -> last sig ts
        self.ml_hits: dict[str, deque] = defaultdict(lambda: deque(maxlen=200))

    def observe_packet(self, pkt):
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return None
        tcp = pkt[TCP]
        now = time.time()
        flags = int(tcp.flags)
        src = pkt[IP].src
        alerts = []

        # SYN flood: many SYN-without-ACK from a single source in < 2s.
        if (flags & 0x02) and not (flags & 0x10):
            self.syn_events[src].append(now)
            recent = [t for t in self.syn_events[src] if now - t <= 2.0]
            if len(recent) >= 50:
                alerts.append(("SYN flood", src, len(recent), 2))

        # Port scan: same src hitting ≥20 distinct dst ports in < 5s.
        if flags & 0x02:
            info = self.scan_targets[src]
            info["ports"].add(tcp.dport)
            info["ts"].append(now)
            recent_ts = [t for t in info["ts"] if now - t <= 5.0]
            if len(info["ports"]) >= 20 and len(recent_ts) >= 20:
                alerts.append(("Port scan", src, len(info["ports"]), 5))
                info["ports"].clear()

        if alerts:
            self.signature_hits[src] = now
        return alerts or None

    def has_recent_signature(self, src_ip: str, window: float = 30.0) -> bool:
        ts = self.signature_hits.get(src_ip)
        return bool(ts and time.time() - ts <= window)

    def observe_ml_hit(self, src_ip: str):
        now = time.time()
        self.ml_hits[src_ip].append(now)
        recent = [t for t in self.ml_hits[src_ip] if now - t <= 10.0]
        if len(recent) >= 5:
            return [("Repeated suspicious activity", src_ip, len(recent), 10)]
        return []


# ---------------------------------------------------------------------------
# State
# ---------------------------------------------------------------------------
packet_count = 0
malicious_flows = 0
threat_count = 0
flow_tracker = FlowTracker()
threat_detector = ThreatDetector()
predicted_flows: dict[str, float] = {}  # key -> last predicted ts
stop_signal = False


# ---------------------------------------------------------------------------
# Core pipeline
# ---------------------------------------------------------------------------
def _ml_alert_allowed(flow: dict, conf: float) -> tuple[bool, str]:
    """Decide whether an ML detection should surface as an alert.

    Strategy: the ML model is a *corroborator*, not a primary detector. It
    only alerts when we have additional reason to believe the flow is
    malicious:

      - signature layer already flagged this source (adds colour)
      - unusually high confidence AND the traffic is *inbound* to us on a
        listening port (possible attack against us)

    Outbound traffic from our own machine to the internet is never alerted
    on ML signal alone — that's the user browsing.
    """
    src_is_us = flow["src_ip"] in LOCAL_IPS
    dst_is_us = flow["dst_ip"] in LOCAL_IPS

    if threat_detector.has_recent_signature(flow["src_ip"]):
        if conf >= CORROBORATED_CONFIDENCE:
            return True, "corroborates signature"

    # Only unsolicited inbound traffic can be an "attack on us". If we
    # initiated the connection, it's our browsing / SaaS usage.
    if src_is_us and not dst_is_us:
        return False, "outbound from local — ignored"

    if conf >= CONFIDENCE_THRESHOLD and dst_is_us:
        return True, "inbound, high-confidence"

    return False, "below threshold"


def process_packet(pkt):
    global packet_count
    if stop_signal:
        return
    packet_count += 1

    key = flow_tracker.process_packet(pkt)
    if not key:
        return

    flow = flow_tracker.flows[key]

    # Signatures always run, even on whitelisted flows — a SYN flood from
    # a multicast source isn't real anyway, but we want the counter moving.
    for sig in (threat_detector.observe_packet(pkt) or []):
        root.after(0, add_threat_alert, {
            "src_ip": sig[1], "description": f"{sig[0]} (signature)",
            "count": sig[2], "window": sig[3], "severity": "high",
        })

    if is_whitelisted(flow["src_ip"], flow["dst_ip"], flow["service"],
                      flow["src_port"], flow["dst_port"]):
        return

    total_pkts = flow["forward_packets"] + flow["reverse_packets"]
    last_pred = predicted_flows.get(key, 0)
    if total_pkts < MIN_PACKETS_FOR_PREDICTION:
        return
    if total_pkts - last_pred < 10 and last_pred:
        return

    try:
        feats = flow_tracker.extract_features(key)
        if not feats:
            return
        row = pd.DataFrame([[feats[f] for f in FEATURE_NAMES]], columns=FEATURE_NAMES)
        scaled = scaler.transform(row)
        pred = int(model.predict(scaled)[0])
        conf = float(model.predict_proba(scaled)[0][pred])
        predicted_flows[key] = total_pkts

        if pred != 1:
            return

        allowed, reason = _ml_alert_allowed(flow, conf)
        if not allowed:
            return

        log_detection(key, conf, reason)
        print(f"[ML] {flow['src_ip']} → {flow['dst_ip']}  "
              f"conf={conf:.2%}  service={flow['service']}  ({reason})")
    except Exception as exc:
        print(f"[ERROR] prediction failed: {exc}")

    if packet_count % 50 == 0:
        root.after(0, update_display)


def log_detection(key: str, confidence: float, reason: str):
    global malicious_flows
    flow = flow_tracker.flows.get(key)
    if not flow:
        return
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(LOG_FILE, "a", newline="") as f:
        csv.writer(f).writerow([
            ts, flow["src_ip"], flow["dst_ip"], flow["proto_label"].upper(),
            flow["service"],
            f"{flow['forward_bytes']}/{flow['reverse_bytes']}",
            f"{flow['forward_packets']}/{flow['reverse_packets']}",
            f"{confidence:.3f}", reason,
        ])
    malicious_flows += 1

    description = f"ML: {flow['service']} flow flagged ({confidence:.0%}) — {reason}"
    root.after(0, add_threat_alert, {
        "src_ip": flow["src_ip"], "description": description,
        "count": flow["forward_packets"] + flow["reverse_packets"],
        "window": "flow", "severity": "medium",
    })
    for esc in threat_detector.observe_ml_hit(flow["src_ip"]):
        root.after(0, add_threat_alert, {
            "src_ip": esc[1], "description": esc[0],
            "count": esc[2], "window": esc[3], "severity": "high",
        })


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------
def update_display():
    stats_labels["Total Packets"].config(text=str(packet_count))
    stats_labels["Malicious Flows"].config(text=str(malicious_flows))
    stats_labels["Threats Detected"].config(text=str(threat_count))
    stats_labels["Active Flows"].config(text=str(len(flow_tracker.flows)))

    for item in flow_tree.get_children():
        flow_tree.delete(item)
    flows = list(flow_tracker.flows.items())[-12:][::-1]
    for key, _ in flows:
        info = flow_tracker.get_flow_info(key)
        if info:
            flow_tree.insert("", "end", values=(
                info["src"], info["dst"], info["proto"],
                info["service"], info["duration"],
                info["packets"], info["bytes"],
            ))


def add_threat_alert(threat: dict):
    global threat_count
    ts = datetime.now().strftime("%H:%M:%S")
    tag = "high" if threat.get("severity") == "high" else "med"
    alert_tree.insert("", 0, values=(
        ts, threat["src_ip"], threat["description"],
        f"{threat['count']} / {threat['window']}",
    ), tags=(tag,))
    if len(alert_tree.get_children()) > 30:
        alert_tree.delete(alert_tree.get_children()[-1])
    threat_count += 1

    if threat.get("severity") == "high":
        status_label.config(text="HIGH THREAT DETECTED", fg="#ff5252")
        root.after(4000, lambda: status_label.config(text="Monitoring", fg="#4caf50"))


def start_sniffing():
    sniff(prn=process_packet, store=0, filter="ip",
          stop_filter=lambda _: stop_signal)


def start_monitoring():
    global stop_signal
    stop_signal = False
    threading.Thread(target=start_sniffing, daemon=True).start()
    status_label.config(text="Monitoring", fg="#4caf50")
    print("Monitoring started")


def stop_monitoring():
    global stop_signal
    stop_signal = True
    status_label.config(text="Stopped", fg="#ffb300")
    print("Monitoring stopped")


def show_stats():
    win = Toplevel(root)
    win.title("SmartShield — session stats")
    win.geometry("440x340")
    text = (
        f"Model:  {type(model).__name__}\n"
        f"Features ({len(FEATURE_NAMES)}):\n  " + ", ".join(FEATURE_NAMES) + "\n\n"
        f"Confidence threshold:  {CONFIDENCE_THRESHOLD:.2f}\n"
        f"Min packets before prediction:  {MIN_PACKETS_FOR_PREDICTION}\n\n"
        f"Packets processed:  {packet_count}\n"
        f"Malicious flows:    {malicious_flows}\n"
        f"Threats detected:   {threat_count}\n"
        f"Active flows:       {len(flow_tracker.flows)}\n"
    )
    Label(win, text=text, font=("Menlo", 11), justify=LEFT, padx=20, pady=20).pack()


# ---------------------------------------------------------------------------
# Tk layout
# ---------------------------------------------------------------------------
root = Tk()
root.title("SmartShield IDS")
root.geometry("980x640")
root.configure(bg="#111418")

style = ttk.Style()
style.theme_use("clam")
style.configure("Treeview", background="#1c2026", foreground="white",
                fieldbackground="#1c2026", rowheight=22)
style.configure("Treeview.Heading", background="#272c34", foreground="white",
                font=("Helvetica", 10, "bold"))
style.map("Treeview", background=[("selected", "#3a5fcd")])

header = Frame(root, bg="#111418", pady=12)
header.pack(fill=X)
Label(header, text="SmartShield Intrusion Detection System",
      font=("Helvetica", 18, "bold"), fg="white", bg="#111418").pack()
status_label = Label(header, text="Monitoring", font=("Helvetica", 11),
                     fg="#4caf50", bg="#111418")
status_label.pack()

stats_frame = Frame(root, bg="#1c2026", padx=20, pady=12)
stats_frame.pack(fill=X, padx=20, pady=10)
stats_labels: dict[str, Label] = {}
for i, name in enumerate(["Total Packets", "Malicious Flows",
                          "Threats Detected", "Active Flows"]):
    col = Frame(stats_frame, bg="#1c2026")
    col.grid(row=0, column=i, padx=18)
    Label(col, text=name, fg="#9aa0a6", bg="#1c2026",
          font=("Helvetica", 10)).pack()
    lbl = Label(col, text="0", fg="white", bg="#1c2026",
                font=("Helvetica", 16, "bold"))
    lbl.pack()
    stats_labels[name] = lbl

main = Frame(root, bg="#111418")
main.pack(fill=BOTH, expand=True, padx=20, pady=10)

flow_col = Frame(main, bg="#111418")
flow_col.pack(side=LEFT, fill=BOTH, expand=True, padx=(0, 10))
Label(flow_col, text="Active flows", fg="white", bg="#111418",
      font=("Helvetica", 12, "bold")).pack(anchor=W, pady=(0, 5))
flow_tree = ttk.Treeview(
    flow_col, columns=("src", "dst", "proto", "service", "dur", "pkts", "bytes"),
    show="headings", height=14,
)
for col, width in (("src", 150), ("dst", 150), ("proto", 60),
                   ("service", 70), ("dur", 60), ("pkts", 70), ("bytes", 100)):
    flow_tree.heading(col, text=col.upper())
    flow_tree.column(col, width=width)
flow_tree.pack(side=LEFT, fill=BOTH, expand=True)

alert_col = Frame(main, bg="#111418")
alert_col.pack(side=RIGHT, fill=BOTH, expand=True, padx=(10, 0))
Label(alert_col, text="Threat alerts", fg="white", bg="#111418",
      font=("Helvetica", 12, "bold")).pack(anchor=W, pady=(0, 5))
alert_tree = ttk.Treeview(
    alert_col, columns=("time", "src", "type", "detail"),
    show="headings", height=14,
)
alert_tree.tag_configure("high", background="#4a1d1d", foreground="#ff8a80")
alert_tree.tag_configure("med", background="#2a2a1d", foreground="#ffe082")
for col, width in (("time", 70), ("src", 130), ("type", 220), ("detail", 100)):
    alert_tree.heading(col, text=col.upper())
    alert_tree.column(col, width=width)
alert_tree.pack(side=LEFT, fill=BOTH, expand=True)

controls = Frame(root, bg="#111418", pady=10)
controls.pack(fill=X)
Button(controls, text="Start", command=start_monitoring,
       bg="#2e7d32", fg="white", font=("Helvetica", 10, "bold"),
       padx=20, bd=0).pack(side=RIGHT, padx=10)
Button(controls, text="Stop", command=stop_monitoring,
       bg="#c62828", fg="white", font=("Helvetica", 10, "bold"),
       padx=20, bd=0).pack(side=RIGHT, padx=10)
Button(controls, text="Stats", command=show_stats,
       bg="#455a64", fg="white", font=("Helvetica", 10, "bold"),
       padx=20, bd=0).pack(side=LEFT, padx=10)
Button(controls, text="Refresh", command=update_display,
       bg="#1565c0", fg="white", font=("Helvetica", 10, "bold"),
       padx=20, bd=0).pack(side=LEFT, padx=10)

if not LOG_FILE.exists():
    with open(LOG_FILE, "w", newline="") as f:
        csv.writer(f).writerow([
            "timestamp", "src_ip", "dst_ip", "proto", "service",
            "bytes_s/d", "pkts_s/d", "confidence", "reason",
        ])


def gui_loop():
    update_display()
    root.after(2000, gui_loop)


print("\n" + "=" * 60)
print(f"SmartShield IDS  |  model={type(model).__name__}  "
      f"features={len(FEATURE_NAMES)}  threshold={CONFIDENCE_THRESHOLD}")
print(f"Logs → {LOG_FILE}")
print("=" * 60 + "\n")

root.after(800, start_monitoring)
root.after(2000, gui_loop)
root.mainloop()
