import os
import csv
import time
import datetime
import threading
from collections import deque
from tkinter import *
from tkinter import ttk, messagebox
from scapy.all import sniff, IP, TCP, UDP, ICMP
import joblib
import pandas as pd


model = joblib.load("models/smartshield_model.pkl")
scaler = joblib.load("models/scaler.pkl")


FEATURE_NAMES = ['proto', 'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss']
proto_map = {'tcp': 0, 'udp': 1, 'icmp': 2}
malicious_timestamps = deque(maxlen=20)

packet_count = 0
malicious_count = 0
threat_count = 0


root = Tk()
root.title("SmartShield IDS Dashboard")
root.geometry("700x500")

status_label = Label(root, text="🟢 Status: Monitoring", fg="green", font=("Arial", 14))
status_label.pack(pady=10)

stats_frame = Frame(root)
stats_frame.pack()

Label(stats_frame, text="📦 Packets Seen:").grid(row=0, column=0)
packet_label = Label(stats_frame, text="0")
packet_label.grid(row=0, column=1)

Label(stats_frame, text="🚨 Malicious:").grid(row=1, column=0)
malicious_label = Label(stats_frame, text="0")
malicious_label.grid(row=1, column=1)

Label(stats_frame, text="⚠️ Threats:").grid(row=2, column=0)
threat_label = Label(stats_frame, text="0")
threat_label.grid(row=2, column=1)


tree = ttk.Treeview(root, columns=("Time", "Proto", "Src", "Dst", "Summary"), show="headings", height=12)
tree.heading("Time", text="Time")
tree.heading("Proto", text="Proto")
tree.heading("Src", text="Source")
tree.heading("Dst", text="Destination")
tree.heading("Summary", text="Summary")
tree.pack(pady=10, fill="both", expand=True)


os.makedirs("logs", exist_ok=True)
csv_path = "logs/detections.csv"
if not os.path.exists(csv_path):
    with open(csv_path, "w", newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["Timestamp", "Source", "Destination", "Protocol", "Length", "Summary"])


def extract_features(packet):
    try:
        proto = 0
        if packet.haslayer(TCP): proto = 0
        elif packet.haslayer(UDP): proto = 1
        elif packet.haslayer(ICMP): proto = 2

        sbytes = len(packet)
        dbytes = len(packet)
        sttl = packet[IP].ttl if IP in packet else 0
        dttl = sttl
        sloss = 0
        dloss = 0
        return [proto, sbytes, dbytes, sttl, dttl, sloss, dloss]
    except:
        return None


def log_alert(packet):
    global malicious_count, threat_count

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    src = packet[IP].src if IP in packet else "N/A"
    dst = packet[IP].dst if IP in packet else "N/A"
    proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "ICMP"
    length = len(packet)
    summary = packet.summary()

    with open(csv_path, "a", newline='') as f:
        writer = csv.writer(f)
        writer.writerow([timestamp, src, dst, proto, length, summary])

    tree.insert("", "end", values=(timestamp, proto, src, dst, summary))
    malicious_count += 1
    malicious_label.config(text=str(malicious_count))

  
    now = time.time()
    malicious_timestamps.append(now)
    recent = [t for t in malicious_timestamps if now - t <= 1]

    if len(recent) >= 20:
        threat_count += 1
        threat_label.config(text=str(threat_count))
        status_label.config(text="🔴 THREAT DETECTED!", fg="red")
        root.after(3000, lambda: status_label.config(text="🟢 Status: Monitoring", fg="green"))
        messagebox.showwarning("⚠️ Threat Detected", "10+ malicious packets detected in 2 seconds!")


def handle_packet(packet):
    global packet_count
    packet_count += 1
    packet_label.config(text=str(packet_count))

    features = extract_features(packet)
    if not features:
        return

    features_df = pd.DataFrame([features], columns=FEATURE_NAMES)
    features_scaled = scaler.transform(features_df)
    prediction = model.predict(features_scaled)[0]

    if prediction == 1:
        log_alert(packet)


def start_sniffing():
    sniff(prn=handle_packet, store=0, filter="ip")

sniff_thread = threading.Thread(target=start_sniffing)
sniff_thread.daemon = True
sniff_thread.start()


root.mainloop()
