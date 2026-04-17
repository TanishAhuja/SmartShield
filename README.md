# SmartShield — ML-Powered Intrusion Detection System

SmartShield is a lightweight real-time network intrusion detection system (IDS)
that combines a **supervised machine-learning classifier** trained on the
UNSW-NB15 dataset with a **signature / heuristic layer** for well-known attack
patterns. It captures live traffic, groups packets into bidirectional flows,
computes a 17-feature vector per flow and surfaces alerts through a Tkinter
dashboard.

> This is a college / learning project. The goal is not to replace an
> enterprise IDS but to demonstrate an end-to-end ML security pipeline —
> dataset → feature engineering → model comparison → deployment.

---

## Highlights

- **Live packet capture** with `scapy` and bidirectional flow tracking.
- **4 ML models compared** — Random Forest (selected), Decision Tree, KNN, SVM.
- **15 engineered features** that are reproducible from raw packets, chosen to
  match the most predictive columns in UNSW-NB15 while avoiding known dataset
  artifacts (see note on TTL below).
- **Signature layer** catches SYN floods and port scans even if the model
  misses them.
- **Whitelist filter** suppresses obvious benign traffic (loopback,
  link-local, multicast, intra-LAN DNS/DHCP) before the model even sees it.
- **Dark-mode Tkinter dashboard** showing active flows, threat alerts and live
  stats. CSV detection logs for offline analysis.

---

## Results

Random Forest was selected based on F1 score on the held-out 20% split:

| Model          | Accuracy | Precision | Recall | F1     | ROC-AUC |
|----------------|----------|-----------|--------|--------|---------|
| Random Forest  | 0.9405   | 0.9711    | 0.9194 | 0.9445 | ~0.98   |
| Decision Tree  | 0.9345   | 0.9730    | 0.9063 | 0.9384 | —       |
| KNN            | 0.9307   | 0.9608    | 0.9113 | 0.9354 | —       |
| SVM            | 0.8674   | 0.9700    | 0.7835 | 0.8668 | —       |

Plots: [`plots/model_comparison.png`](plots/model_comparison.png),
[`plots/roc_curves.png`](plots/roc_curves.png),
[`plots/feature_importance.png`](plots/feature_importance.png), and
per-model confusion matrices in `plots/cm_*.png`.

---

## Architecture

SmartShield uses a **three-layer defence-in-depth** design. The ML model is
deliberately positioned as a *corroborator*, not a primary detector — which
was the single biggest fix that eliminated false positives on real traffic.

```
 every packet
      │
      ▼
┌──────────────┐  ┌────────────────────────────────────────────────────┐
│ FlowTracker  │  │ Layer 1 — WHITELIST                                │
│ (bidir flows)│─▶│ loopback / multicast / broadcast / outbound HTTPS  │
└──────┬───────┘  │ / intra-LAN mDNS / SSDP / NetBIOS / DHCP / DNS.    │
       │          │ Drops ~95% of routine traffic before scoring.      │
       │          └────────────────────────────────────────────────────┘
       │
       ├──────▶  Layer 2 — SIGNATURES (primary alerts)
       │         ────────────────────────────────────
       │         • SYN flood  : ≥50 SYN-no-ACK from one src in 2 s
       │         • Port scan  : ≥20 unique dst ports from one src in 5 s
       │         → high-severity alert, no ML needed.
       │
       ▼
┌──────────────────┐   ┌─────────────────────────────────────────────┐
│ Random Forest    │──▶│ Layer 3 — ML CORROBORATOR                   │
│ (15 features)    │   │ Alerts only if EITHER:                      │
└──────────────────┘   │   • source already has a recent signature   │
                       │     (conf ≥ 0.80 — adds context), OR        │
                       │   • inbound to us at conf ≥ 0.95            │
                       │     (possible unsolicited attack).          │
                       │ Outbound from our machine → NEVER alerted   │
                       │ on ML alone (that's the user browsing).     │
                       └──────────────────────┬──────────────────────┘
                                              ▼
                               Tkinter dashboard + CSV log
```

---

## Feature set

These 15 features are extracted in real time from live packets and exactly
mirror the columns used during training:

| Feature | Meaning |
|---|---|
| `dur` | Flow duration (s) |
| `proto` | Encoded protocol (tcp/udp/icmp/arp/other) |
| `service` | Encoded app-layer service (from dst port) |
| `state` | Derived TCP state (INT/FIN/CON/REQ/RST/…) |
| `spkts` / `dpkts` | Packets source→dest / dest→source |
| `sbytes` / `dbytes` | Bytes source→dest / dest→source |
| `rate` | Total packets per second |
| `sload` / `dload` | Bits per second in each direction |
| `smean` / `dmean` | Mean packet size in each direction |
| `sinpkt` / `dinpkt` | Mean inter-packet interval (ms) |

**TTL features were intentionally dropped.** UNSW-NB15's normal traffic has
TTL values of 31, 254, 62 (from the dataset author's lab hardware), whereas
real-world machines typically use TTL=64 (macOS/Linux) or 128 (Windows).
Keeping `sttl`/`dttl` — the single highest-importance features — embeds a
dataset artifact that causes *every* live flow to be classified as an attack.
Removing them reduces benchmark F1 by ~0.002 but restores real-world
generalization.

Categorical features use a **fixed vocabulary** (`models/encodings.pkl`) so
that training and inference produce identical integer codes — this was a
subtle bug in an earlier iteration where `LabelEncoder` at training time
produced different codes than the live capture path.

---

## Why these design choices?

1. **Fixed encodings for `proto` / `service` / `state`.** A `LabelEncoder`
   fitted on training strings produces arbitrary integer IDs that a live
   sniffer cannot reproduce. Using an explicit vocabulary guarantees
   train-serve parity.
2. **`class_weight="balanced"`.** UNSW-NB15 is ~55% attack traffic but real
   networks are far quieter. Balancing counteracts this label skew so the
   classifier doesn't default to "attack" on ambiguous flows.
3. **Minimum 8 packets before prediction.** Training rows are completed
   flows; predicting after 1–2 packets forces the model far outside its
   training distribution and causes false positives.
4. **Confidence threshold = 0.90.** Only high-confidence attacks become
   alerts. Lower confidences are logged but not surfaced.
5. **Whitelist + signature layer.** The ML model is the *generalist*;
   signatures handle the textbook cases (SYN flood, port scan) that are
   trivial to detect precisely. The whitelist filters out loopback, mDNS,
   DHCP and other LAN chatter that has no business being scored.

---

## Usage

```bash
# 1. Install deps
python -m venv venv
source venv/bin/activate
pip install scapy scikit-learn joblib pandas numpy matplotlib

# 2. Train models + produce plots (uses dataset/UNSW_NB15_training-set.csv)
python train_model.py

# 3. Run the live dashboard (needs root/admin for raw packet capture)
sudo venv/bin/python smartshield_dashboard.py
```

Live detections stream to `logs/detections.csv`.

---

## Attacks it can demonstrate defending against

- **SYN flood / DoS** — detected by the signature layer and the model.
- **Port scans (nmap)** — signature layer triggers after ≥15 distinct ports
  in 5s; the model corroborates via low-`dur`, high-`rate` flows.
- **Exploits / Fuzzers / Reconnaissance** (UNSW-NB15 categories) — the model
  flags flows whose byte/packet/TTL/timing signatures match training data.
- **Generic brute-force patterns** — elevated alerts when the same source IP
  triggers ≥5 ML hits in 10 seconds.

---

## Project structure

```
SmartShield/
├── dataset/                         # UNSW-NB15 train + test CSVs
├── models/                          # trained model, scaler, encodings
├── plots/                           # confusion matrices, ROC, comparisons
├── logs/                            # live detections.csv
├── train_model.py                   # training pipeline (4 classifiers)
├── smartshield_dashboard.py         # live sniffer + Tkinter GUI
├── evaluate_models.py               # post-hoc evaluation utilities
└── README.md
```

---

## Dataset

[UNSW-NB15](https://research.unsw.edu.au/projects/unsw-nb15-dataset) — a
modern benchmark IDS dataset from the Cyber Range Lab of UNSW Canberra.
Covers 9 attack families (DoS, Exploits, Generic, Fuzzers, Reconnaissance,
Analysis, Backdoor, Shellcode, Worms) plus Normal traffic.
