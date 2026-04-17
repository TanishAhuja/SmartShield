"""SmartShield — model training pipeline.

Trains 4 classifiers (Random Forest, KNN, SVM, Decision Tree) on the UNSW-NB15
dataset using a feature set that can be reproduced in real time by the live
packet sniffer. Saves the best model plus confusion matrices, ROC curves, a
feature-importance plot and a model-comparison chart for the resume writeup.
"""

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from joblib import dump
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    ConfusionMatrixDisplay,
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import train_test_split
from sklearn.neighbors import KNeighborsClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier

ROOT = Path(__file__).resolve().parent
DATA_PATH = ROOT / "dataset" / "UNSW_NB15_training-set.csv"
MODELS_DIR = ROOT / "models"
PLOTS_DIR = ROOT / "plots"
MODELS_DIR.mkdir(exist_ok=True)
PLOTS_DIR.mkdir(exist_ok=True)

# Stable encodings — the live sniffer must use these exact integer codes, so
# they are intentionally fixed (not derived from a LabelEncoder).
PROTO_MAP = {"tcp": 0, "udp": 1, "icmp": 2, "arp": 3, "other": 4}

SERVICE_MAP = {
    "-": 0, "dns": 1, "http": 2, "smtp": 3, "ftp": 4, "ftp-data": 5,
    "pop3": 6, "ssh": 7, "ssl": 8, "snmp": 9, "irc": 10, "radius": 11,
    "dhcp": 12, "other": 13,
}

STATE_MAP = {"INT": 0, "FIN": 1, "CON": 2, "REQ": 3, "RST": 4, "ACC": 5, "CLO": 6, "other": 7}

# Note: sttl/dttl are deliberately omitted. UNSW-NB15's lab setup produced
# TTL values (31/254/62/29) that do not appear on real hardware (typically
# 64 for macOS/Linux, 128 for Windows). Keeping sttl/dttl bakes a dataset
# artifact into the classifier and causes every live flow to be flagged.
FEATURES = [
    "dur", "proto", "service", "state",
    "spkts", "dpkts", "sbytes", "dbytes",
    "rate",
    "sload", "dload",
    "smean", "dmean",
    "sinpkt", "dinpkt",
]

print("Loading dataset:", DATA_PATH)
df = pd.read_csv(DATA_PATH)
print(f"  rows={len(df):,}  cols={df.shape[1]}")

df["proto"] = df["proto"].str.lower().map(PROTO_MAP).fillna(PROTO_MAP["other"]).astype(int)
df["service"] = df["service"].str.lower().map(SERVICE_MAP).fillna(SERVICE_MAP["other"]).astype(int)
df["state"] = df["state"].map(STATE_MAP).fillna(STATE_MAP["other"]).astype(int)

X = df[FEATURES].fillna(0).astype(float)
y = df["label"].astype(int)
attack_cat = df["attack_cat"].fillna("Normal")

print(f"  malicious ratio: {y.mean():.3f}")
print(f"  attack categories: {attack_cat.value_counts().to_dict()}")

X_train, X_test, y_train, y_test, cat_train, cat_test = train_test_split(
    X, y, attack_cat, test_size=0.2, random_state=42, stratify=y
)

scaler = StandardScaler()
X_train_s = scaler.fit_transform(X_train)
X_test_s = scaler.transform(X_test)

# class_weight='balanced' on the tree-based classifiers counteracts the ~55%
# malicious skew in UNSW-NB15 so the model doesn't default to "malicious" on
# ambiguous flows.
models = {
    "Random Forest": RandomForestClassifier(
        n_estimators=200, max_depth=20, class_weight="balanced",
        random_state=42, n_jobs=-1,
    ),
    "Decision Tree": DecisionTreeClassifier(
        max_depth=15, class_weight="balanced", random_state=42,
    ),
    "KNN": KNeighborsClassifier(n_neighbors=7, n_jobs=-1),
    "SVM": SVC(kernel="rbf", probability=True, class_weight="balanced", random_state=42),
}

results = {}
best_name, best_model, best_f1 = None, None, -1.0

for name, model in models.items():
    print(f"\nTraining {name}...")
    if name == "SVM":
        idx = np.random.RandomState(42).choice(len(X_train_s), 20000, replace=False)
        model.fit(X_train_s[idx], y_train.iloc[idx])
    else:
        model.fit(X_train_s, y_train)

    preds = model.predict(X_test_s)
    probs = model.predict_proba(X_test_s)[:, 1] if hasattr(model, "predict_proba") else None

    metrics = {
        "accuracy": accuracy_score(y_test, preds),
        "precision": precision_score(y_test, preds),
        "recall": recall_score(y_test, preds),
        "f1": f1_score(y_test, preds),
        "roc_auc": roc_auc_score(y_test, probs) if probs is not None else None,
    }
    results[name] = metrics
    print(f"  accuracy={metrics['accuracy']:.4f}  precision={metrics['precision']:.4f}  "
          f"recall={metrics['recall']:.4f}  f1={metrics['f1']:.4f}")

    cm = confusion_matrix(y_test, preds)
    ConfusionMatrixDisplay(cm, display_labels=["Normal", "Attack"]).plot(
        cmap="Blues", colorbar=False
    )
    plt.title(f"Confusion Matrix — {name}")
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / f"cm_{name.lower().replace(' ', '_')}.png", dpi=110)
    plt.close()

    if metrics["f1"] > best_f1:
        best_f1 = metrics["f1"]
        best_model = model
        best_name = name

print("\n" + "=" * 60)
print(f"Best model: {best_name}  (F1 = {best_f1:.4f})")
print("\nClassification report (binary):")
print(classification_report(y_test, best_model.predict(X_test_s),
                            target_names=["Normal", "Attack"]))

# Plots: model comparison, ROC curves, feature importance.
names_list = list(results.keys())
f1s = [results[n]["f1"] for n in names_list]
accs = [results[n]["accuracy"] for n in names_list]
x = np.arange(len(names_list))
plt.figure(figsize=(9, 5))
plt.bar(x - 0.2, accs, 0.4, label="Accuracy")
plt.bar(x + 0.2, f1s, 0.4, label="F1 Score")
plt.xticks(x, names_list)
plt.ylim(0.0, 1.0)
plt.title("Model Comparison")
plt.legend()
plt.grid(axis="y", alpha=0.3)
plt.tight_layout()
plt.savefig(PLOTS_DIR / "model_comparison.png", dpi=110)
plt.close()

plt.figure(figsize=(7, 6))
for name, model in models.items():
    if not hasattr(model, "predict_proba"):
        continue
    probs = model.predict_proba(X_test_s)[:, 1]
    fpr, tpr, _ = roc_curve(y_test, probs)
    plt.plot(fpr, tpr, label=f"{name} (AUC={results[name]['roc_auc']:.3f})")
plt.plot([0, 1], [0, 1], "k--", alpha=0.4)
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("ROC Curves")
plt.legend(loc="lower right")
plt.grid(alpha=0.3)
plt.tight_layout()
plt.savefig(PLOTS_DIR / "roc_curves.png", dpi=110)
plt.close()

if hasattr(best_model, "feature_importances_"):
    imp = pd.DataFrame({"feature": FEATURES, "importance": best_model.feature_importances_})
    imp_sorted = imp.sort_values("importance", ascending=False)
    print("\nFeature importance (best model):")
    print(imp_sorted.to_string(index=False))
    imp = imp.sort_values("importance", ascending=True)
    plt.figure(figsize=(8, 6))
    plt.barh(imp["feature"], imp["importance"])
    plt.title(f"Feature Importance — {best_name}")
    plt.tight_layout()
    plt.savefig(PLOTS_DIR / "feature_importance.png", dpi=110)
    plt.close()

dump(best_model, MODELS_DIR / "smartshield_model.pkl")
dump(scaler, MODELS_DIR / "scaler.pkl")
dump(FEATURES, MODELS_DIR / "feature_names.pkl")
dump({"proto": PROTO_MAP, "service": SERVICE_MAP, "state": STATE_MAP},
     MODELS_DIR / "encodings.pkl")

with open(MODELS_DIR / "metrics.json", "w") as f:
    json.dump({"best_model": best_name, "results": results, "features": FEATURES}, f, indent=2)

print(f"\nSaved best model ({best_name}) to {MODELS_DIR}")
print(f"Plots written to {PLOTS_DIR}")
