# 🔐 SmartShield – Real-Time Intrusion Detection System (IDS)

**SmartShield** is a machine learning-based real-time Intrusion Detection System (IDS) that classifies network packets as malicious or normal using supervised learning algorithms. It combines live packet sniffing with a GUI dashboard to alert users in real-time.

---

## 📌 Features

- Real-time packet sniffing using **Scapy**
- ML models: **KNN, Random Forest, SVM, Decision Tree**
- GUI-based dashboard using **Tkinter**
- Real-time alerts with CSV logging
- Threshold-based popups for suspicious activity
- Full model evaluation using **Confusion Matrix, ROC, PR, Learning Curves**

---

## 🧠 Model Evaluation

| Model           | Accuracy (%) | AUC Score |
|----------------|--------------|-----------|
| KNN             | 91.2         | 0.89      |
| Random Forest   | 96.5         | 0.97      |
| SVM             | 93.7         | 0.91      |
| Decision Tree   | 90.1         | 0.88      |

### 📊 Confusion Matrix
![Confusion Matrix](images/confusion_matrix_rf.png)

### 📈 ROC Curve
![ROC Curve](images/roc_curve_all_models.png)

### 📉 Precision-Recall Curve
![PR Curve](images/pr_curve_all_models.png)

### 📚 Learning Curve
![Learning Curve](images/learning_curve_rf.png)

> Make sure to place all plots inside the `images/` directory in your repository.

---

## 🖥 GUI Preview

![SmartShield GUI](images/gui_demo.png)

- Live packet monitoring
- Realtime classification with alert banners
- Automatic CSV logging of suspicious packets

---

## 🛠 Tech Stack

- Python 3.x  
- Scikit-learn  
- Scapy  
- Tkinter  
- Joblib  
- Matplotlib / Seaborn

---

## 🧪 Installation

```bash
# Clone the repository
git clone https://github.com/TanishAhuja/SmartShield.git
cd SmartShield

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
