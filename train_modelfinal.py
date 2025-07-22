import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.neighbors import KNeighborsClassifier
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, roc_curve, auc, precision_recall_curve
from sklearn.model_selection import train_test_split, learning_curve
from joblib import dump
import os

df = pd.read_csv('dataset/UNSW_NB15_training-set.csv')
# df2 = pd.read_csv('dataset/UNSW_NB15_testing-set.csv')
# df = pd.concat([df1, df2], ignore_index=True)


encoder = LabelEncoder()
df['proto'] = encoder.fit_transform(df['proto'])

selected_features = ['proto', 'sbytes', 'dbytes', 'sttl', 'dttl', 'sloss', 'dloss', 'label']
df = df[selected_features]


X = df.drop('label', axis=1)
y = df['label']
x_train, x_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

scaler = StandardScaler()
x_train_scaled = scaler.fit_transform(x_train)
x_test_scaled = scaler.transform(x_test)


models = {
    "Random Forest": RandomForestClassifier(n_estimators=100, random_state=42),
    "KNN": KNeighborsClassifier(n_neighbors=5),
    "SVM": SVC(kernel='rbf', probability=True),
    "Decision Tree": DecisionTreeClassifier(random_state=42)
}

best_model = None
best_accuracy = 0
accuracies = {}
conf_matrices = {}

os.makedirs("models", exist_ok=True)
os.makedirs("plots", exist_ok=True)

print("\n🔍 Accuracy Scores:")

for name, model in models.items():
    model.fit(x_train_scaled, y_train)
    preds = model.predict(x_test_scaled)
    acc = accuracy_score(y_test, preds)
    print(f"{name}: {acc:.4f}")
    accuracies[name] = acc
    conf_matrices[name] = confusion_matrix(y_test, preds)
    dump(model, f"models/{name.replace(' ', '_').lower()}.pkl")

    if acc > best_accuracy:
        best_accuracy = acc
        best_model = model
        best_model_name = name


dump(best_model, "models/smartshield_model.pkl")
dump(scaler, "models/scaler.pkl")

print("\n🧾 Classification Report (Best Model):")
print(classification_report(y_test, best_model.predict(x_test_scaled)))
print(f"\n✅ Best Model: {best_model_name} ({best_accuracy:.4f}) saved in models/ folder.")

plt.figure(figsize=(10,6))
plt.bar(accuracies.keys(), accuracies.values(), color='skyblue')
plt.title('Model Accuracy Comparison')
plt.ylabel('Accuracy')
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig('plots/model_accuracy_comparison.png')
plt.close()


for name, cm in conf_matrices.items():
    plt.figure(figsize=(5,4))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
    plt.title(f'{name} - Confusion Matrix')
    plt.xlabel('Predicted')
    plt.ylabel('Actual')
    plt.tight_layout()
    plt.savefig(f'plots/conf_matrix_{name.replace(" ", "_").lower()}.png')
    plt.close()


for name, model in models.items():
    if hasattr(model, "predict_proba"):
        probs = model.predict_proba(x_test_scaled)[:, 1]
    else:
        probs = model.decision_function(x_test_scaled)
        probs = (probs - probs.min()) / (probs.max() - probs.min())  

    fpr, tpr, _ = roc_curve(y_test, probs)
    precision, recall, _ = precision_recall_curve(y_test, probs)

    plt.figure()
    plt.plot(fpr, tpr, label=f"{name} (AUC = {auc(fpr, tpr):.2f})")
    plt.plot([0, 1], [0, 1], linestyle='--')
    plt.title(f"ROC Curve - {name}")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.legend()
    plt.tight_layout()
    plt.savefig(f"plots/roc_{name.replace(' ', '_').lower()}.png")
    plt.close()

    plt.figure()
    plt.plot(recall, precision, label=name)
    plt.title(f"Precision-Recall Curve - {name}")
    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.tight_layout()
    plt.savefig(f"plots/pr_{name.replace(' ', '_').lower()}.png")
    plt.close()


train_sizes, train_scores, test_scores = learning_curve(best_model, x_train_scaled, y_train, cv=5, scoring='accuracy', train_sizes=np.linspace(0.1, 1.0, 10))
train_scores_mean = np.mean(train_scores, axis=1)
test_scores_mean = np.mean(test_scores, axis=1)

plt.figure(figsize=(8, 5))
plt.plot(train_sizes, train_scores_mean, label="Training Score")
plt.plot(train_sizes, test_scores_mean, label="Validation Score")
plt.title(f"Learning Curve - {best_model_name}")
plt.xlabel("Training Set Size")
plt.ylabel("Accuracy")
plt.legend()
plt.grid(True)
plt.tight_layout()
plt.savefig(f"plots/learning_curve_{best_model_name.replace(' ', '_').lower()}.png")
plt.close()

print("\n📊 All graphs, ROC, PR curves, and learning curve saved to 'plots/' folder for report use.")
