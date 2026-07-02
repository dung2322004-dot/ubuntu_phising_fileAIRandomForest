import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    classification_report
)

print("Loading dataset...")

df = pd.read_csv(
    "dataset_9criteria.csv"
)

print("\nDataset shape:")
print(df.shape)

print("\nLabel distribution:")
print(df["label"].value_counts())

# -----------------------------
# Features / Label
# -----------------------------

X = df.drop(
    "label",
    axis=1
)

y = df["label"]

# -----------------------------
# Train / Test Split
# -----------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\n========== TRAIN / TEST ==========")

print("Training samples :", len(X_train))
print("Testing samples  :", len(X_test))

print("\nTraining label distribution:")
print(y_train.value_counts())

print("\nTesting label distribution:")
print(y_test.value_counts())

# -----------------------------
# Train Random Forest
# -----------------------------

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(
    X_train,
    y_train
)

# -----------------------------
# Prediction
# -----------------------------

y_pred = model.predict(X_test)

# -----------------------------
# Accuracy
# -----------------------------

accuracy = accuracy_score(
    y_test,
    y_pred
)

print("\n========== ACCURACY ==========")

print(
    "Accuracy :",
    round(
        accuracy * 100,
        2
    ),
    "%"
)

# -----------------------------
# Confusion Matrix
# -----------------------------

cm = confusion_matrix(
    y_test,
    y_pred
)

tn, fp, fn, tp = cm.ravel()

print("\n========== CONFUSION MATRIX ==========")

print(cm)

print("\nTrue Negative :", tn)
print("False Positive:", fp)
print("False Negative:", fn)
print("True Positive :", tp)

# -----------------------------
# Precision Recall F1
# -----------------------------

print("\n========== CLASSIFICATION REPORT ==========")

print(
    classification_report(
        y_test,
        y_pred,
        target_names=[
            "Safe",
            "Phishing"
        ]
    )
)

# -----------------------------
# Save model
# -----------------------------

joblib.dump(
    model,
    "rf_9criteria.pkl"
)

print("\nModel saved -> rf_9criteria.pkl")
