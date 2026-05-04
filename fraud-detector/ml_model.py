import pandas as pd
import re
import math
from collections import Counter
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.utils import resample
from sklearn.metrics import accuracy_score
import joblib

# ----------------------------
# ENTROPY FUNCTION (REQUIRED)
# ----------------------------
def calculate_entropy(text):
    prob = [n_x / len(text) for x, n_x in Counter(text).items()]
    entropy = -sum(p * math.log2(p) for p in prob)
    return entropy


# ----------------------------
# FEATURE EXTRACTION
# ----------------------------
def extract_features(url):
    features = []

    # Length
    features.append(len(url))

    # Count special characters
    features.append(url.count("-"))
    features.append(url.count("."))
    features.append(url.count("/"))
    features.append(url.count("?"))

    # HTTPS
    features.append(1 if url.startswith("https") else 0)

    # Digit ratio
    digits = sum(c.isdigit() for c in url)
    features.append(digits / len(url) if len(url) > 0 else 0)

    # Suspicious TLD
    suspicious_tlds = ['xyz', 'top', 'club', 'tk', 'ml']
    tld = url.split('.')[-1]
    features.append(1 if tld in suspicious_tlds else 0)

    # Entropy
    features.append(calculate_entropy(url))

    # IP address detection
    ip_pattern = r'\d+\.\d+\.\d+\.\d+'
    features.append(1 if re.search(ip_pattern, url) else 0)

    # Keywords in URL
    keywords = ["login", "verify", "account", "bank", "secure"]
    features.append(sum(1 for k in keywords if k in url.lower()))

    return features


# ----------------------------
# LOAD DATASET
# ----------------------------
import os

base_dir = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(base_dir, "data", "url_dataset.csv")

data = pd.read_csv(file_path)

X = []
y = []

for url, label in zip(data["url"], data["label"]):
    features = extract_features(url)
    X.append(features)
    y.append(label)





print("Label distribution:")
print(data["label"].value_counts())


print("Duplicate URLs:", data["url"].duplicated().sum())

data = data.drop_duplicates(subset="url")


from sklearn.metrics import classification_report






# ----------------------------
# TRAIN / TEST SPLIT (FIRST)
# ----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ----------------------------
# BALANCE ONLY TRAINING DATA
# ----------------------------
train_df = pd.DataFrame(X_train)
train_df['label'] = y_train

majority = train_df[train_df.label == 0]
minority = train_df[train_df.label == 1]

minority_upsampled = resample(
    minority,
    replace=True,
    n_samples=len(majority),
    random_state=42
)

train_balanced = pd.concat([majority, minority_upsampled])

X_train = train_balanced.drop("label", axis=1).values
y_train = train_balanced["label"].values


# ----------------------------
# TRAIN MODEL (IMPROVED)
# ----------------------------
model = RandomForestClassifier(
    n_estimators=200,
    max_depth=10,
    min_samples_split=5,
    random_state=42
)

model.fit(X_train, y_train)

y_pred = model.predict(X_test)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))


# ----------------------------
# MODEL EVALUATION
# ----------------------------
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
print("Model Accuracy:", round(accuracy, 4))


# ----------------------------
# SAVE MODEL
# ----------------------------
joblib.dump(model, "phishing_model.pkl")

print("Model trained and saved successfully.")