import os
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib

# Base Directory Setup (CyberGuardian_v1 root folder tak pahuchega)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Dataset aur Model Save karne ke paths set karein
csv_path = os.path.join(BASE_DIR, "dataset", "phishing_dataset.csv")
model_save_path = os.path.join(BASE_DIR, "phishing_model.pkl") # 👈 Root me save karne ke liye

print("🔄 Loading dataset...")
# 👈 yahan 'on_bad_lines' add kiya hai taaki error wali lines skip ho sakein
df = pd.read_csv(csv_path, on_bad_lines='skip') 

print(f"📊 Dataset loaded successfully with {df.shape[0]} rows.")

# Features (X) aur Target Label (y) split karein
X = df.drop("label", axis=1)
y = df["label"]

print("🤖 Training the Random Forest Model (This might take a moment)...")
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

# Model Fitting
model.fit(X, y)

# Model ko seedha root directory me save karein taaki app.py access kar sake
joblib.dump(model, model_save_path)

print(f"✅ Model Trained & Saved Successfully at: {model_save_path}")