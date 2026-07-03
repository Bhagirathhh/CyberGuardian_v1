import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import joblib
import os
import pandas as pd

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

csv_path = os.path.join(BASE_DIR, "dataset", "phishing_dataset.csv")

df = pd.read_csv(csv_path)

X = df.drop("label", axis=1)
y = df["label"]

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X, y)

joblib.dump(model, "phishing_model.pkl")

print("Model Trained Successfully")