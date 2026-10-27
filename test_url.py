import joblib
import pandas as pd
from sklearn.preprocessing import StandardScaler

print("=== ENJIN PENGESAN SECUSCAN READY ===")

try:
    model = joblib.load("model_secuscan.pkl")
    scaler = joblib.load("scaler.pkl")
    print("🧠 AI model loaded successfully!")

    contoh_ciri_url = [[80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1]]
    scaled = scaler.transform(contoh_ciri_url)
    keputusan = model.predict(scaled)

    print("\n--- AI SCAN RESULT ---")
    if keputusan[0] == 1:
        print("🚨 WARNING: This is a PHISHING website! (Danger)")
    else:
        print("✅ CLEAN: This website is Safe/Legitimate.")

except FileNotFoundError:
    print("The model or scaler file was not found. Please run 'train_ai.py' first.")