import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib  # Library for saving the AI model

# 1. Load the dataset
nama_fail = "phishing_url_dataset.csv"
print("⏳ Preparing the SecuScan AI engine... Please wait...")
df = pd.read_csv(nama_fail)

# 2. Separate features (X) and labels (y)
X = df.drop(columns=['target'])
y = df['target']

# 3. Split the data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 4. Standardize the data for model stability
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# 5. Create and train the machine-learning model
print("\n🤖 The AI is learning phishing patterns...")
model = RandomForestClassifier(random_state=42)
model.fit(X_train_scaled, y_train)
print(" AI training complete!")

# 6. Save the model and scaler to persistent files
nama_fail_model = "model_secuscan.pkl"
nama_fail_scaler = "scaler.pkl"
joblib.dump(model, nama_fail_model)
joblib.dump(scaler, nama_fail_scaler)
print(f"📦 SUCCESS! The AI model was saved as: '{nama_fail_model}'")
print(f"📦 SUCCESS! The scaler was saved as: '{nama_fail_scaler}'")