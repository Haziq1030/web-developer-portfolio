import sys
import os
import joblib
import numpy as np
import mysql.connector
from urllib.parse import urlparse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_PATH = os.path.join(BASE_DIR, "model_secuscan.pkl")
SCALER_PATH = os.path.join(BASE_DIR, "scaler.pkl")

WHITELIST_DOMAINS = {
    "facebook.com",
    "google.com",
    "instagram.com",
    "linkedin.com",
    "microsoft.com",
    "apple.com",
    "youtube.com",
    "github.com",
    "wikipedia.org",
    ".edu.my",
    ".gov.my",
    ".edu",
}


def is_whitelisted_url(url):
    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower().rstrip(".")
    if parsed.scheme not in {"http", "https"} or not hostname:
        return False

    return any(
        hostname == domain or hostname.endswith("." + domain)
        if not domain.startswith(".")
        else hostname.endswith(domain)
        for domain in WHITELIST_DOMAINS
    )

def extract_features(url):
    """
    Extract 13 features from the URL for the machine-learning model.
    """
    parsed = urlparse(url)
    
    url_length = len(url)
    valid_url = 1 if parsed.scheme in ['http', 'https'] and parsed.netloc else 0
    at_symbol = 1 if '@' in url else 0
    
    sensitive_words = ['login', 'verify', 'update', 'account', 'banking', 'secure', 'signin', 'admin', 'bank']
    sensitive_words_count = sum(1 for word in sensitive_words if word in url.lower())
    
    path_length = len(parsed.path)
    isHttps = 1 if parsed.scheme == 'https' else 0
    
    nb_dots = url.count('.')
    nb_hyphens = url.count('-')
    nb_and = url.count('&')
    nb_or = url.count('|')
    nb_www = url.lower().count('www')
    nb_com = url.lower().count('.com')
    nb_underscore = url.count('_')
    
    return [
        url_length, valid_url, at_symbol, sensitive_words_count,
        path_length, isHttps, nb_dots, nb_hyphens, nb_and,
        nb_or, nb_www, nb_com, nb_underscore
    ]

def main():
    # -------------------------------------------------------------
    # 1. TANGKAP ARGUMENT DARI PHP
    # -------------------------------------------------------------
    if len(sys.argv) < 2:
        print("Error: URL diperlukan.")
        sys.exit(1)

    url_input = sys.argv[1]
    purpose = sys.argv[4] if len(sys.argv) >= 5 else "Personal"
    
    # Read user_id from PHP; use None (NULL) when it is missing or zero.
    user_id = None
    if len(sys.argv) >= 4:
        try:
            val = int(sys.argv[3])
            if val > 0:
                user_id = val
        except ValueError:
            user_id = None

    # -------------------------------------------------------------
    # 2. WHITELIST ATAU PREDIKSI MACHINE LEARNING
    # -------------------------------------------------------------
    if is_whitelisted_url(url_input):
        hasil_pemeriksaan = "Safe"
        tahap_ketepatan = "100.00%"
    else:
        model_path = MODEL_PATH if os.path.exists(MODEL_PATH) else os.path.join(BASE_DIR, "model.pkl")
        scaler_path = SCALER_PATH

        try:
            if not os.path.exists(model_path):
                raise FileNotFoundError(f"Model file not found: {model_path}")
            if not os.path.exists(scaler_path):
                raise FileNotFoundError(f"Scaler file not found: {scaler_path}")

            model = joblib.load(model_path)
            scaler = joblib.load(scaler_path)
        except Exception as e:
            print(f"Error loading ML model/scaler: {e}")
            sys.exit(1)

        features = extract_features(url_input)
        scaled_features = scaler.transform([features])
        prediction = model.predict(scaled_features)[0]
        probabilities = model.predict_proba(scaled_features)[0]
        confidence = float(np.max(probabilities) * 100)

        hasil_pemeriksaan = "Phishing" if prediction == 1 else "Safe"
        tahap_ketepatan = f"{confidence:.2f}%"

    # -------------------------------------------------------------
    # 4. SIMPAN KE DATABASE (secuscan_db)
    # -------------------------------------------------------------
    try:
        conn = mysql.connector.connect(
            host="localhost",
            user="root",
            password="",
            database="secuscan_db"
        )
        cursor = conn.cursor()

        sql = """
            INSERT INTO scan_logs (user_id, url, hasil_pemeriksaan, tahap_ketepatan, tujuan)
            VALUES (%s, %s, %s, %s, %s)
        """
        val = (user_id, url_input, hasil_pemeriksaan, tahap_ketepatan, purpose)

        cursor.execute(sql, val)
        conn.commit()  # Simpan perubahan secara kekal
        cursor.close()
        conn.close()

    except Exception as e:
        # Keep the error visible so database failures are easy to diagnose.
        print(f"Database Error: {e}")

    # Output akhir untuk dibaca oleh PHP
    print(f"Hasil: {hasil_pemeriksaan} | Ketepatan: {tahap_ketepatan}")

if __name__ == "__main__":
    main()