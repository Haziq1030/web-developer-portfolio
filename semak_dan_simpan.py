import joblib
import mysql.connector

print("=== SISTEM INTEGRASI SECUSCAN (AI + DATABASE) ===")

try:
    # 1. Connect to the XAMPP MySQL database
    db = mysql.connector.connect(
        host="localhost",
        user="root",
        password="",
        database="secuscan_db"
    )
    cursor = db.cursor()
    print("🔌 Connected to database 'secuscan_db' successfully!")

    # 2. Load the AI model (.pkl)
    model = joblib.load("model_secuscan.pkl")
    print("🧠 AI model activated successfully!")

    # 3. Simulate a user entering a suspicious URL
    url_diuji = "http://maybank2u-secure-login-update.com/login"
    tahap_ketepatan = "91.57%"
    
    # Letakkan 13 ciri heuristik URL tersebut (Contoh: URL panjang, tiada @, dll)
    ciri_heuristik = [[120, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 1]]

    # 4. Let the AI make a decision
    ramalan = model.predict(ciri_heuristik)
    
    if ramalan[0] == 1:
        hasil = "Phishing"
        print(f"\n🚨 AI RESULT: This URL is {hasil}!")
    else:
        hasil = "Safe"
        print(f"\n✅ AI RESULT: This URL is {hasil}.")

    # 5. SQL: Insert the scan result into the scan_logs table
    sql = "INSERT INTO scan_logs (url, hasil_pemeriksaan, tahap_ketepatan) VALUES (%s, %s, %s)"
    nilai = (url_diuji, hasil, tahap_ketepatan)
    
    cursor.execute(sql, nilai)
    db.commit() # Commit so the record is persisted in the database
    
    print("💾 RECORD SAVED TO THE XAMPP DATABASE SUCCESSFULLY!")

    # Tutup sambungan
    cursor.close()
    db.close()

except mysql.connector.Error as e:
    print(f"❌ Error Database: {e}")
except FileNotFoundError:
    print("❌ Error: The 'model_secuscan.pkl' file is missing!")