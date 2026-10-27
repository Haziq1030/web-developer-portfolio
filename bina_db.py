import mysql.connector

try:
    # 1. Sambung ke MySQL Server XAMPP
    sambungan = mysql.connector.connect(
        host="localhost",
        user="root",
        password=""
    )
    
    if sambungan.is_connected():
        cursor = sambungan.cursor()
        
        # 2. Cipta Database SecuScan
        cursor.execute("CREATE DATABASE IF NOT EXISTS secuscan_db")
        print("✅ Database 'secuscan_db' detected/created successfully!")
        
        # 3. Masuk ke dalam database
        cursor.execute("USE secuscan_db")
        
        # 4. Cipta Jadual scan_logs
        bina_jadual = """
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            url VARCHAR(255) NOT NULL,
            hasil_pemeriksaan VARCHAR(50) NOT NULL,
            tahap_ketepatan VARCHAR(10) NOT NULL,
            tarikh_semak TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
        cursor.execute(bina_jadual)
        print("✅ 'scan_logs' table for URL logs detected/created successfully!")

        bina_jadual_aduan = """
        CREATE TABLE IF NOT EXISTS complaints (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT DEFAULT NULL,
            name VARCHAR(100) NOT NULL,
            email VARCHAR(150) NOT NULL,
            category VARCHAR(80) NOT NULL,
            message TEXT NOT NULL,
            status ENUM('New', 'In Progress', 'Resolved') DEFAULT 'New',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            INDEX (user_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """
        cursor.execute(bina_jadual_aduan)
        print("✅ 'complaints' table detected/created successfully!")
        
        cursor.close()
        sambungan.close()

except mysql.connector.Error as e:
    print(f"❌ Alamak, error semasa sambung ke MySQL: {e}")
    print("Please make sure MySQL is started in XAMPP!")