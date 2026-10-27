import pandas as pd

nama_fail = "phishing_url_dataset.csv"

try:
    # Baca data
    df = pd.read_csv(nama_fail)
    print("=== SECUSCAN: ANALISIS DATASET ===")
    
    # 1. Kira jumlah data
    print(f"Total baris data (URL): {df.shape[0]}")
    print(f"Total kolum ciri (Features): {df.shape[1]}")
    
    # 2. Senaraikan nama kolum satu per satu
    print("\n--- Senarai 14 Ciri Heuristik & Target ---")
    for i, kolum in enumerate(df.columns, 1):
        print(f"{i}. {kolum}")
        
except FileNotFoundError:
    print("Fail CSV tidak dijumpai!")