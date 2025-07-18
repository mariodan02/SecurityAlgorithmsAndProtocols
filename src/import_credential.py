# File: import_credential.py
# Posizionalo nella cartella 'src' ed eseguilo con 'python import_credential.py'

import os
from pathlib import Path

# Assicurati che i moduli del progetto siano importabili
import sys
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from wallet.student_wallet import AcademicStudentWallet, WalletConfiguration, CredentialStorage
    from credentials.models import AcademicCredential
except ImportError as e:
    print(f"❌ Errore di importazione: {e}")
    print("Assicurati di eseguire questo script dalla directory 'src' del progetto.")
    sys.exit(1)

# --- CONFIGURAZIONE ---
# Modifica questi valori se necessario
WALLET_NAME = "studente_mariorossi"
WALLET_PASSWORD = "Unisa2025"  # <-- INSERISCI QUI LA TUA PASSWORD
CREDENTIAL_FILE_PATH = "./wallets/studente_mariorossi/a6828d88-e609-4870-bb0f-19674a5bfa74.json" # <-- INSERISCI IL NOME CORRETTO DEL FILE

def main():
    """
    Script per importare una credenziale accademica da un file JSON
    all'interno di un AcademicStudentWallet esistente.
    """
    print("🚀 Avvio script di importazione credenziale...")

    wallet_storage_path = f"./wallets/{WALLET_NAME}"
    credential_path = Path(CREDENTIAL_FILE_PATH)

    # 1. Verifica che i file necessari esistano
    if not credential_path.exists():
        print(f"❌ Errore: File della credenziale non trovato in '{CREDENTIAL_FILE_PATH}'")
        return

    # 2. Carica la credenziale dal file JSON
    print(f"📄 Caricamento credenziale da: {credential_path.name}")
    try:
        credential_json = credential_path.read_text(encoding='utf-8')
        credential_to_import = AcademicCredential.from_json(credential_json)
        print("✅ Credenziale caricata e validata con successo.")
    except Exception as e:
        print(f"❌ Errore durante la lettura o il parsing del file JSON: {e}")
        return

    # 3. Inizializza e sblocca il wallet
    print(f"🔐 Accesso al wallet: {WALLET_NAME}")
    config = WalletConfiguration(
        wallet_name=WALLET_NAME,
        storage_path=wallet_storage_path,
        storage_mode=CredentialStorage.ENCRYPTED_LOCAL
    )
    wallet = AcademicStudentWallet(config)

    if not wallet.unlock_wallet(WALLET_PASSWORD):
        print("❌ Sblocco del wallet fallito. Controlla la password.")
        return
    
    print(f"🔓 Wallet sbloccato. Credenziali attuali: {len(wallet.credentials)}")

    # 4. Aggiungi la credenziale al wallet
    print("📥 Aggiunta della nuova credenziale al wallet...")
    try:
        storage_id = wallet.add_credential(credential_to_import, tags=["importata"])
        print("✅ Credenziale aggiunta con successo!")
        print(f"   ID di archiviazione nel wallet: {storage_id}")
    except Exception as e:
        print(f"❌ Errore durante l'aggiunta della credenziale al wallet: {e}")
        return
        
    # 5. Blocca il wallet per salvare le modifiche in modo sicuro
    wallet.lock_wallet()

    print("\n🎉 Processo di importazione completato.")
    print("Ora, rieseguendo il tuo script originale, dovresti vedere 'Trovate 1 credenziali'.")


if __name__ == "__main__":
    # Assicurati di inserire la password corretta prima di eseguire
    if WALLET_PASSWORD == "1234":
        print("⚠️  ATTENZIONE: Modifica la variabile 'WALLET_PASSWORD' nello script con la tua password reale.")
    else:
        main()