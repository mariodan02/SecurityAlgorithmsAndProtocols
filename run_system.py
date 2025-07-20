# =============================================================================
# RUNNER PRINCIPALE AGGIORNATO
# File: run_system.py
# Sistema Credenziali Accademiche Decentralizzate
# VERSIONE CONSOLIDATA (senza credential_blockchain_api.py separato)
# =============================================================================

import os
import sys
import threading
import time
from pathlib import Path
import uvicorn

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def main():
    """Avvia tutti i server del sistema con architettura consolidata."""
    print("PROJECT WORK - SISTEMA CREDENZIALI ACCADEMICHE")
    print("GRUPPO 19")

    if not check_system_requirements():
        print("❌ Requisiti non soddisfatti. Verifica la struttura del progetto.")
        sys.exit(1)

    try:
        from src.pki.ocsp_responder import app as ocsp_app, HOST as OCSP_HOST, PORT as OCSP_PORT
        from src.web.dashboard import AcademicCredentialsDashboard
        from src.communication.secure_server import AcademicCredentialsSecureServer, ServerConfiguration
        print("✅ Import moduli riuscito")
    except ImportError as e:
        print(f"❌ Errore import: {e}")
        print("💡 Assicurati che tutti i moduli siano presenti e installati")
        sys.exit(1)

    def run_secure_server_consolidated():
        """Avvia il server sicuro consolidato con API blockchain integrate."""
        try:
            config = ServerConfiguration(
                host="localhost",
                port=8443,
                ssl_enabled=True,
                blockchain_rpc_url="http://127.0.0.1:8545"  # Ganache locale
            )
            server = AcademicCredentialsSecureServer(config)
            server.run()
        except Exception as e:
            print(f"❌ Errore secure server consolidato: {e}")

    def run_dashboard():
        """Avvia la dashboard web."""
        try:
            time.sleep(2)  # Attende l'avvio degli altri server
            print("\n🌐 Inizializzazione Dashboard Web...")

            from src.web.dashboard import _dashboard_instance
            dashboard = _dashboard_instance or AcademicCredentialsDashboard()

            print("🌐 Dashboard pronta su: http://localhost:8000")
            print("\n👥 Utenti demo disponibili:")
            print("   🎓 issuer_rennes (password: Unisa2025) - Emette credenziali")
            print("   🔍 verifier_unisa (password: Unisa2025) - Verifica credenziali") 
            print("   👤 studente_mariorossi (password: Unisa2025) - Portafoglio studente")
            print("\n🛑 Premi Ctrl+C per fermare il sistema")
            dashboard.run()
        except Exception as e:
            print(f"❌ Errore dashboard: {e}")

    def run_ocsp_responder():
        """Avvia il servizio OCSP."""
        try:
            uvicorn.run(
                ocsp_app,
                host=OCSP_HOST,
                port=OCSP_PORT,
                log_level="warning"
            )
        except Exception as e:
            print(f"❌ Errore OCSP responder: {e}")

    def show_startup_summary():
        """Mostra un riepilogo dei servizi avviati."""
        time.sleep(1)
        print("SISTEMA AVVIATO CORRETTAMENTE")
        print("📊 Servizi attivi:")
        print("   🌐 Dashboard Web:           http://localhost:8000")
        print("   🔒 API Sicure Consolidate:  https://localhost:8443")
        print("   🔐 OCSP Responder:          http://localhost:3000")
        print("=" * 60)

    # Definisce i thread per i servizi
    threads = [
        threading.Thread(target=run_secure_server_consolidated, daemon=True, name="SecureServer"),
        threading.Thread(target=run_ocsp_responder, daemon=True, name="OCSP"),
        threading.Thread(target=run_dashboard, daemon=True, name="Dashboard"),
        threading.Thread(target=show_startup_summary, daemon=True, name="Summary")
    ]

    # Avvia tutti i thread
    for t in threads:
        t.start()

    try:
        # Mantiene il processo principale attivo
        while any(t.is_alive() for t in threads if t.name != "Summary"):
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n🛑 Fermando il sistema...")
        print("✅ Sistema terminato correttamente")

def check_system_requirements():
    """Verifica i requisiti del sistema."""
    print("🔍 Verifica requisiti del sistema...")
    
    required_dirs = [
        "src/web",
        "src/credentials", 
        "src/communication",
        "src/pki",
        "src/crypto",
        "src/blockchain"  # Aggiunto controllo blockchain
    ]

    optional_dirs = [
        "certificates",
        "keys", 
        "logs"
    ]

    missing_dirs = []
    for dir_path in required_dirs:
        if not Path(dir_path).exists():
            missing_dirs.append(dir_path)
            print(f"   ❌ {dir_path} - MANCANTE (richiesto)")
        else:
            print(f"   ✅ {dir_path}")

    for dir_path in optional_dirs:
        if Path(dir_path).exists():
            print(f"   ✅ {dir_path} (opzionale)")
        else:
            print(f"   ⚠️ {dir_path} - MANCANTE (opzionale)")

    # Verifica file critici
    critical_files = [
        "src/blockchain/blockchain_service.py",
        "src/communication/secure_server.py", 
        "src/web/dashboard.py"
    ]

    missing_files = []
    for file_path in critical_files:
        if not Path(file_path).exists():
            missing_files.append(file_path)
            print(f"   ❌ {file_path} - MANCANTE (critico)")
        else:
            print(f"   ✅ {file_path}")

    if missing_dirs:
        print(f"\n❌ Directory richieste mancanti:")
        for dir_path in missing_dirs:
            print(f"   - {dir_path}")
        return False

    if missing_files:
        print(f"\n❌ File critici mancanti:")
        for file_path in missing_files:
            print(f"   - {file_path}")
        return False

    # Verifica Python packages (opzionale)
    try:
        import fastapi, uvicorn, cryptography, web3
        print("   ✅ Dipendenze Python principali presenti")
    except ImportError as e:
        print(f"   ⚠️ Alcune dipendenze Python potrebbero mancare: {e}")

    print("✅ Requisiti del sistema verificati")
    return True

def show_help():
    """Mostra informazioni di aiuto."""
    print("""
🌐 SERVIZI:
    • Dashboard Web: http://localhost:8000
    • API Sicure: https://localhost:8443  
    • OCSP: http://localhost:3000

👥 UTENTI DEMO:
    • issuer_rennes - Emissione credenziali
    • verifier_unisa - Verifica credenziali
    • studente_mariorossi - Portafoglio studente
    (Password: Unisa2025 per tutti)

    """)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ["--help", "-h", "help"]:
        show_help()
    else:
        main()