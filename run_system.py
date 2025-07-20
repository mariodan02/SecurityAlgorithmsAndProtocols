# =============================================================================
# RUNNER PRINCIPALE
# File: run_system.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

import os
import sys
import threading
import time
from pathlib import Path
import uvicorn

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def main():
    """Avvia tutti i server del sistema."""
    print("PROJECT WORK")
    print("GRUPPO 19")

    if not check_system_requirements():
        print("Requisiti non soddisfatti. Verifica la struttura del progetto.")
        sys.exit(1)

    print("\n🔧 Avvio sistema completo...")

    try:
        from src.pki.ocsp_responder import app as ocsp_app, HOST as OCSP_HOST, PORT as OCSP_PORT
        from src.web.dashboard import AcademicCredentialsDashboard
        from src.communication.secure_server import AcademicCredentialsSecureServer, ServerConfiguration
        print("Import moduli riuscito")
    except ImportError as e:
        print(f"Errore import: {e}")
        sys.exit(1)

    def run_secure_server():
        try:
            print("\nInizializzazione Secure Server...")
            config = ServerConfiguration(
                host="localhost",
                port=8443,
                ssl_enabled=True
            )
            server = AcademicCredentialsSecureServer(config)
            print("🔒 Secure Server pronto su: https://localhost:8443")
            server.run()
        except Exception as e:
            print(f"Errore secure server: {e}")

    def run_dashboard():
        try:
            time.sleep(2) # Attende l'avvio degli altri server
            print("\nInizializzazione Dashboard...")

            from src.web.dashboard import _dashboard_instance
            dashboard = _dashboard_instance or AcademicCredentialsDashboard()


            dashboard = AcademicCredentialsDashboard()
            print("Dashboard pronto su: http://localhost:8000")
            print("\nUtenti demo:")
            print("   - issuer_rennes (password: Unisa2025)")
            print("   - verifier_unisa (password: Unisa2025)")
            print("   - studente_mariorossi (password: Unisa2025)")
            print("\nPremi Ctrl+C per fermare il sistema")
            dashboard.run()
        except Exception as e:
            print(f"Errore dashboard: {e}")
    
    def run_credential_api():
        try:
            from src.web.credential_blockchain_api import create_credential_blockchain_api
            app = create_credential_blockchain_api()
            import uvicorn
            uvicorn.run(app, host="localhost", port=8001, log_level="warning")
        except Exception as e:
            print(f"Errore credential API: {e}")

    # Aggiungi questo thread
    threading.Thread(target=run_credential_api, daemon=True)

    def run_ocsp_responder():
        try:
            print("\nInizializzazione OCSP Responder (FastAPI)...")
            uvicorn.run(
                ocsp_app,
                host=OCSP_HOST,
                port=OCSP_PORT,
                log_level="warning"
            )
        except Exception as e:
            print(f"Errore OCSP responder: {e}")

    threads = [
        threading.Thread(target=run_secure_server, daemon=True),
        threading.Thread(target=run_ocsp_responder, daemon=True),
        threading.Thread(target=run_dashboard, daemon=True)
    ]

    for t in threads:
        t.start()

    try:
        while all(t.is_alive() for t in threads):
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n Fermando il sistema...")
        print("Sistema terminato")

def check_system_requirements():
    """Verifica i requisiti del sistema."""
    required_dirs = [
        "src/web",
        "src/credentials",
        "src/communication",
        "src/pki",
        "src/crypto"
    ]

    missing_dirs = [d for d in required_dirs if not Path(d).exists()]

    if missing_dirs:
        print("Directory mancanti:")
        for dir_path in missing_dirs:
            print(f"   - {dir_path}")
        return False
    return True

if __name__ == "__main__":
    main()