# =============================================================================
# RUNNER PRINCIPALE
# File: run_system.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

import sys
import os
import threading
import time
from pathlib import Path

# AGGIUNGI LA DIRECTORY SRC AL PYTHONPATH
current_dir = Path(__file__).parent.absolute()
src_dir = current_dir / "src"
sys.path.insert(0, str(src_dir))

def main():
    """Avvia entrambi i server"""
    print("PROJECT WORK")
    print("GRUPPO 19")
    
    # Verifica requisiti
    if not check_system_requirements():
        print("❌ Requisiti non soddisfatti. Verifica la struttura del progetto.")
        sys.exit(1)
    
    print("\n🔧 Avvio sistema completo...")
    
    # Test import
    try:
        from web.dashboard import AcademicCredentialsDashboard
        from communication.secure_server import AcademicCredentialsSecureServer, ServerConfiguration
        print("✅ Import moduli riuscito")
    except ImportError as e:
        print(f"❌ Errore import: {e}")
        sys.exit(1)
    
    # Thread per il secure server
    def run_secure_server():
        try:
            print("\n🔒 Inizializzazione Secure Server...")
            config = ServerConfiguration(
                host="localhost",
                port=8443,
                ssl_enabled=True
            )
            server = AcademicCredentialsSecureServer(config)
            print("🔒 Secure Server pronto su: https://localhost:8443")
            server.run()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"❌ Errore secure server: {e}")
    
    # Thread per il dashboard
    def run_dashboard():
        try:
            # Aspetta che il secure server si avvii
            time.sleep(3)
            print("\n🌐 Inizializzazione Dashboard...")
            dashboard = AcademicCredentialsDashboard()
            print("🌐 Dashboard pronto su: http://localhost:8000")
            print("\n👤 Utenti demo:")
            print("   - issuer_rennes (password: Unisa2025)")
            print("   - verifier_unisa (password: Unisa2025)")
            print("   - studente_mariorossi (password: Unisa2025)")
            print("\n🔧 Premi Ctrl+C per fermare il sistema")
            dashboard.run()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"❌ Errore dashboard: {e}")
    
    # Avvia threads
    secure_thread = threading.Thread(target=run_secure_server, daemon=True)
    dashboard_thread = threading.Thread(target=run_dashboard, daemon=True)
    
    # Avvia prima il secure server
    secure_thread.start()
    
    # Poi il dashboard
    dashboard_thread.start()
    
    try:
        # Aspetta l'interruzione
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n Fermando il sistema...")
        print("✅ Sistema terminato")

def check_system_requirements():
    """Verifica i requisiti del sistema"""
    required_dirs = [
        "src/web",
        "src/credentials", 
        "src/communication",
        "src/pki",
        "src/crypto"
    ]
    
    missing_dirs = []
    for dir_path in required_dirs:
        if not Path(dir_path).exists():
            missing_dirs.append(dir_path)
    
    if missing_dirs:
        print("❌ Directory mancanti:")
        for dir_path in missing_dirs:
            print(f"   - {dir_path}")
        return False
    
    return True

if __name__ == "__main__":
    main()