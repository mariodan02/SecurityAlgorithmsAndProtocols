"""
Script di test per verificare l'integrazione blockchain
Da eseguire nella directory src/blockchain/
"""

import os

def test_blockchain_connection():
    """
    Testa la connessione alla blockchain e le operazioni base
    """
    print("=" * 60)
    print("🧪 TEST INTEGRAZIONE BLOCKCHAIN")
    print("=" * 60)
    
    try:
        # Import diretto dato che siamo nella stessa directory
        from blockchain_service import BlockchainService
        
        print("\n1️⃣  Creazione istanza BlockchainService...")
        # Usa la chiave hardcoded (può essere None per usare quella di default)
        blockchain_service = BlockchainService()
        
        print("\n2️⃣  Test verifica credenziale inesistente...")
        test_uuid = "test-credential-12345"
        result = blockchain_service.verify_credential(test_uuid)
        print(f"   Risultato: {result}")
        
        print("\n3️⃣  Test registrazione credenziale...")
        success = blockchain_service.register_credential_directly(test_uuid)
        
        if success:
            print("\n4️⃣  Verifica credenziale appena registrata...")
            result = blockchain_service.verify_credential(test_uuid)
            print(f"   Risultato: {result}")
            
            if result['status'] == 'VALID':
                print("\n🎉 TUTTI I TEST COMPLETATI CON SUCCESSO!")
                print("✅ Il sistema blockchain è pronto per l'uso!")
            else:
                print("\n❌ Errore nella verifica della credenziale registrata")
        else:
            print("\n❌ Errore nella registrazione della credenziale")
            
    except ImportError as e:
        print(f"\n❌ Errore import: {e}")
        print("💡 Assicurati che blockchain_service.py sia nella stessa directory")
        
    except Exception as e:
        print(f"\n❌ Errore durante il test: {e}")
        print("\n🔧 POSSIBILI SOLUZIONI:")
        print("   • Verifica che Ganache sia in esecuzione su porta 7545")
        print("   • Controlla che l'account abbia fondi su Ganache")
        print("   • Verifica che il contratto sia deployato correttamente")
        print("   • Esegui: node compile.js && node deploy.js")

def check_prerequisites():
    """
    Verifica che tutti i prerequisiti siano soddisfatti
    """
    print("\n🔍 VERIFICA PREREQUISITI:")
    
    # Determina il percorso della directory del file di test
    script_dir = os.path.dirname(os.path.abspath(__file__))
    print(f"📂 Script directory: {script_dir}")
    
    # File necessari nella directory corrente
    required_files = [
        "CredentialRegistryAbi.json",    # Stessa directory
        "contract-address.txt",          # Stessa directory
        "blockchain_service.py",         # Stessa directory
    ]
    
    all_good = True
    
    # Controlla file nella directory corrente
    for file_path in required_files:
        full_path = os.path.join(script_dir, file_path)
        if os.path.exists(full_path):
            print(f"   ✅ {file_path}")
        else:
            print(f"   ❌ {file_path} - MANCANTE!")
            print(f"      Cercato in: {full_path}")
            all_good = False
    
    if not all_good:
        print("\n💡 Esegui questi comandi per preparare il sistema:")
        print("   # Vai nella directory blockchain:")
        print("   cd src/blockchain/")
        print("   # Installa dipendenze Node.js:")
        print("   npm install")
        print("   # Compila e deploya il contratto:")
        print("   node compile.js")
        print("   node deploy.js")
        return False
        
    return True

if __name__ == "__main__":
    print(f"📂 Directory corrente: {os.getcwd()}")
    print(f"📄 File di test: {os.path.abspath(__file__)}")
    
    if check_prerequisites():
        test_blockchain_connection()
    else:
        print("\n⚠️  Completa prima la configurazione dei prerequisiti!")