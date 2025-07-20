# Script di debug per verificare lo stato della transazione e del contratto
# Salva come: debug_blockchain_revoke.py

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.blockchain.blockchain_service import BlockchainService

def debug_transaction_and_contract():
    """Debug della transazione fallita e dello stato del contratto"""
    
    print("🔍 DEBUG REVOCA CREDENZIALE BLOCKCHAIN")
    print("=" * 60)
    
    try:
        # Inizializza il servizio blockchain
        blockchain_service = BlockchainService()
        print(f"✅ Servizio blockchain inizializzato")
        print(f"   Account: {blockchain_service.account.address}")
        
        # Verifica saldo
        balance = blockchain_service.w3.eth.get_balance(blockchain_service.account.address)
        balance_eth = blockchain_service.w3.from_wei(balance, 'ether')
        print(f"   Saldo: {balance_eth} ETH")
        
        if balance_eth < 0.01:
            print("❌ SALDO INSUFFICIENTE! Aggiungi ETH all'account su Ganache")
            return
            
        # Hash della transazione fallita
        tx_hash = "0x96ac51cfcd3461be67f0faccc62d011f4412309bfa74a492edd0692eddf10ffd"
        credential_id = "5dd5464d-72b4-4212-887a-3fa8d74bc090"
        
        print(f"\n🔍 Analisi transazione: {tx_hash}")
        
        try:
            # Ottieni la ricevuta della transazione
            receipt = blockchain_service.w3.eth.get_transaction_receipt(tx_hash)
            print(f"   Status: {receipt['status']} ({'✅ Successo' if receipt['status'] == 1 else '❌ Fallita'})")
            print(f"   Gas Usato: {receipt['gasUsed']}")
            print(f"   Gas Limite: {receipt.get('gasLimit', 'N/A')}")
            
            if receipt['status'] == 0:
                print("❌ La transazione è FALLITA sulla blockchain!")
                print("\n🔍 Possibili cause:")
                print("   • Gas insufficiente")
                print("   • Errore nel contratto smart (require failed)")
                print("   • Credenziale già revocata")
                print("   • Account non autorizzato")
                
        except Exception as e:
            print(f"❌ Errore nel recupero della ricevuta: {e}")
            print("   La transazione potrebbe non essere stata confermata")
            
        print(f"\n🔍 Verifica stato corrente della credenziale...")
        
        try:
            # Verifica lo stato attuale della credenziale
            status = blockchain_service.verify_credential(credential_id)
            print(f"   Stato attuale: {status}")
            
            if status['status'] == 'REVOKED':
                print("✅ La credenziale è GIÀ REVOCATA!")
                print("   Questo potrebbe spiegare l'errore nella transazione")
            elif status['status'] == 'VALID':
                print("⚠️  La credenziale è ancora VALIDA")
                print("   La revoca non è riuscita")
            elif status['status'] == 'NOT_FOUND':
                print("❌ Credenziale NON TROVATA sulla blockchain")
                print("   Non può essere revocata se non è registrata")
                
        except Exception as e:
            print(f"❌ Errore nella verifica: {e}")
            
        print(f"\n🔧 Test di revoca manuale...")
        
        try:
            if status.get('status') == 'VALID':
                print("   Tentativo di revoca manuale...")
                success = blockchain_service.revoke_credential_directly(
                    credential_id, 
                    "Test revoca manuale - debug"
                )
                
                if success:
                    print("✅ Revoca manuale RIUSCITA!")
                else:
                    print("❌ Revoca manuale FALLITA!")
                    
        except Exception as e:
            print(f"❌ Errore nella revoca manuale: {e}")
            
    except Exception as e:
        print(f"❌ Errore critico: {e}")
        import traceback
        traceback.print_exc()

def check_ganache_connection():
    """Verifica la connessione a Ganache"""
    print("\n🔍 VERIFICA CONNESSIONE GANACHE")
    print("=" * 40)
    
    try:
        from web3 import Web3
        w3 = Web3(Web3.HTTPProvider("http://127.0.0.1:8545"))
        
        if w3.is_connected():
            print("✅ Connesso a Ganache")
            print(f"   Numero blocco: {w3.eth.block_number}")
            print(f"   Chain ID: {w3.eth.chain_id}")
            
            accounts = w3.eth.accounts
            print(f"   Account disponibili: {len(accounts)}")
            
            for i, account in enumerate(accounts[:3]):
                balance = w3.eth.get_balance(account)
                balance_eth = w3.from_wei(balance, 'ether')
                print(f"   Account {i}: {account} ({balance_eth:.2f} ETH)")
                
        else:
            print("❌ NON connesso a Ganache!")
            print("   • Assicurati che Ganache sia in esecuzione")
            print("   • Verifica che sia sulla porta 8545")
            
    except Exception as e:
        print(f"❌ Errore connessione: {e}")

if __name__ == "__main__":
    check_ganache_connection()
    debug_transaction_and_contract()