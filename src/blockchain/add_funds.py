#!/usr/bin/env python3
"""
Script per aggiungere ETH all'account dell'università su Ganache
"""

from web3 import Web3
import sys

# Configurazione
GANACHE_URL = "http://127.0.0.1:8545"
TARGET_ADDRESS = "0x027b6930e523Dec138764cc88cbf0c771ED2A361"  # Indirizzo dell'università
AMOUNT_ETH = 10  # Quantità di ETH da trasferire

def add_funds_to_university_account():
    print("🏦 Collegamento a Ganache...")
    
    # Connetti a Ganache
    w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
    
    if not w3.is_connected():
        print("❌ Impossibile connettersi a Ganache. Assicurati che sia in esecuzione su porta 7545")
        return False
    
    print("✅ Connesso a Ganache")
    
    # Ottieni gli account predefiniti di Ganache
    accounts = w3.eth.accounts
    if len(accounts) == 0:
        print("❌ Nessun account trovato su Ganache")
        return False
    
    # Usa il primo account come sorgente (dovrebbe avere 100 ETH)
    source_account = accounts[0]
    source_balance = w3.eth.get_balance(source_account)
    source_balance_eth = w3.from_wei(source_balance, 'ether')
    
    print(f"💰 Account sorgente: {source_account}")
    print(f"💵 Saldo sorgente: {source_balance_eth} ETH")
    
    # Verifica il saldo attuale del target
    target_balance = w3.eth.get_balance(TARGET_ADDRESS)
    target_balance_eth = w3.from_wei(target_balance, 'ether')
    print(f"🎯 Account target: {TARGET_ADDRESS}")
    print(f"💵 Saldo target attuale: {target_balance_eth} ETH")
    
    if source_balance_eth < AMOUNT_ETH:
        print(f"❌ L'account sorgente non ha abbastanza ETH ({source_balance_eth} < {AMOUNT_ETH})")
        return False
    
    if target_balance_eth >= AMOUNT_ETH:
        print(f"✅ L'account target ha già {target_balance_eth} ETH, non serve aggiungere fondi")
        return True
    
    # Prepara la transazione
    print(f"🚀 Trasferimento di {AMOUNT_ETH} ETH...")
    
    try:
        # Calcola il gas price
        gas_price = w3.eth.gas_price
        
        # Prepara la transazione
        transaction = {
            'from': source_account,
            'to': TARGET_ADDRESS,
            'value': w3.to_wei(AMOUNT_ETH, 'ether'),
            'gas': 21000,
            'gasPrice': gas_price,
            'nonce': w3.eth.get_transaction_count(source_account)
        }
        
        # Invia la transazione (Ganache non richiede firma per account predefiniti)
        tx_hash = w3.eth.send_transaction(transaction)
        
        print(f"⏳ Transazione inviata: {w3.to_hex(tx_hash)}")
        
        # Aspetta la conferma
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        
        if receipt['status'] == 1:
            # Verifica il nuovo saldo
            new_balance = w3.eth.get_balance(TARGET_ADDRESS)
            new_balance_eth = w3.from_wei(new_balance, 'ether')
            
            print("✅ Trasferimento completato con successo!")
            print(f"💰 Nuovo saldo target: {new_balance_eth} ETH")
            return True
        else:
            print("❌ Transazione fallita")
            return False
            
    except Exception as e:
        print(f"❌ Errore durante il trasferimento: {e}")
        return False

if __name__ == "__main__":
    print("=" * 60)
    print("💰 AGGIUNTA FONDI ALL'ACCOUNT UNIVERSITÀ")
    print("=" * 60)
    
    success = add_funds_to_university_account()
    
    if success:
        print("\n🎉 OPERAZIONE COMPLETATA!")
        print("✅ L'account dell'università ha ora fondi sufficienti")
        print("🚀 Puoi ora avviare il sistema completo")
    else:
        print("\n❌ OPERAZIONE FALLITA!")
        print("🔧 Verifica che Ganache sia in esecuzione e riprova")
        sys.exit(1)