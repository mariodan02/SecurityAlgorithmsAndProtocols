import json
import os
from web3 import Web3

# --- CONFIGURAZIONE ---
GANACHE_URL = "http://127.0.0.1:7545"
CONTRACT_ADDRESS_FILE = os.path.join(os.path.dirname(__file__), 'blockchain/contract-address.txt')
CONTRACT_ABI_FILE = os.path.join(os.path.dirname(__file__), 'blockchain/CredentialRegistryAbi.json')
# --------------------

def register_credential_on_chain(private_key: str, credential_uuid: str):
    """
    Si connette a Ganache e registra un singolo UUID di credenziale.
    """
    try:
        # 1. Connessione a Web3
        w3 = Web3(Web3.HTTPProvider(GANACHE_URL))
        if not w3.is_connected():
            print("ERRORE: Impossibile connettersi a Ganache. Assicurati che sia in esecuzione.")
            return

        # 2. Caricamento dati del contratto
        with open(CONTRACT_ADDRESS_FILE, 'r') as f:
            contract_address = f.read().strip()
        with open(CONTRACT_ABI_FILE, 'r') as f:
            contract_abi = json.load(f)

        # 3. Setup account e contratto
        if not private_key.startswith('0x'):
            private_key = '0x' + private_key
        
        account = w3.eth.account.from_key(private_key)
        contract = w3.eth.contract(address=contract_address, abi=contract_abi)
        print(f"Connesso con l'account: {account.address}")

        # 4. Costruzione della transazione
        nonce = w3.eth.get_transaction_count(account.address)
        tx_params = {
            'from': account.address,
            'nonce': nonce,
            'gas': 1500000,
            'gasPrice': w3.eth.gas_price,
        }
        
        transaction = contract.functions.registerCredential(credential_uuid).build_transaction(tx_params)

        # 5. Firma e invio
        signed_tx = account.sign_transaction(transaction)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        
        print(f"🚀 Transazione inviata... In attesa di conferma. Hash: {w3.to_hex(tx_hash)}")
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

        # 6. Verifica del risultato della transazione
        if receipt['status'] == 1:
            print("\n" + "="*50)
            print("🎉 REGISTRAZIONE COMPLETATA CON SUCCESSO! 🎉")
            # --- LA CORREZIONE È QUI ---
            print(f"  - UUID Credenziale: {credential_uuid}")
            print(f"  - Hash Transazione: {w3.to_hex(receipt.transactionHash)}") 
            print(f"  - Numero Blocco: {receipt.blockNumber}")
            print("="*50)
        else:
            print("\n" + "!"*50)
            print("ERRORE: La transazione è fallita sulla blockchain (reverted).")
            print(f"   - Controlla che l'account {account.address} abbia fondi su Ganache.")
            print(f"   - Controlla l'output del terminale di Ganache per ulteriori dettagli.")
            print("!"*50)

    except FileNotFoundError:
        print("ERRORE: File del contratto non trovati. Hai eseguito 'node compile.js' e 'node deploy.js'?")
    except Exception as e:
        print(f"ERRORE DURANTE LA TRANSAZIONE: {e}")

if __name__ == "__main__":
    print("--- Strumento di Inserimento Manuale su Blockchain ---")

    # Inserisci la chiave privata dal file ganache_key.txt
    issuer_private_key = input("Incolla la chiave privata dell'account issuer (da ganache_key.txt): ").strip()

    # Inserisci l'UUID della credenziale che vuoi registrare
    credential_uuid_to_register = input("Incolla l'UUID della credenziale da registrare: ").strip()

    if issuer_private_key and credential_uuid_to_register:
        register_credential_on_chain(issuer_private_key, credential_uuid_to_register)
    else:
        print("Dati non validi. Riprova.")