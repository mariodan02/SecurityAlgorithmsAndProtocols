import json
import os
from web3 import Web3
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from eth_keys.datatypes import PrivateKey

PROVIDER_URL = "http://127.0.0.1:8545"

# CONFIGURAZIONE HARDCODED DELLA CHIAVE PRIVATA (fallback per test)
GANACHE_PRIVATE_KEY = "0x40b18ebc23bf6dc9401457511ee0ecd5f86ad80032f74c51073ff40077e91b4a"

# CHIAVE DEL "BANKER" - Account Ganache con fondi per finanziare altri account
GANACHE_BANKER_KEY = "0xf0f5e8b2e5074bca7925a5251561b0be6426ee596ed6a521235222af80dd64a7"  # Account #1 di Ganache

def derive_ethereum_key_from_rsa(pem_file_path: str, password: bytes):
    """
    Deriva una chiave privata Ethereum da una chiave privata RSA
    usando HKDF per garantire 32 byte esatti
    """
    try:
        with open(pem_file_path, "rb") as key_file:
            private_key_obj = serialization.load_pem_private_key(
                key_file.read(),
                password=password,
            )

        # Ottieni il numero della chiave privata RSA
        private_key_int = private_key_obj.private_numbers().d 
        
        # Converti in bytes (può essere più di 32 byte)
        private_key_bytes = private_key_int.to_bytes((private_key_int.bit_length() + 7) // 8, byteorder='big')
        
        # Usa HKDF per derivare esattamente 32 byte per Ethereum
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # Esattamente 32 byte per Ethereum
            salt=b"ethereum_account_derivation",  # Salt fisso per consistenza
            info=b"academic_credential_issuer",   # Info specifica per il nostro use case
        )
        
        ethereum_private_key_bytes = hkdf.derive(private_key_bytes)
        return f"0x{ethereum_private_key_bytes.hex()}"
        
    except Exception as e:
        print(f"⚠️  Errore nella derivazione da RSA: {e}")
        return None

def load_contract_data():
    try:
        # Calcola il percorso corretto partendo dalla posizione di questo script
        script_dir = os.path.dirname(os.path.abspath(__file__))
        abi_path = os.path.join(script_dir, 'CredentialRegistryAbi.json')
        address_path = os.path.join(script_dir, 'contract-address.txt')

        with open(abi_path, 'r') as f:
            abi = json.load(f)
        with open(address_path, 'r') as f:
            address = f.read().strip()
        return abi, address
    except FileNotFoundError as e:
        raise RuntimeError(f"Errore: file ABI o indirizzo non trovato. Dettagli: {e}")


class BlockchainService:
    def __init__(self, raw_private_key: str = None):
        """
        Se raw_private_key non viene fornita, prova a derivarla dalla chiave RSA,
        altrimenti usa quella hardcoded. Finanzia automaticamente l'account se necessario.
        """
        self.w3 = Web3(Web3.HTTPProvider(PROVIDER_URL))
        if not self.w3.is_connected():
            raise ConnectionError("Impossibile connettersi al provider Ethereum.")

        # Strategia di fallback per la chiave privata
        if raw_private_key is None:
            # Prova prima a derivare dalla chiave RSA
            script_dir = os.path.dirname(os.path.abspath(__file__))
            rsa_key_path = os.path.join(script_dir, "..", "..", "keys", "universite_rennes_private.pem")
            
            if os.path.exists(rsa_key_path):
                print(f"🔑 Derivazione chiave Ethereum da RSA: {rsa_key_path}")
                raw_private_key = derive_ethereum_key_from_rsa(rsa_key_path, b"Unisa2025")
                
            if raw_private_key is None:
                # Fallback alla chiave hardcoded
                raw_private_key = GANACHE_PRIVATE_KEY
                print(f"🔑 Usando chiave privata hardcoded per Ganache (fallback)")
            else:
                print(f"🔑 Chiave derivata con successo da RSA")

        if not raw_private_key.startswith('0x'):
            raw_private_key = '0x' + raw_private_key

        self.account = self.w3.eth.account.from_key(raw_private_key)
        self.w3.eth.default_account = self.account.address

        contract_abi, contract_address = load_contract_data()
        self.contract = self.w3.eth.contract(address=contract_address, abi=contract_abi)
        print(f"💰 Account blockchain inizializzato: {self.account.address}")
        
        # Verifica e auto-finanzia l'account se necessario
        self._ensure_account_funded()

    def _ensure_account_funded(self, min_balance_eth: float = 500.0):
        """
        Assicura che l'account abbia almeno min_balance_eth ETH.
        Se non ne ha abbastanza, trasferisce fondi dal banker account.
        """
        balance = self.w3.eth.get_balance(self.account.address)
        balance_eth = self.w3.from_wei(balance, 'ether')
        print(f"💵 Saldo attuale dell'account: {balance_eth} ETH")
        
        if balance_eth < min_balance_eth:
            print(f"💸 Saldo insufficiente! Trasferimento automatico di fondi in corso...")
            
            try:
                # Crea account banker per trasferire fondi
                banker_account = self.w3.eth.account.from_key(GANACHE_BANKER_KEY)
                banker_balance = self.w3.eth.get_balance(banker_account.address)
                banker_balance_eth = self.w3.from_wei(banker_balance, 'ether')
                
                print(f"🏦 Banker account: {banker_account.address} (saldo: {banker_balance_eth} ETH)")
                
                if banker_balance_eth < min_balance_eth + 0.1:  # +0.1 per gas
                    print(f"❌ Banker account non ha fondi sufficienti!")
                    print(f"💡 Assicurati che Ganache sia avviato con account predefiniti finanziati")
                    return
                
                # Costruisci transazione di trasferimento
                amount_to_send = self.w3.to_wei(min_balance_eth, 'ether')
                
                transaction = {
                    'to': self.account.address,
                    'value': amount_to_send,
                    'gas': 21000,
                    'gasPrice': self.w3.eth.gas_price,
                    'nonce': self.w3.eth.get_transaction_count(banker_account.address),
                }
                
                # Firma e invia la transazione
                signed_txn = banker_account.sign_transaction(transaction)
                tx_hash = self.w3.eth.send_raw_transaction(signed_txn.rawTransaction)
                
                print(f"🚀 Transazione di finanziamento inviata: {self.w3.to_hex(tx_hash)}")
                
                # Aspetta la conferma
                receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
                
                if receipt['status'] == 1:
                    new_balance = self.w3.eth.get_balance(self.account.address)
                    new_balance_eth = self.w3.from_wei(new_balance, 'ether')
                    print(f"✅ Finanziamento completato! Nuovo saldo: {new_balance_eth} ETH")
                else:
                    print(f"❌ Errore nel finanziamento dell'account")
                    
            except Exception as e:
                print(f"❌ Errore durante il finanziamento automatico: {e}")
                print(f"💡 Aggiungi manualmente fondi all'account {self.account.address} su Ganache")
        else:
            print(f"✅ Account ha fondi sufficienti per le operazioni")

    def build_registration_transaction(self, credential_uuid: str, from_address: str = None):
        """
        from_address ora è opzionale, usa l'account inizializzato se non specificato
        """
        if from_address is None:
            from_address = self.account.address
            
        print(f"BLOCKCHAIN: Preparazione registrazione per UUID: {credential_uuid}...")
        function_call = self.contract.functions.registerCredential(credential_uuid)
        transaction = function_call.build_transaction({
            'from': from_address,
            'nonce': self.w3.eth.get_transaction_count(from_address),
            'gas': 1500000,
            'gasPrice': self.w3.eth.gas_price
        })
        return transaction

    def build_revocation_transaction(self, credential_uuid: str, reason: str, from_address: str = None):
        """
        from_address ora è opzionale, usa l'account inizializzato se non specificato
        """
        if from_address is None:
            from_address = self.account.address
            
        print(f"BLOCKCHAIN: Preparazione revoca per UUID: {credential_uuid}...")
        function_call = self.contract.functions.revokeCredential(credential_uuid, reason)
        transaction = function_call.build_transaction({
            'from': from_address,
            'nonce': self.w3.eth.get_transaction_count(from_address),
            'gas': 1500000,
            'gasPrice': self.w3.eth.gas_price
        })
        return transaction

    def register_credential_directly(self, credential_uuid: str):
        """
        Metodo per registrare direttamente una credenziale (firma e invia la transazione)
        """
        try:
            transaction = self.build_registration_transaction(credential_uuid)
            signed_tx = self.account.sign_transaction(transaction)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            print(f"🚀 Transazione inviata: {self.w3.to_hex(tx_hash)}")
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt['status'] == 1:
                print(f"✅ Credenziale {credential_uuid} registrata con successo!")
                print(f"📋 Hash transazione: {self.w3.to_hex(receipt.transactionHash)}")
                return True
            else:
                print(f"❌ Errore nella registrazione di {credential_uuid}")
                return False
                
        except Exception as e:
            print(f"❌ Errore durante la registrazione: {e}")
            return False

    def verify_credential(self, credential_uuid: str):
        print(f"VERIFIER: Verifica di UUID: {credential_uuid}...")
        try:
            result = self.contract.functions.verifyCredential(credential_uuid).call()
            issuer, timestamp, is_revoked = result[0], result[1], result[2]
            if issuer == '0x0000000000000000000000000000000000000000':
                return {"status": "NOT_FOUND"}
            status = 'REVOKED' if is_revoked else 'VALID'
            return { "status": status, "issuer": issuer, "issueTimestamp": timestamp }
        except Exception as e:
            raise ValueError(f"Errore durante la verifica: {e}")

    def revoke_credential_directly(self, credential_uuid: str, reason: str):
        """
        Metodo per revocare direttamente una credenziale (firma e invia la transazione)
        """
        try:
            transaction = self.build_revocation_transaction(credential_uuid, reason)
            signed_tx = self.account.sign_transaction(transaction)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            
            print(f"🚀 Transazione di revoca inviata: {self.w3.to_hex(tx_hash)}")
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            
            if receipt['status'] == 1:
                print(f"✅ Credenziale {credential_uuid} revocata con successo!")
                print(f"📋 Hash transazione: {self.w3.to_hex(receipt.transactionHash)}")
                return True
            else:
                print(f"❌ Errore nella revoca di {credential_uuid}")
                return False
                
        except Exception as e:
            print(f"❌ Errore durante la revoca: {e}")
            return False