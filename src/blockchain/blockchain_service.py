import os
from web3 import Web3
import json
from cryptography.hazmat.primitives import serialization

# --- 1. Configurazione Iniziale ---

PROVIDER_URL = "http://127.0.0.1:7545"
# Specifica il percorso del tuo file PEM
ISSUER_PEM_FILE = "/keys/universite_rennes_private.pem" # <-- MODIFICA QUI
# Password del file PEM, se presente (altrimenti lasciala a None)
PEM_PASSWORD = None 

# ... (la funzione load_contract_data rimane uguale) ...
def load_contract_data():
    try:
        with open('CredentialRegistryAbi.json', 'r') as f:
            abi = json.load(f)
        with open('contract-address.txt', 'r') as f:
            address = f.read().strip()
        return abi, address
    except FileNotFoundError as e:
        raise RuntimeError(f"Errore: file necessario non trovato. Dettagli: {e}")

def load_private_key_from_pem(filepath, password):
    """
    Legge un file PEM, estrae la chiave privata grezza e la restituisce
    in formato esadecimale compatibile con web3.py.
    """
    try:
        with open(filepath, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=password.encode() if password else None,
            )
        
        # Estrae il valore intero della chiave privata
        private_key_int = private_key.private_numbers().private_value
        # Converte l'intero in una stringa esadecimale di 32 byte (64 caratteri)
        private_key_hex = hex(private_key_int)
        
        return private_key_hex
        
    except (FileNotFoundError, ValueError, TypeError) as e:
        raise RuntimeError(f"Impossibile caricare la chiave dal file PEM: {e}")

# --- 2. Modulo di Interazione con la Blockchain (aggiornato) ---

class BlockchainService:
    # Il costruttore ora accetta un percorso di file invece di una chiave diretta
    def __init__(self, pem_filepath, pem_password=None):
        self.w3 = Web3(Web3.HTTPProvider(PROVIDER_URL))
        if not self.w3.is_connected():
            raise ConnectionError("Impossibile connettersi al provider Ethereum.")

        # Carica la chiave dal file PEM
        private_key_hex = load_private_key_from_pem(pem_filepath, pem_password)
        
        self.account = self.w3.eth.account.from_key(private_key_hex)
        self.w3.eth.default_account = self.account.address
        
        contract_abi, contract_address = load_contract_data()
        self.contract = self.w3.eth.contract(address=contract_address, abi=contract_abi)
        print(f"Modulo inizializzato per l'account: {self.account.address}")

    def build_registration_transaction(self, credential_uuid: str, from_address: str):
        """
        COSTRUISCE ma non invia la transazione di registrazione.
        Restituisce l'oggetto transazione pronto per essere firmato.
        """
        print(f"[BLOCKCHAIN] Preparazione registrazione per UUID: {credential_uuid}...")
        function_call = self.contract.functions.registerCredential(credential_uuid)
        
        # Costruisce l'oggetto transazione
        transaction = function_call.build_transaction({
            'from': from_address,
            'nonce': self.w3.eth.get_transaction_count(from_address),
            'gas': 1500000,
            'gasPrice': self.w3.eth.gas_price
        })
        return transaction

    def build_revocation_transaction(self, credential_uuid: str, reason: str, from_address: str):
        """COSTRUISCE ma non invia la transazione di revoca."""
        print(f"[BLOCKCHAIN] Preparazione revoca per UUID: {credential_uuid}...")
        function_call = self.contract.functions.revokeCredential(credential_uuid, reason)
        
        transaction = function_call.build_transaction({
            'from': from_address,
            'nonce': self.w3.eth.get_transaction_count(from_address),
            'gas': 1500000,
            'gasPrice': self.w3.eth.gas_price
        })
        return transaction

    def verify_credential(self, credential_uuid: str):
        print(f"[VERIFIER] Verifica di UUID: {credential_uuid}...")
        try:
            result = self.contract.functions.verifyCredential(credential_uuid).call()
            
            issuer, timestamp, is_revoked = result[0], result[1], result[2]
            
            if issuer == '0x0000000000000000000000000000000000000000':
                return {"status": "NOT_FOUND"}

            status = 'REVOKED' if is_revoked else 'VALID'
            return {
                "credentialUUID": credential_uuid,
                "status": status,
                "issuer": issuer,
                "issueTimestamp": timestamp
            }
        except Exception as e:
            raise ValueError(f"Errore durante la verifica: {e}")
