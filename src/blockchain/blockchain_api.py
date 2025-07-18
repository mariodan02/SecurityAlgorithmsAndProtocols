# blockchain_api.py
import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from web3 import Web3
import json
# Importa le librerie crittografiche necessarie
from cryptography.hazmat.primitives import serialization

# --- 1. Configurazione Iniziale ---

PROVIDER_URL = "http://127.0.0.1:7545"
# Specifica il percorso del tuo file PEM
ISSUER_PEM_FILE = "/Users/carminecuomo/Documents/SecurityAlgorithmsAndProtocols/keys/universite_rennes_private.pem" # <-- MODIFICA QUI
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

# --- NUOVA FUNZIONE per caricare la chiave dal PEM ---
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

class UniversityModulePy:
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

    # ... (le altre funzioni: _send_transaction, register_credential, ecc. rimangono IDENTICHE) ...
    def _send_transaction(self, function_call):
        """Funzione helper per inviare transazioni firmate."""
        try:
            tx = function_call.build_transaction({
                'from': self.account.address,
                'nonce': self.w3.eth.get_transaction_count(self.account.address),
                'gas': 1500000,
                'gasPrice': self.w3.eth.gas_price
            })
            signed_tx = self.w3.eth.account.sign_transaction(tx, private_key=self.account.key)
            tx_hash = self.w3.eth.send_raw_transaction(signed_tx.rawTransaction)
            tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            return tx_receipt
        except Exception as e:
            # Cattura errori comuni come "credential already registered"
            raise HTTPException(status_code=400, detail=f"Errore nella transazione: {e}")

    def register_credential(self, credential_uuid: str):
        print(f"[ISSUER] Registrazione di UUID: {credential_uuid}...")
        function_call = self.contract.functions.registerCredential(credential_uuid)
        receipt = self._send_transaction(function_call)
        print(f"✅ Registrazione completata. Hash: {self.w3.to_hex(receipt.transaction_hash)}")
        return {"transactionHash": self.w3.to_hex(receipt.transaction_hash)}

    def revoke_credential(self, credential_uuid: str, reason: str):
        print(f"[ISSUER] Revoca di UUID: {credential_uuid}...")
        function_call = self.contract.functions.revokeCredential(credential_uuid, reason)
        receipt = self._send_transaction(function_call)
        print(f"✅ Revoca completata. Hash: {self.w3.to_hex(receipt.transaction_hash)}")
        return {"transactionHash": self.w3.to_hex(receipt.transaction_hash)}

    def verify_credential(self, credential_uuid: str):
        print(f"[VERIFIER] Verifica di UUID: {credential_uuid}...")
        try:
            result = self.contract.functions.verifyCredential(credential_uuid).call()
            
            issuer, timestamp, is_revoked = result[0], result[1], result[2]
            
            if issuer == '0x0000000000000000000000000000000000000000':
                raise HTTPException(status_code=404, detail="Credenziale non trovata nel registro.")

            status = 'REVOKED' if is_revoked else 'VALID'
            return {
                "credentialUUID": credential_uuid,
                "status": status,
                "issuer": issuer,
                "issueTimestamp": timestamp
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Errore durante la verifica: {e}")


# --- 3. Definizione dell'API con FastAPI (aggiornata) ---

app = FastAPI(
    title="Credential Registry API",
    description="API per interagire con lo smart contract di gestione credenziali.",
    version="1.0.0"
)

# Istanza del modulo che l'API userà (ora carica dal file PEM)
module = UniversityModulePy(pem_filepath=ISSUER_PEM_FILE, pem_password=PEM_PASSWORD)

# ... (tutti gli endpoint @app.post, @app.get rimangono IDENTICI) ...

@app.post("/register", status_code=201)
def register(credential: Credential):
    """
    Registra una nuova credenziale sulla blockchain.
    Solo l'account configurato come ISSUER può eseguire questa operazione.
    """
    return module.register_credential(credential.uuid)

@app.post("/revoke")
def revoke(request: RevokeRequest):
    """
    Revoca una credenziale esistente.
    """
    return module.revoke_credential(request.uuid, request.reason)

@app.get("/verify/{credential_uuid}")
def verify(credential_uuid: str):
    """
    Verifica lo stato di una credenziale (VALIDA, REVOCATA o NON TROVATA).
    Questa operazione è pubblica e non richiede autenticazione.
    """
    return module.verify_credential(credential_uuid)

@app.get("/")
def read_root():
    return {"message": "Benvenuto nella Credential Registry API. Vai su /docs per la documentazione."}