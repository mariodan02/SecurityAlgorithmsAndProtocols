import json
import os
from web3 import Web3

PROVIDER_URL = "http://127.0.0.1:8545"

# CONFIGURAZIONE HARDCODED DELLA CHIAVE PRIVATA
GANACHE_PRIVATE_KEY = "0x4a9eb7e15716d4f7c5ab306731c7fb2e633ab4fbd90ca74812dde8cffb8a8f48"

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
        Se raw_private_key non viene fornita, usa quella hardcoded da Ganache
        """
        self.w3 = Web3(Web3.HTTPProvider(PROVIDER_URL))
        if not self.w3.is_connected():
            raise ConnectionError("Impossibile connettersi al provider Ethereum.")

        # Usa la chiave hardcoded se non ne viene fornita una
        if raw_private_key is None:
            raw_private_key = GANACHE_PRIVATE_KEY
            print(f"🔑 Usando chiave privata hardcoded per Ganache")

        if not raw_private_key.startswith('0x'):
            raw_private_key = '0x' + raw_private_key

        self.account = self.w3.eth.account.from_key(raw_private_key)
        self.w3.eth.default_account = self.account.address

        contract_abi, contract_address = load_contract_data()
        self.contract = self.w3.eth.contract(address=contract_address, abi=contract_abi)
        print(f"💰 Account blockchain inizializzato: {self.account.address}")
        
        # Verifica che l'account abbia fondi
        balance = self.w3.eth.get_balance(self.account.address)
        balance_eth = self.w3.from_wei(balance, 'ether')
        print(f"💵 Saldo dell'account: {balance_eth} ETH")
        
        if balance == 0:
            print("⚠️  ATTENZIONE: L'account non ha fondi! Aggiungi ETH su Ganache.")

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