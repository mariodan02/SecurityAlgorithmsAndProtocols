# src/blockchain/blockchain_service.py (NUOVA VERSIONE)
import json
from web3 import Web3

PROVIDER_URL = "http://127.0.0.1:7545"

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
        raise RuntimeError(f"Errore: file ABI/address non trovato. Dettagli: {e}")


class BlockchainService:
    def __init__(self, raw_private_key: str):
        self.w3 = Web3(Web3.HTTPProvider(PROVIDER_URL))
        if not self.w3.is_connected():
            raise ConnectionError("Impossibile connettersi al provider Ethereum.")

        if not raw_private_key.startswith('0x'):
            raw_private_key = '0x' + raw_private_key

        self.account = self.w3.eth.account.from_key(raw_private_key)
        self.w3.eth.default_account = self.account.address

        contract_abi, contract_address = load_contract_data()
        self.contract = self.w3.eth.contract(address=contract_address, abi=contract_abi)
        print(f"Modulo Blockchain inizializzato per l'account: {self.account.address}")

    def build_registration_transaction(self, credential_uuid: str, from_address: str):
        print(f"[BLOCKCHAIN] Preparazione registrazione per UUID: {credential_uuid}...")
        function_call = self.contract.functions.registerCredential(credential_uuid)
        transaction = function_call.build_transaction({
            'from': from_address,
            'nonce': self.w3.eth.get_transaction_count(from_address),
            'gas': 1500000,
            'gasPrice': self.w3.eth.gas_price
        })
        return transaction

    def build_revocation_transaction(self, credential_uuid: str, reason: str, from_address: str):
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
            return { "status": status, "issuer": issuer, "issueTimestamp": timestamp }
        except Exception as e:
            raise ValueError(f"Errore durante la verifica: {e}")