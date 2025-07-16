import datetime
import hashlib
import json

class CredentialRegistryContract:
    """
    Una classe Python che simula la logica di uno smart contract su blockchain 
    per la gestione dello stato delle credenziali accademiche.
    
    In uno scenario reale, questa logica sarebbe implementata in un linguaggio come Solidity
    e distribuita su una rete blockchain (es. Ethereum).
    """

    def __init__(self):
        """
        Inizializza lo stato del contratto. In un contratto reale, questo sarebbe
        uno storage persistente sulla blockchain.
        """
        # Mappatura: credential_hash -> {issuer_id, timestamp, status, revocation_timestamp}
        self.credential_registry = {}
        print("Simulatore di Smart Contract Inizializzato.")

    def _calculate_credential_hash(self, credential_data):
        """
        Calcola un hash SHA-256 del contenuto della credenziale per agire come ID univoco.
        La credenziale dovrebbe essere in un formato JSON canonico (coerente).
        """
        canonical_json = json.dumps(credential_data, sort_keys=True).encode('utf-8')
        return hashlib.sha256(canonical_json).hexdigest()

    def register_credential(self, issuer_id: str, credential_data: dict) -> (bool, str):
        """
        Simula una transazione per registrare una nuova credenziale sulla blockchain.
        Solo l'hash e i metadati vengono memorizzati pubblicamente.

        Args:
            issuer_id: L'identificativo dell'università emittente.
            credential_data: L'intero oggetto JSON della credenziale.

        Returns:
            Una tupla (successo, messaggio_o_hash).
        """
        credential_hash = self._calculate_credential_hash(credential_data)
        
        if credential_hash in self.credential_registry:
            return False, "Errore: Credenziale già registrata."

        self.credential_registry[credential_hash] = {
            "issuer_id": issuer_id,
            "issue_timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "status": "VALID",
            "revocation_timestamp": None
        }
        print(f"Credenziale {credential_hash[:10]}... registrata da {issuer_id}.")
        return True, credential_hash

    def revoke_credential(self, issuer_id: str, credential_hash: str) -> (bool, str):
        """
        Simula una transazione per revocare una credenziale esistente.
        Solo l'emittente originale può revocarla.

        Args:
            issuer_id: L'identificativo dell'università che effettua la revoca.
            credential_hash: L'hash della credenziale da revocare.

        Returns:
            Una tupla (successo, messaggio).
        """
        if credential_hash not in self.credential_registry:
            return False, "Errore: Credenziale non trovata."

        if self.credential_registry[credential_hash]["issuer_id"] != issuer_id:
            return False, "Errore: Solo l'emittente originale può revocare questa credenziale."
            
        if self.credential_registry[credential_hash]["status"] == "REVOKED":
            return False, "Errore: La credenziale è già stata revocata."

        self.credential_registry[credential_hash]["status"] = "REVOKED"
        self.credential_registry[credential_hash]["revocation_timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        
        print(f"Credenziale {credential_hash[:10]}... revocata da {issuer_id}.")
        return True, "Credenziale revocata con successo."

    def get_credential_status(self, credential_hash: str) -> dict:
        """
        Simula una chiamata di lettura pubblica per ottenere lo stato di una credenziale.

        Args:
            credential_hash: L'hash della credenziale da verificare.

        Returns:
            Un dizionario con le informazioni sullo stato della credenziale o un messaggio di errore.
        """
        if credential_hash not in self.credential_registry:
            return {"status": "NOT_FOUND", "message": "Hash della credenziale non trovato nel registro."}
        
        return self.credential_registry[credential_hash]

# Esempio di come usare questo contratto simulato nel vostro blockchain_client.py
# Sostituireste il dizionario mock con un'istanza di questa classe.

if __name__ == '__main__':
    # --- DIMOSTRAZIONE ---
    contract = CredentialRegistryContract()
    
    # L'Università di Salerno (emittente) emette una credenziale
    unisa_id = "did:example:unisa"
    student_credential = {
        "student_id": "0622702628",
        "name": "Mario Rossi",
        "degree": "Laurea in Ingegneria Informatica",
        "issue_date": "2025-07-15"
    }

    # 1. Registra la credenziale
    success, credential_hash = contract.register_credential(unisa_id, student_credential)
    if success:
        print(f"Registrazione riuscita. Hash: {credential_hash}")

    # 2. Un verificatore controlla lo stato
    status_info = contract.get_credential_status(credential_hash)
    print(f"Controllo Stato Iniziale: {status_info}")
    assert status_info["status"] == "VALID"

    # 3. L'università revoca la credenziale
    success, message = contract.revoke_credential(unisa_id, credential_hash)
    print(f"Tentativo di revoca: {message}")

    # 4. Il verificatore controlla di nuovo lo stato
    status_info_after_revoke = contract.get_credential_status(credential_hash)
    print(f"Controllo Stato Dopo Revoca: {status_info_after_revoke}")
    assert status_info_after_revoke["status"] == "REVOKED"