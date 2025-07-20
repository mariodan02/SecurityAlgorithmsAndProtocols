from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from eth_keys.datatypes import PrivateKey
import os

# Assicurati che questi valori siano corretti
PEM_FILE_PATH = "keys/universite_rennes_private.pem" # Chiave dell'issuer
PEM_PASSWORD = b"Unisa2025"

try:
    # Controlla se il file esiste
    if not os.path.exists(PEM_FILE_PATH):
        raise FileNotFoundError(f"Il file della chiave non è stato trovato in '{PEM_FILE_PATH}'. Hai eseguito 'python src/pki/certificate_authority.py'?")

    with open(PEM_FILE_PATH, "rb") as key_file:
        private_key_obj = serialization.load_pem_private_key(
            key_file.read(),
            password=PEM_PASSWORD,
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
    
    # Crea la chiave privata Ethereum
    pk = PrivateKey(ethereum_private_key_bytes)

    print("\nINDIRIZZO ETHEREUM DELL'ISSUER ✅")
    print("Questo è l'indirizzo che ha bisogno di fondi su Ganache:\n")
    print(pk.public_key.to_checksum_address())
    print("\nCHIAVE PRIVATA ETHEREUM (per debug):")
    print(f"0x{ethereum_private_key_bytes.hex()}")
    print("\nCOPIA QUESTO INDIRIZZO E AGGIUNGI FONDI SU GANACHE.")

except Exception as e:
    print(f"\nSi è verificato un errore: {e}")
    import traceback
    traceback.print_exc()