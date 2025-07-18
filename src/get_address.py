# get_address.py (versione corretta)
from cryptography.hazmat.primitives import serialization
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

    # --- QUESTA È LA RIGA CORRETTA ---
    # Nelle nuove versioni della libreria si usa .d invece di .private_value
    private_key_int = private_key_obj.private_numbers().d 
    # ----------------------------------

    private_key_bytes = private_key_int.to_bytes(32, byteorder='big')
    pk = PrivateKey(private_key_bytes)

    print("\n✅ INDIRIZZO ETHEREUM DELL'ISSUER ✅")
    print("Questo è l'indirizzo che ha bisogno di fondi su Ganache:\n")
    print(pk.public_key.to_checksum_address())
    print("\nCOPIA QUESTO INDIRIZZO.")

except Exception as e:
    print(f"\n❌ Si è verificato un errore: {e}")