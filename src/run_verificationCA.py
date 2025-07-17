from pathlib import Path
from credentials.validator import AcademicCredentialValidator, ValidatorConfiguration

# Percorso al certificato della tua Root CA, creato con OpenSSL.
ROOT_CA_CERT_PATH = "./root/ca/certs/ca.cert.pem"

def setup_validator_with_custom_pki():
    """
    Configura e restituisce un'istanza di AcademicCredentialValidator
    utilizzando la PKI personalizzata.
    """
    print("⚙️  Configurazione del validatore con PKI personalizzata...")

    # Verifica che il certificato della Root CA esista
    if not Path(ROOT_CA_CERT_PATH).exists():
        print(f"❌ ERRORE CRITICO: Certificato della Root CA non trovato in '{ROOT_CA_CERT_PATH}'.")
        print("   Il server non può verificare le credenziali senza la CA di fiducia.")
        # In un'applicazione reale, questo dovrebbe impedire l'avvio del server.
        return None

    # Crea la configurazione per il validatore
    validator_config = ValidatorConfiguration(
        trusted_ca_certificates=[ROOT_CA_CERT_PATH]
    )

    # Inizializza il validatore con la nostra configurazione di fiducia
    validator = AcademicCredentialValidator(config=validator_config)

    print(f"✅ Validatore configurato. Si fida della CA in: {ROOT_CA_CERT_PATH}")
    return validator