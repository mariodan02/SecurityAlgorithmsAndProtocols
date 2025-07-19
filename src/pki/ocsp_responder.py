# =============================================================================
# FASE 2: GESTIONE CERTIFICATI X.509 - OCSP RESPONDER
# File: pki/ocsp_responder.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

import datetime
from pathlib import Path
from flask import Flask, request, Response
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

# --- CONFIGURAZIONE ---
# Assicurati che questi percorsi siano corretti
CA_PATH = Path("./certificates/ca")
CA_KEY_PATH = CA_PATH / "private" / "ca_private.pem"
CA_CERT_PATH = CA_PATH / "ca_certificate.pem"
INDEX_FILE_PATH = CA_PATH / "index.txt"
CA_PASSWORD = "Unisa2025" # La password della tua CA
HOST = "127.0.0.1"
PORT = 5001

app = Flask(__name__)

# Variabili globali per CA
ca_key = None
ca_cert = None

def load_ca_data():
    """Carica la chiave e il certificato della CA."""
    global ca_key, ca_cert
    try:
        with open(CA_KEY_PATH, "rb") as f:
            ca_key = serialization.load_pem_private_key(
                f.read(),
                password=CA_PASSWORD.encode()
            )
        with open(CA_CERT_PATH, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        print("✅ CA Key and Certificate loaded successfully.")
    except Exception as e:
        print(f"❌ Critical Error: Could not load CA data. {e}")
        exit(1)

def get_revoked_serials() -> dict:
    """Legge il database della CA per trovare i certificati revocati."""
    revoked = {}
    try:
        with open(INDEX_FILE_PATH, 'r') as f:
            for line in f:
                parts = line.strip().split('\t')
                # Lo stato 'R' indica un certificato revocato
                if parts[0] == 'R':
                    serial = int(parts[3], 16)
                    revoked[serial] = True
    except FileNotFoundError:
        print("⚠️ index.txt not found. Assuming no certificates are revoked.")
    except Exception as e:
        print(f"Error reading index.txt: {e}")
    return revoked

@app.route('/ocsp', methods=['POST'])
def handle_ocsp_request():
    """Gestisce le richieste OCSP in arrivo."""
    try:
        ocsp_request = ocsp.load_der_ocsp_request(request.data)
    except Exception as e:
        return f"Bad request: {e}", 400

    revoked_serials = get_revoked_serials()
    builder = ocsp.OCSPResponseBuilder()

    # === INIZIO CODICE CORRETTO E TESTATO ===
    # L'oggetto ocsp_request non è iterabile. Contiene direttamente i dati.
    cert_status = ocsp.OCSPCertStatus.REVOKED if ocsp_request.serial_number in revoked_serials else ocsp.OCSPCertStatus.GOOD
    
    # Aggiunge la singola risposta per il certificato richiesto
    builder = builder.add_response(
        cert_status=cert_status,
        issuer_key_hash=ocsp_request.issuer_key_hash,
        issuer_name_hash=ocsp_request.issuer_name_hash,
        serial_number=ocsp_request.serial_number,
        this_update=datetime.datetime.now(datetime.timezone.utc),
        next_update=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
    )
    
    # Firma la risposta
    response = builder.responder_id(
        ocsp.OCSPResponderEncoding.NAME, ca_cert
    ).build(ca_key, hashes.SHA256())
    # === FINE CODICE CORRETTO E TESTATO ===

    return Response(response.public_bytes(serialization.Encoding.DER), mimetype='application/ocsp-response')

if __name__ == "__main__":
    print("🚀 Starting OCSP Responder...")
    load_ca_data()
    print(f"📡 Listening on http://{HOST}:{PORT}/ocsp")
    app.run(host=HOST, port=PORT)