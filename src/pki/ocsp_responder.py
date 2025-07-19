# src/pki/ocsp_responder.py

import datetime
from pathlib import Path
from flask import Flask, request, Response
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

# --- CONFIGURAZIONE ---
CA_PATH = Path("./certificates/ca")
ISSUED_CERTS_PATH = Path("./certificates/issued") # Percorso dove sono i certificati emessi
CA_KEY_PATH = CA_PATH / "private" / "ca_private.pem"
CA_CERT_PATH = CA_PATH / "ca_certificate.pem"
INDEX_FILE_PATH = CA_PATH / "index.txt"
CA_PASSWORD = "Unisa2025"
HOST = "127.0.0.1"
PORT = 5001

app = Flask(__name__)

# Variabili globali per CA e certificati emessi
ca_key = None
ca_cert = None
issued_certs_cache = {} # Cache per non leggere sempre da disco

def load_ca_data():
    """Carica la chiave e il certificato della CA."""
    global ca_key, ca_cert
    try:
        with open(CA_KEY_PATH, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=CA_PASSWORD.encode())
        with open(CA_CERT_PATH, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
        print("✅ Chiave e Certificato della CA caricati.")
    except Exception as e:
        print(f"❌ ERRORE CRITICO: Impossibile caricare i dati della CA. {e}")
        exit(1)

def find_certificate_by_serial(serial_number: int) -> x509.Certificate | None:
    """
    Trova un certificato emesso nella directory dei certificati dato il suo numero di serie.
    """
    if serial_number in issued_certs_cache:
        return issued_certs_cache[serial_number]

    try:
        for cert_file in ISSUED_CERTS_PATH.glob("*.pem"):
            with open(cert_file, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
                if cert.serial_number == serial_number:
                    issued_certs_cache[serial_number] = cert # Salva in cache
                    return cert
    except Exception as e:
        print(f"Errore durante la ricerca del certificato: {e}")
    return None

def get_revoked_serials() -> dict:
    """Legge il database della CA per trovare i certificati revocati."""
    revoked = {}
    try:
        with open(INDEX_FILE_PATH, 'r') as f:
            for line in f:
                parts = line.strip().split('\t')
                if parts[0] == 'R':
                    serial = int(parts[3], 16)
                    revoked[serial] = True
    except Exception:
        pass
    return revoked

@app.route('/ocsp', methods=['POST'])
def handle_ocsp_request():
    """Gestisce le richieste OCSP in arrivo."""
    try:
        ocsp_request = ocsp.load_der_ocsp_request(request.data)
    except Exception as e:
        return f"Richiesta non valida: {e}", 400

    # Trova il certificato richiesto
    certificate_to_check = find_certificate_by_serial(ocsp_request.serial_number)
    if not certificate_to_check:
        # Se non troviamo il certificato, rispondiamo con 'unknown'
        builder = ocsp.OCSPResponseBuilder()
        builder = builder.add_response(
            cert_status=ocsp.OCSPCertStatus.UNKNOWN,
            issuer_key_hash=ocsp_request.issuer_key_hash,
            issuer_name_hash=ocsp_request.issuer_name_hash,
            serial_number=ocsp_request.serial_number,
            this_update=datetime.datetime.now(datetime.timezone.utc),
            next_update=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)
        ).responder_id(ocsp.OCSPResponderEncoding.NAME, ca_cert)
        response = builder.sign(ca_key, hashes.SHA256())
        return Response(response.public_bytes(serialization.Encoding.DER), mimetype='application/ocsp-response')

    revoked_serials = get_revoked_serials()
    is_revoked = ocsp_request.serial_number in revoked_serials

    # Imposta i parametri in base allo stato di revoca
    if is_revoked:
        cert_status = ocsp.OCSPCertStatus.REVOKED
        revocation_time = datetime.datetime.now(datetime.timezone.utc)
        # Nota: in un sistema reale, qui andrebbe specificato il motivo della revoca.
        revocation_reason = x509.ocsp.RevocationReason.unspecified 
    else:
        cert_status = ocsp.OCSPCertStatus.GOOD
        revocation_time = None
        revocation_reason = None

    # Ora abbiamo tutti gli oggetti e i parametri necessari
    builder = ocsp.OCSPResponseBuilder()
    builder = builder.add_response(
        cert=certificate_to_check,
        issuer=ca_cert,
        algorithm=hashes.SHA1(),
        cert_status=cert_status,
        this_update=datetime.datetime.now(datetime.timezone.utc),
        next_update=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1),
        revocation_time=revocation_time,      # Fornito sempre
        revocation_reason=revocation_reason   # Fornito sempre
    )

    builder = builder.responder_id(ocsp.OCSPResponderEncoding.NAME, ca_cert)
    response = builder.sign(ca_key, hashes.SHA256())
    
    return Response(response.public_bytes(serialization.Encoding.DER), mimetype='application/ocsp-response')

if __name__ == "__main__":
    print("🚀 Avvio OCSP Responder...")
    load_ca_data()
    # Popoliamo la cache all'avvio per velocità
    find_certificate_by_serial(-1) 
    print(f"📡 In ascolto su http://{HOST}:{PORT}/ocsp")
    app.run(host=HOST, port=PORT)