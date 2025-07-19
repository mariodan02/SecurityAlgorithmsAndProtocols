"""OCSP Responder per la verifica dello stato dei certificati."""

import datetime
from pathlib import Path
from typing import Dict, Optional

import uvicorn
from fastapi import FastAPI, Request, Response
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

# Configurazione percorsi e credenziali
CA_PATH = Path("./certificates/ca")
ISSUED_CERTS_PATH = Path("./certificates/issued")
CA_KEY_PATH = CA_PATH / "private" / "ca_private.pem"
CA_CERT_PATH = CA_PATH / "ca_certificate.pem"
INDEX_FILE_PATH = CA_PATH / "index.txt"
CA_PASSWORD = "Unisa2025"
HOST = "127.0.0.1"
PORT = 5001

app = FastAPI(title="OCSP Responder")

# Variabili globali per CA e cache certificati
ca_key = None
ca_cert = None
issued_certs_cache: Dict[int, x509.Certificate] = {}


def load_ca_data() -> None:
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
            
    except Exception as e:
        raise RuntimeError(f"Impossibile caricare i dati della CA: {e}")


def find_certificate_by_serial(serial_number: int) -> Optional[x509.Certificate]:
    """
    Trova un certificato emesso dato il suo numero di serie.
    
    Args:
        serial_number: Numero di serie del certificato
        
    Returns:
        Certificato se trovato, None altrimenti
    """
    # Controlla cache
    if serial_number in issued_certs_cache:
        return issued_certs_cache[serial_number]

    # Cerca nei file
    try:
        for cert_file in ISSUED_CERTS_PATH.glob("*.pem"):
            with open(cert_file, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
                if cert.serial_number == serial_number:
                    issued_certs_cache[serial_number] = cert
                    return cert
    except Exception:
        pass
    
    return None


def get_revoked_serials() -> Dict[int, bool]:
    """
    Legge il database della CA per trovare i certificati revocati.
    
    Returns:
        Dizionario con i numeri di serie revocati
    """
    revoked = {}
    
    try:
        with open(INDEX_FILE_PATH, 'r') as f:
            for line in f:
                parts = line.strip().split('\t')
                if len(parts) >= 4 and parts[0] == 'R':
                    serial = int(parts[3], 16)
                    revoked[serial] = True
    except Exception:
        pass
    
    return revoked


def create_ocsp_response(ocsp_request: ocsp.OCSPRequest, 
                        certificate_to_check: Optional[x509.Certificate]) -> ocsp.OCSPResponse:
    """
    Crea una risposta OCSP per una richiesta data.
    
    Args:
        ocsp_request: Richiesta OCSP
        certificate_to_check: Certificato da verificare (None se non trovato)
        
    Returns:
        Risposta OCSP firmata
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    next_update = now + datetime.timedelta(hours=1)
    
    builder = ocsp.OCSPResponseBuilder()
    
    if not certificate_to_check:
        # Certificato non trovato - stato UNKNOWN
        builder = builder.add_response(
            cert_status=ocsp.OCSPCertStatus.UNKNOWN,
            issuer_key_hash=ocsp_request.issuer_key_hash,
            issuer_name_hash=ocsp_request.issuer_name_hash,
            serial_number=ocsp_request.serial_number,
            this_update=now,
            next_update=next_update
        )
    else:
        # Controlla se il certificato è revocato
        revoked_serials = get_revoked_serials()
        is_revoked = ocsp_request.serial_number in revoked_serials
        
        if is_revoked:
            cert_status = ocsp.OCSPCertStatus.REVOKED
            revocation_time = now  # In un sistema reale, si dovrebbe leggere la data effettiva
            revocation_reason = x509.ReasonFlags.unspecified
        else:
            cert_status = ocsp.OCSPCertStatus.GOOD
            revocation_time = None
            revocation_reason = None
        
        builder = builder.add_response(
            cert=certificate_to_check,
            issuer=ca_cert,
            algorithm=hashes.SHA1(),
            cert_status=cert_status,
            this_update=now,
            next_update=next_update,
            revocation_time=revocation_time,
            revocation_reason=revocation_reason
        )
    
    # Firma la risposta con la CA
    builder = builder.responder_id(ocsp.OCSPResponderEncoding.NAME, ca_cert)
    return builder.sign(ca_key, hashes.SHA256())


@app.on_event("startup")
def startup_event() -> None:
    """Inizializzazione all'avvio del server."""
    load_ca_data()


@app.post('/ocsp', response_class=Response)
async def handle_ocsp_request(request: Request) -> Response:
    """
    Gestisce le richieste OCSP in arrivo.
    
    Args:
        request: Richiesta HTTP contenente la richiesta OCSP
        
    Returns:
        Risposta HTTP con la risposta OCSP
    """
    try:
        request_data = await request.body()
        ocsp_request = ocsp.load_der_ocsp_request(request_data)
    except Exception as e:
        return Response(
            content=f"Richiesta non valida: {e}", 
            status_code=400
        )

    # Cerca il certificato richiesto
    certificate_to_check = find_certificate_by_serial(ocsp_request.serial_number)
    
    # Crea e firma la risposta OCSP
    ocsp_response = create_ocsp_response(ocsp_request, certificate_to_check)
    
    return Response(
        content=ocsp_response.public_bytes(serialization.Encoding.DER),
        media_type='application/ocsp-response'
    )


if __name__ == "__main__":
    uvicorn.run(app, host=HOST, port=PORT)