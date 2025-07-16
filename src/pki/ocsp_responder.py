import datetime
from flask import Flask, request, Response
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from certificate_authority import CertificateAuthority

# Inizializza l'app Flask per l'OCSP Responder
app = Flask(__name__)

# Carica l'istanza della Certificate Authority
# Si presume che la CA abbia la sua chiave, il suo certificato e un database di certificati emessi/revocati.
# Dovresti sostituire 'ca_private_key.pem', 'ca_certificate.pem' con i percorsi dei tuoi file effettivi
# e assicurarti che la classe CA possa accedere alla sua lista di revoche.
try:
    ca = CertificateAuthority.load("My Test CA")
    print("Certificate Authority caricata con successo.")
except Exception as e:
    print(f"Errore durante il caricamento della Certificate Authority: {e}")
    # In uno scenario reale, potresti voler uscire o gestire l'errore in modo più appropriato
    ca = None

def create_ocsp_response(request_data, ca_instance):
    """
    Crea una risposta OCSP firmata.

    Args:
        request_data: I dati grezzi della richiesta OCSP dal client.
        ca_instance: Un'istanza della CertificateAuthority.

    Returns:
        Una risposta OCSP firmata in formato DER.
    """
    if not ca_instance:
        # Costruisce una risposta con uno stato di errore interno se la CA non è disponibile
        builder = ocsp.OCSPResponseBuilder()
        return builder.response_status(ocsp.OCSPResponseStatus.INTERNAL_ERROR).build().public_bytes(serialization.Encoding.DER)

    ocsp_request = ocsp.load_der_ocsp_request(request_data)
    
    # Per questo progetto, gestiamo una richiesta alla volta.
    # Un responder reale scorrerebbe le richieste in ocsp_request.
    req = ocsp_request[0]

    # Controlla lo stato del certificato nel database della CA
    try:
        # Il numero di serie è ciò che usiamo per cercare il certificato
        cert_serial_number = req.serial_number
        status = ca_instance.check_certificate_status(cert_serial_number)
        
        if status == "revoked":
            revocation_time = ca_instance.get_revocation_time(cert_serial_number)
            cert_status = ocsp.Revoked(revocation_time=revocation_time, revocation_reason=ocsp.RevocationReason.UNSPECIFIED)
        elif status == "good":
            cert_status = ocsp.OCSPCertStatus.GOOD
        else: # "sconosciuto"
            cert_status = ocsp.OCSPCertStatus.UNKNOWN

    except Exception:
        cert_status = ocsp.OCSPCertStatus.UNKNOWN

    builder = ocsp.OCSPResponseBuilder()
    
    # Crea la risposta per il singolo certificato
    builder = builder.add_response(
        cert_id=req.issuer_name_hash,
        cert_hash_algorithm=req.hash_algorithm,
        serial_number=req.serial_number,
        cert_status=cert_status,
        this_update=datetime.datetime.now(datetime.timezone.utc),
        next_update=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),
    )

    # Firma la risposta con la chiave privata della CA
    # Il certificato del responder è tipicamente il certificato della CA stessa o un certificato dedicato alla firma OCSP.
    responder_cert = ca_instance.certificate
    responder_key = ca_instance.private_key
    
    signed_response = builder.responder_id(
        ocsp.OCSPResponderEncoding.NAME, responder_cert
    ).sign(responder_key, hashes.SHA256())

    return signed_response.public_bytes(serialization.Encoding.DER)

@app.route('/ocsp', methods=['POST'])
def ocsp_responder():
    """
    Endpoint Flask per la gestione delle richieste OCSP.
    """
    if request.headers.get('Content-Type') != 'application/ocsp-request':
        return "Invalid Content-Type", 400

    ocsp_request_data = request.get_data()
    ocsp_response_bytes = create_ocsp_response(ocsp_request_data, ca)

    return Response(ocsp_response_bytes, mimetype='application/ocsp-response')

if __name__ == '__main__':
    # Questo server dovrebbe essere eseguito con un server WSGI appropriato in produzione (come Gunicorn)
    # e dietro un reverse proxy (come Nginx).
    # Per lo sviluppo, il server integrato di Flask è sufficiente.
    # Dovrebbe essere in esecuzione su una porta diversa rispetto all'applicazione principale.
    print("Avvio dell'OCSP Responder su http://127.0.0.1:5001")
    app.run(port=5001, debug=True)