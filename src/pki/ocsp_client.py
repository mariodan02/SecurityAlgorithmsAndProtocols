# =============================================================================
# FASE 2: GESTIONE CERTIFICATI X.509 - OCSP CLIENT
# File: pki/ocsp_client.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

import datetime
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Dict, Any

# Cryptography imports
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtensionOID

# HTTP client
import requests

# Import moduli interni
import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from pki.certificate_manager import CertificateManager
except ImportError as e:
    print(f"⚠️  Errore import moduli interni in ocsp_client: {e}")
    raise

# =============================================================================
# 1. ENUMS E STRUTTURE DATI OCSP
# =============================================================================

class OCSPStatus(Enum):
    """Stati di un certificato secondo OCSP"""
    GOOD = "good"
    REVOKED = "revoked"
    UNKNOWN = "unknown"
    ERROR = "error"

@dataclass
class OCSPResponse:
    """Risposta da un responder OCSP"""
    status: OCSPStatus
    certificate_serial: int
    this_update: Optional[datetime.datetime] = None
    next_update: Optional[datetime.datetime] = None
    revocation_time: Optional[datetime.datetime] = None
    revocation_reason: Optional[str] = None
    response_data: Optional[bytes] = None
    error_message: Optional[str] = None

@dataclass
class OCSPConfiguration:
    """Configurazione del client OCSP"""
    timeout_seconds: int = 10
    cache_responses: bool = True
    cache_duration_minutes: int = 60
    user_agent: str = "AcademicCredentialsOCSPClient/1.0"

# =============================================================================
# 2. OCSP CLIENT
# =============================================================================

class OCSPClient:
    """Client per interrogare responder OCSP"""

    def __init__(self, config: Optional[OCSPConfiguration] = None):
        """
        Inizializza il client OCSP
        Args:
            config: Configurazione del client
        """
        self.config = config or OCSPConfiguration()
        self.cert_manager = CertificateManager()
        self.response_cache: Dict[int, OCSPResponse] = {}
        print("📡 OCSP Client inizializzato")

    def check_certificate_status(self,
                                 certificate_to_check: x509.Certificate,
                                 issuer_certificate: x509.Certificate) -> OCSPResponse:
        """
        Controlla lo stato di un certificato via OCSP.
        Args:
            certificate_to_check: Il certificato da verificare.
            issuer_certificate: Il certificato dell'emittente.
        Returns:
            Risposta OCSP con lo stato del certificato.
        """
        serial = certificate_to_check.serial_number

        # --- INIZIO CODICE CORRETTO ---
        # Controlla la cache in modo sicuro
        if self.config.cache_responses and serial in self.response_cache:
            cached_response = self.response_cache[serial]
            if cached_response.next_update:
                # Rendi "aware" entrambi gli oggetti datetime prima del confronto
                now_aware = datetime.datetime.now(datetime.timezone.utc)
                next_update_aware = cached_response.next_update
                
                # Se per qualche motivo next_update è "naive", lo rendiamo "aware"
                if next_update_aware.tzinfo is None:
                    next_update_aware = next_update_aware.replace(tzinfo=datetime.timezone.utc)

                if next_update_aware > now_aware:
                    print(f"✅ Stato certificato {serial} da cache: {cached_response.status.value}")
                    return cached_response
        # --- FINE CODICE CORRETTO ---

        # Estrae l'URL del responder OCSP dal certificato
        ocsp_url = self._get_ocsp_url(certificate_to_check)
        if not ocsp_url:
            return OCSPResponse(status=OCSPStatus.ERROR, certificate_serial=serial, error_message="URL OCSP non trovato nel certificato.")

        print(f"📡 Interrogando OCSP responder: {ocsp_url}")

        try:
            # Costruisce la richiesta OCSP
            builder = ocsp.OCSPRequestBuilder()
            builder = builder.add_certificate(certificate_to_check, issuer_certificate, hashes.SHA1())
            request = builder.build()

            # Invia la richiesta HTTP
            headers = {'Content-Type': 'application/ocsp-request'}
            http_response = requests.post(
                ocsp_url,
                data=request.public_bytes(serialization.Encoding.DER),
                headers=headers,
                timeout=self.config.timeout_seconds
            )
            http_response.raise_for_status()

            # Processa la risposta OCSP
            ocsp_resp = ocsp.load_der_ocsp_response(http_response.content)
            
            if ocsp_resp.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
                return OCSPResponse(status=OCSPStatus.ERROR, certificate_serial=serial, error_message=f"Stato risposta OCSP non valido: {ocsp_resp.response_status.name}")

            response = self._parse_ocsp_response(ocsp_resp)
            
            # Salva in cache
            if self.config.cache_responses:
                self.response_cache[serial] = response
            
            return response

        except Exception as e:
            return OCSPResponse(status=OCSPStatus.ERROR, certificate_serial=serial, error_message=str(e))

    def _get_ocsp_url(self, certificate: x509.Certificate) -> Optional[str]:
        """Estrae l'URL del responder OCSP dall'estensione AuthorityInformationAccess."""
        try:
            aia = certificate.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS).value
            for desc in aia:
                if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                    return desc.access_location.value
        except x509.ExtensionNotFound:
            return None
        return None

    def _parse_ocsp_response(self, ocsp_resp: ocsp.OCSPResponse) -> OCSPResponse:
        """Esegue il parsing della risposta OCSP."""
        serial = ocsp_resp.serial_number
        status = OCSPStatus.UNKNOWN
        revocation_time = None
        revocation_reason = None

        if ocsp_resp.certificate_status == ocsp.OCSPCertStatus.GOOD:
            status = OCSPStatus.GOOD
        elif ocsp_resp.certificate_status == ocsp.OCSPCertStatus.REVOKED:
            status = OCSPStatus.REVOKED
            revocation_time = ocsp_resp.revocation_time
            if ocsp_resp.revocation_reason:
                revocation_reason = ocsp_resp.revocation_reason.name

        return OCSPResponse(
            status=status,
            certificate_serial=serial,
            this_update=ocsp_resp.this_update_utc,
            next_update=ocsp_resp.next_update_utc,
            revocation_time=revocation_time,
            revocation_reason=revocation_reason,
            response_data=ocsp_resp.public_bytes(serialization.Encoding.DER)
        )
    
# =============================================================================
# 3. MOCK OCSP RESPONDER (PER TESTING)
# =============================================================================

class MockOCSPResponder:
    """Un semplice OCSP responder fittizio per scopi di test."""
    
    def __init__(self, ca_private_key, ca_certificate):
        self.revoked_serials = {}  # {serial: (revocation_time, reason)}
        self.ca_private_key = ca_private_key
        self.ca_certificate = ca_certificate

    def revoke(self, serial_number: int, reason: x509.ReasonFlags = x509.ReasonFlags.unspecified):
        self.revoked_serials[serial_number] = (datetime.datetime.now(datetime.timezone.utc), reason)

def handle_request(self, ocsp_request_der: bytes) -> bytes:
    """Gestisce una richiesta OCSP e restituisce una risposta firmata."""
    req = ocsp.load_der_ocsp_request(ocsp_request_der)

    builder = ocsp.OCSPResponseBuilder()

    serial_to_check = req.serial_number

    if serial_to_check in self.revoked_serials:
        revocation_time, reason_flag = self.revoked_serials[serial_to_check]
        # Aggiungi l'estensione CRLReason alla risposta
        builder = builder.add_response(
            cert_status=ocsp.OCSPCertStatus.REVOKED,
            issuer_key_hash=req.issuer_key_hash,
            issuer_name_hash=req.issuer_name_hash,
            serial_number=serial_to_check,
            this_update=datetime.datetime.now(datetime.timezone.utc),
            next_update=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1),
            revocation_time=revocation_time,
            revocation_reason=x509.CRLReason(reason_flag) # CORREZIONE QUI
        ).responder_id(ocsp.OCSPResponderEncoding.NAME, self.ca_certificate)
    else:
         builder = builder.add_response(
            cert_status=ocsp.OCSPCertStatus.GOOD,
            issuer_key_hash=req.issuer_key_hash,
            issuer_name_hash=req.issuer_name_hash,
            serial_number=serial_to_check,
            this_update=datetime.datetime.now(datetime.timezone.utc),
            next_update=datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
        ).responder_id(ocsp.OCSPResponderEncoding.NAME, self.ca_certificate)

    response = builder.build(self.ca_private_key, hashes.SHA256())
    return response.public_bytes(serialization.Encoding.DER)


if __name__ == "__main__":
    print("OCSP Client - Questo file non è pensato per essere eseguito direttamente.")
    print("Contiene le classi per la verifica dello stato dei certificati.")
    
    # Esempio di utilizzo (richiede un certificato e un emittente)
    # cert_manager = CertificateManager()
    # try:
    #     cert_to_check = cert_manager.load_certificate_from_file("path/to/certificate.pem")
    #     issuer_cert = cert_manager.load_certificate_from_file("path/to/issuer.pem")
    #
    #     ocsp_client = OCSPClient()
    #     response = ocsp_client.check_certificate_status(cert_to_check, issuer_cert)
    #
    #     print(f"Stato certificato: {response.status.value}")
    #     if response.status == OCSPStatus.REVOKED:
    #         print(f"Data di revoca: {response.revocation_time}")
    #
    # except (FileNotFoundError, RuntimeError) as e:
    #     print(f"Errore: {e}. Assicurati di avere i certificati di esempio.")