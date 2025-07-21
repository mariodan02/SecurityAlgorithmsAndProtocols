"""Client OCSP per la verifica dello stato dei certificati."""

import datetime
import requests
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Dict

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp
from cryptography.x509.oid import ExtensionOID

from .certificate_manager import CertificateManager


class OCSPStatus(Enum):
    """Stati di un certificato secondo OCSP."""
    GOOD = "good"
    REVOKED = "revoked"
    UNKNOWN = "unknown"
    ERROR = "error"


@dataclass
class OCSPResponse:
    """Risposta da un responder OCSP."""
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
    """Configurazione del client OCSP."""
    timeout_seconds: int = 10
    cache_responses: bool = True
    cache_duration_minutes: int = 60
    user_agent: str = "AcademicCredentialsOCSPClient/1.0"


class OCSPClient:
    """Client per interrogare responder OCSP."""

    def __init__(self, config: Optional[OCSPConfiguration] = None):
        """
        Inizializza il client OCSP.
        
        Args:
            config: Configurazione del client
        """
        self.config = config or OCSPConfiguration()
        self.cert_manager = CertificateManager()
        self.response_cache: Dict[int, OCSPResponse] = {}

    def check_certificate_status(self,
                                certificate_to_check: x509.Certificate,
                                issuer_certificate: x509.Certificate) -> OCSPResponse:
        """
        Controlla lo stato di un certificato via OCSP.
        
        Args:
            certificate_to_check: Il certificato da verificare
            issuer_certificate: Il certificato dell'emittente
            
        Returns:
            Risposta OCSP con lo stato del certificato
        """
        serial = certificate_to_check.serial_number

        # Controlla la cache se abilitata
        if self.config.cache_responses and serial in self.response_cache:
            cached_response = self.response_cache[serial]
            if cached_response.next_update:
                now_aware = datetime.datetime.now(datetime.timezone.utc)
                next_update_aware = cached_response.next_update
                
                # Assicura che entrambi gli oggetti datetime siano timezone-aware
                if next_update_aware.tzinfo is None:
                    next_update_aware = next_update_aware.replace(tzinfo=datetime.timezone.utc)

                if next_update_aware > now_aware:
                    return cached_response

        # Estrae l'URL del responder OCSP dal certificato
        ocsp_url = self._get_ocsp_url(certificate_to_check)
        if not ocsp_url:
            return OCSPResponse(
                status=OCSPStatus.ERROR, 
                certificate_serial=serial, 
                error_message="URL OCSP non trovato nel certificato"
            )

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
                return OCSPResponse(
                    status=OCSPStatus.ERROR, 
                    certificate_serial=serial, 
                    error_message=f"Stato risposta OCSP non valido: {ocsp_resp.response_status.name}"
                )

            response = self._parse_ocsp_response(ocsp_resp)
            
            # Salva in cache se abilitato
            if self.config.cache_responses:
                self.response_cache[serial] = response
            
            return response

        except Exception as e:
            return OCSPResponse(
                status=OCSPStatus.ERROR, 
                certificate_serial=serial, 
                error_message=str(e)
            )

    def _get_ocsp_url(self, certificate: x509.Certificate) -> Optional[str]:
        """Estrae l'URL del responder OCSP dall'estensione AuthorityInformationAccess."""
        try:
            aia = certificate.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_INFORMATION_ACCESS
            ).value
            
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