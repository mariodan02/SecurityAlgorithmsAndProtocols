# =============================================================================
# PKI PACKAGE - PUBLIC KEY INFRASTRUCTURE
# File: pki/__init__.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

"""
Modulo PKI per la gestione dell'infrastruttura a chiave pubblica
del sistema di credenziali accademiche decentralizzate.

Componenti principali:
- Certificate Authority: Emissione e gestione certificati X.509
- Certificate Manager: Parsing, validazione e operazioni sui certificati
- OCSP Client: Verifica stato certificati online

Utilizzo base:
    from pki import AcademicCertificateAuthority, CertificateManager, OCSPClient
    
    # Inizializza CA
    ca = AcademicCertificateAuthority()
    ca.initialize_ca()
    
    # Gestisci certificati
    cert_manager = CertificateManager()
    cert_info = cert_manager.parse_certificate(certificate)
    
    # Verifica status OCSP
    ocsp_client = OCSPClient()
    status = ocsp_client.check_certificate_status(cert, issuer_cert)
"""

# Imports principali
from .certificate_authority import (
    AcademicCertificateAuthority,
    UniversityInfo,
    CertificateRevocationInfo,
    create_sample_universities
)

from .certificate_manager import (
    CertificateManager,
    CertificateInfo,
    CertificateChain,
    CertificateStore
)

from .ocsp_client import (
    OCSPClient,
    OCSPStatus,
    OCSPResponse,
    OCSPConfiguration,
    MockOCSPResponder
)

# Versione del modulo
__version__ = "1.0.0"

# Esporta le classi principali
__all__ = [
    # Certificate Authority
    "AcademicCertificateAuthority",
    "UniversityInfo", 
    "CertificateRevocationInfo",
    "create_sample_universities",
    
    # Certificate Manager
    "CertificateManager",
    "CertificateInfo",
    "CertificateChain", 
    "CertificateStore",
    
    # OCSP Client
    "OCSPClient",
    "OCSPStatus",
    "OCSPResponse",
    "OCSPConfiguration",
    "MockOCSPResponder"
]

# Configurazione di logging
import logging

def setup_pki_logging(level=logging.INFO):
    """Configura logging per il modulo PKI"""
    logger = logging.getLogger(__name__)
    logger.setLevel(level)
    
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    return logger

# Logger del modulo
logger = setup_pki_logging()

def get_pki_info():
    """Informazioni sul modulo PKI"""
    return {
        "name": "Academic Credentials PKI",
        "version": __version__,
        "description": "Public Key Infrastructure for Academic Credentials System",
        "components": {
            "certificate_authority": "X.509 Certificate Authority",
            "certificate_manager": "Certificate parsing and validation", 
            "ocsp_client": "Online Certificate Status Protocol client"
        },
        "standards": [
            "X.509v3 Certificates",
            "PKCS#1 RSA Signatures", 
            "OCSP (RFC 6960)",
            "CRL (RFC 5280)"
        ]
    }

# Banner di inizializzazione
def print_pki_banner():
    """Stampa banner del modulo PKI"""
    print("🏛️" * 50)
    print("PUBLIC KEY INFRASTRUCTURE (PKI)")
    print("Sistema Credenziali Accademiche Decentralizzate")
    print(f"Versione: {__version__}")
    print("🏛️" * 50)

# Auto-esecuzione del banner in modalità debug
import os
if os.environ.get('PKI_DEBUG', '').lower() == 'true':
    print_pki_banner()
    logger.info("PKI module loaded in debug mode")