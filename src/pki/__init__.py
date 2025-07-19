"""
Modulo PKI per la gestione dell'infrastruttura a chiave pubblica.
Gestisce certificati X.509 e operazioni correlate.
"""

from .certificate_manager import (
    CertificateManager,
    CertificateInfo,
    CertificateChain,
    CertificateStore
)

__version__ = "1.0.0-manual-pki"

__all__ = [
    "CertificateManager",
    "CertificateInfo", 
    "CertificateChain",
    "CertificateStore",
]