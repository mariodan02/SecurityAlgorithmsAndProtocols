# =============================================================================
# PKI PACKAGE - PUBLIC KEY INFRASTRUCTURE (Simplified)
# File: pki/__init__.py
# =============================================================================

"""
Modulo PKI per la gestione dell'infrastruttura a chiave pubblica.
Questo modulo si concentra sulla gestione e validazione di certificati esistenti.
"""

# Imports principali dal Certificate Manager
from .certificate_manager import (
    CertificateManager,
    CertificateInfo,
    CertificateChain,
    CertificateStore
)

# Versione del modulo
__version__ = "1.0.0-manual-pki"

# Esporta le classi principali
__all__ = [
    "CertificateManager",
    "CertificateInfo",
    "CertificateChain",
    "CertificateStore",
]