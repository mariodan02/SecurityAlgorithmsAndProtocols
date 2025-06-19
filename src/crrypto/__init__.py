# =============================================================================
# CRYPTO PACKAGE - CRYPTOGRAPHIC FOUNDATIONS
# File: crypto/__init__.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

"""
Modulo Crypto per le fondamenta crittografiche del sistema 
di credenziali accademiche decentralizzate.

Componenti principali:
- RSA Key Manager: Gestione chiavi asimmetriche
- Digital Signature: Firma digitale RSA-SHA256
- Merkle Tree: Alberi di Merkle per divulgazione selettiva
- Crypto Utils: Utilità crittografiche generali

Utilizzo base:
    from crypto import RSAKeyManager, DigitalSignature, MerkleTree, CryptoUtils
    
    # Gestione chiavi
    key_manager = RSAKeyManager(2048)
    private_key, public_key = key_manager.generate_key_pair()
    
    # Firma digitale
    signer = DigitalSignature("PSS")
    signature = signer.sign_data(private_key, data)
    
    # Merkle Tree
    tree = MerkleTree(data_list)
    proof = tree.generate_proof(index)
"""

# Imports principali
from .foundations import (
    RSAKeyManager,
    DigitalSignature,
    MerkleTree,
    CryptoUtils,
    CryptoManager
)

# Versione del modulo
__version__ = "1.0.0"

# Esporta le classi principali
__all__ = [
    "RSAKeyManager",
    "DigitalSignature", 
    "MerkleTree",
    "CryptoUtils",
    "CryptoManager"
]

# Configurazioni di sicurezza consigliate
RECOMMENDED_CONFIG = {
    "rsa_key_size": 2048,  # Minimo consigliato
    "rsa_key_size_ca": 4096,  # Per Certificate Authority
    "padding_type": "PSS",  # Più sicuro di PKCS1v15
    "hash_algorithm": "SHA-256",
    "merkle_hash": "SHA-256"
}

# Algoritmi supportati
SUPPORTED_ALGORITHMS = {
    "asymmetric": ["RSA-2048", "RSA-4096"],
    "signatures": ["RSA-SHA256-PSS", "RSA-SHA256-PKCS1v15"],
    "hashing": ["SHA-256", "SHA-384", "SHA-512"],
    "merkle_tree": ["SHA-256"]
}

def get_crypto_info():
    """Informazioni sul modulo crypto"""
    return {
        "name": "Academic Credentials Crypto",
        "version": __version__,
        "description": "Cryptographic foundations for academic credentials",
        "recommended_config": RECOMMENDED_CONFIG,
        "supported_algorithms": SUPPORTED_ALGORITHMS,
        "security_features": [
            "RSA Key Generation (2048/4096 bit)",
            "Digital Signatures (PSS/PKCS1v15)",
            "Merkle Trees for Selective Disclosure",
            "Secure Timestamp Generation",
            "Timing-Attack Resistant Comparisons"
        ]
    }

def validate_security_config(config: dict) -> bool:
    """
    Valida una configurazione di sicurezza
    
    Args:
        config: Configurazione da validare
        
    Returns:
        True se la configurazione è sicura
    """
    issues = []
    
    # Verifica dimensione chiave RSA
    key_size = config.get('rsa_key_size', 0)
    if key_size < 2048:
        issues.append(f"RSA key size {key_size} troppo piccola (minimo 2048)")
    
    # Verifica algoritmo di padding
    padding = config.get('padding_type', '')
    if padding not in ['PSS', 'PKCS1v15']:
        issues.append(f"Padding type {padding} non supportato")
    
    # Verifica algoritmo hash
    hash_alg = config.get('hash_algorithm', '')
    if hash_alg not in ['SHA-256', 'SHA-384', 'SHA-512']:
        issues.append(f"Hash algorithm {hash_alg} non supportato")
    
    if issues:
        print("⚠️  Problemi di sicurezza trovati:")
        for issue in issues:
            print(f"   - {issue}")
        return False
    
    print("✅ Configurazione di sicurezza valida")
    return True

# Banner di inizializzazione
def print_crypto_banner():
    """Stampa banner del modulo crypto"""
    print("🔐" * 50)
    print("CRYPTOGRAPHIC FOUNDATIONS")
    print("Sistema Credenziali Accademiche Decentralizzate")
    print(f"Versione: {__version__}")
    print("🔐" * 50)

# Configurazione di logging
import logging

def setup_crypto_logging(level=logging.INFO):
    """Configura logging per il modulo crypto"""
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
logger = setup_crypto_logging()

# Auto-esecuzione del banner in modalità debug
import os
if os.environ.get('CRYPTO_DEBUG', '').lower() == 'true':
    print_crypto_banner()
    logger.info("Crypto module loaded in debug mode")