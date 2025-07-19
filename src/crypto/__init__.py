from .foundations import (
    RSAKeyManager,
    DigitalSignature,
    MerkleTree,
    CryptoUtils,
    CryptoManager
)

__version__ = "1.0.0"

__all__ = [
    "RSAKeyManager",
    "DigitalSignature", 
    "MerkleTree",
    "CryptoUtils",
    "CryptoManager"
]

RECOMMENDED_CONFIG = {
    "rsa_key_size": 2048,
    "rsa_key_size_ca": 4096,
    "padding_type": "PSS",
    "hash_algorithm": "SHA-256",
    "merkle_hash": "SHA-256"
}

SUPPORTED_ALGORITHMS = {
    "asymmetric": ["RSA-2048", "RSA-4096"],
    "signatures": ["RSA-SHA256-PSS", "RSA-SHA256-PKCS1v15"],
    "hashing": ["SHA-256", "SHA-384", "SHA-512"],
    "merkle_tree": ["SHA-256"]
}

def get_crypto_info():
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
    issues = []
    
    key_size = config.get('rsa_key_size', 0)
    if key_size < 2048:
        issues.append(f"RSA key size {key_size} too small (minimum 2048)")
    
    padding = config.get('padding_type', '')
    if padding not in ['PSS', 'PKCS1v15']:
        issues.append(f"Padding type {padding} not supported")
    
    hash_alg = config.get('hash_algorithm', '')
    if hash_alg not in ['SHA-256', 'SHA-384', 'SHA-512']:
        issues.append(f"Hash algorithm {hash_alg} not supported")
    
    return not issues