# =============================================================================
# CREDENTIALS PACKAGE - ACADEMIC CREDENTIALS
# File: credentials/__init__.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

"""
Modulo Credentials per la gestione delle credenziali accademiche
del sistema decentralizzato.

Componenti principali:
- Models: Strutture dati e validazione credenziali
- Issuer: Emissione credenziali da parte delle università
- Validator: Validazione e verifica credenziali

Utilizzo base:
    from credentials import AcademicCredential, CredentialFactory
    from credentials import AcademicCredentialIssuer, AcademicCredentialValidator
    
    # Crea credenziale
    credential = CredentialFactory.create_sample_credential()
    
    # Emetti credenziale
    issuer = AcademicCredentialIssuer(config)
    result = issuer.process_issuance_request(request_id)
    
    # Valida credenziale
    validator = AcademicCredentialValidator(config)
    report = validator.validate_credential(credential)
"""

# Import modelli principali
from .models import (
    # Credenziale principale
    AcademicCredential,
    
    # Componenti credenziale
    PersonalInfo,
    ExamGrade,
    Course,
    StudyPeriod,
    University,
    StudyProgram,
    DigitalSignature,
    Metadata,
    
    # Enums
    CredentialStatus,
    StudyType,
    GradeSystem,
    EQFLevel,
    
    # Factory
    CredentialFactory
)

# Import issuer
from .issuer import (
    AcademicCredentialIssuer,
    IssuerConfiguration,
    IssuanceRequest,
    IssuanceResult
)

# Import validator
from .validator import (
    AcademicCredentialValidator,
    ValidatorConfiguration,
    ValidationReport,
    ValidationResult,
    ValidationLevel,
    ValidationError
)

# Versione del modulo
__version__ = "1.0.0"

# Esporta le classi principali
__all__ = [
    # Modelli principali
    "AcademicCredential",
    "PersonalInfo",
    "ExamGrade", 
    "Course",
    "StudyPeriod",
    "University",
    "StudyProgram",
    "DigitalSignature",
    "Metadata",
    
    # Enums
    "CredentialStatus",
    "StudyType",
    "GradeSystem", 
    "EQFLevel",
    
    # Factory
    "CredentialFactory",
    
    # Issuer
    "AcademicCredentialIssuer",
    "IssuerConfiguration",
    "IssuanceRequest",
    "IssuanceResult",
    
    # Validator
    "AcademicCredentialValidator",
    "ValidatorConfiguration", 
    "ValidationReport",
    "ValidationResult",
    "ValidationLevel",
    "ValidationError"
]

# Standard supportati
SUPPORTED_STANDARDS = {
    "credential_format": "Academic Credentials v1.2",
    "signature_algorithms": ["RSA-SHA256-PSS", "RSA-SHA256-PKCS1v15"],
    "grade_systems": ["ITALIAN_30", "FRENCH_20", "GERMAN_6", "ECTS_GRADE", "US_GPA"],
    "eqf_levels": ["6", "7", "8"],
    "study_types": ["ERASMUS", "EXCHANGE", "DOUBLE_DEGREE", "REGULAR"]
}

def get_credentials_info():
    """Informazioni sul modulo credentials"""
    return {
        "name": "Academic Credentials System",
        "version": __version__,
        "description": "Complete system for academic credentials management",
        "components": {
            "models": "Data structures and validation",
            "issuer": "Credential issuance system",
            "validator": "Credential validation system"
        },
        "supported_standards": SUPPORTED_STANDARDS,
        "features": [
            "Pydantic data validation",
            "Digital signature support",
            "Merkle Tree integrity",
            "Selective disclosure ready",
            "Multi-level validation",
            "OCSP integration",
            "Batch processing",
            "Forensic analysis"
        ]
    }

# Configurazioni consigliate
RECOMMENDED_CONFIGURATIONS = {
    "issuer": {
        "auto_sign": True,
        "backup_enabled": True,
        "default_validity_days": 365,
        "key_size": 2048
    },
    "validator": {
        "validation_level": "standard",
        "strict_merkle_validation": True,
        "cache_enabled": True,
        "ocsp_enabled": True
    }
}

def validate_configuration(config_type: str, config: dict) -> bool:
    """
    Valida una configurazione
    
    Args:
        config_type: Tipo configurazione ("issuer" o "validator")
        config: Configurazione da validare
        
    Returns:
        True se valida
    """
    issues = []
    
    if config_type == "issuer":
        required_fields = ["university_info", "certificate_path", "private_key_path"]
        for field in required_fields:
            if field not in config:
                issues.append(f"Campo richiesto mancante: {field}")
    
    elif config_type == "validator":
        if config.get("ocsp_enabled", False):
            if config.get("ocsp_timeout_seconds", 0) <= 0:
                issues.append("OCSP timeout deve essere > 0")
    
    if issues:
        print("⚠️  Problemi configurazione trovati:")
        for issue in issues:
            print(f"   - {issue}")
        return False
    
    print("✅ Configurazione valida")
    return True

# Banner di inizializzazione
def print_credentials_banner():
    """Stampa banner del modulo credentials"""
    print("🎓" * 50)
    print("ACADEMIC CREDENTIALS SYSTEM")
    print("Sistema Credenziali Accademiche Decentralizzate")
    print(f"Versione: {__version__}")
    print("🎓" * 50)

# Configurazione di logging
import logging

def setup_credentials_logging(level=logging.INFO):
    """Configura logging per il modulo credentials"""
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
logger = setup_credentials_logging()

# Auto-esecuzione del banner in modalità debug
import os
if os.environ.get('CREDENTIALS_DEBUG', '').lower() == 'true':
    print_credentials_banner()
    logger.info("Credentials module loaded in debug mode")

# Funzioni di utilità per quick start
def create_demo_credential() -> AcademicCredential:
    """Crea una credenziale demo per testing rapido"""
    return CredentialFactory.create_sample_credential()

def quick_validate(credential: AcademicCredential) -> bool:
    """Validazione rapida di una credenziale"""
    try:
        validator = AcademicCredentialValidator()
        report = validator.validate_credential(credential, ValidationLevel.BASIC)
        return report.is_valid()
    except Exception:
        return False

# Esempi di utilizzo
USAGE_EXAMPLES = {
    "create_credential": """
from credentials import CredentialFactory
credential = CredentialFactory.create_sample_credential()
""",
    
    "issue_credential": """
from credentials import AcademicCredentialIssuer, IssuerConfiguration
config = IssuerConfiguration(...)
issuer = AcademicCredentialIssuer(config)
result = issuer.process_issuance_request(request_id)
""",
    
    "validate_credential": """
from credentials import AcademicCredentialValidator, ValidationLevel
validator = AcademicCredentialValidator()
report = validator.validate_credential(credential, ValidationLevel.STANDARD)
"""
}

def print_usage_examples():
    """Stampa esempi di utilizzo"""
    print("\n📖 ESEMPI DI UTILIZZO:")
    for title, code in USAGE_EXAMPLES.items():
        print(f"\n{title.upper()}:")
        print(code.strip())