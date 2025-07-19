"""
Modulo Credentials per la gestione delle credenziali accademiche
del sistema decentralizzato.

Questo modulo fornisce le componenti principali per:
- Gestione strutture dati e validazione credenziali
- Emissione credenziali da parte delle università
- Validazione e verifica credenziali
"""

import logging
from typing import Dict, Any

# Import modelli principali
from .models import (
    AcademicCredential,
    PersonalInfo,
    ExamGrade,
    Course,
    StudyPeriod,
    University,
    StudyProgram,
    DigitalSignature,
    Metadata,
    CredentialStatus,
    StudyType,
    GradeSystem,
    EQFLevel,
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

__version__ = "1.0.0"

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

# Standard supportati dal sistema
SUPPORTED_STANDARDS = {
    "credential_format": "Academic Credentials v1.2",
    "signature_algorithms": ["RSA-SHA256-PSS", "RSA-SHA256-PKCS1v15"],
    "grade_systems": ["ITALIAN_30", "FRENCH_20", "GERMAN_6", "ECTS_GRADE", "US_GPA"],
    "eqf_levels": ["6", "7", "8"],
    "study_types": ["ERASMUS", "EXCHANGE", "DOUBLE_DEGREE", "REGULAR"]
}

# Configurazioni consigliate per i componenti
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


def get_credentials_info() -> Dict[str, Any]:
    """
    Restituisce informazioni sul modulo credentials.
    
    Returns:
        Dict contenente informazioni dettagliate sul modulo
    """
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


def validate_configuration(config_type: str, config: Dict[str, Any]) -> bool:
    """
    Valida una configurazione per issuer o validator.
    
    Args:
        config_type: Tipo configurazione ("issuer" o "validator")
        config: Dizionario configurazione da validare
        
    Returns:
        True se la configurazione è valida, False altrimenti
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
        logger = logging.getLogger(__name__)
        logger.warning("Problemi configurazione trovati: %s", issues)
        return False
    
    return True


def setup_credentials_logging(level: int = logging.INFO) -> logging.Logger:
    """
    Configura il sistema di logging per il modulo credentials.
    
    Args:
        level: Livello di logging (default: INFO)
        
    Returns:
        Logger configurato
    """
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


def create_demo_credential() -> AcademicCredential:
    """
    Crea una credenziale demo per testing rapido.
    
    Returns:
        Credenziale accademica di esempio
    """
    return CredentialFactory.create_sample_credential()


def quick_validate(credential: AcademicCredential) -> bool:
    """
    Esegue una validazione rapida di una credenziale.
    
    Args:
        credential: Credenziale da validare
        
    Returns:
        True se la credenziale è valida, False altrimenti
    """
    try:
        validator = AcademicCredentialValidator()
        report = validator.validate_credential(credential, ValidationLevel.BASIC)
        return report.is_valid()
    except Exception:
        return False


# Inizializza logger del modulo
logger = setup_credentials_logging()