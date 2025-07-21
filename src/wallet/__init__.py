"""
Modulo Wallet per la gestione del portafoglio digitale studenti
e la divulgazione selettiva delle credenziali accademiche.

Componenti principali:
- Student Wallet: Portafoglio digitale sicuro per credenziali
- Selective Disclosure: Divulgazione selettiva attributi
- Presentation Manager: Gestione presentazioni verificabili

Utilizzo base:
    from wallet import AcademicStudentWallet, WalletConfiguration
    from wallet import SelectiveDisclosureManager, PresentationManager
    
    # Crea wallet
    config = WalletConfiguration(...)
    wallet = AcademicStudentWallet(config)
    wallet.create_wallet("password")
    
    # Divulgazione selettiva
    disclosure_manager = SelectiveDisclosureManager()
    disclosure = disclosure_manager.create_selective_disclosure(...)
    
    # Presentazioni
    presentation_manager = PresentationManager(wallet)
    presentation_id = presentation_manager.create_presentation(...)
"""

# Import wallet principale
from typing import List, Tuple
from .student_wallet import (
    AcademicStudentWallet,
    WalletConfiguration,
    WalletCredential,
    WalletStatus,
    WalletStats,
    CredentialStorage
)

# Import selective disclosure
from .selective_disclosure import (
    SelectiveDisclosureManager,
    SelectiveDisclosure,
    DisclosureLevel,
    AttributeType,
    AttributeSelector,
    MerkleProof
)

# Import presentation manager
from .presentation import (
    PresentationManager,
    VerifiablePresentation,
    PresentationTemplate,
    PresentationFormat,
    PresentationStatus
)

# Versione del modulo
__version__ = "1.0.0"

# Esporta le classi principali
__all__ = [
    # Student Wallet
    "AcademicStudentWallet",
    "WalletConfiguration",
    "WalletCredential",
    "WalletStatus",
    "WalletStats",
    "CredentialStorage",
    
    # Selective Disclosure
    "SelectiveDisclosureManager",
    "SelectiveDisclosure",
    "DisclosureLevel",
    "AttributeType",
    "AttributeSelector",
    "MerkleProof",
    
    # Presentation Manager
    "PresentationManager",
    "VerifiablePresentation",
    "PresentationTemplate",
    "PresentationFormat",
    "PresentationStatus"
]

# Configurazioni consigliate
RECOMMENDED_WALLET_CONFIG = {
    "storage_mode": "encrypted_local",
    "auto_backup": True,
    "backup_interval_hours": 24,
    "max_backup_files": 10,
    "require_password": True,
    "password_min_length": 8,
    "session_timeout_minutes": 30,
    "auto_validate_credentials": True
}

# Livelli di disclosure consigliati per diversi scenari
DISCLOSURE_SCENARIOS = {
    "university_verification": {
        "level": DisclosureLevel.MINIMAL,
        "description": "Verifica iscrizione università",
        "typical_attributes": [
            "metadata.credential_id",
            "subject.pseudonym",
            "issuer.name",
            "total_ects_credits"
        ]
    },
    
    "academic_transcript": {
        "level": DisclosureLevel.DETAILED,
        "description": "Trascrizione accademica completa",
        "typical_attributes": [
            "metadata.credential_id",
            "subject.pseudonym",
            "issuer.name",
            "host_university.name",
            "courses.*.course_name",
            "courses.*.grade.score",
            "average_grade"
        ]
    },
    
    "job_application": {
        "level": DisclosureLevel.STANDARD,
        "description": "Candidatura lavorativa",
        "typical_attributes": [
            "subject.pseudonym",
            "host_university.name",
            "study_program.name",
            "study_program.eqf_level",
            "total_ects_credits",
            "average_grade"
        ]
    },
    
    "scholarship_application": {
        "level": DisclosureLevel.DETAILED,
        "description": "Domanda borsa di studio",
        "typical_attributes": [
            "metadata.credential_id",
            "subject.pseudonym",
            "issuer.name",
            "host_university.name",
            "study_program.name",
            "courses.*.course_name",
            "courses.*.grade.score",
            "average_grade",
            "total_ects_credits"
        ]
    }
}

def get_wallet_info():
    """Informazioni sul modulo wallet"""
    return {
        "name": "Academic Credentials Digital Wallet",
        "version": __version__,
        "description": "Secure digital wallet for academic credentials with selective disclosure",
        "components": {
            "student_wallet": "Secure credential storage and management",
            "selective_disclosure": "Privacy-preserving attribute disclosure",
            "presentation": "Verifiable presentation creation and management"
        },
        "features": [
            "Encrypted credential storage",
            "Selective attribute disclosure",
            "Merkle tree proofs",
            "Digital signatures",
            "Multiple presentation formats",
            "Template-based presentations",
            "Automatic backup",
            "Search and filtering",
            "Cache optimization"
        ],
        "supported_formats": [
            "JSON", "Signed JSON", "W3C Verifiable Credentials", "HTML Reports"
        ]
    }

def create_default_wallet_config(wallet_name: str, storage_path: str) -> WalletConfiguration:
    """
    Crea configurazione wallet con impostazioni raccomandate
    
    Args:
        wallet_name: Nome del wallet
        storage_path: Percorso di storage
        
    Returns:
        Configurazione wallet
    """
    return WalletConfiguration(
        wallet_name=wallet_name,
        storage_path=storage_path,
        **RECOMMENDED_WALLET_CONFIG
    )

def get_disclosure_template(scenario: str) -> dict:
    """
    Ottiene template per scenario di divulgazione
    
    Args:
        scenario: Nome scenario (university_verification, academic_transcript, etc.)
        
    Returns:
        Template di divulgazione
    """
    return DISCLOSURE_SCENARIOS.get(scenario, {})

def validate_wallet_config(config: WalletConfiguration) -> Tuple[bool, List[str]]:
    """
    Valida configurazione wallet
    
    Args:
        config: Configurazione da validare
        
    Returns:
        Tupla (valida, lista_errori)
    """
    errors = []
    
    # Verifica campi obbligatori
    if not config.wallet_name or len(config.wallet_name.strip()) < 3:
        errors.append("Nome wallet deve essere almeno 3 caratteri")
    
    if not config.storage_path:
        errors.append("Percorso storage obbligatorio")
    
    # Verifica password policy
    if config.require_password and config.password_min_length < 8:
        errors.append("Lunghezza minima password deve essere >= 8")
    
    # Verifica backup settings
    if config.auto_backup:
        if config.backup_interval_hours < 1:
            errors.append("Intervallo backup deve essere >= 1 ora")
        
        if config.max_backup_files < 1:
            errors.append("Numero massimo backup deve essere >= 1")
    
    # Verifica session timeout
    if config.session_timeout_minutes < 5:
        errors.append("Timeout sessione deve essere >= 5 minuti")
    
    return len(errors) == 0, errors

def quick_start_wallet(name: str, password: str, storage_path: str = None) -> AcademicStudentWallet:
    """
    Quick start per creare e inizializzare un wallet
    
    Args:
        name: Nome del wallet
        password: Password del wallet
        storage_path: Percorso storage (opzionale)
        
    Returns:
        Wallet inizializzato e sbloccato
    """
    if storage_path is None:
        storage_path = f"./wallet/{name.lower().replace(' ', '_')}"
    
    # Crea configurazione
    config = create_default_wallet_config(name, storage_path)
    
    # Valida configurazione
    is_valid, errors = validate_wallet_config(config)
    if not is_valid:
        raise ValueError(f"Configurazione non valida: {errors}")
    
    # Crea wallet
    wallet = AcademicStudentWallet(config)
    
    # Crea o sblocca
    if not wallet.wallet_file.exists():
        success = wallet.create_wallet(password)
        if not success:
            raise RuntimeError("Creazione wallet fallita")
    else:
        success = wallet.unlock_wallet(password)
        if not success:
            raise RuntimeError("Sblocco wallet fallito")
    
    return wallet

# Esempi di utilizzo
USAGE_EXAMPLES = {
    "create_wallet": """
from wallet import quick_start_wallet
wallet = quick_start_wallet("Mario Rossi", "SecurePassword123!")
""",
    
    "selective_disclosure": """
from wallet import SelectiveDisclosureManager, DisclosureLevel
manager = SelectiveDisclosureManager()
disclosure = manager.create_predefined_disclosure(
    credential, DisclosureLevel.STANDARD
)
""",
    
    "create_presentation": """
from wallet import PresentationManager
pres_manager = PresentationManager(wallet)
presentation_id = pres_manager.create_presentation_from_template(
    "university_enrollment", [storage_id], "Verifica iscrizione"
)
"""
}

# Banner di inizializzazione
def print_wallet_banner():
    """Stampa banner del modulo wallet"""
    print("👤" * 50)
    print("DIGITAL WALLET SYSTEM")
    print("Portafoglio Digitale Credenziali Accademiche")
    print(f"Versione: {__version__}")
    print("👤" * 50)

# Configurazione di logging
import logging

def setup_wallet_logging(level=logging.INFO):
    """Configura logging per il modulo wallet"""
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
logger = setup_wallet_logging()

# Auto-esecuzione del banner in modalità debug
import os
if os.environ.get('WALLET_DEBUG', '').lower() == 'true':
    print_wallet_banner()
    logger.info("Wallet module loaded in debug mode")

def print_usage_examples():
    """Stampa esempi di utilizzo"""
    print("\nESEMPI DI UTILIZZO WALLET:")
    for title, code in USAGE_EXAMPLES.items():
        print(f"\n{title.upper()}:")
        print(code.strip())

def list_disclosure_scenarios():
    """Lista scenari di divulgazione disponibili"""
    print("\nSCENARI DI DIVULGAZIONE DISPONIBILI:")
    for scenario, info in DISCLOSURE_SCENARIOS.items():
        print(f"\n{scenario.upper()}:")
        print(f"   Livello: {info['level'].value}")
        print(f"   Descrizione: {info['description']}")
        print(f"   Attributi tipici: {len(info['typical_attributes'])}")

# Funzioni helper per import comuni
def get_all_wallet_classes():
    """Ottiene tutte le classi del modulo wallet"""
    return {
        'AcademicStudentWallet': AcademicStudentWallet,
        'WalletConfiguration': WalletConfiguration,
        'SelectiveDisclosureManager': SelectiveDisclosureManager,
        'PresentationManager': PresentationManager,
        'DisclosureLevel': DisclosureLevel,
        'PresentationFormat': PresentationFormat
    }