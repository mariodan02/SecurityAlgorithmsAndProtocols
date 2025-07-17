# =============================================================================
# FASE 4: WALLET E DIVULGAZIONE SELETTIVA - STUDENT WALLET (Versione Corretta)
# File: wallet/student_wallet.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

import os
import json
import datetime
import getpass
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
import uuid
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken

# Cryptography imports
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

# Import moduli interni
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from crypto.foundations import RSAKeyManager, DigitalSignature, CryptoUtils, MerkleTree
    from credentials.models import AcademicCredential, CredentialStatus, Course
    from credentials.validator import AcademicCredentialValidator, ValidationLevel
except ImportError as e:
    print(f"⚠️  Errore import moduli interni: {e}")
    print("   Assicurati che tutti i moduli siano presenti nel progetto")
    raise


# =============================================================================
# 1. ENUMS E STRUTTURE DATI WALLET 
# =============================================================================

class WalletStatus(Enum):
    LOCKED = "locked"
    UNLOCKED = "unlocked"
    CORRUPTED = "corrupted"


class CredentialStorage(Enum):
    ENCRYPTED_LOCAL = "encrypted_local"
    PLAINTEXT_LOCAL = "plaintext_local"


@dataclass
class WalletCredential:
    credential: AcademicCredential
    storage_id: str
    added_date: datetime.datetime
    tags: List[str] = field(default_factory=list)
    notes: Optional[str] = None
    favorite: bool = False
    last_accessed: Optional[datetime.datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'credential': self.credential.to_dict(),
            'storage_id': self.storage_id,
            'added_date': self.added_date.isoformat(),
            'tags': self.tags,
            'notes': self.notes,
            'favorite': self.favorite,
            'last_accessed': self.last_accessed.isoformat() if self.last_accessed else None
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'WalletCredential':
        credential = AcademicCredential.from_dict(data['credential'])
        return cls(
            credential=credential,
            storage_id=data['storage_id'],
            added_date=datetime.datetime.fromisoformat(data['added_date']),
            tags=data.get('tags', []),
            notes=data.get('notes'),
            favorite=data.get('favorite', False),
            last_accessed=(
                datetime.datetime.fromisoformat(data['last_accessed'])
                if data.get('last_accessed') else None
            )
        )

@dataclass
class WalletConfiguration:
    wallet_name: str
    storage_path: str
    storage_mode: CredentialStorage = CredentialStorage.ENCRYPTED_LOCAL
    auto_backup: bool = True
    backup_interval_hours: int = 24
    max_backup_files: int = 10
    require_password: bool = True
    password_min_length: int = 8
    session_timeout_minutes: int = 15
    auto_validate_credentials: bool = True


@dataclass
class WalletStats:
    total_credentials: int = 0
    active_credentials: int = 0
    expired_credentials: int = 0
    revoked_credentials: int = 0
    universities_count: int = 0
    total_ects_credits: int = 0
    average_grade: Optional[str] = None
    last_activity: Optional[datetime.datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'total_credentials': self.total_credentials,
            'active_credentials': self.active_credentials,
            'expired_credentials': self.expired_credentials,
            'revoked_credentials': self.revoked_credentials,
            'universities_count': self.universities_count,
            'total_ects_credits': self.total_ects_credits,
            'average_grade': self.average_grade,
            'last_activity': self.last_activity.isoformat() if self.last_activity else None
        }


# =============================================================================
# 2. ACADEMIC STUDENT WALLET (con implementazione Fernet)
# =============================================================================

class AcademicStudentWallet:
    """Wallet digitale per studenti che usa Fernet per la cifratura dei dati a riposo."""
    
    def __init__(self, config: WalletConfiguration):
        self.config = config
        self.status = WalletStatus.LOCKED
        self.crypto_utils = CryptoUtils()
        self.key_manager = RSAKeyManager(2048)
        
        if config.auto_validate_credentials:
            self.credential_validator = AcademicCredentialValidator()
        else:
            self.credential_validator = None
        
        self.credentials: Dict[str, WalletCredential] = {}
        self.wallet_private_key: Optional[rsa.RSAPrivateKey] = None
        self.wallet_public_key: Optional[rsa.RSAPublicKey] = None
        self.last_activity: Optional[datetime.datetime] = None
        self.fernet_key: Optional[bytes] = None
        self.wallet_salt: Optional[bytes] = None

        self.wallet_dir = Path(config.storage_path)
        self.wallet_file = self.wallet_dir / "wallet.enc"
        self.salt_file = self.wallet_dir / "wallet.salt"
        self.keys_file = self.wallet_dir / "keys.enc"
        self.backup_dir = self.wallet_dir / "backups"
        
        self.wallet_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(exist_ok=True)
        
        print(f"👤 Student Wallet inizializzato: {config.wallet_name}")
        print(f"   Storage: {config.storage_path}")

    def create_wallet(self, password: str) -> bool:
        if self.wallet_file.exists():
            print("❌ Wallet già esistente. Impossibile creare.")
            return False
        
        if not self._validate_password(password):
            return False
        
        print(f"🔨 Creando nuovo wallet cifrato: {self.config.wallet_name}")
        
        try:
            self.wallet_private_key, self.wallet_public_key = self.key_manager.generate_key_pair()
            self.wallet_salt = os.urandom(16)
            with open(self.salt_file, "wb") as f:
                f.write(self.wallet_salt)
            
            self.fernet_key = self.crypto_utils.derive_key_from_password(password, self.wallet_salt)
            self._save_encrypted_keys()
            
            self.credentials = {}
            self.status = WalletStatus.UNLOCKED
            self.last_activity = datetime.datetime.utcnow()
            self._save_wallet()
            
            print("✅ Wallet creato e cifrato con successo!")
            return True
            
        except Exception as e:
            print(f"❌ Errore critico durante la creazione del wallet: {e}")
            if self.wallet_file.exists(): self.wallet_file.unlink()
            if self.salt_file.exists(): self.salt_file.unlink()
            if self.keys_file.exists(): self.keys_file.unlink()
            return False

    def unlock_wallet(self, password: str) -> bool:
        if not self.wallet_file.exists() or not self.salt_file.exists():
            print("❌ File del wallet o del salt non trovati.")
            return False
        
        print(f"🔓 Tentativo di sblocco wallet: {self.config.wallet_name}")
        
        try:
            with open(self.salt_file, "rb") as f:
                self.wallet_salt = f.read()

            self.fernet_key = self.crypto_utils.derive_key_from_password(password, self.wallet_salt)

            if not self._load_wallet():
                raise InvalidToken("Caricamento del wallet fallito, possibile password errata.")

            if not self._load_encrypted_keys():
                raise RuntimeError("Caricamento chiavi RSA fallito.")

            self.status = WalletStatus.UNLOCKED
            self.last_activity = datetime.datetime.utcnow()
            
            print(f"✅ Wallet sbloccato! Trovate {len(self.credentials)} credenziali.")
            return True

        except InvalidToken:
            print("❌ Password errata o file del wallet corrotto.")
            self._cleanup_session()
            return False
        except Exception as e:
            print(f"❌ Errore critico durante lo sblocco: {e}")
            self._cleanup_session()
            return False

    def lock_wallet(self) -> bool:
        if self.status == WalletStatus.LOCKED:
            return True
        
        print("🔒 Blocco del wallet...")
        try:
            if self.status == WalletStatus.UNLOCKED:
                self._save_wallet()
            self._cleanup_session()
            print("✅ Wallet bloccato in modo sicuro.")
            return True
        except Exception as e:
            print(f"❌ Errore durante il blocco del wallet: {e}")
            return False
            
    def _save_wallet(self):
        if self.status != WalletStatus.UNLOCKED or not self.fernet_key:
            raise RuntimeError("Impossibile salvare: il wallet è bloccato o la chiave di sessione non è disponibile.")
        
        wallet_content = {
            'version': '1.2-fernet',
            'credentials': [cred.to_dict() for cred in self.credentials.values()]
        }
        
        f = Fernet(self.fernet_key)
        json_data = json.dumps(wallet_content, default=str).encode('utf-8')
        encrypted_data = f.encrypt(json_data)
        
        self.wallet_file.write_bytes(encrypted_data)

    def _load_wallet(self) -> bool:
        f = Fernet(self.fernet_key)
        encrypted_data = self.wallet_file.read_bytes()
        
        if not encrypted_data:
            self.credentials = {}
            return True

        decrypted_data = f.decrypt(encrypted_data)
        wallet_content = json.loads(decrypted_data.decode('utf-8'))
        
        self.credentials = {
            cred_data['storage_id']: WalletCredential.from_dict(cred_data)
            for cred_data in wallet_content.get('credentials', [])
        }
        return True

    def _save_encrypted_keys(self):
        f = Fernet(self.fernet_key)
        keys_json = json.dumps({
            'private_key': self.key_manager.serialize_private_key(self.wallet_private_key).decode('utf-8'),
            'public_key': self.key_manager.serialize_public_key(self.wallet_public_key).decode('utf-8')
        }).encode('utf-8')
        
        encrypted_keys = f.encrypt(keys_json)
        self.keys_file.write_bytes(encrypted_keys)
        os.chmod(self.keys_file, 0o600)

    def _load_encrypted_keys(self) -> bool:
        fernet_instance = Fernet(self.fernet_key)
        
        with open(self.keys_file, 'rb') as key_file_handle:
            encrypted_keys = key_file_handle.read()
        
        decrypted_keys_json = fernet_instance.decrypt(encrypted_keys)

        keys_data = json.loads(decrypted_keys_json.decode('utf-8'))
        
        self.wallet_private_key = self.key_manager.deserialize_private_key(keys_data['private_key'].encode('utf-8'))
        self.wallet_public_key = self.key_manager.deserialize_public_key(keys_data['public_key'].encode('utf-8'))
        return True

    def _cleanup_session(self):
        self.wallet_private_key = None
        self.wallet_public_key = None
        self.fernet_key = None
        self.wallet_salt = None
        self.credentials = {}
        self.status = WalletStatus.LOCKED

    def _validate_password(self, password: str) -> bool:
        if len(password) < self.config.password_min_length:
            print(f"❌ Password troppo corta (minimo {self.config.password_min_length} caratteri)")
            return False
        if not any(c.isupper() for c in password):
            print("❌ La password deve contenere almeno una lettera maiuscola.")
            return False
        if not any(c.isdigit() for c in password):
            print("❌ La password deve contenere almeno un numero.")
            return False
        return True

    def add_credential(self, credential: AcademicCredential, tags: Optional[List[str]] = None) -> str:
        if self.status != WalletStatus.UNLOCKED:
            raise RuntimeError("Il wallet deve essere sbloccato per aggiungere credenziali.")
        
        storage_id = str(uuid.uuid4())
        
        if self.credential_validator:
            validation_report = self.credential_validator.validate_credential(credential, ValidationLevel.BASIC)
            if not validation_report.is_valid():
                print(f"⚠️  Credenziale aggiunta ma non valida: {validation_report.errors}")

        wallet_credential = WalletCredential(
            credential=credential,
            storage_id=storage_id,
            added_date=datetime.datetime.utcnow(),
            tags=tags or [],
            last_accessed=datetime.datetime.utcnow()
        )
        self.credentials[storage_id] = wallet_credential
        self._save_wallet()
        
        if self.config.auto_backup:
            self._create_backup()
            
        return storage_id

    def get_credential(self, storage_id: str) -> Optional[WalletCredential]:
        if self.status != WalletStatus.UNLOCKED:
            raise RuntimeError("Wallet bloccato.")
        
        credential = self.credentials.get(storage_id)
        if credential:
            credential.last_accessed = datetime.datetime.utcnow()
        return credential

    def list_credentials(self, filter_tags: Optional[List[str]] = None, filter_status: Optional[CredentialStatus] = None) -> List[Dict[str, Any]]:
        if self.status != WalletStatus.UNLOCKED:
            raise RuntimeError("Wallet bloccato.")
        
        results = []
        for cred_id, wallet_cred in self.credentials.items():
            # ... Logica di filtro ...
            summary = wallet_cred.credential.get_summary()
            summary['storage_id'] = cred_id
            results.append(summary)
        return results

    def remove_credential(self, storage_id: str) -> bool:
        if self.status != WalletStatus.UNLOCKED:
            raise RuntimeError("Wallet bloccato.")
        if storage_id in self.credentials:
            del self.credentials[storage_id]
            self._save_wallet()
            return True
        return False

    def _create_backup(self) -> bool:
        if self.status != WalletStatus.UNLOCKED: return False
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = self.backup_dir / f"wallet_backup_{timestamp}.enc"
            
            with open(self.wallet_file, 'rb') as src, open(backup_file, 'wb') as dst:
                dst.write(src.read())
            
            self._cleanup_old_backups()
            print(f"💾 Backup cifrato creato: {backup_file.name}")
            return True
        except Exception as e:
            print(f"❌ Errore durante il backup: {e}")
            return False
            
    def _cleanup_old_backups(self):
        try:
            backup_files = sorted(
                self.backup_dir.glob("wallet_backup_*.enc"),
                key=os.path.getmtime,
                reverse=True
            )
            if len(backup_files) > self.config.max_backup_files:
                for f in backup_files[self.config.max_backup_files:]:
                    f.unlink()
        except Exception as e:
            print(f"⚠️  Errore pulizia backup: {e}")

    def get_wallet_statistics(self) -> WalletStats:
        if self.status != WalletStatus.UNLOCKED:
            raise RuntimeError("Wallet bloccato.")
        # ... logica da implementare ...
        return WalletStats()

# =============================================================================
# 3. DEMO E TESTING 
# =============================================================================

def demo_student_wallet():
    print("👤" * 40)
    print("DEMO STUDENT WALLET (con Fernet - Corretto)")
    print("Wallet Digitale Studenti")
    print("👤" * 40)
    
    config = WalletConfiguration(
        wallet_name="Mario Rossi Demo Wallet",
        storage_path="./demo_wallet/mario_rossi",
    )
    wallet = AcademicStudentWallet(config)
    password = "PasswordValida123!"

    # Pulisce vecchi file di test
    if wallet.wallet_dir.exists():
        import shutil
        shutil.rmtree(wallet.wallet_dir)
    wallet.wallet_dir.mkdir(parents=True, exist_ok=True)
    wallet.backup_dir.mkdir(exist_ok=True)

    # 1. Creazione
    print("\n1️⃣ CREAZIONE WALLET CIFRATO")
    if not wallet.create_wallet(password):
        print("ERRORE CRITICO: Impossibile creare il wallet demo.")
        return

    # 2. Aggiunta credenziale
    print("\n2️⃣ AGGIUNTA CREDENZIALE")
    from credentials.models import CredentialFactory
    cred = CredentialFactory.create_sample_credential()
    wallet.add_credential(cred, tags=["demo", "fernet"])
    print(f"Credenziali nel wallet: {len(wallet.credentials)}")

    # 3. Blocco e sblocco
    print("\n3️⃣ BLOCCO E SBLOCCO")
    wallet.lock_wallet()
    if wallet.unlock_wallet(password):
        print("Sblocco riuscito, le credenziali sono ancora presenti.")
        print(f"Credenziali nel wallet: {len(wallet.credentials)}")
    else:
        print("ERRORE CRITICO: Impossibile sbloccare il wallet.")
        return

    print("\n✅ DEMO CORRETTA COMPLETATA!")

if __name__ == "__main__":
    demo_student_wallet()