# =============================================================================
# FASE 4: WALLET E DIVULGAZIONE SELETTIVA - STUDENT WALLET (MODIFICATO)
# File: wallet/student_wallet.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

import os
import json
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import uuid
import base64
import hashlib

# Import di Fernet per la crittografia simmetrica autenticata
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Import moduli interni
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from crypto.foundations import RSAKeyManager, DigitalSignature
    from credentials.models import AcademicCredential
    from credentials.validator import AcademicCredentialValidator, ValidationLevel
    from pki.certificate_authority import CertificateAuthority
except ImportError as e:
    print(f"⚠️ Errore import moduli interni: {e}")
    raise

class WalletStatus(Enum):
    LOCKED = "locked"
    UNLOCKED = "unlocked"
    CORRUPTED = "corrupted"

class CredentialStorage(Enum):
    ENCRYPTED_LOCAL = "encrypted_local"

@dataclass
class WalletCredential:
    credential: AcademicCredential
    storage_id: str
    added_date: datetime.datetime
    tags: List[str] = field(default_factory=list)
    notes: Optional[str] = None
    favorite: bool = False
    last_accessed: Optional[datetime.datetime] = None
    
    def to_dict(self):
        return {
            'credential': self.credential.to_dict(), 'storage_id': self.storage_id,
            'added_date': self.added_date.isoformat(), 'tags': self.tags, 'notes': self.notes,
            'favorite': self.favorite, 'last_accessed': self.last_accessed.isoformat() if self.last_accessed else None
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            credential=AcademicCredential.from_dict(data['credential']), storage_id=data['storage_id'],
            added_date=datetime.datetime.fromisoformat(data['added_date']), tags=data.get('tags', []),
            notes=data.get('notes'), favorite=data.get('favorite', False),
            last_accessed=datetime.datetime.fromisoformat(data['last_accessed']) if data.get('last_accessed') else None
        )

@dataclass
class WalletConfiguration:
    wallet_name: str
    storage_path: str
    storage_mode: CredentialStorage = CredentialStorage.ENCRYPTED_LOCAL
    auto_backup: bool = True
    backup_interval_hours: int = 24
    max_backup_files: int = 10
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
    last_activity: Optional[datetime.datetime] = None

class AcademicStudentWallet:
    def __init__(self, config: WalletConfiguration):
        self.config = config
        self.status = WalletStatus.LOCKED
        self.key_manager = RSAKeyManager(2048)
        self.credential_validator = AcademicCredentialValidator() if config.auto_validate_credentials else None
        
        self.credentials: Dict[str, WalletCredential] = {}
        self.wallet_private_key: Optional[rsa.RSAPrivateKey] = None
        self.wallet_public_key: Optional[rsa.RSAPublicKey] = None
        self.student_certificate: Optional[str] = None
        self.last_activity: Optional[datetime.datetime] = None
        self.fernet: Optional[Fernet] = None
        self.wallet_salt: Optional[bytes] = None

        self.wallet_dir = Path(config.storage_path)
        self.wallet_file = self.wallet_dir / "wallet.enc"
        self.salt_file = self.wallet_dir / "wallet.salt"
        self.keys_file = self.wallet_dir / "keys.enc"
        self.backup_dir = self.wallet_dir / "backups"

        self.wallet_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(exist_ok=True)
        
        print(f"👤 Student Wallet inizializzato: {config.wallet_name}")

    def _derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(), length=32, salt=salt,
            iterations=480000, backend=default_backend()
        )
        return base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))

    def _validate_password(self, password: str) -> bool:
        if len(password) < self.config.password_min_length:
            return False
        return True

    def _cleanup_session(self):
        self.wallet_private_key = None
        self.wallet_public_key = None
        self.student_certificate = None
        self.fernet = None
        self.wallet_salt = None
        self.credentials = {}
        self.status = WalletStatus.LOCKED
        
    def create_wallet(self, password: str, student_common_name: str, student_id: str) -> bool:
        """
        Crea un nuovo wallet caricando la chiave e il certificato pre-generati dalla CA.
        """
        if self.wallet_file.exists():
            print("❌ Wallet già esistente.")
            return False
        
        if not self._validate_password(password):
            return False
        
        print(f"🔨 Creando nuovo wallet per {student_common_name} (caricando identità pre-generata)")
        
        try:
            # --- MODIFICA INIZIO ---
            # 1. Carica la chiave privata e il certificato dello studente generati dalla CA
            student_key_name = f"{student_common_name.replace(' ', '_').lower()}_{student_id}"
            
            # Percorsi dei file pre-generati
            key_path = Path(f"./keys/{student_key_name}_private.pem")
            cert_path = Path(f"./certificates/students/{student_key_name}.pem")
            student_key_password = "StudentPassword123!" # Password hardcoded dalla CA
            
            if not key_path.exists() or not cert_path.exists():
                print(f"❌ ERRORE: Chiave ({key_path}) o certificato ({cert_path}) non trovati.")
                print("   Assicurati di aver eseguito prima 'python src/pki/certificate_authority.py'")
                return False

            print(f"🔑 Caricamento chiave privata da: {key_path}")
            private_key_pem = key_path.read_bytes()
            self.wallet_private_key = self.key_manager.deserialize_private_key(
                private_key_pem,
                password=student_key_password.encode('utf-8')
            )
            self.wallet_public_key = self.wallet_private_key.public_key()
            
            print(f"📄 Caricamento certificato da: {cert_path}")
            self.student_certificate = cert_path.read_text()
            
            # Genera il salt per la password del wallet
            self.wallet_salt = os.urandom(16)
            self.salt_file.write_bytes(self.wallet_salt)
            # --- MODIFICA FINE ---

            # 2. Crea l'oggetto Fernet per la sessione
            fernet_key = self._derive_key_from_password(password, self.wallet_salt)
            self.fernet = Fernet(fernet_key)

            self.status = WalletStatus.UNLOCKED
            self.last_activity = datetime.datetime.utcnow()

            # 3. Salva le chiavi RSA e il certificato in modo cifrato nel wallet
            self._save_encrypted_keys()
            
            # 4. Salva il file del wallet vuoto (ma firmato)
            self.credentials = {}
            self._save_wallet_data()
            
            print("✅ Wallet creato con identità pre-generata e firmato con successo!")
            return True
            
        except Exception as e:
            print(f"❌ Errore critico durante la creazione del wallet: {e}")
            import traceback
            traceback.print_exc()
            if self.wallet_file.exists(): self.wallet_file.unlink()
            if self.salt_file.exists(): self.salt_file.unlink()
            if self.keys_file.exists(): self.keys_file.unlink()
            self._cleanup_session()
            return False

    def unlock_wallet(self, password: str) -> bool:
        if not self.wallet_file.exists() or not self.salt_file.exists():
            return False
        
        try:
            self.wallet_salt = self.salt_file.read_bytes()
            fernet_key = self._derive_key_from_password(password, self.wallet_salt)
            self.fernet = Fernet(fernet_key)

            if not self._load_wallet_data():
                raise RuntimeError("Caricamento wallet fallito.")

            if not self._load_encrypted_keys():
                raise RuntimeError("Caricamento chiavi fallito.")

            self.status = WalletStatus.UNLOCKED
            self.last_activity = datetime.datetime.utcnow()
            
            print(f"✅ Wallet sbloccato! Trovate {len(self.credentials)} credenziali.")
            return True

        except InvalidToken:
            print("❌ Password errata o wallet corrotto.")
            self._cleanup_session()
            return False
        except Exception as e:
            print(f"❌ Errore durante lo sblocco: {e}")
            self._cleanup_session()
            return False

    def lock_wallet(self) -> bool:
        if self.status == WalletStatus.LOCKED: return True
        try:
            if self.status == WalletStatus.UNLOCKED:
                self._save_wallet_data()
            self._cleanup_session()
            return True
        except Exception:
            return False

    def _save_wallet_data(self):
        """Cifra, firma e salva lo stato corrente delle credenziali."""
        if self.status != WalletStatus.UNLOCKED or not self.fernet:
            raise RuntimeError("Wallet bloccato.")
        
        wallet_content = {
            'version': '1.3-signed',
            'credentials': [cred.to_dict() for cred in self.credentials.values()]
        }
        
        signer = DigitalSignature("PSS")
        signed_content = signer.sign_document(self.wallet_private_key, wallet_content)

        json_data = json.dumps(signed_content, default=str).encode('utf-8')
        encrypted_data = self.fernet.encrypt(json_data)
        self.wallet_file.write_bytes(encrypted_data)

    def _load_wallet_data(self) -> bool:
        """Decifra e carica le credenziali, verificando la firma."""
        encrypted_data = self.wallet_file.read_bytes()
        if not encrypted_data:
            self.credentials = {}
            return True

        decrypted_data = self.fernet.decrypt(encrypted_data)
        signed_content = json.loads(decrypted_data.decode('utf-8'))
        
        self._load_encrypted_keys() 
        verifier = DigitalSignature("PSS")
        if not verifier.verify_document_signature(self.wallet_public_key, signed_content):
            print("❌ ATTENZIONE: Firma del wallet non valida! File potenzialmente corrotto.")
            self.status = WalletStatus.CORRUPTED
            return False

        wallet_content = signed_content
        wallet_content.pop('firma', None)

        self.credentials = {
            cred_data['storage_id']: WalletCredential.from_dict(cred_data)
            for cred_data in wallet_content.get('credentials', [])
        }
        return True

    def _save_encrypted_keys(self):
        """Cifra e salva la coppia di chiavi RSA e il certificato dello studente."""
        keys_json = json.dumps({
            'private_key': self.key_manager.serialize_private_key(self.wallet_private_key).decode('utf-8'),
            'public_key': self.key_manager.serialize_public_key(self.wallet_public_key).decode('utf-8'),
            'student_certificate': self.student_certificate
        }).encode('utf-8')
        
        encrypted_keys = self.fernet.encrypt(keys_json)
        self.keys_file.write_bytes(encrypted_keys)
        os.chmod(self.keys_file, 0o600)

    def _load_encrypted_keys(self) -> bool:
        """Decifra e carica la coppia di chiavi RSA e il certificato dello studente."""
        encrypted_keys = self.keys_file.read_bytes()
        decrypted_keys_json = self.fernet.decrypt(encrypted_keys)
        keys_data = json.loads(decrypted_keys_json.decode('utf-8'))
        
        self.wallet_private_key = self.key_manager.deserialize_private_key(keys_data['private_key'].encode('utf-8'))
        self.wallet_public_key = self.key_manager.deserialize_public_key(keys_data['public_key'].encode('utf-8'))
        self.student_certificate = keys_data.get('student_certificate')
        return True
    
    def add_credential(self, credential, tags=None):
        if self.status != WalletStatus.UNLOCKED: raise RuntimeError("Wallet bloccato")
        storage_id = str(uuid.uuid4())
        if self.credential_validator:
            report = self.credential_validator.validate_credential(credential, ValidationLevel.BASIC)
            if not report.is_valid(): print(f"⚠️  Credenziale non valida: {report.errors}")
        self.credentials[storage_id] = WalletCredential(
            credential=credential, storage_id=storage_id, added_date=datetime.datetime.utcnow(),
            tags=tags or [], last_accessed=datetime.datetime.utcnow()
        )
        self._save_wallet_data()
        if self.config.auto_backup: self._create_backup()
        return storage_id
    
    def get_credential(self, storage_id):
        if self.status != WalletStatus.UNLOCKED: raise RuntimeError("Wallet bloccato")
        cred = self.credentials.get(storage_id)
        if cred: cred.last_accessed = datetime.datetime.utcnow()
        return cred
        
    def list_credentials(self):
        if self.status != WalletStatus.UNLOCKED: raise RuntimeError("Wallet bloccato")
        return [c.credential.get_summary() | {'storage_id': sid} for sid, c in self.credentials.items()]
        
    def remove_credential(self, storage_id):
        if self.status != WalletStatus.UNLOCKED: raise RuntimeError("Wallet bloccato")
        if storage_id in self.credentials:
            del self.credentials[storage_id]
            self._save_wallet_data()
            return True
        return False
        
    def _create_backup(self):
        if self.status != WalletStatus.UNLOCKED: return False
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = self.backup_dir / f"wallet_backup_{timestamp}.enc"
            with open(self.wallet_file, 'rb') as src, open(backup_file, 'wb') as dst:
                dst.write(src.read())
            self._cleanup_old_backups()
            return True
        except Exception:
            return False
            
    def _cleanup_old_backups(self):
        try:
            backups = sorted(self.backup_dir.glob("*.enc"), key=os.path.getmtime, reverse=True)
            if len(backups) > self.config.max_backup_files:
                for f in backups[self.config.max_backup_files:]:
                    f.unlink()
        except Exception:
            pass