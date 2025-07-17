# =============================================================================
# FASE 4: WALLET E DIVULGAZIONE SELETTIVA - STUDENT WALLET (Versione Corretta con Fernet)
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
    from crypto.foundations import RSAKeyManager
    from credentials.models import AcademicCredential, CredentialStatus
    from credentials.validator import AcademicCredentialValidator, ValidationLevel
except ImportError as e:
    print(f"⚠️ Errore import moduli interni: {e}")
    raise


# =============================================================================
# 1. ENUMS E STRUTTURE DATI WALLET
# =============================================================================

class WalletStatus(Enum):
    """Stati possibili del wallet."""
    LOCKED = "locked"
    UNLOCKED = "unlocked"
    CORRUPTED = "corrupted"


class CredentialStorage(Enum):
    """Modalità di archiviazione delle credenziali."""
    ENCRYPTED_LOCAL = "encrypted_local"


@dataclass
class WalletCredential:
    """Credenziale archiviata nel wallet."""
    credential: AcademicCredential
    storage_id: str
    added_date: datetime.datetime
    tags: List[str] = field(default_factory=list)
    notes: Optional[str] = None
    favorite: bool = False
    last_accessed: Optional[datetime.datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Converte l'oggetto in un dizionario per la serializzazione."""
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
        """Crea un'istanza da un dizionario."""
        return cls(
            credential=AcademicCredential.from_dict(data['credential']),
            storage_id=data['storage_id'],
            added_date=datetime.datetime.fromisoformat(data['added_date']),
            tags=data.get('tags', []),
            notes=data.get('notes'),
            favorite=data.get('favorite', False),
            last_accessed=datetime.datetime.fromisoformat(data['last_accessed']) if data.get('last_accessed') else None
        )

@dataclass
class WalletConfiguration:
    """Configurazione del wallet."""
    wallet_name: str
    storage_path: str
    storage_mode: CredentialStorage = CredentialStorage.ENCRYPTED_LOCAL
    auto_backup: bool = True
    backup_interval_hours: int = 24
    max_backup_files: int = 10
    password_min_length: int = 12 # Aumentato per maggiore sicurezza
    session_timeout_minutes: int = 15
    auto_validate_credentials: bool = True

@dataclass
class WalletStats:
    """Statistiche del wallet."""
    total_credentials: int = 0
    active_credentials: int = 0
    expired_credentials: int = 0
    revoked_credentials: int = 0
    universities_count: int = 0
    total_ects_credits: int = 0
    last_activity: Optional[datetime.datetime] = None


# =============================================================================
# 2. ACADEMIC STUDENT WALLET (con implementazione Fernet)
# =============================================================================

class AcademicStudentWallet:
    """Wallet digitale per studenti che usa Fernet per la cifratura dei dati a riposo."""

    def __init__(self, config: WalletConfiguration):
        self.config = config
        self.status = WalletStatus.LOCKED
        self.key_manager = RSAKeyManager(2048)

        # Inizializza il validatore di credenziali se richiesto
        self.credential_validator = AcademicCredentialValidator() if config.auto_validate_credentials else None
        
        # Stato volatile del wallet (in memoria)
        self.credentials: Dict[str, WalletCredential] = {}
        self.wallet_private_key: Optional[rsa.RSAPrivateKey] = None
        self.wallet_public_key: Optional[rsa.RSAPublicKey] = None
        self.last_activity: Optional[datetime.datetime] = None
        self.fernet: Optional[Fernet] = None # Oggetto Fernet per la sessione
        self.wallet_salt: Optional[bytes] = None

        # Percorsi dei file
        self.wallet_dir = Path(config.storage_path)
        self.wallet_file = self.wallet_dir / "wallet.enc" # File dati principale cifrato
        self.salt_file = self.wallet_dir / "wallet.salt" # Salt per la derivazione della chiave
        self.keys_file = self.wallet_dir / "keys.enc"    # Chiavi RSA del wallet cifrate
        self.backup_dir = self.wallet_dir / "backups"

        # Crea le directory necessarie
        self.wallet_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(exist_ok=True)
        
        print(f"👤 Student Wallet inizializzato: {config.wallet_name}")

    def _derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Deriva una chiave di cifratura sicura dalla password usando PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000, # Numero di iterazioni raccomandato
            backend=default_backend()
        )
        # La chiave generata da PBKDF2 viene codificata in Base64 per essere usata da Fernet
        return base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))

    def _validate_password(self, password: str) -> bool:
        """Valida la robustezza della password."""
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

    def _cleanup_session(self):
        """Pulisce tutti i dati sensibili dalla memoria al blocco del wallet."""
        self.wallet_private_key = None
        self.wallet_public_key = None
        self.fernet = None
        self.wallet_salt = None
        self.credentials = {}
        self.status = WalletStatus.LOCKED

    def create_wallet(self, password: str) -> bool:
        """Crea un nuovo wallet, generando chiavi e salt."""
        if self.wallet_file.exists():
            print("❌ Wallet già esistente. Impossibile creare.")
            return False
        
        if not self._validate_password(password):
            return False
        
        print(f"🔨 Creando nuovo wallet cifrato: {self.config.wallet_name}")
        
        try:
            # Genera chiavi RSA e il salt per la password
            self.wallet_private_key, self.wallet_public_key = self.key_manager.generate_key_pair()
            self.wallet_salt = os.urandom(16)
            self.salt_file.write_bytes(self.wallet_salt)
            
            # Crea l'oggetto Fernet per la sessione
            fernet_key = self._derive_key_from_password(password, self.wallet_salt)
            self.fernet = Fernet(fernet_key)
            
            # Salva le chiavi RSA cifrate
            self._save_encrypted_keys()
            
            # Salva il file del wallet (inizialmente vuoto)
            self.credentials = {}
            self._save_wallet_data()
            
            self.status = WalletStatus.UNLOCKED
            self.last_activity = datetime.datetime.utcnow()
            
            print("✅ Wallet creato e cifrato con successo!")
            return True
            
        except Exception as e:
            print(f"❌ Errore critico durante la creazione del wallet: {e}")
            # Pulizia in caso di fallimento
            if self.wallet_file.exists(): self.wallet_file.unlink()
            if self.salt_file.exists(): self.salt_file.unlink()
            if self.keys_file.exists(): self.keys_file.unlink()
            return False

    def unlock_wallet(self, password: str) -> bool:
        """Sblocca il wallet usando la password per derivare la chiave di decifratura."""
        if not self.wallet_file.exists() or not self.salt_file.exists():
            print("❌ File del wallet o del salt non trovati.")
            return False
        
        print(f"🔓 Tentativo di sblocco wallet: {self.config.wallet_name}")
        
        try:
            # Carica il salt e deriva la chiave
            self.wallet_salt = self.salt_file.read_bytes()
            fernet_key = self._derive_key_from_password(password, self.wallet_salt)
            self.fernet = Fernet(fernet_key)

            # Tenta di decifrare e caricare il wallet. Se la password è errata, Fernet lancerà InvalidToken.
            if not self._load_wallet_data():
                raise RuntimeError("Caricamento del wallet fallito.")

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
        """Blocca il wallet, salvando prima lo stato corrente e pulendo la sessione."""
        if self.status == WalletStatus.LOCKED:
            return True
        
        print("🔒 Blocco del wallet...")
        try:
            if self.status == WalletStatus.UNLOCKED:
                self._save_wallet_data()
            self._cleanup_session()
            print("✅ Wallet bloccato in modo sicuro.")
            return True
        except Exception as e:
            print(f"❌ Errore durante il blocco del wallet: {e}")
            return False

    def _save_wallet_data(self):
        """Cifra e salva lo stato corrente delle credenziali."""
        if self.status != WalletStatus.UNLOCKED or not self.fernet:
            raise RuntimeError("Impossibile salvare: il wallet è bloccato.")
        
        wallet_content = {
            'version': '1.2-fernet',
            'credentials': [cred.to_dict() for cred in self.credentials.values()]
        }
        json_data = json.dumps(wallet_content, default=str).encode('utf-8')
        encrypted_data = self.fernet.encrypt(json_data)
        self.wallet_file.write_bytes(encrypted_data)

    def _load_wallet_data(self) -> bool:
        """Decifra e carica le credenziali dal file del wallet."""
        encrypted_data = self.wallet_file.read_bytes()
        
        # Gestisce il caso di un wallet nuovo e vuoto
        if not encrypted_data:
            self.credentials = {}
            return True

        decrypted_data = self.fernet.decrypt(encrypted_data)
        wallet_content = json.loads(decrypted_data.decode('utf-8'))
        
        self.credentials = {
            cred_data['storage_id']: WalletCredential.from_dict(cred_data)
            for cred_data in wallet_content.get('credentials', [])
        }
        return True

    def _save_encrypted_keys(self):
        """Cifra e salva la coppia di chiavi RSA del wallet."""
        keys_json = json.dumps({
            'private_key': self.key_manager.serialize_private_key(self.wallet_private_key).decode('utf-8'),
            'public_key': self.key_manager.serialize_public_key(self.wallet_public_key).decode('utf-8')
        }).encode('utf-8')
        
        encrypted_keys = self.fernet.encrypt(keys_json)
        self.keys_file.write_bytes(encrypted_keys)
        os.chmod(self.keys_file, 0o600)

    def _load_encrypted_keys(self) -> bool:
        """Decifra e carica la coppia di chiavi RSA del wallet."""
        encrypted_keys = self.keys_file.read_bytes()
        decrypted_keys_json = self.fernet.decrypt(encrypted_keys)
        keys_data = json.loads(decrypted_keys_json.decode('utf-8'))
        
        self.wallet_private_key = self.key_manager.deserialize_private_key(keys_data['private_key'].encode('utf-8'))
        self.wallet_public_key = self.key_manager.deserialize_public_key(keys_data['public_key'].encode('utf-8'))
        return True

    def add_credential(self, credential: AcademicCredential, tags: Optional[List[str]] = None) -> str:
        """Aggiunge una credenziale al wallet e salva lo stato cifrato."""
        if self.status != WalletStatus.UNLOCKED:
            raise RuntimeError("Il wallet deve essere sbloccato per aggiungere credenziali.")
        
        storage_id = str(uuid.uuid4())
        
        if self.credential_validator:
            validation_report = self.credential_validator.validate_credential(credential, ValidationLevel.BASIC)
            if not validation_report.is_valid():
                print(f"⚠️ Credenziale aggiunta ma non valida: {validation_report.errors}")

        self.credentials[storage_id] = WalletCredential(
            credential=credential, storage_id=storage_id,
            added_date=datetime.datetime.utcnow(), tags=tags or [],
            last_accessed=datetime.datetime.utcnow()
        )
        self._save_wallet_data()
        
        if self.config.auto_backup:
            self._create_backup()
            
        return storage_id

    def get_credential(self, storage_id: str) -> Optional[WalletCredential]:
        """Recupera una credenziale dal wallet."""
        if self.status != WalletStatus.UNLOCKED:
            raise RuntimeError("Wallet bloccato.")
        
        credential = self.credentials.get(storage_id)
        if credential:
            credential.last_accessed = datetime.datetime.utcnow()
        return credential

    def list_credentials(self) -> List[Dict[str, Any]]:
        """Elenca un riassunto di tutte le credenziali."""
        if self.status != WalletStatus.UNLOCKED:
            raise RuntimeError("Wallet bloccato.")
        
        return [cred.credential.get_summary() | {'storage_id': sid} for sid, cred in self.credentials.items()]

    def remove_credential(self, storage_id: str) -> bool:
        """Rimuove una credenziale e salva lo stato."""
        if self.status != WalletStatus.UNLOCKED:
            raise RuntimeError("Wallet bloccato.")
        if storage_id in self.credentials:
            del self.credentials[storage_id]
            self._save_wallet_data()
            return True
        return False

    def _create_backup(self) -> bool:
        """Crea una copia di sicurezza del file del wallet cifrato."""
        if self.status != WalletStatus.UNLOCKED: return False
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = self.backup_dir / f"wallet_backup_{timestamp}.enc"
            
            # Copia semplicemente il file cifrato, che è già un'unità sicura
            with open(self.wallet_file, 'rb') as src, open(backup_file, 'wb') as dst:
                dst.write(src.read())
            
            self._cleanup_old_backups()
            print(f"💾 Backup cifrato creato: {backup_file.name}")
            return True
        except Exception as e:
            print(f"❌ Errore durante il backup: {e}")
            return False
            
    def _cleanup_old_backups(self):
        """Mantiene solo il numero massimo di backup consentito."""
        try:
            backup_files = sorted(self.backup_dir.glob("wallet_backup_*.enc"), key=os.path.getmtime, reverse=True)
            if len(backup_files) > self.config.max_backup_files:
                for f in backup_files[self.config.max_backup_files:]:
                    f.unlink()
        except Exception as e:
            print(f"⚠️ Errore pulizia backup: {e}")

# =============================================================================
# 3. DEMO E TESTING 
# =============================================================================

def demo_student_wallet_fernet():
    """Demo del wallet con la nuova implementazione basata su Fernet."""
    print("👤" * 40)
    print("DEMO STUDENT WALLET (con Fernet)")
    print("👤" * 40)
    
    demo_path = Path("./demo_wallet_fernet")
    if demo_path.exists():
        import shutil
        shutil.rmtree(demo_path)

    config = WalletConfiguration(
        wallet_name="Mario Rossi Fernet Wallet",
        storage_path=str(demo_path),
    )
    wallet = AcademicStudentWallet(config)
    password = "PasswordSuperSicura123!"

    # 1. Creazione
    print("\n1️⃣ CREAZIONE WALLET CIFRATO CON FERNET")
    if not wallet.create_wallet(password):
        print("ERRORE CRITICO: Impossibile creare il wallet.")
        return

    # 2. Aggiunta credenziale
    print("\n2️⃣ AGGIUNTA DI UNA CREDENZIALE")
    from credentials.models import CredentialFactory
    cred = CredentialFactory.create_sample_credential()
    storage_id = wallet.add_credential(cred, tags=["demo", "fernet"])
    print(f"Credenziale aggiunta con ID: {storage_id}")
    print(f"Numero credenziali nel wallet: {len(wallet.credentials)}")

    # 3. Blocco e sblocco
    print("\n3️⃣ TEST DI BLOCCO E SBLOCCO")
    wallet.lock_wallet()
    if wallet.status == WalletStatus.LOCKED:
        print("Wallet bloccato correttamente.")
    
    if wallet.unlock_wallet(password):
        print("Sblocco riuscito, le credenziali sono state caricate.")
        print(f"Numero credenziali nel wallet: {len(wallet.credentials)}")
    else:
        print("ERRORE CRITICO: Impossibile sbloccare il wallet.")
        return
        
    # 4. Tentativo di sblocco con password errata
    print("\n4️⃣ TEST CON PASSWORD ERRATA")
    wallet.lock_wallet()
    if not wallet.unlock_wallet("password_sbagliata"):
        print("Il test con password errata è riuscito: lo sblocco è fallito come previsto.")

    print("\n✅ DEMO CON FERNET COMPLETATA CON SUCCESSO!")

if __name__ == "__main__":
    demo_student_wallet_fernet()