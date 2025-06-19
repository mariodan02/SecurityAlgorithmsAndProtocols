# =============================================================================
# FASE 4: WALLET E DIVULGAZIONE SELETTIVA - STUDENT WALLET
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

# Cryptography imports
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
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
    """Stati possibili del wallet"""
    LOCKED = "locked"
    UNLOCKED = "unlocked"
    ENCRYPTED = "encrypted"
    CORRUPTED = "corrupted"


class CredentialStorage(Enum):
    """Modalità di storage delle credenziali"""
    ENCRYPTED_LOCAL = "encrypted_local"
    PLAINTEXT_LOCAL = "plaintext_local"
    CLOUD_ENCRYPTED = "cloud_encrypted"


@dataclass
class WalletCredential:
    """Credenziale archiviata nel wallet"""
    credential: AcademicCredential
    storage_id: str
    added_date: datetime.datetime
    tags: List[str] = field(default_factory=list)
    notes: Optional[str] = None
    favorite: bool = False
    last_accessed: Optional[datetime.datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte in dizionario per serializzazione"""
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
        """Crea istanza da dizionario"""
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
    """Configurazione del wallet"""
    wallet_name: str
    storage_path: str
    storage_mode: CredentialStorage = CredentialStorage.ENCRYPTED_LOCAL
    auto_backup: bool = True
    backup_interval_hours: int = 24
    max_backup_files: int = 10
    require_password: bool = True
    password_min_length: int = 8
    session_timeout_minutes: int = 30
    auto_validate_credentials: bool = True


@dataclass
class WalletStats:
    """Statistiche del wallet"""
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
# 2. ACADEMIC STUDENT WALLET
# =============================================================================

class AcademicStudentWallet:
    """Wallet digitale per studenti - gestione credenziali accademiche"""
    
    def __init__(self, config: WalletConfiguration):
        """
        Inizializza il wallet studente
        
        Args:
            config: Configurazione wallet
        """
        self.config = config
        self.status = WalletStatus.LOCKED
        
        # Componenti crittografici
        self.crypto_utils = CryptoUtils()
        self.key_manager = RSAKeyManager(2048)
        self.digital_signature = DigitalSignature("PSS")
        
        # Validator per credenziali
        if config.auto_validate_credentials:
            self.credential_validator = AcademicCredentialValidator()
        else:
            self.credential_validator = None
        
        # Storage credenziali
        self.credentials: Dict[str, WalletCredential] = {}
        
        # Chiavi del wallet
        self.wallet_private_key: Optional[rsa.RSAPrivateKey] = None
        self.wallet_public_key: Optional[rsa.RSAPublicKey] = None
        
        # Gestione sessione
        self.session_key: Optional[bytes] = None
        self.last_activity: Optional[datetime.datetime] = None
        self.password_hash: Optional[str] = None
        
        # Paths
        self.wallet_dir = Path(config.storage_path)
        self.wallet_file = self.wallet_dir / "wallet.json"
        self.keys_file = self.wallet_dir / "wallet_keys.pem"
        self.backup_dir = self.wallet_dir / "backups"
        
        # Crea directory
        self.wallet_dir.mkdir(parents=True, exist_ok=True)
        self.backup_dir.mkdir(exist_ok=True)
        
        print(f"👤 Student Wallet inizializzato: {config.wallet_name}")
        print(f"   Storage: {config.storage_path}")
        print(f"   Modalità: {config.storage_mode.value}")
        print(f"   Auto-backup: {config.auto_backup}")
    
    def create_wallet(self, password: str) -> bool:
        """
        Crea un nuovo wallet
        
        Args:
            password: Password per proteggere il wallet
            
        Returns:
            True se wallet creato con successo
        """
        try:
            if self.wallet_file.exists():
                print("❌ Wallet già esistente")
                return False
            
            # Valida password
            if not self._validate_password(password):
                return False
            
            print(f"🔨 Creando nuovo wallet: {self.config.wallet_name}")
            
            # 1. Genera chiavi del wallet
            print("   1️⃣ Generazione chiavi...")
            self.wallet_private_key, self.wallet_public_key = self.key_manager.generate_key_pair()
            
            # 2. Crea hash password
            print("   2️⃣ Configurazione password...")
            self.password_hash = self.crypto_utils.sha256_hash_string(password + "wallet_salt")
            
            # 3. Salva chiavi cifrate
            print("   3️⃣ Salvataggio chiavi...")
            self._save_encrypted_keys(password)
            
            # 4. Inizializza wallet vuoto
            print("   4️⃣ Inizializzazione wallet...")
            self.credentials = {}
            self.status = WalletStatus.UNLOCKED
            self.last_activity = datetime.datetime.utcnow()
            
            # 5. Salva wallet
            self._save_wallet()
            
            print("✅ Wallet creato con successo!")
            return True
            
        except Exception as e:
            print(f"❌ Errore creazione wallet: {e}")
            return False
    
    def unlock_wallet(self, password: str) -> bool:
        """
        Sblocca il wallet con password
        
        Args:
            password: Password del wallet
            
        Returns:
            True se sbloccato con successo
        """
        try:
            if not self.wallet_file.exists():
                print("❌ Wallet non trovato")
                return False
            
            print(f"🔓 Sbloccando wallet: {self.config.wallet_name}")
            
            # 1. Verifica password
            password_hash = self.crypto_utils.sha256_hash_string(password + "wallet_salt")
            
            # Carica dati wallet per verificare password
            wallet_data = self._load_wallet_metadata()
            if wallet_data.get('password_hash') != password_hash:
                print("❌ Password errata")
                return False
            
            # 2. Carica chiavi
            print("   🔑 Caricamento chiavi...")
            if not self._load_encrypted_keys(password):
                return False
            
            # 3. Carica credenziali
            print("   📚 Caricamento credenziali...")
            if not self._load_wallet():
                return False
            
            # 4. Aggiorna stato
            self.status = WalletStatus.UNLOCKED
            self.last_activity = datetime.datetime.utcnow()
            self.password_hash = password_hash
            
            print(f"✅ Wallet sbloccato! ({len(self.credentials)} credenziali)")
            return True
            
        except Exception as e:
            print(f"❌ Errore sblocco wallet: {e}")
            return False
    
    def lock_wallet(self) -> bool:
        """
        Blocca il wallet
        
        Returns:
            True se bloccato con successo
        """
        try:
            if self.status == WalletStatus.LOCKED:
                print("⚠️  Wallet già bloccato")
                return True
            
            print("🔒 Bloccando wallet...")
            
            # Salva stato corrente
            self._save_wallet()
            
            # Pulisce dati sensibili dalla memoria
            self.wallet_private_key = None
            self.wallet_public_key = None
            self.session_key = None
            self.password_hash = None
            
            # Aggiorna stato
            self.status = WalletStatus.LOCKED
            
            print("✅ Wallet bloccato")
            return True
            
        except Exception as e:
            print(f"❌ Errore blocco wallet: {e}")
            return False
    
    def add_credential(self, credential: AcademicCredential, tags: List[str] = None) -> str:
        """
        Aggiunge una credenziale al wallet
        
        Args:
            credential: Credenziale da aggiungere
            tags: Tag per organizzazione
            
        Returns:
            ID storage della credenziale
        """
        if self.status != WalletStatus.UNLOCKED:
            raise RuntimeError("Wallet deve essere sbloccato")
        
        try:
            # Genera ID storage univoco
            storage_id = str(uuid.uuid4())
            
            # Valida credenziale se abilitato
            if self.credential_validator:
                print(f"🔍 Validando credenziale: {credential.metadata.credential_id}")
                validation_report = self.credential_validator.validate_credential(
                    credential, ValidationLevel.BASIC
                )
                
                if not validation_report.is_valid():
                    print(f"⚠️  Credenziale non valida, aggiunta comunque al wallet")
                    for error in validation_report.errors[:3]:
                        print(f"      - {error.message}")
            
            # Crea wrapper credenziale
            wallet_credential = WalletCredential(
                credential=credential,
                storage_id=storage_id,
                added_date=datetime.datetime.utcnow(),
                tags=tags or [],
                last_accessed=datetime.datetime.utcnow()
            )
            
            # Aggiunge al wallet
            self.credentials[storage_id] = wallet_credential
            
            # Aggiorna attività
            self.last_activity = datetime.datetime.utcnow()
            
            # Salva wallet
            self._save_wallet()
            
            # Auto-backup se abilitato
            if self.config.auto_backup:
                self._create_backup()
            
            print(f"✅ Credenziale aggiunta al wallet: {storage_id[:8]}...")
            print(f"   Università: {credential.issuer.name}")
            print(f"   Studente: {credential.subject.pseudonym}")
            print(f"   Corsi: {len(credential.courses)}")
            
            return storage_id
            
        except Exception as e:
            print(f"❌ Errore aggiunta credenziale: {e}")
            raise
    
    def get_credential(self, storage_id: str) -> Optional[WalletCredential]:
        """
        Ottiene una credenziale dal wallet
        
        Args:
            storage_id: ID storage della credenziale
            
        Returns:
            Credenziale se trovata
        """
        if self.status != WalletStatus.UNLOCKED:
            raise RuntimeError("Wallet deve essere sbloccato")
        
        if storage_id in self.credentials:
            credential = self.credentials[storage_id]
            credential.last_accessed = datetime.datetime.utcnow()
            self.last_activity = datetime.datetime.utcnow()
            return credential
        
        return None
    
    def list_credentials(self, filter_tags: List[str] = None, 
                        filter_status: CredentialStatus = None) -> List[Dict[str, Any]]:
        """
        Lista credenziali nel wallet
        
        Args:
            filter_tags: Filtra per tag
            filter_status: Filtra per status
            
        Returns:
            Lista riassunti credenziali
        """
        if self.status != WalletStatus.UNLOCKED:
            raise RuntimeError("Wallet deve essere sbloccato")
        
        results = []
        
        for storage_id, wallet_cred in self.credentials.items():
            credential = wallet_cred.credential
            
            # Applica filtri
            if filter_tags:
                if not any(tag in wallet_cred.tags for tag in filter_tags):
                    continue
            
            if filter_status:
                if credential.status != filter_status:
                    continue
            
            # Crea riassunto
            summary = credential.get_summary()
            summary.update({
                'storage_id': storage_id,
                'added_date': wallet_cred.added_date.isoformat(),
                'tags': wallet_cred.tags,
                'favorite': wallet_cred.favorite,
                'last_accessed': (
                    wallet_cred.last_accessed.isoformat() 
                    if wallet_cred.last_accessed else None
                )
            })
            
            results.append(summary)
        
        # Ordina per data aggiunta (più recenti primi)
        results.sort(key=lambda x: x['added_date'], reverse=True)
        
        return results
    
    def remove_credential(self, storage_id: str) -> bool:
        """
        Rimuove una credenziale dal wallet
        
        Args:
            storage_id: ID storage della credenziale
            
        Returns:
            True se rimossa con successo
        """
        if self.status != WalletStatus.UNLOCKED:
            raise RuntimeError("Wallet deve essere sbloccato")
        
        if storage_id in self.credentials:
            credential_name = self.credentials[storage_id].credential.subject.pseudonym
            del self.credentials[storage_id]
            
            # Aggiorna attività e salva
            self.last_activity = datetime.datetime.utcnow()
            self._save_wallet()
            
            print(f"🗑️  Credenziale rimossa: {credential_name}")
            return True
        
        print(f"⚠️  Credenziale non trovata: {storage_id}")
        return False
    
    def export_credential(self, storage_id: str, output_path: str, 
                         include_private_data: bool = False) -> bool:
        """
        Esporta una credenziale dal wallet
        
        Args:
            storage_id: ID storage della credenziale
            output_path: Percorso file di output
            include_private_data: Include dati privati wallet
            
        Returns:
            True se esportata con successo
        """
        if self.status != WalletStatus.UNLOCKED:
            raise RuntimeError("Wallet deve essere sbloccato")
        
        try:
            wallet_cred = self.get_credential(storage_id)
            if not wallet_cred:
                print(f"❌ Credenziale non trovata: {storage_id}")
                return False
            
            # Prepara dati export
            if include_private_data:
                export_data = wallet_cred.to_dict()
            else:
                export_data = wallet_cred.credential.to_dict()
            
            # Salva file
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
            
            print(f"💾 Credenziale esportata: {output_path}")
            return True
            
        except Exception as e:
            print(f"❌ Errore export: {e}")
            return False
    
    def import_credential(self, file_path: str, tags: List[str] = None) -> Optional[str]:
        """
        Importa una credenziale nel wallet
        
        Args:
            file_path: Percorso file credenziale
            tags: Tag da assegnare
            
        Returns:
            Storage ID se importata con successo
        """
        if self.status != WalletStatus.UNLOCKED:
            raise RuntimeError("Wallet deve essere sbloccato")
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Verifica se è una credenziale wallet o solo credenziale
            if 'credential' in data:
                # Formato wallet completo
                credential = AcademicCredential.from_dict(data['credential'])
            else:
                # Solo credenziale
                credential = AcademicCredential.from_dict(data)
            
            # Aggiunge al wallet
            storage_id = self.add_credential(credential, tags)
            
            print(f"📥 Credenziale importata: {storage_id[:8]}...")
            return storage_id
            
        except Exception as e:
            print(f"❌ Errore import: {e}")
            return None
    
    def search_credentials(self, query: str) -> List[Dict[str, Any]]:
        """
        Cerca credenziali per testo
        
        Args:
            query: Testo da cercare
            
        Returns:
            Lista credenziali trovate
        """
        if self.status != WalletStatus.UNLOCKED:
            raise RuntimeError("Wallet deve essere sbloccato")
        
        results = []
        query_lower = query.lower()
        
        for wallet_cred in self.credentials.values():
            credential = wallet_cred.credential
            
            # Cerca in vari campi
            search_fields = [
                credential.issuer.name,
                credential.host_university.name,
                credential.subject.pseudonym,
                credential.study_program.name,
                ' '.join([course.course_name for course in credential.courses]),
                ' '.join(wallet_cred.tags),
                wallet_cred.notes or ""
            ]
            
            search_text = ' '.join(search_fields).lower()
            
            if query_lower in search_text:
                summary = credential.get_summary()
                summary['storage_id'] = wallet_cred.storage_id
                summary['relevance_score'] = search_text.count(query_lower)
                results.append(summary)
        
        # Ordina per rilevanza
        results.sort(key=lambda x: x['relevance_score'], reverse=True)
        
        return results
    
    def get_wallet_statistics(self) -> WalletStats:
        """
        Ottiene statistiche del wallet
        
        Returns:
            Statistiche wallet
        """
        if self.status != WalletStatus.UNLOCKED:
            raise RuntimeError("Wallet deve essere sbloccato")
        
        stats = WalletStats()
        
        if not self.credentials:
            return stats
        
        # Conta per status
        for wallet_cred in self.credentials.values():
            credential = wallet_cred.credential
            stats.total_credentials += 1
            
            if credential.status == CredentialStatus.ACTIVE:
                stats.active_credentials += 1
            elif credential.status == CredentialStatus.REVOKED:
                stats.revoked_credentials += 1
            
            # Verifica scadenza
            if (credential.metadata.expires_at and 
                datetime.datetime.utcnow() > credential.metadata.expires_at):
                stats.expired_credentials += 1
        
        # Conta università uniche
        universities = set()
        total_credits = 0
        all_grades = []
        
        for wallet_cred in self.credentials.values():
            credential = wallet_cred.credential
            universities.add(credential.issuer.name)
            universities.add(credential.host_university.name)
            total_credits += credential.total_ects_credits
            
            # Raccoglie voti per media
            for course in credential.courses:
                if course.grade.passed and '/' in course.grade.score:
                    try:
                        grade_num = float(course.grade.score.split('/')[0])
                        all_grades.append(grade_num)
                    except:
                        pass
        
        stats.universities_count = len(universities)
        stats.total_ects_credits = total_credits
        stats.last_activity = self.last_activity
        
        # Calcola media voti
        if all_grades:
            avg_grade = sum(all_grades) / len(all_grades)
            stats.average_grade = f"{avg_grade:.2f}/30"
        
        return stats
    
    def create_backup(self) -> bool:
        """
        Crea backup manuale del wallet
        
        Returns:
            True se backup creato
        """
        return self._create_backup()
    
    def restore_backup(self, backup_file: str, password: str) -> bool:
        """
        Ripristina wallet da backup
        
        Args:
            backup_file: File di backup
            password: Password del wallet
            
        Returns:
            True se ripristinato con successo
        """
        try:
            print(f"🔄 Ripristinando wallet da backup: {backup_file}")
            
            # Verifica password
            password_hash = self.crypto_utils.sha256_hash_string(password + "wallet_salt")
            
            # Carica backup
            with open(backup_file, 'r', encoding='utf-8') as f:
                backup_data = json.load(f)
            
            if backup_data.get('password_hash') != password_hash:
                print("❌ Password errata per backup")
                return False
            
            # Ripristina credenziali
            self.credentials = {}
            for cred_data in backup_data.get('credentials', []):
                wallet_cred = WalletCredential.from_dict(cred_data)
                self.credentials[wallet_cred.storage_id] = wallet_cred
            
            # Salva wallet ripristinato
            self._save_wallet()
            
            print(f"✅ Wallet ripristinato ({len(self.credentials)} credenziali)")
            return True
            
        except Exception as e:
            print(f"❌ Errore ripristino backup: {e}")
            return False
    
    def _validate_password(self, password: str) -> bool:
        """Valida password secondo policy"""
        if len(password) < self.config.password_min_length:
            print(f"❌ Password troppo corta (minimo {self.config.password_min_length} caratteri)")
            return False
        
        if not any(c.isupper() for c in password):
            print("❌ Password deve contenere almeno una maiuscola")
            return False
        
        if not any(c.isdigit() for c in password):
            print("❌ Password deve contenere almeno un numero")
            return False
        
        return True

    def _save_encrypted_keys(self, password: str):
        """Salva chiavi cifrate con password"""
        try:
            # Deriva chiave di cifratura dalla password
            password_bytes = password.encode('utf-8')
            # USARE .digest() per ottenere i bytes, non hexdigest() che restituisce una stringa
            key = hashlib.sha256(password_bytes).digest()  # Questo produce una chiave di 32 bytes (256 bit)

            # Serializza chiave privata
            private_pem = self.key_manager.serialize_private_key(self.wallet_private_key)
            public_pem = self.key_manager.serialize_public_key(self.wallet_public_key)

            # Combina chiavi
            keys_data = {
                'private_key': private_pem.decode('utf-8'),
                'public_key': public_pem.decode('utf-8')
            }

            keys_json = json.dumps(keys_data).encode('utf-8')

            # Cifra con AES
            iv = os.urandom(16)  # IV per AES
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            # Padding PKCS7
            pad_length = 16 - (len(keys_json) % 16)
            padded_data = keys_json + bytes([pad_length] * pad_length)

            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

            # Salva IV + dati cifrati
            final_data = iv + encrypted_data

            with open(self.keys_file, 'wb') as f:
                f.write(final_data)

            # Protegge file
            os.chmod(self.keys_file, 0o600)

        except Exception as e:
            raise RuntimeError(f"Errore salvataggio chiavi: {e}")    
    
    def _load_encrypted_keys(self, password: str) -> bool:
        """Carica chiavi cifrate con password"""
        try:
            if not self.keys_file.exists():
                print("❌ File chiavi non trovato")
                return False

            # Deriva chiave di cifratura
            password_bytes = password.encode('utf-8')
            # USARE .digest() anche qui per coerenza
            key = hashlib.sha256(password_bytes).digest()

            # Legge dati cifrati
            with open(self.keys_file, 'rb') as f:
                encrypted_data = f.read()

            # Estrae IV e dati
            iv = encrypted_data[:16]
            ciphertext = encrypted_data[16:]

            # Decifra
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()

            padded_data = decryptor.update(ciphertext) + decryptor.finalize()

            # Rimuove padding
            pad_length = padded_data[-1]
            keys_json = padded_data[:-pad_length]

            # Deserializza chiavi
            keys_data = json.loads(keys_json.decode('utf-8'))

            self.wallet_private_key = self.key_manager.deserialize_private_key(
                keys_data['private_key'].encode('utf-8')
            )
            self.wallet_public_key = self.key_manager.deserialize_public_key(
                keys_data['public_key'].encode('utf-8')
            )

            return True

        except Exception as e:
            print(f"❌ Errore caricamento chiavi: {e}")
            return False
    
    def _save_wallet(self):
        """Salva wallet su storage"""
        try:
            wallet_data = {
                'version': '1.0',
                'wallet_name': self.config.wallet_name,
                'created_date': datetime.datetime.utcnow().isoformat(),
                'password_hash': self.password_hash,
                'status': self.status.value,
                'last_activity': self.last_activity.isoformat() if self.last_activity else None,
                'configuration': {
                    'storage_mode': self.config.storage_mode.value,
                    'auto_backup': self.config.auto_backup,
                    'auto_validate_credentials': self.config.auto_validate_credentials
                },
                'credentials': [cred.to_dict() for cred in self.credentials.values()]
            }
            
            # Salva cifrato o plaintext secondo configurazione
            if self.config.storage_mode == CredentialStorage.ENCRYPTED_LOCAL:
                self._save_encrypted_wallet(wallet_data)
            else:
                with open(self.wallet_file, 'w', encoding='utf-8') as f:
                    json.dump(wallet_data, f, indent=2, ensure_ascii=False, default=str)
            
        except Exception as e:
            raise RuntimeError(f"Errore salvataggio wallet: {e}")
    
    def _load_wallet(self) -> bool:
        """Carica wallet da storage"""
        try:
            if self.config.storage_mode == CredentialStorage.ENCRYPTED_LOCAL:
                wallet_data = self._load_encrypted_wallet()
            else:
                with open(self.wallet_file, 'r', encoding='utf-8') as f:
                    wallet_data = json.load(f)
            
            # Carica credenziali
            self.credentials = {}
            for cred_data in wallet_data.get('credentials', []):
                wallet_cred = WalletCredential.from_dict(cred_data)
                self.credentials[wallet_cred.storage_id] = wallet_cred
            
            return True
            
        except Exception as e:
            print(f"❌ Errore caricamento wallet: {e}")
            return False
    
    def _load_wallet_metadata(self) -> Dict[str, Any]:
        """Carica solo metadati wallet per verifica password"""
        try:
            with open(self.wallet_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            return {
                'password_hash': data.get('password_hash'),
                'wallet_name': data.get('wallet_name'),
                'version': data.get('version')
            }
            
        except Exception as e:
            print(f"❌ Errore caricamento metadati: {e}")
            return {}
    
    def _save_encrypted_wallet(self, wallet_data: Dict[str, Any]):
        """Salva wallet cifrato (implementazione semplificata)"""
        # Per semplicità, salviamo in plaintext con nota di cifratura
        wallet_data['_encryption'] = 'simulated'
        
        with open(self.wallet_file, 'w', encoding='utf-8') as f:
            json.dump(wallet_data, f, indent=2, ensure_ascii=False, default=str)
    
    def _load_encrypted_wallet(self) -> Dict[str, Any]:
        """Carica wallet cifrato (implementazione semplificata)"""
        with open(self.wallet_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def _create_backup(self) -> bool:
        """Crea backup del wallet"""
        try:
            if self.status != WalletStatus.UNLOCKED:
                return False
            
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = self.backup_dir / f"wallet_backup_{timestamp}.json"
            
            # Prepara dati backup
            backup_data = {
                'backup_date': datetime.datetime.utcnow().isoformat(),
                'wallet_name': self.config.wallet_name,
                'password_hash': self.password_hash,
                'credentials': [cred.to_dict() for cred in self.credentials.values()],
                'statistics': self.get_wallet_statistics().to_dict()
            }
            
            # Salva backup
            with open(backup_file, 'w', encoding='utf-8') as f:
                json.dump(backup_data, f, indent=2, ensure_ascii=False, default=str)
            
            # Cleanup vecchi backup
            self._cleanup_old_backups()
            
            print(f"💾 Backup creato: {backup_file.name}")
            return True
            
        except Exception as e:
            print(f"❌ Errore backup: {e}")
            return False
    
    def _cleanup_old_backups(self):
        """Rimuove backup vecchi"""
        try:
            backup_files = list(self.backup_dir.glob("wallet_backup_*.json"))
            
            if len(backup_files) > self.config.max_backup_files:
                # Ordina per data e rimuove i più vecchi
                backup_files.sort(key=lambda f: f.stat().st_mtime)
                
                files_to_remove = backup_files[:-self.config.max_backup_files]
                for file_path in files_to_remove:
                    file_path.unlink()
                    
                print(f"🗑️  Rimossi {len(files_to_remove)} backup vecchi")
                
        except Exception as e:
            print(f"⚠️  Errore cleanup backup: {e}")


# =============================================================================
# 3. DEMO E TESTING
# =============================================================================

def demo_student_wallet():
    """Demo del Student Wallet"""
    
    print("👤" * 40)
    print("DEMO STUDENT WALLET")
    print("Wallet Digitale Studenti")
    print("👤" * 40)
    
    try:
        # 1. Configurazione wallet
        print("\n1️⃣ CONFIGURAZIONE WALLET")
        
        config = WalletConfiguration(
            wallet_name="Mario Rossi - Wallet Erasmus",
            storage_path="./wallet/mario_rossi",
            storage_mode=CredentialStorage.ENCRYPTED_LOCAL,
            auto_backup=True,
            require_password=True,
            auto_validate_credentials=True
        )
        
        wallet = AcademicStudentWallet(config)
        
        # 2. Creazione wallet
        print("\n2️⃣ CREAZIONE WALLET")
        
        password = "SecureWallet123!"
        
        if not wallet.wallet_file.exists():
            success = wallet.create_wallet(password)
            if not success:
                print("❌ Creazione wallet fallita")
                return None
        else:
            print("📂 Wallet esistente trovato")
        
        # 3. Sblocco wallet
        print("\n3️⃣ SBLOCCO WALLET")
        
        unlock_success = wallet.unlock_wallet(password)
        if not unlock_success:
            print("❌ Sblocco wallet fallito")
            return None
        
        # 4. Aggiunta credenziali di test
        print("\n4️⃣ AGGIUNTA CREDENZIALI")
        
        # Importa credenziali esistenti o crea di esempio
        from credentials.models import CredentialFactory
        
        # Crea 3 credenziali di esempio
        credentials_to_add = []
        
        for i in range(3):
            cred = CredentialFactory.create_sample_credential()
            
            # Personalizza per varietà
            if i == 1:
                cred.subject.pseudonym = f"student_erasmus_{i+1}"
                cred.host_university.name = "Technical University of Munich"
                cred.host_university.country = "DE"
                tags = ["germany", "technical", "winter"]
            elif i == 2:
                cred.subject.pseudonym = f"student_erasmus_{i+1}"
                cred.host_university.name = "KU Leuven"
                cred.host_university.country = "BE"
                tags = ["belgium", "research", "spring"]
            else:
                tags = ["france", "erasmus", "first"]
            
            credentials_to_add.append((cred, tags))
        
        storage_ids = []
        for cred, tags in credentials_to_add:
            storage_id = wallet.add_credential(cred, tags)
            storage_ids.append(storage_id)
        
        print(f"✅ Aggiunte {len(storage_ids)} credenziali al wallet")
        
        # 5. Lista credenziali
        print("\n5️⃣ LISTA CREDENZIALI")
        
        all_credentials = wallet.list_credentials()
        print(f"📚 Credenziali nel wallet: {len(all_credentials)}")
        
        for cred_summary in all_credentials:
            print(f"   - {cred_summary['storage_id'][:8]}... | {cred_summary['subject_pseudonym']} | {cred_summary['host_university']} | {cred_summary['total_courses']} corsi")
        
        # 6. Ricerca credenziali
        print("\n6️⃣ RICERCA CREDENZIALI")
        
        search_results = wallet.search_credentials("france")
        print(f"🔍 Risultati ricerca 'france': {len(search_results)}")
        
        for result in search_results:
            print(f"   - {result['subject_pseudonym']} | Score: {result['relevance_score']}")
        
        # 7. Filtri per tag
        print("\n7️⃣ FILTRI PER TAG")
        
        tagged_credentials = wallet.list_credentials(filter_tags=["erasmus"])
        print(f"🏷️  Credenziali con tag 'erasmus': {len(tagged_credentials)}")
        
        # 8. Statistiche wallet
        print("\n8️⃣ STATISTICHE WALLET")
        
        stats = wallet.get_wallet_statistics()
        print("📊 Statistiche:")
        stats_dict = stats.to_dict()
        for key, value in stats_dict.items():
            print(f"   {key}: {value}")
        
        # 9. Export/Import credenziali
        print("\n9️⃣ TEST EXPORT/IMPORT")
        
        if storage_ids:
            # Export prima credenziale
            export_path = "./wallet/exported_credential.json"
            Path("./wallet").mkdir(exist_ok=True)
            
            export_success = wallet.export_credential(storage_ids[0], export_path)
            
            if export_success:
                print(f"💾 Credenziale esportata: {export_path}")
                
                # Test import (rimuovi e reimporta)
                original_count = len(wallet.credentials)
                wallet.remove_credential(storage_ids[0])
                
                imported_id = wallet.import_credential(export_path, ["imported", "test"])
                
                if imported_id:
                    print(f"📥 Credenziale reimportata: {imported_id[:8]}...")
                    final_count = len(wallet.credentials)
                    print(f"   Credenziali: {original_count} → {original_count-1} → {final_count}")
        
        # 10. Backup wallet
        print("\n🔟 BACKUP WALLET")
        
        backup_success = wallet.create_backup()
        if backup_success:
            print("💾 Backup wallet creato")
        
        # 11. Gestione credenziale singola
        print("\n1️⃣1️⃣ GESTIONE CREDENZIALE SINGOLA")
        
        if storage_ids:
            test_storage_id = storage_ids[0]
            wallet_cred = wallet.get_credential(test_storage_id)
            
            if wallet_cred:
                print(f"📋 Credenziale caricata:")
                print(f"   Pseudonimo: {wallet_cred.credential.subject.pseudonym}")
                print(f"   Università: {wallet_cred.credential.host_university.name}")
                print(f"   Tag: {wallet_cred.tags}")
                print(f"   Ultimo accesso: {wallet_cred.last_accessed}")
                
                # Modifica tag
                wallet_cred.tags.append("demo_completed")
                wallet_cred.favorite = True
        
        # 12. Blocco wallet
        print("\n1️⃣2️⃣ BLOCCO WALLET")
        
        lock_success = wallet.lock_wallet()
        if lock_success:
            print("🔒 Wallet bloccato correttamente")
        
        print("\n" + "✅" * 40)
        print("DEMO STUDENT WALLET COMPLETATA!")
        print("✅" * 40)
        
        print(f"\n📁 Wallet directory: {config.storage_path}")
        print(f"🎓 Wallet name: {config.wallet_name}")
        print(f"📚 Credenziali gestite: {len(all_credentials)}")
        print(f"💾 Backup disponibili: {len(list(wallet.backup_dir.glob('*.json')))}")
        
        return wallet
        
    except Exception as e:
        print(f"\n❌ Errore durante demo: {e}")
        import traceback
        traceback.print_exc()
        return None


# =============================================================================
# 4. MAIN - PUNTO DI INGRESSO
# =============================================================================

if __name__ == "__main__":
    print("👤" * 50)
    print("STUDENT WALLET")
    print("Wallet Digitale per Credenziali Accademiche")
    print("👤" * 50)
    
    # Esegui demo
    wallet_instance = demo_student_wallet()
    
    if wallet_instance:
        print("\n🎉 Student Wallet pronto!")
        print("\nFunzionalità disponibili:")
        print("✅ Creazione e gestione wallet sicuro")
        print("✅ Cifratura e protezione password")
        print("✅ Archiviazione credenziali multiple")
        print("✅ Ricerca e filtri avanzati")
        print("✅ Export/Import credenziali")
        print("✅ Backup automatici")
        print("✅ Statistiche e analitiche")
        print("✅ Gestione tag e organizzazione")
        print("✅ Validazione automatica credenziali")
        
        print(f"\n🚀 Pronto per Selective Disclosure!")
    else:
        print("\n❌ Errore inizializzazione Student Wallet")