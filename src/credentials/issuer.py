# =============================================================================
# FASE 3: STRUTTURA CREDENZIALI ACCADEMICHE - ISSUER
# File: credentials/issuer.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

import json
import datetime
import os
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
import uuid
from blockchain.blockchain_service import BlockchainService
# Cryptography imports
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Import moduli interni
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from crypto.foundations import DigitalSignature, CryptoUtils, MerkleTree
    from pki.certificate_manager import CertificateManager
    from credentials.models import (
        AcademicCredential, CredentialStatus, DigitalSignature as CredentialSignature,
        Metadata, University, PersonalInfo, StudyPeriod, StudyProgram, Course,
        CredentialFactory
    )
except ImportError as e:
    print(f"⚠️  Errore import moduli interni: {e}")
    print("   Assicurati che tutti i moduli siano presenti nel progetto")
    raise


# =============================================================================
# 1. STRUTTURE DATI PER ISSUER
# =============================================================================

@dataclass
class IssuerConfiguration:
    """Configurazione issuer università"""
    university_info: University
    certificate_path: str
    private_key_path: str
    private_key_password: Optional[str] = None
    revocation_registry_url: Optional[str] = None
    default_validity_days: int = 365
    auto_sign: bool = True
    backup_enabled: bool = True
    backup_directory: str = "./credentials/backups"


@dataclass
class IssuanceRequest:
    """Richiesta di emissione credenziale"""
    request_id: str
    student_info: PersonalInfo
    study_period: StudyPeriod
    host_university: University
    study_program: StudyProgram
    courses: List[Course]
    requested_by: str  # Identificativo richiedente
    request_date: datetime.datetime
    notes: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte in dizionario"""
        return {
            'request_id': self.request_id,
            'student_info': self.student_info.dict(),
            'study_period': self.study_period.dict(),
            'host_university': self.host_university.dict(),
            'study_program': self.study_program.dict(),
            'courses': [course.dict() for course in self.courses],
            'requested_by': self.requested_by,
            'request_date': self.request_date.isoformat(),
            'notes': self.notes
        }


@dataclass
class IssuanceResult:
    """Risultato emissione credenziale"""
    success: bool
    credential: Optional[AcademicCredential] = None
    credential_id: Optional[str] = None
    signature_info: Optional[Dict[str, Any]] = None
    errors: List[str] = None
    warnings: List[str] = None
    issued_at: Optional[datetime.datetime] = None
    
    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []


# =============================================================================
# 2. ACADEMIC CREDENTIAL ISSUER
# =============================================================================

class AcademicCredentialIssuer:
    """Issuer per credenziali accademiche"""
    
    def __init__(self, config: IssuerConfiguration):
        """
        Inizializza l'issuer
        
        Args:
            config: Configurazione issuer
        """
        # FIXED: Assegna config PRIMA di tutto
        self.config = config
        
        if self.config.backup_enabled:
            Path(self.config.backup_directory).mkdir(parents=True, exist_ok=True)
        
        self.crypto_utils = CryptoUtils()
        self.cert_manager = CertificateManager()
        # Componenti crittografici
        self.digital_signature = DigitalSignature("PSS")
        
        # Storage
        self.credentials_db: Dict[str, AcademicCredential] = {}
        self.pending_requests: Dict[str, IssuanceRequest] = {}
        
        # Cache
        self.university_certificate: Optional[x509.Certificate] = None
        self.university_private_key: Optional[rsa.RSAPrivateKey] = None
        
        # Statistiche
        self.stats = {
            'credentials_issued': 0,
            'requests_processed': 0,
            'signing_operations': 0,
            'validation_errors': 0
        }

        # Inizializziamo la blockchain
        self.blockchain_service = None
        self.web3 = None
        self.issuer_account = None
        
        try:
            # Carica la chiave privata di Ganache dal file di testo
            #with open('ganache_key.txt', 'r') as f:
            ganache_private_key = '0xc6e10d62b4d468cd29192e693c78cb888b1e327f4847dac9bc305dd65bfffb55'

            self.blockchain_service = BlockchainService(
                raw_private_key=ganache_private_key
            )

            if self.blockchain_service:
                self.web3 = self.blockchain_service.w3
                self.issuer_account = self.blockchain_service.account
                print("✅ BlockchainService inizializzato correttamente con la chiave di Ganache.")

        except FileNotFoundError:
            print("⚠️ File 'ganache_key.txt' non trovato. La parte blockchain sarà disattivata.")
            print("   Crea il file e inserisci una delle chiavi private di Ganache.")
            self.blockchain_service = None
        except Exception as e:
            print(f"⚠️ Impossibile inizializzare BlockchainService: {e}")
            print("   Il sistema funzionerà senza integrazione blockchain")
            self.blockchain_service = None
        
        # Continua con il resto dell'inizializzazione...
        self._initialize_issuer()
        print(f"🏛️  Credential Issuer inizializzato per: {config.university_info.name}")

        # Inizializza issuer
        self._initialize_issuer()
        
        print(f"🏛️  Credential Issuer inizializzato per: {config.university_info.name}")
                    
    def _send_signed_transaction(self, transaction):
        """Funzione helper per firmare e inviare."""
        signed_tx = self.issuer_account.sign_transaction(transaction)
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
        return receipt

    def _initialize_issuer(self):
        """Inizializza componenti issuer"""
        try:
            # 1. CARICA CERTIFICATO UNIVERSITÀ (ESSENZIALE!)
            if Path(self.config.certificate_path).exists():
                self.university_certificate = self.cert_manager.load_certificate_from_file(
                    self.config.certificate_path
                )
                print(f"   ✅ Certificato università caricato")
            else:
                print(f"   ⚠️  Certificato non trovato: {self.config.certificate_path}")
            
            # 2. CARICA CHIAVE PRIVATA UNIVERSITÀ (ESSENZIALE!)
            if Path(self.config.private_key_path).exists():
                with open(self.config.private_key_path, 'rb') as f:
                    private_pem = f.read()
                
                password = self.config.private_key_password
                password_bytes = password.encode('utf-8') if password else None
                
                self.university_private_key = serialization.load_pem_private_key(
                    private_pem, password=password_bytes
                )
                print(f"   ✅ Chiave privata università caricata")
            else:
                print(f"   ⚠️  Chiave privata non trovata: {self.config.private_key_path}")
            
            # 3. CREA DIRECTORY DI BACKUP
            if self.config.backup_enabled:
                Path(self.config.backup_directory).mkdir(parents=True, exist_ok=True)
            
            # 4. CARICA DATABASE ESISTENTE
            self._load_credentials_database()
            
            # 5. BLOCKCHAIN - GIÀ INIZIALIZZATO NEL COSTRUTTORE
            print("✅ Issuer inizializzato correttamente")
            
        except Exception as e:
            print(f"❌ Errore inizializzazione issuer: {e}")
            raise
    
    def create_issuance_request(self, 
                              student_info: PersonalInfo,
                              study_period: StudyPeriod,
                              host_university: University,
                              study_program: StudyProgram,
                              courses: List[Course],
                              requested_by: str,
                              notes: Optional[str] = None) -> str:
        """
        Crea una richiesta di emissione credenziale
        
        Args:
            student_info: Informazioni studente
            study_period: Periodo di studio
            host_university: Università ospitante
            study_program: Programma di studio
            courses: Lista corsi
            requested_by: Chi richiede l'emissione
            notes: Note opzionali
            
        Returns:
            ID della richiesta
        """
        request_id = str(uuid.uuid4())
        
        request = IssuanceRequest(
            request_id=request_id,
            student_info=student_info,
            study_period=study_period,
            host_university=host_university,
            study_program=study_program,
            courses=courses,
            requested_by=requested_by,
            request_date=datetime.datetime.utcnow(),
            notes=notes
        )
        
        self.pending_requests[request_id] = request
        
        print(f"📝 Richiesta creata: {request_id}")
        print(f"   Studente: {student_info.pseudonym}")
        print(f"   Corsi: {len(courses)}")
        print(f"   Richiedente: {requested_by}")
        
        return request_id
    
    def process_issuance_request(self, request_id: str) -> IssuanceResult:
        """
        Processa una richiesta di emissione
        
        Args:
            request_id: ID della richiesta
            
        Returns:
            Risultato dell'emissione
        """
        if request_id not in self.pending_requests:
            return IssuanceResult(
                success=False,
                errors=[f"Richiesta {request_id} non trovata"]
            )
        
        request = self.pending_requests[request_id]
        self.stats['requests_processed'] += 1
        
        print(f"⚙️  Processando richiesta: {request_id}")
        
        try:
            # 1. Validazione richiesta
            print("   1️⃣ Validazione richiesta...")
            validation_result = self._validate_issuance_request(request)
            
            if not validation_result.success:
                return validation_result
            
            # 2. Creazione credenziale
            print("   2️⃣ Creazione credenziale...")
            credential = self._create_credential_from_request(request)
            
            # 3. Firma credenziale (se auto_sign abilitato)
            if self.config.auto_sign:
                print("   3️⃣ Firma digitale...")
                signing_result = self.sign_credential(credential)
                
                if not signing_result.success:
                    return signing_result
                
                credential = signing_result.credential
            
            # 4. Registra credenziale
            print("   4️⃣ Registrazione...")
            credential_id = str(credential.metadata.credential_id)
            #self.credentials_db[credential_id] = credential
            if self.blockchain_service:
                print("   4️⃣ Registrazione su Blockchain...")
                # L'errore qui ora fermerà il processo e verrà mostrato all'utente
                unsigned_tx = self.blockchain_service.build_registration_transaction(credential_id, self.issuer_account.address)
                receipt = self._send_signed_transaction(unsigned_tx)
                print(f"✅ Registrazione Blockchain OK. Hash: {self.web3.to_hex(receipt.transaction_hash)}")
            else:
                 print("   ⚠️  Registrazione Blockchain saltata (servizio non attivo).")
            # 5. Backup
            if self.config.backup_enabled:
                print("   5️⃣ Backup...")
                self._backup_credential(credential)
            
            # 6. Rimuovi richiesta processata
            del self.pending_requests[request_id]
            
            # 7. Aggiorna statistiche
            self.stats['credentials_issued'] += 1
            
            result = IssuanceResult(
                success=True,
                credential=credential,
                credential_id=credential_id,
                issued_at=credential.metadata.issued_at
            )
            
            print(f"✅ Credenziale emessa: {credential_id}")
            return result
            
        except Exception as e:
            error_result = IssuanceResult(
                success=False,
                errors=[f"Errore durante emissione: {e}"]
            )
            self.stats['validation_errors'] += 1
            return error_result
    
    def sign_credential(self, credential: AcademicCredential) -> IssuanceResult:
        """
        Firma una credenziale
        
        Args:
            credential: Credenziale da firmare
            
        Returns:
            Risultato operazione
        """
        if not self.university_private_key:
            return IssuanceResult(
                success=False,
                errors=["Chiave privata università non disponibile"]
            )
        
        if not self.university_certificate:
            return IssuanceResult(
                success=False,
                errors=["Certificato università non disponibile"]
            )
        
        try:
            print(f"✍️  Firmando credenziale: {credential.metadata.credential_id}")
            
            # 1. Prepara dati per firma (esclude firma esistente)
            credential_dict = credential.to_dict()
            credential_dict.pop('signature', None)
            
            # 2. Firma documento
            signed_credential_dict = self.digital_signature.sign_document(
                self.university_private_key,
                credential_dict
            )
            
            # 3. Estrae informazioni firma
            signature_info = signed_credential_dict['firma']
            
            # 4. Crea oggetto firma credenziale
            credential_signature = CredentialSignature(
                algorithm=signature_info['algoritmo'],
                value=signature_info['valore'],
                timestamp=datetime.datetime.fromisoformat(
                    signature_info['timestamp'].replace('Z', '+00:00')
                )
            )
            
            # 5. Aggiunge thumbprint certificato
            if self.university_certificate:
                cert_der = self.university_certificate.public_bytes(serialization.Encoding.DER)
                credential_signature.signer_certificate_thumbprint = self.crypto_utils.sha256_hash(cert_der)
            
            # 6. Aggiorna credenziale
            credential.signature = credential_signature
            credential.status = CredentialStatus.ACTIVE
            
            # 7. Aggiorna statistiche
            self.stats['signing_operations'] += 1
            
            print(f"✅ Credenziale firmata con successo")
            
            return IssuanceResult(
                success=True,
                credential=credential,
                signature_info={
                    'algorithm': credential_signature.algorithm,
                    'timestamp': credential_signature.timestamp.isoformat(),
                    'thumbprint': credential_signature.signer_certificate_thumbprint
                }
            )
            
        except Exception as e:
            print(f"❌ Errore firma credenziale: {e}")
            return IssuanceResult(
                success=False,
                errors=[f"Errore firma: {e}"]
            )
    
    def revoke_credential(self, credential_id: str, reason: str) -> bool:
        """
        Revoca una credenziale
        
        Args:
            credential_id: ID credenziale da revocare
            reason: Motivo revoca
            
        Returns:
            True se revoca effettuata
        """
        if credential_id not in self.credentials_db:
            print(f"❌ Credenziale {credential_id} non trovata")
            return False
        
        try:
            credential = self.credentials_db[credential_id]
            credential.status = CredentialStatus.REVOKED
            
            if self.blockchain_service:
                try:
                    # 1. Costruisci
                    unsigned_tx = self.blockchain_service.build_revocation_transaction(
                        credential_id, reason, self.issuer_account.address
                    )
                    # 2. Firma e invia
                    self._send_signed_transaction(unsigned_tx)
                    print(f"🔗 Credenziale {credential_id} revocata su blockchain.")
                except Exception as e:
                     print(f"⚠️  Revoca blockchain fallita: {e}")
            
            print(f"🚫 Credenziale revocata: {credential_id}")
            print(f"   Motivo: {reason}")
            
            # Backup stato revocato
            if self.config.backup_enabled:
                self._backup_credential(credential, suffix="_revoked")
            
            return True
            
        except Exception as e:
            print(f"❌ Errore revoca credenziale: {e}")
            return False
    
    def get_credential(self, credential_id: str) -> Optional[AcademicCredential]:
        """Ottiene una credenziale per ID"""
        return self.credentials_db.get(credential_id)
    
    def list_credentials(self, status_filter: Optional[CredentialStatus] = None) -> List[Dict[str, Any]]:
        """
        Lista credenziali emesse
        
        Args:
            status_filter: Filtra per status (opzionale)
            
        Returns:
            Lista riassunti credenziali
        """
        credentials = []
        
        for credential in self.credentials_db.values():
            if status_filter is None or credential.status == status_filter:
                summary = credential.get_summary()
                credentials.append(summary)
        
        return credentials
    
    def get_pending_requests(self) -> List[Dict[str, Any]]:
        """Ottiene richieste in attesa"""
        return [request.to_dict() for request in self.pending_requests.values()]
    
    def export_credential(self, credential_id: str, output_path: str, format: str = "json") -> bool:
        """
        Esporta una credenziale
        
        Args:
            credential_id: ID credenziale
            output_path: Percorso output
            format: Formato export ("json")
            
        Returns:
            True se export riuscito
        """
        if credential_id not in self.credentials_db:
            print(f"❌ Credenziale {credential_id} non trovata")
            return False
        
        try:
            credential = self.credentials_db[credential_id]
            
            if format.lower() == "json":
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(credential.to_json())
                
                print(f"💾 Credenziale esportata: {output_path}")
                return True
            else:
                print(f"❌ Formato {format} non supportato")
                return False
                
        except Exception as e:
            print(f"❌ Errore export credenziale: {e}")
            return False
    
    def import_credential(self, file_path: str) -> Optional[str]:
        """
        Importa una credenziale da file
        
        Args:
            file_path: Percorso file credenziale
            
        Returns:
            ID credenziale importata o None
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                json_data = f.read()
            
            credential = AcademicCredential.from_json(json_data)
            credential_id = str(credential.metadata.credential_id)
            
            # Verifica che non esista già
            if credential_id in self.credentials_db:
                print(f"⚠️  Credenziale {credential_id} già presente")
                return None
            
            self.credentials_db[credential_id] = credential
            
            print(f"📥 Credenziale importata: {credential_id}")
            return credential_id
            
        except Exception as e:
            print(f"❌ Errore import credenziale: {e}")
            return None
    
    def _validate_issuance_request(self, request: IssuanceRequest) -> IssuanceResult:
        """Valida una richiesta di emissione"""
        errors = []
        warnings = []
        
        try:
            # 1. Valida periodo di studio
            if request.study_period.start_date >= request.study_period.end_date:
                errors.append("Data fine studio deve essere successiva a data inizio")
            
            # 2. Valida corsi nel periodo
            for course in request.courses:
                if not (request.study_period.start_date <= course.exam_date <= request.study_period.end_date):
                    warnings.append(f"Corso {course.course_name} fuori dal periodo di studio")
            
            # 3. Valida crediti ECTS
            total_credits = sum(course.ects_credits for course in request.courses)
            if total_credits == 0:
                errors.append("Nessun credito ECTS nei corsi")
            elif total_credits > 60:  # Limite semestre
                warnings.append(f"Molti crediti ECTS: {total_credits}")
            
            # 4. Valida università ospitante diversa da emittente
            if (request.host_university.name == self.config.university_info.name or
                request.host_university.erasmus_code == self.config.university_info.erasmus_code):
                warnings.append("Università ospitante uguale a università emittente")
            
            # 5. Verifica duplicati studente
            student_pseudonym = request.student_info.pseudonym
            for existing_cred in self.credentials_db.values():
                if (existing_cred.subject.pseudonym == student_pseudonym and
                    existing_cred.study_period.academic_year == request.study_period.academic_year):
                    warnings.append(f"Possibile duplicato per studente {student_pseudonym}")
            
            if errors:
                return IssuanceResult(
                    success=False,
                    errors=errors,
                    warnings=warnings
                )
            
            return IssuanceResult(
                success=True,
                warnings=warnings
            )
            
        except Exception as e:
            return IssuanceResult(
                success=False,
                errors=[f"Errore validazione: {e}"]
            )
    
    def _create_credential_from_request(self, request: IssuanceRequest) -> AcademicCredential:
        """Crea credenziale da richiesta"""

        return CredentialFactory.create_erasmus_credential(
            issuer_university=self.config.university_info,
            host_university=request.host_university,
            student_info=request.student_info,
            courses=request.courses,
            study_period=request.study_period,
            study_program=request.study_program
        )
        
    def _backup_credential(self, credential: AcademicCredential, suffix: str = ""):
        """Crea backup di una credenziale"""
        try:
            backup_dir = Path(self.config.backup_directory)
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            credential_id = str(credential.metadata.credential_id)
            
            filename = f"credential_{credential_id}_{timestamp}{suffix}.json"
            backup_path = backup_dir / filename
            
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.write(credential.to_json())
            
            print(f"💾 Backup creato: {backup_path}")
            
        except Exception as e:
            print(f"⚠️  Errore backup: {e}")
    
    def _load_credentials_database(self):
        """Carica database credenziali esistenti"""
        # Implementazione semplificata - in produzione usare database persistente
        db_path = Path("./credentials/issued_credentials.json")
        
        if db_path.exists():
            try:
                with open(db_path, 'r', encoding='utf-8') as f:
                    db_data = json.load(f)
                
                for credential_data in db_data.get('credentials', []):
                    credential = AcademicCredential.from_dict(credential_data)
                    credential_id = str(credential.metadata.credential_id)
                    self.credentials_db[credential_id] = credential
                
                print(f"📚 Database caricato: {len(self.credentials_db)} credenziali")
                
            except Exception as e:
                print(f"⚠️  Errore caricamento database: {e}")
    
    def _save_credentials_database(self):
        """Salva database credenziali"""
        try:
            db_path = Path("./credentials/issued_credentials.json")
            db_path.parent.mkdir(parents=True, exist_ok=True)
            
            db_data = {
                'version': '1.0',
                'issuer': self.config.university_info.dict(),
                'last_updated': datetime.datetime.utcnow().isoformat(),
                'statistics': self.stats,
                'credentials': [cred.to_dict() for cred in self.credentials_db.values()]
            }
            
            with open(db_path, 'w', encoding='utf-8') as f:
                json.dump(db_data, f, indent=2, ensure_ascii=False, default=str)
            
            print(f"💾 Database salvato: {len(self.credentials_db)} credenziali")
            
        except Exception as e:
            print(f"❌ Errore salvataggio database: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Ottiene statistiche issuer"""
        active_credentials = len([c for c in self.credentials_db.values() 
                                if c.status == CredentialStatus.ACTIVE])
        revoked_credentials = len([c for c in self.credentials_db.values() 
                                 if c.status == CredentialStatus.REVOKED])
        
        return {
            **self.stats,
            'total_credentials': len(self.credentials_db),
            'active_credentials': active_credentials,
            'revoked_credentials': revoked_credentials,
            'pending_requests': len(self.pending_requests),
            'success_rate': (
                self.stats['credentials_issued'] / max(1, self.stats['requests_processed'])
            ) * 100
        }
    
    def cleanup_expired_requests(self, max_age_hours: int = 24):
        """Pulisce richieste scadute"""
        cutoff_time = datetime.datetime.utcnow() - datetime.timedelta(hours=max_age_hours)
        
        expired_requests = [
            req_id for req_id, request in self.pending_requests.items()
            if request.request_date < cutoff_time
        ]
        
        for req_id in expired_requests:
            del self.pending_requests[req_id]
        
        if expired_requests:
            print(f"🗑️  Rimosse {len(expired_requests)} richieste scadute")
    
    def shutdown(self):
        """Shutdown pulito dell'issuer"""
        print("🔄 Shutdown issuer...")
        
        # Salva database
        self._save_credentials_database()
        
        # Pulisce cache
        self.university_certificate = None
        self.university_private_key = None
        
        print("✅ Shutdown completato")


# =============================================================================
# 3. DEMO E TESTING
# =============================================================================

def demo_credential_issuer():
    """Demo del Credential Issuer"""
    
    print("🏛️" * 40)
    print("DEMO CREDENTIAL ISSUER")
    print("Emissione Credenziali Accademiche")
    print("🏛️" * 40)
    
    try:
        # 1. Configurazione issuer
        print("\n1️⃣ CONFIGURAZIONE ISSUER")
        
        # Università emittente
        university_salerno = University(
            name="Università degli Studi di Salerno",
            country="IT",
            erasmus_code="I SALERNO01",
            city="Fisciano",
            website="https://www.unisa.it"
        )
        
        # --- MODIFICA CHIAVE ---
        # Definiamo i percorsi corretti per le chiavi dell'Università di Salerno.
        # Questi file vengono generati eseguendo la demo della Certificate Authority.
        cert_path = "./certificates/issued/university_I_SALERNO01_1002.pem"  # Assumendo che il seriale sia 1002 per Salerno
        key_path = "./keys/universita_salerno_private.pem" # <-- NOME CHIAVE CORRETTO
        
        # Controllo esistenza file per aiutare il debug
        if not Path(cert_path).exists():
            print(f"   🔴 ERRORE: Certificato non trovato: {cert_path}")
            print("   💡 Esegui prima 'python src/pki/certificate_authority.py' per generare i certificati.")
            return None
        
        if not Path(key_path).exists():
            print(f"   🔴 ERRORE: Chiave privata non trovata: {key_path}")
            print("   💡 Esegui prima 'python src/pki/certificate_authority.py' per generare le chiavi.")
            # Nota: Ho modificato certificate_authority.py per salvare correttamente le chiavi.
            return None
        
        # Configurazione
        config = IssuerConfiguration(
            university_info=university_salerno,
            certificate_path=cert_path,
            private_key_path=key_path,
            private_key_password="Unisa2025", 
            revocation_registry_url="https://blockchain.academic-credentials.eu",
            default_validity_days=365,
            auto_sign=True,
            backup_enabled=True
        )
        
        # Inizializza issuer
        issuer = AcademicCredentialIssuer(config)
        
        # 2. Crea richiesta emissione
        print("\n2️⃣ CREAZIONE RICHIESTA EMISSIONE")
        
        # Usa dati dal factory di esempio
        sample_credential = CredentialFactory.create_sample_credential()
        
        request_id = issuer.create_issuance_request(
            student_info=sample_credential.subject,
            study_period=sample_credential.study_period,
            host_university=sample_credential.host_university,
            study_program=sample_credential.study_program,
            courses=sample_credential.courses,
            requested_by="erasmus.office@unisa.it",
            notes="Richiesta standard Erasmus - primo semestre"
        )
        
        print(f"✅ Richiesta creata: {request_id}")
        
        # 3. Verifica richieste pending
        print("\n3️⃣ RICHIESTE IN ATTESA")
        
        pending = issuer.get_pending_requests()
        print(f"📋 Richieste pending: {len(pending)}")
        
        for req in pending:
            print(f"   - {req['request_id'][:8]}... | {req['student_info']['pseudonym']} | {len(req['courses'])} corsi")
        
        # 4. Processa richiesta
        print("\n4️⃣ PROCESSAMENTO RICHIESTA")
        
        result = issuer.process_issuance_request(request_id)
        
        if result.success:
            print(f"✅ Credenziale emessa con successo!")
            print(f"   ID: {result.credential_id}")
            print(f"   Emessa: {result.issued_at}")
            
            if result.signature_info:
                print(f"   Firma: {result.signature_info['algorithm']}")
                print(f"   Thumbprint: {result.signature_info['thumbprint'][:16]}...")
        else:
            print(f"❌ Emissione fallita:")
            for error in result.errors:
                print(f"   - {error}")

        # 5. Lista credenziali emesse
        print("\n5️⃣ CREDENZIALI EMESSE")
        
        issued_credentials = issuer.list_credentials(CredentialStatus.ACTIVE)
        print(f"📊 Credenziali attive: {len(issued_credentials)}")
        
        for cred in issued_credentials:
            print(f"   - {cred['credential_id'][:8]}... | {cred['subject_pseudonym']} | {cred['total_courses']} corsi | {cred['total_ects']} ECTS")
        
        # 6. Test export credenziale
        if result.success and result.credential_id:
            print("\n6️⃣ EXPORT CREDENZIALE")
            
            export_path = f"./credentials/exports/credential_{result.credential_id[:8]}.json"
            Path("./credentials/exports").mkdir(parents=True, exist_ok=True)
            
            export_success = issuer.export_credential(result.credential_id, export_path)
            
            if export_success:
                print(f"💾 Credenziale esportata: {export_path}")
        
        # 7. Statistiche
        print("\n7️⃣ STATISTICHE ISSUER")
        
        stats = issuer.get_statistics()
        print("📊 Statistiche:")
        for key, value in stats.items():
            if isinstance(value, float):
                print(f"   {key}: {value:.2f}")
            else:
                print(f"   {key}: {value}")
        
        # 8. Shutdown
        print("\n8️⃣ SHUTDOWN ISSUER")
        issuer.shutdown()
        
        print("\n" + "✅" * 40)
        print("DEMO CREDENTIAL ISSUER COMPLETATA!")
        print("✅" * 40)
        
        return issuer
        
    except Exception as e:
        print(f"\n❌ Errore durante demo: {e}")
        import traceback
        traceback.print_exc()
        return None

# =============================================================================
# 4. MAIN - PUNTO DI INGRESSO
# =============================================================================

if __name__ == "__main__":
    print("🏛️" * 50)
    print("CREDENTIAL ISSUER")
    print("Emissione Credenziali Accademiche")
    print("🏛️" * 50)
    
    # Esegui demo
    issuer_instance = demo_credential_issuer()
    
    if issuer_instance:
        print("\n🎉 Credential Issuer pronto!")
        print("\nFunzionalità disponibili:")
        print("✅ Gestione richieste emissione")
        print("✅ Validazione dati richiesta")
        print("✅ Creazione credenziali")
        print("✅ Firma digitale automatica")
        print("✅ Gestione stati credenziali")
        print("✅ Export/Import credenziali")
        print("✅ Backup automatici")
        print("✅ Revoca credenziali")
        
        print(f"\n🚀 Pronto per integrazione con Validator!")
    else:
        print("\n❌ Errore inizializzazione Credential Issuer")