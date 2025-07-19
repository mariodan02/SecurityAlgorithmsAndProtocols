"""
Sistema di emissione credenziali accademiche.

Questo modulo fornisce la funzionalità per:
- Configurazione e inizializzazione dell'issuer
- Gestione richieste di emissione
- Creazione e firma credenziali
- Integrazione con blockchain
- Backup e gestione database
"""

import datetime
import json
import logging
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

try:
    from blockchain.blockchain_service import BlockchainService
    from crypto.foundations import CryptoUtils, DigitalSignature
    from credentials.models import (
        AcademicCredential, 
        CredentialFactory,
        CredentialStatus,
        DigitalSignature as CredentialSignature,
        PersonalInfo,
        StudyPeriod,
        StudyProgram,
        University,
        Course
    )
    from pki.certificate_manager import CertificateManager
except ImportError as e:
    raise ImportError(f"Moduli richiesti non disponibili: {e}")


logger = logging.getLogger(__name__)


@dataclass
class IssuerConfiguration:
    """Configurazione per l'issuer di credenziali."""
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
    """Rappresenta una richiesta di emissione credenziale."""
    request_id: str
    student_info: PersonalInfo
    study_period: StudyPeriod
    host_university: University
    study_program: StudyProgram
    courses: List[Course]
    requested_by: str
    request_date: datetime.datetime
    notes: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte la richiesta in dizionario."""
        return {
            'request_id': self.request_id,
            'student_info': self.student_info.model_dump(),
            'study_period': self.study_period.model_dump(),
            'host_university': self.host_university.model_dump(),
            'study_program': self.study_program.model_dump(),
            'courses': [course.model_dump() for course in self.courses],
            'requested_by': self.requested_by,
            'request_date': self.request_date.isoformat(),
            'notes': self.notes
        }


@dataclass
class IssuanceResult:
    """Risultato di un'operazione di emissione credenziale."""
    success: bool
    credential: Optional[AcademicCredential] = None
    credential_id: Optional[str] = None
    signature_info: Optional[Dict[str, Any]] = None
    errors: Optional[List[str]] = None
    warnings: Optional[List[str]] = None
    issued_at: Optional[datetime.datetime] = None
    
    def __post_init__(self):
        """Inizializza liste vuote se None."""
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []


class AcademicCredentialIssuer:
    """
    Issuer per credenziali accademiche.
    
    Gestisce il processo completo di emissione delle credenziali:
    - Validazione richieste
    - Creazione credenziali
    - Firma digitale
    - Registrazione su blockchain
    - Backup e persistenza
    """
    
    def __init__(self, config: IssuerConfiguration):
        """
        Inizializza l'issuer con la configurazione specificata.
        
        Args:
            config: Configurazione dell'issuer
        """
        self.config = config
        
        # Crea directory di backup se abilitato
        if self.config.backup_enabled:
            Path(self.config.backup_directory).mkdir(parents=True, exist_ok=True)
        
        # Inizializza componenti crittografici
        self.crypto_utils = CryptoUtils()
        self.cert_manager = CertificateManager()
        self.digital_signature = DigitalSignature("PSS")
        
        # Storage in memoria
        self.credentials_db: Dict[str, AcademicCredential] = {}
        self.pending_requests: Dict[str, IssuanceRequest] = {}
        
        # Cache per certificati e chiavi
        self.university_certificate: Optional[x509.Certificate] = None
        self.university_private_key: Optional[rsa.RSAPrivateKey] = None
        
        # Statistiche operative
        self.stats = {
            'credentials_issued': 0,
            'requests_processed': 0,
            'signing_operations': 0,
            'validation_errors': 0
        }

        # Inizializza servizio blockchain
        self._initialize_blockchain_service()
        
        # Inizializza componenti issuer
        self._initialize_issuer()
        
        logger.info(f"Credential Issuer inizializzato per: {config.university_info.name}")

    def _initialize_blockchain_service(self) -> None:
        """Inizializza il servizio blockchain se disponibile."""
        self.blockchain_service = None
        self.web3 = None
        self.issuer_account = None
        
        try:
            # Utilizza chiave privata di Ganache per demo
            ganache_private_key = '0xc6e10d62b4d468cd29192e693c78cb888b1e327f4847dac9bc305dd65bfffb55'
            
            self.blockchain_service = BlockchainService(raw_private_key=ganache_private_key)
            
            if self.blockchain_service:
                self.web3 = self.blockchain_service.w3
                self.issuer_account = self.blockchain_service.account
                logger.info("BlockchainService inizializzato correttamente")
        
        except Exception as e:
            logger.warning(f"Impossibile inizializzare BlockchainService: {e}")
            logger.info("Il sistema funzionerà senza integrazione blockchain")
    
    def _send_signed_transaction(self, transaction):
        """
        Firma e invia una transazione blockchain.
        
        Args:
            transaction: Transazione da firmare e inviare
            
        Returns:
            Receipt della transazione
        """
        signed_tx = self.issuer_account.sign_transaction(transaction)
        tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
        receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)
        return receipt

    def _initialize_issuer(self) -> None:
        """Inizializza i componenti dell'issuer."""
        try:
            # Carica certificato università
            if Path(self.config.certificate_path).exists():
                self.university_certificate = self.cert_manager.load_certificate_from_file(
                    self.config.certificate_path
                )
                logger.info("Certificato università caricato")
            else:
                logger.warning(f"Certificato non trovato: {self.config.certificate_path}")
            
            # Carica chiave privata università
            if Path(self.config.private_key_path).exists():
                with open(self.config.private_key_path, 'rb') as f:
                    private_pem = f.read()
                
                password = self.config.private_key_password
                password_bytes = password.encode('utf-8') if password else None
                
                self.university_private_key = serialization.load_pem_private_key(
                    private_pem, password=password_bytes
                )
                logger.info("Chiave privata università caricata")
            else:
                logger.warning(f"Chiave privata non trovata: {self.config.private_key_path}")
            
            # Carica database esistente
            self._load_credentials_database()
            
            logger.info("Issuer inizializzato correttamente")
            
        except Exception as e:
            logger.error(f"Errore inizializzazione issuer: {e}")
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
        Crea una nuova richiesta di emissione credenziale.
        
        Args:
            student_info: Informazioni studente
            study_period: Periodo di studio
            host_university: Università ospitante
            study_program: Programma di studio
            courses: Lista corsi sostenuti
            requested_by: Identificativo richiedente
            notes: Note opzionali
            
        Returns:
            ID della richiesta creata
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
        
        logger.info(f"Richiesta creata: {request_id}")
        logger.debug(f"Studente: {student_info.pseudonym}, Corsi: {len(courses)}")
        
        return request_id
    
    def process_issuance_request(self, request_id: str) -> IssuanceResult:
        """
        Processa una richiesta di emissione credenziale.
        
        Args:
            request_id: ID della richiesta da processare
            
        Returns:
            Risultato dell'operazione di emissione
        """
        if request_id not in self.pending_requests:
            return IssuanceResult(
                success=False,
                errors=[f"Richiesta {request_id} non trovata"]
            )
        
        request = self.pending_requests[request_id]
        self.stats['requests_processed'] += 1
        
        logger.info(f"Processando richiesta: {request_id}")
        
        try:
            # Validazione richiesta
            logger.debug("Validazione richiesta")
            validation_result = self._validate_issuance_request(request)
            
            if not validation_result.success:
                return validation_result
            
            # Creazione credenziale
            logger.debug("Creazione credenziale")
            credential = self._create_credential_from_request(request)
            
            # Firma credenziale se abilitata
            if self.config.auto_sign:
                logger.debug("Firma digitale")
                signing_result = self.sign_credential(credential)
                
                if not signing_result.success:
                    return signing_result
                
                credential = signing_result.credential
            
            # Registrazione
            logger.debug("Registrazione")
            credential_id = str(credential.metadata.credential_id)
            
            # Registrazione su blockchain se disponibile
            if self.blockchain_service:
                try:
                    logger.debug("Registrazione su Blockchain")
                    unsigned_tx = self.blockchain_service.build_registration_transaction(
                        credential_id, self.issuer_account.address
                    )
                    receipt = self._send_signed_transaction(unsigned_tx)
                    logger.info(f"Registrazione Blockchain OK. Hash: {self.web3.to_hex(receipt.transaction_hash)}")
                except Exception as e:
                    logger.error(f"Errore registrazione blockchain: {e}")
                    return IssuanceResult(
                        success=False,
                        errors=[f"Errore registrazione blockchain: {e}"]
                    )
            else:
                logger.info("Registrazione Blockchain saltata (servizio non attivo)")
            
            # Backup se abilitato
            if self.config.backup_enabled:
                logger.debug("Backup")
                self._backup_credential(credential)
            
            # Rimuove richiesta processata
            del self.pending_requests[request_id]
            
            # Aggiorna statistiche
            self.stats['credentials_issued'] += 1
            
            result = IssuanceResult(
                success=True,
                credential=credential,
                credential_id=credential_id,
                issued_at=credential.metadata.issued_at
            )
            
            logger.info(f"Credenziale emessa: {credential_id}")
            return result
            
        except Exception as e:
            logger.error(f"Errore durante emissione: {e}")
            error_result = IssuanceResult(
                success=False,
                errors=[f"Errore durante emissione: {e}"]
            )
            self.stats['validation_errors'] += 1
            return error_result
    
    def sign_credential(self, credential: AcademicCredential) -> IssuanceResult:
        """
        Applica firma digitale a una credenziale.
        
        Args:
            credential: Credenziale da firmare
            
        Returns:
            Risultato dell'operazione di firma
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
            logger.info(f"Firmando credenziale: {credential.metadata.credential_id}")
            
            # Prepara dati per firma (esclude firma esistente)
            credential_dict = credential.to_dict()
            credential_dict.pop('signature', None)
            
            # Firma documento
            signed_credential_dict = self.digital_signature.sign_document(
                self.university_private_key,
                credential_dict
            )
            
            # Estrae informazioni firma
            signature_info = signed_credential_dict['firma']
            
            # Crea oggetto firma credenziale
            credential_signature = CredentialSignature(
                algorithm=signature_info['algoritmo'],
                value=signature_info['valore'],
                timestamp=datetime.datetime.fromisoformat(
                    signature_info['timestamp'].replace('Z', '+00:00')
                )
            )
            
            # Aggiunge thumbprint certificato
            if self.university_certificate:
                cert_der = self.university_certificate.public_bytes(serialization.Encoding.DER)
                credential_signature.signer_certificate_thumbprint = self.crypto_utils.sha256_hash(cert_der)
            
            # Aggiorna credenziale
            credential.signature = credential_signature
            credential.status = CredentialStatus.ACTIVE
            
            # Aggiorna statistiche
            self.stats['signing_operations'] += 1
            
            logger.info("Credenziale firmata con successo")
            
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
            logger.error(f"Errore firma credenziale: {e}")
            return IssuanceResult(
                success=False,
                errors=[f"Errore firma: {e}"]
            )
    
    def revoke_credential(self, credential_id: str, reason: str) -> bool:
        """
        Revoca una credenziale esistente.
        
        Args:
            credential_id: ID della credenziale da revocare
            reason: Motivo della revoca
            
        Returns:
            True se la revoca è stata effettuata con successo
        """
        if credential_id not in self.credentials_db:
            logger.error(f"Credenziale {credential_id} non trovata")
            return False
        
        try:
            credential = self.credentials_db[credential_id]
            credential.status = CredentialStatus.REVOKED
            
            # Registra revoca su blockchain se disponibile
            if self.blockchain_service:
                try:
                    unsigned_tx = self.blockchain_service.build_revocation_transaction(
                        credential_id, reason, self.issuer_account.address
                    )
                    self._send_signed_transaction(unsigned_tx)
                    logger.info(f"Credenziale {credential_id} revocata su blockchain")
                except Exception as e:
                    logger.warning(f"Revoca blockchain fallita: {e}")
            
            logger.info(f"Credenziale revocata: {credential_id}, Motivo: {reason}")
            
            # Backup stato revocato
            if self.config.backup_enabled:
                self._backup_credential(credential, suffix="_revoked")
            
            return True
            
        except Exception as e:
            logger.error(f"Errore revoca credenziale: {e}")
            return False
    
    def get_credential(self, credential_id: str) -> Optional[AcademicCredential]:
        """
        Ottiene una credenziale per ID.
        
        Args:
            credential_id: ID della credenziale
            
        Returns:
            Credenziale trovata o None
        """
        return self.credentials_db.get(credential_id)
    
    def list_credentials(self, status_filter: Optional[CredentialStatus] = None) -> List[Dict[str, Any]]:
        """
        Lista le credenziali emesse con filtro opzionale per stato.
        
        Args:
            status_filter: Filtro per stato credenziali
            
        Returns:
            Lista di riassunti delle credenziali
        """
        credentials = []
        
        for credential in self.credentials_db.values():
            if status_filter is None or credential.status == status_filter:
                summary = credential.get_summary()
                credentials.append(summary)
        
        return credentials
    
    def get_pending_requests(self) -> List[Dict[str, Any]]:
        """
        Ottiene la lista delle richieste in attesa.
        
        Returns:
            Lista delle richieste pendenti
        """
        return [request.to_dict() for request in self.pending_requests.values()]
    
    def export_credential(self, credential_id: str, output_path: str, format: str = "json") -> bool:
        """
        Esporta una credenziale su file.
        
        Args:
            credential_id: ID della credenziale da esportare
            output_path: Percorso file di output
            format: Formato di export (default: json)
            
        Returns:
            True se l'export è riuscito
        """
        if credential_id not in self.credentials_db:
            logger.error(f"Credenziale {credential_id} non trovata")
            return False
        
        try:
            credential = self.credentials_db[credential_id]
            
            if format.lower() == "json":
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(credential.to_json())
                
                logger.info(f"Credenziale esportata: {output_path}")
                return True
            else:
                logger.error(f"Formato {format} non supportato")
                return False
                
        except Exception as e:
            logger.error(f"Errore export credenziale: {e}")
            return False
    
    def import_credential(self, file_path: str) -> Optional[str]:
        """
        Importa una credenziale da file.
        
        Args:
            file_path: Percorso del file contenente la credenziale
            
        Returns:
            ID della credenziale importata o None se errore
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                json_data = f.read()
            
            credential = AcademicCredential.from_json(json_data)
            credential_id = str(credential.metadata.credential_id)
            
            # Verifica che non esista già
            if credential_id in self.credentials_db:
                logger.warning(f"Credenziale {credential_id} già presente")
                return None
            
            self.credentials_db[credential_id] = credential
            
            logger.info(f"Credenziale importata: {credential_id}")
            return credential_id
            
        except Exception as e:
            logger.error(f"Errore import credenziale: {e}")
            return None
    
    def _validate_issuance_request(self, request: IssuanceRequest) -> IssuanceResult:
        """
        Valida una richiesta di emissione.
        
        Args:
            request: Richiesta da validare
            
        Returns:
            Risultato della validazione
        """
        errors = []
        warnings = []
        
        try:
            # Valida periodo di studio
            if request.study_period.start_date >= request.study_period.end_date:
                errors.append("Data fine studio deve essere successiva a data inizio")
            
            # Valida corsi nel periodo
            for course in request.courses:
                if not (request.study_period.start_date <= course.exam_date <= request.study_period.end_date):
                    warnings.append(f"Corso {course.course_name} fuori dal periodo di studio")
            
            # Valida crediti ECTS
            total_credits = sum(course.ects_credits for course in request.courses)
            if total_credits == 0:
                errors.append("Nessun credito ECTS nei corsi")
            elif total_credits > 60:  # Limite semestre
                warnings.append(f"Molti crediti ECTS: {total_credits}")
            
            # Valida università ospitante diversa da emittente
            if (request.host_university.name == self.config.university_info.name or
                request.host_university.erasmus_code == self.config.university_info.erasmus_code):
                warnings.append("Università ospitante uguale a università emittente")
            
            # Verifica duplicati studente
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
        """
        Crea una credenziale dalla richiesta di emissione.
        
        Args:
            request: Richiesta di emissione
            
        Returns:
            Credenziale creata
        """
        return CredentialFactory.create_erasmus_credential(
            issuer_university=self.config.university_info,
            host_university=request.host_university,
            student_info=request.student_info,
            courses=request.courses,
            study_period=request.study_period,
            study_program=request.study_program
        )
        
    def _backup_credential(self, credential: AcademicCredential, suffix: str = "") -> None:
        """
        Crea backup di una credenziale.
        
        Args:
            credential: Credenziale da salvare
            suffix: Suffisso opzionale per il nome file
        """
        try:
            backup_dir = Path(self.config.backup_directory)
            backup_dir.mkdir(parents=True, exist_ok=True)
            
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            credential_id = str(credential.metadata.credential_id)
            
            filename = f"credential_{credential_id}_{timestamp}{suffix}.json"
            backup_path = backup_dir / filename
            
            with open(backup_path, 'w', encoding='utf-8') as f:
                f.write(credential.to_json())
            
            logger.debug(f"Backup creato: {backup_path}")
            
        except Exception as e:
            logger.warning(f"Errore backup: {e}")
    
    def _load_credentials_database(self) -> None:
        """Carica database credenziali esistenti."""
        db_path = Path("./credentials/issued_credentials.json")
        
        if db_path.exists():
            try:
                with open(db_path, 'r', encoding='utf-8') as f:
                    db_data = json.load(f)
                
                for credential_data in db_data.get('credentials', []):
                    credential = AcademicCredential.from_dict(credential_data)
                    credential_id = str(credential.metadata.credential_id)
                    self.credentials_db[credential_id] = credential
                
                logger.info(f"Database caricato: {len(self.credentials_db)} credenziali")
                
            except Exception as e:
                logger.warning(f"Errore caricamento database: {e}")
    
    def _save_credentials_database(self) -> None:
        """Salva database credenziali su file."""
        try:
            db_path = Path("./credentials/issued_credentials.json")
            db_path.parent.mkdir(parents=True, exist_ok=True)
            
            db_data = {
                'version': '1.0',
                'issuer': self.config.university_info.model_dump(),
                'last_updated': datetime.datetime.utcnow().isoformat(),
                'statistics': self.stats,
                'credentials': [cred.to_dict() for cred in self.credentials_db.values()]
            }
            
            with open(db_path, 'w', encoding='utf-8') as f:
                json.dump(db_data, f, indent=2, ensure_ascii=False, default=str)
            
            logger.info(f"Database salvato: {len(self.credentials_db)} credenziali")
            
        except Exception as e:
            logger.error(f"Errore salvataggio database: {e}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Ottiene statistiche operative dell'issuer.
        
        Returns:
            Dizionario con statistiche dettagliate
        """
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
    
    def cleanup_expired_requests(self, max_age_hours: int = 24) -> None:
        """
        Pulisce richieste scadute dal sistema.
        
        Args:
            max_age_hours: Età massima delle richieste in ore
        """
        cutoff_time = datetime.datetime.utcnow() - datetime.timedelta(hours=max_age_hours)
        
        expired_requests = [
            req_id for req_id, request in self.pending_requests.items()
            if request.request_date < cutoff_time
        ]
        
        for req_id in expired_requests:
            del self.pending_requests[req_id]
        
        if expired_requests:
            logger.info(f"Rimosse {len(expired_requests)} richieste scadute")
    
    def shutdown(self) -> None:
        """Esegue shutdown pulito dell'issuer."""
        logger.info("Shutdown issuer")
        
        # Salva database
        self._save_credentials_database()
        
        # Pulisce cache
        self.university_certificate = None
        self.university_private_key = None
        
        logger.info("Shutdown completato")