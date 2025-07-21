"""
Sistema di validazione credenziali accademiche.

Questo modulo fornisce la funzionalità per:
- Validazione formato e struttura credenziali
- Verifica firme digitali e certificati
- Controllo integrità Merkle Tree
- Validazione aspetti temporali
- Verifica stato di revoca (OCSP)
- Analisi forense avanzata
- Validazione divulgazione selettiva
"""

import datetime
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization

try:
    from crypto.foundations import CryptoUtils, DigitalSignature
    from credentials.models import AcademicCredential, Course, CredentialStatus
    from pki.certificate_manager import CertificateManager
    from pki.ocsp_client import OCSPClient, OCSPConfiguration, OCSPStatus
except ImportError as e:
    raise ImportError(f"Moduli richiesti non disponibili: {e}")


logger = logging.getLogger(__name__)


class ValidationLevel(Enum):
    """Livelli di validazione disponibili."""
    BASIC = "basic"               # Validazione base formato
    STANDARD = "standard"         # Include verifica firma
    COMPLETE = "complete"         # Include OCSP e revoca
    FORENSIC = "forensic"         # Validazione forense completa


class ValidationResult(Enum):
    """Possibili risultati di validazione."""
    VALID = "valid"
    INVALID = "invalid"
    WARNING = "warning"
    EXPIRED = "expired"
    REVOKED = "revoked"
    UNKNOWN = "unknown"


@dataclass
class ValidationError:
    """Rappresenta un errore di validazione."""
    code: str
    severity: str  # "error", "warning", "info"
    message: str
    field: Optional[str] = None
    details: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte l'errore in dizionario."""
        return {
            'code': self.code,
            'severity': self.severity,
            'message': self.message,
            'field': self.field,
            'details': self.details or {}
        }


@dataclass
class ValidationReport:
    """Report completo di una validazione."""
    credential_id: str
    validation_level: ValidationLevel
    overall_result: ValidationResult
    timestamp: datetime.datetime
    errors: List[ValidationError] = field(default_factory=list)
    warnings: List[ValidationError] = field(default_factory=list)
    info: List[ValidationError] = field(default_factory=list)
    
    # Risultati specifici delle verifiche
    format_valid: bool = False
    signature_valid: bool = False
    certificate_valid: bool = False
    revocation_status: Optional[str] = None
    merkle_tree_valid: bool = False
    temporal_valid: bool = False
    
    # Dettagli tecnici
    validation_duration_ms: float = 0.0
    validator_version: str = "1.0.0"
    trusted_issuers: List[str] = field(default_factory=list)
    
    def is_valid(self) -> bool:
        """Determina se la credenziale è valida overall."""
        return self.overall_result == ValidationResult.VALID
    
    def has_errors(self) -> bool:
        """Verifica presenza di errori."""
        return len(self.errors) > 0
    
    def has_warnings(self) -> bool:
        """Verifica presenza di warning."""
        return len(self.warnings) > 0
    
    def add_error(self, code: str, message: str, field: Optional[str] = None, 
                  details: Optional[Dict] = None) -> None:
        """Aggiunge un errore al report."""
        self.errors.append(ValidationError(code, "error", message, field, details))
    
    def add_warning(self, code: str, message: str, field: Optional[str] = None, 
                   details: Optional[Dict] = None) -> None:
        """Aggiunge un warning al report."""
        self.warnings.append(ValidationError(code, "warning", message, field, details))
    
    def add_info(self, code: str, message: str, field: Optional[str] = None, 
                 details: Optional[Dict] = None) -> None:
        """Aggiunge un'informazione al report."""
        self.info.append(ValidationError(code, "info", message, field, details))
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte il report in dizionario."""
        return {
            'credential_id': self.credential_id,
            'validation_level': self.validation_level.value,
            'overall_result': self.overall_result.value,
            'timestamp': self.timestamp.isoformat(),
            'is_valid': self.is_valid(),
            'errors': [e.to_dict() for e in self.errors],
            'warnings': [w.to_dict() for w in self.warnings],
            'info': [i.to_dict() for i in self.info],
            'technical_details': {
                'format_valid': self.format_valid,
                'signature_valid': self.signature_valid,
                'certificate_valid': self.certificate_valid,
                'revocation_status': self.revocation_status,
                'merkle_tree_valid': self.merkle_tree_valid,
                'temporal_valid': self.temporal_valid,
                'validation_duration_ms': self.validation_duration_ms,
                'validator_version': self.validator_version,
                'trusted_issuers': self.trusted_issuers
            }
        }


@dataclass
class ValidatorConfiguration:
    """Configurazione per il validator."""
    trusted_ca_certificates: List[str] = field(default_factory=list)
    revocation_check_enabled: bool = True
    ocsp_enabled: bool = True
    ocsp_timeout_seconds: int = 10
    max_certificate_age_days: int = 365
    accept_expired_credentials: bool = False
    strict_merkle_validation: bool = True
    cache_validation_results: bool = True
    cache_duration_minutes: int = 30


class AcademicCredentialValidator:
    """
    Validator per credenziali accademiche.
    
    Gestisce tutti gli aspetti della validazione:
    - Formato e struttura dati
    - Integrità crittografica
    - Verifica certificati e revoche
    - Analisi temporale e forense
    """
    
    def __init__(self, config: Optional[ValidatorConfiguration] = None):
        """
        Inizializza il validator con la configurazione specificata.
        
        Args:
            config: Configurazione del validator (usa default se None)
        """
        self.config = config or ValidatorConfiguration()
        
        # Inizializza componenti crittografici
        self.crypto_utils = CryptoUtils()
        self.digital_signature = DigitalSignature("PSS")
        self.cert_manager = CertificateManager()
        
        # Inizializza client OCSP se abilitato
        if self.config.ocsp_enabled:
            ocsp_config = OCSPConfiguration(
                timeout_seconds=self.config.ocsp_timeout_seconds,
                cache_responses=True
            )
            self.ocsp_client = OCSPClient(ocsp_config)
        else:
            self.ocsp_client = None
        
        # Cache per risultati validazione
        self.validation_cache: Dict[str, Tuple[ValidationReport, datetime.datetime]] = {}
        
        # Certificati CA di fiducia
        self.trusted_ca_certs: Dict[str, x509.Certificate] = {}
        
        # Statistiche operative
        self.stats = {
            'validations_performed': 0,
            'valid_credentials': 0,
            'invalid_credentials': 0,
            'cache_hits': 0,
            'signature_verifications': 0,
            'ocsp_checks': 0
        }
        
        # Carica certificati di fiducia
        self._load_trusted_ca_certificates()
        
        logger.info("Academic Credential Validator inizializzato")
        logger.info(f"CA di fiducia: {len(self.trusted_ca_certs)}")
        logger.info(f"OCSP abilitato: {self.config.ocsp_enabled}")
    
    def validate_credential(self, credential: AcademicCredential, 
                          validation_level: ValidationLevel = ValidationLevel.STANDARD) -> ValidationReport:
        """
        Valida una credenziale accademica al livello specificato.
        
        Args:
            credential: Credenziale da validare
            validation_level: Livello di validazione richiesto
            
        Returns:
            Report dettagliato della validazione
        """
        start_time = datetime.datetime.utcnow()
        credential_id = str(credential.metadata.credential_id)
        
        # Controlla cache se abilitata
        if self.config.cache_validation_results:
            cached_report = self._get_cached_validation(credential_id)
            if cached_report:
                self.stats['cache_hits'] += 1
                logger.debug(f"Validazione da cache: {credential_id[:8]}...")
                return cached_report
        
        logger.info(f"Validando credenziale: {credential_id[:8]}... (livello: {validation_level.value})")
        
        # Inizializza report
        report = ValidationReport(
            credential_id=credential_id,
            validation_level=validation_level,
            overall_result=ValidationResult.UNKNOWN,
            timestamp=start_time
        )
        
        try:
            # Validazioni base
            logger.debug("Validazione formato")
            self._validate_format(credential, report)
            
            logger.debug("Validazione temporale")
            self._validate_temporal(credential, report)
            
            logger.debug("Validazione Merkle Tree")
            self._validate_merkle_tree(credential, report)
            
            # Validazioni avanzate
            if validation_level in [ValidationLevel.STANDARD, ValidationLevel.COMPLETE, ValidationLevel.FORENSIC]:
                logger.debug("Validazione firma digitale")
                self._validate_signature(credential, report)
                
                logger.debug("Validazione certificato")
                self._validate_certificate(credential, report)
            
            # Validazioni complete
            if validation_level in [ValidationLevel.COMPLETE, ValidationLevel.FORENSIC]:
                logger.debug("Verifica revoca")
                self._validate_revocation_status(credential, report)
            
            # Validazioni forensi
            if validation_level == ValidationLevel.FORENSIC:
                logger.debug("Analisi forense")
                self._validate_forensic(credential, report)
            
            # Determina risultato finale
            self._determine_overall_result(report)
            
            # Aggiorna statistiche
            self.stats['validations_performed'] += 1
            if report.is_valid():
                self.stats['valid_credentials'] += 1
            else:
                self.stats['invalid_credentials'] += 1
            
            # Calcola durata e aggiorna report
            duration = (datetime.datetime.utcnow() - start_time).total_seconds() * 1000
            report.validation_duration_ms = duration
            
            # Cache risultato se abilitato
            if self.config.cache_validation_results:
                self._cache_validation_result(credential_id, report)
            
            # Log risultato
            result_icon = "✅" if report.is_valid() else "❌"
            logger.info(f"{result_icon} Validazione completata: {report.overall_result.value} ({duration:.2f}ms)")
            
            if report.has_errors():
                logger.debug(f"Errori: {len(report.errors)}")
            if report.has_warnings():
                logger.debug(f"Warning: {len(report.warnings)}")
            
            return report
            
        except Exception as e:
            logger.error(f"Errore durante validazione: {e}")
            report.add_error("VALIDATION_EXCEPTION", f"Errore durante validazione: {e}")
            report.overall_result = ValidationResult.INVALID
            return report
    
    def validate_selective_disclosure(self, 
                                    disclosed_courses: List[Course],
                                    merkle_proofs: List[List[Dict[str, Any]]],
                                    original_merkle_root: str) -> ValidationReport:
        """
        Valida una presentazione con divulgazione selettiva.
        
        Args:
            disclosed_courses: Corsi divulgati nella presentazione
            merkle_proofs: Prove Merkle per ogni corso divulgato
            original_merkle_root: Radice Merkle originale della credenziale
            
        Returns:
            Report di validazione della divulgazione selettiva
        """
        start_time = datetime.datetime.utcnow()
        
        report = ValidationReport(
            credential_id="selective_disclosure",
            validation_level=ValidationLevel.STANDARD,
            overall_result=ValidationResult.UNKNOWN,
            timestamp=start_time
        )
        
        try:
            logger.info(f"Validando divulgazione selettiva: {len(disclosed_courses)} corsi")
            
            # Verifica coerenza numero corsi e prove
            if len(disclosed_courses) != len(merkle_proofs):
                report.add_error("PROOF_COUNT_MISMATCH", 
                               "Numero di corsi e prove Merkle non corrispondente")
                report.overall_result = ValidationResult.INVALID
                return report
            
            # Valida ogni proof Merkle
            all_proofs_valid = True
            
            for i, (course, proof) in enumerate(zip(disclosed_courses, merkle_proofs)):
                logger.debug(f"Validando proof {i+1}/{len(disclosed_courses)}: {course.course_name}")
                
                course_data = course.model_dump()
                
                try:
                    is_valid = self._verify_merkle_proof(course_data, proof, original_merkle_root)
                    
                    if not is_valid:
                        report.add_error("INVALID_MERKLE_PROOF", 
                                       f"Proof non valida per corso {course.course_name}",
                                       field=f"courses[{i}]")
                        all_proofs_valid = False
                    else:
                        report.add_info("MERKLE_PROOF_VALID", 
                                      f"Proof valida per corso {course.course_name}")
                        
                except Exception as e:
                    report.add_error("MERKLE_PROOF_ERROR", 
                                   f"Errore validazione proof corso {course.course_name}: {e}")
                    all_proofs_valid = False
            
            # Determina risultato finale
            if all_proofs_valid:
                report.overall_result = ValidationResult.VALID
                report.merkle_tree_valid = True
                logger.info("Divulgazione selettiva VALIDA")
            else:
                report.overall_result = ValidationResult.INVALID
                logger.info("Divulgazione selettiva NON VALIDA")
            
            return report
            
        except Exception as e:
            logger.error(f"Errore validazione divulgazione selettiva: {e}")
            report.add_error("SELECTIVE_DISCLOSURE_ERROR", f"Errore validazione: {e}")
            report.overall_result = ValidationResult.INVALID
            return report
    
    def validate_batch_credentials(self, credentials: List[AcademicCredential],
                                 validation_level: ValidationLevel = ValidationLevel.STANDARD) -> List[ValidationReport]:
        """
        Valida un batch di credenziali.
        
        Args:
            credentials: Lista delle credenziali da validare
            validation_level: Livello di validazione da applicare
            
        Returns:
            Lista dei report di validazione
        """
        logger.info(f"Validazione batch: {len(credentials)} credenziali")
        
        reports = []
        
        for i, credential in enumerate(credentials):
            logger.debug(f"Validando {i+1}/{len(credentials)}")
            report = self.validate_credential(credential, validation_level)
            reports.append(report)
        
        # Statistiche batch
        valid_count = sum(1 for r in reports if r.is_valid())
        invalid_count = len(reports) - valid_count
        
        logger.info(f"Batch completato: {valid_count} valide, {invalid_count} non valide")
        
        return reports
    
    def _validate_format(self, credential: AcademicCredential, report: ValidationReport) -> None:
        """Valida il formato base della credenziale."""
        try:
            # Usa il metodo is_valid della credenziale
            is_valid, errors = credential.is_valid()
            
            if is_valid:
                report.format_valid = True
                report.add_info("FORMAT_VALID", "Formato credenziale valido")
            else:
                report.format_valid = False
                for error in errors:
                    report.add_error("FORMAT_ERROR", error)
            
            # Verifiche aggiuntive
            if not credential.courses:
                report.add_error("MISSING_COURSES", "Nessun corso presente nella credenziale")
            
            if credential.total_ects_credits <= 0:
                report.add_error("INVALID_ECTS", "Crediti ECTS non validi")
            
            # Verifica metadati essenziali
            if not credential.metadata.credential_id:
                report.add_error("MISSING_CREDENTIAL_ID", "ID credenziale mancante")
            
            if not credential.metadata.merkle_root:
                report.add_error("MISSING_MERKLE_ROOT", "Merkle root mancante")
                
        except Exception as e:
            report.add_error("FORMAT_VALIDATION_ERROR", f"Errore validazione formato: {e}")
    
    def _validate_temporal(self, credential: AcademicCredential, report: ValidationReport) -> None:
        """Valida gli aspetti temporali della credenziale."""
        try:
            now = datetime.datetime.now(datetime.timezone.utc)
            
            # Verifica scadenza
            if credential.metadata.expires_at:
                if now > credential.metadata.expires_at:
                    report.add_error("CREDENTIAL_EXPIRED", 
                                   f"Credenziale scaduta il {credential.metadata.expires_at}")
                    return
            
            # Verifica data emissione non nel futuro
            if credential.metadata.issued_at > now:
                report.add_error("FUTURE_ISSUANCE", "Data emissione nel futuro")
                return
            
            # Verifica coerenza periodo di studio
            if credential.study_period.start_date >= credential.study_period.end_date:
                report.add_error("INVALID_STUDY_PERIOD", "Periodo di studio non valido")
            
            report.temporal_valid = True
            report.add_info("TEMPORAL_VALID", "Validazione temporale superata")
            
        except Exception as e:
            report.add_error("TEMPORAL_VALIDATION_ERROR", f"Errore validazione temporale: {e}")
                
    def _validate_merkle_tree(self, credential: AcademicCredential, report: ValidationReport) -> None:
        """Valida l'integrità del Merkle Tree."""
        try:
            # Calcola merkle root dai corsi attuali
            calculated_root = credential.calculate_merkle_root()
            stored_root = credential.metadata.merkle_root
            
            if calculated_root == stored_root:
                report.merkle_tree_valid = True
                report.add_info("MERKLE_TREE_VALID", "Merkle Tree valido")
            else:
                report.merkle_tree_valid = False
                
                if self.config.strict_merkle_validation:
                    report.add_error("MERKLE_TREE_MISMATCH", 
                                   "Merkle root calcolata non corrisponde a quella memorizzata",
                                   details={
                                       'calculated': calculated_root,
                                       'stored': stored_root
                                   })
                else:
                    report.add_warning("MERKLE_TREE_MISMATCH", 
                                     "Merkle root calcolata non corrisponde (non critico)")
                    
        except Exception as e:
            report.add_error("MERKLE_VALIDATION_ERROR", f"Errore validazione Merkle Tree: {e}")
    
    def _validate_signature(self, credential: AcademicCredential, report: ValidationReport) -> None:
        """Valida la firma digitale della credenziale."""
        try:
            if not credential.signature:
                report.add_error("MISSING_SIGNATURE", "Firma digitale mancante")
                return
            
            self.stats['signature_verifications'] += 1
            
            # Trova certificato issuer
            issuer_cert = self._find_issuer_certificate(credential)
            if not issuer_cert:
                report.add_error("ISSUER_CERT_NOT_FOUND", 
                            f"Certificato issuer non trovato per {credential.issuer.name}")
                return
            
            # Estrae chiave pubblica
            try:
                issuer_public_key = self.cert_manager.extract_public_key(issuer_cert)
            except Exception as e:
                report.add_error("ISSUER_KEY_EXTRACTION_ERROR", 
                            f"Errore estrazione chiave pubblica: {e}")
                return
            
            # Prepara documento per verifica
            try:
                # Ricostruisce i dati firmati 
                signature_data = {
                    "credential_id": str(credential.metadata.credential_id),
                    "student_id": credential.subject.student_id_hash,
                    "issuer": credential.issuer.name,
                    "issue_date": credential.metadata.issued_at.isoformat(),
                    "courses": [c.course_name for c in credential.courses]
                }
                
                # Crea documento con firma per verifica
                document_with_signature = signature_data.copy()
                document_with_signature['firma'] = {
                    'algoritmo': credential.signature.algorithm,
                    'valore': credential.signature.value,
                    'timestamp': credential.signature.timestamp.isoformat()
                }
                
                is_valid = self.digital_signature.verify_document_signature(
                    issuer_public_key, document_with_signature
                )
                
                if is_valid:
                    report.signature_valid = True
                    report.add_info("SIGNATURE_VALID", "Firma digitale valida")
                else:
                    report.signature_valid = False
                    report.add_error("SIGNATURE_INVALID", "Firma digitale non valida")
                    
            except Exception as e:
                report.add_error("SIGNATURE_VERIFICATION_ERROR", 
                            f"Errore verifica firma: {e}")
                
        except Exception as e:
            report.add_error("SIGNATURE_VALIDATION_ERROR", f"Errore validazione firma: {e}")
        
    def _validate_certificate(self, credential: AcademicCredential, report: ValidationReport) -> None:
        """Valida il certificato dell'issuer."""
        try:
            # Trova certificato issuer
            issuer_cert = self._find_issuer_certificate(credential)
            if not issuer_cert:
                report.add_error("ISSUER_CERT_NOT_FOUND", "Certificato issuer non trovato")
                return
            
            # Verifica scadenza certificato
            cert_expiry_info = self.cert_manager.check_certificate_expiry(issuer_cert)
            
            if cert_expiry_info['is_expired']:
                report.add_error("ISSUER_CERT_EXPIRED", "Certificato issuer scaduto")
                return
            elif cert_expiry_info['expires_soon']:
                report.add_warning("ISSUER_CERT_EXPIRES_SOON", 
                                 f"Certificato issuer scade in {cert_expiry_info['days_until_expiry']} giorni")
            
            # Verifica catena di fiducia
            trust_validation = self._validate_certificate_trust_chain(issuer_cert)
            
            if trust_validation['valid']:
                report.certificate_valid = True
                report.add_info("CERTIFICATE_VALID", "Certificato issuer valido")
                report.trusted_issuers.append(credential.issuer.name)
            else:
                report.certificate_valid = False
                report.add_error("CERTIFICATE_TRUST_FAILED", 
                               "Certificato issuer non nella catena di fiducia")
                
        except Exception as e:
            report.add_error("CERTIFICATE_VALIDATION_ERROR", f"Errore validazione certificato: {e}")
    
    def _validate_revocation_status(self, credential: AcademicCredential, report: ValidationReport) -> None:
        """Valida lo stato di revoca della credenziale."""
        try:
            # Verifica stato locale
            if credential.status == CredentialStatus.REVOKED:
                report.add_error("CREDENTIAL_REVOKED", "Credenziale revocata localmente")
                report.revocation_status = "revoked"
                return
            
            # Verifica OCSP se abilitato
            if self.config.ocsp_enabled and self.ocsp_client:
                issuer_cert = self._find_issuer_certificate(credential)
                ca_cert = self.trusted_ca_certs.get("./certificates/ca/ca_certificate.pem")
                
                if issuer_cert and ca_cert:
                    try:
                        self.stats['ocsp_checks'] += 1
                        ocsp_response = self.ocsp_client.check_certificate_status(issuer_cert, ca_cert)

                        report.revocation_status = ocsp_response.status.value
                        if ocsp_response.status == OCSPStatus.GOOD:
                            report.add_info("OCSP_CHECK_PASSED", "Certificato issuer valido (OCSP)")
                        elif ocsp_response.status == OCSPStatus.REVOKED:
                            report.add_error("ISSUER_CERT_REVOKED", "Il certificato dell'issuer è stato revocato")
                        else:
                            report.add_warning("OCSP_CHECK_UNKNOWN", 
                                             f"Stato OCSP sconosciuto: {ocsp_response.error_message or 'N/A'}")

                    except Exception as e:
                        report.add_warning("OCSP_CHECK_FAILED", f"Errore verifica OCSP: {e}")
                        report.revocation_status = "unknown"
            else:
                report.revocation_status = "not_checked"
                report.add_info("REVOCATION_NOT_CHECKED", "Verifica revoca non eseguita")
                
        except Exception as e:
            report.add_error("REVOCATION_VALIDATION_ERROR", f"Errore verifica revoca: {e}")
    
    def _validate_forensic(self, credential: AcademicCredential, report: ValidationReport) -> None:
        """Esegue validazione forense avanzata."""
        try:
            # Analisi timestamp firma vs emissione
            if credential.signature:
                signature_time = credential.signature.timestamp
                issuance_time = credential.metadata.issued_at
                
                # Verifica che la firma sia ragionevolmente vicina all'emissione
                time_diff = abs((signature_time - issuance_time).total_seconds())
                
                if time_diff > 3600:  # 1 ora
                    report.add_warning("SIGNATURE_TIME_ANOMALY", 
                                     f"Differenza temporale firma-emissione: {time_diff/60:.1f} minuti")
            
            # Analisi statistica dei voti
            if len(credential.courses) > 0:
                grades = []
                for course in credential.courses:
                    if course.grade.passed:
                        try:
                            # Estrae voto numerico per analisi
                            if '/' in course.grade.score:
                                grade_num = float(course.grade.score.split('/')[0])
                                grades.append(grade_num)
                        except:
                            pass
                
                if grades:
                    avg_grade = sum(grades) / len(grades)
                    
                    # Flag per voti sospettosamente alti
                    if avg_grade > 29:  # Media molto alta nel sistema italiano
                        report.add_warning("SUSPICIOUS_HIGH_GRADES", 
                                         f"Media voti molto alta: {avg_grade:.1f}")
            
            # Verifica coerenza università
            if (credential.issuer.country == credential.host_university.country and
                credential.issuer.name != credential.host_university.name):
                report.add_info("DOMESTIC_EXCHANGE", "Scambio domestico rilevato")
            
            report.add_info("FORENSIC_ANALYSIS_COMPLETE", "Analisi forense completata")
            
        except Exception as e:
            report.add_error("FORENSIC_VALIDATION_ERROR", f"Errore analisi forense: {e}")
    
    def _determine_overall_result(self, report: ValidationReport) -> None:
        """Determina il risultato finale basato su tutti i controlli."""
        try:
            # Errori critici che invalidano sempre la credenziale
            critical_errors = [e for e in report.errors if e.code in [
                'CREDENTIAL_REVOKED', 'SIGNATURE_INVALID', 'ISSUER_CERT_EXPIRED',
                'MERKLE_TREE_MISMATCH', 'MISSING_SIGNATURE'
            ]]
            
            if critical_errors:
                report.overall_result = ValidationResult.INVALID
                return
            
            # Se ci sono errori non critici ma comunque importanti
            if report.has_errors():
                report.overall_result = ValidationResult.INVALID
                return
            
            # Se ci sono solo warning
            if report.has_warnings():
                report.overall_result = ValidationResult.WARNING
                return
            
            # Verifica che le validazioni base siano superate
            if (report.format_valid and 
                report.temporal_valid and 
                report.merkle_tree_valid):
                
                # Per validazioni avanzate, controlla anche firma e certificato
                if report.validation_level in [ValidationLevel.STANDARD, ValidationLevel.COMPLETE, ValidationLevel.FORENSIC]:
                    if report.signature_valid and report.certificate_valid:
                        report.overall_result = ValidationResult.VALID
                    else:
                        report.overall_result = ValidationResult.INVALID
                else:
                    report.overall_result = ValidationResult.VALID
            else:
                report.overall_result = ValidationResult.INVALID
                
        except Exception as e:
            report.add_error("RESULT_DETERMINATION_ERROR", f"Errore determinazione risultato: {e}")
            report.overall_result = ValidationResult.INVALID
    
    def _find_issuer_certificate(self, credential: AcademicCredential) -> Optional[x509.Certificate]:
        """Trova il certificato dell'issuer della credenziale."""
        try:
            # Cerca prima per thumbprint se disponibile
            if credential.signature and credential.signature.signer_certificate_thumbprint:
                thumbprint = credential.signature.signer_certificate_thumbprint
                
                for cert in self.trusted_ca_certs.values():
                    cert_der = cert.public_bytes(serialization.Encoding.DER)
                    cert_thumbprint = self.crypto_utils.sha256_hash(cert_der)
                    
                    if cert_thumbprint == thumbprint:
                        return cert
            
            # Cerca per nome università
            issuer_name = credential.issuer.name.lower()
            
            # Mapping specifico per le università demo
            university_mappings = {
                "université de rennes": ["rennes", "universite_rennes"],
                "università degli studi di salerno": ["salerno", "unisa"],
                "università di salerno": ["salerno", "unisa"]
            }
            
            search_terms = [issuer_name]
            for uni_name, aliases in university_mappings.items():
                if issuer_name in uni_name or uni_name in issuer_name:
                    search_terms.extend(aliases)
            
            # Cerca nei certificati caricati
            for cert_path, cert in self.trusted_ca_certs.items():
                try:
                    cert_org = self.cert_manager._get_organization(cert).lower()
                    cert_common_name = self.cert_manager._get_common_name(cert).lower()
                    
                    # Controlla se qualche termine di ricerca corrisponde
                    for term in search_terms:
                        if (term in cert_org or term in cert_common_name or 
                            term in cert_path.lower()):
                            logger.debug(f"Certificato issuer trovato: {cert_path}")
                            return cert
                            
                except Exception as e:
                    logger.warning(f"Errore analisi certificato {cert_path}: {e}")
                    continue
            
            # Cerca direttamente nei file se non trovato
            possible_cert_paths = [
                "./certificates/issued/university_F_RENNES01_1001.pem",
                "./certificates/issued/university_I_SALERNO_2001.pem",
                "certificates/issued/university_F_RENNES01_1001.pem",
                "certificates/issued/university_I_SALERNO_2001.pem"
            ]
            
            for cert_path in possible_cert_paths:
                try:
                    if Path(cert_path).exists():
                        cert = self.cert_manager.load_certificate_from_file(cert_path)
                        cert_org = self.cert_manager._get_organization(cert).lower()
                        
                        for term in search_terms:
                            if term in cert_org or term in cert_path.lower():
                                logger.debug(f"Certificato trovato da fallback: {cert_path}")
                                # Aggiunge alla cache per uso futuro
                                self.trusted_ca_certs[cert_path] = cert
                                return cert
                except Exception:
                    continue
            
            logger.warning(f"Certificato issuer non trovato per: {credential.issuer.name}")
            return None
            
        except Exception as e:
            logger.warning(f"Errore ricerca certificato issuer: {e}")
            return None
        
    def _validate_certificate_trust_chain(self, certificate: x509.Certificate) -> Dict[str, Any]:
        """Valida la catena di fiducia del certificato."""
        try:
            
            for ca_cert in self.trusted_ca_certs.values():
                try:
                    ca_public_key = ca_cert.public_key()
                    ca_public_key.verify(
                        certificate.signature,
                        certificate.tbs_certificate_bytes,
                        certificate.signature_hash_algorithm
                    )
                    
                    return {'valid': True, 'ca_name': self.cert_manager._get_common_name(ca_cert)}
                    
                except InvalidSignature:
                    continue
                except Exception:
                    continue
            
            return {'valid': False, 'error': 'Nessuna CA di fiducia trovata'}
            
        except Exception as e:
            return {'valid': False, 'error': f'Errore validazione trust chain: {e}'}
    
    def _verify_merkle_proof(self, data: Dict, proof: List[Dict], root: str) -> bool:
        """
        Verifica una prova Merkle per un dato specifico.
        
        Args:
            data: Dati del corso da verificare
            proof: Prova Merkle fornita
            root: Radice Merkle attesa
            
        Returns:
            True se la prova è valida
        """
        try:
            # Hash del dato originale
            current_hash = self.crypto_utils.sha256_hash_string(json.dumps(data, sort_keys=True))
            
            # Ricostruisce il percorso verso la radice
            for step in proof:
                sibling_hash = step.get('hash')
                is_right_sibling = step.get('is_right', False)
                
                if not sibling_hash:
                    continue  # Salta step non validi

                if is_right_sibling:
                    # Il sibling è a destra, quindi il nostro hash è a sinistra
                    combined = current_hash + sibling_hash
                else:
                    # Il sibling è a sinistra
                    combined = sibling_hash + current_hash
                
                current_hash = self.crypto_utils.sha256_hash_string(combined)
            
            # Confronta la radice calcolata con quella attesa
            return current_hash == root

        except Exception as e:
            logger.warning(f"Errore verifica Merkle proof: {e}")
            return False

    def _load_trusted_ca_certificates(self) -> None:
        """Carica i certificati CA di fiducia."""
        try:
            # Carica certificati specificati nella configurazione
            for cert_path in self.config.trusted_ca_certificates:
                if Path(cert_path).exists():
                    cert = self.cert_manager.load_certificate_from_file(cert_path)
                    self.trusted_ca_certs[cert_path] = cert
                    logger.debug(f"CA di fiducia caricata: {Path(cert_path).name}")
                else:
                    logger.warning(f"CA non trovata: {cert_path}")
            
            # Carica automaticamente certificati se esistenti
            demo_cert_paths = [
                "./certificates/ca/ca_certificate.pem",
                "./certificates/issued/university_FR_RENNES01_1001.pem", 
                "./certificates/issued/university_IT_SALERNO_2001.pem",
                "certificates/ca/ca_certificate.pem",
                "certificates/issued/university_FR_RENNES01_1001.pem",
                "certificates/issued/university_IT_SALERNO_2001.pem"
            ]
            
            for cert_path in demo_cert_paths:
                try:
                    if Path(cert_path).exists() and cert_path not in self.trusted_ca_certs:
                        cert = self.cert_manager.load_certificate_from_file(cert_path)
                        self.trusted_ca_certs[cert_path] = cert
                        logger.debug(f"Certificato caricato: {Path(cert_path).name}")
                except Exception as e:
                    logger.warning(f"Errore caricamento {cert_path}: {e}")
                    continue
                    
            logger.info(f"Totale certificati caricati: {len(self.trusted_ca_certs)}")
                    
        except Exception as e:
            logger.warning(f"Errore caricamento CA: {e}")

    def _get_cached_validation(self, credential_id: str) -> Optional[ValidationReport]:
        """Ottiene un risultato di validazione dalla cache se valido."""
        if credential_id not in self.validation_cache:
            return None
        
        report, cached_time = self.validation_cache[credential_id]
        
        # Verifica se la cache è ancora valida
        cache_age = datetime.datetime.utcnow() - cached_time
        max_age = datetime.timedelta(minutes=self.config.cache_duration_minutes)
        
        if cache_age > max_age:
            del self.validation_cache[credential_id]
            return None
        
        return report
    
    def _cache_validation_result(self, credential_id: str, report: ValidationReport) -> None:
        """Salva un risultato di validazione nella cache."""
        self.validation_cache[credential_id] = (report, datetime.datetime.utcnow())
        
        # Pulisce la cache se troppo grande
        if len(self.validation_cache) > 1000:
            # Rimuove il 20% delle entry più vecchie
            sorted_cache = sorted(
                self.validation_cache.items(),
                key=lambda x: x[1][1]  # Ordina per timestamp
            )
            
            entries_to_remove = len(sorted_cache) // 5
            for credential_id, _ in sorted_cache[:entries_to_remove]:
                del self.validation_cache[credential_id]
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Ottiene le statistiche operative del validator.
        
        Returns:
            Dizionario con statistiche dettagliate
        """
        cache_hit_rate = 0
        if self.stats['validations_performed'] > 0:
            cache_hit_rate = (self.stats['cache_hits'] / self.stats['validations_performed']) * 100
        
        return {
            **self.stats,
            'cache_size': len(self.validation_cache),
            'trusted_cas': len(self.trusted_ca_certs),
            'cache_hit_rate': cache_hit_rate
        }
    
    def clear_cache(self) -> None:
        """Pulisce la cache delle validazioni."""
        cache_size = len(self.validation_cache)
        self.validation_cache.clear()
        logger.info(f"Cache validazioni pulita ({cache_size} entries)")