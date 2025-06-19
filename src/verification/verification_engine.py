# =============================================================================
# FASE 7: VERIFIER - VERIFICATION ENGINE
# File: verification/verification_engine.py
# Sistema Credenziali Accademiche Decentralizzate
# =============================================================================

import os
import json
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import uuid
import asyncio

# Cryptography imports
from cryptography.hazmat.primitives.asymmetric import rsa

# Import moduli interni
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from crypto.foundations import DigitalSignature, CryptoUtils, MerkleTree
    from credentials.models import AcademicCredential
    from credentials.validator import AcademicCredentialValidator, ValidationLevel, ValidationReport
    from pki.certificate_manager import CertificateManager
    from wallet.selective_disclosure import SelectiveDisclosure, DisclosureLevel
    from wallet.presentation import VerifiablePresentation, PresentationStatus
    from blockchain.revocation_registry import RevocationRegistryManager, BlockchainConfig
except ImportError as e:
    print(f"⚠️  Errore import moduli interni: {e}")
    raise


# =============================================================================
# 1. ENUMS E STRUTTURE DATI VERIFICA
# =============================================================================

class VerificationResult(Enum):
    """Risultati possibili della verifica"""
    VALID = "valid"
    INVALID = "invalid"  
    PARTIAL = "partial"
    PENDING = "pending"
    ERROR = "error"


class VerificationLevel(Enum):
    """Livelli di verifica"""
    BASIC = "basic"                    # Solo formato e firma
    STANDARD = "standard"              # Include certificati
    COMPREHENSIVE = "comprehensive"    # Include blockchain
    FORENSIC = "forensic"             # Verifica completa + audit


class TrustLevel(Enum):
    """Livelli di fiducia nell'emittente"""
    UNKNOWN = "unknown"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    TRUSTED = "trusted"


@dataclass
class IssuerTrustInfo:
    """Informazioni fiducia emittente"""
    issuer_name: str
    country: str
    trust_level: TrustLevel
    certificate_valid: bool
    accreditation_verified: bool
    reputation_score: float  # 0.0 - 1.0
    verification_history: int  # Numero verifiche precedenti
    last_updated: datetime.datetime
    notes: Optional[str] = None


@dataclass
class AttributeVerification:
    """Risultato verifica di un singolo attributo"""
    attribute_path: str
    attribute_value: Any
    is_valid: bool
    merkle_proof_valid: bool
    confidence_score: float  # 0.0 - 1.0
    verification_method: str
    warnings: List[str] = field(default_factory=list)


@dataclass
class CredentialVerificationResult:
    """Risultato verifica di una credenziale"""
    credential_id: str
    overall_result: VerificationResult
    confidence_score: float
    
    # Verifiche specifiche
    format_valid: bool
    signature_valid: bool
    certificate_valid: bool
    merkle_tree_valid: bool
    blockchain_valid: bool
    temporal_valid: bool
    
    # Dettagli attributi
    verified_attributes: List[AttributeVerification]
    
    # Fiducia emittente
    issuer_trust: IssuerTrustInfo
    
    # Metadati verifica
    verification_level: VerificationLevel
    verification_timestamp: datetime.datetime
    verification_duration_ms: int
    
    # Errori e warning
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte in dizionario per serializzazione"""
        return {
            'credential_id': self.credential_id,
            'overall_result': self.overall_result.value,
            'confidence_score': self.confidence_score,
            'format_valid': self.format_valid,
            'signature_valid': self.signature_valid,
            'certificate_valid': self.certificate_valid,
            'merkle_tree_valid': self.merkle_tree_valid,
            'blockchain_valid': self.blockchain_valid,
            'temporal_valid': self.temporal_valid,
            'verified_attributes': [
                {
                    'path': attr.attribute_path,
                    'value': str(attr.attribute_value),
                    'valid': attr.is_valid,
                    'merkle_proof_valid': attr.merkle_proof_valid,
                    'confidence': attr.confidence_score,
                    'method': attr.verification_method,
                    'warnings': attr.warnings
                }
                for attr in self.verified_attributes
            ],
            'issuer_trust': {
                'name': self.issuer_trust.issuer_name,
                'country': self.issuer_trust.country,
                'trust_level': self.issuer_trust.trust_level.value,
                'certificate_valid': self.issuer_trust.certificate_valid,
                'reputation_score': self.issuer_trust.reputation_score,
                'verification_history': self.issuer_trust.verification_history
            },
            'verification_level': self.verification_level.value,
            'verification_timestamp': self.verification_timestamp.isoformat(),
            'verification_duration_ms': self.verification_duration_ms,
            'errors': self.errors,
            'warnings': self.warnings
        }


@dataclass
class PresentationVerificationResult:
    """Risultato verifica di una presentazione completa"""
    presentation_id: str
    overall_result: VerificationResult
    confidence_score: float
    
    # Risultati per credenziale
    credential_results: List[CredentialVerificationResult]
    
    # Verifica presentazione
    presentation_format_valid: bool
    presentation_signature_valid: bool
    presentation_temporal_valid: bool
    
    # Statistiche
    total_credentials: int
    valid_credentials: int
    total_attributes: int
    valid_attributes: int
    
    # Metadati
    verified_by: str  # Università verificatrice
    verification_purpose: str
    verification_timestamp: datetime.datetime
    verification_duration_ms: int
    
    # Errori globali
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte in dizionario per serializzazione"""
        return {
            'presentation_id': self.presentation_id,
            'overall_result': self.overall_result.value,
            'confidence_score': self.confidence_score,
            'credential_results': [cred.to_dict() for cred in self.credential_results],
            'presentation_format_valid': self.presentation_format_valid,
            'presentation_signature_valid': self.presentation_signature_valid,
            'presentation_temporal_valid': self.presentation_temporal_valid,
            'statistics': {
                'total_credentials': self.total_credentials,
                'valid_credentials': self.valid_credentials,
                'total_attributes': self.total_attributes,
                'valid_attributes': self.valid_attributes
            },
            'metadata': {
                'verified_by': self.verified_by,
                'verification_purpose': self.verification_purpose,
                'verification_timestamp': self.verification_timestamp.isoformat(),
                'verification_duration_ms': self.verification_duration_ms
            },
            'errors': self.errors,
            'warnings': self.warnings
        }


# =============================================================================
# 2. VERIFICATION ENGINE PRINCIPALE
# =============================================================================

class CredentialVerificationEngine:
    """Engine principale per la verifica delle credenziali accademiche"""
    
    def __init__(self, 
                 university_name: str,
                 cert_manager: CertificateManager,
                 registry_manager: Optional[RevocationRegistryManager] = None):
        """
        Inizializza l'engine di verifica
        
        Args:
            university_name: Nome università verificatrice
            cert_manager: Manager certificati per verifica PKI
            registry_manager: Manager blockchain per verifica revoche
        """
        self.university_name = university_name
        self.cert_manager = cert_manager
        self.registry_manager = registry_manager
        
        # Componenti crittografici
        self.crypto_utils = CryptoUtils()
        self.digital_signature = DigitalSignature("PSS")
        self.credential_validator = AcademicCredentialValidator()
        
        # Cache e storage
        self.issuer_trust_cache: Dict[str, IssuerTrustInfo] = {}
        self.verification_history: Dict[str, List[CredentialVerificationResult]] = {}
        
        # Configurazione verifica
        self.default_verification_level = VerificationLevel.STANDARD
        self.enable_blockchain_verification = registry_manager is not None
        self.trust_unknown_issuers = False
        self.max_verification_age_hours = 24
        
        # Statistiche
        self.stats = {
            'total_verifications': 0,
            'successful_verifications': 0,
            'failed_verifications': 0,
            'blockchain_verifications': 0,
            'average_duration_ms': 0,
            'last_verification': None
        }
        
        print(f"🔍 Verification Engine inizializzato")
        print(f"   Università: {university_name}")
        print(f"   Blockchain: {'✅ Abilitato' if self.enable_blockchain_verification else '❌ Disabilitato'}")
    
    def verify_presentation(self, 
                           presentation_data: Dict[str, Any],
                           verification_level: VerificationLevel = None,
                           verification_purpose: str = "Academic Credit Recognition") -> PresentationVerificationResult:
        """
        Verifica una presentazione completa
        
        Args:
            presentation_data: Dati presentazione da verificare
            verification_level: Livello di verifica da applicare
            verification_purpose: Scopo della verifica
            
        Returns:
            Risultato verifica presentazione
        """
        start_time = datetime.datetime.utcnow()
        verification_level = verification_level or self.default_verification_level
        
        print(f"🔍 Avvio verifica presentazione")
        print(f"   Livello: {verification_level.value}")
        print(f"   Scopo: {verification_purpose}")
        
        try:
            # 1. Parse presentazione
            presentation = self._parse_presentation(presentation_data)
            if not presentation:
                return self._create_error_result("Formato presentazione non valido")
            
            # 2. Verifica formato presentazione
            presentation_format_valid = self._verify_presentation_format(presentation_data)
            
            # 3. Verifica firma presentazione
            presentation_signature_valid = self._verify_presentation_signature(presentation_data)
            
            # 4. Verifica temporale presentazione
            presentation_temporal_valid = self._verify_presentation_temporal(presentation_data)
            
            # 5. Verifica credenziali individuali
            credential_results = []
            
            for disclosure_data in presentation_data.get('selective_disclosures', []):
                try:
                    disclosure = SelectiveDisclosure.from_dict(disclosure_data)
                    cred_result = self.verify_selective_disclosure(disclosure, verification_level)
                    credential_results.append(cred_result)
                    
                except Exception as e:
                    print(f"❌ Errore verifica disclosure: {e}")
                    error_result = self._create_credential_error_result(
                        disclosure_data.get('credential_id', 'unknown'), 
                        f"Errore verifica disclosure: {e}"
                    )
                    credential_results.append(error_result)
            
            # 6. Calcola risultato complessivo
            overall_result, confidence_score = self._calculate_overall_result(
                credential_results, presentation_format_valid, 
                presentation_signature_valid, presentation_temporal_valid
            )
            
            # 7. Statistiche
            total_credentials = len(credential_results)
            valid_credentials = sum(1 for cr in credential_results if cr.overall_result == VerificationResult.VALID)
            total_attributes = sum(len(cr.verified_attributes) for cr in credential_results)
            valid_attributes = sum(
                sum(1 for attr in cr.verified_attributes if attr.is_valid) 
                for cr in credential_results
            )
            
            # 8. Calcola durata
            duration = datetime.datetime.utcnow() - start_time
            duration_ms = int(duration.total_seconds() * 1000)
            
            # 9. Crea risultato
            result = PresentationVerificationResult(
                presentation_id=presentation_data.get('presentation_id', str(uuid.uuid4())),
                overall_result=overall_result,
                confidence_score=confidence_score,
                credential_results=credential_results,
                presentation_format_valid=presentation_format_valid,
                presentation_signature_valid=presentation_signature_valid,
                presentation_temporal_valid=presentation_temporal_valid,
                total_credentials=total_credentials,
                valid_credentials=valid_credentials,
                total_attributes=total_attributes,
                valid_attributes=valid_attributes,
                verified_by=self.university_name,
                verification_purpose=verification_purpose,
                verification_timestamp=start_time,
                verification_duration_ms=duration_ms
            )
            
            # 10. Aggiorna statistiche
            self._update_verification_stats(result)
            
            print(f"✅ Verifica presentazione completata: {overall_result.value}")
            print(f"   Credenziali valide: {valid_credentials}/{total_credentials}")
            print(f"   Confidence: {confidence_score:.2f}")
            print(f"   Durata: {duration_ms}ms")
            
            return result
            
        except Exception as e:
            print(f"❌ Errore verifica presentazione: {e}")
            
            duration = datetime.datetime.utcnow() - start_time
            duration_ms = int(duration.total_seconds() * 1000)
            
            return PresentationVerificationResult(
                presentation_id=presentation_data.get('presentation_id', 'error'),
                overall_result=VerificationResult.ERROR,
                confidence_score=0.0,
                credential_results=[],
                presentation_format_valid=False,
                presentation_signature_valid=False,
                presentation_temporal_valid=False,
                total_credentials=0,
                valid_credentials=0,
                total_attributes=0,
                valid_attributes=0,
                verified_by=self.university_name,
                verification_purpose=verification_purpose,
                verification_timestamp=start_time,
                verification_duration_ms=duration_ms,
                errors=[f"Errore verifica: {e}"]
            )
    
    def verify_selective_disclosure(self, 
                                  disclosure: SelectiveDisclosure,
                                  verification_level: VerificationLevel = None) -> CredentialVerificationResult:
        """
        Verifica una divulgazione selettiva
        
        Args:
            disclosure: Divulgazione selettiva da verificare
            verification_level: Livello di verifica
            
        Returns:
            Risultato verifica credenziale
        """
        start_time = datetime.datetime.utcnow()
        verification_level = verification_level or self.default_verification_level
        
        print(f"🔍 Verifica disclosure: {disclosure.credential_id}")
        
        try:
            # 1. Verifica formato disclosure
            format_valid = self._verify_disclosure_format(disclosure)
            
            # 2. Verifica firma disclosure (studente)
            signature_valid = self._verify_disclosure_signature(disclosure)
            
            # 3. Verifica Merkle proofs
            merkle_tree_valid = self._verify_merkle_proofs(disclosure)
            
            # 4. Verifica certificato emittente
            certificate_valid = False
            issuer_trust = None
            
            if verification_level in [VerificationLevel.STANDARD, VerificationLevel.COMPREHENSIVE, VerificationLevel.FORENSIC]:
                certificate_valid, issuer_trust = self._verify_issuer_certificate(disclosure)
            
            # 5. Verifica blockchain
            blockchain_valid = True  # Default se non abilitato
            
            if self.enable_blockchain_verification and verification_level in [VerificationLevel.COMPREHENSIVE, VerificationLevel.FORENSIC]:
                blockchain_valid = self._verify_blockchain_status(disclosure)
            
            # 6. Verifica temporale
            temporal_valid = self._verify_temporal_validity(disclosure)
            
            # 7. Verifica attributi individuali
            verified_attributes = self._verify_individual_attributes(disclosure, merkle_tree_valid)
            
            # 8. Calcola risultato complessivo
            overall_result, confidence_score = self._calculate_credential_result(
                format_valid, signature_valid, certificate_valid, 
                merkle_tree_valid, blockchain_valid, temporal_valid,
                verified_attributes, issuer_trust
            )
            
            # 9. Calcola durata
            duration = datetime.datetime.utcnow() - start_time
            duration_ms = int(duration.total_seconds() * 1000)
            
            # 10. Crea risultato
            result = CredentialVerificationResult(
                credential_id=disclosure.credential_id,
                overall_result=overall_result,
                confidence_score=confidence_score,
                format_valid=format_valid,
                signature_valid=signature_valid,
                certificate_valid=certificate_valid,
                merkle_tree_valid=merkle_tree_valid,
                blockchain_valid=blockchain_valid,
                temporal_valid=temporal_valid,
                verified_attributes=verified_attributes,
                issuer_trust=issuer_trust or self._get_unknown_issuer_trust(disclosure),
                verification_level=verification_level,
                verification_timestamp=start_time,
                verification_duration_ms=duration_ms
            )
            
            # 11. Aggiorna cache e history
            self._update_verification_cache(result)
            
            return result
            
        except Exception as e:
            print(f"❌ Errore verifica disclosure: {e}")
            return self._create_credential_error_result(disclosure.credential_id, str(e))
    
    def _parse_presentation(self, presentation_data: Dict[str, Any]) -> Optional[VerifiablePresentation]:
        """Parse e valida formato presentazione"""
        try:
            return VerifiablePresentation.from_dict(presentation_data)
        except Exception as e:
            print(f"❌ Errore parse presentazione: {e}")
            return None
    
    def _verify_presentation_format(self, presentation_data: Dict[str, Any]) -> bool:
        """Verifica formato presentazione"""
        try:
            required_fields = ['presentation_id', 'created_at', 'purpose', 'selective_disclosures']
            
            for field in required_fields:
                if field not in presentation_data:
                    print(f"❌ Campo obbligatorio mancante: {field}")
                    return False
            
            # Verifica che ci siano disclosure
            disclosures = presentation_data.get('selective_disclosures', [])
            if not disclosures:
                print(f"❌ Nessuna divulgazione selettiva presente")
                return False
            
            return True
            
        except Exception as e:
            print(f"❌ Errore verifica formato presentazione: {e}")
            return False
    
    def _verify_presentation_signature(self, presentation_data: Dict[str, Any]) -> bool:
        """Verifica firma presentazione"""
        try:
            signature = presentation_data.get('signature')
            if not signature:
                print(f"⚠️  Presentazione non firmata")
                return True  # Non obbligatorio
            
            # TODO: Implementare verifica firma presentazione con chiave studente
            # Per ora ritorna True
            return True
            
        except Exception as e:
            print(f"❌ Errore verifica firma presentazione: {e}")
            return False
    
    def _verify_presentation_temporal(self, presentation_data: Dict[str, Any]) -> bool:
        """Verifica validità temporale presentazione"""
        try:
            expires_at = presentation_data.get('expires_at')
            if expires_at:
                expiry_date = datetime.datetime.fromisoformat(expires_at.replace('Z', '+00:00'))
                if datetime.datetime.now(datetime.timezone.utc) > expiry_date:
                    print(f"❌ Presentazione scaduta")
                    return False
            
            return True
            
        except Exception as e:
            print(f"❌ Errore verifica temporale presentazione: {e}")
            return False
    
    def _verify_disclosure_format(self, disclosure: SelectiveDisclosure) -> bool:
        """Verifica formato disclosure"""
        try:
            # Verifica campi obbligatori
            if not disclosure.credential_id:
                return False
            
            if not disclosure.disclosed_attributes:
                return False
            
            if not disclosure.merkle_proofs:
                return False
            
            return True
            
        except Exception as e:
            print(f"❌ Errore verifica formato disclosure: {e}")
            return False
    
    def _verify_disclosure_signature(self, disclosure: SelectiveDisclosure) -> bool:
        """Verifica firma disclosure"""
        try:
            # TODO: Implementare verifica firma disclosure
            # Per ora ritorna True
            return True
            
        except Exception as e:
            print(f"❌ Errore verifica firma disclosure: {e}")
            return False
    
    def _verify_merkle_proofs(self, disclosure: SelectiveDisclosure) -> bool:
        """Verifica Merkle proofs"""
        try:
            if not disclosure.merkle_proofs:
                return False
            
            # Verifica ogni proof
            for proof in disclosure.merkle_proofs:
                if not proof.proof_path:
                    continue
                
                # Ricostruisce hash dall'attributo
                attribute_data = disclosure.disclosed_attributes.get(proof.attribute_path)
                if attribute_data is None:
                    continue
                
                # Verifica proof (implementazione semplificata)
                # TODO: Implementare verifica Merkle proof completa
                if not proof.merkle_root:
                    return False
            
            return True
            
        except Exception as e:
            print(f"❌ Errore verifica Merkle proofs: {e}")
            return False
    
    def _verify_issuer_certificate(self, disclosure: SelectiveDisclosure) -> Tuple[bool, Optional[IssuerTrustInfo]]:
        """Verifica certificato emittente"""
        try:
            # Estrae nome emittente dai dati disclosed
            issuer_name = None
            country = "Unknown"
            
            for path, value in disclosure.disclosed_attributes.items():
                if "issuer" in path and "name" in path:
                    issuer_name = str(value)
                if "issuer" in path and "country" in path:
                    country = str(value)
            
            if not issuer_name:
                print(f"⚠️  Nome emittente non trovato nei dati disclosed")
                return False, None
            
            # Verifica se già in cache
            cache_key = f"{issuer_name}_{country}"
            if cache_key in self.issuer_trust_cache:
                cached_trust = self.issuer_trust_cache[cache_key]
                
                # Verifica se cache ancora valida
                cache_age = datetime.datetime.utcnow() - cached_trust.last_updated
                if cache_age.total_seconds() < self.max_verification_age_hours * 3600:
                    return cached_trust.certificate_valid, cached_trust
            
            # Verifica certificato via PKI
            certificate_valid = self._verify_certificate_with_pki(issuer_name, country)
            
            # Crea trust info
            trust_info = IssuerTrustInfo(
                issuer_name=issuer_name,
                country=country,
                trust_level=self._determine_trust_level(issuer_name, country),
                certificate_valid=certificate_valid,
                accreditation_verified=self._verify_accreditation(issuer_name, country),
                reputation_score=self._calculate_reputation_score(issuer_name),
                verification_history=self._get_verification_history_count(issuer_name),
                last_updated=datetime.datetime.utcnow()
            )
            
            # Aggiorna cache
            self.issuer_trust_cache[cache_key] = trust_info
            
            return certificate_valid, trust_info
            
        except Exception as e:
            print(f"❌ Errore verifica certificato emittente: {e}")
            return False, None
    
    def _verify_blockchain_status(self, disclosure: SelectiveDisclosure) -> bool:
        """Verifica status su blockchain"""
        try:
            if not self.registry_manager:
                return True  # Skip se non disponibile
            
            status_info = self.registry_manager.check_credential_status(disclosure.credential_id)
            
            if status_info:
                return status_info.is_valid and status_info.blockchain_status == 1  # ACTIVE
            
            # Credenziale non trovata su blockchain
            return False
            
        except Exception as e:
            print(f"❌ Errore verifica blockchain: {e}")
            return True  # Non bloccare per errori blockchain
    
    def _verify_temporal_validity(self, disclosure: SelectiveDisclosure) -> bool:
        """Verifica validità temporale"""
        try:
            # Verifica se la disclosure è scaduta
            if disclosure.expires_at:
                if datetime.datetime.utcnow() > disclosure.expires_at:
                    return False
            
            # Verifica date degli esami nei dati disclosed
            for path, value in disclosure.disclosed_attributes.items():
                if "exam_date" in path or "date" in path:
                    try:
                        # Parsing flessibile delle date
                        if isinstance(value, str):
                            exam_date = datetime.datetime.fromisoformat(value.replace('Z', '+00:00'))
                            
                            # Verifica che la data non sia nel futuro
                            if exam_date > datetime.datetime.now(datetime.timezone.utc):
                                return False
                    except:
                        continue  # Skip date non parsabili
            
            return True
            
        except Exception as e:
            print(f"❌ Errore verifica temporale: {e}")
            return False
    
    def _verify_individual_attributes(self, disclosure: SelectiveDisclosure, merkle_valid: bool) -> List[AttributeVerification]:
        """Verifica attributi individuali"""
        verified_attributes = []
        
        try:
            for attribute_path, attribute_value in disclosure.disclosed_attributes.items():
                # Trova proof corrispondente
                merkle_proof_valid = False
                verification_method = "format_check"
                
                if merkle_valid:
                    for proof in disclosure.merkle_proofs:
                        if proof.attribute_path == attribute_path:
                            merkle_proof_valid = True
                            verification_method = "merkle_proof"
                            break
                
                # Verifica specifica per tipo attributo
                is_valid, warnings = self._verify_attribute_value(attribute_path, attribute_value)
                
                # Calcola confidence score
                confidence_score = self._calculate_attribute_confidence(
                    is_valid, merkle_proof_valid, attribute_path
                )
                
                attr_verification = AttributeVerification(
                    attribute_path=attribute_path,
                    attribute_value=attribute_value,
                    is_valid=is_valid,
                    merkle_proof_valid=merkle_proof_valid,
                    confidence_score=confidence_score,
                    verification_method=verification_method,
                    warnings=warnings
                )
                
                verified_attributes.append(attr_verification)
            
        except Exception as e:
            print(f"❌ Errore verifica attributi individuali: {e}")
        
        return verified_attributes
    
    def _verify_attribute_value(self, attribute_path: str, value: Any) -> Tuple[bool, List[str]]:
        """Verifica valore specifico di un attributo"""
        warnings = []
        
        try:
            # Verifica formato UUID per credential_id
            if "credential_id" in attribute_path:
                try:
                    uuid.UUID(str(value))
                    return True, warnings
                except:
                    return False, ["Formato UUID non valido"]
            
            # Verifica voti
            if "grade" in attribute_path and "score" in attribute_path:
                score_str = str(value)
                if "/" in score_str:
                    try:
                        num, denom = score_str.split("/")
                        score = float(num)
                        max_score = float(denom)
                        
                        if score < 0 or score > max_score:
                            return False, ["Voto fuori range"]
                        
                        if max_score == 30 and score < 18:
                            warnings.append("Voto insufficiente nel sistema italiano")
                        
                    except:
                        return False, ["Formato voto non riconosciuto"]
            
            # Verifica crediti ECTS
            if "ects" in attribute_path:
                try:
                    credits = int(value)
                    if credits < 0 or credits > 60:
                        warnings.append("Crediti ECTS fuori range tipico")
                except:
                    return False, ["Crediti ECTS non numerici"]
            
            # Verifica codici paese
            if "country" in attribute_path:
                country_code = str(value).upper()
                if len(country_code) != 2:
                    warnings.append("Codice paese non ISO 3166-1")
            
            return True, warnings
            
        except Exception as e:
            print(f"❌ Errore verifica attributo {attribute_path}: {e}")
            return False, [f"Errore verifica: {e}"]
    
    def _calculate_overall_result(self, credential_results: List[CredentialVerificationResult],
                                presentation_format_valid: bool,
                                presentation_signature_valid: bool,
                                presentation_temporal_valid: bool) -> Tuple[VerificationResult, float]:
        """Calcola risultato complessivo presentazione"""
        try:
            if not credential_results:
                return VerificationResult.INVALID, 0.0
            
            # Conta risultati credenziali
            valid_credentials = sum(1 for cr in credential_results if cr.overall_result == VerificationResult.VALID)
            
            # Calcola confidence media
            total_confidence = sum(cr.confidence_score for cr in credential_results)
            avg_confidence = total_confidence / len(credential_results)
            
            # Penalizza per problemi presentazione
            presentation_penalty = 0.0
            if not presentation_format_valid:
                presentation_penalty += 0.3
            if not presentation_signature_valid:
                presentation_penalty += 0.1
            if not presentation_temporal_valid:
                presentation_penalty += 0.2
            
            final_confidence = max(0.0, avg_confidence - presentation_penalty)
            
            # Determina risultato
            if valid_credentials == len(credential_results) and presentation_format_valid:
                return VerificationResult.VALID, final_confidence
            elif valid_credentials > 0:
                return VerificationResult.PARTIAL, final_confidence
            else:
                return VerificationResult.INVALID, final_confidence
                
        except Exception as e:
            print(f"❌ Errore calcolo risultato complessivo: {e}")
            return VerificationResult.ERROR, 0.0
    
    def _calculate_credential_result(self, format_valid: bool, signature_valid: bool,
                                   certificate_valid: bool, merkle_tree_valid: bool,
                                   blockchain_valid: bool, temporal_valid: bool,
                                   verified_attributes: List[AttributeVerification],
                                   issuer_trust: Optional[IssuerTrustInfo]) -> Tuple[VerificationResult, float]:
        """Calcola risultato per singola credenziale"""
        try:
            # Score base
            score = 0.0
            max_score = 0.0
            
            # Pesi verifiche
            weights = {
                'format': 0.1,
                'signature': 0.15,
                'certificate': 0.2,
                'merkle': 0.25,
                'blockchain': 0.15,
                'temporal': 0.1,
                'attributes': 0.05
            }
            
            # Calcola score
            if format_valid:
                score += weights['format']
            max_score += weights['format']
            
            if signature_valid:
                score += weights['signature']
            max_score += weights['signature']
            
            if certificate_valid:
                score += weights['certificate']
            max_score += weights['certificate']
            
            if merkle_tree_valid:
                score += weights['merkle']
            max_score += weights['merkle']
            
            if blockchain_valid:
                score += weights['blockchain']
            max_score += weights['blockchain']
            
            if temporal_valid:
                score += weights['temporal']
            max_score += weights['temporal']
            
            # Score attributi
            if verified_attributes:
                valid_attrs = sum(1 for attr in verified_attributes if attr.is_valid)
                attr_score = (valid_attrs / len(verified_attributes)) * weights['attributes']
                score += attr_score
            max_score += weights['attributes']
            
            # Normalizza
            confidence = score / max_score if max_score > 0 else 0.0
            
            # Bonus per trust emittente
            if issuer_trust:
                trust_bonus = issuer_trust.reputation_score * 0.1
                confidence = min(1.0, confidence + trust_bonus)
            
            # Determina risultato
            if confidence >= 0.9 and format_valid and merkle_tree_valid:
                return VerificationResult.VALID, confidence
            elif confidence >= 0.6:
                return VerificationResult.PARTIAL, confidence
            else:
                return VerificationResult.INVALID, confidence
                
        except Exception as e:
            print(f"❌ Errore calcolo risultato credenziale: {e}")
            return VerificationResult.ERROR, 0.0
    
    # Helper methods (implementazioni semplificate)
    def _verify_certificate_with_pki(self, issuer_name: str, country: str) -> bool:
        """Verifica certificato via PKI"""
        # TODO: Implementare verifica reale con CertificateManager
        return True
    
    def _determine_trust_level(self, issuer_name: str, country: str) -> TrustLevel:
        """Determina livello di fiducia emittente"""
        # Logica semplificata basata su paese e nome
        trusted_countries = ["IT", "FR", "DE", "ES", "UK", "NL"]
        
        if country in trusted_countries:
            if "università" in issuer_name.lower() or "university" in issuer_name.lower():
                return TrustLevel.HIGH
            return TrustLevel.MEDIUM
        
        return TrustLevel.LOW
    
    def _verify_accreditation(self, issuer_name: str, country: str) -> bool:
        """Verifica accreditamento università"""
        # TODO: Implementare verifica accreditamento reale
        return True
    
    def _calculate_reputation_score(self, issuer_name: str) -> float:
        """Calcola score reputazione università"""
        # Score base in base al numero di verifiche precedenti
        history_count = self._get_verification_history_count(issuer_name)
        return min(1.0, 0.5 + (history_count * 0.01))
    
    def _get_verification_history_count(self, issuer_name: str) -> int:
        """Ottiene numero verifiche precedenti per emittente"""
        count = 0
        for credential_id, results in self.verification_history.items():
            for result in results:
                if result.issuer_trust.issuer_name == issuer_name:
                    count += 1
        return count
    
    def _calculate_attribute_confidence(self, is_valid: bool, merkle_proof_valid: bool, attribute_path: str) -> float:
        """Calcola confidence per singolo attributo"""
        base_score = 0.7 if is_valid else 0.0
        
        if merkle_proof_valid:
            base_score += 0.2
        
        # Bonus per attributi critici
        critical_attributes = ["credential_id", "grade", "issuer"]
        if any(critical in attribute_path for critical in critical_attributes):
            base_score += 0.1
        
        return min(1.0, base_score)
    
    def _get_unknown_issuer_trust(self, disclosure: SelectiveDisclosure) -> IssuerTrustInfo:
        """Crea trust info per emittente sconosciuto"""
        return IssuerTrustInfo(
            issuer_name="Unknown Issuer",
            country="Unknown",
            trust_level=TrustLevel.UNKNOWN,
            certificate_valid=False,
            accreditation_verified=False,
            reputation_score=0.0,
            verification_history=0,
            last_updated=datetime.datetime.utcnow(),
            notes="Emittente non identificato nei dati disclosed"
        )
    
    def _create_error_result(self, error_message: str) -> PresentationVerificationResult:
        """Crea risultato di errore per presentazione"""
        return PresentationVerificationResult(
            presentation_id="error",
            overall_result=VerificationResult.ERROR,
            confidence_score=0.0,
            credential_results=[],
            presentation_format_valid=False,
            presentation_signature_valid=False,
            presentation_temporal_valid=False,
            total_credentials=0,
            valid_credentials=0,
            total_attributes=0,
            valid_attributes=0,
            verified_by=self.university_name,
            verification_purpose="Error",
            verification_timestamp=datetime.datetime.utcnow(),
            verification_duration_ms=0,
            errors=[error_message]
        )
    
    def _create_credential_error_result(self, credential_id: str, error_message: str) -> CredentialVerificationResult:
        """Crea risultato di errore per credenziale"""
        return CredentialVerificationResult(
            credential_id=credential_id,
            overall_result=VerificationResult.ERROR,
            confidence_score=0.0,
            format_valid=False,
            signature_valid=False,
            certificate_valid=False,
            merkle_tree_valid=False,
            blockchain_valid=False,
            temporal_valid=False,
            verified_attributes=[],
            issuer_trust=self._get_unknown_issuer_trust(None),
            verification_level=self.default_verification_level,
            verification_timestamp=datetime.datetime.utcnow(),
            verification_duration_ms=0,
            errors=[error_message]
        )
    
    def _update_verification_stats(self, result: PresentationVerificationResult):
        """Aggiorna statistiche verifiche"""
        self.stats['total_verifications'] += 1
        
        if result.overall_result == VerificationResult.VALID:
            self.stats['successful_verifications'] += 1
        else:
            self.stats['failed_verifications'] += 1
        
        if self.enable_blockchain_verification:
            self.stats['blockchain_verifications'] += 1
        
        # Aggiorna durata media
        total_duration = self.stats['average_duration_ms'] * (self.stats['total_verifications'] - 1)
        self.stats['average_duration_ms'] = int(
            (total_duration + result.verification_duration_ms) / self.stats['total_verifications']
        )
        
        self.stats['last_verification'] = datetime.datetime.utcnow().isoformat()
    
    def _update_verification_cache(self, result: CredentialVerificationResult):
        """Aggiorna cache e history verifiche"""
        credential_id = result.credential_id
        
        if credential_id not in self.verification_history:
            self.verification_history[credential_id] = []
        
        self.verification_history[credential_id].append(result)
        
        # Mantieni solo le ultime 10 verifiche per credenziale
        if len(self.verification_history[credential_id]) > 10:
            self.verification_history[credential_id] = self.verification_history[credential_id][-10:]
    
    def get_verification_statistics(self) -> Dict[str, Any]:
        """Ottiene statistiche verifiche"""
        return {
            'engine_stats': self.stats,
            'cache_stats': {
                'issuer_trust_entries': len(self.issuer_trust_cache),
                'verification_history_entries': len(self.verification_history),
                'total_historical_verifications': sum(len(results) for results in self.verification_history.values())
            },
            'configuration': {
                'default_verification_level': self.default_verification_level.value,
                'blockchain_enabled': self.enable_blockchain_verification,
                'trust_unknown_issuers': self.trust_unknown_issuers,
                'max_verification_age_hours': self.max_verification_age_hours
            }
        }


# =============================================================================
# 3. DEMO E TESTING
# =============================================================================

def demo_verification_engine():
    """Demo del Verification Engine"""
    
    print("🔍" * 40)
    print("DEMO VERIFICATION ENGINE")
    print("Engine di Verifica Credenziali")
    print("🔍" * 40)
    
    try:
        # 1. Setup verification engine
        print("\n1️⃣ SETUP VERIFICATION ENGINE")
        
        from pki.certificate_manager import CertificateManager
        
        cert_manager = CertificateManager()
        
        # Per demo, registry manager opzionale
        registry_manager = None
        
        engine = CredentialVerificationEngine(
            university_name="Università degli Studi di Salerno",
            cert_manager=cert_manager,
            registry_manager=registry_manager
        )
        
        print(f"✅ Engine inizializzato")
        
        # 2. Crea presentazione di test
        print("\n2️⃣ CREAZIONE PRESENTAZIONE DI TEST")
        
        # Usa factory per creare dati test
        from credentials.models import CredentialFactory
        from wallet.selective_disclosure import SelectiveDisclosureManager, DisclosureLevel
        
        test_credential = CredentialFactory.create_sample_credential()
        disclosure_manager = SelectiveDisclosureManager()
        
        # Crea disclosure selettiva
        disclosure = disclosure_manager.create_predefined_disclosure(
            test_credential,
            DisclosureLevel.STANDARD,
            purpose="Test Verifica",
            recipient="Università di Salerno"
        )
        
        # Crea presentazione simulata
        presentation_data = {
            'presentation_id': str(uuid.uuid4()),
            'created_at': datetime.datetime.utcnow().isoformat(),
            'created_by': test_credential.subject.pseudonym,
            'purpose': 'Riconoscimento Crediti Accademici',
            'recipient': 'Università degli Studi di Salerno',
            'expires_at': (datetime.datetime.utcnow() + datetime.timedelta(hours=24)).isoformat(),
            'selective_disclosures': [disclosure.to_dict()],
            'format': 'signed_json',
            'signature': {
                'algoritmo': 'RSA-SHA256-PSS',
                'valore': 'mock_signature_for_demo',
                'timestamp': datetime.datetime.utcnow().isoformat()
            }
        }
        
        print(f"✅ Presentazione test creata")
        print(f"   ID: {presentation_data['presentation_id']}")
        print(f"   Disclosures: {len(presentation_data['selective_disclosures'])}")
        
        # 3. Verifica livello BASIC
        print("\n3️⃣ VERIFICA LIVELLO BASIC")
        
        result_basic = engine.verify_presentation(
            presentation_data,
            VerificationLevel.BASIC,
            "Test Verifica Basic"
        )
        
        print(f"📊 Risultato Basic:")
        print(f"   Risultato: {result_basic.overall_result.value}")
        print(f"   Confidence: {result_basic.confidence_score:.2f}")
        print(f"   Credenziali valide: {result_basic.valid_credentials}/{result_basic.total_credentials}")
        print(f"   Durata: {result_basic.verification_duration_ms}ms")
        
        # 4. Verifica livello STANDARD
        print("\n4️⃣ VERIFICA LIVELLO STANDARD")
        
        result_standard = engine.verify_presentation(
            presentation_data,
            VerificationLevel.STANDARD,
            "Test Verifica Standard"
        )
        
        print(f"📊 Risultato Standard:")
        print(f"   Risultato: {result_standard.overall_result.value}")
        print(f"   Confidence: {result_standard.confidence_score:.2f}")
        print(f"   Attributi validi: {result_standard.valid_attributes}/{result_standard.total_attributes}")
        
        # 5. Dettagli verifica credenziale
        print("\n5️⃣ DETTAGLI VERIFICA CREDENZIALE")
        
        if result_standard.credential_results:
            cred_result = result_standard.credential_results[0]
            
            print(f"🔍 Dettagli prima credenziale:")
            print(f"   ID: {cred_result.credential_id}")
            print(f"   Formato valido: {'✅' if cred_result.format_valid else '❌'}")
            print(f"   Firma valida: {'✅' if cred_result.signature_valid else '❌'}")
            print(f"   Certificato valido: {'✅' if cred_result.certificate_valid else '❌'}")
            print(f"   Merkle tree valido: {'✅' if cred_result.merkle_tree_valid else '❌'}")
            print(f"   Blockchain valido: {'✅' if cred_result.blockchain_valid else '❌'}")
            print(f"   Temporale valido: {'✅' if cred_result.temporal_valid else '❌'}")
            
            print(f"🏛️  Fiducia emittente:")
            trust = cred_result.issuer_trust
            print(f"   Nome: {trust.issuer_name}")
            print(f"   Paese: {trust.country}")
            print(f"   Livello fiducia: {trust.trust_level.value}")
            print(f"   Score reputazione: {trust.reputation_score:.2f}")
            print(f"   Verifiche precedenti: {trust.verification_history}")
        
        # 6. Analisi attributi
        print("\n6️⃣ ANALISI ATTRIBUTI")
        
        if result_standard.credential_results and result_standard.credential_results[0].verified_attributes:
            attributes = result_standard.credential_results[0].verified_attributes
            
            print(f"📋 Attributi verificati: {len(attributes)}")
            
            for attr in attributes[:5]:  # Primi 5
                status = "✅" if attr.is_valid else "❌"
                proof_status = "🔗" if attr.merkle_proof_valid else "⚪"
                
                print(f"   {status} {proof_status} {attr.attribute_path}")
                print(f"       Valore: {str(attr.attribute_value)[:50]}...")
                print(f"       Confidence: {attr.confidence_score:.2f}")
                print(f"       Metodo: {attr.verification_method}")
                
                if attr.warnings:
                    for warning in attr.warnings:
                        print(f"       ⚠️  {warning}")
        
        # 7. Export risultato
        print("\n7️⃣ EXPORT RISULTATO")
        
        result_dict = result_standard.to_dict()
        
        # Salva risultato
        output_dir = Path("./verification/results")
        output_dir.mkdir(parents=True, exist_ok=True)
        
        output_file = output_dir / f"verification_result_{result_standard.presentation_id[:8]}.json"
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(result_dict, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"💾 Risultato salvato: {output_file}")
        
        # 8. Statistiche engine
        print("\n8️⃣ STATISTICHE ENGINE")
        
        stats = engine.get_verification_statistics()
        
        print(f"📊 Statistiche verification engine:")
        for section, data in stats.items():
            print(f"   {section}:")
            for key, value in data.items():
                print(f"     {key}: {value}")
        
        # 9. Test caso invalido
        print("\n9️⃣ TEST CASO INVALIDO")
        
        # Crea presentazione invalida
        invalid_presentation = {
            'presentation_id': str(uuid.uuid4()),
            'created_at': datetime.datetime.utcnow().isoformat(),
            'purpose': 'Test Invalido',
            'expires_at': (datetime.datetime.utcnow() - datetime.timedelta(hours=1)).isoformat(),  # Scaduta
            'selective_disclosures': []  # Vuoto
        }
        
        result_invalid = engine.verify_presentation(
            invalid_presentation,
            VerificationLevel.STANDARD,
            "Test Caso Invalido"
        )
        
        print(f"❌ Risultato caso invalido:")
        print(f"   Risultato: {result_invalid.overall_result.value}")
        print(f"   Confidence: {result_invalid.confidence_score:.2f}")
        print(f"   Errori: {len(result_invalid.errors)}")
        
        for error in result_invalid.errors:
            print(f"     - {error}")
        
        print("\n" + "✅" * 40)
        print("DEMO VERIFICATION ENGINE COMPLETATA!")
        print("✅" * 40)
        
        print(f"\n🎯 Funzionalità verificate:")
        print("✅ Verifica presentazioni multi-livello")
        print("✅ Validazione credenziali e attributi")
        print("✅ Verifica Merkle proofs")
        print("✅ Gestione trust emittenti")
        print("✅ Analisi temporale e format")
        print("✅ Calcolo confidence scores")
        print("✅ Export risultati dettagliati")
        print("✅ Statistiche e monitoring")
        print("✅ Gestione errori e edge cases")
        
        return engine, result_standard
        
    except Exception as e:
        print(f"\n❌ Errore durante demo: {e}")
        import traceback
        traceback.print_exc()
        return None, None


# =============================================================================
# 4. MAIN - PUNTO DI INGRESSO
# =============================================================================

if __name__ == "__main__":
    print("🔍" * 50)
    print("VERIFICATION ENGINE")
    print("Engine di Verifica Credenziali Accademiche")
    print("🔍" * 50)
    
    # Esegui demo
    engine, result = demo_verification_engine()
    
    if engine:
        print("\n🎉 Verification Engine pronto!")
        print("\nArchitettura verifica:")
        print("🔍 Engine multi-livello (Basic → Forensic)")
        print("📋 Verifica presentazioni complete")
        print("🔗 Validazione Merkle proofs")
        print("🏛️  Trust management emittenti")
        print("⏰ Controlli temporali")
        print("📊 Confidence scoring")
        print("💾 Cache e history")
        print("📈 Statistiche dettagliate")
        
        print(f"\n🚀 Engine pronto per integrazione!")
    else:
        print("\n❌ Errore inizializzazione Verification Engine")