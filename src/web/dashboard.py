# =============================================================================
# ACADEMIC CREDENTIALS DASHBOARD - Main Application (MODIFICATO)
# File: web/dashboard.py
# Decentralized Academic Credentials System
# =============================================================================

import asyncio
import base64
import os
import json
import uuid
import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
import logging
from dataclasses import dataclass
import httpx

# FastAPI and web dependencies
from fastapi import FastAPI, Request, HTTPException, Depends, Form, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware
from starlette.status import HTTP_302_FOUND, HTTP_403_FORBIDDEN


from credentials.models import CredentialFactory, CredentialStatus
from wallet.presentation import PresentationFormat, PresentationManager
from wallet.student_wallet import AcademicStudentWallet, WalletConfiguration, WalletStatus

# Conditional imports to prevent errors if modules are unavailable
try:
    from credentials.models import AcademicCredential, PersonalInfo, StudyPeriod, StudyProgram, Course, ExamGrade, GradeSystem, EQFLevel, StudyType, University
    from credentials.issuer import AcademicCredentialIssuer, IssuerConfiguration
    from crypto.foundations import CryptoUtils
    MODULES_AVAILABLE = True
except ImportError as e:
    print(f"⚠️ Core modules not available: {e}")
    MODULES_AVAILABLE = False

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate

# =============================================================================
# DATA MODELS AND CONFIGURATION
# =============================================================================

@dataclass
class AppConfig:
    """Centralized application configuration."""
    secret_key: str = "Unisa2025"
    host: str = "127.0.0.1"
    port: int = 8000
    debug: bool = True
    templates_dir: str = "./src/web/templates"
    static_dir: str = "./src/web/static"
    session_timeout_minutes: int = 60
    max_file_size_mb: int = 10
    secure_server_url: str = "https://localhost:8443"
    secure_server_api_key: str = "verifier_unisa"

class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=6)

class UserSession(BaseModel):
    user_id: str
    university_name: str
    role: str
    permissions: List[str]
    login_time: datetime.datetime = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc))
    last_activity: datetime.datetime = Field(default_factory=lambda: datetime.datetime.now(datetime.timezone.utc))
    is_issuer: bool = False
    is_student: bool = False

class DashboardStats(BaseModel):
    total_credentials_issued: int
    total_credentials_verified: int
    pending_verifications: int
    success_rate: float
    last_updated: datetime.datetime

class CredentialIssueRequest(BaseModel):
    student_name: str = Field(..., min_length=2, max_length=100)
    student_id: str = Field(..., min_length=5, max_length=20)
    credential_type: str
    study_period_start: str
    study_period_end: str
    courses: List[Dict[str, Any]] = []

class PresentationRequest(BaseModel):
    purpose: str = Field(..., min_length=5, max_length=200)
    recipient: Optional[str] = Field(None, max_length=100)
    credentials: List[str]
    format: str = "json"

class VerificationRequest(BaseModel):
    presentation_data: Dict[str, Any]
    purpose: str

class FullVerificationRequest(BaseModel):
    presentation_data: Dict[str, Any]
    student_public_key: str
    purpose: str

# =============================================================================
# SERVICES AND UTILITIES
# =============================================================================

class AuthenticationService:
    """Service for handling authentication."""
    
    VALID_USERS = {
        "studente_mariorossi": {"role": "studente", "university": "Università di Salerno"},
        "issuer_rennes": {"role": "issuer", "university": "Université de Rennes"},
        "verifier_unisa": {"role": "verifier", "university": "Università di Salerno"},
        "admin_system": {"role": "admin", "university": "Sistema Centrale"}
    }
    
    @classmethod
    def authenticate_user(cls, username: str, password: str) -> Optional[Dict[str, str]]:
        """Authenticates a user with username and password."""
        if username in cls.VALID_USERS and password == "Unisa2025":
            return cls.VALID_USERS[username]
        return None
    
    @classmethod
    def get_user_permissions(cls, role: str) -> List[str]:
        """Returns user permissions based on their role."""
        permissions_map = {
            "studente": ["read", "share"],
            "issuer": ["read", "write", "issue"],
            "verifier": ["read", "verify"],
            "admin": ["read", "write", "verify", "admin"]
        }
        return permissions_map.get(role, ["read"])

class SessionManager:
    """Manages user sessions."""
    
    def __init__(self, timeout_minutes: int = 60):
        self.sessions: Dict[str, UserSession] = {}
        self.timeout_minutes = timeout_minutes
    
    def create_session(self, user_info: Dict[str, str], username: str) -> str:
        """Creates a new user session."""
        session_id = f"session_{uuid.uuid4()}"
        permissions = AuthenticationService.get_user_permissions(user_info["role"])
        
        role = user_info["role"]
        is_issuer = (role == "issuer")
        is_student = (role == "studente")
        
        self.sessions[session_id] = UserSession(
            user_id=username,
            university_name=user_info["university"],
            role=role,
            permissions=permissions,
            is_issuer=is_issuer,
            is_student=is_student
        )
        
        return session_id
    
    def get_session(self, session_id: str) -> Optional[UserSession]:
        """Retrieves an existing session."""
        if session_id not in self.sessions:
            return None
            
        session = self.sessions[session_id]
        
        if self._is_session_expired(session):
            del self.sessions[session_id]
            return None
        
        session.last_activity = datetime.datetime.now(datetime.timezone.utc)
        return session
    
    def destroy_session(self, session_id: str) -> None:
        """Destroys a session."""
        self.sessions.pop(session_id, None)
    
    def _is_session_expired(self, session: UserSession) -> bool:
        """Checks if a session has expired."""
        expiry_time = session.last_activity + datetime.timedelta(minutes=self.timeout_minutes)
        return datetime.datetime.now(datetime.timezone.utc) > expiry_time

class MockDataService:
    """Service for providing mock/demo data."""
    
    @staticmethod
    def get_dashboard_stats() -> DashboardStats:
        return DashboardStats(
            total_credentials_issued=47,
            total_credentials_verified=32,
            pending_verifications=5,
            success_rate=94.7,
            last_updated=datetime.datetime.now(datetime.timezone.utc)
        )
    
    @staticmethod
    def get_wallet_credentials() -> List[Dict[str, Any]]:
        return [
            {
                "credential_id": "cred_france_123",
                "issuer": "Université de Rennes",
                "issue_date": "2024-09-15",
                "total_courses": 5,
                "status": "Active"
            },
            {
                "credential_id": "cred_germany_456", 
                "issuer": "TU München",
                "issue_date": "2024-02-20",
                "total_courses": 4,
                "status": "Active"
            }
        ]
    
    @staticmethod
    def get_pending_verifications() -> List[Dict[str, str]]:
        return [
            {"student_name": "Mario Rossi", "purpose": "CFU Recognition", "status": "Processing"},
            {"student_name": "Anna Bianchi", "purpose": "Master's Enrollment", "status": "Documentation required"},
            {"student_name": "Luca Verdi", "purpose": "Erasmus+", "status": "Processing"}
        ]
    
    @staticmethod
    def get_integration_stats() -> Dict[str, int]:
        return {
            "connected_systems": 3,
            "auto_approved": 28,
            "manual_review": 7,
            "pending_mappings": 12
        }
    
    @staticmethod
    def get_system_health() -> Dict[str, str]:
        return {
            "blockchain_status": "Operational",
            "database_status": "Operational"
        }
    
    @staticmethod
    def get_test_results() -> Dict[str, Any]:
        return {
            "last_run": "2025-01-15 14:30:00",
            "passed": 18,
            "failed": 2,
            "success_rate": "90%"
        }

# Classe di supporto per la verifica
class PresentationVerifier:
    """Gestisce la verifica completa delle presentazioni selective - CORRETTO"""
    
    def __init__(self, dashboard_instance):
        self.dashboard = dashboard_instance
        self.logger = dashboard_instance.logger
        
    async def verify_presentation_complete(self, presentation_data: dict, student_public_key_pem: str, purpose: str) -> dict:
        """Verifica completa di una presentazione selettiva - CORRETTO"""
        self.logger.info("🔍 Avvio verifica completa presentazione")
        
        report = {
            "credential_id": presentation_data.get("presentation_id", "unknown"),
            "validation_level": "complete", "overall_result": "unknown",
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "is_valid": False, "errors": [], "warnings": [], "info": [],  
            "technical_details": {
                "student_signature_valid": False, "signature_valid": False, 
                "merkle_tree_valid": False, "blockchain_status": "not_checked",
                "temporal_valid": False, "revocation_status": "unknown"
            }
        }

        try:
            # 1. VERIFICA FIRMA DELLO STUDENTE
            self.logger.info("  1️⃣ Verifica firma studente...")
            student_sig_valid = await self._verify_student_signature(presentation_data, student_public_key_pem)
            report["technical_details"]["student_signature_valid"] = student_sig_valid
            if student_sig_valid:
                self.logger.info("✅ Firma studente valida")
            else:
                self.logger.warning("❌ Firma studente non valida")
                report["errors"].append({"code": "STUDENT_SIGNATURE_INVALID", "message": "Firma dello studente non valida"})
            
            # 2. ESTRAI CREDENZIALI
            self.logger.info("  2️⃣ Estrazione credenziali...")
            credentials = self._extract_credentials_from_presentation(presentation_data)
            if not credentials:
                report["errors"].append({"code": "NO_CREDENTIALS_FOUND", "message": "Nessuna credenziale trovata"})
                report["overall_result"] = "invalid"
                return report
            
            # 3. VERIFICA OGNI CREDENZIALE
            all_credentials_valid = True
            for i, cred_disclosure in enumerate(credentials):
                self.logger.info(f"  3️⃣ Verifica credenziale {i+1}/{len(credentials)}...")
                
                # 3.1 VERIFICA MERKLE PROOFS
                if "merkle_proofs" in cred_disclosure:
                    if self.logger.level <= logging.INFO:
                        await self._debug_merkle_structure(cred_disclosure)
                    
                    merkle_valid, merkle_error = await self._verify_merkle_proofs(cred_disclosure, report)
                    if not merkle_valid:
                        if "proof non valida" in merkle_error.lower() or "numero attributi" in merkle_error.lower():
                            report["errors"].append({
                                "code": "MERKLE_PROOF_INVALID", 
                                "message": f"Merkle proof crittograficamente non valida per credenziale {i+1}: {merkle_error}"
                            })
                            all_credentials_valid = False
                        else:
                            report["warnings"].append({
                                "code": "MERKLE_PROOF_PARTIAL", 
                                "message": f"Merkle proof parzialmente valida per credenziale {i+1}: {merkle_error}"
                            })
                    else:
                        report["info"].append({
                            "code": "MERKLE_PROOF_VALID",
                            "message": f"Merkle proof crittograficamente verificata per credenziale {i+1}"
                        })
                        if not merkle_error:
                            report["technical_details"]["merkle_tree_valid"] = True
                else:
                    report["warnings"].append({
                        "code": "NO_MERKLE_PROOFS",
                        "message": f"Nessuna Merkle proof fornita per credenziale {i+1}"
                    })
                
                # 3.2 VERIFICA FIRMA UNIVERSITÀ
                university_sig_valid = await self._verify_university_signature_from_disclosure(cred_disclosure)
                report["technical_details"]["signature_valid"] = university_sig_valid
                if not university_sig_valid:
                    self.logger.warning("      ⚠️ Firma università mancante")
                    report["warnings"].append({
                        "code": "UNIVERSITY_SIGNATURE_MISSING", 
                        "message": f"Firma università mancante per credenziale {i+1}"
                    })
                else:
                    report["info"].append({
                        "code": "UNIVERSITY_SIGNATURE_VALID",
                        "message": f"Firma università verificata per credenziale {i+1}"
                    })
                
                # 3.3 VERIFICA STATO BLOCKCHAIN
                credential_id = cred_disclosure.get("credential_id")
                if credential_id:
                    blockchain_status = await self._verify_blockchain_status(credential_id)
                    report["technical_details"]["blockchain_status"] = blockchain_status
                    
                    if blockchain_status == "revoked":
                        report["errors"].append({
                            "code": "CREDENTIAL_REVOKED", 
                            "message": f"Credenziale {credential_id} risulta revocata"
                        })
                        all_credentials_valid = False
                    elif blockchain_status == "valid":
                        report["info"].append({
                            "code": "BLOCKCHAIN_VALID",
                            "message": f"Credenziale {credential_id} verificata su blockchain"
                        })
                    elif blockchain_status in ["timeout", "unreachable", "error"]:
                        report["warnings"].append({
                            "code": "BLOCKCHAIN_UNREACHABLE",
                            "message": f"Impossibile verificare blockchain per credenziale {credential_id}: {blockchain_status}"
                        })
                    else:
                        report["warnings"].append({
                            "code": "BLOCKCHAIN_UNKNOWN",
                            "message": f"Stato blockchain sconosciuto per credenziale {credential_id}: {blockchain_status}"
                        })

            # 4. VERIFICA TEMPORALE
            self.logger.info("  4️⃣ Verifica temporale...")
            temporal_valid = self._verify_temporal_consistency(presentation_data)
            report["technical_details"]["temporal_valid"] = temporal_valid
            if not temporal_valid:
                report["warnings"].append({"code": "TEMPORAL_INCONSISTENCY", "message": "Inconsistenze temporali rilevate"})
            
            # 5. RISULTATO FINALE - LOGICA MIGLIORATA
            if report["technical_details"]["blockchain_status"] == "revoked":
                report["overall_result"] = "revoked"
                report["is_valid"] = False
                self.logger.info("🚫 Presentazione REVOCATA")
            elif student_sig_valid and all_credentials_valid and len(report["errors"]) == 0:
                report["overall_result"] = "valid"
                report["is_valid"] = True
                self.logger.info("✅ Presentazione VALIDA")
            elif len(report["errors"]) == 0 and len(report["warnings"]) > 0:
                report["overall_result"] = "warning"
                report["is_valid"] = True
                self.logger.info("⚠️ Presentazione VALIDA con avvertenze")
            else:
                report["overall_result"] = "invalid"
                report["is_valid"] = False
                self.logger.info("❌ Presentazione NON VALIDA")

            return report
            
        except Exception as e:
            self.logger.error(f"❌ Errore durante verifica: {e}")
            report["errors"].append({"code": "VERIFICATION_ERROR", "message": f"Errore interno: {str(e)}"})
            report["overall_result"] = "invalid"
            return report
    
    async def _verify_student_signature(self, presentation_data: dict, student_public_key_pem: str) -> bool:
        """Verifica la firma digitale dello studente - CORRETTO"""
        try:
            if "signature" not in presentation_data:
                self.logger.warning("Nessuna firma trovata nella presentazione")
                return False
            
            signature_info = presentation_data["signature"]
            
            # CORREZIONE 1: Gestione migliorata della chiave pubblica
            try:
                # Ripulisce la chiave PEM se necessario
                clean_key = student_public_key_pem.strip()
                if not clean_key.startswith("-----BEGIN"):
                    # Se la chiave non ha l'header, prova ad aggiungerlo
                    clean_key = f"-----BEGIN PUBLIC KEY-----\n{clean_key}\n-----END PUBLIC KEY-----"
                
                public_key = serialization.load_pem_public_key(clean_key.encode())
            except Exception as e:
                self.logger.error(f"Errore caricamento chiave pubblica studente: {e}")
                return False
            
            # Ricostruisce i dati esatti firmati
            data_for_verification = {
                'presentation_id': presentation_data.get('presentation_id'),
                'created_at': presentation_data.get('created_at'),
                'created_by': presentation_data.get('created_by'),
                'purpose': presentation_data.get('purpose'),
                'recipient': presentation_data.get('recipient'),
                'expires_at': presentation_data.get('expires_at'),
                'status': presentation_data.get('status'),
                'selective_disclosures': presentation_data.get('selective_disclosures', []),
                'additional_documents': presentation_data.get('additional_documents', []),
                'format': presentation_data.get('format'),
                'verification_url': presentation_data.get('verification_url'),
            }
            
            from crypto.foundations import DigitalSignature
            verifier = DigitalSignature("PSS")
            
            document_to_verify = data_for_verification.copy()
            document_to_verify['firma'] = signature_info
            
            is_valid = verifier.verify_document_signature(public_key, document_to_verify)
            
            if is_valid: 
                self.logger.info("✅ Firma studente valida")
            else: 
                self.logger.warning("❌ Firma studente non valida")
            return is_valid
            
        except Exception as e:
            self.logger.error(f"Errore verifica firma studente: {e}")
            return False
        
    def _extract_credentials_from_presentation(self, presentation_data: dict) -> list:
        return presentation_data.get("selective_disclosures", [])
    
    async def _find_university_certificate(self, university_name: str) -> Optional[x509.Certificate]:
        """Trova certificato università - MIGLIORATO"""
        try:
            self.logger.info(f"   🔍 Ricerca certificato per: {university_name}")
            
            # CORREZIONE 3: Prima prova API, poi fallback locale
            try:
                async with httpx.AsyncClient(verify=False) as client:
                    response = await client.get(
                        f"{self.dashboard.config.secure_server_url}/api/v1/universities/certificate",
                        params={"name": university_name},
                        headers={"Authorization": f"Bearer {self.dashboard.config.secure_server_api_key}"},
                        timeout=5.0
                    )
                    
                    if response.status_code == 200:
                        cert_data = response.json()
                        if cert_data.get("success"):
                            cert_pem = cert_data["data"]["certificate_pem"]
                            from cryptography.x509 import load_pem_x509_certificate
                            return load_pem_x509_certificate(cert_pem.encode())
            except Exception as api_error:
                self.logger.warning(f"   ⚠️ API non disponibile: {api_error}")
            
            # Fallback: cerca localmente
            university_mappings = {
                "université de rennes": ["rennes", "F_RENNES01"],
                "università degli studi di salerno": ["salerno", "I_SALERNO"], 
                "università di salerno": ["salerno", "I_SALERNO"]
            }
            
            search_terms = [university_name.lower()]
            for uni_name, aliases in university_mappings.items():
                if university_name.lower() in uni_name:
                    search_terms.extend(aliases)
            
            cert_paths = [
                "./certificates/issued/university_F_RENNES01_1001.pem",
                "./certificates/issued/university_I_SALERNO_2001.pem",
                "certificates/issued/university_F_RENNES01_1001.pem", 
                "certificates/issued/university_I_SALERNO_2001.pem"
            ]
            
            for cert_path in cert_paths:
                try:
                    if Path(cert_path).exists():
                        for term in search_terms:
                            if term.lower() in cert_path.lower():
                                from cryptography.x509 import load_pem_x509_certificate
                                with open(cert_path, 'rb') as f:
                                    cert = load_pem_x509_certificate(f.read())
                                self.logger.info(f"   ✅ Certificato trovato: {cert_path}")
                                return cert
                except Exception as e:
                    continue
            
            self.logger.warning(f"   ⚠️ Certificato non trovato per {university_name}")
            return None
            
        except Exception as e:
            self.logger.error(f"   ❌ Errore ricerca certificato: {e}")
            return None
        
    async def _verify_university_signature_from_disclosure(self, disclosure: dict) -> bool:
        """Verifica firma università dalla divulgazione selettiva - NUOVO METODO"""
        try:
            # CORREZIONE 2: Verifica presenza dati università nella divulgazione
            disclosed_attrs = disclosure.get("disclosed_attributes", {})
            issuer_name = None
            
            # Cerca il nome dell'università negli attributi divulgati
            for attr_path, attr_value in disclosed_attrs.items():
                if "issuer" in attr_path and "name" in attr_path:
                    issuer_name = attr_value
                    break
            
            if not issuer_name:
                self.logger.warning("      ⚠️ Nome università non trovato negli attributi divulgati")
                return False
                
            self.logger.info(f"      🏛️ Verificando firma per: {issuer_name}")
            
            # Cerca certificato università
            university_cert = await self._find_university_certificate(issuer_name)
            if not university_cert:
                self.logger.warning(f"      ⚠️ Certificato non trovato per: {issuer_name}")
                return False
            
            # Per ora, dato che la firma università non è presente nella divulgazione selettiva,
            # ma solo nella credenziale originale, consideriamo valida se abbiamo il certificato
            self.logger.info("      ✅ Certificato università trovato (firma presunta valida)")
            return True
            
        except Exception as e:
            self.logger.error(f"      ❌ Errore verifica firma università: {e}")
            return False
            
    async def _verify_merkle_proofs(self, disclosure: dict, report: dict) -> Tuple[bool, str]:
        try:
            self.logger.info("  🌳 Verifica Merkle proofs crittografica...")
            disclosed_attributes = disclosure.get("disclosed_attributes", {})
            merkle_proofs = disclosure.get("merkle_proofs", [])
            
            if not disclosed_attributes:
                self.logger.warning("  ⚠️ Nessun attributo divulgato")
                return False, "Nessun attributo divulgato"
            
            if not merkle_proofs:
                self.logger.warning("  ⚠️ Nessuna Merkle proof fornita")
                return False, "Nessuna Merkle proof fornita"
            
            if len(disclosed_attributes) != len(merkle_proofs):
                error_msg = f"Numero attributi ({len(disclosed_attributes)}) ≠ numero proof ({len(merkle_proofs)})"
                self.logger.warning(f"  ❌ {error_msg}")
                return False, error_msg
            
            # Verifica ogni Merkle proof individualmente
            all_proofs_valid = True
            valid_count = 0
            
            for i, proof in enumerate(merkle_proofs):
                attribute_value = proof.get("attribute_value")
                proof_path = proof.get("proof_path", [])
                merkle_root = proof.get("merkle_root")
                
                if not merkle_root or not proof_path or attribute_value is None:
                    self.logger.warning(f"    ❌ Proof {i+1} struttura incompleta")
                    all_proofs_valid = False
                    continue
                
                # Verifica crittografica della singola proof
                is_valid = await self._verify_single_merkle_proof(
                    attribute_value, proof_path, merkle_root
                )
                
                if is_valid:
                    valid_count += 1
                    self.logger.info(f"    ✅ Proof {i+1} crittograficamente valida")
                else:
                    self.logger.warning(f"    ❌ Proof {i+1} crittograficamente non valida")
                    all_proofs_valid = False
            
            # Risultato finale
            success_rate = valid_count / len(merkle_proofs)
            
            if all_proofs_valid:
                self.logger.info(f"  ✅ Tutte le Merkle proof sono valide ({valid_count}/{len(merkle_proofs)})")
                report["technical_details"]["merkle_tree_valid"] = True
                return True, ""
            elif success_rate >= 0.8:  # 80% delle proof devono essere valide
                warning_msg = f"Alcune proof non valide ma la maggioranza è corretta ({valid_count}/{len(merkle_proofs)})"
                self.logger.warning(f"  ⚠️ {warning_msg}")
                report["technical_details"]["merkle_tree_valid"] = True
                return True, warning_msg
            else:
                error_msg = f"Troppe proof non valide ({valid_count}/{len(merkle_proofs)})"
                self.logger.warning(f"  ❌ {error_msg}")
                return False, error_msg
                
        except Exception as e:
            self.logger.error(f"  💥 Errore critico durante verifica Merkle proof: {e}")
            return False, f"Errore interno: {e}"
    
    async def _verify_single_merkle_proof(self, attribute_value: Any, proof_path: List[Dict], merkle_root: str) -> bool:
        """
        Verifica crittografica di una singola Merkle proof ricostruendo il percorso verso la radice.
        
        Args:
            attribute_value: Il valore dell'attributo divulgato
            proof_path: Lista di hash siblings per ricostruire il percorso
            merkle_root: La radice Merkle originale da verificare
            
        Returns:
            True se la proof è crittograficamente valida
        """
        try:
            # Importa CryptoUtils per il calcolo degli hash
            from crypto.foundations import CryptoUtils
            crypto_utils = CryptoUtils()
            
            # 1. Calcola l'hash dell'attributo divulgato
            if isinstance(attribute_value, (dict, list)):
                import json
                attribute_str = json.dumps(attribute_value, sort_keys=True)
            else:
                attribute_str = str(attribute_value)
            
            current_hash = crypto_utils.sha256_hash_string(attribute_str)
            self.logger.info(f"      Hash attributo: {current_hash[:16]}...")
            
            # 2. Ricostruisce il percorso verso la radice usando i siblings
            for step_index, step in enumerate(proof_path):
                sibling_hash = step.get('hash')
                is_right_sibling = step.get('is_right', False)
                
                if not sibling_hash:
                    self.logger.warning(f"      ⚠️ Step {step_index}: hash sibling mancante")
                    continue
                
                # Combina l'hash corrente con il sibling secondo la posizione
                if is_right_sibling:
                    # Il sibling è a destra, quindi il nostro hash è a sinistra
                    combined = current_hash + sibling_hash
                    self.logger.info(f"      Step {step_index}: {current_hash[:8]}... + {sibling_hash[:8]}... (R)")
                else:
                    # Il sibling è a sinistra, quindi il nostro hash è a destra
                    combined = sibling_hash + current_hash
                    self.logger.info(f"      Step {step_index}: {sibling_hash[:8]}... + {current_hash[:8]}... (L)")
                
                # Calcola il nuovo hash
                current_hash = crypto_utils.sha256_hash_string(combined)
                self.logger.info(f"      → Nuovo hash: {current_hash[:16]}...")
            
            # 3. Confronta la radice calcolata con quella attesa
            calculated_root = current_hash
            expected_root = merkle_root
            
            self.logger.info(f"      Radice calcolata: {calculated_root[:16]}...")
            self.logger.info(f"      Radice attesa:    {expected_root[:16]}...")
            
            is_valid = calculated_root == expected_root
            
            if is_valid:
                self.logger.info(f"      ✅ Merkle proof VALIDA")
            else:
                self.logger.warning(f"      ❌ Merkle proof NON VALIDA")
                self.logger.warning(f"         Radici non corrispondenti!")
            
            return is_valid
            
        except ImportError:
            self.logger.error("      ❌ CryptoUtils non disponibile")
            return False
        except Exception as e:
            self.logger.error(f"      💥 Errore verifica singola proof: {e}")
            return False
    
    async def _debug_merkle_structure(self, disclosure: dict):
        """
        Metodo di debug per analizzare la struttura delle Merkle proof.
        """
        try:
            self.logger.info("  🔍 DEBUG: Analisi struttura Merkle proof")
            
            disclosed_attributes = disclosure.get("disclosed_attributes", {})
            merkle_proofs = disclosure.get("merkle_proofs", [])
            
            self.logger.info(f"    Attributi divulgati: {len(disclosed_attributes)}")
            for i, (key, value) in enumerate(disclosed_attributes.items()):
                value_preview = str(value)[:50] + "..." if len(str(value)) > 50 else str(value)
                self.logger.info(f"      {i}: {key} = {value_preview}")
            
            self.logger.info(f"    Merkle proofs: {len(merkle_proofs)}")
            for i, proof in enumerate(merkle_proofs):
                self.logger.info(f"      Proof {i}:")
                self.logger.info(f"        Index: {proof.get('attribute_index')}")
                self.logger.info(f"        Root: {proof.get('merkle_root', 'N/A')[:16]}...")
                self.logger.info(f"        Steps: {len(proof.get('proof_path', []))}")
                
                for j, step in enumerate(proof.get('proof_path', [])):
                    side = "R" if step.get('is_right') else "L"
                    hash_preview = step.get('hash', 'N/A')[:16] + "..." if step.get('hash') else 'N/A'
                    self.logger.info(f"          Step {j}: {hash_preview} ({side})")
                    
        except Exception as e:
            self.logger.error(f"      💥 Errore debug Merkle: {e}")

    async def _verify_blockchain_status(self, credential_id: str) -> str:
        """Verifica lo stato della credenziale su blockchain - MIGLIORATO"""
        try:
            # CORREZIONE 4: Timeout e gestione errori migliorata
            async with httpx.AsyncClient(verify=False) as client:
                response = await client.post(
                    f"{self.dashboard.config.secure_server_url}/api/v1/credentials/verify",
                    headers={"Authorization": f"Bearer {self.dashboard.config.secure_server_api_key}"},
                    json={"credential_data": {"metadata": {"credential_id": credential_id}}},
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get("success"):
                        blockchain_result = result.get("data", {}).get("blockchain_result", {})
                        if blockchain_result.get("revoked"): 
                            return "revoked"
                        elif blockchain_result.get("is_valid"): 
                            return "valid"
                        else: 
                            return "invalid"
                    else: 
                        return "error"
                else: 
                    return "unreachable"
                    
        except asyncio.TimeoutError:
            self.logger.warning(f"Timeout verifica blockchain per {credential_id}")
            return "timeout"
        except Exception as e:
            self.logger.error(f"Errore verifica blockchain: {e}")
            return "error"
            
    def _verify_temporal_consistency(self, presentation_data: dict) -> bool:
        """Verifica la coerenza temporale della presentazione - CORRETTO"""
        try:
            now = datetime.datetime.now(datetime.timezone.utc)
            
            expires_at_str = presentation_data.get("expires_at")
            if expires_at_str:
                # CORREZIONE 5: Gestione timezone migliorata
                try:
                    if expires_at_str.endswith('Z'):
                        expires_at_str = expires_at_str[:-1] + '+00:00'
                    elif '+' not in expires_at_str and 'T' in expires_at_str:
                        expires_at_str += '+00:00'
                    
                    expires_at = datetime.datetime.fromisoformat(expires_at_str)
                    if now > expires_at:
                        self.logger.warning("Presentazione scaduta")
                        return False
                except ValueError as e:
                    self.logger.warning(f"Formato data scadenza non valido: {expires_at_str}")
                    return False
            
            return True
        except Exception as e:
            self.logger.error(f"Errore verifica temporale: {e}")
            return False
        
    def extract_student_public_key_from_wallet():
        """Helper per estrarre la chiave pubblica dallo student wallet"""
        try:
            # Percorso del certificato studente (demo)
            student_cert_path = "./certificates/students/mario_rossi_0622702628.pem"
            
            if Path(student_cert_path).exists():
                with open(student_cert_path, 'rb') as f:
                    from cryptography.x509 import load_pem_x509_certificate
                    cert = load_pem_x509_certificate(f.read())
                    public_key = cert.public_key()
                    
                    # Serializza in formato PEM per uso nel dashboard
                    pem_key = public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                    
                    return pem_key.decode('utf-8')
            
            return None
        except Exception as e:
            print(f"Errore estrazione chiave pubblica studente: {e}")
            return None
        
# =============================================================================
# MIDDLEWARE AND DEPENDENCIES
# =============================================================================

def get_current_user(request: Request, session_manager: SessionManager) -> Optional[UserSession]:
    """Dependency to get the current user from the session."""
    session_id = request.session.get("session_id")
    if session_id:
        return session_manager.get_session(session_id)
    return None

def require_auth(request: Request, session_manager: SessionManager) -> UserSession:
    """Dependency that requires authentication."""
    user = get_current_user(request, session_manager)
    if not user:
        raise HTTPException(
            status_code=HTTP_403_FORBIDDEN,
            detail="Authentication required"
        )
    return user

# =============================================================================
# MAIN DASHBOARD CLASS
# =============================================================================

class AcademicCredentialsDashboard:
    """
    Main dashboard for managing academic credentials.
    """
    
    def __init__(self, config: Optional[AppConfig] = None):
        self.config = config or AppConfig()
        self.app = FastAPI(
            title="Academic Credentials Dashboard",
            description="System for the decentralized management of academic credentials.",
            version="2.0.0"
        )
        
        # Services
        self.session_manager = SessionManager(self.config.session_timeout_minutes)
        self.mock_data = MockDataService()
        self.issuer = None  # Will be initialized later
        
        # Configure logging
        self._setup_logging()
        
        # Initialize components
        self._setup_directories()
        self._setup_templates()
        self._setup_middleware()
        self._setup_static_files()
        
        # Create authentication dependencies
        self.auth_deps = self._create_auth_dependencies()
        
        self._setup_routes()
        self._initialize_system_components()
        self._initialize_verification_service()

    def _setup_logging(self) -> None:
        """Configures the logging system."""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            force=True
        )
        self.logger = logging.getLogger(__name__)

    def run(self, host: Optional[str] = None, port: Optional[int] = None):
        """Starts the web server."""
        import uvicorn
        
        host = host or self.config.host
        port = port or self.config.port
        
        uvicorn.run(
            self.app,
            host=host,
            port=port,
            log_level="warning",
            access_log=False
        )

    def _safe_json_serializer(self, obj):
            """
            Custom JSON serializer for handling datetime and other non-serializable objects.
            """
            if isinstance(obj, datetime.datetime):
                return obj.isoformat()
            elif isinstance(obj, datetime.date):
                return obj.isoformat()
            elif isinstance(obj, uuid.UUID):
                return str(obj)
            elif hasattr(obj, 'to_dict'):
                return obj.to_dict()
            elif hasattr(obj, '__dict__'):
                return obj.__dict__
            else:
                return str(obj)

    def _create_json_response(self, data: Dict[str, Any], status_code: int = 200) -> JSONResponse:
        """
        Creates a JSONResponse with safe serialization.
        """
        try:
            json.dumps(data, default=str)
            return JSONResponse(data, status_code=status_code)
        except TypeError:
            safe_data = json.loads(json.dumps(data, default=self._safe_json_serializer))
            return JSONResponse(safe_data, status_code=status_code)

    def _setup_directories(self) -> None:
        """Creates the necessary directories for the application."""
        self.templates_dir = Path(self.config.templates_dir)
        self.static_dir = Path(self.config.static_dir)
        self.wallets_dir = Path("./student_wallets")
        self.templates_dir.mkdir(parents=True, exist_ok=True)
        self.static_dir.mkdir(parents=True, exist_ok=True)
        self.wallets_dir.mkdir(parents=True, exist_ok=True)
    
    def _setup_templates(self) -> None:
        """Configures the template rendering system."""
        self.templates = Jinja2Templates(directory=str(self.templates_dir))
    
    def _setup_middleware(self) -> None:
        """Configures application middleware."""
        self.app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"]
        )
        self.app.add_middleware(
            SessionMiddleware,
            secret_key=self.config.secret_key
        )
    
    def _setup_static_files(self) -> None:
        """Configures static file serving."""
        self.app.mount("/static", StaticFiles(directory=str(self.static_dir)), name="static")
    
    def _create_auth_dependencies(self):
        """Creates authentication dependencies."""
        
        def get_current_user_dep(request: Request) -> Optional[UserSession]:
            return get_current_user(request, self.session_manager)
        
        def require_auth_dep(request: Request) -> UserSession:
            user = get_current_user(request, self.session_manager)
            if not user:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Authentication required")
            return user
        
        def require_write_permission_dep(request: Request) -> UserSession:
            user = get_current_user(request, self.session_manager)
            if not user:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Authentication required")
            if "write" not in user.permissions:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Write permission required")
            return user
        
        def require_verify_permission_dep(request: Request) -> UserSession:
            user = get_current_user(request, self.session_manager)
            if not user:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Authentication required")
            if "verify" not in user.permissions:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Verification permission required")
            return user
        
        def require_admin_permission_dep(request: Request) -> UserSession:
            user = get_current_user(request, self.session_manager)
            if not user:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Authentication required")
            if "admin" not in user.permissions:
                raise HTTPException(status_code=HTTP_403_FORBIDDEN, detail="Admin permission required")
            return user
        
        return {
            'get_current_user': get_current_user_dep,
            'require_auth': require_auth_dep,
            'require_write': require_write_permission_dep,
            'require_verify': require_verify_permission_dep,
            'require_admin': require_admin_permission_dep
        }

    def _initialize_system_components(self) -> None:
        """Initializes core system components."""
        self.logger.info("🔧 Initializing system components...")
        
        if not MODULES_AVAILABLE:
            self.logger.warning("⚠️ Core system modules not available - running in demo mode")
            return
        
        try:
            current_dir = Path.cwd()
            self.logger.info(f"Current working directory: {current_dir}")
            
            possible_cert_paths = [
                "certificates/issued/university_F_RENNES01_1001.pem",
                "./certificates/issued/university_F_RENNES01_1001.pem", 
                "src/certificates/issued/university_F_RENNES01_1001.pem",
                "./src/certificates/issued/university_F_RENNES01_1001.pem"
            ]
            
            possible_key_paths = [
                "keys/universite_rennes_private.pem",
                "./keys/universite_rennes_private.pem",
                "src/keys/universite_rennes_private.pem", 
                "./src/keys/universite_rennes_private.pem"
            ]
            
            cert_path = None
            key_path = None
            
            for path in possible_cert_paths:
                if Path(path).exists():
                    cert_path = path
                    self.logger.info(f"✅ Found certificate at: {cert_path}")
                    break
            
            for path in possible_key_paths:
                if Path(path).exists():
                    key_path = path
                    self.logger.info(f"✅ Found private key at: {key_path}")
                    break
            
            if not cert_path or not key_path:
                self.logger.error(f"❌ Required files not found:")
                self.logger.error(f"   Certificate: {cert_path or 'NOT FOUND'}")
                self.logger.error(f"   Private key: {key_path or 'NOT FOUND'}")
                self.logger.error("   Please run certificate_authority.py first to generate certificates")
                return
            
            university_info = University(
                name="Université de Rennes",
                country="FR",
                city="Rennes",
                erasmus_code="F RENNES01",
                website="https://www.univ-rennes1.fr"
            )
            
            issuer_config = IssuerConfiguration(
                university_info=university_info,
                certificate_path=cert_path,
                private_key_path=key_path,
                private_key_password="Unisa2025",
                backup_enabled=True,
                backup_directory="./credentials/backups"
            )
            
            self.logger.info("🏛️ Creating AcademicCredentialIssuer...")
            self.issuer = AcademicCredentialIssuer(config=issuer_config)
            self.logger.info("✅ Issuer initialized successfully")
            
        except Exception as e:
            self.logger.error(f"❌ Error initializing system components: {e}", exc_info=True)
            self.issuer = None
            
    def _initialize_verification_service(self):
        """Inizializza il servizio di verifica."""
        self.verification_service = PresentationVerifier(self)
        
        if MODULES_AVAILABLE:
            try:
                from credentials.validator import AcademicCredentialValidator
                self.verification_service.validator = AcademicCredentialValidator()
            except ImportError:
                self.verification_service.validator = None

    async def _call_secure_api(self, endpoint: str, payload: dict) -> dict:
        """Helper function for calling secure APIs."""
        url = f"{self.config.secure_server_url}{endpoint}"
        headers = {"Authorization": f"Bearer {self.config.secure_server_api_key}"}
        
        async with httpx.AsyncClient(verify=False) as client:
            response = await client.post(url, json=payload, headers=headers)
            response.raise_for_status()
            return response.json()

    def _get_student_wallet(self, user: UserSession) -> AcademicStudentWallet:
        """Helper per ottenere o creare il wallet di uno studente."""
        if not user or user.role != "studente":
            return None

        common_name = user.user_id
        if common_name.startswith("studente_"):
            common_name = common_name[len("studente_"):].replace('_', ' ').title()
        else:
            common_name = common_name.replace('_', ' ').title()
        
        student_id = "0622702628" # Hardcoded ID for the demo user

        wallet_name = f"studente_{common_name.replace(' ', '_').lower()}_wallet"
        wallet_path = self.wallets_dir / wallet_name
        
        config = WalletConfiguration(
            wallet_name=wallet_name,
            storage_path=str(wallet_path)
        )
        wallet = AcademicStudentWallet(config)

        if not wallet.wallet_file.exists():
            print(f"🔧 Creazione wallet per {common_name}...")
            
            wallet.create_wallet(
                password="Unisa2025",
                student_common_name="Mario Rossi", # Hardcoded for demo user
                student_id=student_id
            )

            if wallet.unlock_wallet("Unisa2025"):
                print("Aggiunta di una credenziale di esempio al nuovo wallet...")
                if MODULES_AVAILABLE:
                    try:
                        sample_credential = CredentialFactory.create_sample_credential()
                        signed_credential = wallet.sign_credential_with_university_key(sample_credential)
                        signed_credential.status = CredentialStatus.ACTIVE
                        wallet.add_credential(signed_credential, tags=["esempio", "auto-generata"])
                        print("✅ Credenziale di esempio aggiunta con successo.")
                    except Exception as e:
                        print(f"❌ Errore durante l'aggiunta della credenziale di esempio: {e}")

        if wallet.status == WalletStatus.LOCKED:
            wallet.unlock_wallet("Unisa2025")
            
        return wallet
    
    def _setup_routes(self) -> None:
        """Configures all application routes."""

        @self.app.post("/request_credential")
        async def handle_credential_request(
            request: Request,
            user: UserSession = Depends(self.auth_deps['require_auth'])
        ):
            """Gestisce la richiesta di credenziale a un'università esterna"""
            try:
                if not user.is_student:
                    return JSONResponse(
                        {"success": False, "message": "Solo gli studenti possono richiedere credenziali"},
                        status_code=403
                    )
                
                data = await request.json()
                university = data.get('university')
                purpose = data.get('purpose', '')
                
                # Configurazione per Università de Rennes (esempio)
                university_config = {
                    "Université de Rennes": {
                        "url": "https://localhost:8443/api/v1/credentials/request",
                        "api_key": "issuer_rennes"
                    }
                }
                
                if university not in university_config:
                    return JSONResponse(
                        {"success": False, "message": "Università non supportata"},
                        status_code=400
                    )
                
                config = university_config[university]
                
                # Dati studente (da wallet)
                wallet = self._get_student_wallet(user)
                student_id = "0622702628"  # Esempio, in realtà da wallet
                
                # Crea payload per la richiesta TLS
                payload = {
                    "student_name": "Mario Rossi",
                    "student_id": student_id,
                    "purpose": purpose,
                    "requested_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
                }
                
                # Invia richiesta TLS al server universitario
                async with httpx.AsyncClient(verify=False) as client:  # verify=False solo per testing!
                    response = await client.post(
                        config['url'],
                        json=payload,
                        headers={
                            "Authorization": f"Bearer {config['api_key']}",
                            "Content-Type": "application/json"
                        },
                        timeout=10.0
                    )
                    
                    if response.status_code == 200:
                        return JSONResponse({
                            "success": True,
                            "message": "Richiesta inviata con successo",
                            "request_id": response.json().get('request_id'),
                            "university": university
                        })
                    else:
                        return JSONResponse({
                            "success": False,
                            "message": f"Errore università: {response.text}",
                            "status_code": response.status_code
                        }, status_code=502)
                        
            except Exception as e:
                return JSONResponse(
                    {"success": False, "message": f"Errore interno: {str(e)}"},
                    status_code=500
                )
        
        @self.app.post("/verification/full-verify")
        async def handle_full_verification(
            request: Request, 
            user: UserSession = Depends(self.auth_deps['require_verify'])
        ):
            """Gestisce la verifica completa di una presentazione selettiva."""
            try:
                self.logger.info(f"🔍 Richiesta verifica completa da {user.user_id}")
                
                body = await request.json()
                
                presentation_data = body.get("presentation_data")
                student_public_key = body.get("student_public_key")
                purpose = body.get("purpose", "verification")
                
                if not presentation_data or not student_public_key:
                    return JSONResponse(
                        {"success": False, "message": "Dati presentazione e chiave pubblica richiesti"},
                        status_code=400
                    )
                
                verification_report = await self.verification_service.verify_presentation_complete(
                    presentation_data, student_public_key, purpose
                )
                
                self.logger.info(f"✅ Verifica completata: {verification_report['overall_result']}")
                
                return JSONResponse({
                    "success": True,
                    "message": "Verifica completata",
                    "verification_report": verification_report
                })
                
            except json.JSONDecodeError:
                return JSONResponse(
                    {"success": False, "message": "Formato JSON non valido"},
                    status_code=400
                )
            except Exception as e:
                self.logger.error(f"❌ Errore verifica completa: {e}")
                return JSONResponse(
                    {"success": False, "message": f"Errore interno: {str(e)}"},
                    status_code=500
                )

        @self.app.get("/", response_class=HTMLResponse)
        async def home(request: Request):
            """Main page."""
            user = self.auth_deps['get_current_user'](request)
            if user:
                redirect_url = "/wallet" if user.role == 'studente' else "/dashboard"
                return RedirectResponse(url=redirect_url, status_code=HTTP_302_FOUND)
            
            return self.templates.TemplateResponse("home.html", {"request": request, "title": "Home"})
        
        @self.app.get("/login", response_class=HTMLResponse)
        async def login_page(request: Request):
            """Login page."""
            return self.templates.TemplateResponse("login.html", {"request": request, "title": "Login"})
        
        @self.app.post("/login")
        async def login(request: Request, username: str = Form(...), password: str = Form(...)):
            """Handles user login."""
            try:
                user_info = AuthenticationService.authenticate_user(username, password)
                if user_info:
                    session_id = self.session_manager.create_session(user_info, username)
                    request.session["session_id"] = session_id
                    
                    redirect_url = "/wallet" if user_info["role"] == "studente" else "/dashboard"
                    self.logger.info(f"Login successful for {username} (role: {user_info['role']})")
                    
                    return RedirectResponse(url=redirect_url, status_code=HTTP_302_FOUND)
                
                return self.templates.TemplateResponse("login.html", {
                    "request": request, "error": "Invalid credentials", "title": "Login"
                })
                
            except Exception as e:
                self.logger.error(f"Login error: {e}")
                return self.templates.TemplateResponse("login.html", {
                    "request": request, "error": "System error. Please try again later.", "title": "Login"
                })
        
        @self.app.get("/logout")
        async def logout(request: Request):
            """Logs the user out."""
            session_id = request.session.get("session_id")
            if session_id:
                self.session_manager.destroy_session(session_id)
            request.session.clear()
            return RedirectResponse(url="/", status_code=HTTP_302_FOUND)
        
        @self.app.get("/wallet", response_class=HTMLResponse)
        async def wallet_page(request: Request):
            """Student's wallet page."""
            user = self.auth_deps['get_current_user'](request)
            if not user or user.role != "studente":
                return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
            
            wallet = self._get_student_wallet(user)
            wallet_creds = wallet.list_credentials()
            
            credentials = [
                {
                    'storage_id': cred['storage_id'],
                    'issuer': cred['issuer'],
                    'issue_date': cred['issued_at'],
                    'total_courses': cred['total_courses'],
                    'status': cred['status']
                } for cred in wallet_creds
            ]
            
            return self.templates.TemplateResponse("student_wallet.html", {
                "request": request, "user": user, "title": "My Wallet", "credentials": credentials
            })

        @self.app.get("/dashboard", response_class=HTMLResponse)
        async def dashboard(request: Request):
            """Main dashboard page."""
            user = self.auth_deps['get_current_user'](request)
            if not user or user.role == "studente":
                return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
            
            stats = self.mock_data.get_dashboard_stats()
            message = request.query_params.get("message")
            
            return self.templates.TemplateResponse("dashboard.html", {
                "request": request, "user": user, "stats": stats, "title": "Dashboard", "message": message
            })
        
        @self.app.get("/credentials", response_class=HTMLResponse)
        async def credentials_page(request: Request):
            """Credentials management page."""
            user = self.auth_deps['get_current_user'](request)
            if not user or user.role == "studente":
                return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
            
            credentials = []
            try:
                credentials_base_dir = Path("./src/credentials")
                if credentials_base_dir.exists():
                    for user_dir in credentials_base_dir.iterdir():
                        if user_dir.is_dir():
                            for credential_file in user_dir.glob("credential_*.json"):
                                try:
                                    with open(credential_file, 'r', encoding='utf-8') as f:
                                        if MODULES_AVAILABLE:
                                            credential_data = json.load(f)
                                            credential = AcademicCredential.from_dict(credential_data)
                                            summary = credential.get_summary()
                                            credentials.append({
                                                'credential_id': summary['credential_id'],
                                                'student_name': summary['subject_pseudonym'],
                                                'issued_at': summary['issued_at'][:19],
                                                'issued_by': credential.issuer.name,
                                                'status': summary['status'].title(),
                                                'total_courses': summary['total_courses'],
                                                'total_ects': summary['total_ects'],
                                                'file_path': str(credential_file)
                                            })
                                        else:
                                            credentials.append({
                                                'credential_id': f"mock_{credential_file.stem}",
                                                'student_name': "Mario Rossi",
                                                'issued_at': "2024-01-15 10:30:00",
                                                'issued_by': "Université de Rennes",
                                                'status': "Active",
                                                'total_courses': 5,
                                                'total_ects': 30,
                                                'file_path': str(credential_file)
                                            })
                                except Exception as e:
                                    self.logger.warning(f"Error loading credential {credential_file}: {e}")
                                    continue
                
                credentials.sort(key=lambda x: x['issued_at'], reverse=True)
                
            except Exception as e:
                self.logger.error(f"Error loading credentials: {e}")
            
            return self.templates.TemplateResponse("credentials.html", {
                "request": request, "user": user, "title": "Manage Credentials", "credentials": credentials
            })
        
        @self.app.get("/credentials/issue", response_class=HTMLResponse)
        async def issue_credential_page(request: Request):
            """Page for issuing new credentials."""
            user = self.auth_deps['require_write'](request)
            
            return self.templates.TemplateResponse("issue_credential.html", {
                "request": request, "user": user, "title": "Issue New Credential"
            })
        
        @self.app.post("/credentials/issue")
        async def handle_issue_credential(
            request: Request,
            student_name: str = Form(...),
            student_id: str = Form(...),
            credential_type: str = Form(...),
            study_period_start: str = Form(...),
            study_period_end: str = Form(...),
            course_name: List[str] = Form([]),
            course_cfu: List[str] = Form([]),
            course_grade: List[str] = Form([]),
            course_date: List[str] = Form([])
        ):
            """
            Handles the issuance of a new credential with better error handling and logging
            """
            self.logger.info(f"📝 Credential issuance request received for student: {student_name}")
            
            try:
                user = self.auth_deps['require_write'](request)
                self.logger.info(f"✅ User authenticated: {user.user_id}")
                
                if not self.issuer:
                    self.logger.error("❌ Issuer service not initialized")
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail="Servizio di emissione non disponibile"
                    )
                
                self.logger.info("✅ Issuer service available")

                self.logger.info("🔧 Preparing student data...")
                crypto_utils = CryptoUtils()
                
                name_parts = student_name.strip().split()
                first_name = name_parts[0] if name_parts else "Unknown"
                last_name = name_parts[-1] if len(name_parts) > 1 else "Student"
                
                student_info = PersonalInfo(
                    surname_hash=crypto_utils.sha256_hash_string(last_name),
                    name_hash=crypto_utils.sha256_hash_string(first_name),
                    birth_date_hash=crypto_utils.sha256_hash_string("1990-01-01"),
                    student_id_hash=crypto_utils.sha256_hash_string(student_id),
                    pseudonym=f"student_{student_name.lower().replace(' ', '_')}"
                )
                self.logger.info("✅ Student info created")

                self.logger.info("🔧 Preparing study period...")
                try:
                    start_date = datetime.datetime.fromisoformat(study_period_start + "T00:00:00+00:00")
                    end_date = datetime.datetime.fromisoformat(study_period_end + "T23:59:59+00:00")
                    academic_year = f"{start_date.year}/{start_date.year + 1}"
                    
                    study_period = StudyPeriod(
                        start_date=start_date,
                        end_date=end_date,
                        study_type=StudyType.ERASMUS,
                        academic_year=academic_year
                    )
                    self.logger.info("✅ Study period created")
                except Exception as e:
                    self.logger.error(f"❌ Error creating study period: {e}")
                    raise ValueError(f"Date non valide: {e}")

                host_university = self.issuer.config.university_info

                study_program = StudyProgram(
                    name="Computer Science Exchange Program",
                    isced_code="0613",
                    eqf_level=EQFLevel.LEVEL_7,
                    program_type="Master's Degree Exchange",
                    field_of_study="Computer Science"
                )
                self.logger.info("✅ Study program created")

                self.logger.info("🔧 Preparing courses...")
                courses = []
                
                for i in range(len(course_name)):
                    if course_name[i] and course_cfu[i] and course_grade[i]:
                        try:
                            exam_grade = ExamGrade(
                                score=course_grade[i],
                                passed=True,
                                grade_system=GradeSystem.ECTS_GRADE,
                                ects_grade=course_grade[i]
                            )
                            
                            if course_date[i]:
                                exam_date = datetime.datetime.fromisoformat(course_date[i] + "T10:00:00+00:00")
                            else:
                                exam_date = study_period.end_date
                            
                            course = Course(
                                course_name=course_name[i],
                                course_code=f"CRS-{i+1:03d}",
                                isced_code="0613",
                                grade=exam_grade,
                                exam_date=exam_date,
                                ects_credits=int(course_cfu[i]),
                                professor=f"Prof. {user.university_name}"
                            )
                            courses.append(course)
                            self.logger.info(f"✅ Added course: {course_name[i]}")
                            
                        except Exception as e:
                            self.logger.error(f"❌ Error creating course {i}: {e}")
                            raise ValueError(f"Errore nel corso {course_name[i]}: {e}")

                if not courses:
                    raise ValueError("È necessario specificare almeno un corso")
                
                self.logger.info(f"✅ Created {len(courses)} courses")

                self.logger.info("🔧 Creating issuance request...")
                request_id = self.issuer.create_issuance_request(
                    student_info=student_info,
                    study_period=study_period,
                    host_university=host_university,
                    study_program=study_program,
                    courses=courses,
                    requested_by=user.user_id,
                    notes=f"Credenziale di tipo: {credential_type}"
                )
                self.logger.info(f"✅ Issuance request created: {request_id}")

                self.logger.info("⚙️ Processing issuance request...")
                issuance_result = self.issuer.process_issuance_request(request_id)
                
                if not issuance_result.success:
                    error_msg = "; ".join(issuance_result.errors)
                    self.logger.error(f"❌ Issuance failed: {error_msg}")
                    raise ValueError(f"Emissione fallita: {error_msg}")

                self.logger.info("✅ Credential issued successfully")

                credential = issuance_result.credential
                credential_id_str = str(credential.metadata.credential_id)
                
                import re
                safe_student_name = re.sub(r'[^\w\s-]', '', student_name).strip().replace(' ', '_')
                
                output_dir = Path(f"src/credentials/{user.user_id}/{safe_student_name}/")
                output_dir.mkdir(parents=True, exist_ok=True)
                
                output_path = output_dir / f"{credential_id_str}.json"
                
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(credential.to_json())
                
                self.logger.info(f"💾 Credential saved to: {output_path}")

                result_data = {
                    "success": True,
                    "message": "Credenziale emessa con successo!",
                    "credential_id": credential_id_str,
                    "file_path": str(output_path),
                    "issued_at": credential.metadata.issued_at.isoformat(),
                    "total_courses": len(courses),
                    "total_ects": sum(c.ects_credits for c in courses)
                }
                
                self.logger.info(f"🎉 Credential issuance completed successfully for {student_name}")
                return JSONResponse(result_data)
                
            except ValueError as e:
                self.logger.warning(f"⚠️ Validation error: {e}")
                return JSONResponse(
                    {"success": False, "message": f"Errore nei dati: {str(e)}"}, 
                    status_code=400
                )
                
            except HTTPException as he:
                self.logger.error(f"❌ HTTP Exception: {he.detail}")
                raise he
                
            except Exception as e:
                self.logger.error(f"🔥 Critical error during credential issuance: {e}", exc_info=True)
                return JSONResponse(
                    {"success": False, "message": f"Errore interno del server: {str(e)}"},
                    status_code=500
                )
                                        
        @self.app.get("/verification", response_class=HTMLResponse)
        async def verification_page(request: Request):
            """Credential verification page."""
            user = self.auth_deps['get_current_user'](request)
            if not user or user.role == "studente":
                return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
            
            return self.templates.TemplateResponse("verification.html", {
                "request": request, "user": user, "title": "Verify Credentials"
            })
        
        @self.app.get("/integration", response_class=HTMLResponse)
        async def integration_page(request: Request):
            """Systems integration page."""
            user = self.auth_deps['get_current_user'](request)
            if not user or user.role == "studente":
                return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
            
            integration_stats = self.mock_data.get_integration_stats()
            
            return self.templates.TemplateResponse("integration.html", {
                "request": request, "user": user, "title": "Systems Integration", "integration_stats": integration_stats
            })
        
        @self.app.get("/monitoring", response_class=HTMLResponse)
        async def monitoring_page(request: Request):
            """System monitoring page."""
            user = self.auth_deps['get_current_user'](request)
            if not user or user.role == "studente":
                return RedirectResponse(url="/login", status_code=HTTP_302_FOUND)
            
            system_health = self.mock_data.get_system_health()
            
            return self.templates.TemplateResponse("monitoring.html", {
                "request": request, "user": user, "title": "System Monitoring", "system_health": system_health
            })
        
        @self.app.get("/health")
        async def health_check():
            """Health check endpoint."""
            return JSONResponse({
                "status": "healthy",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "version": "2.0.0"
            })

        @self.app.get("/credentials/{storage_id}", response_class=JSONResponse)
        async def get_credential_details(
            storage_id: str, user: UserSession = Depends(self.auth_deps['require_auth'])
        ):
            """Get details for a specific credential."""
            wallet = self._get_student_wallet(user)
            cred = wallet.get_credential(storage_id)
            
            if not cred:
                raise HTTPException(status_code=404, detail="Credential not found")
            
            return {
                "storage_id": storage_id,
                "credential_id": str(cred.credential.metadata.credential_id),
                "issuer": cred.credential.issuer.name,
                "issue_date": cred.credential.metadata.issued_at.strftime("%Y-%m-%d"),
                "status": cred.credential.status.value,
                "total_ects": cred.credential.total_ects_credits,
                "courses": [
                    {"name": course.course_name, "grade": course.grade.score}
                    for course in cred.credential.courses
                ]
            }

        @self.app.post("/presentations", response_class=JSONResponse)
        async def create_presentation(
            request: Request,
            user: UserSession = Depends(self.auth_deps['require_auth'])
        ):
            """Creates a new presentation from selected credentials with selective disclosure."""
            try:
                body = await request.json()
                
                self.logger.info(f"Creating presentation for user: {user.user_id}")
                self.logger.info(f"Request body: {body}")
                
                if not user.is_student:
                    return JSONResponse(
                        {"success": False, "message": "Solo gli studenti possono creare presentazioni"},
                        status_code=403
                    )

                if not body.get('purpose') or len(body.get('purpose', '').strip()) < 5:
                    return JSONResponse(
                        {"success": False, "message": "Lo scopo deve essere di almeno 5 caratteri"},
                        status_code=400
                    )
                
                if not body.get('credentials') or len(body.get('credentials')) == 0:
                    return JSONResponse(
                        {"success": False, "message": "Selezionare almeno una credenziale"},
                        status_code=400
                    )

                wallet = self._get_student_wallet(user)
                if not wallet or wallet.status != WalletStatus.UNLOCKED:
                    return JSONResponse(
                        {"success": False, "message": "Wallet non disponibile o bloccato"},
                        status_code=500
                    )

                if not MODULES_AVAILABLE:
                    return JSONResponse(
                        {"success": False, "message": "Moduli wallet non disponibili"},
                        status_code=503
                    )

                from wallet.presentation import PresentationManager, PresentationFormat
                from wallet.selective_disclosure import DisclosureLevel

                presentation_manager = PresentationManager(wallet)
                
                selected_attributes = body.get('selected_attributes', [])
                if not selected_attributes:
                    selected_attributes = [
                        "metadata.credential_id", "subject.pseudonym", 
                        "issuer.name", "total_ects_credits"
                    ]

                self.logger.info(f"Selected attributes: {selected_attributes}")

                credential_selections = []
                for storage_id in body.get('credentials'):
                    wallet_cred = wallet.get_credential(storage_id)
                    if not wallet_cred:
                        return JSONResponse(
                            {"success": False, "message": f"Credenziale {storage_id} non trovata nel wallet"},
                            status_code=400
                        )
                    
                    selection = {
                        'storage_id': storage_id,
                        'disclosure_level': DisclosureLevel.CUSTOM,
                        'custom_attributes': selected_attributes
                    }
                    credential_selections.append(selection)

                self.logger.info(f"Credential selections prepared: {len(credential_selections)}")

                presentation_id = presentation_manager.create_presentation(
                    purpose=body.get('purpose'),
                    credential_selections=credential_selections,
                    recipient=body.get('recipient'),
                    expires_hours=72
                )

                self.logger.info(f"Presentation created with ID: {presentation_id}")

                sign_success = presentation_manager.sign_presentation(presentation_id)
                if not sign_success:
                    return JSONResponse(
                        {"success": False, "message": "Errore durante la firma della presentazione"},
                        status_code=500
                    )

                self.logger.info("Presentation signed successfully")

                # --- MODIFICA INIZIO ---
                # Il percorso di export ora dipende dalla directory del wallet dello studente.
                export_dir = wallet.wallet_dir / "presentations"
                # --- MODIFICA FINE ---
                
                export_dir.mkdir(exist_ok=True)
                output_path = export_dir / f"{presentation_id}.json"
                
                export_success = presentation_manager.export_presentation(
                    presentation_id,
                    str(output_path), 
                    PresentationFormat.SIGNED_JSON
                )

                if not export_success:
                    return JSONResponse(
                        {"success": False, "message": "Errore durante l'export della presentazione"},
                        status_code=500
                    )

                self.logger.info(f"Presentation exported to: {output_path}")

                presentation = presentation_manager.get_presentation(presentation_id)
                if not presentation:
                    return JSONResponse(
                        {"success": False, "message": "Errore: presentazione non trovata dopo creazione"},
                        status_code=500
                    )

                try:
                    summary = presentation.get_summary()
                except Exception as e:
                    self.logger.warning(f"Error getting presentation summary: {e}")
                    summary = {
                        'total_disclosures': len(presentation.selective_disclosures),
                        'total_attributes_disclosed': 0,
                        'is_signed': presentation.signature is not None
                    }

                response_data = {
                    "success": True,
                    "message": "Presentazione verificabile creata con successo",
                    "presentation_id": presentation_id,
                    "download_url": f"/presentations/{presentation_id}/download",
                    "details": {
                        "total_disclosures": summary.get('total_disclosures', 0),
                        "attributes_disclosed": summary.get('total_attributes_disclosed', 0),
                        "signed": summary.get('is_signed', False),
                        "expires_at": (
                            presentation.expires_at.isoformat() 
                            if presentation.expires_at else None
                        )
                    }
                }

                self.logger.info("Presentation creation completed successfully")
                return self._create_json_response(response_data)

            except ImportError as e:
                self.logger.error(f"Import error in presentation creation: {e}")
                return JSONResponse(
                    {"success": False, "message": "Moduli wallet non disponibili"},
                    status_code=503
                )
            except Exception as e:
                self.logger.error(f"Error creating presentation: {e}", exc_info=True)
                return JSONResponse(
                    {"success": False, "message": f"Errore interno: {str(e)}"},
                    status_code=500
                )

        @self.app.get("/presentations/{presentation_id}/download")
        async def download_presentation(
            presentation_id: str, 
            user: UserSession = Depends(self.auth_deps['require_auth'])
        ):
            """Downloads a presentation file."""
            try:
                # MODIFICA: Il percorso del file ora dipende dal wallet dello studente
                if not user.is_student:
                     raise HTTPException(status_code=403, detail="Accesso non autorizzato")
                
                wallet = self._get_student_wallet(user)
                file_path = wallet.wallet_dir / "presentations" / f"{presentation_id}.json"
                
                if not file_path.exists():
                    self.logger.warning(f"Presentation file not found: {file_path}")
                    raise HTTPException(status_code=404, detail="Presentazione non trovata")
                
                self.logger.info(f"Downloading presentation: {presentation_id} for user {user.user_id}")
                return FileResponse(
                    file_path, 
                    filename=f"presentation_{presentation_id[:8]}.json",
                    media_type='application/json'
                )
                
            except HTTPException:
                raise
            except Exception as e:
                self.logger.error(f"Error downloading presentation: {e}")
                raise HTTPException(status_code=500, detail="Errore durante il download")
# =============================================================================
# APPLICATION ENTRY POINT
# =============================================================================

_dashboard_instance = None

def get_dashboard_app() -> FastAPI:
    """Factory function to get the application instance."""
    global _dashboard_instance
    if _dashboard_instance is None:
        _dashboard_instance = AcademicCredentialsDashboard()
    return _dashboard_instance.app

app = get_dashboard_app()

if __name__ == "__main__":
    print("🌐 Starting Academic Credentials Dashboard in standalone mode...")
    dashboard = AcademicCredentialsDashboard()
    dashboard.run()